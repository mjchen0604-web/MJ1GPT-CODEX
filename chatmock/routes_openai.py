from __future__ import annotations

import json
import time
from typing import Any, Dict, List

from flask import Blueprint, Response, current_app, jsonify, make_response, request

from .config import BASE_INSTRUCTIONS, GPT5_CODEX_INSTRUCTIONS
from .api_keys import require_api_key
from .limits import record_rate_limits_from_response
from .http import build_cors_headers
from .reasoning import (
    allowed_efforts_for_model,
    apply_reasoning_to_message,
    build_reasoning_param,
    extract_reasoning_from_model_name,
)
from .upstream import normalize_model_name, start_upstream_request
from .utils import (
    convert_chat_messages_to_responses_input,
    convert_tools_chat_to_responses,
    sse_translate_chat,
    sse_translate_text,
)


openai_bp = Blueprint("openai", __name__)


@openai_bp.before_request
def _guard_api_key():
    return require_api_key()


def _log_json(prefix: str, payload: Any) -> None:
    try:
        print(f"{prefix}\n{json.dumps(payload, indent=2, ensure_ascii=False)}")
    except Exception:
        try:
            print(f"{prefix}\n{payload}")
        except Exception:
            pass


def _wrap_stream_logging(label: str, iterator, enabled: bool):
    if not enabled:
        return iterator

    def _gen():
        for chunk in iterator:
            try:
                text = (
                    chunk.decode("utf-8", errors="replace")
                    if isinstance(chunk, (bytes, bytearray))
                    else str(chunk)
                )
                print(f"{label}\n{text}")
            except Exception:
                pass
            yield chunk

    return _gen()

def _normalize_instructions(value: Any, fallback: str, *, default: str = "You are a helpful assistant.") -> str:
    if isinstance(value, str):
        cleaned = value.strip()
        if cleaned:
            return value
    if isinstance(fallback, str):
        cleaned = fallback.strip()
        if cleaned:
            return fallback
    return default


def _instructions_for_model(model: str) -> str:
    base = _normalize_instructions(current_app.config.get("BASE_INSTRUCTIONS"), BASE_INSTRUCTIONS)
    if model.startswith("gpt-5.2-codex") or model.startswith("gpt-5-codex") or model.startswith("gpt-5.1-codex"):
        codex = _normalize_instructions(
            current_app.config.get("GPT5_CODEX_INSTRUCTIONS"),
            GPT5_CODEX_INSTRUCTIONS,
            default=base,
        )
        return codex
    return base


@openai_bp.route("/v1/chat/completions", methods=["POST"])
def chat_completions() -> Response:
    verbose = bool(current_app.config.get("VERBOSE"))
    verbose_obfuscation = bool(current_app.config.get("VERBOSE_OBFUSCATION"))
    reasoning_effort = current_app.config.get("REASONING_EFFORT", "medium")
    reasoning_summary = current_app.config.get("REASONING_SUMMARY", "auto")
    reasoning_compat = current_app.config.get("REASONING_COMPAT", "think-tags")
    compatibility_mode = bool(current_app.config.get("COMPATIBILITY_MODE"))
    debug_model = current_app.config.get("DEBUG_MODEL")

    raw = request.get_data(cache=True, as_text=True) or ""
    if verbose:
        try:
            print("IN POST /v1/chat/completions\n" + raw)
        except Exception:
            pass
    try:
        payload = json.loads(raw) if raw else {}
    except Exception:
        try:
            payload = json.loads(raw.replace("\r", "").replace("\n", ""))
        except Exception:
            err = {"error": {"message": "Invalid JSON body"}}
            if verbose:
                _log_json("OUT POST /v1/chat/completions", err)
            return jsonify(err), 400

    requested_model = payload.get("model")
    model = normalize_model_name(requested_model, debug_model)
    messages = payload.get("messages")
    if messages is None and isinstance(payload.get("prompt"), str):
        messages = [{"role": "user", "content": payload.get("prompt") or ""}]
    if messages is None and isinstance(payload.get("input"), str):
        messages = [{"role": "user", "content": payload.get("input") or ""}]
    if messages is None:
        messages = []
    if not isinstance(messages, list):
        err = {"error": {"message": "Request must include messages: []"}}
        if verbose:
            _log_json("OUT POST /v1/chat/completions", err)
        return jsonify(err), 400

    def _flatten_content(value: Any) -> str:
        if isinstance(value, list):
            parts: List[str] = []
            for part in value:
                if isinstance(part, dict):
                    text = part.get("text") or part.get("content")
                    if isinstance(text, str) and text:
                        parts.append(text)
                elif isinstance(part, str):
                    parts.append(part)
            return "\n".join([p for p in parts if p])
        if isinstance(value, str):
            return value
        return ""

    system_texts: List[str] = []
    if isinstance(messages, list):
        normalized: List[Dict[str, Any]] = []
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            role = msg.get("role")
            if role == "system":
                content = _flatten_content(msg.get("content"))
                if compatibility_mode:
                    normalized.append({"role": "user", "content": content})
                else:
                    if content:
                        system_texts.append(content)
                continue
            normalized.append(msg)
        messages = normalized
    is_stream = bool(payload.get("stream"))
    stream_options = payload.get("stream_options") if isinstance(payload.get("stream_options"), dict) else {}
    include_usage = bool(stream_options.get("include_usage", False))

    tools_responses = convert_tools_chat_to_responses(payload.get("tools"))
    tool_choice = payload.get("tool_choice", "auto")
    parallel_tool_calls = bool(payload.get("parallel_tool_calls", False))
    responses_tools_payload = payload.get("responses_tools") if isinstance(payload.get("responses_tools"), list) else []
    extra_tools: List[Dict[str, Any]] = []
    had_responses_tools = False

    def _normalize_choice(value: Any) -> str | None:
        if not isinstance(value, str):
            return None
        normalized = value.strip().lower()
        if normalized in ("", "undefined", "[undefined]", "null"):
            return None
        if normalized in ("auto", "none"):
            return normalized
        return None

    normalized_tool_choice = _normalize_choice(tool_choice)
    if normalized_tool_choice:
        tool_choice = normalized_tool_choice
    responses_tool_choice = _normalize_choice(payload.get("responses_tool_choice"))
    if isinstance(responses_tools_payload, list):
        for _t in responses_tools_payload:
            if not (isinstance(_t, dict) and isinstance(_t.get("type"), str)):
                continue
            if _t.get("type") not in ("web_search", "web_search_preview"):
                err = {
                    "error": {
                        "message": "Only web_search/web_search_preview are supported in responses_tools",
                        "code": "RESPONSES_TOOL_UNSUPPORTED",
                    }
                }
                if verbose:
                    _log_json("OUT POST /v1/chat/completions", err)
                return jsonify(err), 400
            extra_tools.append(_t)

        if not extra_tools and bool(current_app.config.get("DEFAULT_WEB_SEARCH")):
            disable_default = responses_tool_choice == "none" or tool_choice == "none"
            if not disable_default:
                extra_tools = [{"type": "web_search"}]

        if extra_tools:
            import json as _json
            MAX_TOOLS_BYTES = 32768
            try:
                size = len(_json.dumps(extra_tools))
            except Exception:
                size = 0
            if size > MAX_TOOLS_BYTES:
                err = {"error": {"message": "responses_tools too large", "code": "RESPONSES_TOOLS_TOO_LARGE"}}
                if verbose:
                    _log_json("OUT POST /v1/chat/completions", err)
                return jsonify(err), 400
            had_responses_tools = True
            tools_responses = (tools_responses or []) + extra_tools

    if responses_tool_choice in ("auto", "none"):
        tool_choice = responses_tool_choice

    input_items = convert_chat_messages_to_responses_input(messages)
    if not input_items and isinstance(payload.get("prompt"), str) and payload.get("prompt").strip():
        input_items = [
            {"type": "message", "role": "user", "content": [{"type": "input_text", "text": payload.get("prompt")}]}
        ]

    model_reasoning = extract_reasoning_from_model_name(requested_model)
    payload_effort = str(payload.get("reasoning_effort") or "").strip().lower()
    payload_summary = str(payload.get("reasoning_summary") or "").strip().lower()
    disable_reasoning = payload_effort in ("none", "off", "disable")
    if disable_reasoning:
        reasoning_param = None
    else:
        if isinstance(payload.get("reasoning"), dict):
            reasoning_overrides = payload.get("reasoning")
        elif payload_effort or payload_summary:
            reasoning_overrides = {"effort": payload_effort, "summary": payload_summary}
        else:
            reasoning_overrides = model_reasoning
        reasoning_param = build_reasoning_param(
            reasoning_effort,
            reasoning_summary,
            reasoning_overrides,
            allowed_efforts=allowed_efforts_for_model(model),
        )

    instructions = _instructions_for_model(model)
    if system_texts:
        system_block = "\n\n".join(system_texts)
        if isinstance(instructions, str) and instructions.strip():
            instructions = instructions.rstrip() + "\n\n" + system_block
        else:
            instructions = system_block

    upstream, error_resp = start_upstream_request(
        model,
        input_items,
        instructions=instructions,
        tools=tools_responses,
        tool_choice=tool_choice,
        parallel_tool_calls=parallel_tool_calls,
        reasoning_param=reasoning_param,
    )
    if error_resp is not None:
        if verbose:
            try:
                body = error_resp.get_data(as_text=True)
                if body:
                    try:
                        parsed = json.loads(body)
                    except Exception:
                        parsed = body
                    _log_json("OUT POST /v1/chat/completions", parsed)
            except Exception:
                pass
        return error_resp

    record_rate_limits_from_response(upstream)

    created = int(time.time())
    def _read_err_body(resp: Response) -> Dict[str, Any]:
        try:
            raw = resp.content
            return json.loads(raw.decode("utf-8", errors="ignore")) if raw else {"raw": resp.text}
        except Exception:
            return {"raw": resp.text}

    def _is_tools_rejected(payload: Dict[str, Any]) -> bool:
        if not isinstance(payload, dict):
            return False
        err = payload.get("error")
        if not isinstance(err, dict):
            return False
        code = err.get("code")
        if isinstance(code, str) and code == "RESPONSES_TOOLS_REJECTED":
            return True
        message = err.get("message")
        if isinstance(message, str):
            lowered = message.lower()
            return "tools" in lowered and "reject" in lowered
        return False

    if upstream.status_code >= 400:
        err_body = _read_err_body(upstream)
        tools_for_retry = tools_responses
        if had_responses_tools and _is_tools_rejected(err_body):
            if verbose:
                print("[Passthrough] Upstream rejected tools; retrying without tools (args redacted)")
            upstream2, err2 = start_upstream_request(
                model,
                input_items,
                instructions=instructions,
                tools=None,
                tool_choice="none",
                parallel_tool_calls=False,
                reasoning_param=reasoning_param,
            )
            record_rate_limits_from_response(upstream2)
            if err2 is None and upstream2 is not None and upstream2.status_code < 400:
                upstream = upstream2
            else:
                err_body = _read_err_body(upstream2) if upstream2 is not None else err_body
            tools_for_retry = None

        if upstream.status_code == 400 and reasoning_param is not None:
            upstream3, err3 = start_upstream_request(
                model,
                input_items,
                instructions=instructions,
                tools=tools_for_retry,
                tool_choice=tool_choice,
                parallel_tool_calls=parallel_tool_calls,
                reasoning_param=None,
            )
            if err3 is not None:
                return err3
            record_rate_limits_from_response(upstream3)
            if upstream3 is not None and upstream3.status_code < 400:
                upstream = upstream3
            else:
                err_body = _read_err_body(upstream3) if upstream3 is not None else err_body

        if upstream.status_code >= 400:
            if verbose:
                print("Upstream error status=", upstream.status_code)
                _log_json("UPSTREAM ERROR BODY", err_body)
            err_msg = (err_body.get("error", {}) or {}).get("message", "Upstream error")
            err_code = (err_body.get("error", {}) or {}).get("code")
            err = {"error": {"message": err_msg}}
            if isinstance(err_code, str) and err_code:
                err["error"]["code"] = err_code
            if verbose:
                _log_json("OUT POST /v1/chat/completions", err)
            return jsonify(err), upstream.status_code

    if is_stream:
        if verbose:
            print("OUT POST /v1/chat/completions (streaming response)")
        stream_iter = sse_translate_chat(
            upstream,
            requested_model or model,
            created,
            verbose=verbose_obfuscation,
            vlog=print if verbose_obfuscation else None,
            reasoning_compat=reasoning_compat,
            include_usage=include_usage,
        )
        stream_iter = _wrap_stream_logging("STREAM OUT /v1/chat/completions", stream_iter, verbose)
        resp = Response(
            stream_iter,
            status=upstream.status_code,
            mimetype="text/event-stream",
            headers={"Cache-Control": "no-cache", "Connection": "keep-alive"},
        )
        for k, v in build_cors_headers().items():
            resp.headers.setdefault(k, v)
        return resp

    full_text = ""
    reasoning_summary_text = ""
    reasoning_full_text = ""
    response_id = "chatcmpl"
    tool_calls: List[Dict[str, Any]] = []
    error_message: str | None = None
    usage_obj: Dict[str, int] | None = None

    def _extract_usage(evt: Dict[str, Any]) -> Dict[str, int] | None:
        try:
            usage = (evt.get("response") or {}).get("usage")
            if not isinstance(usage, dict):
                return None
            pt = int(usage.get("input_tokens") or 0)
            ct = int(usage.get("output_tokens") or 0)
            tt = int(usage.get("total_tokens") or (pt + ct))
            return {"prompt_tokens": pt, "completion_tokens": ct, "total_tokens": tt}
        except Exception:
            return None
    try:
        for raw in upstream.iter_lines(decode_unicode=False):
            if not raw:
                continue
            line = raw.decode("utf-8", errors="ignore") if isinstance(raw, (bytes, bytearray)) else raw
            if not line.startswith("data: "):
                continue
            data = line[len("data: "):].strip()
            if not data:
                continue
            if data == "[DONE]":
                break
            try:
                evt = json.loads(data)
            except Exception:
                continue
            kind = evt.get("type")
            mu = _extract_usage(evt)
            if mu:
                usage_obj = mu
            if isinstance(evt.get("response"), dict) and isinstance(evt["response"].get("id"), str):
                response_id = evt["response"].get("id") or response_id
            if kind == "response.output_text.delta":
                full_text += evt.get("delta") or ""
            elif kind == "response.reasoning_summary_text.delta":
                reasoning_summary_text += evt.get("delta") or ""
            elif kind == "response.reasoning_text.delta":
                reasoning_full_text += evt.get("delta") or ""
            elif kind == "response.output_item.done":
                item = evt.get("item") or {}
                if isinstance(item, dict) and item.get("type") == "function_call":
                    call_id = item.get("call_id") or item.get("id") or ""
                    name = item.get("name") or ""
                    args = item.get("arguments") or ""
                    if isinstance(call_id, str) and isinstance(name, str) and isinstance(args, str):
                        tool_calls.append(
                            {
                                "id": call_id,
                                "type": "function",
                                "function": {"name": name, "arguments": args},
                            }
                        )
            elif kind == "response.failed":
                error_message = evt.get("response", {}).get("error", {}).get("message", "response.failed")
            elif kind == "response.completed":
                break
    finally:
        upstream.close()

    if error_message:
        resp = make_response(jsonify({"error": {"message": error_message}}), 502)
        for k, v in build_cors_headers().items():
            resp.headers.setdefault(k, v)
        return resp

    message: Dict[str, Any] = {"role": "assistant", "content": full_text if full_text else None}
    if tool_calls:
        message["tool_calls"] = tool_calls
    message = apply_reasoning_to_message(message, reasoning_summary_text, reasoning_full_text, reasoning_compat)
    completion = {
        "id": response_id or "chatcmpl",
        "object": "chat.completion",
        "created": created,
        "model": requested_model or model,
        "choices": [
            {
                "index": 0,
                "message": message,
                "finish_reason": "stop",
            }
        ],
        **({"usage": usage_obj} if usage_obj else {}),
    }
    if verbose:
        _log_json("OUT POST /v1/chat/completions", completion)
    resp = make_response(jsonify(completion), upstream.status_code)
    for k, v in build_cors_headers().items():
        resp.headers.setdefault(k, v)
    return resp


@openai_bp.route("/v1/completions", methods=["POST"])
def completions() -> Response:
    verbose = bool(current_app.config.get("VERBOSE"))
    verbose_obfuscation = bool(current_app.config.get("VERBOSE_OBFUSCATION"))
    debug_model = current_app.config.get("DEBUG_MODEL")
    reasoning_effort = current_app.config.get("REASONING_EFFORT", "medium")
    reasoning_summary = current_app.config.get("REASONING_SUMMARY", "auto")
    compatibility_mode = bool(current_app.config.get("COMPATIBILITY_MODE"))

    raw = request.get_data(cache=True, as_text=True) or ""
    if verbose:
        try:
            print("IN POST /v1/completions\n" + raw)
        except Exception:
            pass
    try:
        payload = json.loads(raw) if raw else {}
    except Exception:
        err = {"error": {"message": "Invalid JSON body"}}
        if verbose:
            _log_json("OUT POST /v1/completions", err)
        return jsonify(err), 400

    requested_model = payload.get("model")
    model = normalize_model_name(requested_model, debug_model)
    prompt = payload.get("prompt")
    if isinstance(prompt, list):
        prompt = "".join([p if isinstance(p, str) else "" for p in prompt])
    if not isinstance(prompt, str):
        prompt = payload.get("suffix") or ""
    stream_req = bool(payload.get("stream", False))
    stream_options = payload.get("stream_options") if isinstance(payload.get("stream_options"), dict) else {}
    include_usage = bool(stream_options.get("include_usage", False))

    messages = [{"role": "user", "content": prompt or ""}]
    input_items = convert_chat_messages_to_responses_input(messages)

    model_reasoning = extract_reasoning_from_model_name(requested_model)
    payload_effort = str(payload.get("reasoning_effort") or "").strip().lower()
    payload_summary = str(payload.get("reasoning_summary") or "").strip().lower()
    disable_reasoning = payload_effort in ("none", "off", "disable")
    if disable_reasoning:
        reasoning_param = None
    else:
        if isinstance(payload.get("reasoning"), dict):
            reasoning_overrides = payload.get("reasoning")
        elif payload_effort or payload_summary:
            reasoning_overrides = {"effort": payload_effort, "summary": payload_summary}
        else:
            reasoning_overrides = model_reasoning
        reasoning_param = build_reasoning_param(
            reasoning_effort,
            reasoning_summary,
            reasoning_overrides,
            allowed_efforts=allowed_efforts_for_model(model),
        )
    instructions = _instructions_for_model(model)
    upstream, error_resp = start_upstream_request(
        model,
        input_items,
        instructions=instructions,
        reasoning_param=reasoning_param,
    )
    if error_resp is not None:
        if verbose:
            try:
                body = error_resp.get_data(as_text=True)
                if body:
                    try:
                        parsed = json.loads(body)
                    except Exception:
                        parsed = body
                    _log_json("OUT POST /v1/completions", parsed)
            except Exception:
                pass
        return error_resp

    record_rate_limits_from_response(upstream)

    created = int(time.time())
    if upstream.status_code >= 400:
        try:
            err_body = json.loads(upstream.content.decode("utf-8", errors="ignore")) if upstream.content else {"raw": upstream.text}
        except Exception:
            err_body = {"raw": upstream.text}
        err = {"error": {"message": (err_body.get("error", {}) or {}).get("message", "Upstream error")}}
        if verbose:
            _log_json("OUT POST /v1/completions", err)
        return jsonify(err), upstream.status_code

    if stream_req:
        if verbose:
            print("OUT POST /v1/completions (streaming response)")
        stream_iter = sse_translate_text(
            upstream,
            requested_model or model,
            created,
            verbose=verbose_obfuscation,
            vlog=(print if verbose_obfuscation else None),
            include_usage=include_usage,
        )
        stream_iter = _wrap_stream_logging("STREAM OUT /v1/completions", stream_iter, verbose)
        resp = Response(
            stream_iter,
            status=upstream.status_code,
            mimetype="text/event-stream",
            headers={"Cache-Control": "no-cache", "Connection": "keep-alive"},
        )
        for k, v in build_cors_headers().items():
            resp.headers.setdefault(k, v)
        return resp

    full_text = ""
    response_id = "cmpl"
    usage_obj: Dict[str, int] | None = None
    def _extract_usage(evt: Dict[str, Any]) -> Dict[str, int] | None:
        try:
            usage = (evt.get("response") or {}).get("usage")
            if not isinstance(usage, dict):
                return None
            pt = int(usage.get("input_tokens") or 0)
            ct = int(usage.get("output_tokens") or 0)
            tt = int(usage.get("total_tokens") or (pt + ct))
            return {"prompt_tokens": pt, "completion_tokens": ct, "total_tokens": tt}
        except Exception:
            return None
    try:
        for raw_line in upstream.iter_lines(decode_unicode=False):
            if not raw_line:
                continue
            line = raw_line.decode("utf-8", errors="ignore") if isinstance(raw_line, (bytes, bytearray)) else raw_line
            if not line.startswith("data: "):
                continue
            data = line[len("data: "):].strip()
            if not data or data == "[DONE]":
                if data == "[DONE]":
                    break
                continue
            try:
                evt = json.loads(data)
            except Exception:
                continue
            if isinstance(evt.get("response"), dict) and isinstance(evt["response"].get("id"), str):
                response_id = evt["response"].get("id") or response_id
            mu = _extract_usage(evt)
            if mu:
                usage_obj = mu
            kind = evt.get("type")
            if kind == "response.output_text.delta":
                full_text += evt.get("delta") or ""
            elif kind == "response.completed":
                break
    finally:
        upstream.close()

    completion = {
        "id": response_id or "cmpl",
        "object": "text_completion",
        "created": created,
        "model": requested_model or model,
        "choices": [
            {"index": 0, "text": full_text, "finish_reason": "stop", "logprobs": None}
        ],
        **({"usage": usage_obj} if usage_obj else {}),
    }
    if verbose:
        _log_json("OUT POST /v1/completions", completion)
    resp = make_response(jsonify(completion), upstream.status_code)
    for k, v in build_cors_headers().items():
        resp.headers.setdefault(k, v)
    return resp


@openai_bp.route("/v1/models", methods=["GET"])
def list_models() -> Response:
    expose_variants = bool(current_app.config.get("EXPOSE_REASONING_MODELS"))
    model_groups = [
        ("gpt-5", ["high", "medium", "low", "minimal"]),
        ("gpt-5.1", ["high", "medium", "low"]),
        ("gpt-5.2", ["xhigh", "high", "medium", "low"]),
        ("gpt-5-codex", ["high", "medium", "low"]),
        ("gpt-5.2-codex", ["xhigh", "high", "medium", "low"]),
        ("gpt-5.1-codex", ["high", "medium", "low"]),
        ("gpt-5.1-codex-max", ["xhigh", "high", "medium", "low"]),
        ("gpt-5.1-codex-mini", []),
        ("codex-mini", []),
    ]
    model_ids: List[str] = []
    for base, efforts in model_groups:
        model_ids.append(base)
        if expose_variants:
            model_ids.extend([f"{base}-{effort}" for effort in efforts])
    data = [{"id": mid, "object": "model", "owned_by": "owner"} for mid in model_ids]
    models = {"object": "list", "data": data}
    resp = make_response(jsonify(models), 200)
    for k, v in build_cors_headers().items():
        resp.headers.setdefault(k, v)
    return resp
