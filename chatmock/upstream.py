from __future__ import annotations

import datetime
import json
import os
import time
from typing import Any, Dict, List, Tuple

import requests
from flask import Response, current_app, jsonify, make_response

from .config import CHATGPT_RESPONSES_URL
from .http import build_cors_headers
from .session import ensure_session_id
from flask import request as flask_request
from .auth_store import record_account_result
from .utils import get_effective_chatgpt_auth


def _log_json(prefix: str, payload: Any) -> None:
    try:
        print(f"{prefix}\n{json.dumps(payload, indent=2, ensure_ascii=False)}")
    except Exception:
        try:
            print(f"{prefix}\n{payload}")
        except Exception:
            pass


def normalize_model_name(name: str | None, debug_model: str | None = None) -> str:
    if isinstance(debug_model, str) and debug_model.strip():
        return debug_model.strip()
    if not isinstance(name, str) or not name.strip():
        return "gpt-5"
    base = name.split(":", 1)[0].strip()
    for sep in ("-", "_"):
        lowered = base.lower()
        for effort in ("minimal", "low", "medium", "high", "xhigh"):
            suffix = f"{sep}{effort}"
            if lowered.endswith(suffix):
                base = base[: -len(suffix)]
                break
    mapping = {
        "gpt5": "gpt-5",
        "gpt-5-latest": "gpt-5",
        "gpt-5": "gpt-5",
        "gpt-5.1": "gpt-5.1",
        "gpt5.2": "gpt-5.2",
        "gpt-5.2": "gpt-5.2",
        "gpt-5.2-latest": "gpt-5.2",
        "gpt5.2-codex": "gpt-5.2-codex",
        "gpt-5.2-codex": "gpt-5.2-codex",
        "gpt-5.2-codex-latest": "gpt-5.2-codex",
        "gpt-5.2-codeX": "gpt-5.2-codex",
        "gpt5-codex": "gpt-5-codex",
        "gpt-5-codex": "gpt-5-codex",
        "gpt-5-codex-latest": "gpt-5-codex",
        "gpt-5.1-codex": "gpt-5.1-codex",
        "gpt-5.1-codex-max": "gpt-5.1-codex-max",
        "codex": "codex-mini-latest",
        "codex-mini": "codex-mini-latest",
        "codex-mini-latest": "codex-mini-latest",
        "gpt-5.1-codex-mini": "gpt-5.1-codex-mini",
    }
    return mapping.get(base, base)


def _retry_after_seconds(headers: Dict[str, str] | None) -> int | None:
    if not isinstance(headers, dict):
        return None
    raw = headers.get("Retry-After")
    if not raw:
        return None
    try:
        return int(raw)
    except Exception:
        return None


def start_upstream_request(
    model: str,
    input_items: List[Dict[str, Any]],
    *,
    instructions: str | None = None,
    tools: List[Dict[str, Any]] | None = None,
    tool_choice: Any | None = None,
    parallel_tool_calls: bool = False,
    reasoning_param: Dict[str, Any] | None = None,
):
    account_override = None
    try:
        account_override = (
            flask_request.headers.get("X-ChatMock-Account")
            or flask_request.headers.get("X-ChatMock-Account-Id")
            or None
        )
    except Exception:
        account_override = None

    include: List[str] = []
    if isinstance(reasoning_param, dict):
        include.append("reasoning.encrypted_content")

    client_session_id = None
    try:
        client_session_id = (
            flask_request.headers.get("X-Session-Id")
            or flask_request.headers.get("session_id")
            or None
        )
    except Exception:
        client_session_id = None
    session_id = ensure_session_id(instructions, input_items, client_session_id)

    responses_payload = {
        "model": model,
        "instructions": instructions if isinstance(instructions, str) and instructions.strip() else instructions,
        "input": input_items,
        "tools": tools or [],
        "tool_choice": tool_choice if tool_choice in ("auto", "none") or isinstance(tool_choice, dict) else "auto",
        "parallel_tool_calls": bool(parallel_tool_calls),
        "store": False,
        "stream": True,
        "prompt_cache_key": session_id,
    }
    if include:
        responses_payload["include"] = include

    if reasoning_param is not None:
        responses_payload["reasoning"] = reasoning_param

    verbose = False
    try:
        verbose = bool(current_app.config.get("VERBOSE"))
    except Exception:
        verbose = False
    if verbose:
        _log_json("OUTBOUND >> ChatGPT Responses API payload", responses_payload)

    failover_attempts = 0
    if not account_override:
        raw_failover = os.getenv("CHATMOCK_ACCOUNT_FAILOVER") or os.getenv("CHATGPT_LOCAL_ACCOUNT_FAILOVER") or ""
        try:
            failover_attempts = int(raw_failover)
        except Exception:
            failover_attempts = 0
        failover_attempts = max(0, min(10, failover_attempts))

    attempts = 1 if account_override else (1 + failover_attempts)
    last_upstream = None
    for attempt in range(attempts):
        access_token, account_id, cooldown_until = get_effective_chatgpt_auth(account_override)
        if not access_token or not account_id:
            if cooldown_until:
                now = datetime.datetime.now(datetime.timezone.utc)
                retry_after = int(max(0, (cooldown_until - now).total_seconds()))
                err = {
                    "error": {
                        "message": "All accounts are cooling down. Retry later.",
                        "code": "ACCOUNTS_COOLDOWN",
                        "retry_after": retry_after,
                    }
                }
                resp = make_response(jsonify(err), 429)
                if retry_after:
                    resp.headers["Retry-After"] = str(retry_after)
                for k, v in build_cors_headers().items():
                    resp.headers.setdefault(k, v)
                return None, resp
            resp = make_response(
                jsonify(
                    {
                        "error": {
                            "message": "Missing ChatGPT credentials. Run 'python3 chatmock.py login' first.",
                        }
                    }
                ),
                401,
            )
            for k, v in build_cors_headers().items():
                resp.headers.setdefault(k, v)
            return None, resp

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Accept": "text/event-stream",
            "chatgpt-account-id": account_id,
            "OpenAI-Beta": "responses=experimental",
            "session_id": session_id,
        }

        try:
            upstream = requests.post(
                CHATGPT_RESPONSES_URL,
                headers=headers,
                json=responses_payload,
                stream=True,
                timeout=600,
            )
        except requests.RequestException as e:
            resp = make_response(jsonify({"error": {"message": f"Upstream ChatGPT request failed: {e}"}}), 502)
            for k, v in build_cors_headers().items():
                resp.headers.setdefault(k, v)
            return None, resp

        last_upstream = upstream
        retry_after = _retry_after_seconds(getattr(upstream, "headers", {}) or {})
        if upstream.status_code < 400:
            record_account_result(account_id, success=True)
        else:
            record_account_result(
                account_id,
                success=False,
                status_code=upstream.status_code,
                retry_after_seconds=retry_after,
            )

        if upstream.status_code in (401, 403, 429) and attempt < (attempts - 1):
            try:
                upstream.close()
            except Exception:
                pass
            continue
        return upstream, None

    return last_upstream, None
