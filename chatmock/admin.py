from __future__ import annotations

import json
import os
import secrets
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List

from flask import (
    Blueprint,
    Response,
    abort,
    current_app,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from .settings import (
    DEFAULT_SETTINGS,
    VALID_REASONING_COMPAT,
    VALID_REASONING_EFFORT,
    VALID_REASONING_SUMMARY,
    load_settings,
    save_settings,
)
from .auth_store import (
    account_from_auth_json,
    delete_account,
    get_account,
    load_store,
    save_store,
    set_active,
    upsert_account,
    write_active_auth,
)
from .api_keys import (
    add_key,
    delete_key as delete_api_key,
    attach_usage,
    list_keys,
    load_api_keys,
    reset_usage,
    save_api_keys,
    env_keys,
    update_key,
)
from . import oauth_flow
from .utils import get_home_dir, read_auth_file, write_auth_file


admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


def _admin_password() -> str | None:
    pw = os.getenv("CHATMOCK_ADMIN_PASSWORD") or os.getenv("CHATGPT_LOCAL_ADMIN_PASSWORD")
    if isinstance(pw, str) and pw.strip():
        return pw.strip()
    return None


def _require_admin_enabled() -> None:
    if not _admin_password():
        abort(404)


def _require_ui_login() -> None:
    if not session.get("chatmock_admin"):
        abort(401)


def _require_api_auth() -> None:
    pw = _admin_password()
    if not pw:
        abort(404)

    header = request.headers.get("Authorization", "")
    token = ""
    if isinstance(header, str) and header.lower().startswith("bearer "):
        token = header[7:].strip()
    if not token:
        token = (request.headers.get("X-ChatMock-Admin-Password") or "").strip()
    if token != pw:
        abort(401)


def _current_settings() -> Dict[str, Any]:
    cfg = current_app.config
    return {
        "verbose": bool(cfg.get("VERBOSE")),
        "verbose_obfuscation": bool(cfg.get("VERBOSE_OBFUSCATION")),
        "reasoning_effort": (cfg.get("REASONING_EFFORT") or "medium"),
        "reasoning_summary": (cfg.get("REASONING_SUMMARY") or "auto"),
        "reasoning_compat": (cfg.get("REASONING_COMPAT") or "think-tags"),
        "debug_model": cfg.get("DEBUG_MODEL") or None,
        "expose_reasoning_models": bool(cfg.get("EXPOSE_REASONING_MODELS")),
        "enable_web_search": bool(cfg.get("DEFAULT_WEB_SEARCH")),
        "compatibility_mode": bool(cfg.get("COMPATIBILITY_MODE")),
    }


def _apply_settings(settings: Dict[str, Any]) -> None:
    current_app.config.update(
        VERBOSE=bool(settings.get("verbose")),
        VERBOSE_OBFUSCATION=bool(settings.get("verbose_obfuscation")),
        REASONING_EFFORT=settings.get("reasoning_effort") or "medium",
        REASONING_SUMMARY=settings.get("reasoning_summary") or "auto",
        REASONING_COMPAT=settings.get("reasoning_compat") or "think-tags",
        DEBUG_MODEL=settings.get("debug_model") or None,
        EXPOSE_REASONING_MODELS=bool(settings.get("expose_reasoning_models")),
        DEFAULT_WEB_SEARCH=bool(settings.get("enable_web_search")),
        COMPATIBILITY_MODE=bool(settings.get("compatibility_mode")),
    )


def _parse_iso8601(value: str) -> datetime | None:
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _format_duration(seconds: int) -> str:
    seconds = max(0, int(seconds))
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, remainder = divmod(remainder, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if not parts:
        parts.append(f"{remainder}s")
    return " ".join(parts)


def _auth_context(error: str | None = None) -> Dict[str, Any]:
    home_dir = get_home_dir()
    store = load_store(home_dir)
    accounts = store.get("accounts") if isinstance(store, dict) else []
    active_account_id = store.get("active_account_id") if isinstance(store, dict) else ""
    strategy = (os.getenv("CHATMOCK_ACCOUNT_STRATEGY") or os.getenv("CHATGPT_LOCAL_ACCOUNT_STRATEGY") or "").strip().lower()
    is_round_robin = strategy in ("round_robin", "round-robin", "rr")
    active_account = get_account(store, active_account_id) if isinstance(store, dict) else None
    has_tokens = bool((active_account or {}).get("tokens", {}).get("access_token"))
    if not has_tokens:
        auth = read_auth_file() or {}
        has_tokens = bool((auth.get("tokens") or {}).get("access_token"))
    flow = oauth_flow.load_flow(home_dir)
    if flow and not oauth_flow.flow_is_valid(flow):
        oauth_flow.delete_flow(home_dir)
        flow = None

    flow_expires_in = None
    if flow:
        try:
            created_at = float(flow.get("created_at") or 0)
            remaining = int(oauth_flow.FLOW_TTL_SECONDS - (time.time() - created_at))
            flow_expires_in = max(0, remaining)
        except Exception:
            flow_expires_in = "未知"

    now = datetime.now(timezone.utc)
    decorated_accounts = []
    for acc in accounts if isinstance(accounts, list) else []:
        if not isinstance(acc, dict):
            continue
        entry = dict(acc)
        cooldown_until = entry.get("cooldown_until")
        cooldown_dt = _parse_iso8601(cooldown_until) if isinstance(cooldown_until, str) else None
        if cooldown_dt and cooldown_dt > now:
            entry["cooldown_active"] = True
            entry["cooldown_remaining"] = _format_duration(int((cooldown_dt - now).total_seconds()))
        else:
            entry["cooldown_active"] = False
            entry["cooldown_remaining"] = ""
        decorated_accounts.append(entry)

    return {
        "has_tokens": has_tokens,
        "home_dir": home_dir,
        "flow": flow,
        "flow_expires_in": flow_expires_in,
        "error": error,
        "accounts": decorated_accounts,
        "active_account_id": active_account_id or "",
        "account_strategy": strategy or "default",
        "is_round_robin": is_round_robin,
    }


@admin_bp.before_request
def _guard():
    _require_admin_enabled()


@admin_bp.after_request
def _no_store(resp: Response) -> Response:
    resp.headers.setdefault("Cache-Control", "no-store")
    resp.headers.setdefault("Pragma", "no-cache")
    resp.headers.setdefault("Expires", "0")
    return resp


@admin_bp.get("/login")
def login_page() -> Response:
    return make_response(render_template("admin_login.html", error=None))


@admin_bp.post("/login")
def login_post() -> Response:
    pw = _admin_password() or ""
    submitted = (request.form.get("password") or "").strip()
    if submitted and submitted == pw:
        session["chatmock_admin"] = True
        return redirect(url_for("admin.panel"))
    return make_response(render_template("admin_login.html", error="密码不正确"))


@admin_bp.post("/logout")
def logout_post() -> Response:
    session.pop("chatmock_admin", None)
    return redirect(url_for("admin.login_page"))


@admin_bp.get("/")
def panel() -> Response:
    if not session.get("chatmock_admin"):
        return redirect(url_for("admin.login_page"))

    saved = load_settings()
    current = _current_settings()
    home_dir = get_home_dir()
    auth_ctx = _auth_context()
    keys_store = load_api_keys()
    keys = attach_usage(list_keys(keys_store))
    generated = session.pop("generated_key", None)
    keys_enabled = bool(env_keys() or keys)

    auth_error = session.pop("auth_error", None) or auth_ctx.get("error")
    key_error = session.pop("key_error", None)

    return make_response(
        "admin_panel.html",
        current=current,
        saved={**DEFAULT_SETTINGS, **saved},
        valid_efforts=sorted(VALID_REASONING_EFFORT),
        valid_summaries=sorted(VALID_REASONING_SUMMARY),
        valid_compats=sorted(VALID_REASONING_COMPAT),
        home_dir=home_dir,
        has_tokens=auth_ctx.get("has_tokens"),
        flow=auth_ctx.get("flow"),
        flow_expires_in=auth_ctx.get("flow_expires_in"),
        accounts=auth_ctx.get("accounts"),
        active_account_id=auth_ctx.get("active_account_id"),
        account_strategy=auth_ctx.get("account_strategy"),
        auth_error=auth_error,
        api_keys_enabled=keys_enabled,
        keys=keys,
        generated_key=generated,
        key_error=key_error,
    )


@admin_bp.post("/settings")
def update_settings_form() -> Response:
    if not session.get("chatmock_admin"):
        return redirect(url_for("admin.login_page"))

    def _get_bool(name: str) -> bool:
        return (request.form.get(name) or "").strip().lower() in ("1", "true", "yes", "on")

    payload: Dict[str, Any] = {
        "verbose": _get_bool("verbose"),
        "verbose_obfuscation": _get_bool("verbose_obfuscation"),
        "reasoning_effort": (request.form.get("reasoning_effort") or "").strip().lower(),
        "reasoning_summary": (request.form.get("reasoning_summary") or "").strip().lower(),
        "reasoning_compat": (request.form.get("reasoning_compat") or "").strip().lower(),
        "debug_model": (request.form.get("debug_model") or "").strip() or None,
        "expose_reasoning_models": _get_bool("expose_reasoning_models"),
        "enable_web_search": _get_bool("enable_web_search"),
        "compatibility_mode": _get_bool("compatibility_mode"),
    }

    if payload["reasoning_effort"] not in VALID_REASONING_EFFORT:
        payload["reasoning_effort"] = DEFAULT_SETTINGS["reasoning_effort"]
    if payload["reasoning_summary"] not in VALID_REASONING_SUMMARY:
        payload["reasoning_summary"] = DEFAULT_SETTINGS["reasoning_summary"]
    if payload["reasoning_compat"] not in VALID_REASONING_COMPAT:
        payload["reasoning_compat"] = DEFAULT_SETTINGS["reasoning_compat"]

    _apply_settings(payload)
    save_settings(payload)
    return redirect(url_for("admin.panel"))


@admin_bp.post("/settings/reset")
def reset_settings_form() -> Response:
    if not session.get("chatmock_admin"):
        return redirect(url_for("admin.login_page"))

    path = os.path.join(get_home_dir(), "server_settings.json")
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass

    _apply_settings(DEFAULT_SETTINGS)
    return redirect(url_for("admin.panel"))


@admin_bp.get("/auth")
def auth_page() -> Response:
    if not session.get("chatmock_admin"):
        return redirect(url_for("admin.login_page"))

    return redirect(url_for("admin.panel"))


@admin_bp.post("/auth/start")
def auth_start() -> Response:
    if not session.get("chatmock_admin"):
        return redirect(url_for("admin.login_page"))

    home_dir = get_home_dir()
    flow = oauth_flow.create_flow()
    oauth_flow.save_flow(home_dir, flow)
    return redirect(url_for("admin.auth_page"))


def _parse_callback_input(raw: str) -> tuple[str | None, str | None]:
    if not raw:
        return None, None
    if "://" in raw:
        parsed = urllib.parse.urlparse(raw)
        query = urllib.parse.parse_qs(parsed.query)
    else:
        query = urllib.parse.parse_qs(raw)
    code = (query.get("code") or [None])[0]
    state = (query.get("state") or [None])[0]
    if not code and "code=" not in raw and "state=" not in raw:
        code = raw
    return code, state


@admin_bp.post("/auth/complete")
def auth_complete() -> Response:
    if not session.get("chatmock_admin"):
        return redirect(url_for("admin.login_page"))

    callback_url = (request.form.get("callback_url") or "").strip()
    if not callback_url:
        session["auth_error"] = "请粘贴完整回调 URL 或 code"
        return redirect(url_for("admin.panel"))

    home_dir = get_home_dir()
    flow = oauth_flow.load_flow(home_dir)
    if not flow or not oauth_flow.flow_is_valid(flow):
        session["auth_error"] = "授权链接已过期，请重新生成"
        return redirect(url_for("admin.panel"))

    code, state = _parse_callback_input(callback_url)
    if not code:
        session["auth_error"] = "回调 URL 中未找到 code"
        return redirect(url_for("admin.panel"))

    flow_state = flow.get("state")
    if flow_state and not state:
        session["auth_error"] = "回调 URL 缺少 state"
        return redirect(url_for("admin.panel"))
    if flow_state and state != flow_state:
        session["auth_error"] = "state 不匹配，请重新生成授权链接"
        return redirect(url_for("admin.panel"))

    try:
        bundle = oauth_flow.exchange_code(flow, code)
    except Exception as exc:
        session["auth_error"] = f"令牌交换失败：{exc}"
        return redirect(url_for("admin.panel"))

    auth_json_contents = {
        "OPENAI_API_KEY": bundle.api_key,
        "tokens": {
            "id_token": bundle.token_data.id_token,
            "access_token": bundle.token_data.access_token,
            "refresh_token": bundle.token_data.refresh_token,
            "account_id": bundle.token_data.account_id,
        },
        "last_refresh": bundle.last_refresh,
    }
    account = account_from_auth_json(auth_json_contents)
    if account:
        store = load_store(home_dir) or {"accounts": []}
        store = upsert_account(store, account)
        store = set_active(store, account.get("account_id"))
        if not save_store(store, home_dir):
            session["auth_error"] = "写入 auth_store 失败"
            return redirect(url_for("admin.panel"))
        write_active_auth(store, account.get("account_id"))
    else:
        if not write_auth_file(auth_json_contents):
            session["auth_error"] = "写入 auth.json 失败"
            return redirect(url_for("admin.panel"))

    oauth_flow.delete_flow(home_dir)
    return redirect(url_for("admin.panel"))


@admin_bp.post("/auth/upload")
def auth_upload() -> Response:
    if not session.get("chatmock_admin"):
        return redirect(url_for("admin.login_page"))

    def _parse_payloads(raw: str) -> List[Dict[str, Any]]:
        try:
            data = json.loads(raw) if raw else None
        except Exception:
            return []
        if isinstance(data, dict):
            return [data]
        if isinstance(data, list):
            return [d for d in data if isinstance(d, dict)]
        return []

    payloads: List[Dict[str, Any]] = []
    files = request.files.getlist("auth_file")
    for file in files:
        if not file or not getattr(file, "filename", ""):
            continue
        raw = b""
        try:
            raw = file.read()
            content = raw.decode("utf-8-sig", errors="strict")
        except Exception:
            try:
                content = raw.decode("utf-8", errors="ignore")
            except Exception:
                content = ""
        payloads.extend(_parse_payloads(content))

    if not payloads:
        content = (request.form.get("auth_json") or "").strip()
        payloads = _parse_payloads(content)

    if not payloads:
        session["auth_error"] = "auth.json 解析失败，请确认文件格式"
        return redirect(url_for("admin.panel"))

    home_dir = get_home_dir()
    store = load_store(home_dir) or {"accounts": []}
    imported = 0
    for parsed in payloads:
        account = account_from_auth_json(parsed)
        if not account:
            continue
        store = upsert_account(store, account)
        store = set_active(store, account.get("account_id"))
        imported += 1

    if not imported:
        session["auth_error"] = "auth.json 未包含有效账号信息（需要含 id_token 或 account_id）"
        return redirect(url_for("admin.panel"))

    if not save_store(store, home_dir):
        session["auth_error"] = "写入 auth_store 失败"
        return redirect(url_for("admin.panel"))
    write_active_auth(store, store.get("active_account_id"))

    return redirect(url_for("admin.panel"))


@admin_bp.post("/auth/clear")
def auth_clear() -> Response:
    if not session.get("chatmock_admin"):
        return redirect(url_for("admin.login_page"))

    path = os.path.join(get_home_dir(), "auth.json")
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass
    oauth_flow.delete_flow(get_home_dir())
    return redirect(url_for("admin.panel"))


@admin_bp.post("/auth/activate")
def auth_activate() -> Response:
    if not session.get("chatmock_admin"):
        return redirect(url_for("admin.login_page"))
    account_id = (request.form.get("account_id") or "").strip()
    home_dir = get_home_dir()
    store = load_store(home_dir) or {"accounts": []}
    store = set_active(store, account_id)
    save_store(store, home_dir)
    write_active_auth(store, account_id)
    return redirect(url_for("admin.panel"))


@admin_bp.post("/auth/delete")
def auth_delete() -> Response:
    if not session.get("chatmock_admin"):
        return redirect(url_for("admin.login_page"))
    account_id = (request.form.get("account_id") or "").strip()
    home_dir = get_home_dir()
    store = load_store(home_dir) or {"accounts": []}
    store = delete_account(store, account_id)
    save_store(store, home_dir)
    write_active_auth(store)
    return redirect(url_for("admin.panel"))


@admin_bp.get("/keys")
def keys_page() -> Response:
    if not session.get("chatmock_admin"):
        return redirect(url_for("admin.login_page"))
    return redirect(url_for("admin.panel"))


@admin_bp.post("/keys/add")
def keys_add() -> Response:
    if not session.get("chatmock_admin"):
        return redirect(url_for("admin.login_page"))
    label = (request.form.get("label") or "").strip() or "key"
    raw_key = (request.form.get("api_key") or "").strip()
    def _parse_limit(name: str) -> int | None | str:
        raw = (request.form.get(name) or "").strip()
        if not raw:
            return None
        try:
            val = int(raw)
        except Exception:
            return "__error__"
        return val if val > 0 else None

    total = _parse_limit("limit_total")
    daily = _parse_limit("limit_daily")
    if "__error__" in (total, daily):
        session["key_error"] = "限额必须是正整数（留空=不限）"
        return redirect(url_for("admin.panel"))

    if not raw_key:
        raw_key = secrets.token_urlsafe(24)
        session["generated_key"] = raw_key
    store = load_api_keys()
    store = add_key(
        store,
        raw_key,
        label,
        limits={"total": total, "daily": daily},
    )
    if not save_api_keys(store):
        session["key_error"] = "保存 API Key 失败"
        return redirect(url_for("admin.panel"))
    return redirect(url_for("admin.panel"))


@admin_bp.post("/keys/delete")
def keys_delete() -> Response:
    if not session.get("chatmock_admin"):
        return redirect(url_for("admin.login_page"))
    key_id = (request.form.get("id") or "").strip()
    store = load_api_keys()
    store = delete_api_key(store, key_id)
    save_api_keys(store)
    return redirect(url_for("admin.panel"))


@admin_bp.post("/keys/update")
def keys_update() -> Response:
    if not session.get("chatmock_admin"):
        return redirect(url_for("admin.login_page"))

    def _parse_limit(name: str) -> int | None | str:
        raw = (request.form.get(name) or "").strip()
        if not raw:
            return None
        try:
            val = int(raw)
        except Exception:
            return "__error__"
        return val if val > 0 else None

    key_id = (request.form.get("id") or "").strip()
    label = (request.form.get("label") or "").strip()
    raw_key = (request.form.get("api_key") or "").strip()
    total = _parse_limit("limit_total")
    daily = _parse_limit("limit_daily")
    if "__error__" in (total, daily):
        session["key_error"] = "限额必须是正整数（留空=不限）"
        return redirect(url_for("admin.panel"))

    store = load_api_keys()
    old_limits = {}
    for k in list_keys(store):
        if k.get("id") == key_id:
            old_limits = k.get("limits") or {}
            break
    old_total = old_limits.get("total")
    old_daily = old_limits.get("daily")
    store = update_key(
        store,
        key_id,
        label=label or None,
        raw_key=raw_key or None,
        limits={"total": total, "daily": daily},
    )
    save_api_keys(store)
    if total != old_total or daily != old_daily:
        reset_usage(key_id)
    return redirect(url_for("admin.panel"))


@admin_bp.post("/keys/reset-usage")
def keys_reset_usage() -> Response:
    if not session.get("chatmock_admin"):
        return redirect(url_for("admin.login_page"))
    reset_usage()
    return redirect(url_for("admin.panel"))


@admin_bp.get("/api/settings")
def api_get_settings() -> Response:
    _require_api_auth()
    return jsonify({"saved": {**DEFAULT_SETTINGS, **load_settings()}, "current": _current_settings()})


@admin_bp.post("/api/settings")
def api_set_settings() -> Response:
    _require_api_auth()
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        abort(400)
    merged = {**DEFAULT_SETTINGS, **payload}
    # Reuse the on-disk sanitizer.
    save_settings(merged)
    effective = {**DEFAULT_SETTINGS, **load_settings()}
    _apply_settings(effective)
    return jsonify({"ok": True, "settings": effective})
