from __future__ import annotations

import datetime
import hashlib
import json
import os
import secrets
import threading
from typing import Any, Dict, List

from flask import Response, jsonify, make_response, request

from .utils import get_home_dir


STORE_FILENAME = "api_keys.json"
USAGE_FILENAME = "api_keys_usage.json"
_USAGE_STATE: Dict[str, Dict[str, Any]] = {}
_USAGE_LOADED = False
_USAGE_LOCK = threading.Lock()


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def _secret() -> str:
    secret = os.getenv("CHATMOCK_SECRET_KEY")
    if isinstance(secret, str) and secret.strip():
        return secret.strip()
    return ""


def _hash_key(raw: str) -> str:
    data = (_secret() + raw).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _parse_limit(value: Any) -> int | None:
    if value is None:
        return None
    try:
        parsed = int(value)
    except Exception:
        return None
    return parsed if parsed > 0 else None


def normalize_limits(raw: Dict[str, Any] | None) -> Dict[str, int | None]:
    raw = raw if isinstance(raw, dict) else {}
    return {
        "total": _parse_limit(raw.get("total")),
        "daily": _parse_limit(raw.get("daily")),
    }


def store_path(home_dir: str | None = None) -> str:
    home = home_dir or get_home_dir()
    return os.path.join(home, STORE_FILENAME)


def usage_path(home_dir: str | None = None) -> str:
    home = home_dir or get_home_dir()
    return os.path.join(home, USAGE_FILENAME)


def _normalize_usage_state(state: Dict[str, Any] | None) -> Dict[str, Any]:
    state = state if isinstance(state, dict) else {}
    total = int(state.get("total_count") or 0)
    day_count = int(state.get("day_count") or 0)
    day = state.get("day") if isinstance(state.get("day"), str) else None
    return {
        "total_count": max(0, total),
        "day": day,
        "day_count": max(0, day_count),
    }


def _load_usage_state() -> None:
    global _USAGE_LOADED
    if _USAGE_LOADED:
        return
    _USAGE_LOADED = True
    path = usage_path()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            keys = data.get("keys")
            if isinstance(keys, dict):
                for key_id, state in keys.items():
                    if isinstance(key_id, str):
                        _USAGE_STATE[key_id] = _normalize_usage_state(state)
    except FileNotFoundError:
        return
    except Exception:
        return


def _save_usage_state() -> None:
    home = get_home_dir()
    path = usage_path(home)
    try:
        os.makedirs(home, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"keys": _USAGE_STATE}, f, indent=2)
    except Exception:
        return


def load_api_keys(home_dir: str | None = None) -> Dict[str, Any]:
    path = store_path(home_dir)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return {"keys": []}


def save_api_keys(store: Dict[str, Any], home_dir: str | None = None) -> bool:
    home = home_dir or get_home_dir()
    path = store_path(home)
    try:
        os.makedirs(home, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(store, f, indent=2)
        return True
    except Exception:
        return False


def list_keys(store: Dict[str, Any]) -> List[Dict[str, Any]]:
    keys = store.get("keys")
    if not isinstance(keys, list):
        return []
    normalized = []
    for k in keys:
        if not isinstance(k, dict):
            continue
        k = dict(k)
        if "raw" not in k:
            k["raw"] = ""
        k["limits"] = normalize_limits(k.get("limits"))
        normalized.append(k)
    return normalized


def add_key(
    store: Dict[str, Any],
    raw_key: str,
    label: str | None = None,
    limits: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    raw_key = raw_key.strip()
    key_id = secrets.token_hex(8)
    entry = {
        "id": key_id,
        "label": label or "key",
        "raw": raw_key,
        "hash": _hash_key(raw_key),
        "last4": raw_key[-4:] if len(raw_key) >= 4 else raw_key,
        "created_at": _now_iso(),
        "limits": normalize_limits(limits),
    }
    keys = list_keys(store)
    keys.append(entry)
    store["keys"] = keys
    return store


def update_key(
    store: Dict[str, Any],
    key_id: str,
    *,
    label: str | None = None,
    raw_key: str | None = None,
    limits: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    keys = list_keys(store)
    updated = []
    for k in keys:
        if k.get("id") != key_id:
            updated.append(k)
            continue
        entry = dict(k)
        if isinstance(label, str) and label.strip():
            entry["label"] = label.strip()
        if isinstance(raw_key, str) and raw_key.strip():
            entry["raw"] = raw_key.strip()
            entry["hash"] = _hash_key(entry["raw"])
            entry["last4"] = entry["raw"][-4:] if len(entry["raw"]) >= 4 else entry["raw"]
        if limits is not None:
            entry["limits"] = normalize_limits(limits)
        updated.append(entry)
    store["keys"] = updated
    return store


def delete_key(store: Dict[str, Any], key_id: str) -> Dict[str, Any]:
    keys = list_keys(store)
    store["keys"] = [k for k in keys if k.get("id") != key_id]
    return store


def update_key_limits(store: Dict[str, Any], key_id: str, limits: Dict[str, Any]) -> Dict[str, Any]:
    return update_key(store, key_id, limits=limits)


def env_keys() -> List[str]:
    raw = os.getenv("CHATMOCK_API_KEYS", "")
    if not isinstance(raw, str) or not raw.strip():
        return []
    return [k.strip() for k in raw.split(",") if k.strip()]


def _extract_token() -> str:
    header = request.headers.get("Authorization", "")
    token = ""
    if isinstance(header, str) and header.lower().startswith("bearer "):
        token = header[7:].strip()
    if not token:
        token = (request.headers.get("X-API-Key") or "").strip()
    return token


def _find_key_entry(token: str, store: Dict[str, Any]) -> Dict[str, Any] | None:
    if not token:
        return None
    if token in env_keys():
        return None
    hashed = _hash_key(token)
    for k in list_keys(store):
        if k.get("hash") == hashed:
            return k
    return None


def verify_token(token: str, store: Dict[str, Any]) -> bool:
    if not token:
        return False
    if token in env_keys():
        return True
    return _find_key_entry(token, store) is not None


def _get_usage_state(key_id: str) -> Dict[str, Any]:
    _load_usage_state()
    state = _USAGE_STATE.get(key_id)
    if not isinstance(state, dict):
        state = {"total_count": 0, "day": None, "day_count": 0}
        _USAGE_STATE[key_id] = state
    return state


def _check_and_track_limits(entry: Dict[str, Any]) -> tuple[bool, str | None]:
    limits = normalize_limits(entry.get("limits"))

    key_id = entry.get("id") or ""
    if not key_id:
        return True, None

    state = _get_usage_state(key_id)
    now_day = datetime.datetime.now(datetime.timezone.utc).date().isoformat()

    if state.get("day") != now_day:
        state["day"] = now_day
        state["day_count"] = 0

    if limits["total"] is not None and state.get("total_count", 0) >= limits["total"]:
        return False, "Total quota exceeded"
    if limits["daily"] is not None and state["day_count"] >= limits["daily"]:
        return False, "Daily quota exceeded"

    state["total_count"] = int(state.get("total_count", 0)) + 1
    state["day_count"] += 1
    with _USAGE_LOCK:
        _save_usage_state()
    return True, None


def attach_usage(keys: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    _load_usage_state()
    for k in keys:
        key_id = k.get("id") if isinstance(k, dict) else None
        if not isinstance(key_id, str):
            continue
        state = _USAGE_STATE.get(key_id) or {}
        k["usage"] = {
            "total": int(state.get("total_count") or 0),
            "daily": int(state.get("day_count") or 0),
            "day": state.get("day") if isinstance(state.get("day"), str) else None,
        }
    return keys


def reset_usage(key_id: str | None = None) -> None:
    _load_usage_state()
    with _USAGE_LOCK:
        if key_id:
            _USAGE_STATE.pop(key_id, None)
        else:
            _USAGE_STATE.clear()
        _save_usage_state()


def attach_release(resp: Response) -> Response:
    return resp


def require_api_key() -> Response | None:
    keys = env_keys()
    store = load_api_keys()
    has_keys = bool(keys) or bool(list_keys(store))
    if not has_keys:
        return None
    token = _extract_token()
    if not verify_token(token, store):
        resp = make_response(jsonify({"error": {"message": "Invalid API key"}}), 401)
        return resp
    entry = _find_key_entry(token, store)
    if entry:
        allowed, reason = _check_and_track_limits(entry)
        if not allowed:
            resp = make_response(jsonify({"error": {"message": reason}}), 429)
            return resp
    return None
