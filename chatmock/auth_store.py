from __future__ import annotations

import datetime
import json
import os
import threading
from typing import Any, Dict, List, Optional

from .utils import get_home_dir, parse_jwt_claims, write_auth_file


STORE_FILENAME = "auth_store.json"
_RR_LOCK = threading.Lock()
_RR_COUNTER = 0


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def store_path(home_dir: str | None = None) -> str:
    home = home_dir or get_home_dir()
    return os.path.join(home, STORE_FILENAME)


def _normalize_store(store: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(store.get("accounts"), list):
        store["accounts"] = []
    if not isinstance(store.get("active_account_id"), str):
        store["active_account_id"] = ""
    return store


def _parse_iso8601(value: str) -> datetime.datetime | None:
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        dt = datetime.datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt.astimezone(datetime.timezone.utc)
    except Exception:
        return None


def _cooldown_until(account: Dict[str, Any]) -> datetime.datetime | None:
    raw = account.get("cooldown_until")
    if isinstance(raw, str) and raw:
        return _parse_iso8601(raw)
    return None


def _has_tokens(account: Dict[str, Any]) -> bool:
    tokens = account.get("tokens") if isinstance(account.get("tokens"), dict) else {}
    return bool(tokens.get("access_token") or tokens.get("refresh_token"))


def is_account_available(account: Dict[str, Any], now: datetime.datetime | None = None) -> bool:
    now = now or datetime.datetime.now(datetime.timezone.utc)
    cooldown = _cooldown_until(account)
    if cooldown and cooldown > now:
        return False
    return True


def _collect_available_accounts(store: Dict[str, Any], now: datetime.datetime | None = None) -> List[Dict[str, Any]]:
    store = _normalize_store(store)
    now = now or datetime.datetime.now(datetime.timezone.utc)
    accounts = store.get("accounts") or []
    usable: List[Dict[str, Any]] = []
    for account in accounts:
        if not isinstance(account, dict):
            continue
        account_id = account.get("account_id")
        if not isinstance(account_id, str) or not account_id:
            continue
        if not _has_tokens(account):
            continue
        if not is_account_available(account, now):
            continue
        usable.append(account)
    if len(usable) > 1:
        usable.sort(key=lambda a: a.get("account_id") or "")
    return usable


def earliest_cooldown(store: Dict[str, Any], now: datetime.datetime | None = None) -> datetime.datetime | None:
    store = _normalize_store(store)
    now = now or datetime.datetime.now(datetime.timezone.utc)
    earliest: datetime.datetime | None = None
    for account in store.get("accounts") or []:
        if not isinstance(account, dict):
            continue
        cooldown = _cooldown_until(account)
        if not cooldown or cooldown <= now:
            continue
        if earliest is None or cooldown < earliest:
            earliest = cooldown
    return earliest


def pick_round_robin_account(store: Dict[str, Any]) -> Dict[str, Any] | None:
    """
    Pick the next account in a process-local round-robin sequence.

    This does NOT modify the on-disk store or active account; it only selects
    an account for the current request.
    """
    usable = _collect_available_accounts(store)
    if not usable:
        return None

    global _RR_COUNTER
    with _RR_LOCK:
        idx = _RR_COUNTER % len(usable)
        _RR_COUNTER += 1
    return usable[idx]


def pick_first_available_account(store: Dict[str, Any], preferred_id: str | None = None) -> Dict[str, Any] | None:
    store = _normalize_store(store)
    now = datetime.datetime.now(datetime.timezone.utc)
    if preferred_id:
        preferred = get_account(store, preferred_id)
        if isinstance(preferred, dict) and _has_tokens(preferred) and is_account_available(preferred, now):
            return preferred
    available = _collect_available_accounts(store, now)
    return available[0] if available else None


def _next_quota_backoff(prev_level: int) -> tuple[int, int]:
    base = 1
    max_seconds = 30 * 60
    cooldown = base * (2 ** max(0, prev_level))
    if cooldown < base:
        cooldown = base
    if cooldown >= max_seconds:
        return max_seconds, prev_level
    return cooldown, prev_level + 1


def mark_account_success(store: Dict[str, Any], account_id: str) -> Dict[str, Any]:
    store = _normalize_store(store)
    for account in store.get("accounts") or []:
        if not isinstance(account, dict):
            continue
        if account.get("account_id") != account_id:
            continue
        account["cooldown_until"] = ""
        account["backoff_level"] = 0
        account["last_error_code"] = None
        account["last_error_message"] = ""
        account["last_error_at"] = ""
        account["last_success_at"] = _now_iso()
        break
    return store


def mark_account_failure(
    store: Dict[str, Any],
    account_id: str,
    status_code: int | None,
    *,
    retry_after_seconds: int | None = None,
    message: str | None = None,
) -> Dict[str, Any]:
    store = _normalize_store(store)
    now = datetime.datetime.now(datetime.timezone.utc)
    for account in store.get("accounts") or []:
        if not isinstance(account, dict):
            continue
        if account.get("account_id") != account_id:
            continue
        cooldown_seconds = 0
        backoff_level = int(account.get("backoff_level") or 0)
        if status_code == 429:
            if isinstance(retry_after_seconds, int) and retry_after_seconds > 0:
                cooldown_seconds = retry_after_seconds
            else:
                cooldown_seconds, backoff_level = _next_quota_backoff(backoff_level)
        elif status_code in (401, 403):
            cooldown_seconds = 30 * 60
            backoff_level = 0
        elif status_code == 404:
            cooldown_seconds = 12 * 60 * 60
            backoff_level = 0
        elif status_code in (408, 500, 502, 503, 504):
            cooldown_seconds = 60
            backoff_level = 0

        if cooldown_seconds > 0:
            account["cooldown_until"] = (now + datetime.timedelta(seconds=cooldown_seconds)).isoformat().replace("+00:00", "Z")
        account["backoff_level"] = backoff_level
        account["last_error_code"] = status_code
        account["last_error_message"] = message or ""
        account["last_error_at"] = _now_iso()
        break
    return store


def record_account_result(
    account_id: str | None,
    *,
    success: bool,
    status_code: int | None = None,
    retry_after_seconds: int | None = None,
    message: str | None = None,
    home_dir: str | None = None,
) -> bool:
    if not account_id:
        return False
    store = load_store(home_dir) or {"accounts": []}
    if success:
        store = mark_account_success(store, account_id)
    else:
        store = mark_account_failure(
            store,
            account_id,
            status_code,
            retry_after_seconds=retry_after_seconds,
            message=message,
        )
    return save_store(store, home_dir)


def load_store(home_dir: str | None = None) -> Dict[str, Any] | None:
    path = store_path(home_dir)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return _normalize_store(data)
    except FileNotFoundError:
        return None
    except Exception:
        return None
    return None


def save_store(store: Dict[str, Any], home_dir: str | None = None) -> bool:
    home = home_dir or get_home_dir()
    path = store_path(home)
    try:
        os.makedirs(home, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(_normalize_store(store), f, indent=2)
        return True
    except Exception:
        return False


def _account_id_from_tokens(tokens: Dict[str, Any]) -> str | None:
    account_id = tokens.get("account_id")
    if isinstance(account_id, str) and account_id:
        return account_id
    id_token = tokens.get("id_token")
    if isinstance(id_token, str) and id_token:
        claims = parse_jwt_claims(id_token) or {}
        auth_claims = claims.get("https://api.openai.com/auth") if isinstance(claims, dict) else None
        if isinstance(auth_claims, dict):
            derived = auth_claims.get("chatgpt_account_id")
            if isinstance(derived, str) and derived:
                return derived
    return None


def _label_from_tokens(tokens: Dict[str, Any]) -> str:
    id_token = tokens.get("id_token")
    if isinstance(id_token, str) and id_token:
        claims = parse_jwt_claims(id_token) or {}
        email = claims.get("email") if isinstance(claims, dict) else None
        if isinstance(email, str) and email:
            return email
    account_id = tokens.get("account_id")
    if isinstance(account_id, str) and account_id:
        return account_id
    return "account"


def normalize_auth_json(auth: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(auth, dict):
        return {}
    tokens = auth.get("tokens") if isinstance(auth.get("tokens"), dict) else None
    if isinstance(tokens, dict):
        return auth
    flat_tokens: Dict[str, Any] = {}
    for key in ("id_token", "access_token", "refresh_token", "account_id"):
        value = auth.get(key)
        if isinstance(value, str) and value:
            flat_tokens[key] = value
    if flat_tokens:
        normalized = dict(auth)
        normalized["tokens"] = flat_tokens
        return normalized
    return auth


def account_from_auth_json(auth: Dict[str, Any]) -> Dict[str, Any] | None:
    auth = normalize_auth_json(auth)
    tokens = auth.get("tokens") if isinstance(auth.get("tokens"), dict) else {}
    if not isinstance(tokens, dict):
        return None
    account_id = _account_id_from_tokens(tokens)
    if not account_id:
        return None
    label = auth.get("label") if isinstance(auth.get("label"), str) else None
    if not label:
        label = _label_from_tokens(tokens)
    return {
        "account_id": account_id,
        "label": label,
        "tokens": tokens,
        "last_refresh": auth.get("last_refresh") or _now_iso(),
        "created_at": auth.get("created_at") or _now_iso(),
        "api_key": auth.get("OPENAI_API_KEY") if isinstance(auth.get("OPENAI_API_KEY"), str) else None,
    }


def upsert_account(store: Dict[str, Any], account: Dict[str, Any]) -> Dict[str, Any]:
    store = _normalize_store(store)
    account_id = account.get("account_id")
    if not isinstance(account_id, str) or not account_id:
        return store
    accounts = store.get("accounts") or []
    updated = False
    for idx, existing in enumerate(accounts):
        if isinstance(existing, dict) and existing.get("account_id") == account_id:
            accounts[idx] = {**existing, **account}
            updated = True
            break
    if not updated:
        accounts.append(account)
    store["accounts"] = accounts
    if not store.get("active_account_id"):
        store["active_account_id"] = account_id
    return store


def delete_account(store: Dict[str, Any], account_id: str) -> Dict[str, Any]:
    store = _normalize_store(store)
    accounts = store.get("accounts") or []
    accounts = [a for a in accounts if not (isinstance(a, dict) and a.get("account_id") == account_id)]
    store["accounts"] = accounts
    if store.get("active_account_id") == account_id:
        store["active_account_id"] = accounts[0].get("account_id") if accounts else ""
    return store


def get_account(store: Dict[str, Any], account_id: str | None = None) -> Dict[str, Any] | None:
    store = _normalize_store(store)
    accounts = store.get("accounts") or []
    if account_id:
        for account in accounts:
            if isinstance(account, dict) and account.get("account_id") == account_id:
                return account
    active_id = store.get("active_account_id")
    if isinstance(active_id, str) and active_id:
        for account in accounts:
            if isinstance(account, dict) and account.get("account_id") == active_id:
                return account
    return accounts[0] if accounts else None


def set_active(store: Dict[str, Any], account_id: str) -> Dict[str, Any]:
    store = _normalize_store(store)
    if any(isinstance(a, dict) and a.get("account_id") == account_id for a in store.get("accounts", [])):
        store["active_account_id"] = account_id
    return store


def write_active_auth(store: Dict[str, Any], account_id: str | None = None) -> bool:
    account = get_account(store, account_id)
    if not account:
        return False
    tokens = account.get("tokens") if isinstance(account.get("tokens"), dict) else {}
    auth_json = {
        "OPENAI_API_KEY": account.get("api_key"),
        "tokens": tokens,
        "last_refresh": account.get("last_refresh") or _now_iso(),
    }
    return write_auth_file(auth_json)
