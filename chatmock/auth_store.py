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


def pick_round_robin_account(store: Dict[str, Any]) -> Dict[str, Any] | None:
    """
    Pick the next account in a process-local round-robin sequence.

    This does NOT modify the on-disk store or active account; it only selects
    an account for the current request.
    """
    store = _normalize_store(store)
    accounts = store.get("accounts") or []
    usable: List[Dict[str, Any]] = []
    for account in accounts:
        if not isinstance(account, dict):
            continue
        account_id = account.get("account_id")
        if not isinstance(account_id, str) or not account_id:
            continue
        tokens = account.get("tokens") if isinstance(account.get("tokens"), dict) else {}
        if not (tokens.get("access_token") or tokens.get("refresh_token")):
            continue
        usable.append(account)

    if not usable:
        return None

    global _RR_COUNTER
    with _RR_LOCK:
        idx = _RR_COUNTER % len(usable)
        _RR_COUNTER += 1
    return usable[idx]


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


def account_from_auth_json(auth: Dict[str, Any]) -> Dict[str, Any] | None:
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
