from __future__ import annotations

import datetime
import json
import os
import secrets
import ssl
import time
import urllib.parse
import urllib.request
from typing import Any, Dict, Tuple

import certifi

from .config import CLIENT_ID_DEFAULT, OAUTH_ISSUER_DEFAULT
from .models import AuthBundle, TokenData
from .utils import generate_pkce, parse_jwt_claims


FLOW_FILENAME = "auth_flow.json"
FLOW_TTL_SECONDS = 15 * 60

_SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())


def _token_endpoint(issuer: str) -> str:
    return f"{issuer}/oauth/token"


def flow_path(home_dir: str) -> str:
    return os.path.join(home_dir, FLOW_FILENAME)


def load_flow(home_dir: str) -> Dict[str, Any] | None:
    path = flow_path(home_dir)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except FileNotFoundError:
        return None
    except Exception:
        return None


def save_flow(home_dir: str, data: Dict[str, Any]) -> None:
    os.makedirs(home_dir, exist_ok=True)
    path = flow_path(home_dir)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def delete_flow(home_dir: str) -> None:
    path = flow_path(home_dir)
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass


def create_flow(
    *,
    client_id: str | None = None,
    issuer: str | None = None,
    redirect_uri: str | None = None,
) -> Dict[str, Any]:
    client_id = client_id or CLIENT_ID_DEFAULT
    issuer = issuer or OAUTH_ISSUER_DEFAULT
    redirect_uri = redirect_uri or "http://localhost:1455/auth/callback"
    pkce = generate_pkce()
    state = secrets.token_hex(32)
    created_at = time.time()
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid profile email offline_access",
        "code_challenge": pkce.code_challenge,
        "code_challenge_method": "S256",
        "id_token_add_organizations": "true",
        "codex_cli_simplified_flow": "true",
        "state": state,
    }
    auth_url = f"{issuer}/oauth/authorize?" + urllib.parse.urlencode(params)
    return {
        "client_id": client_id,
        "issuer": issuer,
        "redirect_uri": redirect_uri,
        "state": state,
        "code_verifier": pkce.code_verifier,
        "code_challenge": pkce.code_challenge,
        "created_at": created_at,
        "auth_url": auth_url,
    }


def flow_is_valid(flow: Dict[str, Any]) -> bool:
    try:
        created_at = float(flow.get("created_at") or 0)
    except Exception:
        return False
    return (time.time() - created_at) <= FLOW_TTL_SECONDS


def _maybe_obtain_api_key(
    issuer: str,
    client_id: str,
    token_data: TokenData,
    token_claims: Dict[str, Any],
    access_claims: Dict[str, Any],
) -> str | None:
    org_id = token_claims.get("organization_id")
    project_id = token_claims.get("project_id")
    if not org_id or not project_id:
        return None

    exchange_data = urllib.parse.urlencode(
        {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "client_id": client_id,
            "requested_token": "openai-api-key",
            "subject_token": token_data.id_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
            "name": f"ChatGPT Local [auto-generated] ({datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d')})",
        }
    ).encode()

    with urllib.request.urlopen(
        urllib.request.Request(
            _token_endpoint(issuer),
            data=exchange_data,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        ),
        context=_SSL_CONTEXT,
    ) as resp:
        payload = json.loads(resp.read().decode())
    return payload.get("access_token")


def exchange_code(flow: Dict[str, Any], code: str) -> AuthBundle:
    issuer = flow.get("issuer") or OAUTH_ISSUER_DEFAULT
    client_id = flow.get("client_id") or CLIENT_ID_DEFAULT
    redirect_uri = flow.get("redirect_uri") or "http://localhost:1455/auth/callback"
    code_verifier = flow.get("code_verifier")

    data = urllib.parse.urlencode(
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "code_verifier": code_verifier,
        }
    ).encode()

    with urllib.request.urlopen(
        urllib.request.Request(
            _token_endpoint(issuer),
            data=data,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        ),
        context=_SSL_CONTEXT,
    ) as resp:
        payload = json.loads(resp.read().decode())

    id_token = payload.get("id_token", "")
    access_token = payload.get("access_token", "")
    refresh_token = payload.get("refresh_token", "")

    id_token_claims = parse_jwt_claims(id_token) or {}
    access_token_claims = parse_jwt_claims(access_token) or {}

    auth_claims = (id_token_claims or {}).get("https://api.openai.com/auth", {})
    chatgpt_account_id = auth_claims.get("chatgpt_account_id", "")

    token_data = TokenData(
        id_token=id_token,
        access_token=access_token,
        refresh_token=refresh_token,
        account_id=chatgpt_account_id,
    )

    api_key = _maybe_obtain_api_key(issuer, client_id, token_data, id_token_claims, access_token_claims)

    last_refresh_str = (
        datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    )
    return AuthBundle(api_key=api_key, token_data=token_data, last_refresh=last_refresh_str)

