from __future__ import annotations

import os
import secrets
from flask import Flask, jsonify

from .config import BASE_INSTRUCTIONS, GPT5_CODEX_INSTRUCTIONS
from .http import build_cors_headers
from .settings import DEFAULT_SETTINGS, load_settings
from .api_keys import attach_release
from .routes_openai import openai_bp
from .routes_ollama import ollama_bp
from .admin import admin_bp


def create_app(
    verbose: bool = False,
    verbose_obfuscation: bool = False,
    reasoning_effort: str = "medium",
    reasoning_summary: str = "auto",
    reasoning_compat: str = "think-tags",
    debug_model: str | None = None,
    expose_reasoning_models: bool = False,
    default_web_search: bool = False,
    compatibility_mode: bool = False,
) -> Flask:
    app = Flask(__name__)

    secret = os.getenv("CHATMOCK_SECRET_KEY")
    app.secret_key = secret.strip() if isinstance(secret, str) and secret.strip() else secrets.token_hex(32)

    app.config.update(
        VERBOSE=bool(verbose),
        VERBOSE_OBFUSCATION=bool(verbose_obfuscation),
        REASONING_EFFORT=reasoning_effort,
        REASONING_SUMMARY=reasoning_summary,
        REASONING_COMPAT=reasoning_compat,
        DEBUG_MODEL=debug_model,
        BASE_INSTRUCTIONS=BASE_INSTRUCTIONS,
        GPT5_CODEX_INSTRUCTIONS=GPT5_CODEX_INSTRUCTIONS,
        EXPOSE_REASONING_MODELS=bool(expose_reasoning_models),
        DEFAULT_WEB_SEARCH=bool(default_web_search),
        COMPATIBILITY_MODE=bool(compatibility_mode),
    )

    if (os.getenv("CHATMOCK_ADMIN_PASSWORD") or os.getenv("CHATGPT_LOCAL_ADMIN_PASSWORD")) and not bool(
        (os.getenv("CHATMOCK_DISABLE_ADMIN") or "").strip().lower() in ("1", "true", "yes", "on")
    ):
        app.register_blueprint(admin_bp)

    if not bool((os.getenv("CHATMOCK_DISABLE_SETTINGS") or "").strip().lower() in ("1", "true", "yes", "on")):
        loaded = load_settings()
        if loaded:
            app.config.update(
                **(
                    {"VERBOSE": bool(loaded.get("verbose"))}
                    if "verbose" in loaded
                    else {}
                ),
                **(
                    {"VERBOSE_OBFUSCATION": bool(loaded.get("verbose_obfuscation"))}
                    if "verbose_obfuscation" in loaded
                    else {}
                ),
                **(
                    {"REASONING_EFFORT": loaded.get("reasoning_effort") or reasoning_effort}
                    if "reasoning_effort" in loaded
                    else {}
                ),
                **(
                    {"REASONING_SUMMARY": loaded.get("reasoning_summary") or reasoning_summary}
                    if "reasoning_summary" in loaded
                    else {}
                ),
                **(
                    {"REASONING_COMPAT": loaded.get("reasoning_compat") or reasoning_compat}
                    if "reasoning_compat" in loaded
                    else {}
                ),
                **(
                    {"DEBUG_MODEL": loaded.get("debug_model") or None}
                    if "debug_model" in loaded
                    else {}
                ),
                **(
                    {"EXPOSE_REASONING_MODELS": bool(loaded.get("expose_reasoning_models"))}
                    if "expose_reasoning_models" in loaded
                    else {}
                ),
                **(
                    {"DEFAULT_WEB_SEARCH": bool(loaded.get("enable_web_search"))}
                    if "enable_web_search" in loaded
                    else {}
                ),
                **(
                    {"COMPATIBILITY_MODE": bool(loaded.get("compatibility_mode"))}
                    if "compatibility_mode" in loaded
                    else {}
                ),
            )

    @app.get("/")
    @app.get("/health")
    def health():
        return jsonify({"status": "ok"})

    @app.after_request
    def _cors(resp):
        for k, v in build_cors_headers().items():
            resp.headers.setdefault(k, v)
        return attach_release(resp)

    app.register_blueprint(openai_bp)
    app.register_blueprint(ollama_bp)

    return app
