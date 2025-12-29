from __future__ import annotations

import json
import os
import tempfile
from typing import Any, Dict

from .utils import eprint, get_home_dir


SETTINGS_FILENAME = "server_settings.json"

VALID_REASONING_EFFORT = {"minimal", "low", "medium", "high", "xhigh"}
VALID_REASONING_SUMMARY = {"auto", "concise", "detailed", "none"}
VALID_REASONING_COMPAT = {"legacy", "o3", "think-tags", "current"}

DEFAULT_SETTINGS: Dict[str, Any] = {
    "verbose": False,
    "verbose_obfuscation": False,
    "reasoning_effort": "medium",
    "reasoning_summary": "auto",
    "reasoning_compat": "think-tags",
    "debug_model": None,
    "expose_reasoning_models": False,
    "enable_web_search": False,
    "compatibility_mode": False,
}


def settings_path(home_dir: str | None = None) -> str:
    base = home_dir or get_home_dir()
    return os.path.join(base, SETTINGS_FILENAME)


def _coerce_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("1", "true", "yes", "y", "on"):
            return True
        if v in ("0", "false", "no", "n", "off"):
            return False
    return None


def _sanitize_settings(raw: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        return {}

    out: Dict[str, Any] = {}

    vb = _coerce_bool(raw.get("verbose"))
    if vb is not None:
        out["verbose"] = vb

    vbo = _coerce_bool(raw.get("verbose_obfuscation"))
    if vbo is not None:
        out["verbose_obfuscation"] = vbo

    effort = raw.get("reasoning_effort")
    if isinstance(effort, str) and effort.strip().lower() in VALID_REASONING_EFFORT:
        out["reasoning_effort"] = effort.strip().lower()

    summary = raw.get("reasoning_summary")
    if isinstance(summary, str) and summary.strip().lower() in VALID_REASONING_SUMMARY:
        out["reasoning_summary"] = summary.strip().lower()

    compat = raw.get("reasoning_compat")
    if isinstance(compat, str) and compat.strip().lower() in VALID_REASONING_COMPAT:
        out["reasoning_compat"] = compat.strip().lower()

    dbg = raw.get("debug_model")
    if dbg is None:
        out["debug_model"] = None
    elif isinstance(dbg, str):
        out["debug_model"] = dbg.strip() or None

    erm = _coerce_bool(raw.get("expose_reasoning_models"))
    if erm is not None:
        out["expose_reasoning_models"] = erm

    ews = _coerce_bool(raw.get("enable_web_search"))
    if ews is not None:
        out["enable_web_search"] = ews

    compat = _coerce_bool(raw.get("compatibility_mode"))
    if compat is not None:
        out["compatibility_mode"] = compat

    return out


def load_settings(home_dir: str | None = None) -> Dict[str, Any]:
    path = settings_path(home_dir)
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        return _sanitize_settings(raw if isinstance(raw, dict) else {})
    except FileNotFoundError:
        return {}
    except Exception as exc:
        eprint(f"WARNING: failed to read {path}: {exc}")
        return {}


def save_settings(settings: Dict[str, Any], home_dir: str | None = None) -> bool:
    home = home_dir or get_home_dir()
    path = settings_path(home)
    try:
        os.makedirs(home, exist_ok=True)
    except Exception as exc:
        eprint(f"ERROR: unable to create settings home directory {home}: {exc}")
        return False

    sanitized = _sanitize_settings(settings)
    payload = {**DEFAULT_SETTINGS, **sanitized}

    tmp_dir = os.path.dirname(path) or "."
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=tmp_dir,
            prefix=SETTINGS_FILENAME + ".",
            suffix=".tmp",
            delete=False,
        ) as fp:
            if hasattr(os, "fchmod"):
                os.fchmod(fp.fileno(), 0o600)
            json.dump(payload, fp, indent=2, ensure_ascii=False)
            fp.write("\n")
            tmp_path = fp.name
        os.replace(tmp_path, path)
        return True
    except Exception as exc:
        eprint(f"ERROR: unable to write settings file {path}: {exc}")
        try:
            if "tmp_path" in locals() and os.path.exists(tmp_path):
                os.unlink(tmp_path)
        except Exception:
            pass
        return False
