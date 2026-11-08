"""Shared runtime state.

Hooks, tools and the CLI all need the same three things: the taint store, the effective policy and
the plugin's own data directory. Keeping them here (rather than in ``__init__.py``) means the tool
and CLI modules never import the registration module — no import cycle, and every surface sees the
same process-wide state.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any

from . import policy as policy_mod
from .taint import TaintStore

logger = logging.getLogger(__name__)

PLUGIN_NAME = "taint-sentry"
SETTINGS_TTL = 5.0

#: Keys this plugin reads from ``plugins.entries.taint-sentry.settings``. ``ctx.get_config`` is a
#: per-key getter (``get_config("mode")``), not a dict accessor — reading it with no argument
#: returns the default and silently yields an empty settings dict.
SETTING_KEYS = ("mode", "taint_ttl_seconds", "policy_file", "debug_trace", "on_error")

_store = TaintStore()
_lock = threading.Lock()
_ctx: Any = None
_settings: dict = {}
_settings_ts: float = 0.0
_data_dir: Path | None = None
_data_dir_resolved = False


def bind(ctx: Any) -> None:
    """Called once from ``register(ctx)``. Every other surface reads state through this module."""
    global _ctx
    _ctx = ctx


def context() -> Any:
    return _ctx


def settings() -> dict:
    """This plugin's settings namespace, refreshed at most every few seconds."""
    global _settings, _settings_ts
    now = time.time()
    if now - _settings_ts < SETTINGS_TTL:
        return _settings
    value: dict = {}
    try:
        getter = getattr(_ctx, "get_config", None)
        if callable(getter):
            for key in SETTING_KEYS:
                try:
                    raw = getter(key, None)
                except TypeError:
                    raw = getter(key)
                if raw is not None:
                    value[key] = raw
        else:
            value = dict(_settings)
    except Exception as err:  # a settings read must never break a hook
        logger.debug("taint-sentry: settings read failed (%s)", err)
        value = dict(_settings)
    with _lock:
        _settings = value
        _settings_ts = now
    return value


def invalidate_settings() -> None:
    """Force the next :func:`settings` call to re-read (used by the CLI after a write)."""
    global _settings_ts
    _settings_ts = 0.0


_CLEAR_REQUEST = "clear.request"
_CLEAR_MAX_AGE = 300.0  # a stale request must never clear a later session's taint


def request_clear(session_id: str = "") -> bool:
    """Leave a clear request for the process that actually holds the taint.

    Taint lives in the memory of the process running the agent, so `hermes taint-sentry clear` typed in a
    shell cannot reach it — that command is its own process with its own empty store. The CLI leaves
    this marker instead, and the next tool call in the live process consumes it.
    """
    data = data_dir()
    if data is None:
        return False
    try:
        Path(data).mkdir(parents=True, exist_ok=True)
        (Path(data) / _CLEAR_REQUEST).write_text(
            json.dumps({"ts": time.time(), "session_id": session_id or ""}), encoding="utf-8"
        )
        return True
    except Exception as err:  # pragma: no cover - depends on host layout
        logger.debug("taint-sentry: cannot leave a clear request (%s)", err)
        return False


def consume_clear_request() -> dict:
    """Apply a pending clear request. Returns ``{}`` when there was nothing to do."""
    data = data_dir()
    if data is None:
        return {}
    marker = Path(data) / _CLEAR_REQUEST
    try:
        if not marker.is_file():
            return {}
        payload = json.loads(marker.read_text(encoding="utf-8") or "{}")
        marker.unlink()
    except Exception:
        return {}
    try:
        if time.time() - float(payload.get("ts") or 0) > _CLEAR_MAX_AGE:
            return {}
    except (TypeError, ValueError):
        return {}
    session_id = str(payload.get("session_id") or "")
    if session_id:
        cleared = 1 if _store.clear(session_id) else 0
    else:
        cleared = _store.session_count()
        _store.reset()
    return {"cleared": cleared, "session_id": session_id}


def data_dir() -> Path | None:
    """``<hermes home>/plugin-data/taint-sentry/`` — survives plugin update/remove, follows the profile."""
    global _data_dir, _data_dir_resolved
    if _data_dir_resolved:
        return _data_dir
    try:
        from plugins.plugin_storage import plugin_data_dir  # type: ignore

        _data_dir = plugin_data_dir(PLUGIN_NAME)
    except Exception as err:  # pragma: no cover - host layout dependent
        logger.debug("taint-sentry: no plugin data dir (%s)", err)
        _data_dir = None
    _data_dir_resolved = True
    return _data_dir


def store() -> TaintStore:
    return _store


def effective_policy(*, force: bool = False) -> dict:
    """The policy in force right now, with the taint TTL pushed into the store."""
    pol = policy_mod.resolve_policy(settings=settings(), data_dir=data_dir(), force=force)
    try:
        _store.ttl_seconds = int(pol.get("taint_ttl_seconds", 1800))
    except (TypeError, ValueError):
        pass
    return pol


def mode() -> str:
    """``enforce`` | ``monitor`` | ``off``. Read straight from the policy so one source wins."""
    return str(effective_policy().get("mode", "enforce"))


def workspace() -> str:
    """Best available notion of the workspace root for path decisions.

    Hooks are not handed a cwd, so the agent's own process cwd is the honest answer; a policy can
    override it with ``workspace:``.
    """
    try:
        override = str(effective_policy().get("workspace") or "").strip()
        if override:
            return override
    except Exception:
        pass
    try:
        return os.getcwd()
    except Exception:
        return ""


def session_of(session_id: str = "", task_id: str = "") -> str:
    """Hooks carry both ids; either identifies the run. Prefer the session."""
    return str(session_id or task_id or "")


def reset_for_tests() -> None:
    """Drop all state. Tests only."""
    global _ctx, _settings, _settings_ts, _data_dir, _data_dir_resolved
    _store.reset()
    _store.ttl_seconds = 1800
    _ctx = None
    _settings = {}
    _settings_ts = 0.0
    _data_dir = None
    _data_dir_resolved = False
    policy_mod.reset_cache()


__all__ = [
    "PLUGIN_NAME",
    "bind",
    "context",
    "settings",
    "invalidate_settings",
    "data_dir",
    "store",
    "effective_policy",
    "mode",
    "workspace",
    "session_of",
    "reset_for_tests",
]
