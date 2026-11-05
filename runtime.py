"""Shared runtime state.

Hooks, tools and the CLI all need the same three things: the taint store, the effective policy and
the plugin's own data directory. Keeping them here (rather than in ``__init__.py``) means the tool
and CLI modules never import the registration module — no import cycle, and every surface sees the
same process-wide state.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from pathlib import Path
from typing import Any

from . import policy as policy_mod
from .taint import TaintStore

logger = logging.getLogger(__name__)

PLUGIN_NAME = "sentry"
SETTINGS_TTL = 5.0

#: Keys this plugin reads from ``plugins.entries.sentry.settings``. ``ctx.get_config`` is a
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
        logger.debug("sentry: settings read failed (%s)", err)
        value = dict(_settings)
    with _lock:
        _settings = value
        _settings_ts = now
    return value


def invalidate_settings() -> None:
    """Force the next :func:`settings` call to re-read (used by the CLI after a write)."""
    global _settings_ts
    _settings_ts = 0.0


def data_dir() -> Path | None:
    """``<hermes home>/plugin-data/sentry/`` — survives plugin update/remove, follows the profile."""
    global _data_dir, _data_dir_resolved
    if _data_dir_resolved:
        return _data_dir
    try:
        from plugins.plugin_storage import plugin_data_dir  # type: ignore

        _data_dir = plugin_data_dir(PLUGIN_NAME)
    except Exception as err:  # pragma: no cover - host layout dependent
        logger.debug("sentry: no plugin data dir (%s)", err)
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
