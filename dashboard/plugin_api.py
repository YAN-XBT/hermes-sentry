"""Taint Sentry's backend for its own desktop half.

Runs inside the gateway process, so it reads the *live* plugin state — the same module objects the
hooks use, not a copy. Routes mount under ``/api/plugins/taint-sentry/``.

The one thing this backend deliberately can do that the model cannot: change the policy. The pane
toggles a rule, and that write happens here, on the human's click. A tool call that tried the same
thing through the CLI or this API is refused by the ``plugin_tamper`` rule.
"""

from __future__ import annotations

import importlib
import logging
import sys
from pathlib import Path
from typing import Any

from fastapi import APIRouter

logger = logging.getLogger("hermes_plugins.taint_sentry.api")

router = APIRouter()

PLUGIN_ID = "taint-sentry"
#: This file is ``<package>/dashboard/plugin_api.py``, so the package is one level up. The loader
#: turns the key's hyphen into an underscore — `taint-sentry` is imported as `taint_sentry` — which
#: is why the module name is derived from the directory rather than from the key.
PACKAGE_DIR = Path(__file__).resolve().parents[1]
MODULE = PACKAGE_DIR.name.replace("-", "_")


def _package() -> Any | None:
    """The plugin's own package, however the loader happened to register it.

    It has to be the *live* module the hooks use: a second import would be a second copy with its own
    taint store, and the pane would show a plugin that is quietly not the one enforcing. So look for
    the already-imported package this file lives in, by path, before guessing names.
    """
    for module in list(sys.modules.values()):
        try:
            if module is None or not hasattr(module, "runtime"):
                continue
            origin = getattr(module, "__file__", "") or ""
            if origin and Path(origin).resolve() == PACKAGE_DIR / "__init__.py":
                return module
        except Exception:
            continue
    for name in (MODULE, f"hermes_plugins.{MODULE}"):
        try:
            module = importlib.import_module(name)
        except Exception:
            continue
        if hasattr(module, "runtime"):
            return module
    for key, module in list(sys.modules.items()):
        if key.rsplit(".", 1)[-1] in {MODULE, PLUGIN_ID} and hasattr(module, "runtime"):
            return module
    return None


def _broadcast(event: str, payload: dict | None = None) -> None:
    """Push to the desktop half over the gateway event stream. Never fatal."""
    if "tui_gateway.server" not in sys.modules:
        return  # no gateway in this process: nothing is attached to it
    try:
        from hermes_cli.plugin_events import broadcast_plugin_event

        broadcast_plugin_event(PLUGIN_ID, event, payload or {})
    except Exception as err:  # pragma: no cover - depends on host layout
        logger.debug("taint-sentry: broadcast failed (%s)", err)


def _unavailable(reason: str) -> dict:
    return {"available": False, "reason": reason, "mode": "unknown", "rules": {}, "tainted": [], "tallies": {}}


@router.get("/state")
async def state() -> dict:
    """Mode, rules in force, tainted sessions and the ledger tallies."""
    pkg = _package()
    if pkg is None:
        return _unavailable("plugin package not importable in this process")

    try:
        policy = pkg.runtime.effective_policy(force=True)
        store = pkg.runtime.store()
        tallies = pkg.receipts.counts()
        sessions = []
        for row in store.sessions():
            sessions.append(
                {
                    "session_id": str(row.get("session_id") or "(unnamed)"),
                    "labels": pkg.sources.describe_sources(row.get("sources") or {}) or "untrusted content",
                    "age_s": int(row.get("age_s") or 0),
                }
            )
        return {
            "available": True,
            "mode": policy.get("mode", "enforce"),
            "policy_source": str(policy.get("_source") or "built-in defaults"),
            "taint_ttl_seconds": policy.get("taint_ttl_seconds"),
            "rules": {
                str(name): str((spec or {}).get("action", ""))
                for name, spec in (policy.get("rules") or {}).items()
            },
            "rule_when": {
                str(name): str((spec or {}).get("when", ""))
                for name, spec in (policy.get("rules") or {}).items()
            },
            "tainted": sessions,
            "tallies": {
                "total": tallies.get("total", 0),
                "by_action": tallies.get("by_action", {}),
                "by_rule": tallies.get("by_rule", {}),
            },
            "ledger": pkg.receipts.backend(),
        }
    except Exception as err:
        logger.warning("taint-sentry: /state failed (%s)", err)
        return _unavailable(str(err))


@router.get("/receipts")
async def receipts(limit: int = 40, session_id: str = "", actions_only: bool = False) -> dict:
    """Newest-first decisions. `actions_only` hides the informational rows."""
    pkg = _package()
    if pkg is None:
        return {"items": [], "reason": "plugin package not importable in this process"}
    try:
        rows = pkg.receipts.recent(
            limit=max(1, min(int(limit), 200)),
            session_id=session_id,
            actions_only=bool(actions_only),
        )
        return {"items": rows}
    except Exception as err:
        logger.warning("taint-sentry: /receipts failed (%s)", err)
        return {"items": [], "reason": str(err)}


@router.get("/explain")
async def explain() -> dict:
    """The most recent call this policy actually refused."""
    pkg = _package()
    if pkg is None:
        return {"decision": None}
    try:
        for row in pkg.receipts.recent(limit=200):
            if str(row.get("action")) in ("block", "escalate"):
                return {"decision": row}
    except Exception as err:
        logger.warning("taint-sentry: /explain failed (%s)", err)
    return {"decision": None}


@router.post("/taint/clear")
async def taint_clear(body: dict | None = None) -> dict:
    """Clear one session's taint, or every session in this process."""
    pkg = _package()
    if pkg is None:
        return {"ok": False, "reason": "plugin package not importable in this process"}
    body = body or {}
    session_id = str(body.get("session_id") or "")
    try:
        store = pkg.runtime.store()
        if session_id:
            cleared = 1 if store.clear(session_id) else 0
        else:
            cleared = store.session_count()
            store.reset()
        _broadcast("provenance", {"cleared": cleared})
        return {"ok": True, "cleared": cleared}
    except Exception as err:
        logger.warning("taint-sentry: /taint/clear failed (%s)", err)
        return {"ok": False, "reason": str(err)}


@router.post("/rules")
async def set_rule(body: dict) -> dict:
    """Set one rule's action in the plugin's own policy file.

    This is the human's click in the pane. The model has no route to it: `hermes taint-sentry set`, the
    same edit in `config.yaml`, and a request to this namespace all trip `plugin_tamper`.
    """
    pkg = _package()
    if pkg is None:
        return {"ok": False, "reason": "plugin package not importable in this process"}

    rule = str((body or {}).get("rule") or "")
    action = str((body or {}).get("action") or "")
    if not rule or action not in pkg.policy.ACTIONS:
        return {"ok": False, "reason": f"rule and action required (action one of {', '.join(pkg.policy.ACTIONS)})"}

    try:
        data = pkg.runtime.data_dir()
        if data is None:
            return {"ok": False, "reason": "plugin data dir unavailable"}

        cli = importlib.import_module(f"{pkg.__name__}.cli")
        path = cli._policy_path(data)
        existing: dict = {}
        if path.is_file():
            existing = pkg.policy.load_policy_file(path) or {}
        if not isinstance(existing, dict):
            existing = {}

        rules = existing.setdefault("rules", {})
        if not isinstance(rules, dict):
            rules = existing["rules"] = {}
        current = (pkg.runtime.effective_policy(force=True).get("rules") or {}).get(rule) or {}
        spec = dict(current)
        spec["when"] = spec.get("when") or "tainted"
        spec["action"] = action
        rules[rule] = spec

        cli._write_policy(path, existing)
        pkg.policy.reset_cache()
        pkg.runtime.effective_policy(force=True)
        _broadcast("policy.changed", {"rule": rule, "action": action})
        return {"ok": True, "rule": rule, "action": action, "policy_file": str(path)}
    except Exception as err:
        logger.warning("taint-sentry: /rules failed (%s)", err)
        return {"ok": False, "reason": str(err)}
