"""Durable receipts: every decision this plugin makes, with the source that caused it.

Backed by the plugin's own SQLite database under ``<hermes home>/plugin-data/taint-sentry/``, which
survives ``hermes plugins update`` and ``remove`` and follows the active profile. If that storage
is unavailable the ledger degrades to an in-memory ring buffer so the plugin still works — a
missing receipt is a bug, a crash on the tool path is an outage.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from collections import deque
from typing import Any

from . import sanitize

logger = logging.getLogger(__name__)

PLUGIN_NAME = "taint-sentry"
DB_FILENAME = "receipts.db"
MAX_MEMORY_ROWS = 1000

_SCHEMA = """
CREATE TABLE IF NOT EXISTS receipts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         REAL    NOT NULL,
    session_id TEXT    NOT NULL DEFAULT '',
    turn_id    TEXT    NOT NULL DEFAULT '',
    kind       TEXT    NOT NULL DEFAULT '',
    tool_name  TEXT    NOT NULL DEFAULT '',
    rule       TEXT    NOT NULL DEFAULT '',
    action     TEXT    NOT NULL DEFAULT '',
    severity   TEXT    NOT NULL DEFAULT '',
    sources    TEXT    NOT NULL DEFAULT '',
    detail     TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_receipts_ts ON receipts (ts DESC);
CREATE INDEX IF NOT EXISTS idx_receipts_session ON receipts (session_id, ts DESC);
"""

_lock = threading.Lock()
_memory: deque[dict] = deque(maxlen=MAX_MEMORY_ROWS)
_state: dict[str, Any] = {"conn": None, "failed": False, "path": ""}

# The desktop half subscribes through this: one listener, fed every recorded row, so the console
# updates the moment a call is decided. No listener (no Desktop attached, headless run) costs
# nothing, and a listener that raises can never break the tool path.
_listener: Any = None


def set_listener(fn: Any) -> None:
    """Register the sink that receives every recorded row."""
    global _listener
    _listener = fn


def _notify(row: dict) -> None:
    fn = _listener
    if fn is None:
        return
    try:
        fn(row)
    except Exception:  # pragma: no cover
        pass


def _connect() -> sqlite3.Connection | None:
    """Open (once) the receipts DB. Returns ``None`` if storage is unavailable."""
    if _state["conn"] is not None or _state["failed"]:
        return _state["conn"]
    try:
        from plugins.plugin_storage import plugin_db  # type: ignore

        conn = plugin_db(PLUGIN_NAME, DB_FILENAME)
        conn.executescript(_SCHEMA)
        conn.commit()
        _state["conn"] = conn
        _state["path"] = "plugin-data/%s/%s" % (PLUGIN_NAME, DB_FILENAME)
    except Exception as err:  # pragma: no cover - depends on host layout
        _state["failed"] = True
        logger.warning("taint-sentry: receipts DB unavailable, using memory ledger (%s)", err)
    return _state["conn"]


def backend() -> str:
    """``"sqlite"`` or ``"memory"`` — reported by ``hermes taint-sentry status``."""
    return "sqlite" if _connect() is not None else "memory"


def path() -> str:
    return str(_state.get("path") or "")


def record(
    *,
    kind: str,
    action: str = "",
    rule: str = "",
    tool_name: str = "",
    session_id: str = "",
    turn_id: str = "",
    severity: str = "",
    sources: str = "",
    detail: str = "",
) -> None:
    """Append one receipt. Never raises — this runs inside a policy hook."""
    row = {
        "ts": time.time(),
        "session_id": session_id or "",
        "turn_id": turn_id or "",
        "kind": kind,
        "tool_name": tool_name,
        "rule": rule,
        "action": action,
        "severity": severity,
        "sources": sanitize.redact_secrets(sources),
        "detail": sanitize.redact_secrets(str(detail))[:2000],
    }
    try:
        with _lock:
            conn = _connect()
            if conn is None:
                _memory.append(row)
                _notify(row)
                return
            conn.execute(
                "INSERT INTO receipts (ts, session_id, turn_id, kind, tool_name, rule, action,"
                " severity, sources, detail) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    row["ts"],
                    row["session_id"],
                    row["turn_id"],
                    row["kind"],
                    row["tool_name"],
                    row["rule"],
                    row["action"],
                    row["severity"],
                    row["sources"],
                    row["detail"],
                ),
            )
            conn.commit()
    except Exception as err:  # pragma: no cover
        logger.debug("taint-sentry: receipt write failed (%s)", err)
        with _lock:
            _memory.append(row)
    _notify(row)


def recent(limit: int = 20, *, session_id: str = "", actions_only: bool = False) -> list[dict]:
    """Newest-first receipts. ``actions_only`` hides the informational rows."""
    limit = max(1, min(int(limit), 500))
    clauses = []
    params: list[Any] = []
    if session_id:
        clauses.append("session_id = ?")
        params.append(session_id)
    if actions_only:
        clauses.append("action IN ('block','escalate','monitor')")
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = f"SELECT ts, session_id, turn_id, kind, tool_name, rule, action, severity, sources, detail FROM receipts{where} ORDER BY ts DESC LIMIT ?"
    params.append(limit)
    with _lock:
        conn = _connect()
        if conn is None:
            rows = [r for r in reversed(_memory)]
            if session_id:
                rows = [r for r in rows if r["session_id"] == session_id]
            if actions_only:
                rows = [r for r in rows if r["action"] in ("block", "escalate", "monitor")]
            return rows[:limit]
        try:
            cursor = conn.execute(sql, params)
            keys = ("ts", "session_id", "turn_id", "kind", "tool_name", "rule", "action", "severity", "sources", "detail")
            return [dict(zip(keys, row)) for row in cursor.fetchall()]
        except Exception as err:  # pragma: no cover
            logger.debug("taint-sentry: receipt read failed (%s)", err)
            return []


def counts(*, since_seconds: float | None = None) -> dict:
    """Tally receipts by action and rule. Used by the status tool and the CLI."""
    since = time.time() - since_seconds if since_seconds else 0.0
    with _lock:
        conn = _connect()
        if conn is None:
            rows = list(_memory)
        else:
            try:
                cursor = conn.execute(
                    "SELECT action, rule, ts FROM receipts WHERE ts >= ?", (since,)
                )
                rows = [{"action": r[0], "rule": r[1], "ts": r[2]} for r in cursor.fetchall()]
            except Exception:  # pragma: no cover
                rows = []
    by_action: dict[str, int] = {}
    by_rule: dict[str, int] = {}
    for row in rows:
        action = row.get("action") or "info"
        by_action[action] = by_action.get(action, 0) + 1
        if row.get("rule"):
            by_rule[row["rule"]] = by_rule.get(row["rule"], 0) + 1
    return {"total": len(rows), "by_action": by_action, "by_rule": by_rule}


def export(limit: int = 200) -> str:
    """Receipts as a JSON document (``hermes taint-sentry export``)."""
    return json.dumps(recent(limit), indent=2, default=str)


def reset_memory() -> None:
    """Test helper: drop the in-memory ledger."""
    with _lock:
        _memory.clear()


__all__ = ["record", "recent", "counts", "export", "backend", "path", "reset_memory"]
