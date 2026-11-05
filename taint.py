"""Per-session taint state.

A taint mark says: *this session has ingested content from a source that is not allowed to give
instructions*. It is set by provenance (see ``sources.py``), never by a model's opinion, and it
decays on a TTL so a single fetched page does not gate the session forever.

State lives in process memory and is keyed by session id. It is intentionally not persisted:
a resumed session re-earns its taint the moment it reads untrusted content again, and stale taint
across a restart would gate work for no reason. Receipts (the durable half) live in ``receipts.py``.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

MAX_SESSIONS = 512


@dataclass
class Mark:
    """One untrusted source observed in a session."""

    label: str
    tool: str
    host: str
    reason: str
    signatures: tuple[str, ...] = ()
    severity: str | None = None
    count: int = 1
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    turn_id: str = ""

    def as_dict(self) -> dict:
        return {
            "label": self.label,
            "tool": self.tool,
            "host": self.host,
            "reason": self.reason,
            "signatures": list(self.signatures),
            "severity": self.severity,
            "count": self.count,
            "age_seconds": round(time.time() - self.last_seen, 1),
            "turn_id": self.turn_id,
        }


@dataclass
class SessionTaint:
    """All taint for one session."""

    session_id: str
    marks: dict[str, Mark] = field(default_factory=dict)
    artifacts: dict[str, str] = field(default_factory=dict)  # path -> label that wrote it
    sensitive: dict[str, float] = field(default_factory=dict)  # path -> last read time
    marks_total: int = 0
    created: float = field(default_factory=time.time)

    def as_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "marks_total": self.marks_total,
            "sources": {label: mark.as_dict() for label, mark in self.marks.items()},
            "artifacts": dict(self.artifacts),
            "age_seconds": round(time.time() - self.created, 1),
        }


class TaintStore:
    """Thread-safe taint registry. One instance per process, owned by the plugin."""

    def __init__(self, ttl_seconds: int = 1800) -> None:
        self._lock = threading.Lock()
        self._sessions: dict[str, SessionTaint] = {}
        self.ttl_seconds = max(int(ttl_seconds), 1)

    # --- writes ---------------------------------------------------------------------------

    def mark(
        self,
        session_id: str,
        *,
        label: str,
        tool: str = "",
        host: str = "",
        reason: str = "",
        signatures: tuple[str, ...] = (),
        severity: str | None = None,
        turn_id: str = "",
    ) -> Mark | None:
        """Record an untrusted source. Returns the (updated) mark, or ``None`` if disabled."""
        if not session_id or not label:
            return None
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                session = SessionTaint(session_id=session_id)
                self._sessions[session_id] = session
                self._evict_locked()
            mark = session.marks.get(label)
            if mark is None:
                mark = Mark(
                    label=label,
                    tool=tool,
                    host=host,
                    reason=reason,
                    signatures=tuple(signatures),
                    severity=severity,
                    turn_id=turn_id,
                )
                session.marks[label] = mark
            else:
                mark.count += 1
                mark.last_seen = time.time()
                if signatures:
                    merged = tuple(dict.fromkeys((*mark.signatures, *signatures)))
                    mark.signatures = merged
                if severity == "high" or mark.severity is None:
                    mark.severity = severity or mark.severity
                if turn_id:
                    mark.turn_id = turn_id
            session.marks_total += 1
            return mark

    def note_artifact(self, session_id: str, path: str, label: str) -> None:
        """Remember that ``path`` now holds content from an untrusted source (taint propagation)."""
        if not session_id or not path:
            return
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                session = SessionTaint(session_id=session_id)
                self._sessions[session_id] = session
                self._evict_locked()
            session.artifacts[str(path)] = label

    def note_sensitive(self, session_id: str, path: str) -> None:
        """Remember that this session read a sensitive path.

        Feeds the ``credential_exfil`` composite: a read and a data-sending call are each harmless
        alone, and a credential leaving the machine is not. Entries decay with the taint TTL.
        """
        if not session_id or not path:
            return
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                session = SessionTaint(session_id=session_id)
                self._sessions[session_id] = session
                self._evict_locked()
            session.sensitive[str(path)] = time.time()

    def recent_sensitive(self, session_id: str, within: float | None = None) -> str:
        """Most recently read sensitive path still inside the window, or ``""``."""
        if not session_id:
            return ""
        window = self.ttl_seconds if within is None else max(float(within), 1.0)
        cutoff = time.time() - window
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return ""
            live = {p: ts for p, ts in session.sensitive.items() if ts >= cutoff}
            session.sensitive = live
            if not live:
                return ""
            return max(live.items(), key=lambda kv: kv[1])[0]

    def clear(self, session_id: str) -> bool:
        with self._lock:
            return self._sessions.pop(session_id, None) is not None

    def reset(self) -> None:
        """Drop every session's taint. Used by ``hermes sentry clear --all`` and tests."""
        with self._lock:
            self._sessions.clear()

    # --- reads ----------------------------------------------------------------------------

    def _live(self, session_id: str) -> SessionTaint | None:
        session = self._sessions.get(session_id)
        if session is None:
            return None
        cutoff = time.time() - self.ttl_seconds
        expired = [label for label, mark in session.marks.items() if mark.last_seen < cutoff]
        for label in expired:
            del session.marks[label]
        if not session.marks and not session.artifacts:
            self._sessions.pop(session_id, None)
            return None
        return session

    def is_tainted(self, session_id: str) -> bool:
        if not session_id:
            return False
        with self._lock:
            return self._live(session_id) is not None

    def snapshot(self, session_id: str) -> dict:
        """Serializable taint state for a banner, a receipt or the ``sentry_status`` tool."""
        if not session_id:
            return {"session_id": "", "tainted": False, "marks_total": 0, "sources": {}, "artifacts": {}}
        with self._lock:
            session = self._live(session_id)
            if session is None:
                return {
                    "session_id": session_id,
                    "tainted": False,
                    "marks_total": 0,
                    "sources": {},
                    "artifacts": {},
                }
            data = session.as_dict()
            data["tainted"] = True
            data["ttl_seconds"] = self.ttl_seconds
            return data

    def artifact_label(self, session_id: str, path: str) -> str:
        """Return the taint label if ``path`` was written from untrusted content."""
        if not session_id or not path:
            return ""
        with self._lock:
            session = self._live(session_id)
            if session is None:
                return ""
            target = str(path).replace("\\", "/").lower()
            for known, label in session.artifacts.items():
                if known.replace("\\", "/").lower() == target:
                    return label
            return ""

    def labels(self, session_id: str) -> tuple[str, ...]:
        with self._lock:
            session = self._live(session_id)
            return tuple(session.marks) if session else ()

    def session_count(self) -> int:
        with self._lock:
            return len(self._sessions)

    def sessions(self) -> list[dict]:
        """Snapshot every live session. Used by ``hermes sentry status``."""
        with self._lock:
            live = [self._live(sid) for sid in list(self._sessions)]
            return [s.as_dict() for s in live if s is not None]

    def _evict_locked(self) -> None:
        """Keep the registry bounded: drop the least recently touched sessions."""
        if len(self._sessions) <= MAX_SESSIONS:
            return
        ordered = sorted(self._sessions.items(), key=lambda kv: kv[1].created)
        for session_id, _ in ordered[: max(1, len(ordered) - MAX_SESSIONS)]:
            self._sessions.pop(session_id, None)


__all__ = ["TaintStore", "Mark", "SessionTaint"]
