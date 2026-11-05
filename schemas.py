"""Tool schemas — what the model reads.

Deliberately only two, and both read-only: a security plugin must not hand the model a way to
change its own policy. Clearing taint, allowlisting a host and editing the policy are user actions,
so they live in the CLI where only a person can run them.
"""

from __future__ import annotations

SENTRY_STATUS = {
    "name": "sentry_status",
    "description": (
        "Report whether this session is currently tainted by untrusted content, which sources "
        "tainted it, which injection signatures were seen, and how many tool calls sentry has "
        "gated. Call this when a tool call was blocked or escalated and you need to know why, or "
        "before doing something irreversible to check whether the session is under the influence "
        "of content that arrived from a web page, an MCP server, a screenshot or an image."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "session_id": {
                "type": "string",
                "description": "Session to inspect. Omit for the current session.",
            }
        },
        "required": [],
    },
}

SENTRY_RECEIPTS = {
    "name": "sentry_receipts",
    "description": (
        "List recent sentry decisions: which tool call was allowed, blocked, escalated or observed, "
        "under which rule, and which untrusted source caused it. Use this to explain a block to the "
        "user, or to audit what happened earlier in the session."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "limit": {
                "type": "integer",
                "description": "How many receipts to return (1-50, default 10).",
            },
            "decisions_only": {
                "type": "boolean",
                "description": "Only return block/escalate/monitor rows, skipping provenance stamps.",
            },
        },
        "required": [],
    },
}

__all__ = ["SENTRY_STATUS", "SENTRY_RECEIPTS"]
