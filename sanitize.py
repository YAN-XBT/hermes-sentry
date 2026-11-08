"""Provenance-safe text hygiene.

Two jobs, both deterministic and stdlib-only:

* ``strip_invisible`` — remove the characters attackers use to hide instructions from a human
  reading the same text (zero-width space, bidi overrides, unicode tag characters, Hangul
  fillers). The text keeps its meaning for a reader; the hidden channel does not survive.
* ``scan`` — flag instruction-shaped text arriving from a source that is not allowed to give
  instructions (imperative overrides, concealment requests, egress instructions, secret targets).

Nothing here calls a model. A false negative costs signal, never safety: the taint mark is set by
the *source*, not by the signature scan, so a novel phrasing still gets gated.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Iterable

# Characters with no visible glyph that carry meaning only to a machine. Deliberately excludes
# U+200C/U+200D (ZWNJ/ZWJ) — legitimate in Persian, Indic and emoji sequences — and U+FE00..U+FE0F
# (variation selectors, emoji presentation). Both are counted as *suspicious* when clustered.
_INVISIBLE_SINGLES = frozenset(
    {
        0x00AD,  # soft hyphen
        0x061C,  # arabic letter mark
        0x115F,  # hangul choseong filler
        0x1160,  # hangul jungseong filler
        0x17B4,  # khmer vowel inherent aq
        0x17B5,  # khmer vowel inherent aa
        0x180E,  # mongolian vowel separator
        0x200B,  # zero width space
        0x200E,  # left-to-right mark
        0x200F,  # right-to-left mark
        0x3164,  # hangul filler
        0xFEFF,  # zero width no-break space / BOM
        0xFFA0,  # halfwidth hangul filler
    }
)

_INVISIBLE_RANGES = (
    (0x202A, 0x202E),  # bidi embeddings and overrides
    (0x2060, 0x2064),  # word joiner, invisible operators
    (0x2066, 0x2069),  # bidi isolates
    (0x206A, 0x206F),  # deprecated format characters
    (0xFFF9, 0xFFFB),  # interlinear annotation
    (0x1D173, 0x1D17A),  # musical symbol format
    (0xE0001, 0xE0001),  # language tag
    (0xE0020, 0xE007F),  # tag characters — the classic hidden-instruction channel
)

# Counted as suspicious, not stripped: legitimate in some scripts, but a long run is a tell.
_SUSPICIOUS_CLUSTER = frozenset({0x200C, 0x200D, 0x2060, 0xFE0F})

_STRIP_SET = _INVISIBLE_SINGLES | frozenset(
    cp for lo, hi in _INVISIBLE_RANGES for cp in range(lo, hi + 1)
)

# Scanned-bytes ceiling: a multi-MB blob has poor signal and slows the tool path.
MAX_SCAN_CHARS = 200_000


@dataclass(frozen=True)
class Finding:
    """One instruction-shaped signature matched in untrusted text."""

    name: str
    severity: str  # "high" | "medium"
    excerpt: str

    def as_dict(self) -> dict:
        return {"name": self.name, "severity": self.severity, "excerpt": self.excerpt}


@dataclass(frozen=True)
class Hygiene:
    """Result of sanitizing one piece of untrusted text."""

    text: str
    stripped: int
    kinds: tuple[str, ...]

    @property
    def had_invisible(self) -> bool:
        return self.stripped > 0


def _kind_of(cp: int) -> str:
    if cp == 0x200B or cp == 0xFEFF:
        return "zero-width"
    if 0x202A <= cp <= 0x202E or 0x2066 <= cp <= 0x2069:
        return "bidi-override"
    if 0xE0000 <= cp <= 0xE007F:
        return "unicode-tag"
    return "format-char"


def strip_invisible(text: str) -> Hygiene:
    """Remove invisible characters. Returns the clean text plus a removal tally.

    A cluster of ZWNJ/ZWJ/variation selectors is also stripped: a single one is legitimate text,
    ten in a row is a payload. The rest of the text is never rewritten or reflowed.
    """
    if not text:
        return Hygiene(text="", stripped=0, kinds=())

    out: list[str] = []
    removed = 0
    kinds: set[str] = set()
    cluster = 0

    for ch in text:
        cp = ord(ch)
        if cp in _STRIP_SET:
            removed += 1
            kinds.add(_kind_of(cp))
            cluster = 0
            continue
        if cp in _SUSPICIOUS_CLUSTER:
            cluster += 1
            if cluster >= 4:
                removed += 1
                kinds.add("invisible-cluster")
                continue
            out.append(ch)
            continue
        cluster = 0
        out.append(ch)

    return Hygiene(text="".join(out), stripped=removed, kinds=tuple(sorted(kinds)))


# --- instruction signatures -------------------------------------------------------------------
#
# Patterns are deliberately loose and cheap. They never decide whether to gate a call (the source
# does that); they name *why* a source looked hostile, which is what makes a receipt readable.

#: An HTML comment longer than this is a payload dump, not a directive — the same window the rule
#: always had (600 characters either side of the keyword).
_COMMENT_SPAN_LIMIT = 1200
_HTML_DIRECTIVE_RE = re.compile(r"(?i)\b(?:instruction|ignore|system|you\s+must|assistant)\b")


def _find_html_comment_directive(text: str) -> str | None:
    """The first HTML comment whose body reads like an instruction, or ``None``.

    Deliberately not one regex. The natural pattern — a lazy "anything that is not the end of the
    comment", twice — re-tests at every character it consumes, so a body made of ``<!--`` with no
    ``-->`` anywhere costs seconds inside a single call: measured 4.8 s at the 200 KB scan cap, which
    is a free stall for any page that ships it. Walking the text with ``str.find`` is linear and
    cannot be steered, and it expresses two things one pattern cannot: the comment has to close, and
    it is allowed to contain ``>`` on the way there.
    """
    at = 0
    while True:
        start = text.find("<!--", at)
        if start < 0:
            return None
        end = text.find("-->", start + 4)
        if end < 0:
            return None
        body = text[start:end]
        if len(body) <= _COMMENT_SPAN_LIMIT and _HTML_DIRECTIVE_RE.search(body):
            return body
        at = end + 3


#: A rule is `(name, severity, matcher)`, where the matcher is either a pattern string or, where a
#: pattern cannot be made linear, a function returning the offending text.
_SIGNATURES: tuple[tuple[str, str, object], ...] = (
    (
        "instruction_override",
        "high",
        r"(?i)\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}?"
        r"\b(?:previous|prior|earlier|above|all|any|the)\b[^.\n]{0,24}?"
        r"\b(?:instruction|prompt|rule|direction|message|context)s?\b",
    ),
    (
        "instruction_override",
        "high",
        r"(?i)\b(?:do not|don'?t|never)\s+(?:follow|obey|listen to|comply with)\b[^.\n]{0,40}?"
        r"\b(?:instruction|prompt|rule|user|system)s?\b",
    ),
    (
        "role_reassignment",
        "high",
        r"(?i)\byou\s+are\s+now\b|\bfrom\s+now\s+on\s+you\b|\bnew\s+(?:persona|role|identity)\b",
    ),
    (
        "fake_turn_marker",
        "high",
        r"(?im)^[ \t>*-]*(?:system|developer|assistant|user)\s*(?:prompt)?\s*[:>]\s*\S",
    ),
    (
        "fresh_instructions",
        "medium",
        r"(?i)\b(?:new|updated|revised|real|actual)\s+instructions?\b[^.\n]{0,20}?\b(?:are|follow|below)\b",
    ),
    (
        "concealment",
        "high",
        r"(?i)\b(?:do not|don'?t|never)\b[^.\n]{0,30}?"
        r"\b(?:tell|inform|mention|notify|reveal|show|alert|report)\b[^.\n]{0,24}?"
        r"\b(?:user|operator|human|owner|them)\b",
    ),
    (
        "secret_target",
        "high",
        r"(?i)(?:id_rsa|id_ed25519|\.env\b|\bauth\.json\b|\.git-credentials|\.netrc|"
        r"\.aws[/\\]|\.ssh[/\\]|private[_ -]?key|api[_ -]?key|access[_ -]?token|"
        r"credential|password|keychain|wallet\.dat)",
    ),
    (
        "egress_instruction",
        "high",
        r"(?i)\b(?:send|post|upload|exfiltrate|forward|email|curl|wget|transmit|paste)\b"
        r"[^.\n]{0,60}?(?:https?://|webhook|pastebin|@[a-z0-9.-]+\.[a-z]{2,})",
    ),
    (
        "shell_instruction",
        "medium",
        r"(?i)\b(?:run|execute|invoke)\b[^.\n]{0,30}?"
        r"\b(?:command|shell|bash|sh\b|powershell|cmd\.exe|python -c|node -e)\b",
    ),
    (
        "tool_coercion",
        "medium",
        r"(?i)\b(?:call|use|invoke)\b[^.\n]{0,24}?\b(?:the\s+)?(?:tool|function)\b"
        r"[^.\n]{0,30}?\b(?:terminal|write_file|patch|read_file|browser|delegate)\b",
    ),
    (
        "authority_claim",
        "medium",
        r"(?i)\b(?:i\s+am|this\s+is)\b[^.\n]{0,30}?"
        r"\b(?:your\s+(?:developer|creator|admin|operator|owner|supervisor)|"
        r"openai|anthropic|nous\s*research)\b",
    ),
    (
        "html_comment_directive",
        "medium",
        _find_html_comment_directive,
    ),
    (
        "css_cloak",
        "high",
        r"(?i)(?:font-size\s*:\s*0(?:px|em|rem|%)?|"
        r"color\s*:\s*(?:#fff(?:fff)?|white|rgba\(\s*255\s*,\s*255\s*,\s*255\s*,\s*0\s*\)))",
    ),
    (
        "base64_blob",
        "medium",
        r"\b[A-Za-z0-9+/]{120,}={0,2}\b",
    ),
)

def _matcher(spec: object):
    """A rule's matcher: a function as-is, or a pattern compiled into one that returns its match."""
    if callable(spec):
        return spec
    rx = re.compile(str(spec))

    def _search(text: str) -> str | None:
        found = rx.search(text)
        return found.group(0) if found else None

    return _search


_MATCHERS: tuple[tuple[str, str, object], ...] = tuple(
    (name, severity, _matcher(spec)) for name, severity, spec in _SIGNATURES
)

MAX_FINDINGS = 12


def scan(text: str) -> list[Finding]:
    """Return instruction-shaped signatures found in ``text`` (deduped by name, capped)."""
    if not text:
        return []
    if len(text) > MAX_SCAN_CHARS:
        text = text[:MAX_SCAN_CHARS]

    findings: list[Finding] = []
    seen: set[str] = set()
    for name, severity, match_rule in _MATCHERS:
        if name in seen:
            continue
        hit = match_rule(text)
        if not hit:
            continue
        seen.add(name)
        excerpt = " ".join(hit.split())[:160]
        findings.append(Finding(name=name, severity=severity, excerpt=excerpt))
        if len(findings) >= MAX_FINDINGS:
            break
    return findings


def highest_severity(findings: Iterable[Finding]) -> str | None:
    """``"high"`` if any high finding, else ``"medium"``, else ``None``."""
    best: str | None = None
    for finding in findings:
        if finding.severity == "high":
            return "high"
        best = "medium"
    return best


def is_probably_text(value: str) -> bool:
    """Cheap guard: skip binary-ish blobs so the tool path never walks a megabyte of base64."""
    if not value:
        return False
    sample = value[:4000]
    if "\x00" in sample:
        return False
    printable = sum(1 for ch in sample if ch.isprintable() or ch in "\n\r\t")
    return printable / max(len(sample), 1) > 0.7


def normalize_whitespace(text: str) -> str:
    """Collapse runs of blank lines left behind after stripping — keeps receipts readable."""
    return re.sub(r"\n{3,}", "\n\n", text)


_SECRET_INLINE_RE = re.compile(
    r"(?i)(?:"
    r"(?:api[_-]?key|apikey|password|passwd|secret|token|authorization)\s*[:=]\s*"
    r"(?:bearer\s+)?[^\s,;\"']+|"
    r"bearer\s+[A-Za-z0-9._\-]{8,}|"
    r"(?:sk|pk|ghp|gho|ghs|github_pat|xox[baprs])[-_][A-Za-z0-9_\-]{10,}"
    r")"
)


def redact_secrets(text: str) -> str:
    """Strip credential-shaped substrings.

    Applied before anything reaches the receipts ledger: a receipt records the *decision*, and must
    not become a second copy of whatever secret happened to be in the call.
    """
    return _SECRET_INLINE_RE.sub("[redacted]", str(text or ""))


def category_summary(text: str) -> dict[str, int]:
    """Count format characters by unicode category. Used by ``hermes taint-sentry explain``."""
    counts: dict[str, int] = {}
    for ch in text[:MAX_SCAN_CHARS]:
        if unicodedata.category(ch) == "Cf":
            counts[ch] = counts.get(ch, 0) + 1
    return counts
