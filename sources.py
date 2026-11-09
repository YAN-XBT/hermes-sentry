"""Provenance classification: who authored this text, and what would a call reach?

The taint mark is set by *source*, not by content. That is the whole point: a novel injection
phrasing still gets gated because the turn that read a web page is gated, no matter what the page
said. Signature scanning only explains the decision afterwards.
"""

from __future__ import annotations

import base64
import os
import re
from dataclasses import dataclass, field
from pathlib import PurePath, PurePosixPath, PureWindowsPath

# Tools whose result is authored by a third party. Exact names, plus the mcp__ prefix below.
UNTRUSTED_TOOLS = frozenset(
    {
        "web_search",
        "web_extract",
        "web_fetch",
        "browser_exec",
        "vision_analyze",
        "computer_use",
        "read_window_below",
        "drive_preview",
    }
)

# Any tool from an MCP server is third-party code with third-party content.
UNTRUSTED_PREFIXES = ("mcp__",)

# Tools whose trust depends on *what* they touch: a path in the workspace is yours, a path in
# ~/.ssh is not, and a file written earlier from untrusted content stays untrusted.
PATH_GATED_TOOLS = frozenset({"read_file", "search_files", "terminal", "process_manage"})

# Paths an injected instruction wants. Reading one of these while tainted is the exfil setup.
SENSITIVE_PATH_RE = re.compile(
    r"(?i)(?:"
    r"id_(?:rsa|ed25519|ecdsa|dsa)(?!\.pub)|"
    r"\.ssh[/\\]|\.aws[/\\]|\.kube[/\\]|\.gnupg[/\\]|\.docker[/\\]config\.json|"
    r"\.git-credentials|\.netrc|\.npmrc|\.pypirc|\.pgpass|"
    r"(?:^|[/\\\s\"'])\.env(?!\.(?:example|sample|template|dist|md|rst|txt))(?:\.|$|[/\\\s\"'])|"
    r"auth\.json|credentials(?:\.json)?|secrets?\.(?:json|yaml|yml|toml|ini)|"
    r"\.hermes[/\\]|hermes[/\\]config\.yaml|"
    r"keychain|login\.keychain|Credential Manager|"
    r"\.pem\b|\.pfx\b|\.p12\b|wallet\.dat|keystore"
    r")"
)

# A sensitive directory on its own is a listing, not a credential. Reading inside it is not.
_SENSITIVE_DIR_ROOTS = (
    "~/.ssh",
    "~/.aws",
    "~/.kube",
    "~/.gnupg",
    "/.ssh",
    "/.aws",
    "/.kube",
    "/.gnupg",
    ".hermes",
    "/.hermes",
)


def is_sensitive_path(path: str) -> bool:
    """True when ``path`` names material an injected instruction would want to read.

    ``ls ~/.ssh/`` lists a directory and is allowed; ``cat ~/.ssh/id_rsa`` is not.
    """
    text = str(path or "").strip()
    if not text or not SENSITIVE_PATH_RE.search(text):
        return False
    stripped = text.rstrip("/\\").replace("\\", "/").lower()
    if stripped.endswith(".pub"):
        return False  # a public key is public — `.ssh/` alone would otherwise make it sensitive
    return not any(stripped.endswith(root) for root in _SENSITIVE_DIR_ROOTS)


# Files the agent itself reads as *instructions* in a later session: project rules, skills, hook
# handlers, Hermes' own config, plugin manifests. A write here is not a data change, it is a change
# to what the agent will do next time — the persistence half of a prompt injection.
INSTRUCTION_PATH_RE = re.compile(
    r"(?i)(?:"
    r"\b(?:AGENTS|CLAUDE)\.md\b|"
    r"\.hermes\.md\b|"
    r"\bSKILL\.md\b|"
    r"\.hermes[/\\]config\.ya?ml\b|"
    r"[/\\]hermes[/\\]config\.ya?ml\b|"
    r"[/\\]profiles[/\\][^/\\\s]+[/\\]config\.ya?ml\b|"
    r"\.hermes[/\\](?:hooks|skills|cron)[/\\]"
    r")"
)

# Manifests only matter where Hermes actually loads them: inside a Hermes home, an installed plugin
# directory, or a plugin-data tree. A checkout of your own plugin repo is just source.
_MANIFEST_RE = re.compile(r"(?i)\b(?:plugin|HOOK)\.ya?ml\b|\b(?:plugin|mcp)\.json\b")
_HERMES_TREE_RE = re.compile(
    r"(?i)(?:[/\\]\.hermes[/\\]|[/\\]hermes[/\\](?:plugins|plugin-data)[/\\]|[/\\](?:plugins|plugin-data)[/\\])"
)


def is_instruction_path(path: str) -> bool:
    """True when writing ``path`` changes what the agent will read as instructions later."""
    text = str(path or "")
    if not text:
        return False
    if INSTRUCTION_PATH_RE.search(text):
        return True
    return bool(_MANIFEST_RE.search(text) and _HERMES_TREE_RE.search(text))


_TOKEN_RE = re.compile(r"""[^\s"'`(){}\[\],;|&<>]{2,240}""")


def _instruction_candidates(text: str) -> tuple[str, ...]:
    """Filename-shaped tokens in a shell line or a code blob that count as instruction files."""
    found: list[str] = []
    for match in _TOKEN_RE.finditer(text or ""):
        token = match.group(0).strip("'\"`")
        if token and is_instruction_path(token):
            found.append(token)
    return tuple(dict.fromkeys(found))

# Network clients that reach out. Interpreters are handled separately below: `python -c` is only a
# network client when the code actually uses a network library, otherwise every dotted identifier in
# a script becomes a "host" and every sensitive path a "send".
_NET_CLIENTS = (
    r"(?<![\w.\\-])(?:curl|wget|httpie|http|nc|ncat|netcat|scp|sftp|rsync|ftp|telnet|ssh|pwsh|"
    r"powershell|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)(?![\w\\-])"
)

_INTERPRETER_RE = r"(?:python[0-9.]*\s+-c|node\s+-e|perl\s+-e|ruby\s+-e)"
_NETWORK_LIB_RE = (
    r"(?:requests\.|urllib|http\.client|httpx\.|socket\.|urlopen|fetch\(|axios|"
    r"Invoke-WebRequest|paramiko|ftplib|smtplib|boto3)"
)

_SEND_MARKERS = (
    "--data",
    "--data-binary",
    "--data-raw",
    "-d ",
    "--form",
    "--upload-file",
    "--post-file",
    "-X POST",
    "-XPUT",
    "-X PUT",
    "--method POST",
    "requests.post",
    "requests.put",
    "urlopen(",
    "httpx.post",
    "fetch(",
    "XMLHttpRequest",
    "Method Post",
    "-m POST",
)

# curl/wget-only upload flags. Kept out of the generic list because `-T` is also ssh's
# "no pseudo-terminal" flag, `-F` is a field flag in other CLIs (`gh api -f`), and `--json` is a
# response-format flag everywhere except curl, where it uploads a body.
_CLIENT_UPLOAD_RE = re.compile(r"(?:^|\s)(?:-[TF]|--json)\s")

_URL_HOST_RE = re.compile(r"https?://([^/\s\"'<>()\[\]\\]+)", re.I)

# Bare-host detection is restricted to real TLDs. Without this, a dotted identifier in a script
# (`sys.path.insert`) is read as a hostname, which then feeds the egress rules.
_KNOWN_TLDS = frozenset(
    """com net org edu gov int io co ai app dev sh xyz info biz me tv cc cloud site online store
    tech space live news blog pro top page link email group team work world today life zone host
    website press media agency digital studio design software systems network solutions services
    uk de fr nl ru ua pl it es se no fi dk cz gr tr cn jp in br mx ar cl za au nz ca us test
    example localhost internal lan""".split()
)
_BARE_HOST_RE = re.compile(
    r"(?<![\w./-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:"
    + "|".join(sorted(_KNOWN_TLDS))
    + r"))(?::\d{1,5})?(?![\w.-])",
    re.I,
)

# Local-only destinations: never an exfil channel worth gating.
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0", "host.docker.internal"})

_MCP_TOOL_RE = re.compile(r"^mcp__([a-z0-9_.-]+?)__")

# Shell command separators. `a; b` and `a | b` are two steps, and only a single step that both
# names a sensitive path and reaches the network is the exfil composite.
_SEGMENT_SPLIT_RE = re.compile(r"\|\||&&|[;\n|]")


def segments_of(command: str) -> tuple[str, ...]:
    """Split a shell line into its steps, so unrelated clauses are not read as one action."""
    return tuple(s.strip() for s in _SEGMENT_SPLIT_RE.split(command or "") if s.strip())


@dataclass(frozen=True)
class Source:
    """Where a piece of content came from."""

    trust: str  # "trusted" | "untrusted" | "unknown"
    label: str  # short human label, e.g. "web_fetch:evil.test"
    tool: str
    host: str = ""
    reason: str = ""

    @property
    def is_untrusted(self) -> bool:
        return self.trust == "untrusted"


@dataclass
class Egress:
    """A network destination a tool call would reach."""

    hosts: tuple[str, ...] = ()
    sends_data: bool = False
    detail: str = ""

    def external_hosts(self, allow: frozenset[str]) -> tuple[str, ...]:
        return tuple(
            h for h in self.hosts if h.lower() not in _LOCAL_HOSTS and not _host_allowed(h, allow)
        )


@dataclass
class PathTouches:
    """Filesystem paths a tool call reads or writes, split by sensitivity."""

    paths: tuple[str, ...] = ()
    sensitive: tuple[str, ...] = ()
    #: Sensitive paths that are *read* rather than written — what `credential_read` acts on.
    sensitive_reads: tuple[str, ...] = ()
    outside_workspace: tuple[str, ...] = ()
    instruction: tuple[str, ...] = ()
    #: Real write targets only — the sole thing that becomes a tainted artifact. A directory that a
    #: command merely walks through must not turn every later command into untrusted content.
    written_paths: tuple[str, ...] = ()
    writes: bool = False
    meta: dict = field(default_factory=dict)


def _strip_port(host: str) -> str:
    """Drop a ``:port`` suffix so allowlist entries match regardless of port (and so loopback
    detection is not defeated by ``127.0.0.1:8099``)."""
    host = (host or "").strip().lower()
    if host.startswith("["):  # bracketed IPv6, e.g. [::1]:8099
        return host.split("]", 1)[0].lstrip("[")
    return host.split(":", 1)[0]


def host_of(url: str) -> str:
    match = _URL_HOST_RE.search(url or "")
    return _strip_port(match.group(1).split("@")[-1]) if match else ""


def _host_allowed(host: str, allow: frozenset[str]) -> bool:
    host = host.lower()
    for entry in allow:
        entry = entry.lower().lstrip(".")
        if host == entry or host.endswith("." + entry):
            return True
    return False


def classify(tool_name: str, args: dict, *, workspace: str = "", tainted_artifact: str = "") -> Source:
    """Classify a tool call's *result* provenance before it is appended to the conversation.

    Only genuine third-party authorship taints: remote fetches, MCP servers, screens and images,
    and files that were themselves written during a tainted turn (``tainted_artifact``). A plain
    local file read is the user's own material — flagging those would taint every coding session
    and gate work for no reason.
    """
    tool = (tool_name or "").strip()

    mcp = _MCP_TOOL_RE.match(tool)
    if mcp:
        return Source("untrusted", f"{tool} (mcp:{mcp.group(1)})", tool, reason="third-party MCP server")

    if tool in UNTRUSTED_TOOLS:
        host = ""
        for key in ("url", "href", "target", "query", "image_url", "path"):
            value = args.get(key) if isinstance(args, dict) else None
            if isinstance(value, str):
                host = host or host_of(value)
        label = f"{tool}:{host}" if host else tool
        return Source("untrusted", label, tool, host=host, reason="content authored by a third party")

    if tainted_artifact:
        return Source(
            "untrusted",
            f"file:{_short(tainted_artifact)}",
            tool,
            reason=f"file written from untrusted content ({tainted_artifact})",
        )

    if tool in PATH_GATED_TOOLS:
        # A shell command that reaches the network returns third-party content, exactly like a
        # fetch tool does. Reading a local file does not — flagging those would taint every
        # coding session and gate work for no reason.
        egress = egress_of(tool, args)
        if egress.hosts:
            host = egress.hosts[0]
            return Source(
                "untrusted",
                f"{tool}:{host}",
                tool,
                host=host,
                reason="content fetched from the network by a shell command",
            )
        return Source("trusted", tool, tool)

    if tool in {"write_file", "patch"}:
        return Source("trusted", tool, tool)

    if not tool:
        return Source("unknown", "unknown", tool, reason="no tool name supplied")

    return Source("unknown", tool, tool, reason="tool not in the trust table")


def _short(path: str, limit: int = 60) -> str:
    path = str(path).replace("\\", "/")
    return path if len(path) <= limit else "…" + path[-limit:]


def _paths_in(args: dict) -> tuple[str, ...]:
    """Best-effort path extraction from tool arguments (``path``, ``file_path``, or a shell line)."""
    if not isinstance(args, dict):
        return ()
    found: list[str] = []
    for key in ("path", "file_path", "paths", "target", "directory", "cwd", "glob"):
        value = args.get(key)
        if isinstance(value, str) and value:
            found.append(value)
        elif isinstance(value, (list, tuple)):
            found.extend(str(v) for v in value if isinstance(v, str) and v)
    command = args.get("command")
    if isinstance(command, str) and command:
        found.extend(_paths_from_command(command))
    return tuple(dict.fromkeys(found))


_PATH_TOKEN_RE = re.compile(r"""(?:^|[\s"'=<>|(,@])((?:~|\.{1,2}|[A-Za-z]:|[\\/])[^\s"'<>|;)]{1,240})""")

# Output targets in a shell line: a redirect, `-o`, `--output`, or `tee`. Only these count as a
# write for taint propagation.
_REDIRECT_RE = re.compile(
    r"""(?:>>?|--output[= ]|--outfile[= ]|-o\s|tee\s+(?:-a\s+)?)\s*("?)([^\s"'|;&><]+)\1"""
)

# Destinations that are not a write: the `2>&1` idiom (already excluded by the char class) and the
# null sinks. Treating these as writes gated most real shell commands in a tainted session.
_NULL_TARGETS = frozenset({"/dev/null", "nul", "nul:", "$null", "/dev/stdout", "/dev/stderr"})

# Scratch space. Writing there from a tainted session is normal work, not worth a prompt.
_TEMP_MARKERS = (
    "/tmp/",
    "/var/tmp/",
    "/private/tmp/",
    "/temp/",
    "/appdata/local/temp/",
    "/cache/scratch/",
)


def is_temp_path(path: str) -> bool:
    text = str(path or "").replace("\\", "/").lower()
    return any(marker in text for marker in _TEMP_MARKERS)

# Verbs that change the filesystem without a redirect.
_DESTRUCTIVE_RE = re.compile(r"\b(?:rm|rmdir|mv|cp|install|truncate)\b|\bsed\s+-i\b", re.I)

# Code-bearing tools write without a path argument, so the code text is inspected for a write verb
# before any filename in it is treated as a destination.
_CODE_WRITE_RE = re.compile(
    r"(?i)(?:open\s*\([^)\n]{0,120}['\"][wax]|write_text|write_bytes|shutil\.|"
    r"os\.(?:remove|rename|replace|unlink|makedirs)|subprocess|os\.system|popen|"
    r"\.write\(|>>?\s*\S)"
)


def _redirect_targets(command: str) -> tuple[str, ...]:
    """Real output targets only. ``2>&1``, ``>/dev/null`` and friends write nothing."""
    targets = (m.group(2) for m in _REDIRECT_RE.finditer(command or ""))
    return tuple(dict.fromkeys(t for t in targets if t.lower() not in _NULL_TARGETS))


def _paths_from_command(command: str) -> list[str]:
    return [m.group(1) for m in _PATH_TOKEN_RE.finditer(command or "")]


def _expanded(path: str) -> str:
    """``~`` is a placeholder, not a location: expand it before asking where a path lands.

    Skipping ``~``-prefixed paths made every home-relative write invisible to the outside-workspace
    check — ``write_file("~/.bashrc")`` in a tainted session was never even considered.
    """
    return os.path.expanduser(path) if path.startswith("~") else path


def _inside(path: str, workspace: str) -> bool:
    try:
        if re.match(r"^[A-Za-z]:[\\/]", path) or path.startswith("\\\\"):
            p = PureWindowsPath(path)
        elif path.startswith("~") or path.startswith("/"):
            p = PurePosixPath(path.replace("\\", "/"))
        else:
            return True  # relative path: assume it resolves inside the workspace
        w = PureWindowsPath(workspace) if re.match(r"^[A-Za-z]:[\\/]", workspace) else PurePosixPath(
            workspace.replace("\\", "/")
        )
        return p == w or w in p.parents
    except Exception:
        return True  # never gate on a path we could not parse


def egress_of(tool_name: str, args: dict) -> Egress:
    """Network destinations a tool call would reach, and whether it sends data outward."""
    tool = (tool_name or "").strip()
    if not isinstance(args, dict):
        args = {}

    if tool in {"browser_exec", "web_fetch", "web_extract", "drive_preview", "computer_use"}:
        blob = " ".join(str(args.get(k, "")) for k in ("url", "href", "target", "code", "command", "action"))
        hosts = tuple(dict.fromkeys(_hosts_in(blob)))
        sends = any(marker.lower() in blob.lower() for marker in ("post", "upload", "submit", "fill", "type", "click", "send"))
        return Egress(hosts=hosts, sends_data=sends, detail="browser/web navigation")

    if tool == "terminal":
        command = str(args.get("command", ""))
        return _egress_from_command(command)

    if tool == "text_to_speech":
        return Egress(detail="audio synthesis")

    return Egress()


def _hosts_in(blob: str) -> list[str]:
    hosts = [m.group(1).split("@")[-1] for m in _URL_HOST_RE.finditer(blob or "")]
    if not hosts:
        hosts = [m.group(1) for m in _BARE_HOST_RE.finditer(blob or "")]
    return [_strip_port(h) for h in hosts if h]


def _egress_from_command(command: str) -> Egress:
    command = command or ""
    lowered = command.lower()
    real_client = bool(re.search(_NET_CLIENTS, command, re.I))
    # An interpreter counts as a network client only when the code uses a network library.
    interpreter = bool(re.search(_INTERPRETER_RE, command, re.I)) and bool(
        re.search(_NETWORK_LIB_RE, command, re.I)
    )
    if not (real_client or interpreter):
        return Egress()

    hosts = tuple(dict.fromkeys(_hosts_in(command)))
    sends = any(marker.lower() in lowered for marker in _SEND_MARKERS)
    if not sends and real_client:
        sends = bool(_CLIENT_UPLOAD_RE.search(command)) and bool(
            re.search(r"(?:curl|wget)", command, re.I)
        )
    if not sends:
        # A network client with a piped body (`| nc host`, `cat x | curl`) is a send too.
        sends = bool(re.search(r"\|\s*(?:curl|nc|ncat|netcat|ssh|scp)", lowered))
    if real_client and SENSITIVE_PATH_RE.search(command):
        # A real network client with a sensitive path in the same command is a send, period.
        sends = True
    return Egress(hosts=hosts, sends_data=sends, detail="shell network client")


# Commands that can actually read a file. A shell line that merely *names* a credential path — in a
# commit message, a log line, a comment — is not a read; `curl -d @key` is still caught by the
# same-step exfiltration composite, which matches the path directly.
_READ_VERB_RE = re.compile(
    r"(?i)(?:^|[\s|;&(,=\[{])(?:"
    r"(?:cat|bat|less|more|head|tail|type|strings|xxd|od|base64|tar|zip|unzip|"
    r"grep|rg|awk|sed|cut|sort|uniq|diff|"
    r"cp|mv|scp|rsync|sftp|ftp|"
    r"curl|wget|nc|ncat|socat|"
    r"ssh-keygen|ssh-add|ssh|openssl|gpg|age|certutil|"
    r"python\d?|py|node|deno|bun|ruby|perl|php|powershell|pwsh|cmd|"
    r"get-content|gc|readfile|read_file|get_file)\b"
    r"|git\s+(?:add|stage|show|diff|cat-file|restore|checkout)\b"
    r"|(?:open|read|load|read_text|read_bytes)\s*\("
    r")"
)


def _reads_what_it_names(tool: str, args: dict) -> bool:
    """True when the call is a file tool, or a shell line that uses a command able to read a file.

    File tools pass their target as an argument, so the path *is* the read. Shell text is different:
    ``cat ~/.ssh/id_rsa`` reads, while ``git commit -m "stop reading .env"`` only mentions one.
    """
    text = ""
    if tool in PATH_GATED_TOOLS:
        text = str(args.get("command") or "")
    elif tool in {"execute_code", "process_manage"}:
        text = str(args.get("code") or args.get("script") or args.get("data") or "")
    if not text.strip():
        return True
    return bool(_READ_VERB_RE.search(text))


# `powershell -enc <base64>` is the standard way to hide a payload from anything that reads the
# command line: the line itself is noise. PowerShell encodes UTF-16LE; plain UTF-8 shows up too.
_ENCODED_BLOB_RE = re.compile(r"(?i)(?:-enc|--encodedcommand|-encodedcommand)\s+([A-Za-z0-9+/=]{24,})")
_PIPED_B64_RE = re.compile(r"(?i)base64\s+(?:-d|--decode)\s*<<<\s*['\"]?([A-Za-z0-9+/=]{24,})")

# A written *script* is the two-step attack: step 1 writes the payload, step 2 runs it, and no rule
# ever sees the credential on a command line. Only these destinations are treated that way — a
# README that documents an exfil command is not a payload.
_SCRIPT_EXT_RE = re.compile(
    r"(?i)\.(?:py|pyw|sh|bash|zsh|ps1|psm1|bat|cmd|js|mjs|cjs|ts|rb|pl|php|vbs|wsf|jar|exe)$"
)


def decode_payloads(text: str) -> list[str]:
    """Decoded forms of an obfuscated command line, newest-first order not guaranteed.

    The caller evaluates each as its own call, so an encoded payload is judged by what it does
    rather than by how it reads.
    """
    out: list[str] = []
    if not text:
        return out
    for match in list(_ENCODED_BLOB_RE.finditer(text)) + list(_PIPED_B64_RE.finditer(text)):
        blob = match.group(1)
        padded = blob + "=" * (-len(blob) % 4)
        for encoding in ("utf-16-le", "utf-8"):
            try:
                decoded = base64.b64decode(padded, validate=False).decode(encoding, "ignore")
            except Exception:
                continue
            decoded = decoded.strip()
            if len(decoded) >= 8 and decoded not in out:
                out.append(decoded)
    return out


# Content is not a command line: in a list literal the flag sits next to a quote or a comma
# (`['curl','-d','@key']`), so the command-line markers are too strict for file text.
_CONTENT_SEND_RE = re.compile(
    r"(?i)(?:"
    r"(?:^|[\s,=(\[{])-{1,2}(?:d|F|T|data|data-binary|data-raw|json|form|upload-file|post-file)\b|"
    r"requests\.(?:post|put)|httpx\.post|urlopen\(|urllib|fetch\(|"
    r"Invoke-WebRequest|Invoke-RestMethod|\bcurl\b|\bwget\b|\bncat?\b|socat"
    r")"
)


def _is_reserved_host(host: str) -> bool:
    """True for names that cannot receive anything (RFC 2606 / 6761, plus loopback)."""
    host = _strip_port(str(host or "")).lower().strip(".")
    if host in ("127.0.0.1", "::1", "0.0.0.0", "localhost", "example.com", "example.org", "example.net"):
        return True
    return bool(re.search(r"(?:^|\.)(?:test|example|invalid|localhost|local|internal|lan|home)$", host))


def _only_reserved_hosts(text: str) -> bool:
    """True when every host named in the text is one that cannot receive data."""
    hosts = [match.group(1) for match in _URL_HOST_RE.finditer(text)]
    return bool(hosts) and all(_is_reserved_host(host) for host in hosts)


def payload_in_content(path: str, content: str) -> str:
    """Detail string when a written script both names a credential and sends data, else ``""``.

    A script that only ever sends to a reserved name (`*.test`, `example.com`, loopback) is an
    example — a security fixture, or a document describing an attack — not a payload: nothing can be
    exfiltrated to a host that does not resolve. That is the one principled way to tell an attack
    from its description, and it is what stops the rule from flagging the tests for the rule.
    """
    if not content or not _SCRIPT_EXT_RE.search(str(path or "")):
        return ""
    match = SENSITIVE_PATH_RE.search(content)
    if not match:
        return ""
    if not _CONTENT_SEND_RE.search(content):
        return ""
    if _only_reserved_hosts(content):
        return ""
    return f"{path} names {match.group(0)} and sends data"


# What a shell line *runs*, as opposed to reads: an interpreter argument, `./script`, `cmd /c`.
# Running a file this session pulled in while tainted is the payload path — step 2 never has to name
# a credential on the command line for the attack to work.
_EXEC_RE = re.compile(
    r"(?i)(?:^|[\s|;&(])(?:python\d?|py|node|deno|bun|bash|sh|zsh|perl|ruby|php|pwsh|"
    r"powershell(?:\s+-file)?|cmd\s+/c|source)\s+([^\s|;&)\"']+)"
)
_EXEC_BARE_RE = re.compile(r"(?:^|[\s|;&(])(\.{1,2}[/\\][^\s|;&)\"']+)")


def executed_paths(tool_name: str, args: dict) -> tuple[str, ...]:
    """Files a call would *run* rather than read."""
    tool = (tool_name or "").strip()
    text = ""
    if tool in PATH_GATED_TOOLS:
        text = str(args.get("command") or "")
    elif tool in {"execute_code", "process_manage"}:
        text = str(args.get("code") or args.get("script") or args.get("data") or "")
    if not text:
        return ()
    found = [match.group(1) for match in _EXEC_RE.finditer(text)]
    found += [match.group(1) for match in _EXEC_BARE_RE.finditer(text)]
    return tuple(dict.fromkeys(path for path in found if path))


def paths_of(tool_name: str, args: dict, *, workspace: str = "") -> PathTouches:
    """Filesystem touches for the policy engine: which are sensitive, which leave the workspace."""
    tool = (tool_name or "").strip()
    if not isinstance(args, dict):
        args = {}
    if tool not in PATH_GATED_TOOLS and tool not in {
        "write_file",
        "patch",
        "skill_manage",
        "execute_code",
    }:
        return PathTouches()

    paths = _paths_in(args)
    sensitive = tuple(
        p for p in paths if is_sensitive_path(p) and _reads_what_it_names(tool, args)
    )
    outside = tuple(p for p in paths if workspace and not _inside(_expanded(p), workspace))
    command = str(args.get("command", "")) if tool in PATH_GATED_TOOLS else ""
    code = str(args.get("code") or args.get("script") or "") if tool == "execute_code" else ""

    if tool in {"write_file", "patch", "skill_manage"}:
        written = tuple(
            value
            for key in ("path", "file_path")
            if isinstance(value := args.get(key), str) and value
        )
    elif command:
        written = _redirect_targets(command)
    elif code and _CODE_WRITE_RE.search(code):
        written = _instruction_candidates(code)
    else:
        written = ()

    writes = tool in {"write_file", "patch", "skill_manage"} or bool(written) or (
        bool(command) and bool(_DESTRUCTIVE_RE.search(command))
    )

    written_set = {w.replace("\\", "/").lower() for w in written}
    sensitive_reads = tuple(
        p for p in sensitive if p.replace("\\", "/").lower() not in written_set
    )

    instruction: tuple[str, ...] = ()
    if writes:
        # A shell redirect names its target without any path syntax, and code writes name it inside
        # a string literal, so the raw text is scanned too — but only for writes, so reading those
        # files is never gated.
        found = [*_instruction_candidates(command), *_instruction_candidates(code)]
        found += [c for c in (*paths, *written) if is_instruction_path(c)]
        instruction = tuple(dict.fromkeys(found))

    return PathTouches(
        paths=tuple(paths),
        sensitive=sensitive,
        sensitive_reads=sensitive_reads,
        outside_workspace=outside,
        instruction=instruction,
        written_paths=written,
        writes=writes,
    )


def written_text(args: dict) -> str:
    """The text a write tool is about to put on disk. Empty for tools that write nothing."""
    if not isinstance(args, dict):
        return ""
    parts = [args.get(key) for key in ("content", "new_string", "file_content")]
    return "\n".join(p for p in parts if isinstance(p, str) and p)


def workspace_of(args: dict) -> str:
    """The working directory a call is anchored to, if the tool declares one."""
    if isinstance(args, dict):
        for key in ("workdir", "cwd", "directory"):
            value = args.get(key)
            if isinstance(value, str) and value:
                return value
    return ""


def describe_sources(sources: dict) -> str:
    """Render taint sources for a banner or receipt: ``web_fetch:evil.test (2)``."""
    parts = []
    for label, info in sorted(sources.items()):
        count = info.get("count", 1) if isinstance(info, dict) else 1
        parts.append(f"{label}×{count}" if count > 1 else label)
    return ", ".join(parts)


__all__ = [
    "Source",
    "Egress",
    "PathTouches",
    "classify",
    "egress_of",
    "paths_of",
    "written_text",
    "host_of",
    "workspace_of",
    "describe_sources",
    "SENSITIVE_PATH_RE",
    "UNTRUSTED_TOOLS",
    "UNTRUSTED_PREFIXES",
]
