"""Outbound-secret redaction for the Sentinel LLM gateway egress path.

Decision 0006 assigns Stream E "secret redaction on the egress path ... protecting
this host from what it sends to a third-party router that publishes no retention
terms". This module is that hygiene layer. It runs on every outbound message right
before the proxy call and strips anything that looks like a credential this host
holds, replacing it with a stable placeholder and recording an audit entry that
names the detector and a length/position hint - never the value, a substring of it,
or a hash of it, because a hash of a short secret is brute-forceable and defeats the
point of redacting in the first place.

The harder design constraint is what this module must NOT touch. Sentinel's agents
scan deliberately vulnerable targets (OWASP Juice Shop, WebGoat), so this gateway's
*legitimate* traffic is made of SQL injection payloads, XSS strings, path traversal
strings, stack traces, and file hashes - the actual work product. A redactor tuned to
"anything that looks suspicious" mangles that workload, and a guardrail that quietly
corrupts prompts degrades every downstream finding invisibly: a slightly-worse LLM
answer looks exactly like a slightly-worse LLM, so nobody notices the guardrail broke
the run. Decision 0006 makes the same call for injection *detection* at this layer,
for the same underlying reason (see
docs/decisions/0006-the-gateway-labels-provenance-it-does-not-detect-injection.md):
production classifiers
tuned to attack-shaped content either miss camouflaged attacks or false-positive on
legitimate security vocabulary, and there is no way to have it both ways with a
pattern matcher. This module accepts the narrower, tractable version of that problem
- credentials have identifiable shapes (known prefixes, assignment syntax, JWT/PEM
structure) that attack payloads do not - and draws two lines deliberately:

- A standalone long hex run (SHA-256 file hash territory) is never redacted, only
  flagged as `unclassified-high-entropy` with `redacted: false`. In this workload a
  64-char hex string is overwhelmingly a file hash inside a legitimate scanner
  finding, not a secret; redacting it would destroy real evidence for no security
  benefit, since a bare hex string authenticates nothing on its own. Hex is only
  redacted when it appears as the *value* of a known credential assignment
  (`token=<hex>` etc.), because at that point the surrounding syntax - not the
  character set - is what makes it a credential.
- Attack payloads (`' OR 1=1--`, `<script>alert(1)</script>`, `../../etc/passwd`,
  and the like) are not pattern-matched at all. Nothing in the detector set below
  looks for "suspicious" shapes in general; every detector matches a specific,
  narrow credential shape (a known key prefix, an assignment keyword, PEM framing,
  JWT's three-dot structure, RFC 4122 UUID layout). A payload string does not
  collide with any of those shapes, so it passes through untouched.

Kept free of any litellm import so the logic is testable without the proxy installed,
and free of any third-party import so it has no supply-chain surface of its own.
"""

from __future__ import annotations

import re

# --- placeholder -------------------------------------------------------------------


def _placeholder(cls: str) -> str:
    return f"[redacted:{cls}]"


class RedactionError(ValueError):
    """Input to the redactor did not match the API contract (e.g. wrong type)."""


# --- detectors -----------------------------------------------------------------------
# Applied in this order, each pass over the output of the previous one. That ordering
# is load-bearing, not cosmetic:
#
# 1. PEM blocks first: they are large and distinctive, and redacting them whole
#    prevents their base64 body from later being partially matched by narrower
#    detectors (JWT, hex) and reported twice under the wrong class.
# 2. Assignment forms next: `token=<hex>` or `api_key="sk-..."` should be reported
#    once, under the assignment's class, using the syntax (a known key followed by
#    `=`/`:`) as the signal - not the shape of the value. Running this before the
#    prefix/JWT/hex detectors means an already-redacted value can never be
#    re-matched by them, because the placeholder text has none of their shapes.
# 3. Credential prefixes, then JWTs, then UUIDs: each is a narrow structural match
#    for a value with no key= syntax around it (a bare key pasted into a curl
#    command, for example).
# 4. Finally, standalone high-entropy hex is scanned for on what remains and only
#    ever flagged, never redacted - see the module docstring for why.

# PEM private-key blocks: `-----BEGIN ... PRIVATE KEY-----` through the matching END,
# non-greedy so two separate keys in one prompt are not merged into one match.
_PEM_BLOCK = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)

# Assignment-style credentials: a known key, a `=` or `:` separator, and a value that
# is either quoted (captured whole, spaces and all) or a single unquoted token. The
# `Bearer <token>` alternative is what makes `authorization: Bearer <jwt>` redact as
# one finding under the `authorization` class instead of leaving the token exposed
# after only the literal word "Bearer" gets consumed by the bare-token alternative.
# The optional closing quote after the key is not cosmetic. JSON is the dominant
# serialisation in this workload — scanner findings, HTTP captures, `docker inspect`
# output and config dumps all arrive as JSON — and `{"password":"x"}` puts a quote
# between the key and the colon. Without it the detector missed the most common shape it
# exists for and only appeared to work because a few values carry their own recognisable
# prefix.
#
# The scheme list generalises `Bearer`: an unlisted scheme fell through to the bare
# alternative, which consumed only the scheme word and left the credential in place while
# still recording a redaction — a false clean signal, worse than no detector.
#
# `&` and `#` terminate the bare value because a query string continues past the
# credential: consuming to the next space swallowed `&csrf=...` and destroyed adjacent
# evidence, which is the corruption this module is built to avoid.
_ASSIGNMENT = re.compile(
    r"(?P<head>\b(?P<key>token|secret|password|passwd|api[_-]?key|client[_-]secret"
    r"|access[_-]token|refresh[_-]token|private[_-]key|access[_-]key|authorization|cookie)"
    r"[\"']?\s*[:=]\s*)"
    r"(?:\"(?P<dq>[^\"]+)\"|'(?P<sq>[^']+)'"
    r"|(?P<scheme>(?:Bearer|Basic|Digest|Negotiate|Token|ApiKey)\s+\S+)"
    r"|(?P<bare>[^\s,;&#\"']+))",
    re.IGNORECASE,
)

# A DSN carries its password inside the URL. This repository's own compose files avoid
# DSNs for exactly that reason — "it shows up in tracebacks and in docker inspect" — and
# tracebacks are precisely what an agent pastes into a prompt.
_DSN_CREDENTIAL = re.compile(r"(?P<pre>[a-z][a-z0-9+.\-]*://[^\s:/@]+:)(?P<pw>[^\s@/]+)(?P<post>@)", re.IGNORECASE)

_ASSIGNMENT_CLASS = {
    "token": "token",
    "secret": "secret",
    "password": "password",
    "api_key": "api-key",
    "authorization": "authorization",
    "cookie": "cookie",
}

# Known credential prefixes. `\b` before each guards against matching mid-identifier
# (e.g. the "sk-" inside "risk-averse" never reaches a word boundary at the 's').
_CREDENTIAL_PREFIX = re.compile(
    r"\b(?:"
    r"(?P<openai>sk-[A-Za-z0-9_-]{10,})"
    r"|(?P<gh_pat>github_pat_[A-Za-z0-9_]{20,})"
    r"|(?P<gh_token>ghp_[A-Za-z0-9]{20,})"
    r"|(?P<aws_key>AKIA[0-9A-Z]{16})"
    r"|(?P<slack>xox[baprs]-[A-Za-z0-9-]{10,})"
    r")"
)

_PREFIX_CLASS = {
    "openai": "openai-key",
    "gh_pat": "github-pat",
    "gh_token": "github-token",
    "aws_key": "aws-access-key",
    "slack": "slack-token",
}

# JWTs: three base64url segments separated by dots, with the first anchored to `eyJ`.
#
# A length floor alone is not enough here. Three dotted segments of 10+ characters is
# also the shape of a Java package path, and Java source is exactly what the SAST arm
# sends through this gateway: `organization.applications.configuration.LoaderFactory`
# matched the length-only pattern and was rewritten to `[redacted:jwt]`, silently
# corrupting the source under analysis.
#
# `eyJ` is the base64url encoding of `{"` followed by the start of a JSON key, which is
# how every JWT header begins. Anchoring on it costs the ability to catch a JWT whose
# header is not JSON - which the standard does not permit - and buys immunity to the
# dotted-identifier false positive that this workload produces constantly.
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{7,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")

# RFC 4122 UUID layout.
_UUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")

# Standalone 64-char hex: SHA-256 hash territory. See module docstring - flagged, not
# redacted, unless it was already consumed above as an assignment value.
_HEX64 = re.compile(r"\b[0-9a-fA-F]{64}\b")


def _line_of(text: str, index: int) -> int:
    """1-based line number for a match offset, so an audit entry can point an operator
    at the right place without ever including the matched text itself."""
    return text.count("\n", 0, index) + 1


def _finding(cls: str, value_len: int, line: int, redacted: bool = True) -> dict:
    # `count` is the character length of what was matched, not the secret itself and
    # not a hash of it - a length alone does not let anyone reconstruct or brute-force
    # the value, even a short one, so it is safe to keep in an audit trail.
    return {"class": cls, "count": value_len, "line": line, "redacted": redacted}


def _apply(text: str, pattern: re.Pattern[str], cls: str, findings: list[dict]) -> str:
    def _sub(match: re.Match[str]) -> str:
        findings.append(_finding(cls, len(match.group()), _line_of(text, match.start())))
        return _placeholder(cls)

    return pattern.sub(_sub, text)


def _apply_assignment(text: str, findings: list[dict]) -> str:
    def _sub(match: re.Match[str]) -> str:
        key = match.group("key").lower().replace("-", "_")
        cls = _ASSIGNMENT_CLASS.get(key, key)
        value = match.group("dq") or match.group("sq") or match.group("scheme") or match.group("bare") or ""
        findings.append(_finding(cls, len(value), _line_of(text, match.start())))
        # `head` is the key plus its separator (`token=`, `Cookie: `); keeping it
        # intact preserves the surrounding syntax so the redacted text still reads
        # as the shape of a request, just with the value gone.
        return f"{match.group('head')}{_placeholder(cls)}"

    return _ASSIGNMENT.sub(_sub, text)


def _apply_dsn(text: str, findings: list[dict]) -> str:
    def _sub(match: re.Match[str]) -> str:
        findings.append(_finding("dsn-password", len(match.group("pw")), _line_of(text, match.start())))
        return f"{match.group('pre')}{_placeholder('dsn-password')}{match.group('post')}"

    return _DSN_CREDENTIAL.sub(_sub, text)


def _apply_credential_prefix(text: str, findings: list[dict]) -> str:
    def _sub(match: re.Match[str]) -> str:
        cls = _PREFIX_CLASS.get(match.lastgroup, "credential-prefix")
        findings.append(_finding(cls, len(match.group()), _line_of(text, match.start())))
        return _placeholder(cls)

    return _CREDENTIAL_PREFIX.sub(_sub, text)


def _flag_high_entropy_hex(text: str, findings: list[dict]) -> None:
    # Never rewrites text - see module docstring for why a bare hex run is treated
    # as probable file-hash evidence and only surfaced to an operator, not stripped.
    for match in _HEX64.finditer(text):
        findings.append(_finding("unclassified-high-entropy", len(match.group()), _line_of(text, match.start()), redacted=False))


# --- public API ------------------------------------------------------------------


def redact(text: str) -> tuple[str, list[dict]]:
    """Strip credentials out of one prompt string.

    Returns the redacted text and one audit entry per finding, ordered PEM block,
    then assignment-form credentials, then bare credential prefixes, then JWTs, then
    UUIDs, with standalone high-entropy hex flagged (not redacted) last. Each pass
    runs on the previous pass's output, so a value already replaced by a placeholder
    can never be re-matched and double-reported by a later, narrower detector.
    """
    if not isinstance(text, str):
        raise RedactionError(f"redact() requires a string, got {type(text).__name__}")

    findings: list[dict] = []
    working = _apply(text, _PEM_BLOCK, "pem-private-key", findings)
    working = _apply_assignment(working, findings)
    working = _apply_dsn(working, findings)
    working = _apply_credential_prefix(working, findings)
    working = _apply(working, _JWT, "jwt", findings)
    working = _apply(working, _UUID, "uuid", findings)
    _flag_high_entropy_hex(working, findings)
    return working, findings


def _redact_in_place(container, key, findings: list[dict], where: str) -> None:
    """Redact one text-bearing slot, recording where it was."""
    value = container[key]
    if not isinstance(value, str) or not value:
        return
    redacted, found = redact(value)
    if found:
        container[key] = redacted
        findings.extend({"location": where, **f} for f in found)


def redact_request(data: dict) -> tuple[dict, list[dict], list[str]]:
    """Redact every text-bearing location in a proxy request, whatever its shape.

    Returns the mutated request, the audit entries, and the list of locations that
    actually carried text. That last value is what lets the caller fail closed: a request
    whose content lives somewhere this function does not know about yields an empty list,
    and the guardrail can refuse rather than forward it unexamined.

    Keying redaction on `messages` alone was a silent bypass. The Responses API carries
    content in `input`, the legacy completion API in `prompt`, and tool arguments in
    `tool_calls[].function.arguments` — and the scanner this gateway was built for calls
    the Responses API exclusively. Requests on those routes left the host with the
    guardrail inert and were then persisted to the trace store in plaintext.
    """
    if not isinstance(data, dict):
        raise RedactionError(f"request must be an object, got {type(data).__name__}")

    findings: list[dict] = []
    covered: list[str] = []

    def walk_content(container, key, where):
        value = container.get(key)
        if isinstance(value, str) and value:
            covered.append(where)
            _redact_in_place(container, key, findings, where)
        elif isinstance(value, list):
            for index, part in enumerate(value):
                if isinstance(part, str) and part:
                    covered.append(f"{where}[{index}]")
                    _redact_in_place(value, index, findings, f"{where}[{index}]")
                elif isinstance(part, dict):
                    # Multimodal parts and Responses-API items both nest their text.
                    for text_key in ("text", "content", "input_text"):
                        if isinstance(part.get(text_key), str) and part[text_key]:
                            covered.append(f"{where}[{index}].{text_key}")
                            _redact_in_place(part, text_key, findings, f"{where}[{index}].{text_key}")
                        elif isinstance(part.get(text_key), list):
                            walk_content(part, text_key, f"{where}[{index}].{text_key}")

    messages = data.get("messages")
    if isinstance(messages, list):
        for index, message in enumerate(messages):
            if not isinstance(message, dict):
                continue
            walk_content(message, "content", f"messages[{index}].content")
            # Tool arguments are the quieter half: `content` is often null on a tool
            # call, so a redactor that only reads `content` sees nothing while a
            # credential rides in the arguments on every turn of an agent loop.
            for call_index, call in enumerate(message.get("tool_calls") or []):
                function = (call or {}).get("function") or {}
                if isinstance(function.get("arguments"), str) and function["arguments"]:
                    where = f"messages[{index}].tool_calls[{call_index}].arguments"
                    covered.append(where)
                    _redact_in_place(function, "arguments", findings, where)

    for key in ("input", "prompt", "instructions", "system"):
        walk_content(data, key, key)

    return data, findings, covered


def redact_messages(messages: list[dict]) -> tuple[list[dict], list[dict]]:
    """Apply redact() to every string message content.

    Non-string content (multimodal parts, tool-call payloads) is passed through
    unchanged rather than rejected: this runs on every outbound message regardless
    of provenance, and refusing the whole request over a shape this module does not
    parse would be a worse outcome than leaving that one field alone. The input list
    and its message dicts are never mutated - a message is only replaced (with a
    shallow copy carrying the redacted content) when a finding actually applies to
    it, so a caller that inspects the original request after the call still sees
    what it sent.
    """
    if not isinstance(messages, list):
        raise RedactionError(f"redact_messages() requires a list, got {type(messages).__name__}")

    out: list[dict] = []
    all_findings: list[dict] = []
    for index, message in enumerate(messages):
        if not isinstance(message, dict):
            raise RedactionError(f"message at index {index} must be an object, got {type(message).__name__}")

        content = message.get("content")
        if not isinstance(content, str):
            out.append(message)
            continue

        redacted_text, findings = redact(content)
        if not findings:
            out.append(message)
            continue

        rewritten = dict(message)
        rewritten["content"] = redacted_text
        out.append(rewritten)
        all_findings.extend({"message_index": index, **finding} for finding in findings)

    return out, all_findings
