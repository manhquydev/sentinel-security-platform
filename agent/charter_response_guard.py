"""Canonical guard for untrusted HTTP-response content used by the charter agent."""
from __future__ import annotations

import re
from dataclasses import dataclass

from .pii import redact, scrub

PREVIEW_BYTE_LIMIT = 512
PREVIEW_SCALAR_LIMIT = 256

_ATTEMPTS = (
    ("objective-change", re.compile(r"\b(?:ignore|change|replace)\b.{0,80}\b(?:objective|goal|task|instructions?)\b", re.I | re.S)),
    ("secret-disclosure", re.compile(r"\b(?:reveal|disclose|print|show)\b.{0,80}\b(?:system prompt|api[ _-]?key|token|secret|password)\b", re.I | re.S)),
    ("out-of-scope-tool", re.compile(r"\b(?:run|call|invoke|execute)\b.{0,80}\b(?:shell|curl|wget|browser|tool|command)\b", re.I | re.S)),
)

# The terminal evaluator rejects any unlabelled phone-shaped sequence from a
# persisted response projection. The executor must make the same conservative
# decision before a preview is persisted; otherwise a target response can pass
# the capture guard yet make final publication impossible. This detector is
# intentionally confined to the response-preview boundary, not the shared PII
# scrubber used for scanner evidence, where bare numeric identifiers are useful.
_UNLABELLED_PHONE_SHAPE = re.compile(r"\b(?:\+?\d[ .()\-]?){8,15}\b")


@dataclass(frozen=True)
class ResponseGuardResult:
    status: str  # accepted | quarantined
    reasons: tuple[str, ...]
    persisted_text: str


@dataclass(frozen=True)
class ResponsePreview:
    """The only response-derived projection permitted to leave the executor."""

    status: str  # accepted | quarantined
    quarantine: dict[str, int]
    preview: str | None = None
    preview_truncated: bool | None = None


def guard_http_response(content: str | None) -> ResponseGuardResult:
    """Compatibility guard for existing retrieval callers.

    This legacy surface redacts PII before returning text.  The charter executor
    uses ``guard_response_preview`` below instead, where any PII quarantines.
    """
    safe = scrub(content) or ""
    reasons = tuple(name for name, pattern in _ATTEMPTS if pattern.search(safe))
    return ResponseGuardResult("quarantined" if reasons else "accepted", reasons, safe)


def _media_reason(content_types: tuple[str, ...]) -> str | None:
    if type(content_types) is not tuple:
        return "media-malformed"
    if not content_types:
        return "media-missing"
    if len(content_types) != 1:
        return "media-duplicate"
    value = content_types[0]
    if type(value) is not str or not value or any(ord(character) < 32 or ord(character) > 126 for character in value):
        return "media-malformed"
    pieces = value.split(";")
    if any(not piece.strip() for piece in pieces):
        return "media-malformed"
    media = pieces[0].strip().lower()
    if "/" not in media or any(character.isspace() for character in media):
        return "media-malformed"
    parameters = [piece.strip() for piece in pieces[1:]]
    parsed: list[tuple[str, str]] = []
    for parameter in parameters:
        if parameter.count("=") != 1:
            return "media-malformed"
        name, parameter_value = (part.strip() for part in parameter.split("=", 1))
        if not name or not parameter_value or any(character.isspace() for character in parameter_value):
            return "media-malformed"
        parsed.append((name.lower(), parameter_value.lower()))
    charset_count = sum(name == "charset" for name, _ in parsed)
    if charset_count > 1:
        return "media-duplicate"
    if media != "application/json" or len(parsed) != 1 or parsed[0] != ("charset", "utf-8"):
        return "media-unsupported"
    return None


def _bounded_prefix(text: str) -> tuple[str, bool]:
    prefix: list[str] = []
    byte_count = 0
    for character in text:
        encoded_length = len(character.encode("utf-8"))
        if len(prefix) == PREVIEW_SCALAR_LIMIT or byte_count + encoded_length > PREVIEW_BYTE_LIMIT:
            break
        prefix.append(character)
        byte_count += encoded_length
    value = "".join(prefix)
    return value, value != text


def guard_response_preview(body: bytes, content_types: tuple[str, ...]) -> ResponsePreview:
    """Classify full capped bytes and return a bounded safe projection only.

    Neither a response body nor a media header is included in an error result.
    """
    media = _media_reason(content_types)
    if media:
        return ResponsePreview("quarantined", {media: 1})
    if type(body) is not bytes:
        return ResponsePreview("quarantined", {"decode-invalid-utf8": 1})
    try:
        text = body.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return ResponsePreview("quarantined", {"decode-invalid-utf8": 1})
    scrubbed, pii_findings = redact(text)
    reasons: dict[str, int] = {}
    for finding in pii_findings:
        reason = f"pii-{finding.cls}"
        reasons[reason] = reasons.get(reason, 0) + finding.count
    unlabelled_phone_count = len(_UNLABELLED_PHONE_SHAPE.findall(scrubbed or ""))
    if unlabelled_phone_count:
        reasons["pii-phone"] = reasons.get("pii-phone", 0) + unlabelled_phone_count
    for name, pattern in _ATTEMPTS:
        if pattern.search(text):
            reasons[name] = reasons.get(name, 0) + 1
    if reasons:
        return ResponsePreview("quarantined", reasons)
    preview, truncated = _bounded_prefix(text)
    return ResponsePreview("accepted", {}, preview, truncated)
