"""The committed fuzzing payload corpus (decision 0013: hybrid — this is the deterministic half).

Every payload here is READ-SAFE: it is designed to go into a GET query parameter, where it can
only make the target *read* (a search, a lookup). None of these change server state. State-
changing / exploit payloads are a separate, reserved set (not sent until Week-8 HITL), and are
deliberately NOT in this module.

The corpus is small and reviewable on purpose: the LLM's job (decision 0013) is to rank and mutate
from what the responses show, not to invent a boundary-value corpus from scratch. Grouping by
class lets the engine report which class produced a signal and lets the LLM reason over classes.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Payload:
    cls: str      # payload class, e.g. "sqli", "xss", "boundary"
    value: str


# A benign value per target is used to record the baseline the detectors compare against.
BENIGN = "apple"

CORPUS: list[Payload] = [
    # boundary / malformed inputs
    Payload("boundary", ""),
    Payload("boundary", " "),
    Payload("boundary", "0"),
    Payload("boundary", "-1"),
    Payload("boundary", "2147483648"),          # 2^31, off the int boundary
    Payload("boundary", "A" * 5000),            # oversize
    Payload("boundary", "\x00"),                # raw null byte
    Payload("boundary", "%00"),                 # encoded null
    Payload("type-confusion", "a[]=1"),          # array-style param confusion
    # SQL injection markers (read-only: they alter a SELECT, not state)
    Payload("sqli", "'"),
    Payload("sqli", "' OR '1'='1"),
    Payload("sqli", "')--"),
    Payload("sqli", "' UNION SELECT NULL--"),
    Payload("sqli", "1) OR (1=1"),
    # cross-site scripting / reflection probes
    Payload("xss", "<script>alert(1)</script>"),
    Payload("xss", "\"><img src=x onerror=1>"),
    Payload("xss", "javascript:alert(1)"),
    # path traversal (read attempt)
    Payload("traversal", "../../../../etc/passwd"),
    Payload("traversal", "..%2f..%2f..%2fetc%2fpasswd"),
    # template / expression injection probes
    Payload("template", "${7*7}"),
    Payload("template", "{{7*7}}"),
    # NoSQL operator probe
    Payload("nosql", "[$ne]=1"),
]


def classes() -> list[str]:
    """Distinct payload classes in the corpus, in stable order."""
    seen: list[str] = []
    for p in CORPUS:
        if p.cls not in seen:
            seen.append(p.cls)
    return seen


def by_classes(wanted: list[str]) -> list[Payload]:
    """Corpus filtered to the requested classes (used when the LLM prioritizes a class)."""
    want = set(wanted)
    return [p for p in CORPUS if p.cls in want]
