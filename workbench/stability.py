"""Positive, negative, and stability canary gate for B3."""
from __future__ import annotations

from typing import Mapping


class StabilityViolation(ValueError):
    """Raised when the exact B3 control set is absent or changed."""


def validate_canaries(
    responses: Mapping[str, Mapping[str, object]],
    *,
    expected: Mapping[str, set[str]],
) -> bool:
    required = {"positive", "negative", "stability"}
    if set(responses) != required or set(expected) != required:
        raise StabilityViolation("B3 requires positive, negative, and stability canaries")
    for name in sorted(required):
        value = responses[name]
        if not isinstance(value, Mapping) or set(value) != {"proposal_ids"}:
            raise StabilityViolation("B3 canary response has an unexpected shape")
        actual = value["proposal_ids"]
        if not isinstance(actual, list) or set(actual) != expected[name]:
            raise StabilityViolation(f"B3 {name} canary changed")
    return True
