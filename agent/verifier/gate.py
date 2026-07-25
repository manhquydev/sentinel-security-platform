"""Deterministic-first gate: skip the LLM for findings a high-precision rule already nails.

The verifier's FP-reduction must be measured as the LLM's MARGINAL contribution OVER this gate (the
red-team's attribution point), so the gate is explicit and committed. Rules whose precision is already
high get auto-KEEP (no LLM call, no cost); everything else is the LLM-triaged residual. The allowlist
starts small + conservative and is extended from measured per-rule precision on the corpus — never
guessed. An empty allowlist simply routes every flagged finding to the verifier (a valid, honest
starting point for the spike).
"""

from __future__ import annotations

# Semgrep rule_ids observed high-precision on the corpus (extend only from a measured per-rule
# precision >= a committed bar; keep it conservative — a wrong entry silently costs FP-reduction).
HIGH_PRECISION_RULES: frozenset[str] = frozenset()


def is_high_precision(rule_id: str) -> bool:
    return rule_id in HIGH_PRECISION_RULES
