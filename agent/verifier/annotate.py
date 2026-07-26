"""Non-load-bearing LLM annotator (the honest upgrade from decision 0020).

The verifier spike proved an LLM that DROPS findings is unsafe (it hides real vulns). This is the safe
alternative: the LLM assigns a review PRIORITY to each SAST finding and NEVER drops one — recall is
preserved by construction. To stay provenance-safe (the spike showed hardened models refuse to grade
raw target-derived code), the annotator reasons over the finding's CODE-DERIVED FACTS only (rule id,
CWE, severity) — operator content, like the recon agent reasoning over lake-finding facts — not the
raw source. Its output is a ranking hint for a human triager, measured (does it rank true-positives
above false-positive traps?), never a keep/drop decision.
"""

from __future__ import annotations

import os
import re
from typing import Callable

_RUBRIC = (
    "You are prioritising static-analysis findings for a human security reviewer's queue. Given one "
    "finding's scanner rule, CWE, and severity for a web application, output how likely it is to be a "
    "REAL, impactful vulnerability worth reviewing first — NOT whether to drop it (nothing is dropped). "
    "Consider the CWE's typical exploitability and impact and the scanner's known false-positive "
    "tendency for that rule. Reply with a final line EXACTLY: PRIORITY: <number between 0.0 and 1.0>"
)


def annotate(rule_id: str, cwe: int | None, severity: str, *, model: str | None = None,
             chat: Callable | None = None) -> float | None:
    """Return a 0..1 review-priority for one finding, or None if the model gave no parseable number.
    Reasons over code-derived FACTS only (operator provenance) — never the raw target code."""
    if chat is None:
        from agent import llm  # operator content only: these are code-derived scanner facts

        def chat(system: str, user: str) -> str:  # noqa: E306
            return llm.chat([llm.Msg("system", system, llm.operator()),
                             llm.Msg("user", user, llm.operator())],
                            model=model or os.environ.get("RECON_MODEL", "sast-grok45"),
                            max_tokens=120, temperature=0.0)

    user = f"finding: scanner_rule={rule_id} CWE={cwe} severity={severity}"
    out = chat(_RUBRIC, user)
    m = re.search(r"PRIORITY:\s*([01]?\.?\d+)", out)
    if not m:
        m = re.search(r"\b(0?\.\d+|1\.0|0|1)\b", out)   # lenient fallback
    return max(0.0, min(1.0, float(m.group(1)))) if m else None
