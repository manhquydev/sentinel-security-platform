"""Single-turn, provenance-safe guided-question triage of one SAST finding (Phase-1 spike).

For a residual finding the deterministic gate did not auto-keep, ONE gateway call asks a small,
CWE-specific, Sentinel-authored (clean-room) yes/no set about exploitability, then a structural
verdict-integrity gate decides whether to trust the reply. The verdict is one of:

  keep       — the verifier could not justify dropping it (a real vuln, or an unjustifiable "keep")
  likely-fp  — the verifier justifiably marks it a false positive
  unknown    — unparseable / refused / integrity-failed reply

FAIL-SAFE: `unknown` and `keep` both map to the EFFECTIVE verdict `keep`, so a parse failure or a
hardened-model refusal (the Week-10 finding: models refuse the grading role under target-derived
provenance) costs PRECISION, never RECALL. The verifier can only reduce false positives it can
structurally justify. See docs/ai-sast-verifier-design.md.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Callable

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
QUESTIONS_DIR = os.path.join(_HERE, "questions")


@dataclass
class Finding:
    rule_id: str
    cwe: int | None
    file: str
    line: int
    code_slice: str
    message: str = ""


@dataclass
class Verdict:
    raw: str                 # keep | likely-fp | unknown
    effective: str           # keep | likely-fp   (fail-safe: unknown/keep -> keep)
    integrity: str           # ok | unparseable | refused | cwe-fabrication | no-questions
    model_ok: bool           # did the model return a conforming, integrity-passing reply?
    answers: list[str] = field(default_factory=list)


_RUBRIC = (
    "You are triaging one static-analysis finding to decide if it is a TRUE vulnerability or a FALSE "
    "POSITIVE. You are given the finding's CWE, the flagged code, and a short yes/no checklist. Answer "
    "the checklist from the code only; do not assume unshown context makes it exploitable. Decide: if "
    "untrusted input can reach the dangerous sink WITHOUT an intervening validator/parameterizer, the "
    "finding is real (KEEP); if the code shows it is not exploitable (constant/parameterized/escaped), "
    "it is a false positive (LIKELY-FP). End your reply with two lines EXACTLY:\n"
    "CWE: <the finding's cwe number>\n"
    "VERDICT: KEEP | LIKELY-FP"
)


def _question_set(cwe: int | None) -> dict | None:
    """Load the clean-room question set for a CWE, if one exists."""
    if cwe is None:
        return None
    for name in os.listdir(QUESTIONS_DIR) if os.path.isdir(QUESTIONS_DIR) else []:
        if not name.endswith(".json"):
            continue
        qs = json.load(open(os.path.join(QUESTIONS_DIR, name), encoding="utf-8"))
        if int(qs.get("cwe", -1)) == int(cwe):
            return qs
    return None


def _parse(reply: str, expected_cwe: int | None) -> tuple[str, str]:
    """Return (raw_verdict, integrity). Structural — never trusts prose."""
    verds = re.findall(r"VERDICT:\s*(KEEP|LIKELY[- ]?FP)", reply, re.IGNORECASE)
    if not verds:
        return "unknown", "refused"          # no conforming verdict (refusal / prose)
    # CWE-fabrication check: if the reply commits to a CWE, it must be the finding's own.
    cwes = re.findall(r"CWE:\s*(\d+)", reply, re.IGNORECASE)
    if expected_cwe is not None and cwes and int(cwes[-1]) != int(expected_cwe):
        return "unknown", "cwe-fabrication"
    v = verds[-1].upper().replace(" ", "-")
    return ("likely-fp" if v == "LIKELY-FP" else "keep"), "ok"


def verify(finding: Finding, *, model: str | None = None, provenance: str = "target-derived",
           chat: Callable | None = None) -> Verdict:
    """Triage one finding. `chat` is injectable for offline tests; defaults to the provenance gateway.
    `provenance` selects the trust label on the code message: 'target-derived' is the security-correct
    label (the spike measures that the hardened models refuse under it); 'operator' is the FORBIDDEN
    trust downgrade, measured only to show whether the verifier is inaccurate or merely unreachable."""
    qs = _question_set(finding.cwe)
    if qs is None:
        # No clean-room question set for this class yet -> cannot justify a drop -> fail safe.
        return Verdict(raw="unknown", effective="keep", integrity="no-questions", model_ok=False)

    if chat is None:
        from agent import llm  # gateway client (provenance-enforced)
        trust = (llm.operator() if provenance == "operator"
                 else llm.target_derived(source="sast-finding", target=finding.file))

        def chat(system: str, user: str) -> str:  # noqa: E306
            return llm.chat([llm.Msg("system", system, llm.operator()), llm.Msg("user", user, trust)],
                            model=model or os.environ.get("RECON_MODEL", "sast-sol"),
                            max_tokens=400, temperature=0.0)

    checklist = "\n".join(f"- {q}" for q in qs.get("questions", []))
    system = f"{_RUBRIC}\n\nCWE-{finding.cwe} ({qs.get('category','')}) checklist:\n{checklist}"
    user = (f"[DATA:target-derived] finding rule={finding.rule_id} cwe={finding.cwe} "
            f"file={finding.file}:{finding.line}\n--- code ---\n{finding.code_slice}\n--- end ---")
    reply = chat(system, user)
    raw, integrity = _parse(reply, finding.cwe)
    effective = "likely-fp" if raw == "likely-fp" else "keep"   # fail-safe: unknown/keep -> keep
    return Verdict(raw=raw, effective=effective, integrity=integrity, model_ok=(integrity == "ok"))
