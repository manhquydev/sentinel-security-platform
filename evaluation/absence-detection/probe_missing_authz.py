"""Differential authz prober: detect ABSENCE-of-control at runtime (E8).

Decision 0023 measured that SAST detects the *presence* of bad patterns 9.5x better than the *absence*
of required controls, and that the absence bucket is the larger half of real vulnerabilities. An absent
control has no code token to match — but it is trivially observable in BEHAVIOUR. This is the minimal
runtime instrument for one absence class:

    CWE-306/284/862 — missing authentication / access control / authorization

**Oracle (differential, credential-free):** the attack-surface baseline already labels each endpoint's
`auth_class` (public / authenticated / administrative). Request a non-public endpoint with **no
credentials at all**:

    401/403   -> the control is PRESENT  (correct behaviour)
    2xx       -> the control is ABSENT   -> FINDING; the response size is recorded as IMPACT context,
                 not as the verdict (an administrative endpoint answering `{"version":"20.1.1"}`
                 unauthenticated is a missing-access-control finding regardless of how few bytes it is —
                 an early version of this prober used a size threshold as the verdict and wrongly
                 downgraded exactly that case).

A committed set of **expected-protected** endpoints is probed identically as the built-in NEGATIVE
CONTROL: they must come back 401/403. An oracle that flagged everything would flag them too, so their
correct classification is what proves the prober discriminates rather than rubber-stamping.

**Safety (decision 0013's read-only bound, no HITL needed):** GET only; only endpoints the baseline
marks `state_change == "read-only"`; loopback targets only (fail-closed); no credentials are sent, no
account is created, nothing is mutated; one request per endpoint.

    rag/.venv/bin/python evaluation/absence-detection/probe_missing_authz.py
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
BASELINE = os.path.join(_ROOT, "attack-surface", "baselines", "juice-shop-df1b6bbd8bce.json")
TARGET = os.environ.get("TARGET_URL", "http://127.0.0.1:13000")
TIMEOUT = 6
# Bodies at or below this size carry no real data (e.g. `{"user":{}}`) — recorded as IMPACT context on
# a finding, never as the verdict itself.
TRIVIAL_BODY_BYTES = 32

# NEGATIVE CONTROL: GET endpoints that genuinely require a session on this target. They must classify
# as `control-present` (401/403); if the prober ever flags these, its oracle is broken. Read-only GETs.
EXPECTED_PROTECTED = ["/rest/basket/1", "/api/Cards", "/api/Addresss"]


def _assert_loopback(url: str) -> None:
    """Fail closed: this prober only ever touches the local harness."""
    host = (urlparse(url).hostname or "").lower()
    if host not in ("127.0.0.1", "localhost", "::1"):
        print(f"FAIL: refusing non-loopback target {url!r} (read-only local harness only)")
        sys.exit(2)


def _candidates() -> list[dict]:
    """Non-public, READ-ONLY, GET endpoints from the pinned attack-surface baseline."""
    data = json.load(open(BASELINE, encoding="utf-8"))
    out = []
    for e in data.get("endpoints", []):
        if e.get("method") != "GET":
            continue
        if e.get("auth_class") in (None, "public"):
            continue
        if e.get("state_change") != "read-only":     # never probe a state-changing path
            continue
        if ":" in e.get("path", ""):                  # skip templated ids we cannot instantiate safely
            continue
        out.append(e)
    return out


def probe(endpoint: dict) -> dict:
    """One credential-free GET; classify the control as present/absent."""
    url = TARGET.rstrip("/") + endpoint["path"]
    try:
        r = requests.get(url, timeout=TIMEOUT)  # deliberately NO auth header
        status, size = r.status_code, len(r.content or b"")
        body = (r.text or "")[:120]
    except Exception as exc:  # network/transport failure is not a finding
        return {**_base(endpoint), "verdict": "error", "detail": str(exc)[:120]}

    if status in (401, 403):
        verdict, detail = "control-present", f"HTTP {status} as required"
    elif 200 <= status < 300:
        # The VERDICT is the missing control; size is impact context only.
        impact = "data returned" if size > TRIVIAL_BODY_BYTES else "trivial body (low data impact)"
        verdict, detail = "control-absent", f"HTTP {status}, {size}B without credentials — {impact}"
    else:
        verdict, detail = "inconclusive", f"HTTP {status}"
    return {**_base(endpoint), "verdict": verdict, "status": status, "bytes": size,
            "impact": ("data" if size > TRIVIAL_BODY_BYTES else "minimal") if verdict == "control-absent" else None,
            "detail": detail, "sample": body if verdict == "control-absent" else ""}


def _base(e: dict) -> dict:
    return {"path": e["path"], "auth_class": e.get("auth_class"), "cwe_class": "306/284/862",
            "role": e.get("_role", "baseline")}


def main() -> int:
    _assert_loopback(TARGET)
    eps = _candidates()
    if not eps:
        print("FAIL: no non-public read-only GET endpoints in the baseline — nothing to probe")
        return 2
    for e in eps:
        e["_role"] = "baseline"
    controls_in = [{"path": p, "auth_class": "expected-protected", "state_change": "read-only",
                    "method": "GET", "_role": "negative-control"} for p in EXPECTED_PROTECTED]
    results = [probe(e) for e in eps + controls_in]

    findings = [r for r in results if r["verdict"] == "control-absent" and r["role"] == "baseline"]
    neg = [r for r in results if r["role"] == "negative-control"]
    neg_ok = [r for r in neg if r["verdict"] == "control-present"]

    out = {"generated_at": datetime.now(timezone.utc).isoformat(), "target": TARGET,
           "probed": len(results), "findings": len(findings),
           "negative_controls": {"total": len(neg), "correctly_protected": len(neg_ok)},
           "results": results}
    with open(os.path.join(_HERE, "authz-probe-260725.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)

    print(f"target={TARGET}  probed={len(results)} read-only GET endpoints (NO credentials sent)")
    for r in results:
        mark = {"control-absent": "FINDING ", "control-present": "ok      ",
                "error": "error   ", "inconclusive": "?       "}[r["verdict"]]
        tag = "[neg-ctl]" if r["role"] == "negative-control" else "         "
        print(f"  {mark}{tag} {str(r['auth_class']):18s} {r['path']:36s} {r['detail']}")
    print(f"\nRESULT: {len(findings)} missing-authz finding(s) on baseline-labelled non-public endpoints; "
          f"negative controls correctly protected {len(neg_ok)}/{len(neg)}"
          + ("  -> oracle discriminates" if len(neg_ok) == len(neg) and neg else
             "  -> ORACLE SUSPECT (a protected endpoint was flagged)"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
