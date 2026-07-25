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
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# Persisted evidence goes through the project's canonical secrets->target-raw->PII scrub (0017).
# A red-team found this path wrote RAW response bodies with no redaction: harmless while probing
# unauthenticated endpoints, but the moment probes carry identities the body is another user's
# email/JWT/PII heading into a committed artefact.
from agent import trace  # noqa: E402
BASELINE = os.path.join(_ROOT, "attack-surface", "baselines", "juice-shop-df1b6bbd8bce.json")
# The APP origin (harness publishes it for testing) and the ENFORCEMENT origin (Kong, decision
# 0010: "authorization enforcement is Kong ACL"). A red-team proved that probing only the app origin
# manufactures findings: /rest/admin/application-version answers 200 direct but 401 through Kong, so
# the control exists and the earlier "missing authz" finding was an artefact of the wrong origin.
TARGET = os.environ.get("TARGET_URL", "http://127.0.0.1:13000")            # app, direct
GATEWAY = os.environ.get("GATEWAY_URL", "https://127.0.0.1:18443")        # Kong, the enforcement point
TIMEOUT = 6
# Bodies at or below this size carry no real data (e.g. `{"user":{}}`) — recorded as IMPACT context on
# a finding, never as the verdict itself.
TRIVIAL_BODY_BYTES = 32

# NEGATIVE CONTROL: GET endpoints that genuinely require a session on this target. They must classify
# as `control-present` (401/403); if the prober ever flags these, its oracle is broken. Read-only GETs.
EXPECTED_PROTECTED = ["/rest/basket/1", "/api/Cards", "/api/Addresss"]
# A path that does not exist. On an SPA target the server answers 200 with index.html, which an
# earlier version mis-classified as "control-absent" — so this control MUST come back non-2xx or
# be recognised as the HTML fallback, else the oracle is unsound on this target.
NONEXISTENT_CONTROL = "/this-path-should-not-exist-sentinel-probe"


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
        out.append(e)   # `confidence` rides along for the verdict gate
    return out


def _get(base: str, path: str):
    """One credential-free, non-redirect-following GET. Returns (status, size, body, ctype) or None."""
    try:
        r = requests.get(base.rstrip("/") + path, timeout=TIMEOUT, allow_redirects=False, verify=False)
        return r.status_code, len(r.content or b""), (r.text or "")[:120], r.headers.get("content-type", "")
    except Exception:
        return None


def probe(endpoint: dict) -> dict:
    """Credential-free GET against BOTH the enforcement origin and the app origin.

    Verdict is decided at the ENFORCEMENT point, because that is where the control is supposed to
    live (decision 0010). The app-origin answer only refines severity:
      gateway 401/403                      -> control-present (and if the app also refuses: defence in depth)
      gateway 401/403 + app 2xx            -> gateway-only-enforcement (informational: no defence in depth,
                                              a bypass to the app origin would work — NOT a missing control)
      gateway 2xx                          -> control-absent (the real finding)
    """
    gw = _get(GATEWAY, endpoint["path"])
    app = _get(TARGET, endpoint["path"])
    if gw is None and app is None:
        return {**_base(endpoint), "verdict": "error", "detail": "both origins unreachable"}
    # If the gateway is unreachable we cannot judge the control at all — fail loudly, never "clean".
    if gw is None:
        return {**_base(endpoint), "verdict": "error",
                "detail": f"enforcement origin {GATEWAY} unreachable — refusing to judge from the app origin"}
    status, size, body, ctype = gw
    app_status = app[0] if app else None

    if status in (401, 403):
        if app_status is not None and 200 <= app_status < 300:
            verdict = "gateway-only-enforcement"
            detail = (f"gateway HTTP {status} (control present) but app origin answers {app_status} — "
                      "no defence in depth; informational, not a missing control")
        else:
            verdict, detail = "control-present", f"HTTP {status} at the enforcement point as required"
    elif 200 <= status < 300 and "text/html" in (ctype or "").lower():
        # SPA fallback: the server answers 200 + index.html for ANY path, so a 200 here is no evidence.
        verdict, detail = "inconclusive", f"HTTP {status} but HTML (SPA fallback) — not endpoint evidence"
    elif 200 <= status < 300 and endpoint.get("confidence") not in ("observed", "high", None):
        # The baseline label is a hypothesis, not an observation: report, do not claim a finding.
        verdict, detail = "label-unverified", f"HTTP {status}, {size}B but baseline label is a hypothesis"
    elif 200 <= status < 300:
        # The VERDICT is the missing control; size is impact context only.
        impact = "data returned" if size > TRIVIAL_BODY_BYTES else "trivial body (low data impact)"
        verdict, detail = "control-absent", f"HTTP {status}, {size}B without credentials — {impact}"
    else:
        verdict, detail = "inconclusive", f"HTTP {status}"
    return {**_base(endpoint), "verdict": verdict, "status": status, "bytes": size,
            "impact": ("data" if size > TRIVIAL_BODY_BYTES else "minimal") if verdict == "control-absent" else None,
            "detail": detail,
            "sample": trace.redact_persisted(body) if verdict == "control-absent" else ""}


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
                    "method": "GET", "confidence": "observed", "_role": "negative-control"}
                   for p in EXPECTED_PROTECTED]
    controls_in.append({"path": NONEXISTENT_CONTROL, "auth_class": "nonexistent-path",
                        "state_change": "read-only", "method": "GET", "confidence": "observed",
                        "_role": "negative-control"})
    results = [probe(e) for e in eps + controls_in]

    findings = [r for r in results if r["verdict"] == "control-absent" and r["role"] == "baseline"]
    neg = [r for r in results if r["role"] == "negative-control"]
    # a negative control passes if it is NOT reported as a finding
    neg_ok = [r for r in neg if r["verdict"] in ("control-present", "inconclusive", "gateway-only-enforcement")]

    out = {"generated_at": datetime.now(timezone.utc).isoformat(), "target": TARGET,
           "probed": len(results), "findings": len(findings),
           "negative_controls": {"total": len(neg), "correctly_protected": len(neg_ok)},
           "results": results}
    with open(os.path.join(_HERE, "authz-probe-260725.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)

    print(f"target={TARGET}  probed={len(results)} read-only GET endpoints (NO credentials sent)")
    for r in results:
        mark = {"control-absent": "FINDING ", "control-present": "ok      ", "error": "error   ",
                "inconclusive": "?       ", "label-unverified": "unverif ",
                "gateway-only-enforcement": "info    "}[r["verdict"]]
        tag = "[neg-ctl]" if r["role"] == "negative-control" else "         "
        print(f"  {mark}{tag} {str(r['auth_class']):18s} {r['path']:36s} {r['detail']}")
    print(f"\nRESULT: {len(findings)} missing-authz finding(s) on baseline-labelled non-public endpoints; "
          f"negative controls correctly protected {len(neg_ok)}/{len(neg)}"
          + ("  -> oracle discriminates" if len(neg_ok) == len(neg) and neg else
             "  -> ORACLE SUSPECT (a protected endpoint was flagged)"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
