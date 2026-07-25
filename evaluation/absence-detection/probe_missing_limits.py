"""Read-only probes for two more ABSENCE classes: no rate limit, and verbose-error info exposure (E9).

Extends E8's differential idea to absence classes that need NO credentials and NO state change:

  * **CWE-770/400 — no resource/rate limit.** Oracle: issue N identical GETs to a PUBLIC read-only
    endpoint and watch for any throttling signal (HTTP 429, `Retry-After`, or a rate-limit header).
    None across N requests => the control is absent. This is a *bounded* probe: N is small and the
    target is the local throwaway harness.
  * **CWE-200 — information exposure via verbose errors.** Oracle: send MALFORMED values to a public
    read-only endpoint (still a GET; nothing is written) and check whether the response leaks internal
    detail. This **reuses the project's own payload corpus (`agent/fuzz_payloads.py`) and signal
    detector (`agent/fuzz_signals.py`)** rather than inventing weaker ones — a first version with five
    hand-written payloads reported "handled generically" on an endpoint where the project's own fuzzer
    had already recorded `stack_trace`, i.e. the instrument was weaker than the tool next to it.
    A `stack_trace`/`server_error` signal => the generic-error-handling control is absent.

Both are "absence" in the decision-0023 sense: nothing bad is *written in the code* to match; what is
missing is a control, observable only in behaviour.

**Safety:** GET only; public read-only endpoints from the pinned attack-surface baseline; loopback
fail-closed; bounded request budget; no credentials; nothing mutated. Inside decision 0013's read-only
bound — no HITL required.

    rag/.venv/bin/python evaluation/absence-detection/probe_missing_limits.py
"""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone
from urllib.parse import quote, urlparse

import requests

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from agent import fuzz_payloads, fuzz_signals  # noqa: E402  (reuse the project's corpus + detector)
BASELINE = os.path.join(_ROOT, "attack-surface", "baselines", "juice-shop-df1b6bbd8bce.json")
TARGET = os.environ.get("TARGET_URL", "http://127.0.0.1:13000")
TIMEOUT = 6
RATE_BURST = int(os.environ.get("RATE_BURST", "25"))   # bounded: small burst, local harness only

# Signals that SOME throttling control exists (any one of these => control present).
_THROTTLE_HEADERS = ("retry-after", "x-ratelimit-limit", "x-ratelimit-remaining", "ratelimit-limit")


def _assert_loopback(url: str) -> None:
    host = (urlparse(url).hostname or "").lower()
    if host not in ("127.0.0.1", "localhost", "::1"):
        print(f"FAIL: refusing non-loopback target {url!r} (read-only local harness only)")
        sys.exit(2)


def _public_read_targets() -> list[dict]:
    """Public, read-only GET endpoints; prefer ones taking a query parameter (for the malformed probe)."""
    data = json.load(open(BASELINE, encoding="utf-8"))
    out = []
    for e in data.get("endpoints", []):
        if (e.get("method") == "GET" and e.get("auth_class") == "public"
                and e.get("state_change") == "read-only" and ":" not in e.get("path", "")):
            params = [p.get("name") for p in (e.get("parameters") or []) if p.get("name")]
            out.append({"path": e["path"], "param": params[0] if params else None})
    return out


def probe_rate_limit(path: str) -> dict:
    """Bounded burst of identical GETs; any throttling signal => control present."""
    url = TARGET.rstrip("/") + path
    statuses, throttled_by = [], None
    for i in range(RATE_BURST):
        try:
            r = requests.get(url, timeout=TIMEOUT)
        except Exception as exc:
            return {"class": "CWE-770/400 no-rate-limit", "path": path, "verdict": "error",
                    "detail": str(exc)[:100]}
        statuses.append(r.status_code)
        if r.status_code == 429:
            throttled_by = f"HTTP 429 at request {i+1}"
            break
        hit = [h for h in _THROTTLE_HEADERS if h in {k.lower() for k in r.headers}]
        if hit:
            throttled_by = f"{hit[0]} header at request {i+1}"
            break
    verdict = "control-present" if throttled_by else "control-absent"
    return {"class": "CWE-770/400 no-rate-limit", "path": path, "verdict": verdict,
            "requests": len(statuses),
            "detail": throttled_by or f"{len(statuses)} identical requests, no 429 and no rate-limit header"}


def probe_verbose_error(path: str, param: str | None) -> dict:
    """Malformed GET values (the project's own corpus); a leak signal => generic-error control absent."""
    if not param:
        return {"class": "CWE-200 verbose-error", "path": path, "verdict": "skipped",
                "detail": "no query parameter to malform"}
    base_url = TARGET.rstrip("/") + path
    try:  # baseline with a benign value, so the detector can compare against it
        b = requests.get(f"{base_url}?{param}=test", timeout=TIMEOUT)
        baseline = fuzz_signals.baseline_of(b.status_code, b.text or "",
                                            b.headers.get("content-type", ""))
    except Exception as exc:
        return {"class": "CWE-200 verbose-error", "path": path, "verdict": "error",
                "detail": str(exc)[:100]}

    leaks, sent = [], 0
    for p in fuzz_payloads.CORPUS:
        url = f"{base_url}?{param}={quote(p.value, safe='')}"
        try:
            r = requests.get(url, timeout=TIMEOUT)
        except Exception:
            continue
        sent += 1
        for s in fuzz_signals.detect(baseline, r.status_code, r.text or "",
                                     r.headers.get("content-type", ""), p.value):
            # Only error-disclosure signals evidence a MISSING generic-error control.
            if s.kind in ("stack_trace", "server_error"):
                leaks.append({"payload_class": p.cls, "signal": s.kind, "status": r.status_code,
                              "reason": s.reason[:90]})
                break
    verdict = "control-absent" if leaks else "control-present"
    kinds = sorted({leak["signal"] for leak in leaks})
    return {"class": "CWE-200 verbose-error", "path": path, "param": param, "verdict": verdict,
            "payloads_sent": sent, "leaks": leaks[:5],
            "detail": (f"{len(leaks)}/{sent} payloads leaked internal detail ({','.join(kinds)})"
                       if leaks else f"{sent} corpus payloads handled generically")}


def main() -> int:
    _assert_loopback(TARGET)
    targets = _public_read_targets()
    if not targets:
        print("FAIL: no public read-only GET endpoints in the baseline")
        return 2
    results = [probe_rate_limit(targets[0]["path"])]
    for t in targets:
        results.append(probe_verbose_error(t["path"], t["param"]))

    findings = [r for r in results if r["verdict"] == "control-absent"]
    present = [r for r in results if r["verdict"] == "control-present"]
    out = {"generated_at": datetime.now(timezone.utc).isoformat(), "target": TARGET,
           "rate_burst": RATE_BURST, "probes": len(results), "findings": len(findings),
           "control_present": len(present), "results": results}
    with open(os.path.join(_HERE, "limits-probe-260725.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)

    print(f"target={TARGET}  {len(results)} read-only probes (no credentials, nothing mutated)")
    for r in results:
        mark = {"control-absent": "FINDING ", "control-present": "ok      ",
                "skipped": "skip    ", "error": "error   "}[r["verdict"]]
        print(f"  {mark} {r['class']:26s} {r['path']:26s} {r['detail']}")
    print(f"\nRESULT: {len(findings)} absence finding(s), {len(present)} control(s) present "
          f"(a mix proves the oracles discriminate).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
