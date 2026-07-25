"""Exposure gap: how much of the application does the enforcement point actually protect?

Decision 0025 measured that the gateway-routed non-public endpoints have no authorization of their own —
Kong is the sole control. The unanswered question is the SIZE of the gap: Kong routes 8 endpoints; how
many does the application actually expose, and therefore how many sit in front of no control at all?

**Deterministic discovery, no LLM.** The Angular bundle (`/main.js`) contains the API paths the client
calls; `robots.txt` and the attack-surface baseline add more. This is the honest comparator the Phase-3
plan needed: an empirical check found that ~every app endpoint outside Kong's 8 routes classifies as
"unrouted and reachable", so *guessing* paths (by wordlist or by LLM) is not a discovery method — it is
enumeration of a set the bundle already lists exactly.

Each discovered path is verified at BOTH origins as the live agent identity:

    gateway 404 + app 2xx (non-HTML)  -> UNPROTECTED   (exists, no control in front of it)
    gateway 2xx/401/403               -> routed        (the gateway sees it; 0025 covers its posture)
    app 401/403                       -> app-enforced  (the app defends this one itself)
    app 404 / HTML SPA fallback       -> not a real endpoint (discarded, never a finding)

The `app-enforced` bucket matters: an early draft of the Phase-3 plan asserted "the app enforces
nothing itself", over-generalising 0025 (which was scoped to the 2 routed non-public endpoints).
`/api/Users` answers 401 — the app does defend some endpoints. This script measures that instead of
assuming it.

Read-only: GET only, loopback only, bounded, nothing mutated (decision 0013). Evidence redacted at
capture; artefact gitignored.

    rag/.venv/bin/python -W ignore evaluation/absence-detection/measure_exposure_gap.py
"""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone

import requests

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from agent import gateway, trace  # noqa: E402

SURFACE = os.path.join(_HERE, "routed-surface.json")
TIMEOUT = 6
MAX_PATHS = int(os.environ.get("MAX_PATHS", "60"))   # bounded probe budget
# API paths as they appear in the client bundle. Deliberately narrow: only /api/… and /rest/… literals,
# no fuzzy guessing — a path this regex misses is a coverage limit, not a false positive.
_PATH_RX = re.compile(r'["\'](/(?:api|rest)/[A-Za-z0-9_\-/]{2,40})["\']')
# Never probe anything whose name suggests a side effect, even via GET (some apps accept GET for these).
_DESTRUCTIVE = re.compile(r"(delete|destroy|remove|reset|logout|drop|purge|wipe|revoke)", re.I)


def discover(app_origin: str) -> tuple[list[str], dict]:
    """Deterministically enumerate API paths the client itself references."""
    sources: dict = {}
    paths: set[str] = set()
    try:
        js = requests.get(app_origin.rstrip("/") + "/main.js", timeout=20).text
        found = {m.group(1) for m in _PATH_RX.finditer(js)}
        sources["main.js"] = len(found)
        paths |= found
    except Exception as exc:
        sources["main.js"] = f"error: {str(exc)[:60]}"
    try:
        base = json.load(open(os.path.join(_ROOT, "attack-surface", "baselines",
                                           "juice-shop-df1b6bbd8bce.json"), encoding="utf-8"))
        bl = {e["path"] for e in base.get("endpoints", []) if ":" not in e.get("path", "")}
        sources["attack-surface-baseline"] = len(bl)
        paths |= bl
    except Exception as exc:
        sources["attack-surface-baseline"] = f"error: {str(exc)[:60]}"
    safe = sorted(p for p in paths if not _DESTRUCTIVE.search(p))
    sources["excluded_destructive_looking"] = len(paths) - len(safe)
    return safe[:MAX_PATHS], sources


def _get(base: str, path: str, token: str | None = None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        r = requests.get(base.rstrip("/") + path, timeout=TIMEOUT, headers=headers,
                         allow_redirects=False, verify=False)
        return {"status": r.status_code, "bytes": len(r.content or b""),
                "html": "text/html" in (r.headers.get("content-type") or "").lower(),
                "body": (r.text or "")[:120]}
    except Exception:
        return None


def classify(gw, app) -> tuple[str, str]:
    if app is None or app["status"] == 404 or app["html"]:
        return "not-an-endpoint", "app 404 or SPA HTML fallback — discarded, never a finding"
    if gw is not None and gw["status"] != 404:
        return "routed", f"gateway sees it (HTTP {gw['status']}) — posture covered by decision 0025"
    if app["status"] in (401, 403):
        return "app-enforced", f"not routed, but the app itself refuses (HTTP {app['status']})"
    if 200 <= app["status"] < 300:
        return "unprotected", (f"not routed at the gateway and the app answers {app['status']} "
                               f"({app['bytes']}B) — no control in front of it")
    return "inconclusive", f"app HTTP {app['status']}"


def main() -> int:
    surface = json.load(open(SURFACE, encoding="utf-8"))
    gw_origin, app_origin = surface["enforcement_origin"], surface["app_origin"]
    routed = {r["path"] for r in surface["routes"]}

    try:
        token = gateway._token()
    except Exception as exc:
        print(f"FAIL: no live agent identity ({str(exc)[:80]}) — refusing to run; without it every "
              "gateway reply is 401 and everything would look routed.")
        return 2
    sc = _get(gw_origin, surface["session_canary"]["path"], token)
    if not (sc and 200 <= sc["status"] < 300):
        print("FAIL: session canary did not return 2xx with a minted token — identity not live.")
        return 2

    paths, sources = discover(app_origin)
    if not paths:
        print("FAIL: deterministic discovery found no paths — refusing to report a gap of zero.")
        return 2

    results, counts = [], {}
    for p in paths:
        verdict, detail = classify(_get(gw_origin, p, token), _get(app_origin, p))
        counts[verdict] = counts.get(verdict, 0) + 1
        results.append({"path": p, "verdict": verdict, "detail": trace.redact_persisted(detail)})

    real = [r for r in results if r["verdict"] != "not-an-endpoint"]
    unprotected = [r for r in results if r["verdict"] == "unprotected"]
    out = {"generated_at": datetime.now(timezone.utc).isoformat(),
           "discovery_sources": sources, "probe_budget": MAX_PATHS,
           "discovered": len(paths), "real_endpoints": len(real),
           "routed_by_gateway": len(routed), "counts": counts,
           "unprotected": len(unprotected), "results": results}
    with open(os.path.join(_HERE, "exposure-gap-260726.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)

    print(f"discovery (deterministic, no LLM): {sources}")
    print(f"probed {len(paths)} paths as the live agent identity\n")
    for v, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"  {v:16s} {n}")
    print(f"\nEXPOSURE GAP: {len(unprotected)} of {len(real)} real endpoints have NO control in front "
          f"of them (the gateway routes {len(routed)}).")
    if unprotected:
        print("  examples: " + ", ".join(r["path"] for r in unprotected[:6]))
    print(f"COVERAGE: bounded to {MAX_PATHS} paths from client-bundle + baseline discovery; the app's "
          "true surface may be larger.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
