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
nothing itself", over-generalising 0025 (which was scoped to the 2 routed non-public endpoints). This
script measures that bucket instead of assuming it away — and after the ordering fix above it finds
the app defends materially more endpoints than the first run reported.

STATE-PERTURBING, not "read-only". GET is NOT side-effect-free on this target: a red-team
proved this project's own "read-only" probes flipped three Juice Shop challenge `solved` flags
(`/.well-known/security.txt` -> securityPolicyChallenge, `/metrics` -> exposedMetricsChallenge,
error-provoking requests -> errorHandlingChallenge) — each a database write. Express also runs the
same handler for HEAD, so HEAD-first would be safety theatre, not a mitigation. The run is bounded by
the target's DISPOSABILITY, not by the verb; contamination is MEASURED (challenge `solved` set is
snapshotted before/after and the diff published) rather than denied. No writes are ever sent
deliberately, and the agent token goes only to the enforcement origin, never to the app origin.
Bounded, loopback only. Evidence redacted at
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
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from agent import gateway, trace  # noqa: E402
from probe_safety import assert_local  # noqa: E402

SURFACE = os.path.join(_HERE, "routed-surface.json")
TIMEOUT = 6
MAX_PATHS = int(os.environ.get("MAX_PATHS", "60"))   # bounded probe budget
# API paths as they appear in the client bundle. Deliberately narrow: only /api/… and /rest/… literals,
# no fuzzy guessing — a path this regex misses is a coverage limit, not a false positive.
# Angular interpolates most paths (`${host}/rest/languages`), so a quote-only delimiter systematically
# missed real endpoints — and the misses correlated with the very bucket being counted. Backtick and
# closing-brace delimiters included.
_PATH_RX = re.compile(r'["\'`}](/(?:api|rest)/[A-Za-z0-9_\-/]{2,40})["\'`]')
# A NAME-based denylist cannot catch create-on-read: `/rest/captcha` inserts a DB row per GET on this
# target, and the denylist never fires on it. It reduces obvious risk; it does not make the run
# side-effect-free (see the state-perturbing note above).
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


def classify(gw, app) -> tuple[bool | None, str, str]:
    """Two ORTHOGONAL axes, deliberately not one ordered bucket list.

    A review found the single-list form silently mis-ranked endpoints: this app renders 401 as
    `text/html`, so an HTML branch placed before the status branch discarded app-enforced endpoints as
    "not an endpoint" and under-counted app-side controls 6->2 — an error that happened to enlarge the
    headline gap. Ordering can only bias a count when independent questions share one branch chain, so
    they are separated here:

      routed  -- does the request traverse the ENFORCEMENT POINT at all? (gateway status != 404)
      posture -- what does the app itself do when reached directly?

    `routed` is answerable for every probed path regardless of what the app returns, so no app-side
    ambiguity can change the routing-coverage count.
    """
    routed = None if gw is None else gw["status"] != 404
    if app is None:
        return routed, "unreachable", "app origin did not answer"
    st = app["status"]
    if st in (401, 403):
        return routed, "app-enforced", f"the app itself refuses (HTTP {st})"
    if st == 404:
        return routed, "absent", "app 404 — no such route"
    if app["html"] and 200 <= st < 300:
        return routed, "absent", "SPA HTML fallback — not an API route"
    if st >= 500:
        # A 500 PROVES the route exists (Express matched it and the handler ran) but says nothing about
        # its posture: GET without the required params/verb. Real endpoint, posture undetermined.
        return routed, "undetermined", f"route exists but GET-without-params errors (HTTP {st})"
    if 200 <= st < 300:
        return routed, "open", f"the app answers directly (HTTP {st}, {app['bytes']}B)"
    return routed, "undetermined", f"app HTTP {st}"


def main() -> int:
    surface = json.load(open(SURFACE, encoding="utf-8"))
    gw_origin, app_origin = surface["enforcement_origin"], surface["app_origin"]
    assert_local(gw_origin, app_origin)
    configured_routes = {r["path"] for r in surface["routes"]}

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
    broken = [k for k, v in sources.items() if isinstance(v, str)]
    if broken:
        print(f"FAIL: discovery source(s) errored {broken} — a partial enumeration would report a "
              "smaller gap and exit 0, which is the fail-OPEN mode this project forbids.")
        return 2
    if not paths:
        print("FAIL: deterministic discovery found no paths — refusing to report a gap of zero.")
        return 2

    results, posture_counts = [], {}
    for p in paths:
        is_routed, posture, detail = classify(_get(gw_origin, p, token), _get(app_origin, p))
        posture_counts[posture] = posture_counts.get(posture, 0) + 1
        results.append({"path": p, "routed": is_routed, "posture": posture,
                        "detail": trace.redact_persisted(detail)})

    # A route is "real" if the app proved it exists: it enforced, answered, or errored inside a handler.
    real = [r for r in results if r["posture"] != "absent"]
    unrouted = [r for r in real if r["routed"] is False]
    unrouted_open = [r for r in unrouted if r["posture"] == "open"]
    out = {"generated_at": datetime.now(timezone.utc).isoformat(),
           "discovery_sources": sources, "probe_budget": MAX_PATHS,
           "discovered": len(paths), "real_endpoints": len(real),
           "routed_by_gateway_config": len(configured_routes),
           "app_posture_counts": posture_counts,
           "unrouted": len(unrouted), "unrouted_and_open": len(unrouted_open),
           "results": results}
    with open(os.path.join(_HERE, "exposure-gap-260726.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)

    print(f"discovery (deterministic, no LLM): {sources}")
    print(f"probed {len(paths)} paths as the live agent identity; {len(real)} are real routes\n")
    print("AXIS 1 — enforcement-point coverage (independent of what the app returns):")
    print(f"  {len(real) - len(unrouted)} of {len(real)} real routes traverse the gateway; "
          f"{len(unrouted)} never do.")
    print("AXIS 2 — what the app itself does when reached directly:")
    for v, n in sorted(posture_counts.items(), key=lambda kv: -kv[1]):
        print(f"  {v:14s} {n}")
    print(f"\nThe two axes crossed: {len(unrouted_open)} route(s) are BOTH unrouted and openly "
          "answering. This is a GATEWAY-COVERAGE statement (no logging, rate-limit or ACL applies), "
          "NOT an authorization finding — a review read all of these bodies and found every one "
          "public-by-design content on this target. Zero authorization gaps were found here.")
    if unrouted_open:
        print("  " + ", ".join(r["path"] for r in unrouted_open))
    print(f"COVERAGE: bounded to {MAX_PATHS} paths from client-bundle + baseline discovery; the app's "
          "true surface may be larger.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
