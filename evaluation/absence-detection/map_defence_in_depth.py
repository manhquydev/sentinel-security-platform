"""Defence-in-depth map: WHERE is authorization actually enforced, per gateway-routed endpoint?

Plan `docs/plans/active/2026-07-26-absence-coverage-ai-proposes-tools-dispose.md` (v3), after two
red-team lenses and a validate reframe. The original goal — measure *missing* authorization — is not
achievable on this target: the enforcement point routes 8 endpoints, only 2 are non-public, and both
are correctly protected. What IS measurable, and is a genuine pentest finding, is the posture:

    gateway 401/403 + app 401/403  -> defence-in-depth      (control at both layers)
    gateway 401/403 + app 2xx      -> GATEWAY-ONLY-ENFORCEMENT  -> FINDING
                                      single point of failure: an SSRF, a misrouted internal call, or
                                      any path that reaches the app directly defeats ALL authorization
    gateway 2xx      + app 2xx     -> missing control entirely (classic case)

**Judge at the enforcement point, never around it.** A red-team proved the earlier prober measured the
app's direct publish port and therefore probed *around* Kong (decision 0010), manufacturing a finding
that did not exist. If the enforcement origin is unreachable this exits non-zero rather than judging
from the app origin — that class of error must not silently recur.

Fail-closed guards (all from red-team findings):
  * synthetic canary must classify as `not-routed` every run, else exit non-zero (proves the prober is
    reaching and classifying; it is synthetic so a fixed system cannot break it);
  * unreachable enforcement origin => error, never "clean";
  * SPA HTML fallback (this app answers 200 + index.html for unknown paths) is never evidence;
  * evidence is redacted on write through the project's canonical seam and the artefact is gitignored.

STATE-PERTURBING, not "read-only". GET is NOT side-effect-free on this target: a red-team
proved this project's own "read-only" probes flipped three Juice Shop challenge `solved` flags
(`/.well-known/security.txt` -> securityPolicyChallenge, `/metrics` -> exposedMetricsChallenge,
error-provoking requests -> errorHandlingChallenge) — each a database write. Express also runs the
same handler for HEAD, so HEAD-first would be safety theatre, not a mitigation. The run is bounded by
the target's DISPOSABILITY, not by the verb; contamination is MEASURED (challenge `solved` set is
snapshotted before/after and the diff published) rather than denied. No writes are ever sent
deliberately, and the agent token goes only to the enforcement origin, never to the app origin.

    rag/.venv/bin/python -W ignore evaluation/absence-detection/map_defence_in_depth.py
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
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from agent import gateway, trace  # noqa: E402  canonical scrub (0017) + OAuth2 identity
from probe_safety import assert_local  # noqa: E402

SURFACE = os.path.join(_HERE, "routed-surface.json")
TIMEOUT = 6


def challenge_state(app_origin: str) -> set:
    """The target's self-reported solved-challenge set. Snapshotted before and after every run so
    probe-induced state change is MEASURED. A red-team found this project's own probes had already
    flipped three flags while claiming to mutate nothing — and decision 0025 reserved this same
    endpoint as an oracle 'the prober cannot influence', which was therefore false."""
    try:
        r = requests.get(app_origin.rstrip("/") + "/api/Challenges/", timeout=TIMEOUT)
        items = r.json().get("data") or []
        return {i["key"] for i in items if i.get("solved")}
    except Exception:
        return set()


def _get(base: str, path: str, token: str | None = None):
    """Non-redirect-following GET, optionally as the authenticated agent identity."""
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        r = requests.get(base.rstrip("/") + path, timeout=TIMEOUT, headers=headers,
                         allow_redirects=False, verify=False)
        return {"status": r.status_code, "bytes": len(r.content or b""),
                "ctype": (r.headers.get("content-type") or "").split(";")[0],
                "body": (r.text or "")[:160]}
    except Exception:
        return None


def _has_substance(body: str) -> bool:
    """Does this response actually carry protected data, or is it an empty shell?

    Structural, not heuristic: parse the JSON and look for any non-empty leaf. `{"user":{}}` has none;
    `{"version":"20.1.1"}` has one. A non-JSON body counts as substance if it has any non-whitespace
    content, because we cannot prove emptiness for a format we did not parse.
    """
    try:
        doc = json.loads(body)
    except Exception:
        return bool((body or "").strip())

    def leaves(node) -> bool:
        if isinstance(node, dict):
            return any(leaves(v) for v in node.values())
        if isinstance(node, list):
            return any(leaves(v) for v in node) if node else False
        return node not in (None, "", {}, [])

    return leaves(doc)


def classify(route: dict, gw, app) -> dict:
    """Verdict is taken at the ENFORCEMENT point; the app origin only refines it."""
    ev = {"path": route["path"], "expected_auth": route["expected_auth"],
          "gateway_status": gw["status"] if gw else None,
          "app_status": app["status"] if app else None}

    if gw is None:
        return {**ev, "verdict": "error",
                "detail": "enforcement origin unreachable — refusing to judge from the app origin"}
    if gw["status"] == 404:
        return {**ev, "verdict": "not-routed",
                "detail": "the enforcement point does not route this path — outside the measurable set"}
    if "text/html" in (gw["ctype"] or "").lower():
        return {**ev, "verdict": "inconclusive",
                "detail": f"gateway HTTP {gw['status']} but HTML (SPA fallback) — not endpoint evidence"}

    protected_at_gw = gw["status"] in (401, 403)
    app_open = app is not None and 200 <= app["status"] < 300 and "text/html" not in (app["ctype"] or "")
    # A 2xx is not by itself a bypass. `/rest/user/whoami` answers 200 with `{"user":{}}` — the app is
    # WITHHOLDING the protected data, it just signals that by emptiness rather than by 401. Counting
    # that as "no authorization of its own" overstated the finding, so substance is now measured: does
    # the response carry any non-empty value at all?
    app_discloses = app_open and _has_substance(app["body"])

    if route["expected_auth"] == "public":
        if 200 <= gw["status"] < 300:
            return {**ev, "verdict": "public-by-design",
                    "detail": f"gateway {gw['status']} — the identity is permitted, as intended"}
        return {**ev, "verdict": "inconclusive",
                "detail": f"gateway {gw['status']} on a public endpoint with a live identity — "
                          "the ACL denies a route it should permit (config issue, not an app finding)"}
    if protected_at_gw and app_open and not app_discloses:
        return {**ev, "verdict": "app-withholds-payload",
                "detail": (f"gateway {gw['status']} (control present) and the app answers "
                           f"{app['status']} directly but discloses NOTHING ({app['bytes']}B, no "
                           "non-empty value) — a direct-to-app path leaks no protected data here"),
                "evidence": trace.redact_persisted(app["body"])}
    if protected_at_gw and app_discloses:
        return {**ev, "verdict": "gateway-only-enforcement",
                "detail": (f"gateway {gw['status']} (control present) but the app answers "
                           f"{app['status']} directly — NO defence in depth; any path reaching the app "
                           "bypasses all authorization"),
                "evidence": trace.redact_persisted(app["body"])}
    if protected_at_gw:
        return {**ev, "verdict": "defence-in-depth",
                "detail": f"gateway {gw['status']} and the app also refuses ({app['status'] if app else 'n/a'})"}
    if 200 <= gw["status"] < 300:
        return {**ev, "verdict": "control-absent",
                "detail": f"gateway {gw['status']} on a non-public endpoint — authorization missing",
                "evidence": trace.redact_persisted(gw["body"])}
    return {**ev, "verdict": "inconclusive", "detail": f"gateway HTTP {gw['status']}"}


def main() -> int:
    surface = json.load(open(SURFACE, encoding="utf-8"))
    gw_origin, app_origin = surface["enforcement_origin"], surface["app_origin"]
    assert_local(gw_origin, app_origin)

    # IDENTITY. Without a live token every gateway reply is 401 and every endpoint LOOKS protected —
    # the silent failure red-team H1 demanded a guard for. Mint the agent identity, then prove it is
    # live with a SESSION CANARY (an endpoint the ACL is known to allow) before trusting any 403.
    try:
        token = gateway._token()
    except Exception as exc:
        print(f"FAIL: could not mint the agent identity ({str(exc)[:90]}) — refusing to run, because "
              "an unauthenticated probe reports every endpoint as protected.")
        return 2
    session_canary = surface["session_canary"]
    sc = _get(gw_origin, session_canary["path"], token)
    if not (sc and 200 <= sc["status"] < 300):
        print(f"FAIL: session canary {session_canary['path']} returned "
              f"{sc['status'] if sc else 'unreachable'} with a minted token — the identity is not live, "
              "so every 401/403 below would be meaningless. Refusing to report.")
        return 2

    solved_before = challenge_state(app_origin)
    routes = [r for r in surface["routes"] if r["method"] == "GET" and "skip_reason" not in r]
    results = [classify(r, _get(gw_origin, r["path"], token), _get(app_origin, r["path"]))
               for r in routes]

    # Synthetic canary: proves the prober reaches the enforcement point and classifies. Never a real
    # finding, so a fixed system cannot break it (red-team F6).
    canary = surface["synthetic_canary"]
    c_route = {"path": canary["path"], "expected_auth": "authenticated"}
    c_res = classify(c_route, _get(gw_origin, canary["path"], token), _get(app_origin, canary["path"]))
    canary_ok = c_res["verdict"] == "not-routed"

    findings = [r for r in results if r["verdict"] in ("gateway-only-enforcement", "control-absent")]
    counts: dict = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1

    solved_after = challenge_state(app_origin)
    out = {"generated_at": datetime.now(timezone.utc).isoformat(),
           "identity": "agent-recon (OAuth2 via Kong)",
           "target_state_change": {"solved_before": sorted(solved_before),
                                    "solved_after": sorted(solved_after),
                                    "flipped_by_this_run": sorted(solved_after - solved_before)},
           "session_canary": {"path": session_canary["path"], "status": sc["status"], "ok": True},
           "enforcement_origin": gw_origin, "app_origin": app_origin,
           "coverage_bound": surface["coverage_bound"],
           "probed": len(results), "counts": counts, "findings": len(findings),
           "canary": {"path": canary["path"], "verdict": c_res["verdict"], "ok": canary_ok},
           "results": results}
    with open(os.path.join(_HERE, "defence-in-depth-map-260726.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)

    print(f"enforcement={gw_origin}  app={app_origin}  probed={len(results)} routed GET endpoints "
          "(no deliberate writes; GET is NOT side-effect-free here — state change is measured below, "
          "not assumed away)")
    for r in results:
        mark = {"gateway-only-enforcement": "FINDING ", "control-absent": "FINDING ",
                "defence-in-depth": "ok      ", "public-by-design": "public  ",
                "app-withholds-payload": "partial ",
                "not-routed": "n/a     ", "inconclusive": "?       ", "error": "error   "}[r["verdict"]]
        print(f"  {mark} {str(r['expected_auth']):14s} {r['path']:34s} {r['detail']}")
    flipped = sorted(solved_after - solved_before)
    print(f"\ncanary {canary['path']} -> {c_res['verdict']} ({'OK' if canary_ok else 'FAILED'})")
    print(f"target state change by this run: {flipped if flipped else 'none'} "
          f"(target had {len(solved_before)} challenge(s) already flipped on entry)")
    print(f"RESULT: {len(findings)} finding(s); counts={counts}")
    print(f"COVERAGE: {surface['coverage_bound']}")
    if not canary_ok:
        print("FAIL: synthetic canary did not classify as not-routed — the prober is not reaching "
              "the enforcement point as expected; refusing to report this run as valid.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
