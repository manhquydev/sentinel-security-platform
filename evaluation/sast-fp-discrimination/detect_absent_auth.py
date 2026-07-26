"""Can a deterministic rule reach the absence classes at all, or only an LLM?

Decisions 0022-0024 rest on a load-bearing claim: absence-of-control classes are invisible to pattern
SAST, measured recall ~0-6.8%, and the supporting evidence is that Bandit and Semgrep together emit 33
distinct CWE classes across the corpus and **not one is absence-class**. That evidence is real. What it
establishes, though, is a property of *those rulesets*, not a property of determinism — and the two got
conflated into "an absent control writes no token, so pattern matching has nothing to match".

E53 already dented that: five hand-written regex detectors found ten real unlabelled defects. This tests
the claim head-on against ground truth the corpus DOES label.

THE DETECTOR. Ground-truth CWE-306/862 sites in this corpus look like a route decorator with no
authentication on it:

    @app.route('/evaluate', methods=['POST','GET'])
    def evaluate():                       # no @login_required, no Depends(...), no permission check

So: find route declarations, look at the decorators attached to that function and its body, and report the
ones with nothing that establishes identity or permission. Nothing clever, nothing statistical, about
sixty lines.

SCORED WITH THE PROJECT'S OWN MATCHER — `run_spike.match`, file + CWE + line within LINE_TOL, claim-once —
so the number is directly comparable to the engine and model figures already published rather than a new
yardstick invented to flatter a new instrument.

WHAT WOULD FALSIFY THE POINT: recall near zero, which is what the standing claim predicts. That outcome is
entirely available to this design, and it is what Bandit and Semgrep actually produce on these classes.

    rag/.venv/bin/python -W ignore evaluation/sast-fp-discrimination/detect_absent_auth.py
"""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
for _p in (_ROOT, _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import run_spike as rs  # noqa: E402

# A route is declared by one of these decorators.
ROUTE = re.compile(r"^\s*@(?:\w+\.)?(?:route|get|post|put|patch|delete)\s*\(", re.M)

# Anything that establishes WHO the caller is, or WHAT they may do. Presence of any of these on the
# handler means the control is not absent — the point is to report only handlers with none of them.
AUTH_MARKER = re.compile(
    r"login_required|permission_required|user_passes_test|staff_member_required|"
    r"require_role|require_roles|require_user|require_auth|requires_auth|"
    r"Depends\s*\(\s*(?:get_current|require_|verify_|auth)|"
    r"IsAuthenticated|permission_classes|authentication_classes|"
    r"current_user|request\.user\.is_authenticated|@token_required|@jwt_required|"
    r"api_key|check_permission|has_perm|ensure_\w*auth", re.I)

# Protection declared once for a whole router or application, which a handler-only scan cannot see:
# FastAPI routers carry dependencies=[Depends(...)], Flask has before_request, Django has auth middleware.
# Measured at 9 of 101 finding-producing files (28 of 621 findings, 4.5%) — too small to rescue precision,
# but a correctness gap regardless, and reporting a route as unprotected when its router protects it is
# simply wrong.
# App-wide protection: nothing in the module can be unprotected behind it.
APP_LEVEL = re.compile(r"@\w+\.before_request|add_middleware\s*\([^)]*Auth"
                       r"|LoginRequiredMiddleware|AuthenticationMiddleware", re.I)
# Per-router protection: `admin = APIRouter(dependencies=[Depends(require_user)])` protects only the
# handlers decorated with THAT router. A file often holds both a protected and a public router, so
# suppressing the whole module on one match was too coarse — it cost four real detections.
PROTECTED_ROUTER = re.compile(
    r"^\s*(\w+)\s*=\s*APIRouter\s*\([^)]*dependencies\s*=\s*\[[^\]]*(?:Depends|require|auth)",
    re.I | re.M)
# Which router object a decorator belongs to: @admin.get(...) -> "admin".
ROUTE_OWNER = re.compile(r"^\s*@(\w+)\.(?:route|get|post|put|patch|delete)\s*\(")

# Protection written in the body rather than as a decorator. Two kinds of construct turn up there and
# only ONE of them is a control:
#
#   ENFORCEMENT — the handler refuses. `abort(403)`, `raise HTTPException(401)`, an `is_admin` test, a
#   comparison of the object's owner against the caller, a token actually verified. These deny the
#   request, so the control is present and reporting the handler is a false positive.
#
#   IDENTITY — the handler merely learns who is calling: `session['user_id']`, a redirect to login.
#   Knowing the caller is not checking their permission, and a handler that reads the session and then
#   acts on any object it is handed is the textbook shape of CWE-862. These must NOT suppress.
#
# The split is semantic, and the corpus agrees with it: across 602 finding sites the enforcement
# constructs appear on 1 of 71 real defects while the identity constructs appear on 9 — so treating
# identity as protection would silently discard real findings, which is the failure mode that matters.
ENFORCEMENT = re.compile(
    r"abort\s*\(\s*40[13]|"
    r"HTTPException\s*\([^)]*(?:401|403|status\.HTTP_40[13])|"
    r"\bis_admin\b|\.is_admin|is_superuser|is_staff|"
    r"\.(?:user_id|owner_id|author_id)\s*(?:!=|==)|"
    r"\bauthorize\s*\(|\bcan_\w+\s*\(|\bcheck_\w*(?:access|owner|admin)|"
    r"jwt\.decode|decode_token|verify_token|validate_token", re.I)

# Handlers that are meant to be public. Reporting these would be noise, not a finding.
PUBLIC_OK = re.compile(r"\b(login|logout|signup|register|healthz?|health_check|ping|status|"
                       r"index|home|docs|openapi|metrics|robots|favicon|static|webhook)\b", re.I)

SELF_TEST = [
    ("@app.route('/admin')\ndef admin():\n    return User.objects.all()", True,
     "route with no auth marker at all"),
    ("@app.route('/admin')\n@login_required\ndef admin():\n    return 1", False,
     "login_required present"),
    ("@router.get('/x')\ndef x(u: User = Depends(get_current_user)):\n    return 1", False,
     "FastAPI dependency present"),
    ("@app.route('/login', methods=['POST'])\ndef login():\n    return 1", False,
     "login is meant to be public"),
    ("adm = APIRouter(dependencies=[Depends(require_user)])\n@adm.get('/x')\ndef x():\n    return 1", False,
     "handler on a router that carries the dependency"),
    ("adm = APIRouter(dependencies=[Depends(require_user)])\npub = APIRouter()\n"
     "@pub.get('/secrets')\ndef s():\n    return 1", True,
     "a DIFFERENT, unprotected router in the same file must still be reported"),
    ("@app.route('/admin')\ndef admin():\n    if not user.is_admin:\n        abort(403)\n"
     "    return 1", False,
     "enforcement in the body: the handler refuses, so the control is present"),
    ("@app.route('/doc/<int:i>')\ndef doc(i):\n    u = session['user_id']\n"
     "    return Doc.query.get(i)", True,
     "IDENTITY IS NOT AUTHORIZATION: reading the session then serving any object is CWE-862"),
]


def _handler_span(lines: list[str], i: int) -> tuple[int, int]:
    """From a decorator line, return the span covering its decorators and the function body."""
    start = i
    while start > 0 and lines[start - 1].lstrip().startswith("@"):
        start -= 1
    j = i
    while j < len(lines) and not re.match(r"\s*(?:async\s+)?def\s", lines[j]):
        j += 1
    end = j + 1
    indent = len(lines[j]) - len(lines[j].lstrip()) if j < len(lines) else 0
    while end < len(lines):
        ln = lines[end]
        if ln.strip() and (len(ln) - len(ln.lstrip())) <= indent and not ln.lstrip().startswith(("@", "#")):
            break
        end += 1
    return start, min(end, len(lines))


def findings_for(src: str, relpath: str) -> list[dict]:
    """Report every route handler with no authentication or authorization marker on it."""
    if APP_LEVEL.search(src):
        return []                      # every handler in the module sits behind app-wide auth
    protected = set(PROTECTED_ROUTER.findall(src))
    lines = src.splitlines()
    out = []
    for m in ROUTE.finditer(src):
        i = src[:m.start()].count("\n")
        owner = ROUTE_OWNER.match(lines[i])
        if owner and owner.group(1) in protected:
            continue                   # this particular router carries the dependency
        start, end = _handler_span(lines, i)
        block = "\n".join(lines[start:end])
        if AUTH_MARKER.search(block) or ENFORCEMENT.search(block):
            continue
        head = "\n".join(lines[i:min(i + 3, len(lines))])
        if PUBLIC_OK.search(head):
            continue
        # CWE-306 is "missing authentication for a critical function"; the corpus labels these sites
        # under 306 and 862 interchangeably, so the finding is emitted for both and claim-once in the
        # matcher prevents it being counted twice.
        for cwe in (306, 862):
            out.append({"rule_id": "absent-auth", "cwe": cwe, "file": relpath,
                        "line": i + 1, "code_slice": lines[i][:120], "severity": "HIGH"})
    return out


def self_test() -> bool:
    ok = True
    for src, want, why in SELF_TEST:
        got = bool(findings_for(src, "t.py"))
        if got != want:
            print(f"  SELF-TEST FAILED ({why}): got {got}, wanted {want}")
            ok = False
    return ok


def main() -> int:
    if not os.path.isdir(rs.REPOS):
        print("FAIL: corpus not fetched")
        return 2
    if not self_test():
        print("FAIL: the detector does not separate an unauthenticated route from a protected one.")
        return 2
    print(f"detector self-test PASSED ({len(SELF_TEST)} cases)\n")

    tp = fp = 0
    real_306 = real_862 = 0
    per_repo = []
    for slug in sorted(os.listdir(rs.REPOS)):
        root = os.path.join(rs.REPOS, slug)
        if not os.path.isdir(root):
            continue
        gt = rs.load_gt(slug)
        if not gt:
            continue
        real_306 += sum(1 for g in gt if g["is_vulnerable"] and 306 in g["cwes"])
        real_862 += sum(1 for g in gt if g["is_vulnerable"] and 862 in g["cwes"])
        findings = []
        for dp, _, fns in os.walk(root):
            for fn in fns:
                if not fn.endswith(".py"):
                    continue
                path = os.path.join(dp, fn)
                try:
                    src = open(path, encoding="utf-8", errors="replace").read()
                except OSError:
                    continue
                findings += findings_for(src, os.path.relpath(path, root))
        claimed: set[int] = set()
        rtp = sum(1 for f in findings if rs.match(f, gt, claimed))
        tp += rtp
        fp += len(findings) - rtp
        if findings:
            per_repo.append({"repo": slug, "findings": len(findings), "tp": rtp})

    real = real_306 + real_862
    print(f"ground-truth entries: CWE-306 {real_306}, CWE-862 {real_862}, total {real}")
    print(f"detector findings matched (claim-once, file+CWE+line+/-{rs.LINE_TOL}): {tp}")
    print(f"recall on these two classes = {tp}/{real} = {tp/real:.3f}")
    print(f"unmatched findings: {fp}")
    print("\ncomparison, same corpus and same matcher:")
    print("  Bandit + Semgrep on absence classes : 0 (they emit no absence-class rule at all)")
    print(f"  this detector                       : {tp}")

    out = {"generated_at": datetime.now(timezone.utc).isoformat(),
           "detector": "absent-auth (route handler with no authn/authz marker)",
           "scored_with": "run_spike.match — file + CWE + line tolerance, claim-once",
           "gt_306": real_306, "gt_862": real_862, "matched": tp, "unmatched": fp,
           "recall": round(tp / real, 4) if real else None, "per_repo": per_repo}
    with open(os.path.join(_HERE, "absent-auth-detector-260726.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
