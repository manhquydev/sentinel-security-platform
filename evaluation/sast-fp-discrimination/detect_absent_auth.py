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

# A route is declared by one of these decorators. The two negative lookaheads reject unittest.mock's
# `@patch` family, which shares the `patch` verb: `@patch('mod.thing')`, `@patch.object(...)`,
# `@mock.patch(...)`, `@unittest.mock.patch(...)` are test scaffolding, not HTTP routes. A real PATCH route
# always carries an app/router prefix (`@app.patch(`, `@router.patch(`), never a bare or mock-prefixed one.
# Measured on the teaching corpus this changes nothing (0 mock decorators there); it corrects production
# code, where a fifth to four-fifths of a repo's `@patch` decorators are mocks in tests (E78).
ROUTE = re.compile(
    r"^\s*@(?!patch\b)(?!(?:unittest\.)?mock\.patch\b)(?:\w+\.)?"
    r"(?:route|get|post|put|patch|delete)\s*\(", re.M)

# Anything that establishes WHO the caller is, or WHAT they may do. Presence of any of these on the
# handler means the control is not absent — the point is to report only handlers with none of them.
AUTH_MARKER = re.compile(
    r"login_required|permission_required|user_passes_test|staff_member_required|"
    r"require_role|require_roles|require_user|require_auth|requires_auth|"
    r"Depends\s*\(\s*(?:get_current|require_|verify_|auth)|"
    # FastAPI's `Security(...)` exists solely to declare a security requirement — it is `Depends` with
    # scopes, used for OAuth2/API-key/HTTP-auth schemes and nothing else. Missing it cost 221 of 241
    # false positives on one production application (E84), and unlike a generic `dependencies=[...]`
    # (which routinely injects a database session) its presence is unambiguous.
    r"Security\s*\(|"
    r"IsAuthenticated|permission_classes|authentication_classes|"
    r"current_user|request\.user\.is_authenticated|@token_required|@jwt_required|"
    r"api_key|check_permission|has_perm|ensure_\w*auth", re.I)

# Protection declared once for a whole router or application, which a handler-only scan cannot see:
# FastAPI routers carry dependencies=[Depends(...)], Flask has before_request, Django has auth middleware.
# Measured at 9 of 101 finding-producing files (28 of 621 findings, 4.5%) — too small to rescue precision,
# but a correctness gap regardless, and reporting a route as unprotected when its router protects it is
# simply wrong.
# App-wide protection: nothing in the module can be unprotected behind it.
#
# The middleware CLASS must itself be auth-shaped. The first version matched `add_middleware(...Auth...)`
# anywhere inside the call, which caught **CORSMiddleware** in three corpus applications, because
# `allow_headers=["Content-Type", "Authorization"]` contains the word. CORS is not authentication, and
# that single mis-match accounted for most of the "21% recall cost" E82 attributed to carve-outs (E83).
# Anchoring on the first argument is what distinguishes `add_middleware(AuthTokenMiddleware, ...)` from
# `add_middleware(CORSMiddleware, allow_headers=[... "Authorization"])`.
APP_LEVEL = re.compile(
    r"@\w+\.before_request"
    r"|add_middleware\s*\(\s*(?:\w+\.)*\w*(?:auth|login_required|jwt|session)\w*"
    r"|Middleware\s*\(\s*(?:\w+\.)*\w*(?:Authentication|Authorization|AuthToken)\w*"
    r"|LoginRequiredMiddleware|AuthenticationMiddleware", re.I)
# Per-router protection: `admin = APIRouter(dependencies=[Depends(require_user)])` protects only the
# handlers decorated with THAT router. A file often holds both a protected and a public router, so
# suppressing the whole module on one match was too coarse — it cost four real detections.
PROTECTED_ROUTER = re.compile(
    r"^\s*(\w+)\s*=\s*APIRouter\s*\([^)]*dependencies\s*=\s*\[[^\]]*(?:Depends|require|auth)",
    re.I | re.M)
# Which router object a decorator belongs to: @admin.get(...) -> "admin".
ROUTE_OWNER = re.compile(r"^\s*@(\w+)\.(?:route|get|post|put|patch|delete)\s*\(")

# --- CROSS-FILE PROTECTION (E81) -------------------------------------------------------------------
# Production applications centralise authentication. Measured on four real apps: two enforce it with
# app-wide middleware declared in `main.py`/`asgi.py` while their routes live in `routers/*.py`, and the
# per-file APP_LEVEL suppressor above can never see it — 20 of 20 sampled flags in those apps sat on
# routes that were already protected. A single-file detector is structurally blind to how real
# applications are built, and that blindness, not the vocabulary, is what caps production precision.
#
# The fix is a repository-level pre-pass that answers two questions before any file is scanned:
#   1. does this application enforce authentication for every request? (middleware / before_request)
#   2. which router objects are mounted with a dependency, anywhere in the tree?
# `include_router(chat_router, dependencies=[Depends(get_verified_user)])` in main.py protects handlers
# written on `chat_router` in another module entirely.
#
# What this deliberately does NOT do: prove reachability. App-wide middleware routinely carves out
# login, health and webhook paths, so "the app has auth middleware" is not "every route is protected".
# Suppressing on it trades recall for precision, and the trade is stated rather than hidden — see the
# `carve_outs` field, which records the exemption paths found so the cost is visible.
MOUNT_WITH_DEPS = re.compile(
    r"include_router\s*\(\s*([\w.]+)[^)]*dependencies\s*=\s*\[[^\]]*(?:Depends|require|auth)",
    re.I)
APP_DEPS = re.compile(r"FastAPI\s*\([^)]*dependencies\s*=\s*\[[^\]]*(?:Depends|require|auth)", re.I)
DRF_DEFAULT = re.compile(r"DEFAULT_PERMISSION_CLASSES\s*[:=]\s*[\[(][^\])]*(?:IsAuthenticated|"
                         r"DjangoModelPermissions|IsAdminUser)", re.I)
# Paths a global guard typically exempts. Their presence means suppression is over-broad, so they are
# counted and reported rather than silently ignored.
CARVE_OUT = re.compile(r"['\"]/(?:login|signin|auth|health|healthz|ping|docs|openapi|redoc|static|"
                       r"metrics|webhook|public)[\w/]*['\"]", re.I)


class RepoContext:
    """What protects routes in this repository, gathered before any single file is judged.

    Backward compatible by design: `findings_for(src, rel)` without a context behaves exactly as before,
    so every existing caller and every published corpus number is unaffected until it opts in.

    The two mechanisms it carries have very different prices, measured on the corpus (E82) rather than
    assumed, so they are controlled separately:

      * **router propagation** — a router mounted with a dependency in another module. Precise, and it
        costs **nothing**: zero corpus true positives lost. On by default.
      * **app-wide suppression** — the application registers an enforcing auth guard, so every request is
        authenticated. Removes **508 of 514** production false positives across two real apps at **zero
        corpus recall cost** (76/289 either way; four non-defect sites suppressed). **On by default.**
        The first measurement put the cost at 21% and concluded it was not payable; that figure was two
        bugs of my own — `add_middleware(CORSMiddleware, allow_headers=[..."Authorization"])` matching as
        auth, and a repository treated as one application when `vulpy` ships `good/` and `bad/` variants.
        Fixing both, plus requiring the guard to ENFORCE rather than merely load a session, took the cost
        to zero (E83).
    """

    def __init__(self, app_wide: bool = False, routers: set[str] | None = None,
                 carve_outs: int = 0, evidence: list[str] | None = None,
                 suppress_app_wide: bool = True, scopes: set[str] | None = None) -> None:
        self.app_wide = app_wide
        self.routers = routers or set()
        self.carve_outs = carve_outs
        self.evidence = evidence or []
        self.suppress_app_wide = suppress_app_wide
        self.scopes = scopes or set()      # directory subtrees an app-wide guard actually covers

    def protects(self, owner: str | None, relpath: str | None = None) -> bool:
        return (self.app_wide_covers(relpath) or (owner is not None and owner in self.routers))

    def app_wide_covers(self, relpath: str | None) -> bool:
        """Does an app-wide guard cover THIS file?

        A repository is not always one application. `vulpy` ships `good/` and `bad/` variants of the same
        app: `good/vulpy.py` registers `@app.before_request`, `bad/mod_*.py` holds the planted defects, and
        treating the repository as a single unit let the good app's guard suppress the bad app's routes —
        five real detections lost to a scope error rather than to any carve-out (E83).

        Scope rule: a guard covers the directory subtree it was registered in. Registered at the root, it
        covers everything; registered in `good/`, it covers `good/`.
        """
        if not (self.app_wide and self.suppress_app_wide):
            return False
        if relpath is None or not self.scopes:
            return True
        rel = relpath.replace("\\", "/")
        return any(s == "" or rel.startswith(s + "/") for s in self.scopes)

    def __repr__(self) -> str:
        return (f"RepoContext(app_wide={self.app_wide}, routers={sorted(self.routers)}, "
                f"scopes={sorted(self.scopes)}, carve_outs={self.carve_outs})")


def _global_guard_enforces(src: str) -> bool:
    """Does this module's app-level guard actually REFUSE, or does it only learn who is calling?

    The same distinction E61 established for handler bodies, applied at application scope — and it is
    what separates the two `vulpy` variants, whose `before_request` hooks are byte-identical:

        @app.before_request
        def before_request():
            g.session = libsession.load(request)     # loads identity; refuses nothing

    Treating that as app-wide protection suppressed six real defects in the `bad` variant (E83). A guard
    counts only if its body contains an enforcement construct — an abort, a raise, a redirect to login, a
    permission test. Middleware registered by class name (`AuthTokenMiddleware`) is taken at its word: its
    body is not in this file, and the class name is the only evidence available.
    """
    lines = src.splitlines()
    for i, ln in enumerate(lines):
        if not re.match(r"\s*@\w+\.before_request", ln):
            continue
        start, end = _handler_span(lines, i)
        body = "\n".join(lines[start:end])
        # Refusing is not enough — it must refuse ON AN IDENTITY OR PERMISSION CONDITION. pgadmin4's
        # `limit_host_addr` returns 403 for Host-header injection: a real control, but not authentication,
        # and counting it suppressed 31 flags that no auth guard covers (E85). So the body needs both a
        # refusal AND a reference to who the caller is or what they may do.
        # Refusal forms, each added from a verified application rather than guessed: `abort(401)`
        # (pgadmin4), `login_manager.unauthorized()` (changedetection.io — Flask-Login's standard
        # refusal), an explicit 401/403 response, a redirect to login.
        refuses = bool(ENFORCEMENT.search(body)) or bool(re.search(
            r"\babort\s*\(|\braise\b|redirect\s*\("
            r"|\.unauthorized\s*\(|make_response\s*\([^)]*40[13]"
            r"|status_code\s*=\s*40[13]|Response\s*\([^)]*40[13]", body))
        identity = bool(AUTH_MARKER.search(body)) or bool(re.search(
            r"is_authenticated|current_user|\bsession\b|\blogin\b|\bpermission|\btoken\b|"
            r"\buser\b|is_admin|is_staff|is_superuser", body, re.I))
        if refuses and identity:
            return True
    return False


def scan_repo(root: str, skip_dirs: set[str] | None = None) -> RepoContext:
    """One pass over a repository to find centralised protection before judging any route."""
    skip = skip_dirs or {".git", "node_modules", ".venv", "venv", "__pycache__"}
    app_wide, routers, carve, evidence, scopes = False, set(), 0, [], set()
    for dp, dirs, fns in os.walk(root):
        dirs[:] = [d for d in dirs if d not in skip]
        for fn in fns:
            if not fn.endswith(".py"):
                continue
            path = os.path.join(dp, fn)
            try:
                src = open(path, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            rel = os.path.relpath(path, root)
            # Tests declare mock middleware and fixture routers; they protect nothing in production.
            if "/tests/" in rel.replace("\\", "/") or fn.startswith("test_"):
                continue
            # A `before_request` hook counts only if it enforces; middleware registered by an
            # auth-shaped class name is taken at its word (its body is elsewhere).
            hook_only = bool(re.search(r"@\w+\.before_request", src)) and not re.search(
                r"add_middleware\s*\(\s*(?:\w+\.)*\w*(?:auth|jwt|session)\w*"
                r"|LoginRequiredMiddleware|AuthenticationMiddleware",
                "\n".join(l for l in src.splitlines() if not re.match(r"\s*(?:from|import)\s", l)),
                re.I)
            enforces = _global_guard_enforces(src) if hook_only else True
            if enforces and (APP_LEVEL.search(src) or APP_DEPS.search(src) or DRF_DEFAULT.search(src)):
                app_wide = True
                evidence.append(rel)
                scopes.add(os.path.dirname(rel).replace("\\", "/"))
            for m in MOUNT_WITH_DEPS.finditer(src):
                routers.add(m.group(1).split(".")[-1])
            routers.update(PROTECTED_ROUTER.findall(src))
            carve += len(CARVE_OUT.findall(src))
    return RepoContext(app_wide, routers, carve, evidence[:8], scopes=scopes)
# ---------------------------------------------------------------------------------------------------

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
    ("@router.get('/w')\ndef w(u=Security(verify_oauth_client, scopes=['read'])):\n    return 1", False,
     "FastAPI Security() is a security declaration, not a generic dependency"),
    ("@router.get('/w')\ndef w(db=Depends(get_db)):\n    return Data.query.all()", True,
     "a generic dependency (a db session) is NOT authentication and must still be reported"),
    ("@patch('requests.get')\ndef test_thing(m):\n    assert call() == 1", False,
     "unittest.mock @patch is not a route — it shares the verb 'patch' but is test scaffolding"),
    ("@mock.patch('svc.client')\ndef test_flow(m):\n    do()", False,
     "@mock.patch is not a route either"),
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


def findings_for(src: str, relpath: str, ctx: "RepoContext | None" = None) -> list[dict]:
    """Report every route handler with no authentication or authorization marker on it.

    `ctx` carries repository-level protection discovered by `scan_repo` — app-wide middleware and routers
    mounted with a dependency in another module. Without it the function behaves exactly as it always has,
    so every published corpus number stands unchanged; with it the structural false positives measured in
    E81 are suppressed.
    """
    if ctx is not None and ctx.app_wide_covers(relpath):
        return []                      # opt-in: an app-wide guard covers this file's subtree
    if APP_LEVEL.search(src):
        return []                      # every handler in the module sits behind app-wide auth
    protected = set(PROTECTED_ROUTER.findall(src))
    if ctx is not None:
        protected |= ctx.routers       # mounted with a dependency somewhere else in the tree
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
    # Both denominators are counted, because the obvious ones double-count and flatter the result:
    #
    #   real_306 + real_862 counts an entry labelled with BOTH classes twice — 48 of them here — so a
    #   defect the detector can only find once sits in the denominator twice. Distinct entries is the
    #   honest denominator for "recall over this class".
    #
    #   findings counts each SITE twice, because the detector emits one finding per CWE for every route
    #   it reports (`for cwe in (306, 862)`). A user is shown route handlers, not (route, CWE) pairs, so
    #   finding-level precision understates by exactly 2x and the product sentence built on it named
    #   twice as many handlers as exist.
    distinct_real = 0
    sites = 0
    tp_sites = 0
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
        distinct_real += sum(1 for g in gt if g["is_vulnerable"]
                             and (306 in g["cwes"] or 862 in g["cwes"]))
        # The published number must describe what the tool actually does, and the tool is cross-file
        # aware (E83): a repository pre-pass finds enforcing app-wide guards and cross-file router mounts
        # before any file is judged.
        ctx = scan_repo(root)
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
                findings += findings_for(src, os.path.relpath(path, root), ctx)
        claimed: set[int] = set()
        hit_sites = set()
        rtp = 0
        for f in findings:
            if rs.match(f, gt, claimed):
                rtp += 1
                hit_sites.add((f["file"], f["line"]))
        tp += rtp
        fp += len(findings) - rtp
        sites += len({(f["file"], f["line"]) for f in findings})
        tp_sites += len(hit_sites)
        if findings:
            per_repo.append({"repo": slug, "findings": len(findings), "tp": rtp})

    real = real_306 + real_862
    print(f"ground-truth entries: CWE-306 {real_306}, CWE-862 {real_862}, sum {real}")
    print(f"  of which carry BOTH classes: {real - distinct_real};  DISTINCT entries: {distinct_real}")
    print(f"detector findings matched (claim-once, file+CWE+line+/-{rs.LINE_TOL}): {tp}")
    print(f"\nRECALL")
    print(f"  over distinct entries (honest) : {tp}/{distinct_real} = {tp/distinct_real:.3f}")
    print(f"  over the summed denominator    : {tp}/{real} = {tp/real:.3f}  <- double-counts dual-labelled")
    print(f"\nPRECISION")
    print(f"  per SITE, what a user is shown : {tp_sites}/{sites} = {tp_sites/sites:.3f}")
    print(f"  per finding                    : {tp}/{tp+fp} = {tp/(tp+fp):.3f}  <- 2 findings per site")
    print(f"\nreported route handlers: {sites}   (findings emitted: {tp + fp} = {(tp+fp)/sites:.1f}x)")
    print("\ncomparison, same corpus and same matcher:")
    print("  Bandit + Semgrep on absence classes : 0 (they emit no absence-class rule at all)")
    print(f"  this detector                       : {tp}")

    out = {"generated_at": datetime.now(timezone.utc).isoformat(),
           "detector": "absent-auth (route handler with no authn/authz marker)",
           "scored_with": "run_spike.match — file + CWE + line tolerance, claim-once",
           "gt_306": real_306, "gt_862": real_862, "gt_distinct": distinct_real,
           "matched": tp, "unmatched": fp,
           "sites": sites, "tp_sites": tp_sites,
           "recall": round(tp / distinct_real, 4) if distinct_real else None,
           "recall_summed_denominator": round(tp / real, 4) if real else None,
           "precision_site": round(tp_sites / sites, 4) if sites else None,
           "precision_finding": round(tp / (tp + fp), 4) if (tp + fp) else None,
           "denominator_note": "recall is over DISTINCT labelled entries; the summed 306+862 denominator "
                               "double-counts the 48 entries carrying both. precision is per SITE; the "
                               "detector emits one finding per CWE so finding-level precision halves it",
           "per_repo": per_repo}
    with open(os.path.join(_HERE, "absent-auth-detector-260726.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
