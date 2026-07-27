"""How many centralised-auth idioms exist? The measurement that decides whether vocabulary can ever work.

E85 held the cross-file fixes out of sample and found the reduction is **bimodal**: three of twelve
production applications lost 99-100% of their flags, nine lost none. Vocabulary-based detection either
recognises an application's idiom completely or misses it completely. The tempting response — read the nine
and add their idioms — is precisely the in-sample fitting E85 was built to detect.

The question that decides the approach is not "what idiom does app N use" but **how many idioms are there**.
If a handful cover most applications, the vocabulary is merely incomplete and finishable. If the tail is
long and flat, no vocabulary can converge and the whole detector design is capped.

HOW THE CATALOGUE AVOIDS FITTING THESE APPLICATIONS. Every pattern below is written from **framework
documentation** — the ways Flask, FastAPI/Starlette, Django/DRF, Tornado, aiohttp and Sanic document
centralised authentication — and NOT by reading the repositories it is scored on. Patterns the detector
already knows are marked, so the census reports both what exists and what is currently reachable.

THE THREE OUTCOMES, and each says something different:
  * an application matches a KNOWN idiom          -> the detector already handles it (or has a bug)
  * it matches a CATALOGUED but unknown idiom     -> a finishable vocabulary gap, and the census sizes it
  * it matches NOTHING                            -> either it genuinely has no centralised auth (its
                                                     flags may be real) or the idiom is outside any
                                                     framework's documented set, which is the finding
                                                     that would cap the approach

WHAT WOULD FALSIFY "vocabulary can work": a large share of applications matching nothing, or a coverage
curve that keeps climbing with each idiom added rather than flattening.

    rag/.venv/bin/python -W ignore evaluation/sast-fp-discrimination/run_idiom_census.py
"""

from __future__ import annotations

import collections
import json
import os
import re
import sys
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import detect_absent_auth as det  # noqa: E402

CLONE_DIRS = [os.path.join(os.environ.get("TMPDIR", "/tmp"), d)
              for d in ("volume-census-clones", "heldout-production-clones")]
SKIP = {".git", "node_modules", ".venv", "venv", "__pycache__", "tests", "test"}

# Catalogue written from framework documentation, not from these repositories.
# (known=True marks what `detect_absent_auth` can already act on.)
IDIOMS: list[tuple[str, str, bool, re.Pattern]] = [
    # --- Flask -------------------------------------------------------------------------------------
    ("flask", "before_request hook", True,
     re.compile(r"@\w+\.before_request")),
    ("flask", "Flask-Login login_required", True,
     re.compile(r"@login_required|login_required\b")),
    ("flask", "Flask-Security/Principal decorators", False,
     re.compile(r"@auth_required|@roles_required|@roles_accepted|@permissions_required")),
    ("flask", "Flask-HTTPAuth", False,
     re.compile(r"HTTPBasicAuth\s*\(|HTTPTokenAuth\s*\(|@auth\.login_required")),
    ("flask", "Flask-JWT-Extended", False,
     re.compile(r"@jwt_required|jwt_required\s*\(|verify_jwt_in_request")),
    # --- FastAPI / Starlette ----------------------------------------------------------------------
    ("fastapi", "app/router dependencies=", True,
     re.compile(r"(?:FastAPI|APIRouter)\s*\([^)]*dependencies\s*=|include_router\s*\([^)]*dependencies\s*=")),
    ("fastapi", "Security() / Depends() auth", True,
     re.compile(r"Security\s*\(|Depends\s*\(\s*(?:get_current|require_|verify_|auth)")),
    ("starlette", "AuthenticationMiddleware", True,
     re.compile(r"add_middleware\s*\(\s*(?:\w+\.)*AuthenticationMiddleware|"
                r"Middleware\s*\(\s*(?:\w+\.)*AuthenticationMiddleware")),
    ("starlette", "custom BaseHTTPMiddleware auth", False,
     re.compile(r"class\s+\w*(?:Auth|Token|Session)\w*\s*\(\s*BaseHTTPMiddleware")),
    ("starlette", "requires() decorator", False,
     re.compile(r"@requires\s*\(|from\s+starlette\.authentication\s+import[^\n]*requires")),
    # --- Django / DRF -----------------------------------------------------------------------------
    ("django", "AuthenticationMiddleware in MIDDLEWARE", True,
     re.compile(r"['\"]django\.contrib\.auth\.middleware\.AuthenticationMiddleware['\"]")),
    ("django", "DRF DEFAULT_PERMISSION_CLASSES", True,
     re.compile(r"DEFAULT_PERMISSION_CLASSES")),
    ("django", "permission_classes on a view", True,
     re.compile(r"permission_classes\s*=")),
    ("django", "LoginRequiredMiddleware", True,
     re.compile(r"LoginRequiredMiddleware")),
    ("django", "@login_required / LoginRequiredMixin", True,
     re.compile(r"@login_required|LoginRequiredMixin|PermissionRequiredMixin")),
    # --- Tornado / aiohttp / Sanic ----------------------------------------------------------------
    ("tornado", "get_current_user / @authenticated", False,
     re.compile(r"def\s+get_current_user\s*\(|@tornado\.web\.authenticated|@authenticated\b")),
    ("aiohttp", "middleware auth", False,
     re.compile(r"@web\.middleware[\s\S]{0,200}?(?:auth|token|login)", re.I)),
    ("sanic", "middleware / decorator auth", False,
     re.compile(r"@app\.middleware\s*\([^)]*request[^)]*\)[\s\S]{0,200}?(?:auth|token)", re.I)),
    # --- framework-agnostic -----------------------------------------------------------------------
    # ("agnostic", "explicit gateway/proxy auth note") was REMOVED before publication: it matched 11 of 16
    # applications, all of them on prose — comments about "AWS API Gateway" header handling and "reverse
    # proxy" behaviour, never an auth mechanism. A pattern that fires on documentation is not evidence of
    # enforcement, and left in it would have carried the top-1 coverage figure single-handedly.
    ("agnostic", "ASGI/WSGI wrapper auth", False,
     re.compile(r"class\s+\w*Auth\w*(?:Middleware)?\s*\([^)]*\)\s*:[\s\S]{0,300}?__call__")),
]


def repo_paths() -> list[tuple[str, str]]:
    out = []
    for base in CLONE_DIRS:
        if not os.path.isdir(base):
            continue
        for name in sorted(os.listdir(base)):
            root = os.path.join(base, name)
            if os.path.isdir(root):
                out.append((name.replace("__", "/"), root))
    return out


def scan(root: str) -> tuple[set[tuple[str, str]], int, int]:
    """(idioms matched, route declarations, flags today)."""
    matched, routes, flags = set(), 0, 0
    ctx = det.scan_repo(root)
    for dp, dirs, fns in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP]
        for fn in fns:
            if not fn.endswith(".py") or fn.startswith("test_"):
                continue
            path = os.path.join(dp, fn)
            try:
                src = open(path, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            # imports name a mechanism without installing it (E85 defect 2)
            body = "\n".join(l for l in src.splitlines()
                             if not re.match(r"\s*(?:from|import)\s", l))
            routes += len(det.ROUTE.findall(src))
            flags += len({x["line"] for x in det.findings_for(src, os.path.relpath(path, root), ctx)})
            for fw, name, _known, rx in IDIOMS:
                if rx.search(body):
                    matched.add((fw, name))
    return matched, routes, flags


def main() -> int:
    if not det.self_test():
        print("FAIL: detector self-test")
        return 2
    known = {(fw, n) for fw, n, k, _ in IDIOMS if k}
    apps, rows = [], []
    for repo, root in repo_paths():
        matched, routes, flags = scan(root)
        if routes < 20:
            continue                                    # not a route-bearing application
        apps.append(repo)
        rows.append({"repo": repo, "routes": routes, "flags": flags,
                     "idioms": sorted(f"{fw}:{n}" for fw, n in matched),
                     "known": sorted(f"{fw}:{n}" for fw, n in matched & known),
                     "unknown": sorted(f"{fw}:{n}" for fw, n in matched - known),
                     "any_idiom": bool(matched)})
    if len(rows) < 8:
        print(f"FAIL: only {len(rows)} route-bearing applications available")
        return 2

    print(f"=== idiom census over {len(rows)} production web applications ===\n")
    for r in sorted(rows, key=lambda r: -r["routes"]):
        tag = "KNOWN" if r["known"] else ("unknown-only" if r["idioms"] else "NONE")
        print(f"  {r['repo']:<34} routes {r['routes']:>4} flags {r['flags']:>4}  "
              f"{len(r['idioms'])} idiom(s) [{tag}]")

    freq = collections.Counter(i for r in rows for i in r["idioms"])
    none_at_all = [r["repo"] for r in rows if not r["idioms"]]
    unknown_only = [r["repo"] for r in rows if r["idioms"] and not r["known"]]

    print(f"\nidiom frequency across {len(rows)} applications:")
    for name, n in freq.most_common():
        mark = "known  " if name in {f"{fw}:{nm}" for fw, nm in known} else "UNKNOWN"
        print(f"  {mark} {n:>3}/{len(rows)}  {name}")

    # Coverage curve: how many applications are explained by the top-k idioms?
    print("\ncoverage curve — applications touched by the top-k most common idioms:")
    ordered = [name for name, _ in freq.most_common()]
    for k in (1, 2, 3, 5, 8, len(ordered)):
        if k > len(ordered):
            continue
        top = set(ordered[:k])
        cov = sum(1 for r in rows if top & set(r["idioms"]))
        print(f"  top {k:>2}: {cov}/{len(rows)} = {cov/len(rows):.0%}")

    print(f"\napplications matching NO catalogued idiom: {len(none_at_all)}/{len(rows)} "
          f"= {len(none_at_all)/len(rows):.0%} {none_at_all or ''}")
    print(f"applications matching only UNCATALOGUED-by-detector idioms: {len(unknown_only)} {unknown_only or ''}")

    flat = len(none_at_all) / len(rows)
    verdict = ("VOCABULARY IS FINISHABLE — a short catalogue explains nearly every application"
               if flat <= 0.15 else
               "VOCABULARY IS CAPPED — a substantial share of applications match no documented idiom, "
               "so no finite list converges")
    print(f"\n  {verdict}")
    print("  This counts MECHANISMS PRESENT, not whether they cover every route: an application can")
    print("  register a guard and still leave routes exempt. It bounds what a vocabulary could reach.")

    out = {"generated_at": datetime.now(timezone.utc).isoformat(),
           "question": "how many centralised-auth idioms exist, and can a finite vocabulary converge?",
           "catalogue_source": "framework documentation (Flask, FastAPI/Starlette, Django/DRF, Tornado, "
                               "aiohttp, Sanic) — NOT read from the repositories scored here",
           "applications": len(rows),
           "idiom_frequency": dict(freq),
           "known_to_detector": sorted(f"{fw}:{n}" for fw, n in known),
           "apps_matching_nothing": none_at_all,
           "apps_matching_only_unknown": unknown_only,
           "coverage_curve": {str(k): sum(1 for r in rows if set(ordered[:k]) & set(r["idioms"]))
                              for k in (1, 2, 3, 5, 8, len(ordered)) if k <= len(ordered)},
           "fraction_unexplained": round(flat, 4),
           "verdict": verdict,
           "limitation": "counts mechanisms present, not route-level coverage",
           "per_repo": rows}
    with open(os.path.join(_HERE, "idiom-census-260727.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    print("\nwrote idiom-census-260727.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
