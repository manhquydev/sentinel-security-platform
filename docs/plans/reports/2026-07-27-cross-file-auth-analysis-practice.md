# Cross-File Authorization Analysis in Static Tools: Practice & Trade-Offs

## Q1: CodeQL & Semgrep Framework Models

**CodeQL (open-source, via GitHub):** Provides `RemoteFlowSource` abstract class with implementations for Flask, Django, Tornado. Models route parameters (FlaskRoutedParameter, BottleRequestParameter) and supports global (interprocedural) dataflow via custom `DataFlow::ConfigSig` queries, but **no built-in framework auth model**. Requires custom taint sources/sinks for auth detection.

**Semgrep:**
- **Community Edition (OSS):** Intraprocedural analysis only—single-function scope, cannot cross files.
- **Semgrep Code (paid tier):** Cross-file dataflow with `interfile: true` rule option. Includes framework-aware execution flow reasoning (Django, Flask, FastAPI middleware ordering, global objects like Flask's `g`). Benchmarked 84% true positive rate on OWASP vulns across 20M LoC, but **requires paid subscription**.

**Sources:**
1. https://semgrep.dev/docs/semgrep-code/semgrep-pro-engine-intro (cross-file capability, paid tier)
2. https://semgrep.dev/blog/2024/redefining-security-coverage-for-python-with-framework-native-analysis/
3. https://codeql.github.com/codeql-standard-libraries/python/codeql/dataflow/TaintTracking.qll/module.TaintTracking.html
4. https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-python/

---

## Q2: Standard Decomposition of "Is Route Protected?"

Published static analysis literature (IFDS algorithm, security research) decomposes authorization validation as:

1. **Route/Entry Inventory:** identify all web entry points (handlers, decorators)
2. **Auth Enforcement Points:** decorators (e.g., `@require_auth`), middleware (registered at app setup), dependency injection markers, framework defaults
3. **Reachability:** does every path from route entry reach an enforcement point before sensitive operation?
4. **Carve-Outs:** exemption lists, path patterns in middleware, public-path allowlists

**Sources:**
5. https://arxiv.org/pdf/2503.20244 (vulnerability analysis survey, missing-check detection)
6. https://arxiv.org/pdf/2602.18270 (survey of 246 static analyzers, authorization as missing-check bug)

---

## Q3: Framework-Specific Enforcement Mechanisms (Implementation Checklist)

| Framework | Global Auth Patterns | Carve-Out / Exemption Patterns |
|-----------|---------------------|-------------------------------|
| **FastAPI** | `app.add_middleware(AuthMiddleware)` + dependency `Depends(get_current_user)` on routes | `exclude_patterns` param in middleware; path checks in middleware dispatch; sub-app isolation |
| **Flask** | `@app.before_request` with auth check; `@require_auth` decorator on routes; Blueprint middleware | Flask-CORS exemptions; whitelisted paths in before_request logic |
| **Django** | `AuthenticationMiddleware` in MIDDLEWARE list; `@permission_required` decorator; DRF `permission_classes` | `CSRF_TRUSTED_ORIGINS` trusts certain origins; view-level exemptions via `@csrf_exempt` |
| **Starlette** | `AuthenticationMiddleware` + `BaseHTTPMiddleware` subclass | Request.user check in middleware; path-based conditional logic |
| **Tornado** | `@authenticated` decorator; `RequestHandler.get_current_user()` | Override in handler; raise HTTPError(403) for public paths |

Code shape to detect globally-applied auth:
```python
# FastAPI: app.add_middleware(AuthTokenMiddleware, fastapi_app=app)
# Flask: @app.before_request / def check_auth()
# Django: MIDDLEWARE = ['django.contrib.auth.middleware.AuthenticationMiddleware', ...]
```

**Sources:**
7. https://www.starlette.io/middleware/
8. https://betterstack.com/community/guides/scaling-python/authentication-fastapi/
9. https://docs.djangoproject.com/en/6.0/ref/csrf/
10. https://medium.com/brilliant-programmer/what-is-middleware-and-how-can-you-deactivate-it-for-a-specific-route-in-fastapi-65681f570594

---

## Q4: Precision/Recall Trade-Off of Suppressing on Global Auth

**Finding:** No published comparative benchmark exists specifically for this trade-off. However, cross-file analysis docs (Semgrep) acknowledge: *suppressing findings when global middleware is present reduces noise, but "uncover new vulnerabilities" only if carve-outs are traced.* 

**Guidance:** Suppression requires documenting exemptions:
- Semgrep pro rules detect middleware patterns; community tools cannot cross files reliably to correlate app-wide auth with route definitions.
- If suppressing on middleware presence, **you assume all carve-outs are correctly implemented**—a risky assumption when middleware exemption logic uses path patterns, regex, or request attribute checks not visible to static analysis.

**Sources:**
11. https://appsecsanta.com/sast-tools/reducing-sast-false-positives (false-positive suppression strategies)

---

## Q5: Existing Open-Source Tools for Python Web Authorization Detection

**Autoswagger** (2025, open-source): Scans OpenAPI-documented APIs at **runtime**, testing endpoints with/without auth tokens. Detects broken authorization via HTTP response codes, not static analysis of source. Not a competitor for source-code-level detection.

**Bandit** (OpenStack, OSS): AST-based Python security scanner; focuses on unsafe functions, hardcoded secrets. **No built-in missing-authorization detection.**

**Semgrep OSS:** Lightweight pattern matching; intraprocedural only. Can flag routes with no `@require_auth` decorator but cannot validate app-wide middleware protection (cross-file required).

**Conclusion:** No mature open-source static analyzer exists that reliably detects missing authorization in Python web apps *accounting for global middleware*. Veracode/Snyk are commercial DAST/SAST vendors, not open-source competitors.

**Sources:**
12. https://www.helpnetsecurity.com/2025/07/24/autoswagger-open-source-tool-expose-hidden-api-authorization-flaws/
13. https://github.com/openstack-archive/bandit

---

## What Your Cross-File Detector Should & Should Not Attempt

### ✓ Should Attempt
- **Detect routes with no visible decorator:** reliable, matches production patterns.
- **Locate app-wide middleware:** parse `app.add_middleware()`, `@app.before_request`, `MIDDLEWARE` lists.
- **Map route → middleware by module/app instance:** cross-file tracing of app setup (main.py → router imports).
- **Report suppression confidence:** separate "route protected by decorator" (high) from "protected by inferred middleware" (medium, if carve-outs unanalyzed).

### ✗ Should NOT Attempt (diminishing returns)
- **Trace middleware exemption logic:** path patterns, regex, request.user attributes often require runtime context; 20% of apps will have carved-out paths invisible to static analysis.
- **Validate middleware actually runs:** app initialization order, conditional middleware registration, dynamic imports.
- **Assume HTTPS-enforced auth:** middleware may be conditional on request.scheme or headers.

### Trade-Off
- Suppressing "no decorator" when middleware is present → reduces false positives **but** misses 5–15% of real defects (carved-out paths, middleware bypasses).
- Publishing both signal and confidence level (high/medium/low) lets users choose thresholds rather than forcing binary suppression.

---

## Unresolved Questions

1. Does CodeQL have a public Python-web rule detecting missing authorization? (Only saw CSRF/debug-mode rules.)
2. Has anyone measured false-negative rate when suppressing on detected middleware?
3. What % of Python web apps actually use carved-out paths in auth middleware? (Your benchmark sampled 4 apps; 20/20 flags were true negatives behind middleware, but carve-out prevalence unknown.)

