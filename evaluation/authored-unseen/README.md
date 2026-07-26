# Authored unseen test set (E26 → E34)

**Twelve matched pairs** (24 modules) across **Flask, FastAPI and Django**, written 2026-07-26 in the
sessions that measured them, so no model can have trained on them. E26 used the first four (a
demonstration, n = 8, p = 0.071 — not significant); E34 extends to twelve, which is powered. Each pair implements the same feature in the same style; the `_a`
variant has the required control **removed**, the `_b` variant has it **present**. Ground truth is exact
by construction.

| pair | `_a` (defect) | `_b` (control present) |
|---|---|---|
| `invoices` | CWE-639 — invoice fetched by id with no `org_id` scope | `org_id` filter on the query |
| `reset` | CWE-307 — password reset with no rate limit or lockout | `@limiter.limit` on both routes |
| `exports` | CWE-862 — payroll CSV export with no role check | `role not in (...)` → 403 |
| `webhooks` | CWE-306 — billing webhook with no authentication | HMAC signature verification |
| `profile` | CWE-915 — mass assignment, every posted key written | field allowlist |
| `bulk` | CWE-639 — bulk fetch with no tenant scope | `tenant_id` filter |
| `internal` | CWE-306 — internal admin routes with no auth | `before_request` token check |
| `email` | CWE-620 — email change with no re-authentication | current-password check |
| `attachments` | CWE-639 — delete by id with no ownership check | **subtle**: ownership enforced by an injected dependency |
| `lookup` | CWE-209 — error path returns stack trace and query | logs server-side, returns generic error |
| `reports` | CWE-862 — service `base()` queryset unscoped | **subtle**: scope applied inside `base()` |
| `download` | CWE-639 — document fetched by pk alone | `org_id` in the lookup |

**Constraints followed while authoring** (preregistered in `docs/ai-sast-research-log.md` under E26):

- **Matched pairs.** Anything that makes a defect conspicuous also appears in its control twin, where it
  must *not* be flagged. This is what stops "textbook shape" from inflating the score.
- **No announcements.** No comment, identifier or docstring hints at the defect. No `# vulnerable`, no
  `unsafe_`, no `TODO: add authz`.
- **Realistic idiom.** Ordinary CRUD handlers with ORM queries, serialisers, pagination and error
  handling — not four-line demonstrations.
- **Three frameworks**, so "this author's Flask style" is not what gets detected.
- **Subtle controls** in some `_b` variants — a guard injected as a dependency, a scope applied inside a
  service base method — so specificity is tested against near-misses, not only against obvious checks.
- **Blind at measurement time.** Files are shuffled and renamed `module_N.py` before being shown, so
  neither filename nor ordering encodes the answer key.

**What a high score here does NOT mean:** it shows the detector finds defects *of the classes chosen, in
the style of this author*. A real client codebase contains defects nobody designed to be findable. This
set closes the "unseen code" gap, not the "realistic distribution" gap.
