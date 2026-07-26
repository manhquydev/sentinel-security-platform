# Authored unseen test set (E26)

Four **matched pairs** of Flask route modules, written 2026-07-26 in the session that measured them, so
no model can have trained on them. Each pair implements the same feature in the same style; the `_a`
variant has the required control **removed**, the `_b` variant has it **present**. Ground truth is exact
by construction.

| pair | `_a` (defect) | `_b` (control present) |
|---|---|---|
| `invoices` | CWE-639 — invoice fetched by id with no `org_id` scope | `org_id` filter on the query |
| `reset` | CWE-307 — password reset with no rate limit or lockout | `@limiter.limit` on both routes |
| `exports` | CWE-862 — payroll CSV export with no role check | `role not in (...)` → 403 |
| `webhooks` | CWE-306 — billing webhook with no authentication | HMAC signature verification |

**Constraints followed while authoring** (preregistered in `docs/ai-sast-research-log.md` under E26):

- **Matched pairs.** Anything that makes a defect conspicuous also appears in its control twin, where it
  must *not* be flagged. This is what stops "textbook shape" from inflating the score.
- **No announcements.** No comment, identifier or docstring hints at the defect. No `# vulnerable`, no
  `unsafe_`, no `TODO: add authz`.
- **Realistic idiom.** Ordinary CRUD handlers with ORM queries, serialisers, pagination and error
  handling — not four-line demonstrations.
- **Blind at measurement time.** Files are shuffled and renamed `module_N.py` before being shown, so
  neither filename nor ordering encodes the answer key.

**What a high score here does NOT mean:** it shows the detector finds defects *of the classes chosen, in
the style of this author*. A real client codebase contains defects nobody designed to be findable. This
set closes the "unseen code" gap, not the "realistic distribution" gap.
