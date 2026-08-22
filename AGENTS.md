# Agent Instructions

<!-- HARNESS:BEGIN -->
## Harness

Start with the requested outcome, then use the repository as the system of
record. Read `docs/WORKFLOW.md` and only the product, design, plan,
code, and validation material relevant to the task.

- Answers, explanations, reviews, diagnoses, plans, and status reports are
  read-only. Inspect only what is needed and do not mutate repository or Harness
  state.
- For a bounded change, use an ephemeral plan: inspect the affected behavior and
  existing proof, implement the change, and run behavior-appropriate validation.
  No control-plane operation is required.
- Create or update one file under `docs/plans/active/` when work spans sessions,
  needs coordination or an ordered sequence, has meaningful dependencies, or
  requires explicit recovery steps. Move it to `docs/plans/completed/` only
  after validation.
- Before editing, identify repository authority for each new externally
  observable policy. If materially different choices remain open, stop before
  edits; configurable defaults are not authority.
- Also pause when product intent remains ambiguous, an action is difficult to
  recover, validation would be weakened, or the request does not authorize the
  needed action.
- Claim completion only with relevant executable or observable evidence. Report
  the outcome, important changed surfaces, validation, and unresolved risks.

SQLite intake, story, trace, scoring, audit, and proposal commands are optional
compatibility features. Use them only when explicitly requested or required by
an external orchestrator.
<!-- HARNESS:END -->

## Autonomy Authorization (maintainer override)

This override intentionally relaxes the conservative defaults of the Harness
block above. It is placed outside the `HARNESS:BEGIN/END` markers so a harness
re-run does not clobber it. For this project the maintainer authorizes agents
(Codex and Claude Code) to work autonomously, like a full coding agent:

- You MAY inspect, edit, create, run, test, and spawn parallel subagents to
  complete a clear task in one continuous flow. The "answers/reviews are
  read-only" and "stop before edits / pause on ambiguity" defaults do NOT apply
  to authorized delivery work — proceed and self-correct instead of stopping to
  ask at each step.
- Prefer acting over asking. Ask only when a decision is genuinely the
  maintainer's (pricing, schema shape, irreversible scope) or cannot be resolved
  from the repo/live state.
- A durable `docs/plans/active/` file is optional, not a gate: create one only
  for genuinely multi-session or high-risk work; small/bounded changes need none.

Non-negotiable rails still apply: never commit or print secrets/`infra/.env`
contents; confirm before truly destructive or hard-to-reverse actions; do not
weaken or delete tests to make them pass; keep changes scoped to the request.

## Pre-Approved File Access

Two paths are pre-approved as project-known, not generically secret, so
searching for or referencing their names (docs, comments, tests) needs no
approval:

- `scanners/image-pins.env` — public, tracked in git; holds only pinned
  container image tags (no secrets).
- `infra/.env` — a real, git-ignored local secrets file (LiteLLM/DB/Langfuse
  keys, admin passwords). The maintainer has pre-approved agent access to it.

In Claude Code specifically: this project's local privacy-block hook allows
both paths, but the user's separate global hook copy (shared across all their
projects, deliberately left untouched) still gates direct `Read`/`Edit`/`Write`
of `infra/.env`'s real content — expect a one-time approval prompt for that.
Reading it via `Bash` (e.g. `cat infra/.env`) is not gated. Codex and other
tools without this hook mechanism may read/reference both paths directly.

This exemption covers read/reference access only. It does not change what may
be committed: `infra/.env` stays git-ignored, and its contents must never be
pasted into a commit, tracked file, code comment, or chat/log output. Use
`infra/.env.example` as the template for documenting required keys.

## Current State (memory · updated 2026-08-20)

Charter meets every minimum-to-pass and exceeds; slim grader 338 passed, full
overlay 140 passed, PII 10/10 FP 0. Live surfaces are up: public docs site
and Access-gated DefectDojo. A 2026-08-20 review checked the public doors
(app ports not on the internet, IAP-only SSH, no VM service account). That
is an exposure review, not a live 9-step AI quality score. Details/how-to
(do not duplicate here):

- Deployment status: [`docs/deployment.md`](docs/deployment.md) (Cloudflare
  Worker docs site + GCP VM `sentinel-charter` full Charter topology).
- Use/test the live deployment: [`docs/operations/live-deployment-guide.md`](docs/operations/live-deployment-guide.md).
- Completion evidence: [`docs/reports/sentinel-completion-selfassessment.md`](docs/reports/sentinel-completion-selfassessment.md).
- Latest journal: [`docs/journal/2026-08-20-production-deploy-and-hardening.md`](docs/journal/2026-08-20-production-deploy-and-hardening.md).

Live surfaces: docs `https://vinsoc.manhquy.io.vn` (+ `.id.vn`); gated app
`https://app.vinsoc.manhquy.io.vn` (Cloudflare Access → DefectDojo, 5 real
findings). Security: app ports loopback-only + no public firewall opening; SSH
IAP-only; VM has **no service account** (Vertex via ADC file) + a
`sentinel-metadata-guard` blocking container→metadata. **The GCP VM bills while
running** (`infra/gcp/deploy.sh teardown` to stop). Open follow-up: a
`live_run:true` FP/FN scorecard is blocked by a model↔enrichment-schema mismatch
(fix by choosing a schema-honoring model — never by weakening the validator).
