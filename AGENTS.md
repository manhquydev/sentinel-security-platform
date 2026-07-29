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
