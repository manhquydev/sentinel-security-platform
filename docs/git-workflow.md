# Git workflow

A lightweight, professional workflow for this repository. It exists because Weeks 2–4 were
built on a single long-lived branch (`week2-api-gateway-agent-iam`) and merged as one 40-file
PR — which works, but is hard to review, hard to revert, and mixes unrelated concerns. The rule
below is: **one short-lived branch per phase/fix, one small PR, main always green.**

## Principles

1. **`main` is always green and deployable.** Never commit directly to `main`. Every change lands
   through a reviewed PR.
2. **One branch per unit of work.** A week/phase, a feature, or a fix — not several weeks stacked.
   A branch should live hours-to-days, not weeks.
3. **Small PRs.** Aim for a PR a reviewer can read in one sitting. If a phase is large, split it
   (e.g. "store", then "pipeline", then "eval") into stacked PRs or sequential ones.
4. **Unrelated WIP lives on its own branch**, never as uncommitted edits sitting in `main`'s
   working tree (that is how work gets lost or accidentally committed).

## Branch naming

`<type>/<short-slug>`, matching the conventional-commit types already in use:

- `feat/week5-fuzzing-engine`
- `fix/rag-stale-chunk-prune`
- `docs/git-workflow`
- `chore/pin-kong-image`

## The loop (per branch)

```
git switch main && git pull                 # start from fresh main
git switch -c feat/<slug>                    # new short-lived branch
# ... implement -> code-review -> audit -> fix (the cook loop) ...
# run the relevant test suites; keep them green
git add -p && git commit                     # conventional commits, focused
git push -u origin feat/<slug>
gh pr create --base main --fill              # open the PR (early is fine)
# address CodeRabbit / review findings, re-verify
gh pr merge --squash --delete-branch         # or --merge; see policy below
git switch main && git pull                  # resync
```

## Commit and merge policy

- **Conventional commits** (`feat(scope):`, `fix:`, `docs:`), no AI references. Keep each commit
  focused and reversible.
- **Squash-merge** a feature branch whose intermediate commits are noise → one clean commit on
  `main`. **Merge-commit** a branch whose commits are individually meaningful (per-phase feat +
  docs), to preserve that structure. Never let a branch accumulate so much that neither is clean.
- Delete the branch on merge.

## Pre-merge checklist (self-review)

- [ ] The relevant test suites pass locally, plus the Week-1 regression net.
- [ ] No secret in the diff: `.env`, rendered configs, TLS material, local Python envs, and model
      or corpus caches are gitignored and untracked. (Scan the diff before pushing to a public
      repo.)
- [ ] Docs updated where behaviour/architecture changed; a decision record for durable choices.
- [ ] CodeRabbit findings triaged (fixed or dismissed with a reason).
- [ ] The PR description states what changed, how it was verified, and any disclosed residual.

## Recommended repository settings (not yet applied — propose to enable)

These make the workflow enforced rather than merely intended. They need repo-admin action:

1. **Protect `main`:** require a PR (block direct pushes), require the review/status checks to
   pass, require the branch up to date before merge. (GitHub → Settings → Branches.)
2. **A PR-triggered test workflow.** The existing `security-scan.yml` is deliberately **push-only
   and fork-unsafe-by-design** (no `pull_request`/`pull_request_target`) — see its Week-1
   rationale. A PR test workflow must keep that safety: trigger on `pull_request` from the **same
   repo only**, `permissions: contents: read`, no secrets, run the offline suites (schema,
   RRF-unit, redaction, workflow-safety). Do **not** grant it lake/gateway/DD access — those are
   host-local. Proposed, not added, because touching CI on a public repo deserves explicit sign-off.
3. **A PR template** (`.github/PULL_REQUEST_TEMPLATE.md`) encoding the checklist above.

## Handling the current benchmark WIP

There are uncommitted benchmark changes in `main`'s working tree (a separate track). Recommended:
move them to their own branch so they are neither lost nor accidentally committed into an
unrelated PR:

```
git switch -c feat/benchmark-router-tiers
git add benchmark/ infra/litellm/
git commit -m "feat(benchmark): add router model tiers"
```

Do not stage personal weekly reports (`docs/*_NguyenManhQuy_*`, presentation
scripts, or local-only charters); they are gitignored.

(Left for the owner of that work to run — it is not this workflow doc's to commit.)
