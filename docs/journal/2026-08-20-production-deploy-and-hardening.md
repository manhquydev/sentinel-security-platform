# 2026-08-20 — Charter goes to production, and the lab audits its own cloud

Took Charter from "verified locally" to a live GCP deployment, populated the
gated app with real findings, then let independent agents red-team it and fixed
what they found. Coordinated as a lead over parallel omp workers (herdr), with
`kongming` advising at each high-stakes fork.

## What shipped

- **Completion closure (Wave 1):** committed the Week-2 aggregate artifact
  (`artifacts/week1.aggregate.jsonl`, 36 records, sha256 `d7717e70…` matching
  week-02), restored the root README fresh-clone reproducibility block (test 50/0),
  added `finding_count` to RunMetrics, a dry-run FP/FN scorecard, and a 10–15 min
  demo runbook.
- **Deep verification:** slim grader **338 passed**; the grader-excluded Charter
  suite is **140 passed** once optional deps are present — no hidden defects, only
  missing packages. Documented as `requirements-full.txt` + `full-test-suite.md`
  without touching the slim grader contract.
- **Production (GCP VM):** authored `infra/gcp/` deploy kit and stood up the full
  compose topology on `sentinel-charter` (e2-standard-4). Docs on
  `vinsoc.manhquy.io.vn`; gated app on `app.vinsoc.manhquy.io.vn`
  (Cloudflare Tunnel → DefectDojo, Cloudflare Access in front). Imported 5 real
  findings (Trivy secret/misconfig + Nuclei header) into the live DefectDojo.
- **Independent production test (clean-scope agents):** external, VM-runtime, and
  red-team passes all confirmed the posture — "Juice Shop from the public
  internet: NO." App ports closed, SSH IAP-only, loopback-only binds, grader
  ritual reproduced on the VM (102 passed).

## Lessons worth keeping

- **The honest failure was the best artifact.** The live LLM scorecard would not
  produce a clean run: Vertex flash-lite ignores the strict `response_format`
  json_schema, and OpenAI models free-form triage prose that the `_confidence`
  validator refuses. That fail-closed refusal — the agent declining to publish
  unconstrained model output — is a stronger security story than a coerced green
  number. We captured the exact rejected output and stopped; we did not weaken the
  validator.
- **The red-team corrected the cloud, not the code.** Independent audit found the
  one real gap: the default compute SA carried `cloud-platform`, and the
  deliberately-vulnerable Juice Shop container could mint a project-wide token from
  the metadata server. Fix, defense-in-depth, B-then-A: a `DOCKER-USER` iptables
  DROP to `169.254.169.254` (no downtime), then `--no-service-account` at the VM
  (host metadata token → 404), persisted via a `sentinel-metadata-guard` systemd
  unit, and defaulted safe in the kit.
- **`unless-stopped` is what made the root fix cheap.** Removing the SA needs a
  stop/start; because every container is `unless-stopped`, the topology
  auto-resumed and the "Kong must be fresh" launcher gate never triggered.
- **Two mistaken "gaps" were retired by evidence.** "Raw scan committed" was false
  (`scanners/out/` is gitignored, `git ls-files` empty); the `artifacts/README`
  claiming the aggregate "not present yet" was stale the moment the files landed —
  both corrected.

## State after this session

Charter meets every minimum-to-pass and exceeds; live on GCP with a gated,
populated DefectDojo; independently red-teamed; secrets never in git. Standing
follow-ups: a live `live_run:true` scorecard needs a model that honors the closed
enrichment schema (model↔contract fork, not a validator weakening); the VM bills
until teardown; the maintainer must rotate the Cloudflare/R2 credentials shared
in-session.
