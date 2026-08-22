# Sentinel Charter demo talk track (10–15 minutes)

Seven required scenes for the six-week Charter demo. Commands below are
copied from the scripts; do not invent flags. This is **not** a live
acceptance claim. The operator-gated live path is
[`sentinel-live-acceptance-runbook.md`](sentinel-live-acceptance-runbook.md).

**Clock:** 12 minutes if the Week-5 facade is already up; 15 minutes if you
start topology + facade in the first minute.

**Defaults**

| Item | Value |
|---|---|
| Repo root | run every command from the repository root |
| Python | `.venv/bin/python` (grader venv). `scripts/sentinel-demo.sh` itself defaults to `rag/.venv/bin/python`; override with `SENTINEL_PYTHON=.venv/bin/python` if that is the venv you built |
| Week-5 facade | `http://127.0.0.1:18055` only |
| Target (live only) | `http://127.0.0.1:13000` behind Kong `127.0.0.1:18443` |

`scripts/sentinel-demo.sh` usage (no `--help` flag; unknown verbs print this and exit 2):

```text
sentinel-demo.sh run --profile charter --run-id ID
                 resume ID
                 recover-audit ID
                 verify ID
                 --teardown ID
```

Optional on `run` / `resume` only: `--artifact-input PATH --artifact-sha256 SHA` (CI Trivy handoff).

---

## 0. Start surfaces (~1 min)

**Live topology (optional; not a Charter run):**

```bash
bash scripts/sentinel-charter-up.sh
scripts/sentinel-live-preflight.sh base
```

Expected: launcher prints `Charter topology start requested; this is not a Charter run.`
Preflight prints `PASS …` lines and `READY_FOR_FRESH_PROPOSAL`, or `BLOCK …`.

**Week-5 loopback facade (required for scenes 4-offline, 6, 7):**

```bash
docker compose -f infra/week5-demo/docker-compose.yml up --build -d --wait
```

If Docker is not used, one process (do not run this at the same time as the
compose service; both bind `127.0.0.1:18055`):

```bash
PYTHONPATH=. .venv/bin/python scripts/sentinel-week5-demo.py
```

Optional flags on that script: `--bind 127.0.0.1` (default) and `--port 18055` (default).

Expected: `GET http://127.0.0.1:18055/health` returns `{"ok": true}` (see `scripts/week5-demo-curl.sh`).

---

## 1. Scan run (~2 min)

**Live controller** (needs preflight READY; pauses later at HITL):

```bash
SENTINEL_PYTHON=.venv/bin/python bash scripts/sentinel-demo.sh run --profile charter --run-id demo
```

Expected: stages include `scan-redact-import` then `analysis-report` then `proposal`.
When `SENTINEL_CHARTER_APPROVAL_FILE` / `SENTINEL_CHARTER_PUBLIC_KEY` are unset, process exit of `sentinel-demo.sh run`/`resume` is **75** — that is the HITL pause, not a crash. **76** is only the internal approval-stage return; it is remapped to 75. Artifacts land under `${SENTINEL_RUNS_DIR:-.sentinel-runs}/demo/` (`normalized.jsonl`, `report.jsonl`, `request-spec.json`, `manifest.json`).

**Offline / no topology** (still a real scanner command; no Juice Shop required):

```bash
command -v jq >/dev/null
workspace="$(mktemp -d)"
source scanners/image-pins.env
export IMAGE="$JUICE_SHOP_IMAGE" TRIVY_SCANNERS="secret,misconfig"
./scanners/run-trivy.sh "$workspace/trivy.raw.json"
./scanners/redact-report.sh trivy "$workspace/trivy.raw.json" /tmp/trivy.sanitized.json
```

Expected: a sanitized JSON report path printed; raw file is not the thing you show.

---

## 2. Agent report (~1.5 min)

**Live:** after scene 1, show the private report:

```bash
python3 -c 'import json,pathlib,os; p=pathlib.Path(os.environ.get("SENTINEL_RUNS_DIR",".sentinel-runs"))/"demo"/"report.jsonl";
print(p); [print(json.dumps(json.loads(l), indent=2)[:400]) for l in p.read_text().splitlines()[:1]]'
```

Expected: JSONL rows with typed finding id, name, severity, location, scanner evidence, explanation, remediation, confidence. No invented endpoints.

**Offline fallback** (committed sample, not a live Juice Shop report):

```bash
.venv/bin/python -c 'from pathlib import Path; p=Path("docs/reports/artifacts/week3-sample-report.jsonl"); print(p.read_text()[:500])'
```

Expected: `schema_version` `week3-analysis/v1`, three grouped findings (nuclei / trivy / semgrep).

---

## 3. Agent proposes a request (~1.5 min)

**Live:** the `proposal` stage of the same `sentinel-demo.sh run` writes `request-spec.json`.

```bash
python3 -c 'import json,os,pathlib; p=pathlib.Path(os.environ.get("SENTINEL_RUNS_DIR",".sentinel-runs"))/"demo"/"request-spec.json"; print(p.read_text())'
```

Expected: one catalog case only (`method`, `path`, `query` or `body`, `purpose`). Not a free-form URL.

**Offline:** Week-5 facade preview of the POST catalog case (does not send):

```bash
curl -fsS -H 'Content-Type: application/json' \
  -d '{"case_id":"post-empty-object"}' \
  http://127.0.0.1:18055/demo/hitl/preview
```

Expected: `"method":"POST"`, `"path":"/sentinel-charter/rest/basket"`, `"body":"{}"`, `"purpose"` present, `"sent":false`.

---

## 4. HITL approve / reject (~2.5 min)

### 4a. Real Charter signer (shows endpoint, payload, purpose)

```bash
.venv/bin/python scripts/sentinel-charter-approve.py \
  "${SENTINEL_RUNS_DIR:-.sentinel-runs}/demo/request-spec.json" \
  --key-file "$HOME/.sentinel/charter-approval.ed25519.pem" \
  --out /tmp/charter-decision.json
```

Non-interactive reject (same display, then writes a reject envelope):

```bash
.venv/bin/python scripts/sentinel-charter-approve.py \
  "${SENTINEL_RUNS_DIR:-.sentinel-runs}/demo/request-spec.json" \
  --key-file "$HOME/.sentinel/charter-approval.ed25519.pem" \
  --decision reject \
  --out /tmp/charter-decision.json
```

`--decision` is only `approve`, `reject`, or `revoke`. `--key-file` and `--out` are required. `--out` must not already exist (O_EXCL).

Expected stdout, in this order:

```text
Request <uuid>
  <METHOD> <path>?<query>
  body: '...'
  purpose: ...
  expiry: ...
  immutable digest: ...
Approve this fixed request? [y/N]
```

Interactive default without `--decision`: `n` / empty → reject. Resume a reject (zero send):

```bash
SENTINEL_PYTHON=.venv/bin/python \
SENTINEL_CHARTER_APPROVAL_FILE=/tmp/charter-decision.json \
SENTINEL_CHARTER_PUBLIC_KEY="$HOME/.sentinel/charter-approval.ed25519.pub.pem" \
  bash scripts/sentinel-demo.sh resume demo
```

Expected: stage `approval` records rejected; `request.json` has `action_sent: false`; no `receipt.json`.

### 4b. Always-available reject (facade never talks to Kong)

```bash
curl -fsS -H 'Content-Type: application/json' \
  -d '{"case_id":"post-empty-object","decision":"reject"}' \
  http://127.0.0.1:18055/demo/hitl/decide
```

Expected: `"decision":"reject"`, `"sent":false`. Even `"decision":"approve"` on this facade stays `"sent":false`.

---

## 5. Request via Kong gateway (~2 min)

Only after a **fresh** `--decision approve` envelope and
`scripts/sentinel-live-preflight.sh dispatch demo` reporting
`READY_FOR_APPROVED_DISPATCH`.

Controller path (preferred; adapter holds the secrets, not the shell):

```bash
scripts/sentinel-live-preflight.sh dispatch demo
SENTINEL_PYTHON=.venv/bin/python \
SENTINEL_CHARTER_APPROVAL_FILE=/tmp/charter-decision.json \
SENTINEL_CHARTER_PUBLIC_KEY="$HOME/.sentinel/charter-approval.ed25519.pub.pem" \
  bash scripts/sentinel-demo.sh resume demo
```

Expected: `executor` then `response-guard`; `receipt.json` appears; `request.json` has `action_sent: true` and `request_count: 1`. GET receipts are v2 preview-only; POST is a 4xx non-mutation receipt. Do not paste Kong logs or raw bodies.

Direct executor (same argv the adapter uses; **do not** export these secrets into the controller shell):

```bash
.venv/bin/python scripts/sentinel-charter-executor.py \
  "${SENTINEL_RUNS_DIR:-.sentinel-runs}/demo/request-spec.json" \
  /tmp/charter-decision.json \
  --state "${SENTINEL_RUNS_DIR:-.sentinel-runs}/demo/executor-state.sqlite" \
  --public-key "$HOME/.sentinel/charter-approval.ed25519.pub.pem"
```

Required env in **that** process only: `SENTINEL_CHARTER_EXECUTOR_SECRET`, `SENTINEL_CHARTER_EXECUTOR_API_KEY`. Missing either prints `{"refused":"executor-credential-required"}` and exits 2. Reject/revoke envelopes refuse before any mint.

If keys or Kong are absent, say so and show scene 4b (`sent: false`) instead of faking a gateway call.

---

## 6. Prompt injection blocked (~1.5 min)

```bash
curl -fsS -H 'Content-Type: application/json' \
  -d '{"fixture":"goal"}' \
  http://127.0.0.1:18055/demo/ipi
```

Expected: `"status":"quarantined"`, `"sent":false`, reason includes `objective-change`. Fixture file: `tests/fixtures/charter-response-ipi-goal.json`.

Second fixture (secrets / tool-call):

```bash
curl -fsS -H 'Content-Type: application/json' \
  -d '{"fixture":"secrets"}' \
  http://127.0.0.1:18055/demo/ipi
```

Expected: `"status":"quarantined"`, `"sent":false`.

Packaged three-scene check (health + IPI + PII + HITL reject):

```bash
bash scripts/week5-demo-curl.sh
```

Expected lines: `ipi quarantined`, `pii redacted`, `hitl preview …`, `hitl reject not_sent`.

---

## 7. PII masked (~1.5 min)

```bash
curl -fsS -H 'Content-Type: application/json' \
  -d '{"text":"user_phone=+12025550143"}' \
  http://127.0.0.1:18055/demo/pii
```

Expected: `"sent":false`; `+12025550143` absent from `"redacted"`; a finding with `"cls":"phone"`.

Offline unit check (no server):

```bash
PYTHONPATH=. .venv/bin/python -c "from agent.pii import redact; print(redact('user_phone=+12025550143')[0])"
```

Expected: placeholder `[redacted:pii:phone]`, not the number.

---

## Close (~0.5 min)

| If you ran | Show |
|---|---|
| Live `run` + reject resume | `manifest.json` `result.status=rejected`, `metrics.request_count=0` |
| Live approve + dispatch | `bash scripts/sentinel-demo.sh verify demo` (needs the private evaluator artifact) |
| Offline only | `evaluation/charter-eval/charter-evaluation.json` is a **sample / dry-run** scorecard (`live_run: false`), not this demo's live FP/FN |

Do not print `infra/.env`, API keys, approval private keys, or raw target bodies.

**Stop the facade when done** (only if you started it):

```bash
docker compose -f infra/week5-demo/docker-compose.yml down
```

or Ctrl-C the `sentinel-week5-demo.py` process. Live topology teardown is
`bash scripts/sentinel-demo.sh --teardown demo` for that run id only — it does
not stop Kong / Juice Shop.
