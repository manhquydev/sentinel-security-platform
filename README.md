# Project Sentinel

Sentinel is a research/education capstone for **safe, evidence-bound web
application security analysis in a local lab**. Its current published product
authority is the [charter brief](docs/product/sentinel-charter-brief.md); the
as-built map is
[sentinel-six-week-as-built-architecture](docs/sentinel-six-week-as-built-architecture.md).

The charter's flow is: scan a deliberately vulnerable local target, normalize
and redact findings, retrieve security context, produce a grounded report, then
propose a tightly bounded test request. A human approval and the Kong gateway
are required before the only permitted write proof. Sentinel is not an
autonomous exploitation tool or a product for external targets.

## Two products (do not mix evidence)

| Surface | What it is | What it is not |
|---|---|---|
| **Charter** | Six-week Juice Shop loopback lab: scan → redact → grounded report → signed HITL → one catalog request through Kong | Not the Workbench, not an external-target product |
| **Workbench** | Separate local research UI/broker for fixture readiness and future comparative corpus work | Not Charter completion, not Charter approval/audit evidence |

- Charter product: [charter brief](docs/product/sentinel-charter-brief.md)
- Workbench product: [workbench brief](docs/product/sentinel-security-research-workbench.md)
- Live Charter operator procedure: [live acceptance runbook](docs/operations/sentinel-live-acceptance-runbook.md)
- Workbench demo surface: [workbench demo](docs/operations/sentinel-workbench-demo.md)
- Weekly mentor reports: [docs/reports](docs/reports/index.md) (Starlight site in [`website/`](website/README.md))

Pinned scanner/harness image digests live in committed
[`scanners/image-pins.env`](scanners/image-pins.env) (public tags only; no secrets).

## Charter boundary

- **Target:** the literal local Juice Shop sandbox at `http://127.0.0.1:13000`;
  redirects and external targets are refused.
- **Safety:** scanner output is redacted before storage; target-derived content
  is treated as untrusted; request approval and gateway controls fail closed;
  detected PII and prompt-injection content are quarantined. The executable
  owners are [scanners](scanners/README.md),
  [Kong](infra/kong/README.md), and the [charter scripts](scripts/sentinel-demo.sh).
- **Allowed active requests:** the executor accepts only a compiled catalog of
  six predeclared cases through Kong: baseline, empty, special-character, and
  256-character product-search queries; plus empty-object and wrong-type basket
  POST bodies. It never accepts arbitrary paths, headers, or payloads. The POST
  cases are signed-HITL and must return `4xx`, proving a non-mutating boundary.
  Real exploitation, successful data mutation, and generic Internet-target
  support are out of scope.
- **Not six-week requirements:** the historical Week 7–12 research and optional
  extensions (multi-agent work, GraphRAG, MCP/A2A, vLLM/GPU, and LLM-as-a-Judge)
  are not current completion requirements.

## Current maturity

The completed [charter closure record](docs/plans/completed/2026-08-04-sentinel-charter-literal-closure.md)
is the evidence ledger. Charter minimum is met by offline contracts **and** a
fresh bounded local live run (`charter-live-260804-local-003`: scan → report →
signed approval → one catalog GET through Kong → evaluation, with correlated
Kong audit). Historical R5 remains non-resumable under v2 policy. Offline
audit-only recovery is intentionally not live acceptance.

Workbench is a **separate** product: fixture/safety and host-local corpus prep
only until an admitted TypeScript corpus and B3 calibration exist. See the
[workbench brief](docs/product/sentinel-security-research-workbench.md).

## Start from the owning entry point

### Charter (live path)

| Need | Entry point |
|---|---|
| Product contract | [Charter brief](docs/product/sentinel-charter-brief.md), [as-built architecture](docs/sentinel-six-week-as-built-architecture.md) |
| Operator live acceptance procedure | [Live acceptance runbook](docs/operations/sentinel-live-acceptance-runbook.md) |
| No-secret readiness (`base` / `dispatch RUN_ID`) | [`scripts/sentinel-live-preflight.sh`](scripts/sentinel-live-preflight.sh) |
| Bring up existing local topology | [`scripts/sentinel-charter-up.sh`](scripts/sentinel-charter-up.sh) — Compose startup only, not a Charter run |
| Run, resume, recover-audit, or verify | [`scripts/sentinel-demo.sh`](scripts/sentinel-demo.sh) — `run`/`resume` need private credentials and approval material; `verify` checks a passed terminal run |

### Workbench (separate surface)

| Need | Entry point |
|---|---|
| Product boundary and evidence state | [Workbench brief](docs/product/sentinel-security-research-workbench.md) |
| Loopback browser + host broker | [`scripts/workbench-up.sh`](scripts/workbench-up.sh) — prints a one-time fragment capability |
| Fixture-only scanner capability status | [`scripts/workbench-scanner-preflight.sh`](scripts/workbench-scanner-preflight.sh) `--fixture-profile typescript` |
| Host-local OpenSSF corpus cache (no admission) | [`scripts/workbench-corpus-acquire.py`](scripts/workbench-corpus-acquire.py) |
| Candidate inventory from that cache | [`scripts/workbench-corpus-inventory.py`](scripts/workbench-corpus-inventory.py) |
| Demo / acceptance notes | [Workbench demo](docs/operations/sentinel-workbench-demo.md), [scanner viability](docs/operations/workbench-scanner-viability.md) |

### Shared lab surfaces

| Need | Entry point |
|---|---|
| Image digest pins (reviewable, no secrets) | [`scanners/image-pins.env`](scanners/image-pins.env) |
| Scanner, redaction, and lake import | [Scanner guide](scanners/README.md) and [DefectDojo guide](infra/defectdojo/README.md) |
| RAG corpus/retrieval contract or live store | [RAG guide](rag/README.md), [`tests/run-charter-rag-contract.sh`](tests/run-charter-rag-contract.sh), and [`tests/rag-retrieval-test.sh`](tests/rag-retrieval-test.sh) |
| Project documentation and active work | [Documentation map](docs/README.md) and [active plans](docs/plans/active/) |

## Fresh-clone scan-to-redaction (no secrets)

Run this from the repository root. This narrow local proof needs Docker daemon and
socket access, `jq`, and public pinned images available to Docker. It needs no DefectDojo credentials, instance, or target-app service. It scans the digest-pinned Juice Shop image and produces a sanitized local report; it does not import findings or verify the lake.

```bash
(
  set -euo pipefail
  command -v jq >/dev/null || { echo "jq is required for redaction" >&2; exit 1; }
  workspace="$(mktemp -d)"
  trap 'rm -rf "$workspace"' EXIT
  source scanners/image-pins.env
  export IMAGE="$JUICE_SHOP_IMAGE" TRIVY_SCANNERS="secret,misconfig"
  sanitized_report="$(mktemp -t trivy.sanitized.XXXXXX.json)"
  ./scanners/run-trivy.sh "$workspace/trivy.raw.json"
  ./scanners/redact-report.sh trivy "$workspace/trivy.raw.json" "$sanitized_report"
  rm -rf "$workspace"
  trap - EXIT
  printf 'sanitized report: %s\n' "$sanitized_report"
)
```

`TRIVY_SCANNERS=secret,misconfig` avoids the vulnerability-database download.
The private raw workspace is removed immediately after redaction and on failure.

## Provisioned DefectDojo import and verification

DefectDojo import and `verify-lake.sh` are **provisioned** operations: use the
[DefectDojo guide](infra/defectdojo/README.md) and its service credentials. This does not reproduce the historical baseline from a fresh clone, because that baseline includes inputs the no-secret quick-start does not provision.

The RAG store's [Compose definition](infra/rag-store/docker-compose.yml) mounts
the tracked `infra/rag-store/schema.sql` source into PostgreSQL's
first-initialization hook. A fresh clone can therefore initialize an empty
`rag-db` volume from the committed schema. This applies only to an empty data
volume and is not a schema-migration mechanism. Use the [RAG guide](rag/README.md)
for the separate hermetic corpus contract and live-store prerequisites.

## Documentation and history

Use [docs/README.md](docs/README.md) to navigate current product, decisions, and
plans. Historical research and the former twelve-week programme are context, not
the current six-week product contract; do not use them to infer completion.
