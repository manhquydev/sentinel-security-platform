# Project Sentinel

Sentinel is a research/education capstone for **safe, evidence-bound web
application security analysis in a local lab**. Its current product authority is
the [six-week charter](docs/Project_Sentinel_6-week.md); the concise product
description is the [charter brief](docs/product/sentinel-charter-brief.md).

The charter's flow is: scan a deliberately vulnerable local target, normalize
and redact findings, retrieve security context, produce a grounded report, then
propose a tightly bounded test request. A human approval and the Kong gateway
are required before the only permitted write proof. Sentinel is not an
autonomous exploitation tool or a product for external targets.

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
is the current evidence ledger.

- Offline component, controller, recovery, evaluation, and no-secret CI-handoff
  contracts have been exercised; those are **not** live-service or full-charter
  proof.
- A credentialed structured-output path and a historical literal-origin run have
  reached scan, no-close import, grounded analysis, and a fixed request proposal.
  That run stopped at approval. Its R5 request artifact is expired and invalid
  under the current v2 policy, so it is non-resumable and cannot be backfilled.
- A fresh bounded v2 run completed scan, normalization, grounded analysis,
  signed approval, one catalog request through Kong, response quarantine,
  final report, and current-run evaluation. Its private local artifacts and
  correlated Kong audit record are summarized in the
  [charter closure record](docs/plans/completed/2026-08-04-sentinel-charter-literal-closure.md).
  Offline audit-only recovery remains intentionally insufficient for live
  acceptance.

## Start from the owning entry point

| Need | Entry point |
|---|---|
| Product contract and six-week deliverables | [Six-week charter](docs/Project_Sentinel_6-week.md) and [charter brief](docs/product/sentinel-charter-brief.md) |
| Bring up the existing local topology | [`scripts/sentinel-charter-up.sh`](scripts/sentinel-charter-up.sh) — prerequisite/startup contract only, not a Charter run |
| Run, resume, or verify a Charter profile | [`scripts/sentinel-demo.sh`](scripts/sentinel-demo.sh) — `run`/`resume` validate private credential and approval prerequisites; `verify` checks an existing passed terminal run |
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
