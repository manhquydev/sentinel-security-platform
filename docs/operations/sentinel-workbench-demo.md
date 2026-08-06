# Sentinel Workbench demo

Local fixture/safety surface only. Not a baseline scan, AI efficacy result, or
security finding.

## Run

```bash
# Fixture acceptance (pytest + isolation + artifact guard)
bash scripts/workbench-acceptance.sh

# Loopback browser + host broker + private worker
bash scripts/workbench-up.sh
```

`workbench-up` prints a URL on `http://127.0.0.1:4173/` with a one-time
`#startup_capability=…` fragment. The browser clears the fragment before network
activity, posts the capability only in the bootstrap body to the exact-origin
host broker (`http://127.0.0.1:4174`), and can submit the metadata-only fixture
readiness command.

## What the safe readiness check proves

The check is **containment and workflow**, not analysis:

- Profile is fixture-transport-only (`workbench/fixture_transport.py`).
- The private worker refuses the fixture transport command before any source
  scan (`workbench/worker_service.py`).
- Compose UI has no Docker socket, no evidence mount, and no B3 credentials.

Do not read a refused readiness check as a scanner finding or as proof that B0
engines lack image/policy pins. Engine capability preflight is separate — see
[workbench-scanner-viability.md](./workbench-scanner-viability.md). Preflight
`ready` means image pin + frozen policy only; it is not a completed B0 scan and
does not admit a corpus.

## CMC

The CMC card stays disabled unless the immutable CMC value gate is `passed`.
CMC inventory or a local transport smoke receipt is never an AI-efficacy or
Sentinel capstone claim. Public claim language requirements:
[sentinel-workbench-claim-checklist.md](./sentinel-workbench-claim-checklist.md).
