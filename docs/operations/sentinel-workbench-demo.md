# Sentinel Workbench demo

Run `bash scripts/workbench-acceptance.sh` for the local fixture proof, then
`bash scripts/workbench-up.sh` for the loopback browser surface.

The URL printed by `workbench-up` contains a one-time fragment capability. The
browser clears it before network activity, creates an exact-origin host-broker
session, and can run the safe fixture readiness check. At the current
`not-ready` scanner policy, that check must end as a refusal before any source
scan. It demonstrates containment and workflow only; it is not a baseline
scan, AI result, or security finding.

The CMC card stays disabled unless the immutable CMC value gate is `passed`.
CMC inventory or a local transport smoke receipt is never an AI-efficacy or
Sentinel capstone claim.
