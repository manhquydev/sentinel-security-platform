#!/usr/bin/env bash
# Same-controller charter E2E harness. Offline mode proves control flow only.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.."&&pwd)"; DEMO="$ROOT/scripts/sentinel-demo.sh"
if [ "${REQUIRE_SENTINEL_LIVE:-0}" = 1 ]; then
  [ -n "${SENTINEL_LITELLM_ALIAS:-}" ] && [ -n "${LITELLM_MASTER_KEY:-}" ] && [ -n "${SENTINEL_STAGE_ADAPTER:-}" ] || { echo 'required live Sentinel prerequisites missing' >&2; exit 1; }
fi
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
a="$d/a"; cat >"$a" <<'EOF'
#!/usr/bin/env bash
set -eu
printf '%s\n' "$1" >>"$SENTINEL_E2E_LOG"
[ "${SENTINEL_E2E_FAIL:-}" != "$1" ] || { echo failed; exit 0; }
if [ "$1" = analysis-report ]; then
  umask 077
  printf '%s\n' '{"schema_version":"1.0","finding_id":"finding:charter-nuclei-header","source_ids":["nuclei:one"],"tool":"nuclei","scanner":"DAST","title":"Missing content security policy","severity":"Low","location":"http://127.0.0.1:13000/rest/products","evidence":["template-id=header"]}' >"$2/normalized.jsonl"
  printf '%s\n' '{"schema_version":"1.0","finding_id":"finding:charter-trivy-secret","source_ids":["trivy:one"],"tool":"trivy","scanner":"SAST","title":"Generic API key","severity":"High","location":"file:package-lock.json","evidence":["rule-id=generic-api-key"]}' >>"$2/normalized.jsonl"
  printf '%s\n' '{"schema_version":"1.0","finding_id":"finding:charter-nuclei-header","name":"Missing content security policy","severity":"Low","location":"http://127.0.0.1:13000/rest/products","scanner_evidence":["template-id=header"],"explanation":"Scanner observed a missing header.","remediation":"Set the documented header.","confidence":"high","source_ids":["nuclei:one"],"knowledge_provenance":["owasp:headers"]}' >"$2/report.jsonl"
  chmod 600 "$2/normalized.jsonl" "$2/report.jsonl"
fi
echo passed
EOF
chmod +x "$a"
SENTINEL_RUNS_DIR="$d/runs" SENTINEL_STAGE_ADAPTER="$a" SENTINEL_E2E_LOG="$d/log" "$DEMO" run --profile charter --run-id e2e
SENTINEL_RUNS_DIR="$d/runs" "$DEMO" verify e2e
rm -f "$d/log"
if SENTINEL_E2E_FAIL=analysis-report SENTINEL_RUNS_DIR="$d/runs" SENTINEL_STAGE_ADAPTER="$a" SENTINEL_E2E_LOG="$d/log" "$DEMO" run --profile charter --run-id failed; then exit 1; fi
grep -q '^analysis-report$' "$d/log" && ! grep -q '^proposal$' "$d/log"
