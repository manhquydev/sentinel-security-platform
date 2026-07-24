#!/usr/bin/env bash
# Week-4 recon tools contract (lake reader + gateway probe). Live-gated: skips if the stacks are
# down, unless REQUIRE_AGENT=1. These prove the two facts the tools are built around actually
# hold against the running system — the scanner filter really filters, and the gateway identity
# really is scoped.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$REPO_ROOT/rag/.venv/bin/python"
ENV_FILE="${ENV_FILE:-$REPO_ROOT/infra/.env}"
REQUIRE_AGENT="${REQUIRE_AGENT:-0}"

PASS=0; FAIL=0; SKIP=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
skip() { printf '  \033[33mSKIP\033[0m %s\n' "$1"; SKIP=$((SKIP+1)); }
sect() { printf '\n== %s ==\n' "$1"; }

[ -x "$PY" ] || { echo "missing venv at $PY"; exit 2; }
cd "$REPO_ROOT" || { echo "cannot cd to $REPO_ROOT"; exit 2; }
[ -f "$ENV_FILE" ] && { set -a; . "$ENV_FILE"; set +a; }
run_py() { "$PY" - "$@"; }

sect "lake reader (read-only DefectDojo)"
if [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 4 "${DD_URL:-http://localhost:8080}/api/v2/" 2>/dev/null)" = "000" ]; then
  m="DefectDojo not reachable"; [ "$REQUIRE_AGENT" = 1 ] && bad "$m" || skip "$m"
else
  # The scanner filter must actually filter: Nuclei count must be the DAST baseline (21), not the
  # whole lake (36) — the bug that returns everything when the filter is ignored.
  if run_py <<'PY'
import sys
from agent.lake import Lake
lk = Lake()
nuclei = lk.findings("juice-shop-harness", "Nuclei Scan")
trivy  = lk.findings("juice-shop-harness", "Trivy Scan")
semgrep = lk.findings("webgoat", "Semgrep JSON Report")
print(f"  nuclei={len(nuclei)} trivy={len(trivy)} semgrep={len(semgrep)} endpoints={len(lk._load_endpoints())}")
# Baselines from the lake: Nuclei 21 (DAST), Trivy 4 (SCA), Semgrep 11 (SAST).
ok = len(nuclei) == 21 and len(trivy) == 4 and len(semgrep) == 11
# SAST/SCA findings locate via file_path (reliable). The canonical DAST endpoint surface is
# discoverable via the endpoint list, even though DefectDojo's endpoint dedup leaves Nuclei
# per-finding endpoint refs pointing at merged-away ids (a documented data quirk, not a bug here).
ok = ok and any(f.file_path for f in semgrep) and any(f.file_path for f in trivy)
ok = ok and len(lk._load_endpoints()) >= 4
sys.exit(0 if ok else 1)
PY
  then ok "scanner filter is real (21/4/11) with reliable locators + discoverable DAST surface"
  else bad "lake counts/locators wrong (filter ignored?)"; fi

  # Read-only identity: the service account cannot delete (decision 0004).
  if run_py <<'PY'
import sys, requests
from agent.lake import Lake
lk = Lake(); tok = lk._auth()
r = requests.delete(f"{lk.url}/api/v2/findings/99999/", headers={"Authorization": f"Token {tok}"}, timeout=10)
sys.exit(0 if r.status_code in (403, 404, 405) else 1)  # never 204/200
PY
  then ok "lake identity is read-only (delete refused)"; else bad "lake identity could delete"; fi
fi

sect "gateway probe (agent-recon identity)"
if [ -z "${AGENT_RECON_SECRET:-}" ] || [ "$(curl -sk -o /dev/null -w '%{http_code}' --max-time 4 "${KONG_PROXY:-https://127.0.0.1:18443}/rest/products/search?q=x" 2>/dev/null)" = "000" ]; then
  m="gateway not reachable / no secret"; [ "$REQUIRE_AGENT" = 1 ] && bad "$m" || skip "$m"
else
  if run_py <<'PY'
import sys
from agent.gateway import Gateway
gw = Gateway()
pub, _ = gw.get("/rest/products/search?q=apple")
adm, _ = gw.get("/rest/admin/application-version")
print(f"  public={pub} admin={adm}")
# The agent inherits agent-recon's scope: public read allowed, admin refused.
sys.exit(0 if (pub == 200 and adm == 403) else 1)
PY
  then ok "gateway probe: public read 200, admin 403 (scope inherited from agent-recon)"
  else bad "gateway probe scope wrong"; fi
fi

printf '\n%d passed, %d failed, %d skipped\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" -eq 0 ]
