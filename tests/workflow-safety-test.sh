#!/usr/bin/env bash
# CI workflow safety, enforced so a future edit cannot quietly reopen a hole.
#
# The security-scan workflow runs on a public repo. These assertions are the
# machine-checked version of the review rules: no fork-reachable trigger, no
# unpinned third-party action, least-privilege permissions, no persisted git
# credential, and — the property the whole design rests on — the workflow never
# contacts the lake.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WF="$REPO_ROOT/.github/workflows/security-scan.yml"

PASS=0; FAIL=0
ok()  { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
sect(){ printf '\n== %s ==\n' "$1"; }

[ -f "$WF" ] || { echo "missing $WF" >&2; exit 2; }

sect "no fork-reachable trigger"
# A bare-word check so `pull_request:` OR `pull_request_target:` both trip it,
# anywhere in the file.
for trig in pull_request pull_request_target; do
  if grep -Eq "^[[:space:]]*${trig}:" "$WF"; then
    bad "workflow declares a $trig trigger"
  else
    ok "no $trig trigger"
  fi
done

sect "least-privilege permissions"
grep -Eq '^permissions:' "$WF" && ok "permissions block present" || bad "no permissions block (defaults to write)"
grep -Eq '^[[:space:]]*contents:[[:space:]]*read' "$WF" && ok "contents: read" || bad "contents is not read-only"
# Nothing should grant a write scope or an id-token.
if grep -Eq '(contents|packages|id-token|actions|deployments):[[:space:]]*write' "$WF"; then
  bad "a write permission is granted"
else
  ok "no write permission granted"
fi

sect "third-party actions are pinned to a full commit SHA"
# Every `uses:` that names an owner/repo must pin a 40-hex SHA, never a tag.
unpinned=0; nactions=0
while IFS= read -r line; do
  nactions=$((nactions+1))
  ref="${line##*@}"; ref="${ref%%#*}"; ref="$(printf '%s' "$ref" | tr -d '[:space:]')"
  if printf '%s' "$ref" | grep -Eq '^[0-9a-f]{40}$'; then :; else
    bad "action not SHA-pinned: $ref"; unpinned=1
  fi
done < <(grep -E '^[[:space:]]*uses:[[:space:]]*[^[:space:]]+/[^[:space:]]+@' "$WF")
[ "$nactions" -gt 0 ] || bad "no third-party actions found to check (unexpected)"
[ "$unpinned" -eq 0 ] && [ "$nactions" -gt 0 ] && ok "all $nactions action(s) SHA-pinned"

sect "checkout does not persist credentials"
grep -Eq 'persist-credentials:[[:space:]]*false' "$WF" && ok "persist-credentials: false" || bad "checkout may leave a token in .git/config"

sect "the workflow never contacts the lake"
# Examine EXECUTABLE content only: a comment may say "never touches DefectDojo",
# but no run step or field may reference the importer, the lake host/port, the API
# path, the token, or the reimport endpoint. Strip whole-line and inline comments
# first (the workflow quotes no '#').
EXEC="$(sed 's/#.*//' "$WF")"
for forbidden in "import-report.sh" "scan-and-import.sh" "defectdojo" "dd_api_token" "api/v2" "reimport-scan" ":8080" ":55433"; do
  if printf '%s' "$EXEC" | grep -qi "$forbidden"; then
    bad "workflow references '$forbidden' in executable content — it must not touch DefectDojo"
  else
    ok "no executable reference to '$forbidden'"
  fi
done

sect "only redacted reports are uploaded"
# Raw reports legitimately appear as redaction INPUTS in the run steps; what must
# never happen is a raw report in the upload artifact. Isolate the upload-artifact
# step and check only its path list.
upload_block="$(awk '/uses:[[:space:]]*actions\/upload-artifact/{f=1} f{print}' "$WF")"
if printf '%s' "$upload_block" | grep -qE '\.raw\.(json|xml|jsonl)'; then
  bad "a raw (unredacted) report is in the upload artifact"
else
  ok "the upload artifact lists no raw report"
fi
if printf '%s' "$upload_block" | grep -qE '\.san\.(json|xml|jsonl)'; then
  ok "the upload artifact lists redacted (.san) reports"
else
  bad "the upload artifact lists no redacted report"
fi

printf '\n== summary ==\n  %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
