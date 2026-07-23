#!/usr/bin/env bash
# Fail if a credential has leaked out of benchmark/.env into a file that would be
# committed or packed.
#
# `git grep` is not available here: this tree is not a git repository. So the scan
# walks the filesystem over the paths that WOULD be tracked, skipping the ones the
# ignore files exclude.
#
# It searches for the literal values currently configured rather than guessing at
# key shapes: a prefix pattern like `sk-` matches the bearer tokens but not a Postgres
# DSN, and the only authority on what a secret looks like is the secret itself. Values are read from
# the environment, passed to grep through a pipe (never argv, which is world-readable
# via /proc), and never printed — only the offending path and line number are shown.
#
# Usage: set -a; . benchmark/.env; set +a; bash benchmark/scripts/scan-for-secrets.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Every variable whose value must never appear outside benchmark/.env.
SECRET_VARS=(
  ROUTER_API_KEY LITELLM_MASTER_KEY LITELLM_DATABASE_URL DEEPSEEK_API_KEY JUDGE_API_KEY EMBED_API_KEY
  DD_API_KEY DD_APP_KEY SAIST_VIRTUAL_KEY METIS_VIRTUAL_KEY
  V0_RUN1_VIRTUAL_KEY V0_RUN2_VIRTUAL_KEY V0_RUN3_VIRTUAL_KEY
  V0_SOL_RUN1_VIRTUAL_KEY V0_SOL_RUN2_VIRTUAL_KEY V0_SOL_RUN3_VIRTUAL_KEY
  V0_TERRA_RUN1_VIRTUAL_KEY V0_TERRA_RUN2_VIRTUAL_KEY V0_TERRA_RUN3_VIRTUAL_KEY
  V0_GPT55_RUN1_VIRTUAL_KEY V0_GPT55_RUN2_VIRTUAL_KEY V0_GPT55_RUN3_VIRTUAL_KEY
)

patterns=""
armed=0
for var in "${SECRET_VARS[@]}"; do
  value="${!var:-}"
  # Short values are placeholders or non-secret; matching them would flood the scan.
  if [ "${#value}" -ge 12 ]; then
    patterns+="$value"$'\n'
    armed=$((armed + 1))
  fi
done

if [ "$armed" -eq 0 ]; then
  echo "[FAIL] no secret values loaded — source benchmark/.env first, or this scan proves nothing" >&2
  exit 2
fi
echo "[info] scanning for $armed configured secret values (values are never printed)"

# grep reads patterns from a file so one recursive pass covers the whole tree; a
# per-file loop takes minutes here. The file is created 0600 in a private temp dir
# and removed on any exit path.
pattern_file="$(mktemp)"
chmod 600 "$pattern_file"
trap 'rm -f "$pattern_file"' EXIT
printf '%s' "$patterns" > "$pattern_file"

# Excluded: the paths .gitignore/.repomixignore already keep out of version control
# and packaging, plus .env and the key tmp files, which are where these values live.
leaks="$(grep -rF -l -f "$pattern_file" "$REPO_ROOT" \
  --exclude-dir=runs --exclude-dir=results --exclude-dir=tools --exclude-dir=targets \
  --exclude-dir=node_modules --exclude-dir=external --exclude-dir=worktrees \
  --exclude-dir=.git --exclude-dir=__pycache__ --exclude-dir=.venv --exclude-dir=.pytest_cache \
  --exclude='.env' --exclude='*.key.tmp' 2>/dev/null)"

if [ -n "$leaks" ]; then
  echo >&2
  echo "Secret scan FAILED — a configured credential value appears in:" >&2
  printf '%s\n' "$leaks" | sed "s#^$REPO_ROOT/#  [LEAK] #" >&2
  exit 1
fi
echo "Secret scan OK: no configured credential value appears outside benchmark/.env."
