#!/usr/bin/env bash
# Render the Kong declarative policy template into a gitignored, secret-bearing file.
#
# kong.declarative.yml.tmpl is the reviewable source of truth and holds NO secrets;
# this step substitutes the provision key and per-agent client secrets from infra/.env
# into kong.rendered.yml, which the kong-config container imports. The rendered file is
# gitignored and must never be committed.
#
# Only the three ${...} placeholders in the template are substituted (envsubst with an
# explicit allowlist), so a literal ${...} elsewhere in the YAML is left untouched.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ENV_FILE:-$HERE/../.env}"
TMPL="$HERE/kong.declarative.yml.tmpl"
OUT="$HERE/kong.rendered.yml"

[ -f "$TMPL" ] || { echo "FATAL: template not found: $TMPL" >&2; exit 1; }
[ -f "$ENV_FILE" ] || { echo "FATAL: env file not found: $ENV_FILE (copy infra/.env.example)" >&2; exit 1; }

# Load only the Kong secrets, without leaking the whole env into this shell's exports.
set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a

for v in KONG_PROVISION_KEY AGENT_RECON_SECRET PROBE_ADMIN_SECRET; do
  if [ -z "${!v:-}" ]; then
    echo "FATAL: $v is unset or empty in $ENV_FILE" >&2
    exit 2
  fi
done

# Explicit allowlist: substitute exactly these names, nothing else.
envsubst '${KONG_PROVISION_KEY} ${AGENT_RECON_SECRET} ${PROBE_ADMIN_SECRET}' \
  < "$TMPL" > "$OUT"

# A leftover ${UPPER_VAR} means a secret placeholder went unresolved — fail rather
# than import a config with a literal "${SECRET}" as a credential. Match only genuine
# variable placeholders (${ followed by an uppercase letter or underscore), so a
# documentation "${...}" in a comment does not trip the guard.
if grep -qE '\$\{[A-Z_]' "$OUT"; then
  echo "FATAL: unresolved placeholder remains in $OUT" >&2
  grep -nE '\$\{[A-Z_]' "$OUT" >&2
  rm -f "$OUT"
  exit 3
fi

chmod 600 "$OUT"
echo "Rendered $OUT (gitignored, secret-bearing)."
