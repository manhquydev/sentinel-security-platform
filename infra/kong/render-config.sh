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
# Tests and isolated operators may select an explicit output; the default stays the deployment
# artifact. Never infer an output from an input/environment secret.
OUT="${OUT:-$HERE/kong.rendered.yml}"

[ -f "$TMPL" ] || { echo "FATAL: template not found: $TMPL" >&2; exit 1; }
[ -f "$ENV_FILE" ] || { echo "FATAL: env file not found: $ENV_FILE (copy infra/.env.example)" >&2; exit 1; }

# Parse only the values this renderer needs.  The private env file is data, not
# shell code: sourcing it would execute command substitutions in a secret value.
env_value() {
  local wanted="$1" output="$2" line parsed_value seen=0
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"
    case "$line" in
      "$wanted"=*)
        seen=$((seen + 1))
        parsed_value="${line#*=}"
        ;;
    esac
  done < "$ENV_FILE"
  [ "$seen" -eq 1 ] && [ -n "${parsed_value:-}" ] || return 1
  printf -v "$output" '%s' "$parsed_value"
}

for v in KONG_PROVISION_KEY AGENT_RECON_SECRET PROBE_ADMIN_SECRET SENTINEL_CHARTER_EXECUTOR_SECRET; do
  value=""
  env_value "$v" value || { echo "FATAL: required Kong configuration is invalid" >&2; exit 2; }
  export "$v=$value"
done

# Restrict permissions at creation time, not after: a chmod that runs after the write leaves a
# brief window where the secret-bearing file is world-readable. umask 077 makes the redirect
# create it 0600 from the first byte.
umask 077

# Explicit allowlist: substitute exactly these names, nothing else.
envsubst '${KONG_PROVISION_KEY} ${AGENT_RECON_SECRET} ${PROBE_ADMIN_SECRET} ${SENTINEL_CHARTER_EXECUTOR_SECRET}' \
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
