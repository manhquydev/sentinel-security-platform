#!/usr/bin/env bash
# Print freshly generated key material for infra/.env.
#
# Values are printed to stdout only and never written to disk by this script, so
# that the operator decides where they land. Nothing here is idempotent by design:
# every run yields new keys, and reusing a stale DD_CREDENTIAL_AES_256_KEY is the
# one mistake that silently makes existing stored credentials unreadable.

set -euo pipefail

# DefectDojo enforces its own password policy on accounts created through the
# API (upper, lower, digit, special, minimum length). A purely alphanumeric
# password is rejected with password_no_symbol, so account passwords get a
# guaranteed special character appended rather than being stripped of one.
dd_password() {
    printf '%s!Aa1' "$(openssl rand -base64 24 | tr -d '/+=' | head -c 24)"
}

echo "# generated $(date -Iseconds) - paste into infra/.env"
echo "DD_SECRET_KEY=$(openssl rand -base64 32)"
echo "DD_CREDENTIAL_AES_256_KEY=$(openssl rand -base64 32)"
# DB password stays alphanumeric: it travels in a libpq connection string.
echo "DD_DATABASE_PASSWORD=$(openssl rand -base64 24 | tr -d '/+=' | head -c 32)"
echo "DD_ADMIN_PASSWORD=$(dd_password)"
echo "DD_SERVICE_ACCOUNT_PASSWORD=$(dd_password)"
echo
echo "# DD_CREDENTIAL_AES_256_KEY must be escrowed with every database dump." >&2
echo "# A dump restored under a different key yields rows that decrypt to nothing." >&2
