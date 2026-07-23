#!/usr/bin/env bash
# Back up the DefectDojo external database, and optionally rehearse the restore.
#
#   scripts/dd-backup.sh              dump + escrow metadata
#   scripts/dd-backup.sh --drill      dump, then run the DEEP restore drill
#
# Why the drill is "deep": a row-count comparison proves neither integrity nor
# recoverability. DefectDojo encrypts stored tool credentials with
# DD_CREDENTIAL_AES_256_KEY, so a dump restored under a rotated key yields rows
# that are present, well-formed, and permanently unreadable. The drill therefore
# restores into a throwaway database, boots the application against it, and
# asserts that a planted canary credential decrypts back to its known value.
#
# Every dump is written alongside a .meta.json recording the FINGERPRINT of the
# AES key in force (sha256 of the key, never the key itself). Restoring a dump
# whose fingerprint does not match the current key is the failure this escrow is
# designed to make obvious before the restore rather than after.
#
# Backup ownership by database mode:
#   self-managed pg container (current) -> this script, run from cron
#   managed postgres host               -> provider snapshots; this script still
#                                          owns the drill, and the provider's
#                                          restore cadence must be documented

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ENV_FILE:-$REPO_ROOT/infra/.env}"
BACKUP_DIR="${BACKUP_DIR:-$REPO_ROOT/infra/backups}"
DB_CONTAINER="${DB_CONTAINER:-dd-postgres}"
APP_CONTAINER="${APP_CONTAINER:-dd-uwsgi}"
RUN_DRILL=0
[ "${1:-}" = "--drill" ] && RUN_DRILL=1

# shellcheck disable=SC1090
set -a; . "$ENV_FILE"; set +a
: "${DD_DATABASE_NAME:?}" "${DD_DATABASE_USER:?}" "${DD_DATABASE_PASSWORD:?}" "${DD_CREDENTIAL_AES_256_KEY:?}"

mkdir -p "$BACKUP_DIR"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
DUMP="$BACKUP_DIR/defectdojo-$STAMP.dump"
META="$BACKUP_DIR/defectdojo-$STAMP.meta.json"
CANARY_NAME="dd-backup-canary"
CANARY_SECRET="canary-$STAMP"

key_fingerprint() { printf '%s' "$DD_CREDENTIAL_AES_256_KEY" | sha256sum | cut -d' ' -f1; }

# ---------------------------------------------------------------------------
# 1. plant the canary so the drill has something whose plaintext we know
# ---------------------------------------------------------------------------
# The canary must be written through DefectDojo's own encryption helper. Assigning
# Tool_Configuration.api_key directly stores PLAINTEXT: encryption lives in
# dojo_crypto_encrypt() (called from the form layer), not in the model's save().
# A plaintext canary would decrypt "successfully" under any key at all, which
# makes the whole drill a rubber stamp - verified by restoring under a random key
# and still reading the value back.
echo "==> ensuring canary credential exists (encrypted via dojo_crypto_encrypt)"
docker exec "$APP_CONTAINER" python manage.py shell --no-imports -c "
from dojo.models import Tool_Type, Tool_Configuration
from dojo.utils import dojo_crypto_encrypt, prepare_for_view
tt,_ = Tool_Type.objects.get_or_create(name='backup-drill')
tc,_ = Tool_Configuration.objects.get_or_create(name='$CANARY_NAME', tool_type=tt,
                                                defaults={'authentication_type':'API'})
tc.api_key = dojo_crypto_encrypt('$CANARY_SECRET')
tc.save()

stored = Tool_Configuration.objects.get(pk=tc.pk).api_key
if '$CANARY_SECRET' in (stored or ''):
    raise SystemExit('FATAL: canary was stored in plaintext - the drill would prove nothing')
if prepare_for_view(stored) != '$CANARY_SECRET':
    raise SystemExit('FATAL: canary does not round-trip under the current key')
print('    canary stored encrypted (id=%s)' % tc.id)
" 2>&1 | tail -1

# ---------------------------------------------------------------------------
# 2. dump
# ---------------------------------------------------------------------------
echo "==> dumping $DD_DATABASE_NAME"
docker exec -e PGPASSWORD="$DD_DATABASE_PASSWORD" "$DB_CONTAINER" \
    pg_dump -U "$DD_DATABASE_USER" -d "$DD_DATABASE_NAME" -Fc > "$DUMP"
chmod 0600 "$DUMP"

SIZE=$(stat -c%s "$DUMP")
SHA=$(sha256sum "$DUMP" | cut -d' ' -f1)
IMAGE_DIGEST=$(docker inspect -f '{{index .RepoDigests 0}}' "$(docker inspect -f '{{.Image}}' "$APP_CONTAINER")" 2>/dev/null || echo "unknown")

cat > "$META" <<EOF
{
  "dump": "$(basename "$DUMP")",
  "created_utc": "$STAMP",
  "bytes": $SIZE,
  "sha256": "$SHA",
  "aes_key_fingerprint_sha256": "$(key_fingerprint)",
  "canary_tool_configuration": "$CANARY_NAME",
  "app_image": "$IMAGE_DIGEST",
  "note": "Restoring under an AES key whose fingerprint differs from the value above yields rows that decrypt to nothing."
}
EOF
chmod 0600 "$META"
echo "    $DUMP ($SIZE bytes)"
echo "    $META"

[ "$RUN_DRILL" -eq 1 ] || {
    echo
    echo "dump complete. Restore drill NOT run (pass --drill to rehearse it)."
    exit 0
}

# ---------------------------------------------------------------------------
# 3. DEEP restore drill
# ---------------------------------------------------------------------------
DRILL_DB="dd_drill_$(date -u +%H%M%S)"
echo
echo "==> restore drill into throwaway database $DRILL_DB"

cleanup() {
    docker exec -e PGPASSWORD="$DD_DATABASE_PASSWORD" "$DB_CONTAINER" \
        psql -U "$DD_DATABASE_USER" -d postgres -c "DROP DATABASE IF EXISTS $DRILL_DB;" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker exec -e PGPASSWORD="$DD_DATABASE_PASSWORD" "$DB_CONTAINER" \
    psql -U "$DD_DATABASE_USER" -d postgres -c "CREATE DATABASE $DRILL_DB;" >/dev/null

docker exec -i -e PGPASSWORD="$DD_DATABASE_PASSWORD" "$DB_CONTAINER" \
    pg_restore -U "$DD_DATABASE_USER" -d "$DRILL_DB" --no-owner < "$DUMP" >/dev/null 2>&1 || true

echo "==> booting application against the restored database"
DRILL_OUT=$(docker run --rm --network dd-net \
    -v "$REPO_ROOT/infra/defectdojo-db/certs/ca.crt:/certs/ca.crt:ro" \
    -e DD_DATABASE_ENGINE=django.db.backends.postgresql \
    -e DD_DATABASE_HOST=dd-postgres -e DD_DATABASE_PORT=5432 \
    -e DD_DATABASE_NAME="$DRILL_DB" \
    -e DD_DATABASE_USER="$DD_DATABASE_USER" \
    -e DD_DATABASE_PASSWORD="$DD_DATABASE_PASSWORD" \
    -e PGSSLMODE=verify-full -e PGSSLROOTCERT=/certs/ca.crt \
    -e DD_SECRET_KEY="$DD_SECRET_KEY" \
    -e DD_CREDENTIAL_AES_256_KEY="$DD_CREDENTIAL_AES_256_KEY" \
    -e DD_DEBUG=False \
    --entrypoint python \
    "$(docker inspect -f '{{.Config.Image}}' "$APP_CONTAINER")" \
    manage.py shell --no-imports -c "
from dojo.models import Tool_Configuration
from dojo.utils import prepare_for_view
tc = Tool_Configuration.objects.get(name='$CANARY_NAME')
try:
    recovered = prepare_for_view(tc.api_key)
except Exception as exc:
    recovered = '<undecryptable: %s>' % type(exc).__name__
print('DRILL_RESULT=' + ('OK' if recovered == '$CANARY_SECRET' else 'MISMATCH'))
" 2>&1 | tail -3)

echo "$DRILL_OUT"
if grep -q "DRILL_RESULT=OK" <<<"$DRILL_OUT"; then
    echo
    echo "RESTORE DRILL PASSED: restored DB boots and the canary credential AES-decrypts."
else
    echo
    echo "RESTORE DRILL FAILED: the dump restored but its encrypted credentials are unreadable." >&2
    echo "Check aes_key_fingerprint_sha256 in $META against the current key." >&2
    exit 1
fi
