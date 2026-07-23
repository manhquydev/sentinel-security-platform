#!/usr/bin/env bash
# Entrypoint wrapper for the DefectDojo external postgres container.
#
# Exists for one reason: postgres refuses to start if its private key is readable
# by anyone other than the database user or root. A bind-mounted key carries the
# host's ownership (uid 1000 here), which postgres rejects outright. Copying the
# material into a container-local directory and chowning it to the postgres user
# is the fix that does not require the host files to be root-owned - and keeps the
# base image digest-pinned rather than forcing a derived build.
#
# Runs as root, which is how the official postgres entrypoint starts before it
# re-execs itself under gosu.

set -euo pipefail

# Certs are generated (and gitignored); pg_hba.conf is a committed repo file, so
# the two arrive on separate mounts.
SRC=/certs-src
SRC_HBA=/pg_hba.conf.src
DST=/certs

if [ -d "$SRC" ]; then
    mkdir -p "$DST"
    cp "$SRC/server.crt" "$SRC/server.key" "$SRC/ca.crt" "$DST/"
    cp "$SRC_HBA" "$DST/pg_hba.conf"

    chown postgres:postgres "$DST"/server.crt "$DST"/server.key "$DST"/ca.crt "$DST"/pg_hba.conf
    chmod 0600 "$DST/server.key"
    chmod 0644 "$DST/server.crt" "$DST/ca.crt" "$DST/pg_hba.conf"

    echo "[dd-pg-entrypoint] TLS material staged in $DST"
else
    echo "FATAL [dd-pg-entrypoint]: $SRC not mounted - run scripts/dd-gen-db-certs.sh first" >&2
    exit 78
fi

exec docker-entrypoint.sh "$@"
