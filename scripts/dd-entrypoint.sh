#!/bin/sh
# Shared entrypoint wrapper for every DefectDojo container that boots Django.
#
# Order is the whole point:
#   1. dd-boot-guard.sh  - refuses public/absent crypto keys before Django loads
#   2. upstream entrypoint - performs its own TLS-verified DB readiness wait
#      (docker/reach_database.sh runs "select 1" through manage.py dbshell, which
#      goes over libpq and therefore honours PGSSLMODE/PGSSLROOTCERT), the broker
#      wait, and "manage.py check", then execs the real process.
#
# Migrations are NOT run here. They belong to the one-shot `initializer` service,
# which compose gates with `service_completed_successfully` so the app and both
# celery containers cannot race it or half-apply a migration on a crash-loop.
#
# Usage (from compose):
#   entrypoint: ["/dd-entrypoint.sh", "/entrypoint-uwsgi.sh"]

set -eu

/dd-boot-guard.sh

# Assert the TLS trust anchor exists before handing over. Without it libpq would
# fall back to an unverified connection and the failure would surface as a
# confusing auth error much later.
if [ "${PGSSLMODE:-}" = "verify-full" ] || [ "${PGSSLMODE:-}" = "verify-ca" ]; then
    if [ ! -r "${PGSSLROOTCERT:-/dev/null}" ]; then
        echo "FATAL [dd-entrypoint]: PGSSLMODE=${PGSSLMODE} but PGSSLROOTCERT is unreadable at '${PGSSLROOTCERT:-<unset>}'" >&2
        exit 78
    fi
    echo "[dd-entrypoint] postgres TLS: ${PGSSLMODE}, CA at ${PGSSLROOTCERT}"
fi

exec "$@"
