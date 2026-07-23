#!/bin/sh
# Abort container boot when DefectDojo's crypto keys are absent or publicly known.
#
# Runs as the FIRST command of the app/worker/initializer entrypoint, before any
# Django import. Placement matters: DD_CREDENTIAL_AES_256_KEY encrypts stored tool
# credentials at rest, so a process that reaches Django settings has already
# decrypted them with whatever key it was given. Checking after boot detects the
# problem; checking here prevents it.
#
# Fail-closed on three distinct states, all of which yield a usable-but-public key:
#   unset  -> Django's own default from settings.dist.py takes over ("" / ".")
#   empty  -> same fallback
#   known  -> a value published in the DefectDojo repo or its compose file
#
# POSIX sh: this runs inside the DefectDojo image before anything else is trusted.

set -eu

# Values published in the DefectDojo source tree. Anything matching is public.
# settings.dist.py:157-158 supply "" and "." as the in-code fallbacks; the
# docker-compose.yml defaults supply the two literal strings.
KNOWN_PUBLIC_SECRET_KEYS='
hhZCp@D28z!n@NED*yB!ROMt+WzsY*iq
.
'
KNOWN_PUBLIC_AES_KEYS='
&91a*agLqesc*0DJ+2*bAbsUZfR*4nLw
.
'

fail() {
    # Never echo the offending value - this runs with stdout attached to docker logs.
    echo "FATAL [dd-boot-guard]: $1" >&2
    echo "FATAL [dd-boot-guard]: refusing to start. Generate keys with 'openssl rand -base64 32' and set them in infra/defectdojo/.env" >&2
    exit 78  # EX_CONFIG
}

# `set -u` would abort on an unset var before we can report which one, so probe
# for existence separately from reading the value.
check_present() {
    var_name="$1"
    eval "is_set=\${$var_name+set}"
    [ "${is_set:-}" = "set" ] || fail "$var_name is unset (Django would silently fall back to its public default)"
}

check_not_public() {
    var_name="$1"
    var_value="$2"
    known_list="$3"

    [ -n "$var_value" ] || fail "$var_name is empty (Django would silently fall back to its public default)"

    # Guard against a key that is technically non-default but trivially weak.
    if [ "${#var_value}" -lt 16 ]; then
        fail "$var_name is shorter than 16 characters"
    fi

    echo "$known_list" | while IFS= read -r known; do
        [ -n "$known" ] || continue
        if [ "$var_value" = "$known" ]; then
            exit 1
        fi
    done || fail "$var_name matches a publicly published DefectDojo default"
}

check_present DD_SECRET_KEY
check_present DD_CREDENTIAL_AES_256_KEY

check_not_public DD_SECRET_KEY "$DD_SECRET_KEY" "$KNOWN_PUBLIC_SECRET_KEYS"
check_not_public DD_CREDENTIAL_AES_256_KEY "$DD_CREDENTIAL_AES_256_KEY" "$KNOWN_PUBLIC_AES_KEYS"

# DD_DEBUG=True leaks the database password through Django's traceback page.
if [ "${DD_DEBUG:-False}" != "False" ]; then
    fail "DD_DEBUG must be False (tracebacks would expose DB credentials)"
fi

echo "[dd-boot-guard] key material and DD_DEBUG validated"
