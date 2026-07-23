#!/usr/bin/env bash
# Generate the local CA and postgres server certificate for the DefectDojo external DB.
#
# Why a CA and not a bare self-signed cert: the stack connects with
# sslmode=verify-full, which checks both the chain and the hostname. That mode is
# not chosen for MITM protection on a docker bridge - it is chosen so the TLS code
# path is genuinely exercised now, instead of discovering it was never wired up on
# the day the DB is swapped for the VinSOC replica.
#
# SANs cover both reachable names:
#   dd-postgres  - from inside the compose network (app, celery, initializer)
#   localhost    - from the host, via the published 127.0.0.1:55433 port (backups, psql)
#
# Idempotent: refuses to overwrite existing material unless --force is given, so a
# rerun cannot silently invalidate a running stack's trust anchor.

set -euo pipefail

CERT_DIR="${CERT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/infra/defectdojo-db/certs}"
DAYS_CA="${DAYS_CA:-3650}"
DAYS_SERVER="${DAYS_SERVER:-825}"   # browsers/libs reject longer leaf lifetimes
FORCE=0

[ "${1:-}" = "--force" ] && FORCE=1

mkdir -p "$CERT_DIR"

if [ -f "$CERT_DIR/server.crt" ] && [ "$FORCE" -eq 0 ]; then
    echo "certs already present in $CERT_DIR (use --force to regenerate)"
    echo "note: regenerating invalidates the trust anchor of any running stack"
    exit 0
fi

umask 0077

echo "==> local CA"
openssl req -new -x509 -nodes -newkey rsa:4096 \
    -keyout "$CERT_DIR/ca.key" \
    -out "$CERT_DIR/ca.crt" \
    -days "$DAYS_CA" \
    -subj "/CN=vinsoc-defectdojo-local-ca" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

echo "==> postgres server key + CSR"
openssl req -new -nodes -newkey rsa:2048 \
    -keyout "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.csr" \
    -subj "/CN=dd-postgres" 2>/dev/null

echo "==> signing server cert (SAN: dd-postgres, localhost, 127.0.0.1)"
openssl x509 -req \
    -in "$CERT_DIR/server.csr" \
    -CA "$CERT_DIR/ca.crt" \
    -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial \
    -out "$CERT_DIR/server.crt" \
    -days "$DAYS_SERVER" \
    -extfile <(printf 'subjectAltName=DNS:dd-postgres,DNS:localhost,IP:127.0.0.1\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n') 2>/dev/null

rm -f "$CERT_DIR/server.csr" "$CERT_DIR/ca.srl"

# The CA cert is a public trust anchor and is mounted read-only into app
# containers; only the private keys stay 0600.
chmod 0644 "$CERT_DIR/ca.crt" "$CERT_DIR/server.crt"
chmod 0600 "$CERT_DIR/ca.key" "$CERT_DIR/server.key"

echo
echo "==> verifying chain and SANs"
openssl verify -CAfile "$CERT_DIR/ca.crt" "$CERT_DIR/server.crt"
openssl x509 -in "$CERT_DIR/server.crt" -noout -ext subjectAltName

echo
echo "certs written to $CERT_DIR"
echo "server.key is chowned to the postgres uid by the container entrypoint wrapper,"
echo "because postgres refuses a key readable by anyone but its own user or root."
