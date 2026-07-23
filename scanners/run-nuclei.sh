#!/usr/bin/env bash
# Nuclei DAST wrapper (phase-03).
#   run-nuclei.sh <output.jsonl>
# Actively probes TARGET_URL. Emits Nuclei JSONL (RAW — caller MUST pass through
# redact-report.sh BEFORE any JSONL→JSON conversion; extracted-results carry
# harvested tokens). The target is allowlist-validated and the resolved IP is
# pinned into the container (anti-DNS-rebind). Image pinned by @sha256.
set -euo pipefail

out="${1:?output jsonl path required}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "$HERE/image-pins.env" ] && . "$HERE/image-pins.env"

# Production = digest-pinned docker image. NUCLEI_BIN = a local nuclei binary
# (fallback when the container registry is unreachable).
NUCLEI_BIN="${NUCLEI_BIN:-}"
if [ -z "$NUCLEI_BIN" ]; then
  NUCLEI_IMAGE="${NUCLEI_IMAGE:?NUCLEI_IMAGE unset — populate scanners/image-pins.env with a @sha256 digest (or set NUCLEI_BIN for a local binary)}"
  case "$NUCLEI_IMAGE" in *@sha256:*) : ;; *) echo "run-nuclei: NUCLEI_IMAGE must be @sha256-pinned" >&2; exit 4;; esac
fi

TARGET_URL="${TARGET_URL:?TARGET_URL required}"
ALLOWLIST="${ALLOWLIST:?ALLOWLIST required (fail-closed target guard)}"

# Fail-closed allowlist + pin the resolved IP; refuse to scan a rejected target.
pin="$(ALLOWLIST="$ALLOWLIST" "$HERE/target-allowlist.sh" validate "$TARGET_URL")" \
  || { echo "run-nuclei: target rejected by allowlist" >&2; exit 1; }

mkdir -p "$(dirname "$out")"
errlog="$(mktemp)"

# Status sidecar on every exit (see run-semgrep.sh). The errlog cleanup rides the
# same trap. CONTACT stays false until the post-scan re-probe positively confirms
# the target answered.
STATUS="error"; CONTACT="false"; DETAIL="run did not complete"
cleanup() { local rc=$?; "$HERE/write-status.sh" nuclei "$out" "$STATUS" "$CONTACT" "$rc" "$DETAIL" 2>/dev/null || true; rm -f "$errlog"; }
trap cleanup EXIT
# Templates: first run uses nuclei's bundled/downloaded set (mirroring +
# checksum-pinning them is the hardening follow-up noted in README).
# Distinguish a crash from a clean scan: nuclei exits 0 on success (with or
# without findings) and non-zero on a real error. A non-zero exit is fail-closed
# (an empty output from a crash must NOT read as "clean") — do NOT `|| true`.
# -dr: nuclei does not follow redirects by default, but a template can opt in with
#   `redirects: true`. -dr forcibly disables it, so a template cannot walk a
#   redirect off the allowlisted target regardless of what it requests. This is the
#   only redirect control nuclei exposes; the residual same-host-port gap is
#   documented in README (--network host reaches loopback services on other ports).
# -ni: OAST templates otherwise call ProjectDiscovery's public interactsh servers
#   (oast.pro et al) with target-derived data — egress the allowlist never sees.
#   Disabling it drops those templates rather than leaking through them.
redirect_egress_flags=(-dr -ni)
set +e
if [ -n "$NUCLEI_BIN" ]; then
  # Local binary reaches 127.0.0.1:13000 directly (no --network host needed).
  "$NUCLEI_BIN" -target "$TARGET_URL" -jsonl -silent -no-color -disable-update-check \
    "${redirect_egress_flags[@]}" \
    >"$out" 2>"$errlog"
else
  # --network host so 127.0.0.1:13000 resolves to the host loopback harness.
  docker run --rm --network host \
    "$NUCLEI_IMAGE" \
      -target "$TARGET_URL" \
      -jsonl -silent -no-color \
      -disable-update-check \
      "${redirect_egress_flags[@]}" \
    >"$out" 2>"$errlog"
fi
rc=$?
set -e
if [ "$rc" -ne 0 ]; then
  echo "run-nuclei: scanner error (exit $rc) — NOT a clean scan; last stderr:" >&2
  tail -3 "$errlog" >&2
  exit 5
fi

# Proof of contact, checked AFTER the scan. Nuclei exits 0 with an empty report
# both when the target is genuinely clean and when it never answered — it skips a
# host after repeated errors and still succeeds. A findings-free report is only
# evidence of remediation if the target was actually up, so re-probe it here
# rather than trusting the pre-scan readiness gate, which says nothing about the
# minutes the scan itself spanned.
if ! ALLOWLIST="$ALLOWLIST" "$HERE/target-allowlist.sh" ready "$TARGET_URL" >/dev/null 2>&1; then
  echo "run-nuclei: $TARGET_URL did not answer after the scan — findings-free output is not proof of a clean target" >&2
  exit 7
fi
STATUS="ok"; CONTACT="true"; DETAIL="target answered post-scan, validated $pin"

# The resolved IP was validated + pinned by target-allowlist. Forcing nuclei
# onto that exact IP (defeating a rebind between validation and scan) matters
# only for hostname targets; the current harness target is a literal loopback IP,
# so pinning is a no-op here and the scan-time IP-force is a documented follow-up.
echo "run-nuclei: wrote $out ($(wc -l <"$out" 2>/dev/null || echo 0) findings, validated $pin)" >&2
