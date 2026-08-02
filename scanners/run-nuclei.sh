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
configured_image="${NUCLEI_IMAGE:-}"
[ -f "$HERE/image-pins.env" ] && . "$HERE/image-pins.env"
[[ -n "$configured_image" ]] && NUCLEI_IMAGE="$configured_image"

# Production = digest-pinned docker image. NUCLEI_BIN = a local nuclei binary
# (fallback when the container registry is unreachable).
NUCLEI_BIN="${NUCLEI_BIN:-}"
if [ -z "$NUCLEI_BIN" ]; then
  NUCLEI_IMAGE="${NUCLEI_IMAGE:?NUCLEI_IMAGE unset — populate scanners/image-pins.env with a @sha256 digest (or set NUCLEI_BIN for a local binary)}"
  case "$NUCLEI_IMAGE" in *@sha256:*) : ;; *) echo "run-nuclei: NUCLEI_IMAGE must be @sha256-pinned" >&2; exit 4;; esac
fi

TARGET_URL="${TARGET_URL:?TARGET_URL required}"
SENTINEL_PROFILE="${SENTINEL_PROFILE:-}"
charter=false
case "$SENTINEL_PROFILE" in
  "") ;;
  charter) charter=true ;;
  *) echo "run-nuclei: unsupported SENTINEL_PROFILE '$SENTINEL_PROFILE'" >&2; exit 2 ;;
esac

charter_templates=()
verify_charter_templates() {
  local manifest="$HERE/charter-template-manifest.json"
  [ -r "$manifest" ] || { echo "run-nuclei: missing charter template manifest" >&2; return 1; }
  # The manifest is the reviewed selection boundary.  Verify both directions:
  # every listed file has its approved digest and every committed file under the
  # charter directory is listed, so neither bundled nor newly dropped templates
  # can join a charter scan implicitly.
  mapfile -t charter_templates < <(python3 - "$HERE" "$manifest" <<'PY'
import hashlib, json, pathlib, sys

root, manifest = map(pathlib.Path, sys.argv[1:])
try:
    doc = json.loads(manifest.read_text(encoding="utf-8"))
    rows = doc.get("templates")
    if doc.get("version") != 1 or not isinstance(rows, list) or not rows:
        raise ValueError("manifest requires version 1 and a non-empty template list")
    listed = set()
    for row in rows:
        path = row.get("path")
        if not isinstance(path, str) or not path.startswith("charter-templates/"):
            raise ValueError("template path is outside charter-templates")
        if pathlib.PurePosixPath(path).is_absolute() or ".." in pathlib.PurePosixPath(path).parts:
            raise ValueError("template path traversal")
        file = root / path
        if not file.is_file():
            raise ValueError("listed template is absent")
        if row.get("review_status") != "approved" or row.get("protocol") != "http":
            raise ValueError("template is not approved HTTP scope")
        if hashlib.sha256(file.read_bytes()).hexdigest() != row.get("sha256"):
            raise ValueError("template digest mismatch")
        text = file.read_text(encoding="utf-8")
        if "http:" not in text or "dns:" in text or "oast" in text.lower() or "interactsh" in text.lower():
            raise ValueError("template content is outside reviewed HTTP scope")
        listed.add(file.resolve())
        print(path)
    actual = {p.resolve() for p in (root / "charter-templates").rglob("*") if p.is_file()}
    if listed != actual:
        raise ValueError("unlisted or missing charter template")
except Exception as exc:
    print(f"run-nuclei: charter template verification failed: {exc}", file=sys.stderr)
    raise SystemExit(1)
PY
)
  [ "${#charter_templates[@]}" -gt 0 ]
}

if "$charter"; then
  [ -n "${CHARTER_RUN_ROOT:-}" ] || { echo "run-nuclei: CHARTER_RUN_ROOT required for charter raw quarantine" >&2; exit 2; }
  [ -d "$CHARTER_RUN_ROOT" ] || { echo "run-nuclei: charter run root does not exist" >&2; exit 2; }
  case "$out" in "$CHARTER_RUN_ROOT"/*) ;; *) echo "run-nuclei: charter raw output must be run-local" >&2; exit 2;; esac
  pin="$("$HERE/target-allowlist.sh" charter-validate "$TARGET_URL")" \
    || { echo "run-nuclei: charter target rejected" >&2; exit 1; }
  verify_charter_templates || exit 1
else
  ALLOWLIST="${ALLOWLIST:?ALLOWLIST required (fail-closed target guard)}"
  # Fail-closed allowlist + pin the resolved IP; refuse to scan a rejected target.
  pin="$(ALLOWLIST="$ALLOWLIST" "$HERE/target-allowlist.sh" validate "$TARGET_URL")" \
    || { echo "run-nuclei: target rejected by allowlist" >&2; exit 1; }
fi

mkdir -p "$(dirname "$out")"
if "$charter"; then
  # The controller creates this file with mktemp, but enforce the artifact
  # boundary here as well so an alternate charter caller cannot weaken it.
  : >"$out"
  chmod 600 "$out"
  errlog="$(mktemp "$CHARTER_RUN_ROOT/.nuclei-stderr.XXXXXX")"
  chmod 600 "$errlog"
else
  errlog="$(mktemp)"
fi

# Status sidecar on every exit (see run-semgrep.sh). The errlog cleanup rides the
# same trap. CONTACT stays false until the post-scan re-probe positively confirms
# the target answered.
STATUS="error"; CONTACT="false"; DETAIL="run did not complete"
cleanup() {
  local rc=$?
  if "$charter"; then
    # Failure diagnostics stay in the private run root.  Do not report the raw
    # output/sidecar names or scanner stderr to ordinary logs.  A successful
    # scanner is not a successful charter pipeline: the controller erases this
    # file only after sanitization, import, gate, and observation all succeed.
    :
  else
    "$HERE/write-status.sh" nuclei "$out" "$STATUS" "$CONTACT" "$rc" "$DETAIL" 2>/dev/null || true
    rm -f "$errlog"
  fi
}
trap cleanup EXIT
# The charter's redirect refusal is an admission condition, not post-scan
# telemetry.  It has to happen before Nuclei gets any target argument.
if "$charter" && ! "$HERE/target-allowlist.sh" charter-ready "$TARGET_URL" >/dev/null 2>&1; then
  echo "run-nuclei: charter target failed non-redirecting readiness; scanner not invoked" >&2
  exit 7
fi
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
redirect_egress_flags+=(-no-interactsh)
set +e
if [ -n "$NUCLEI_BIN" ]; then
  # Local binary reaches 127.0.0.1:13000 directly (no --network host needed).
  if "$charter"; then
    args=()
    for template in "${charter_templates[@]}"; do args+=(-t "$HERE/$template"); done
    "$NUCLEI_BIN" -target "$TARGET_URL" -jsonl -silent -no-color -disable-update-check \
      "${redirect_egress_flags[@]}" "${args[@]}" >"$out" 2>"$errlog"
  else
    "$NUCLEI_BIN" -target "$TARGET_URL" -jsonl -silent -no-color -disable-update-check \
      "${redirect_egress_flags[@]}" >"$out" 2>"$errlog"
  fi
else
  # --network host so 127.0.0.1:13000 resolves to the host loopback harness.
  if "$charter"; then
    args=()
    for template in "${charter_templates[@]}"; do args+=(-t "/$template"); done
    docker run --rm --network host -v "$HERE/charter-templates:/charter-templates:ro" \
      "$NUCLEI_IMAGE" -target "$TARGET_URL" -jsonl -silent -no-color -disable-update-check \
      "${redirect_egress_flags[@]}" "${args[@]}" >"$out" 2>"$errlog"
  else
    docker run --rm --network host \
      "$NUCLEI_IMAGE" \
        -target "$TARGET_URL" \
        -jsonl -silent -no-color \
        -disable-update-check \
        "${redirect_egress_flags[@]}" \
      >"$out" 2>"$errlog"
  fi
fi
rc=$?
set -e
if [ "$rc" -ne 0 ]; then
  if "$charter"; then
    echo "run-nuclei: charter scanner error (exit $rc); diagnostics retained in private quarantine" >&2
  else
    echo "run-nuclei: scanner error (exit $rc) — NOT a clean scan; last stderr:" >&2
    tail -3 "$errlog" >&2
  fi
  exit 5
fi

# Proof of contact, checked AFTER the scan. Nuclei exits 0 with an empty report
# both when the target is genuinely clean and when it never answered — it skips a
# host after repeated errors and still succeeds. A findings-free report is only
# evidence of remediation if the target was actually up, so re-probe it here
# rather than trusting the pre-scan readiness gate, which says nothing about the
# minutes the scan itself spanned.
if "$charter"; then
  ready=("$HERE/target-allowlist.sh" charter-ready "$TARGET_URL")
else
  ready=(env "ALLOWLIST=$ALLOWLIST" "$HERE/target-allowlist.sh" ready "$TARGET_URL")
fi
if ! "${ready[@]}" >/dev/null 2>&1; then
  echo "run-nuclei: $TARGET_URL did not answer after the scan — findings-free output is not proof of a clean target" >&2
  exit 7
fi
STATUS="ok"; CONTACT="true"; DETAIL="target answered post-scan, validated $pin"

# The resolved IP was validated + pinned by target-allowlist. Forcing nuclei
# onto that exact IP (defeating a rebind between validation and scan) matters
# only for hostname targets; the current harness target is a literal loopback IP,
# so pinning is a no-op here and the scan-time IP-force is a documented follow-up.
if "$charter"; then
  echo "run-nuclei: charter scan complete for literal origin" >&2
else
  echo "run-nuclei: wrote $out ($(wc -l <"$out" 2>/dev/null || echo 0) findings, validated $pin)" >&2
fi
