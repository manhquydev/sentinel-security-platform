#!/usr/bin/env bash
# Sentinel — GCP Compute Engine deploy controller.
#
# One VM that mirrors the local Charter docker-compose topology 1:1. Every service
# binds 127.0.0.1 on the VM, so the deliberately-vulnerable Juice Shop target is
# private by construction: there is NO public ingress rule for any app port. The
# only inbound path is SSH over IAP (or one operator CIDR); reach the product
# surface through an IAP/SSH tunnel.
#
# This controller never provisions cloud resources implicitly and never prints or
# commits secrets. Application secrets live in infra/.env and are copied to the VM
# by `sync`, out-of-band from git.
#
# Usage:
#   bash infra/gcp/deploy.sh <command>
# Commands:
#   preflight   Verify gcloud, auth, project, billing, APIs, and local prerequisites.
#   provision   Create the firewall rule(s) and the VM (idempotent).
#   sync        rsync the repo + infra/.env + DefectDojo certs to the VM.
#   bootstrap   Install Docker + create the dd-net network on the VM.
#   up          Run scripts/sentinel-charter-up.sh on the VM (brings the topology up).
#   status      Show VM + container status.
#   tunnel      Open IAP/SSH local port-forwards to the loopback product surface.
#   teardown    Delete the VM (keeps the firewall rule unless --all).
#   all         preflight -> provision -> sync -> bootstrap -> up.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
CONFIG="${SENTINEL_GCP_CONFIG:-$HERE/config.env}"

log()  { printf '\033[36m[deploy]\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m  PASS\033[0m %s\n' "$*"; }
warn() { printf '\033[33m  WARN\033[0m %s\n' "$*"; }
die()  { printf '\033[31mFATAL:\033[0m %s\n' "$*" >&2; exit 1; }

load_config() {
  [ -f "$CONFIG" ] || die "missing $CONFIG (copy config.env.example and fill it in)"
  # shellcheck disable=SC1090
  set -a; . "$CONFIG"; set +a
  : "${PROJECT_ID:?PROJECT_ID is required in config.env}"
  : "${ZONE:?ZONE is required in config.env}"
  : "${VM_NAME:?VM_NAME is required in config.env}"
  : "${ACCESS_MODEL:=iap}"
  : "${NETWORK_TAG:=sentinel}"
  : "${REMOTE_REPO_DIR:=/opt/sentinel/vinsoc}"
  GC=(gcloud --project "$PROJECT_ID")
}

need_gcloud() { command -v gcloud >/dev/null 2>&1 || die "gcloud is not installed. Install: sudo snap install google-cloud-cli --classic  (then: gcloud init)"; }

ssh_vm() { "${GC[@]}" compute ssh "$VM_NAME" --zone "$ZONE" "$@"; }

vm_exists() { "${GC[@]}" compute instances describe "$VM_NAME" --zone "$ZONE" >/dev/null 2>&1; }

# --------------------------------------------------------------------------
cmd_preflight() {
  need_gcloud
  load_config
  log "preflight for project=$PROJECT_ID zone=$ZONE vm=$VM_NAME access=$ACCESS_MODEL"
  local fail=0

  local acct; acct="$(gcloud auth list --filter=status:ACTIVE --format='value(account)' 2>/dev/null | head -1)"
  [ -n "$acct" ] && ok "authenticated as $acct" || { warn "no active gcloud account — run: gcloud auth login"; fail=1; }

  if gcloud projects describe "$PROJECT_ID" >/dev/null 2>&1; then ok "project reachable"; else warn "cannot describe project $PROJECT_ID"; fail=1; fi

  local billing; billing="$(gcloud billing projects describe "$PROJECT_ID" --format='value(billingEnabled)' 2>/dev/null || true)"
  [ "$billing" = "True" ] && ok "billing enabled" || warn "billing not confirmed (need billing to create a VM)"

  local svc; svc="$(gcloud services list --enabled --project "$PROJECT_ID" --format='value(config.name)' 2>/dev/null || true)"
  grep -q '^compute.googleapis.com' <<<"$svc" && ok "compute API enabled" || warn "compute API not enabled — run: gcloud services enable compute.googleapis.com"
  grep -q '^aiplatform.googleapis.com' <<<"$svc" && ok "aiplatform (Vertex) API enabled" || warn "Vertex API not enabled — LLM runs need: gcloud services enable aiplatform.googleapis.com"

  if [ "$ACCESS_MODEL" = "operator-cidr" ]; then
    [ -n "${OPERATOR_SSH_CIDR:-}" ] && ok "operator SSH CIDR set" || { warn "ACCESS_MODEL=operator-cidr but OPERATOR_SSH_CIDR is empty"; fail=1; }
  else
    ok "access model IAP (no public app ingress)"
  fi

  # Local secret material that sentinel-charter-up.sh will require on the VM.
  [ -f "$REPO_ROOT/infra/.env" ] && ok "local infra/.env present (will be synced)" || warn "local infra/.env missing — create it before 'up' (see infra/.env.example)"
  { [ -f "$REPO_ROOT/infra/defectdojo-db/certs/ca.crt" ] && [ -f "$REPO_ROOT/infra/defectdojo-db/certs/server.crt" ]; } \
    && ok "DefectDojo certs present" || warn "DefectDojo certs missing under infra/defectdojo-db/certs (ca.crt, server.crt)"

  [ "$fail" -eq 0 ] && log "preflight OK" || die "preflight found blocking gaps (see WARN/FATAL above)"
}

# --------------------------------------------------------------------------
cmd_provision() {
  need_gcloud; load_config
  local net_tag="$NETWORK_TAG"

  if [ "$ACCESS_MODEL" = "iap" ]; then
    # Allow IAP SSH at higher precedence (lower number) than the world-SSH deny.
    if ! "${GC[@]}" compute firewall-rules describe "sentinel-allow-iap-ssh" >/dev/null 2>&1; then
      log "creating firewall rule sentinel-allow-iap-ssh (tcp:22 from IAP range only, priority 800)"
      "${GC[@]}" compute firewall-rules create sentinel-allow-iap-ssh \
        --direction=INGRESS --action=ALLOW --rules=tcp:22 --priority=800 \
        --source-ranges=35.235.240.0/20 --target-tags="$net_tag"
    else ok "firewall sentinel-allow-iap-ssh exists"; fi
    # The default VPC ships default-allow-ssh (tcp:22 from 0.0.0.0/0, all instances).
    # Do NOT delete that shared rule; instead deny world SSH for THIS tag only, so a
    # tagged VM is reachable via IAP but not the public internet. Deny at priority
    # 900 sits below the IAP allow (800) so IAP still wins.
    if ! "${GC[@]}" compute firewall-rules describe "sentinel-deny-public-ssh" >/dev/null 2>&1; then
      log "creating firewall rule sentinel-deny-public-ssh (deny tcp:22 from 0.0.0.0/0, tag-scoped, priority 900)"
      "${GC[@]}" compute firewall-rules create sentinel-deny-public-ssh \
        --direction=INGRESS --action=DENY --rules=tcp:22 --priority=900 \
        --source-ranges=0.0.0.0/0 --target-tags="$net_tag"
    else ok "firewall sentinel-deny-public-ssh exists"; fi
  else
    [ -n "${OPERATOR_SSH_CIDR:-}" ] || die "operator-cidr access requires OPERATOR_SSH_CIDR"
    [ "$OPERATOR_SSH_CIDR" != "0.0.0.0/0" ] || die "OPERATOR_SSH_CIDR must not be 0.0.0.0/0 (that opens SSH to the world)"
    if ! "${GC[@]}" compute firewall-rules describe "sentinel-allow-operator-ssh" >/dev/null 2>&1; then
      log "creating firewall rule sentinel-allow-operator-ssh (tcp:22 from $OPERATOR_SSH_CIDR)"
      "${GC[@]}" compute firewall-rules create sentinel-allow-operator-ssh \
        --direction=INGRESS --action=ALLOW --rules=tcp:22 \
        --source-ranges="$OPERATOR_SSH_CIDR" --target-tags="$net_tag"
    else ok "firewall sentinel-allow-operator-ssh exists"; fi
  fi
  log "NOTE: no firewall rule opens any app port. Juice Shop/Kong/etc stay loopback-only."

  if vm_exists; then
    ok "VM $VM_NAME already exists"
    return 0
  fi

  local sa_args=()
  if [ -n "${SERVICE_ACCOUNT_EMAIL:-}" ]; then
    sa_args=(--service-account="$SERVICE_ACCOUNT_EMAIL" --scopes="${SERVICE_ACCOUNT_SCOPES:-https://www.googleapis.com/auth/cloud-platform}")
  else
    sa_args=(--scopes="${SERVICE_ACCOUNT_SCOPES:-https://www.googleapis.com/auth/cloud-platform}")
  fi

  log "creating VM $VM_NAME ($MACHINE_TYPE, $BOOT_DISK_SIZE)"
  "${GC[@]}" compute instances create "$VM_NAME" \
    --zone="$ZONE" \
    --machine-type="${MACHINE_TYPE:-e2-standard-4}" \
    --image-family="${IMAGE_FAMILY:-ubuntu-2404-lts-amd64}" \
    --image-project="${IMAGE_PROJECT:-ubuntu-os-cloud}" \
    --boot-disk-size="${BOOT_DISK_SIZE:-60GB}" \
    --boot-disk-type="${BOOT_DISK_TYPE:-pd-balanced}" \
    --tags="$net_tag" \
    --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring \
    "${sa_args[@]}"
  ok "VM created"
}

# --------------------------------------------------------------------------
cmd_sync() {
  need_gcloud; load_config
  vm_exists || die "VM $VM_NAME does not exist — run: deploy.sh provision"
  local ssh_flag=""; [ "$ACCESS_MODEL" = "iap" ] && ssh_flag="--tunnel-through-iap"

  log "ensuring $REMOTE_REPO_DIR exists on the VM"
  # shellcheck disable=SC2086
  ssh_vm $ssh_flag --command "sudo mkdir -p '$REMOTE_REPO_DIR' && sudo chown \"\$(id -un)\":\"\$(id -gn)\" '$REMOTE_REPO_DIR'"

  log "copying working tree via scp (INCLUDES infra/.env + certs; out-of-band, not git)"
  # shellcheck disable=SC2086
  "${GC[@]}" compute scp --recurse --zone "$ZONE" $ssh_flag \
    --compress \
    "$REPO_ROOT"/{agent,scanners,rag,infra,scripts,evaluation,attack-surface,adapters,requirements.txt,pytest.ini,README.md,AGENTS.md} \
    "$VM_NAME":"$REMOTE_REPO_DIR"/ \
    || die "scp failed"
  ok "repo synced to $REMOTE_REPO_DIR"
  warn "infra/.env and infra/defectdojo-db/certs were transferred directly (not via git). Verify with: deploy.sh status"
}

# --------------------------------------------------------------------------
cmd_bootstrap() {
  need_gcloud; load_config
  vm_exists || die "VM $VM_NAME does not exist — run: deploy.sh provision"
  local ssh_flag=""; [ "$ACCESS_MODEL" = "iap" ] && ssh_flag="--tunnel-through-iap"
  log "installing Docker + creating dd-net on the VM"
  # shellcheck disable=SC2086
  ssh_vm $ssh_flag --command "REMOTE_REPO_DIR='$REMOTE_REPO_DIR' bash -s" < "$HERE/remote-bootstrap.sh"
  ok "bootstrap complete"
}

# --------------------------------------------------------------------------
cmd_up() {
  need_gcloud; load_config
  vm_exists || die "VM $VM_NAME does not exist"
  local ssh_flag=""; [ "$ACCESS_MODEL" = "iap" ] && ssh_flag="--tunnel-through-iap"
  log "bringing up the Charter topology on the VM"
  # shellcheck disable=SC2086
  ssh_vm $ssh_flag --command "cd '$REMOTE_REPO_DIR' && bash scripts/sentinel-charter-up.sh"
  ok "topology start requested (this is not a Charter run)"
}

# --------------------------------------------------------------------------
cmd_status() {
  need_gcloud; load_config
  if vm_exists; then
    "${GC[@]}" compute instances describe "$VM_NAME" --zone "$ZONE" \
      --format='value(name,status,machineType.scope(machineTypes),networkInterfaces[0].networkIP)'
    local ssh_flag=""; [ "$ACCESS_MODEL" = "iap" ] && ssh_flag="--tunnel-through-iap"
    # shellcheck disable=SC2086
    ssh_vm $ssh_flag --command "docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' 2>/dev/null || echo 'docker not ready'"
  else
    warn "VM $VM_NAME does not exist"
  fi
}

# --------------------------------------------------------------------------
cmd_tunnel() {
  need_gcloud; load_config
  vm_exists || die "VM $VM_NAME does not exist"
  local ssh_flag=""; [ "$ACCESS_MODEL" = "iap" ] && ssh_flag="--tunnel-through-iap"
  log "opening local forwards: 8080=DefectDojo 3001=Langfuse 13000=Juice Shop (view-only) 18443=Kong"
  log "Ctrl-C to close. These bind to YOUR localhost only; the VM stays private."
  # shellcheck disable=SC2086
  ssh_vm $ssh_flag -- \
    -L 8080:127.0.0.1:8080 \
    -L 3001:127.0.0.1:3001 \
    -L 13000:127.0.0.1:13000 \
    -L 18443:127.0.0.1:18443 \
    -N
}

# --------------------------------------------------------------------------
cmd_teardown() {
  need_gcloud; load_config
  # Guard against deleting the wrong instance from a stale config.env. Require an
  # explicit confirmation matching the VM name (env var or interactive prompt).
  if [ "${SENTINEL_GCP_CONFIRM:-}" != "$VM_NAME" ]; then
    if [ -t 0 ]; then
      printf 'Type the VM name to confirm deletion of "%s": ' "$VM_NAME"; read -r reply
      [ "$reply" = "$VM_NAME" ] || die "confirmation mismatch; aborting teardown"
    else
      die "refusing to teardown non-interactively without SENTINEL_GCP_CONFIRM=$VM_NAME"
    fi
  fi
  if vm_exists; then
    log "deleting VM $VM_NAME"
    "${GC[@]}" compute instances delete "$VM_NAME" --zone "$ZONE" --quiet
    ok "VM deleted"
  else warn "VM $VM_NAME already absent"; fi
  if [ "${1:-}" = "--all" ]; then
    for r in sentinel-allow-iap-ssh sentinel-deny-public-ssh sentinel-allow-operator-ssh; do
      if "${GC[@]}" compute firewall-rules describe "$r" >/dev/null 2>&1; then
        "${GC[@]}" compute firewall-rules delete "$r" --quiet && ok "firewall $r deleted"
      fi
    done
  fi
}

# --------------------------------------------------------------------------
main() {
  local cmd="${1:-}"; shift || true
  case "$cmd" in
    preflight) cmd_preflight ;;
    provision) cmd_provision ;;
    sync)      cmd_sync ;;
    bootstrap) cmd_bootstrap ;;
    up)        cmd_up ;;
    status)    cmd_status ;;
    tunnel)    cmd_tunnel ;;
    teardown)  cmd_teardown "$@" ;;
    all)       cmd_preflight; cmd_provision; cmd_sync; cmd_bootstrap; cmd_up; cmd_status ;;
    ""|-h|--help)
      sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' ;;
    *) die "unknown command: $cmd (try: preflight provision sync bootstrap up status tunnel teardown all)" ;;
  esac
}
main "$@"
