#!/usr/bin/env bash
# Runs ON the VM (piped in by deploy.sh bootstrap). Installs Docker Engine +
# Compose plugin, enables the daemon, adds the login user to the docker group,
# and creates the dd-net network that scripts/sentinel-charter-up.sh requires.
# Idempotent: safe to re-run.
set -euo pipefail

REMOTE_REPO_DIR="${REMOTE_REPO_DIR:-/opt/sentinel/vinsoc}"

log() { printf '[vm-bootstrap] %s\n' "$*"; }

if ! command -v docker >/dev/null 2>&1; then
  log "installing Docker Engine + Compose plugin"
  curl -fsSL https://get.docker.com | sudo sh
else
  log "docker already installed: $(docker --version)"
fi

if ! docker compose version >/dev/null 2>&1; then
  log "installing docker compose plugin via apt"
  sudo apt-get update -y && sudo apt-get install -y docker-compose-plugin
fi

sudo systemctl enable --now docker

# python3-venv lets an operator reproduce the slim grader ritual on the VM
# (python3 -m venv .venv; pytest ...). Ubuntu server images ship python3 without
# ensurepip/venv by default.
if ! python3 -c 'import ensurepip' >/dev/null 2>&1; then
  log "installing python3-venv (ensurepip) for grader reproducibility"
  sudo apt-get update -y && sudo apt-get install -y python3-venv
fi

# Let the login user talk to docker without sudo. Group membership takes effect
# on the next login/SSH session, so deploy.sh up re-connects fresh.
if ! id -nG "$(id -un)" | tr ' ' '\n' | grep -qx docker; then
  log "adding $(id -un) to the docker group (effective next SSH session)"
  sudo usermod -aG docker "$(id -un)"
fi

# Defense in depth: block containers (esp. the deliberately-vulnerable Juice
# Shop) from reaching the GCP metadata server. Even with no VM service account,
# this closes the SSRF -> metadata path for any future SA. Persisted via systemd
# so it survives reboots (docker recreates DOCKER-USER on start).
if [ ! -f /etc/systemd/system/sentinel-metadata-guard.service ]; then
  log "installing sentinel-metadata-guard (block container egress to 169.254.169.254)"
  sudo tee /etc/systemd/system/sentinel-metadata-guard.service >/dev/null <<'UNIT'
[Unit]
Description=Sentinel: block container egress to GCP metadata (169.254.169.254)
After=docker.service
Requires=docker.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c "/sbin/iptables -C DOCKER-USER -d 169.254.169.254 -j DROP 2>/dev/null || /sbin/iptables -I DOCKER-USER 1 -d 169.254.169.254 -j DROP"
[Install]
WantedBy=multi-user.target
UNIT
  sudo systemctl daemon-reload
  sudo systemctl enable --now sentinel-metadata-guard.service || true
fi

# Charter launcher precondition: an external dd-net bridge network.
if ! sudo docker network inspect dd-net >/dev/null 2>&1; then
  log "creating dd-net docker network"
  sudo docker network create dd-net
else
  log "dd-net already present"
fi

log "verifying repo landed at $REMOTE_REPO_DIR"
if [ -f "$REMOTE_REPO_DIR/scripts/sentinel-charter-up.sh" ]; then
  log "repo OK"
else
  log "WARNING: $REMOTE_REPO_DIR/scripts/sentinel-charter-up.sh not found — run deploy.sh sync"
fi

log "bootstrap done. Next on operator machine: deploy.sh up"
