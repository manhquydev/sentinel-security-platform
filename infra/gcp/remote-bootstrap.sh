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

# Let the login user talk to docker without sudo. Group membership takes effect
# on the next login/SSH session, so deploy.sh up re-connects fresh.
if ! id -nG "$(id -un)" | tr ' ' '\n' | grep -qx docker; then
  log "adding $(id -un) to the docker group (effective next SSH session)"
  sudo usermod -aG docker "$(id -un)"
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
