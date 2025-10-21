#!/usr/bin/env bash
#
# deploy.sh
# A robust idempotent deployment script implementing the "Internal Requirements Matrix".
#
# Features:
#  - Collects inputs (repo, PAT, branch, SSH key, remote host/user, remote dir, app port)
#  - Clones/updates repo using PAT (token embedded safely during clone)
#  - Verifies Dockerfile / docker-compose.yml
#  - Checks SSH connectivity
#  - Prepares remote server (installs Docker, docker-compose via compose plugin, nginx)
#  - Transfers project via rsync (excludes and --delete)
#  - Builds/runs containers (docker compose preferred, otherwise docker build/run)
#  - Configures nginx reverse proxy 80 -> app port (placeholder for certbot)
#  - Validation checks (docker status, container up, remote curl probe)
#  - Logging, error codes, cleanup, idempotency
#
# Usage:
#   ./deploy.sh               # interactive
#   ./deploy.sh --repo <git-url> --pat <PAT> --host user@host --key /path/key --remote-dir /opt/app --branch main --port 3000
#   ./deploy.sh --cleanup --host user@host --key /path/key --remote-dir /opt/app
#

set -o errexit
set -o pipefail
set -o nounset

############
# CONFIG
############
SCRIPT_NAME="$(basename "$0")"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
LOG_DIR="./logs"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/deploy_${TIMESTAMP}.log"

# Defaults
DEFAULT_BRANCH="main"
RSYNC_EXCLUDES=(--exclude .git --exclude .env --exclude node_modules --exclude vendor)
SSH_OPTS_COMMON="-o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new"

# Exit codes
E_BAD_ARGS=2
E_SSH_FAIL=10
E_GIT_FAIL=11
E_FILE_MISSING=12
E_RSYNC_FAIL=13
E_REMOTE_CMD_FAIL=14
E_DEPLOY_FAIL=15
E_VALIDATION_FAIL=16

############
# Logging helpers
############
log() {
  local lvl="$1"; shift
  local msg="$*"
  echo "[$(date +'%Y-%m-%d %H:%M:%S')] [$lvl] $msg" | tee -a "$LOG_FILE"
}
info()  { log "INFO" "$*"; }
warn()  { log "WARN" "$*"; }
err()   { log "ERROR" "$*"; }

on_exit() {
  rc=$?
  if [ $rc -ne 0 ]; then
    err "Script exited with code $rc. See log: $LOG_FILE"
  else
    info "Script finished successfully."
  fi
}
trap on_exit EXIT

############
# Helpers
############
prompt() {
  local varname="$1"
  local prompt_text="$2"
  local default="${3:-}"
  local hide="${4:-false}"

  if [ "$hide" = "true" ]; then
    read -r -s -p "$prompt_text" val
    echo
  else
    read -r -p "$prompt_text" val
  fi
  if [ -z "$val" ]; then
    echo "$default"
  else
    echo "$val"
  fi
}

mask_token() {
  # display a masked PAT for logs
  local token="$1"
  if [ -z "$token" ]; then echo ""; return; fi
  local head="${token:0:4}"
  local tail="${token: -4}"
  echo "${head}...${tail}"
}

usage() {
  cat <<EOF
Usage: $SCRIPT_NAME [options]

Options:
  --repo <git-url>        Repository HTTPS URL (e.g. https://github.com/owner/repo.git)
  --pat <PAT>             GitHub Personal Access Token (used to clone)
  --branch <branch>       Branch to deploy (default: $DEFAULT_BRANCH)
  --host <user@host>      Remote SSH target
  --key <ssh-key-path>    SSH private key for remote access
  --remote-dir <path>     Remote path to deploy into (default: /opt/app)
  --local-dir <path>      Local clone directory (default: ./app)
  --port <app-port>       Application port on remote (default: 3000)
  --cleanup               Perform remote cleanup (remove containers, nginx site, project dir)
  -h|--help               Show this help
EOF
  exit $E_BAD_ARGS
}

############
# Parse args (basic)
############
# positional defaults
REPO_URL=""
PAT=""
BRANCH="$DEFAULT_BRANCH"
REMOTE_HOST=""
SSH_KEY=""
REMOTE_DIR="/opt/app"
LOCAL_REPO_DIR="./app"
APP_PORT=3000
DO_CLEANUP=false

# Simple args loop
while [ $# -gt 0 ]; do
  case "$1" in
    --repo) REPO_URL="$2"; shift 2;;
    --pat) PAT="$2"; shift 2;;
    --branch) BRANCH="$2"; shift 2;;
    --host) REMOTE_HOST="$2"; shift 2;;
    --key) SSH_KEY="$2"; shift 2;;
    --remote-dir) REMOTE_DIR="$2"; shift 2;;
    --local-dir) LOCAL_REPO_DIR="$2"; shift 2;;
    --port) APP_PORT="$2"; shift 2;;
    --cleanup) DO_CLEANUP=true; shift;;
    -h|--help) usage;;
    *) warn "Unknown arg: $1"; usage;;
  esac
done

############
# Interactive prompts if missing
############
if [ -z "$REPO_URL" ]; then
  REPO_URL="$(prompt REPO_URL "Repo HTTPS URL (e.g. https://github.com/owner/repo.git): " )"
fi

if [ -z "$PAT" ]; then
  PAT="$(prompt PAT "GitHub Personal Access Token (input hidden): " "" true)"
fi

if [ -z "$REMOTE_HOST" ]; then
  REMOTE_HOST="$(prompt REMOTE_HOST "Remote host (user@host): ")"
fi

if [ -z "$SSH_KEY" ]; then
  SSH_KEY="$(prompt SSH_KEY "Path to SSH private key (e.g. ~/.ssh/id_rsa): " "~/.ssh/id_rsa")"
fi

if [ -z "$REMOTE_DIR" ]; then
  REMOTE_DIR="$(prompt REMOTE_DIR "Remote directory to deploy into: " "/opt/app")"
fi

if [ -z "$LOCAL_REPO_DIR" ]; then
  LOCAL_REPO_DIR="$(prompt LOCAL_REPO_DIR "Local directory for clone: " "./app")"
fi

if [ -z "$APP_PORT" ]; then
  APP_PORT="$(prompt APP_PORT "Internal app port (container listens on): " "3000")"
fi

# Expand tilde in ssh key
SSH_KEY="${SSH_KEY/#\~/$HOME}"

info "Starting deployment. Log: $LOG_FILE"
info "Repo: $REPO_URL"
info "Repo branch: $BRANCH"
info "Remote: $REMOTE_HOST:$REMOTE_DIR"
info "Local dir: $LOCAL_REPO_DIR"
info "App port: $APP_PORT"
info "Masked PAT: $(mask_token "$PAT")"

############
# Sanity checks
############
if [ ! -f "$SSH_KEY" ]; then
  err "SSH key not found at $SSH_KEY"
  exit $E_FILE_MISSING
fi

if [ -z "$REPO_URL" ] || [ -z "$PAT" ]; then
  err "Repo URL and PAT are required."
  exit $E_BAD_ARGS
fi

############
# Functions implementing tasks
############

check_ssh_connectivity() {
  info "Checking SSH connectivity to $REMOTE_HOST..."
  if ssh -i "$SSH_KEY" $SSH_OPTS_COMMON "$REMOTE_HOST" "echo connected" &>> "$LOG_FILE"; then
    info "SSH connectivity OK"
  else
    err "SSH connection to $REMOTE_HOST failed."
    exit $E_SSH_FAIL
  fi
}

clone_or_update_repo() {
  info "Cloning or updating repository in $LOCAL_REPO_DIR..."
  # If dir exists and is a git repo -> fetch & checkout branch
  if [ -d "$LOCAL_REPO_DIR/.git" ]; then
    info "Existing repo found. Fetching and resetting to remote..."
    pushd "$LOCAL_REPO_DIR" >/dev/null
    git fetch origin "$BRANCH" &>> "$LOG_FILE" || { err "git fetch failed"; exit $E_GIT_FAIL; }
    git checkout "$BRANCH" &>> "$LOG_FILE" || { err "git checkout failed"; exit $E_GIT_FAIL; }
    git pull origin "$BRANCH" &>> "$LOG_FILE" || { err "git pull failed"; exit $E_GIT_FAIL; }
    popd >/dev/null
    return
  fi

  # Build token-embedded URL but avoid logging the token
  # Convert https://github.com/owner/repo.git -> https://<PAT>@github.com/owner/repo.git
  local token_url
  token_url="${REPO_URL/https:\/\//https:\/\/$PAT@}"

  # Clone
  git clone --branch "$BRANCH" "$token_url" "$LOCAL_REPO_DIR" &>> "$LOG_FILE" || {
    err "git clone failed"
    exit $E_GIT_FAIL
  }

  # Reset origin URL to the standard HTTPS URL without PAT to avoid storing token
  pushd "$LOCAL_REPO_DIR" >/dev/null
  git remote set-url origin "$REPO_URL" &>> "$LOG_FILE" || warn "Failed to reset origin URL (non-fatal)"
  popd >/dev/null
  info "Repo cloned into $LOCAL_REPO_DIR"
}

verify_project_files() {
  info "Verifying presence of Dockerfile or docker-compose.yml..."
  if [ -f "$LOCAL_REPO_DIR/Dockerfile" ]; then
    info "Dockerfile found."
    return 0
  fi
  if [ -f "$LOCAL_REPO_DIR/docker-compose.yml" ] || [ -f "$LOCAL_REPO_DIR/docker-compose.yaml" ]; then
    info "docker-compose file found."
    return 0
  fi
  err "Neither Dockerfile nor docker-compose.yml found in $LOCAL_REPO_DIR"
  exit $E_FILE_MISSING
}

remote_prepare() {
  info "Preparing remote server: installing Docker, docker compose plugin, nginx if needed..."

  # Prepare a here-doc script to run remotely (idempotent)
  ssh -i "$SSH_KEY" $SSH_OPTS_COMMON "$REMOTE_HOST" bash -s -- "$REMOTE_DIR" "$USER" <<'REMOTE_SCRIPT' >>"$LOG_FILE" 2>&1
set -o errexit
set -o pipefail

REMOTE_DIR="$1"
LOCAL_USER="$2"

# Detect package manager and install prerequisites
if command -v apt-get >/dev/null 2>&1; then
  PM="apt"
  sudo apt-get update -y
  sudo apt-get install -y ca-certificates curl gnupg lsb-release
  # Docker install (get.docker.com)
  curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
  sudo sh /tmp/get-docker.sh
  sudo systemctl enable --now docker
elif command -v yum >/dev/null 2>&1; then
  PM="yum"
  sudo yum install -y yum-utils
  curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
  sudo sh /tmp/get-docker.sh
  sudo systemctl enable --now docker
else
  echo "Unsupported package manager. Please install docker manually." >&2
  exit 1
fi

# Ensure user is in docker group (may require logout/login to take effect)
if id -nG "$LOCAL_USER" | grep -qw docker; then
  echo "User in docker group"
else
  sudo usermod -aG docker "$LOCAL_USER" || true
fi

# Install nginx if missing
if ! command -v nginx >/dev/null 2>&1; then
  if [ "$PM" = "apt" ]; then
    sudo apt-get install -y nginx
    sudo systemctl enable --now nginx
  elif [ "$PM" = "yum" ]; then
    sudo yum install -y nginx
    sudo systemctl enable --now nginx
  fi
fi

# Create remote dir with proper perms
sudo mkdir -p "$REMOTE_DIR"
sudo chown "$LOCAL_USER":"$LOCAL_USER" "$REMOTE_DIR"
echo "remote_prepare_done"
REMOTE_SCRIPT

  info "Remote preparation complete (Docker/nginx ensured)."
}

transfer_project() {
  info "Transferring project to remote using rsync..."
  # Ensure local dir exists
  if [ ! -d "$LOCAL_REPO_DIR" ]; then
    err "Local repo dir $LOCAL_REPO_DIR missing"
    exit $E_FILE_MISSING
  fi

  # Build rsync ssh option
  RSYNC_SSH="ssh -i '$SSH_KEY' $SSH_OPTS_COMMON -o IdentitiesOnly=yes"
  # Use --delete to sync exact state
  rsync -avz --delete "${RSYNC_EXCLUDES[@]}" -e "$RSYNC_SSH" "$LOCAL_REPO_DIR"/ "$REMOTE_HOST":"$REMOTE_DIR"/ &>> "$LOG_FILE" || {
    err "rsync to remote failed"
    exit $E_RSYNC_FAIL
  }
  info "Project files transferred."
}

remote_deploy_app() {
  info "Deploying application on remote..."

  # Determine whether to use docker compose or single Dockerfile
  ssh -i "$SSH_KEY" $SSH_OPTS_COMMON "$REMOTE_HOST" bash -s -- "$REMOTE_DIR" "$APP_PORT" <<'REMOTE_DEPLOY' >>"$LOG_FILE" 2>&1
set -o errexit
set -o pipefail
REMOTE_DIR="$1"
APP_PORT="$2"
cd "$REMOTE_DIR"

# Stop and remove old containers by label or name (safe idempotent attempt)
# Try docker compose first
if [ -f docker-compose.yml ] || [ -f docker-compose.yaml ]; then
  echo "Detected docker-compose file; using docker compose up -d --build"
  # Remove old compose stack if present
  if docker compose ls --format json 2>/dev/null | grep -q .; then
    # best-effort: not forcibly removing all stacks; rely on compose up to recreate
    true
  fi
  docker compose pull || true
  docker compose up -d --build
else
  if [ -f Dockerfile ]; then
    # Name the image by directory name + timestamp
    IMG_NAME="app_deploy_$(date +%s)"
    # Stop and remove containers that were created with previous image name patterns (best-effort)
    docker ps -a --format '{{.ID}} {{.Image}} {{.Names}}' | grep app_deploy_ || true
    docker build -t "$IMG_NAME" .
    # Stop and remove existing container named app_container if exists
    if docker ps -a --format '{{.Names}}' | grep -q '^app_container$'; then
      docker rm -f app_container || true
    fi
    # Run container mapping host port to container port
    docker run -d --name app_container -p 127.0.0.1:${APP_PORT}:${APP_PORT} "$IMG_NAME" || (echo "docker run failed" >&2; exit 1)
  else
    echo "No Dockerfile or compose file found" >&2
    exit 1
  fi
fi

# Wait a bit for container(s) to start
sleep 3

# Print docker ps for validation logs
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}' || true

echo "remote_deploy_done"
REMOTE_DEPLOY

  info "Remote deploy command finished."
}

configure_nginx() {
  info "Configuring nginx on remote to reverse proxy 80 -> 127.0.0.1:$APP_PORT"

  local site_name
  site_name="$(basename "$REMOTE_DIR")"

  # Create nginx config via heredoc pushed through SSH (idempotent)
  ssh -i "$SSH_KEY" $SSH_OPTS_COMMON "$REMOTE_HOST" bash -s -- "$site_name" "$REMOTE_DIR" "$APP_PORT" <<'NGINX_CONF' >>"$LOG_FILE" 2>&1
set -o errexit
set -o pipefail
SITE_NAME="$1"
REMOTE_DIR="$2"
APP_PORT="$3"
CONF_PATH="/etc/nginx/sites-available/${SITE_NAME}.conf"
Enabled_PATH="/etc/nginx/sites-enabled/${SITE_NAME}.conf"

# Build nginx config
sudo tee "$CONF_PATH" > /dev/null <<EOF
server {
    listen 80;
    server_name _;

    location / {
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_pass http://127.0.0.1:${APP_PORT};
        proxy_read_timeout 90;
    }

    # Optional: static file serving - point to project's public dir if exists
    # root ${REMOTE_DIR}/public;
}
EOF

# Enable site by symlink
if [ -f "$Enabled_PATH" ]; then
  sudo rm -f "$Enabled_PATH"
fi
sudo ln -s "$CONF_PATH" "$Enabled_PATH" || true

# Test nginx configuration and reload
sudo nginx -t
sudo systemctl reload nginx

echo "nginx_config_done"
NGINX_CONF

  info "Nginx configured and reloaded on remote."
  info "NOTE: SSL/Certbot step intentionally left as a placeholder. You can run certbot on the remote to obtain certs."
}

validate_deployment() {
  info "Validating deployment..."

  # Check docker is active and container(s) running
  ssh -i "$SSH_KEY" $SSH_OPTS_COMMON "$REMOTE_HOST" bash -s -- "$APP_PORT" <<'REMOTE_VALIDATE' >>"$LOG_FILE" 2>&1
set -o errexit
set -o pipefail
APP_PORT="$1"

# Docker running?
if ! sudo systemctl is-active --quiet docker; then
  echo "docker_not_active" >&2
  exit 1
fi

# Basic pgrep for container listening on port
if ss -ltnp | grep -q ":${APP_PORT} "; then
  echo "port_listening"
else
  echo "port_not_listening" >&2
  exit 2
fi

# Test local curl to app
if command -v curl >/dev/null 2>&1; then
  if curl -sS "http://127.0.0.1:${APP_PORT}" >/dev/null 2>&1; then
    echo "http_ok"
  else
    echo "http_fail" >&2
    exit 3
  fi
else
  echo "curl_missing_but_port_ok"
fi
REMOTE_VALIDATE

  # Test nginx fronted (from local machine) - optional best-effort
  if curl -sS "http://${REMOTE_HOST#*@}" >/dev/null 2>&1; then
    info "Public HTTP probe OK"
  else
    warn "Public HTTP probe failed; remote local probe may have succeeded. Check DNS/port 80 reachability."
  fi

  info "Validation completed (see logs for details)."
}

remote_cleanup() {
  info "Performing remote cleanup (this will remove project dir, nginx site, containers)..."
  ssh -i "$SSH_KEY" $SSH_OPTS_COMMON "$REMOTE_HOST" bash -s -- "$REMOTE_DIR" <<'REMOTE_CLEAN' >>"$LOG_FILE" 2>&1
set -o errexit
set -o pipefail
REMOTE_DIR="$1"

# Stop and remove containers related to this directory (best-effort)
# Attempt to stop containers named app_container and remove images prefixed with app_deploy_
docker rm -f app_container || true
# Remove images with our prefix (best-effort)
docker images --format '{{.Repository}}:{{.Tag}} {{.ID}}' | awk '/app_deploy_/ {print $2}' | xargs -r docker rmi -f || true

# Remove nginx site config
SITE_NAME="$(basename "$REMOTE_DIR")"
CONF_PATH="/etc/nginx/sites-available/${SITE_NAME}.conf"
ENABLED="/etc/nginx/sites-enabled/${SITE_NAME}.conf"
sudo rm -f "$ENABLED" "$CONF_PATH" || true
sudo nginx -t || true
sudo systemctl reload nginx || true

# Remove project dir
sudo rm -rf "$REMOTE_DIR" || true

echo "remote_cleanup_done"
REMOTE_CLEAN

  info "Remote cleanup done."
}

############
# Main flow
############
# If only cleanup is requested, do that and exit
if [ "$DO_CLEANUP" = true ]; then
  check_ssh_connectivity
  remote_cleanup
  exit 0
fi

# 1. Check SSH
check_ssh_connectivity

# 2. Clone or update repo
clone_or_update_repo

# 3. Verify Dockerfile/docker-compose
verify_project_files

# 4. Prepare remote environment (docker/nginx)
remote_prepare

# 5. Transfer project files to remote
transfer_project

# 6. Deploy on remote (compose or docker build/run)
remote_deploy_app

# 7. Configure nginx to reverse proxy
configure_nginx

# 8. Validate deployment
if validate_deployment; then
  info "Deployment validation completed successfully."
else
  err "Deployment validation failed."
  exit $E_VALIDATION_FAIL
fi

info "Deployment finished. Logs: $LOG_FILE"
info "If you want HTTPS, run certbot on the remote (e.g. sudo certbot --nginx -d your.domain)."

exit 0

