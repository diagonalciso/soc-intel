#!/bin/bash
set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE_NAME="socint"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
USER_NAME="$(whoami)"

echo "=== SOCINT Service Installer ==="
echo "Project: $PROJECT_DIR"
echo "User:    $USER_NAME"
echo ""

# ── Install Docker if missing ────────────────────────────────────
if ! command -v docker &>/dev/null; then
  echo "[1/4] Installing Docker..."
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl gnupg lsb-release
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
  systemctl enable --now docker
  echo "    Docker installed."
else
  echo "[1/4] Docker already installed: $(docker --version)"
fi

# ── Add user to docker group ──────────────────────────────────────
if ! groups "$USER_NAME" | grep -q docker; then
  echo "[2/4] Adding $USER_NAME to docker group..."
  usermod -aG docker "$USER_NAME"
  echo "    Done. Re-login required for group to take effect in interactive sessions."
else
  echo "[2/4] User already in docker group."
fi

# ── Create .env if missing ───────────────────────────────────────
if [ ! -f "$PROJECT_DIR/.env" ]; then
  echo "[3/4] Creating .env..."
  cp "$PROJECT_DIR/.env.example" "$PROJECT_DIR/.env"
  SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
  sed -i "s/change-me-to-a-long-random-string/$SECRET/" "$PROJECT_DIR/.env"
else
  echo "[3/4] .env already exists."
fi

# ── Write systemd service file ───────────────────────────────────
echo "[4/4] Installing systemd service: $SERVICE_FILE"

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=SOCINT Threat Intelligence Platform
Documentation=https://github.com/openclaw/socint
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
User=root
WorkingDirectory=${PROJECT_DIR}
EnvironmentFile=${PROJECT_DIR}/.env

ExecStartPre=/usr/bin/docker compose pull --quiet
ExecStart=/usr/bin/docker compose up -d --remove-orphans
ExecStop=/usr/bin/docker compose down
ExecReload=/usr/bin/docker compose restart

TimeoutStartSec=300
TimeoutStopSec=120

StandardOutput=journal
StandardError=journal
SyslogIdentifier=socint

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"

echo ""
echo "=== Installation complete ==="
echo ""
echo "Commands:"
echo "  Start:   systemctl start socint"
echo "  Stop:    systemctl stop socint"
echo "  Status:  systemctl status socint"
echo "  Logs:    journalctl -u socint -f"
echo ""
echo "Starting SOCINT now..."
systemctl start "$SERVICE_NAME"
echo ""
systemctl status "$SERVICE_NAME" --no-pager
echo ""
echo "  Frontend:  http://0.0.0.0:3000"
echo "  API docs:  http://0.0.0.0:8000/api/docs"
