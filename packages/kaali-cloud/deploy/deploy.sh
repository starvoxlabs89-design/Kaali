#!/usr/bin/env bash
# Kaali Cloud one-shot deploy — RUN THIS ON YOUR VPS as a sudoer.
# Idempotent: safe to re-run.
#
#   curl -fsSL https://raw.githubusercontent.com/starvoxlabs89-design/kaali/main/packages/kaali-cloud/deploy/deploy.sh | sudo bash
# or after `git clone` on the VPS:
#   cd kaali/packages/kaali-cloud && sudo bash deploy/deploy.sh

set -euo pipefail

# --- 0. Config ---------------------------------------------------------------
REPO_URL="${REPO_URL:-https://github.com/starvoxlabs89-design/kaali.git}"
INSTALL_DIR="${INSTALL_DIR:-/opt/kaali}"
SVC_USER="${SVC_USER:-kaali}"
API_HOST="${API_HOST:-api.kaali.io}"
APP_HOST="${APP_HOST:-app.kaali.io}"
DB_NAME="${DB_NAME:-kaali}"
DB_USER="${DB_USER:-kaali}"

step() { printf "\n\033[1;36m➤ %s\033[0m\n" "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

# --- 1. Packages -------------------------------------------------------------
step "Installing packages (nodejs 20, postgres, nginx, certbot)"
if ! have node || [[ "$(node -v)" != v20.* && "$(node -v)" != v21.* && "$(node -v)" != v22.* ]]; then
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  apt-get install -y nodejs
fi
apt-get install -y postgresql nginx certbot python3-certbot-nginx git

# --- 2. User + code ----------------------------------------------------------
step "Creating service user + fetching code"
id -u "$SVC_USER" >/dev/null 2>&1 || useradd -r -m -d "$INSTALL_DIR" -s /bin/bash "$SVC_USER"
mkdir -p "$INSTALL_DIR"
if [[ ! -d "$INSTALL_DIR/kaali/.git" ]]; then
  sudo -u "$SVC_USER" git clone "$REPO_URL" "$INSTALL_DIR/kaali"
else
  sudo -u "$SVC_USER" git -C "$INSTALL_DIR/kaali" pull --ff-only
fi

APP_DIR="$INSTALL_DIR/kaali/packages/kaali-cloud"
sudo -u "$SVC_USER" bash -lc "cd '$APP_DIR' && npm install --omit=dev --silent"

# --- 3. Postgres -------------------------------------------------------------
step "Configuring Postgres role + database"
if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='$DB_USER'" | grep -q 1; then
  DB_PASS=$(openssl rand -hex 24)
  sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';"
  echo "DB_PASS=$DB_PASS" > "$APP_DIR/.db_credentials"
  chown "$SVC_USER:$SVC_USER" "$APP_DIR/.db_credentials"
  chmod 600 "$APP_DIR/.db_credentials"
  echo "  → generated DB password saved to $APP_DIR/.db_credentials"
fi
if ! sudo -u postgres psql -lqt | cut -d\| -f1 | grep -qw "$DB_NAME"; then
  sudo -u postgres createdb -O "$DB_USER" "$DB_NAME"
fi

step "Applying migrations"
for f in "$APP_DIR"/migrations/*.sql; do
  echo "  applying $(basename "$f")"
  sudo -u postgres psql -d "$DB_NAME" -f "$f" >/dev/null
done

# --- 4. .env -----------------------------------------------------------------
step "Ensuring .env"
if [[ ! -f "$APP_DIR/.env" ]]; then
  DB_PASS_LINE=$(cat "$APP_DIR/.db_credentials" 2>/dev/null || echo "DB_PASS=CHANGE_ME")
  DB_PASS_VAL=${DB_PASS_LINE#DB_PASS=}
  cat > "$APP_DIR/.env" <<EOF
PORT=4842
PUBLIC_URL=https://$API_HOST
DASHBOARD_URL=https://$APP_HOST
DATABASE_URL=postgres://$DB_USER:$DB_PASS_VAL@127.0.0.1:5432/$DB_NAME
SESSION_SECRET=$(openssl rand -hex 32)
CSRF_SECRET=$(openssl rand -hex 32)
COOKIE_SECURE=1

# Fill these before restart:
RESEND_API_KEY=
EMAIL_FROM=Kaali <noreply@$API_HOST>
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
META_APP_ID=
META_APP_SECRET=
EOF
  chown "$SVC_USER:$SVC_USER" "$APP_DIR/.env"
  chmod 600 "$APP_DIR/.env"
  echo "  → generated $APP_DIR/.env — edit RESEND_API_KEY + OAuth keys, then re-run OR restart service."
else
  echo "  → $APP_DIR/.env exists, leaving alone"
fi

# --- 5. systemd --------------------------------------------------------------
step "Installing systemd unit"
sed "s|/opt/kaali/kaali-cloud|$APP_DIR|g" "$APP_DIR/deploy/kaali-cloud.service" > /etc/systemd/system/kaali-cloud.service
systemctl daemon-reload
systemctl enable kaali-cloud >/dev/null

# --- 6. nginx ----------------------------------------------------------------
step "Installing nginx site"
sed -e "s|api.kaali.io|$API_HOST|g" -e "s|app.kaali.io|$APP_HOST|g" \
  "$APP_DIR/deploy/nginx.conf" > /etc/nginx/sites-available/kaali.conf
ln -sfn /etc/nginx/sites-available/kaali.conf /etc/nginx/sites-enabled/kaali.conf
nginx -t
systemctl reload nginx

# --- 7. Start ----------------------------------------------------------------
step "Starting kaali-cloud"
systemctl restart kaali-cloud
sleep 2
if systemctl is-active --quiet kaali-cloud; then
  echo "  ✓ kaali-cloud is running on 127.0.0.1:4842"
else
  echo "  ✗ kaali-cloud failed to start — check: journalctl -u kaali-cloud -n 50"
  exit 1
fi

# --- 8. TLS (optional, only if DNS resolves) ---------------------------------
step "TLS (certbot). Requires DNS pointing to this box."
if getent hosts "$API_HOST" >/dev/null 2>&1; then
  certbot --nginx -d "$API_HOST" -d "$APP_HOST" --non-interactive --agree-tos \
    -m "hello@$API_HOST" --redirect || echo "  certbot failed — you can rerun it later."
else
  echo "  → DNS for $API_HOST not resolving yet. After DNS propagates, run:"
  echo "     sudo certbot --nginx -d $API_HOST -d $APP_HOST"
fi

# --- 9. Done -----------------------------------------------------------------
cat <<EOF

✅ Done.

Next steps for you:
 1. Edit  $APP_DIR/.env  and set RESEND_API_KEY, GOOGLE_CLIENT_ID/SECRET, META_APP_ID/SECRET.
 2. Restart:  sudo systemctl restart kaali-cloud
 3. Point DNS: $API_HOST + $APP_HOST → this VPS.
 4. If not done: sudo certbot --nginx -d $API_HOST -d $APP_HOST
 5. Test signup at:  https://$APP_HOST/
 6. Watch logs:  sudo journalctl -u kaali-cloud -f
EOF
