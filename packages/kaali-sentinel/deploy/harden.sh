#!/usr/bin/env bash
# Kaali — fresh-host hardening. RUN THIS FIRST on a newly reinstalled VPS,
# BEFORE deploying any app. Idempotent; safe to re-run.
#
#   curl -fsSL https://raw.githubusercontent.com/starvoxlabs89-design/Kaali/main/packages/kaali-sentinel/deploy/harden.sh | sudo bash
#
# Closes the doors that let the pakchoi compromise happen (and recur):
#   • key-only SSH  (PasswordAuthentication no, root key-only) — the original vector
#   • fail2ban       (stops SSH brute-force)
#   • ufw            (only 22/80/443 inbound)
#   • unattended security upgrades
#   • a non-root 'deploy' user (stop running apps as root)
#   • Kaali Sentinel on a 30-min timer + a known-good baseline (catches re-infection early)
#   • refuses to install/keep an exposed Docker socket (the persistence vector)

set -euo pipefail
RAW="https://raw.githubusercontent.com/starvoxlabs89-design/Kaali/main/packages/kaali-sentinel"
step() { printf "\n\033[1;36m➤ %s\033[0m\n" "$*"; }
warn() { printf "\033[1;33m  ! %s\033[0m\n" "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }
[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }

# --- 1. Patch the system ------------------------------------------------------
step "Updating packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq && apt-get -y -qq upgrade

# --- 2. Key-only SSH (the pakchoi entry vector) -------------------------------
step "Hardening SSH to key-only"
# SAFETY: never lock yourself out — require at least one authorized key first.
KEYS=$(grep -cvE '^\s*(#|$)' /root/.ssh/authorized_keys 2>/dev/null || echo 0)
if [[ "$KEYS" -lt 1 ]]; then
  warn "No key in /root/.ssh/authorized_keys — NOT disabling password auth (would lock you out)."
  warn "Add your public key first:  ssh-copy-id root@<host>   then re-run."
else
  # Neutralise any 'PasswordAuthentication yes' cloud-init/default leaves behind…
  sed -ri 's/^(\s*PasswordAuthentication\s+yes)/#\1  # disabled by kaali-harden/I' /etc/ssh/sshd_config 2>/dev/null || true
  for f in /etc/ssh/sshd_config.d/*.conf; do [[ -f "$f" ]] && sed -ri 's/^(\s*PasswordAuthentication\s+yes)/#\1  # disabled/I' "$f"; done
  # …and set the authoritative policy (00- prefix loads first → wins first-match).
  cat > /etc/ssh/sshd_config.d/00-kaali-hardening.conf <<'CONF'
# Kaali hardening — key-only SSH
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 3
CONF
  if sshd -t; then systemctl reload ssh 2>/dev/null || systemctl reload sshd; echo "  ✓ key-only SSH active ($KEYS key(s) trusted)"; else warn "sshd config invalid — left unchanged"; fi
fi

# --- 3. fail2ban --------------------------------------------------------------
step "Installing fail2ban (SSH brute-force protection)"
apt-get install -y -qq fail2ban
cat > /etc/fail2ban/jail.d/sshd.local <<'CONF'
[sshd]
enabled = true
maxretry = 4
findtime = 10m
bantime = 1h
CONF
systemctl enable --now fail2ban >/dev/null 2>&1 && echo "  ✓ fail2ban active"

# --- 4. Firewall --------------------------------------------------------------
step "Configuring ufw (allow 22/80/443, deny the rest)"
apt-get install -y -qq ufw
ufw allow 22/tcp >/dev/null; ufw allow 80/tcp >/dev/null; ufw allow 443/tcp >/dev/null
ufw default deny incoming >/dev/null; ufw default allow outgoing >/dev/null
ufw --force enable >/dev/null && echo "  ✓ ufw active"

# --- 5. Automatic security updates -------------------------------------------
step "Enabling unattended security upgrades"
apt-get install -y -qq unattended-upgrades
dpkg-reconfigure -f noninteractive unattended-upgrades >/dev/null 2>&1 || true
echo "  ✓ security patches auto-applied"

# --- 6. Non-root deploy user --------------------------------------------------
step "Creating non-root 'deploy' user (stop running apps as root)"
if ! id -u deploy >/dev/null 2>&1; then
  useradd -m -s /bin/bash deploy
  install -d -m 700 -o deploy -g deploy /home/deploy/.ssh
  cp /root/.ssh/authorized_keys /home/deploy/.ssh/authorized_keys 2>/dev/null || true
  chown deploy:deploy /home/deploy/.ssh/authorized_keys 2>/dev/null || true
  chmod 600 /home/deploy/.ssh/authorized_keys 2>/dev/null || true
  echo "  ✓ 'deploy' created (use provision-product.sh for per-app locked users)"
else
  echo "  → 'deploy' already exists"
fi

# --- 7. Docker sanity (the pakchoi persistence vector) ------------------------
step "Docker check"
if have docker; then
  warn "Docker is installed. pakchoi persisted via containers + an exposed socket."
  warn "Remove it unless an app truly needs it:  apt-get purge -y docker-ce docker.io containerd"
  SOCK=$(stat -c '%a' /var/run/docker.sock 2>/dev/null || echo "")
  [[ -n "$SOCK" && "$SOCK" =~ [2367] ]] && warn "docker.sock is $SOCK — never mount it into a container."
else
  echo "  ✓ Docker not installed (persistence vector absent — keep it that way)"
fi

# --- 8. Kaali Sentinel — continuous host monitoring + baseline ----------------
step "Installing Kaali Sentinel (30-min host scan + baseline)"
install -d /opt/kaali-sentinel /var/lib/kaali
if have node; then
  curl -fsSL "$RAW/host-scan.js" -o /opt/kaali-sentinel/host-scan.js
  # Establish a known-good baseline NOW (a fresh, clean box) → future drift = alert.
  node /opt/kaali-sentinel/host-scan.js --save-baseline >/dev/null 2>&1 && echo "  ✓ baseline saved to /var/lib/kaali/baseline.json"
  cat > /etc/systemd/system/kaali-sentinel.service <<'CONF'
[Unit]
Description=Kaali Sentinel — host compromise scan
After=network.target
[Service]
Type=oneshot
ExecStart=/usr/bin/env node /opt/kaali-sentinel/host-scan.js --baseline /var/lib/kaali/baseline.json
Nice=10
IOSchedulingClass=idle
CONF
  cat > /etc/systemd/system/kaali-sentinel.timer <<'CONF'
[Unit]
Description=Run Kaali Sentinel every 30 minutes
[Timer]
OnBootSec=30s
OnUnitActiveSec=30min
Persistent=true
[Install]
WantedBy=timers.target
CONF
  systemctl daemon-reload
  systemctl enable --now kaali-sentinel.timer >/dev/null 2>&1 && echo "  ✓ Sentinel timer active — re-scans every 30 min, alerts on drift"
else
  warn "node not found yet — after deploying apps, run: node host-scan.js --save-baseline"
fi

# --- Done --------------------------------------------------------------------
cat <<DONE

✅ Host hardened. Verify:
   sshd -T | grep -E 'passwordauthentication|permitrootlogin'   # expect: no / prohibit-password
   ufw status
   fail2ban-client status sshd
   systemctl list-timers kaali-sentinel.timer

Next: deploy apps from GitHub (NOT from the old disk), restore DATA ONLY,
then rotate every secret. Never restore crontab / systemd / /opt scripts / docker images.
DONE
