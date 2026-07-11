# Kaali Cloud — deploy runbook

Everything you actually need to type, in order. ~30 minutes end-to-end.

## Pre-flight checklist (do these off the VPS first — 10 min)

- [ ] **DNS.** In your Cloudflare (or wherever) console, add A/AAAA records:
  - `api.kaali.io` → your Hostinger Mumbai VPS IP
  - `app.kaali.io` → same IP
  - `kaali.io` → same IP (or a landing site of your choice)
  - Turn Cloudflare proxy OFF for `api.` and `app.` until certbot completes; you can re-enable orange-cloud after.
- [ ] **Push the code to GitHub.** In your `/Volumes/AI/kaali` locally:
  ```bash
  git push origin main
  ```
  Confirm `github.com/starvoxlabs89-design/kaali` reflects the latest commits (should end at `83a197d`).
- [ ] **Grab a Resend API key.** [resend.com](https://resend.com) → Add Domain → verify DNS records → API Keys → Create → copy `re_…`.
- [ ] **Google OAuth (5 min):** [console.cloud.google.com](https://console.cloud.google.com) → *Credentials → Create OAuth Client ID (Web)* → redirect URI `https://api.kaali.io/auth/google/callback` → copy Client ID + Secret.
- [ ] **Meta OAuth (optional now, App Review needed later):** [developers.facebook.com](https://developers.facebook.com) → Create App → Facebook Login → redirect `https://api.kaali.io/auth/meta/callback` → App Settings → Privacy Policy URL `https://api.kaali.io/privacy.html` → copy App ID + Secret. (Public `email` scope needs Business Verification — start it in parallel.)

## On the VPS — 3 commands (~15 min)

SSH in as a user with sudo:

```bash
ssh yourvps
```

### 1. Run the deploy script

```bash
curl -fsSL https://raw.githubusercontent.com/starvoxlabs89-design/kaali/main/packages/kaali-cloud/deploy/deploy.sh | sudo bash
```

This installs Node 20 · Postgres · nginx · certbot, clones the repo, creates the `kaali` role + DB + runs migrations, writes a fresh `.env` with a random 32-byte `SESSION_SECRET` and DB password, installs the systemd unit + nginx site, tries certbot if DNS is already pointing here.

### 2. Fill in `.env`

```bash
sudo nano /opt/kaali/kaali/packages/kaali-cloud/.env
```

Paste in `RESEND_API_KEY`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `META_APP_ID`, `META_APP_SECRET` from the pre-flight step. Save.

### 3. Restart & verify

```bash
sudo systemctl restart kaali-cloud
sudo systemctl status kaali-cloud
curl -s https://api.kaali.io/auth/providers   # expect: {"providers":["google","meta"]}
```

Open `https://app.kaali.io/` — you should see the sign-in page with both OAuth buttons + email form.

## After launch

**Watch logs:** `sudo journalctl -u kaali-cloud -f`

**Daily Postgres backup** (cron):
```bash
echo '0 3 * * * postgres pg_dump -Fc kaali > /var/backups/kaali-$(date +\%F).dump && find /var/backups -name "kaali-*.dump" -mtime +14 -delete' | sudo tee /etc/cron.d/kaali-backup
```

**Update deploys** (after future `git push`):
```bash
ssh yourvps 'sudo -u kaali git -C /opt/kaali/kaali pull && sudo systemctl restart kaali-cloud'
```

## Troubleshooting

| Problem | Fix |
|---|---|
| `kaali-cloud` won't start | `sudo journalctl -u kaali-cloud -n 100` — likely missing env var or DB permission |
| certbot fails | DNS hasn't propagated yet. Wait, then `sudo certbot --nginx -d api.kaali.io -d app.kaali.io` |
| OAuth buttons don't appear on the page | Env vars for that provider are blank — re-check `.env` and restart |
| Google callback errors "redirect_uri_mismatch" | The URI in Google Console must exactly match `https://api.kaali.io/auth/google/callback` (https, no trailing slash) |
| Meta login says "unavailable" for non-admins | Expected until App Review + Business Verification complete |
| Signup email never arrives | `.env` `RESEND_API_KEY` blank or sender domain unverified — the link prints to journalctl in that case |

## Rollback

```bash
sudo systemctl stop kaali-cloud
sudo -u kaali git -C /opt/kaali/kaali reset --hard <previous-commit-sha>
sudo systemctl start kaali-cloud
```

DB schema is additive-only (no destructive migrations); rolling back code is safe.
