# 🛰️ Kaali Sentinel — host compromise scanner

Zero-dependency Linux host scanner that detects the classic server-intrusion indicators — **the ones that would have caught a rogue `pakchoi` user with a hardcoded password the day it appeared.**

```bash
sudo node host-scan.js
```

No install, no dependencies, single file. Node ≥18 (already on any box running the Kaali stack).

## What it detects

| Module | Catches |
|---|---|
| **users** | Second UID-0 (root) account · system account with a login shell · **any account with a password hash + login shell** (the `pakchoi`/hardcoded-password backdoor pattern) · recently-created homes |
| **ssh** | Every `authorized_keys` entry (with fingerprint, for you to eyeball) · `PermitRootLogin yes` · `PasswordAuthentication yes` (the likely entry vector for brute-forced backdoors) |
| **persistence** | `/etc/ld.so.preload` rootkit · malicious cron (`curl\|sh`, `/tmp`, base64) · `rc.local` · systemd services running from `/tmp`, `/dev/shm`, hidden home paths |
| **runtime** | Processes executing from `/tmp` · `/dev/shm` · known miners (xmrig, kinsing…) · unexpected listening ports |
| **files** | SUID-root binaries outside the standard set (privilege backdoors) |
| **logs** | Successful **root** password logins · heavy brute-forcing · a summary of every source IP that successfully logged in (spot the unfamiliar one) |

Each finding has a severity, the evidence, and the exact remediation command.

## Usage

```bash
sudo node host-scan.js                          # terminal report
sudo node host-scan.js --json > scan.json       # machine-readable
sudo node host-scan.js --cloud-key k_live_...    # also stream to kaali.io dashboard
sudo node host-scan.js --allow ./allow.json      # baseline allowlist (silence known-good)
```

Exit code `2` if any critical/high finding (so it fails CI / alerts a cron wrapper), else `0`.

### Allowlist (`allow.json`)

Tell it what's normal for *your* box so real findings stand out:

```json
{
  "users": ["kaali", "deploy"],
  "ssh_key_fingerprints": ["SHA256:abc123…"],
  "listen_ports": [22, 80, 443, 5432, 4842],
  "systemd_units": ["kaali-cloud.service"]
}
```

## 24/7 monitoring (systemd timer)

Run it every 30 minutes and stream results to your Kaali dashboard:

```bash
sudo cp deploy/kaali-sentinel.service deploy/kaali-sentinel.timer /etc/systemd/system/
# edit the .service: set the --cloud-key and script path
sudo systemctl daemon-reload
sudo systemctl enable --now kaali-sentinel.timer
```

Findings land in your Kaali Cloud events feed; critical/high ones mark the run as `blocked` so you can alert on them.

## Incident-response use (run it NOW on a suspected box)

If a box may already be compromised:

1. **Snapshot first** (your VPS panel) — preserve evidence.
2. `sudo node host-scan.js --json > /root/kaali-incident.json` — full scope in one file.
3. Review the critical/high findings — they map to persistence + entry vector.
4. **Rebuild, don't clean.** A hardcoded-password user means the box can't be trusted; migrate to fresh infra with all-new secrets and destroy the old one.
5. Report per your obligations (India: CERT-In 6-hour + DPDP breach notice — see the [India Compliance Kit](https://github.com/starvoxlabs89-design/india-compliance-kit)).

## Honest scope

This is **detection**, not prevention or removal. It surfaces indicators fast and cheaply; it does not clean a box (you shouldn't clean a compromised box — you rebuild it). It's heuristic — a determined attacker can hide from any single-pass scanner, so pair it with off-box log shipping and a rebuild policy.

## License

MIT © 2026 Starvox Labs
