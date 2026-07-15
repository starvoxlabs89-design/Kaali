#!/usr/bin/env node
/*
 * Kaali Sentinel — host compromise scanner.
 *
 * Detects the classic Linux server-intrusion indicators: backdoor users
 * (e.g. a rogue "pakchoi" account with a hardcoded password), rogue SSH keys,
 * cron/systemd/rc persistence, malware running from /tmp|/dev/shm, unexpected
 * listeners, SUID anomalies, LD_PRELOAD rootkits, and suspicious auth.log events.
 *
 * Zero dependencies. Linux-targeted. Run as root for full coverage:
 *
 *     sudo node host-scan.js                 # terminal report
 *     sudo node host-scan.js --json          # machine-readable
 *     sudo node host-scan.js --cloud-key K   # also POST to kaali.io/ingest
 *     sudo node host-scan.js --allow ./allow.json   # baseline allowlist
 *
 * Exit code: 2 if any critical/high finding, else 0.
 */
import fs from "node:fs";
import cp from "node:child_process";
import os from "node:os";

// ---------- args ----------
const argv = process.argv.slice(2);
const opt = {
  json: argv.includes("--json"),
  cloudKey: val("--cloud-key"),
  cloudUrl: val("--cloud-url") || "https://kaali.io/ingest",
  allowPath: val("--allow"),
};
function val(flag) { const i = argv.indexOf(flag); return i >= 0 ? argv[i + 1] : null; }

// ---------- allowlist (baseline of known-good) ----------
const DEFAULT_ALLOW = {
  users: [],                 // extra human/service usernames you expect (besides distro defaults)
  ssh_key_fingerprints: [],  // SHA256:... fingerprints you recognise
  listen_ports: [22, 80, 443, 5432, 4842], // add your app ports
  systemd_units: [],         // extra unit names you run
};
let ALLOW = { ...DEFAULT_ALLOW };
if (opt.allowPath) {
  try { ALLOW = { ...DEFAULT_ALLOW, ...JSON.parse(fs.readFileSync(opt.allowPath, "utf8")) }; }
  catch (e) { warn(`could not read allowlist ${opt.allowPath}: ${e.message}`); }
}

// ---------- helpers ----------
const isRoot = (typeof process.getuid === "function") && process.getuid() === 0;
const SEV = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const findings = [];
function add(f) { findings.push(f); }
function finding(severity, title, detail, evidence, fix) {
  add({ severity, title, detail: detail || null, evidence: evidence || null, fix: fix || null });
}
function sh(cmd) { try { return cp.execSync(cmd, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], timeout: 15000 }); } catch { return ""; } }
function readFileSafe(p) { try { return fs.readFileSync(p, "utf8"); } catch { return null; } }
function warn(m) { if (!opt.json) process.stderr.write(`  ! ${m}\n`); }

// Distro system users we don't flag (uid < 1000, no login shell expected).
const SHELL_LOGIN = /\/(bash|sh|zsh|ash|dash|fish|ksh)$/;

// =====================================================================
// 1. USERS & /etc/shadow — the pakchoi-class backdoor
// =====================================================================
function scanUsers() {
  const passwd = readFileSafe("/etc/passwd");
  if (!passwd) { warn("cannot read /etc/passwd"); return; }
  const shadow = isRoot ? readFileSafe("/etc/shadow") : null;
  if (!shadow && isRoot) warn("cannot read /etc/shadow");

  const shadowHash = {};
  if (shadow) for (const line of shadow.split("\n")) {
    const [u, h] = line.split(":");
    if (u) shadowHash[u] = h || "";
  }

  for (const line of passwd.split("\n")) {
    if (!line.trim()) continue;
    const [name, , uidStr, , , home, shell] = line.split(":");
    const uid = parseInt(uidStr, 10);
    if (!name || Number.isNaN(uid)) continue;

    // (a) Any UID-0 account that isn't root = instant privilege backdoor
    if (uid === 0 && name !== "root") {
      finding("critical", `Second root-privileged account: ${name}`,
        "A non-root account has UID 0 — full root via a hidden username.",
        line, `Delete it: userdel -r ${name}  (and investigate how it was added)`);
    }

    // (b) Service/system account (uid<1000) that has a login shell = suspicious
    const hasLoginShell = SHELL_LOGIN.test(shell || "");
    if (uid > 0 && uid < 1000 && hasLoginShell && !ALLOW.users.includes(name)) {
      finding("high", `System account with a login shell: ${name}`,
        `uid=${uid}, shell=${shell} — service accounts normally use /usr/sbin/nologin.`,
        line, `If unexpected, lock it: usermod -s /usr/sbin/nologin ${name}; passwd -l ${name}`);
    }

    // (c) THE pakchoi pattern: an account that has a PASSWORD HASH set + a login
    //     shell, and isn't a distro default or in your allowlist.
    if (shadow) {
      const h = shadowHash[name] || "";
      const hasPassword = h && h !== "*" && h !== "!" && !h.startsWith("!") && h.length > 4;
      const looksHuman = uid >= 1000;
      const knownGood = ALLOW.users.includes(name) || name === "root";
      if (hasPassword && hasLoginShell && !knownGood) {
        finding(looksHuman ? "high" : "critical",
          `Account with a set password + login shell: ${name}`,
          "A login-capable account has a password hash — this is exactly how hardcoded-password backdoors (e.g. a rogue 'pakchoi' user) persist.",
          `${name} uid=${uid} shell=${shell} passwd_hash=${h.slice(0, 12)}…`,
          `Verify you created this. If not: usermod -L ${name}; then userdel -r ${name} after evidence capture.`);
      }
    }

    // (d) Recently created accounts (heuristic: home dir mtime very recent)
    if (uid >= 1000 && home && home.startsWith("/home")) {
      try {
        const st = fs.statSync(home);
        const ageDays = (Date.now() - st.ctimeMs) / 86400000;
        if (ageDays < 14 && !ALLOW.users.includes(name)) {
          finding("medium", `Recently created user home: ${name}`,
            `Home ${home} created ${ageDays.toFixed(1)} days ago.`, line,
            "Confirm this account is yours.");
        }
      } catch { /* ignore */ }
    }
  }
}

// =====================================================================
// 2. SSH — rogue authorized_keys + weak sshd config
// =====================================================================
function scanSSH() {
  // authorized_keys across root + all homes
  const homes = ["/root"];
  try { for (const d of fs.readdirSync("/home")) homes.push(`/home/${d}`); } catch { /* */ }
  for (const home of homes) {
    for (const kf of [`${home}/.ssh/authorized_keys`, `${home}/.ssh/authorized_keys2`]) {
      const content = readFileSafe(kf);
      if (!content) continue;
      const keys = content.split("\n").filter((l) => l.trim() && !l.trim().startsWith("#"));
      for (const key of keys) {
        // fingerprint via ssh-keygen if available
        let fp = "";
        try {
          fs.writeFileSync("/tmp/.kaali_k", key);
          fp = (sh("ssh-keygen -lf /tmp/.kaali_k 2>/dev/null") || "").trim().split(/\s+/)[1] || "";
          fs.unlinkSync("/tmp/.kaali_k");
        } catch { /* */ }
        const comment = key.trim().split(/\s+/).slice(2).join(" ") || "(no comment)";
        if (fp && ALLOW.ssh_key_fingerprints.includes(fp)) continue;
        finding("high", `SSH authorized key in ${kf}`,
          "Every key here can log in as this user. Confirm you recognise it.",
          `${fp || "fp?"}  ${comment}`,
          `If unknown, remove that line from ${kf} immediately.`);
      }
    }
  }
  // sshd config risks
  const sshd = readFileSafe("/etc/ssh/sshd_config") || "";
  if (/^\s*PermitRootLogin\s+yes/mi.test(sshd))
    finding("high", "SSH root login enabled", "PermitRootLogin yes lets attackers brute-force root directly.", null, "Set PermitRootLogin prohibit-password (or no) + restart sshd.");
  if (/^\s*PasswordAuthentication\s+yes/mi.test(sshd))
    finding("medium", "SSH password authentication enabled", "Password auth allows brute-force — a likely entry vector for hardcoded-password backdoors.", null, "Set PasswordAuthentication no, use keys only, then restart sshd.");
}

// =====================================================================
// 3. PERSISTENCE — cron, systemd, rc, profile, ld.so.preload
// =====================================================================
function scanPersistence() {
  // ld.so.preload = classic userland rootkit
  const preload = readFileSafe("/etc/ld.so.preload");
  if (preload && preload.trim())
    finding("critical", "/etc/ld.so.preload is set", "This forces a shared library into EVERY process — a hallmark of userland rootkits.", preload.trim(), "Investigate the .so it points to; almost always malicious on a normal server.");

  // cron
  const cronPaths = ["/etc/crontab"];
  for (const dir of ["/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/var/spool/cron", "/var/spool/cron/crontabs"]) {
    try { for (const f of fs.readdirSync(dir)) cronPaths.push(`${dir}/${f}`); } catch { /* */ }
  }
  for (const p of cronPaths) {
    const c = readFileSafe(p);
    if (!c) continue;
    for (const line of c.split("\n")) {
      const l = line.trim();
      if (!l || l.startsWith("#")) continue;
      if (/(curl|wget)\b.*\|\s*(sh|bash)|\/tmp\/|\/dev\/shm|base64\s+-d|\.onion|nc\s|ncat\s|python.*-c|\bchmod\s+\+x/.test(l))
        finding("high", `Suspicious cron entry in ${p}`, "Cron line matches a malware-persistence pattern.", l.slice(0, 160), `Remove from ${p} after capturing evidence.`);
    }
  }

  // rc.local / profile.d modifications
  const rc = readFileSafe("/etc/rc.local");
  if (rc && /(curl|wget|\/tmp\/|\/dev\/shm|base64)/.test(rc))
    finding("high", "Suspicious /etc/rc.local", "Boot script contains download/exec or /tmp references.", rc.slice(0, 200), "Review and clean /etc/rc.local.");

  // systemd units running from suspicious locations
  const units = sh("systemctl list-units --type=service --all --no-legend --no-pager 2>/dev/null");
  for (const line of units.split("\n")) {
    const unit = line.trim().split(/\s+/)[0];
    if (!unit || !unit.endsWith(".service")) continue;
    const exec = sh(`systemctl show -p ExecStart --value ${unit} 2>/dev/null`).trim();
    if (/\/tmp\/|\/dev\/shm|\/home\/[^/]+\/\.|base64|curl|wget/.test(exec) && !ALLOW.systemd_units.includes(unit))
      finding("critical", `Suspicious systemd service: ${unit}`, "A service runs from /tmp, /dev/shm, or a hidden home path.", exec.slice(0, 160), `systemctl disable --now ${unit}; then find + remove the unit file.`);
  }
}

// =====================================================================
// 4. PROCESSES & NETWORK — malware from /tmp, cryptominers, odd listeners
// =====================================================================
function scanRuntime() {
  // processes whose executable path is in a suspicious dir
  const ps = sh("ps -eo pid,user,comm,args --no-headers 2>/dev/null");
  for (const line of ps.split("\n")) {
    if (/\/(tmp|dev\/shm|var\/tmp)\//.test(line))
      finding("high", "Process running from a temp/RAM directory", "Malware commonly executes from /tmp, /dev/shm, /var/tmp.", line.trim().slice(0, 160), "Identify the PID, capture the binary, then kill it.");
    if (/\b(xmrig|minerd|kdevtmpfsi|kinsing|\.\/systemd-|\bcryptonight)\b/i.test(line))
      finding("critical", "Likely cryptominer / known-malware process", "Process name matches a known miner/malware family.", line.trim().slice(0, 160), "Kill it, find its persistence (cron/systemd), and rebuild the box.");
  }

  // listening ports not in allowlist
  const listen = sh("ss -tlnp 2>/dev/null") || sh("netstat -tlnp 2>/dev/null");
  for (const line of listen.split("\n")) {
    const m = line.match(/:(\d+)\s/);
    if (!m) continue;
    const port = parseInt(m[1], 10);
    if (!ALLOW.listen_ports.includes(port) && port !== 53 && port !== 631)
      finding("medium", `Unexpected listening port: ${port}`, "A service is listening on a port not in your allowlist.", line.trim().slice(0, 160), `Confirm what owns port ${port}; if unknown, treat as a possible backdoor/C2.`);
  }
}

// =====================================================================
// 5. FILES — SUID anomalies, world-writable system files
// =====================================================================
function scanFiles() {
  // SUID root binaries outside the usual set
  const knownSuid = new Set(["sudo","su","passwd","chsh","chfn","newgrp","gpasswd","mount","umount","ping","pkexec","fusermount","fusermount3","ssh-keysign","dbus-daemon-launch-helper","polkit-agent-helper-1","chrome-sandbox","snap-confine"]);
  const suid = sh("find /usr /bin /sbin /opt /home /tmp -perm -4000 -type f 2>/dev/null");
  for (const p of suid.split("\n")) {
    if (!p.trim()) continue;
    const base = p.split("/").pop();
    if (!knownSuid.has(base))
      finding("high", `Unexpected SUID-root binary: ${p}`, "A setuid-root binary outside the standard set can be a privilege backdoor.", p, "Verify the package owns it (dpkg -S / rpm -qf). If not, remove it.");
  }
}

// =====================================================================
// 6. LOGS — successful root logins, accepted passwords, sudo by odd users
// =====================================================================
function scanLogs() {
  const logs = ["/var/log/auth.log", "/var/log/secure"];
  let content = "";
  for (const l of logs) { const c = readFileSafe(l); if (c) content += c; }
  if (!content) { warn("no readable auth log (need root)"); return; }
  const lines = content.split("\n");
  const acceptedIPs = {};
  for (const line of lines) {
    let m = line.match(/Accepted (password|publickey) for (\S+) from ([\d.]+)/);
    if (m) { const ip = m[3]; (acceptedIPs[ip] = acceptedIPs[ip] || new Set()).add(m[2]); }
    if (/Accepted password for root /.test(line))
      finding("high", "Successful root login via password", "Direct password root login succeeded — high-risk and a likely attacker action.", line.trim().slice(-160), "Disable root password login; audit the source IP.");
  }
  // brute-force volume
  const fails = (content.match(/Failed password/g) || []).length;
  if (fails > 500)
    finding("medium", `Heavy SSH brute-forcing (${fails} failed logins)`, "High failed-login volume — the box is being actively attacked; a weak password may have fallen.", null, "Install fail2ban, disable password auth, restrict SSH by IP.");
  // summarise accepted-login source IPs for human review
  const ips = Object.keys(acceptedIPs);
  if (ips.length)
    finding("info", `Successful SSH logins came from ${ips.length} IP(s)`, "Review these — an unfamiliar IP is a red flag.", ips.map((ip) => `${ip} → ${[...acceptedIPs[ip]].join(",")}`).join("  |  ").slice(0, 300), null);
}

// =====================================================================
// 7. DEEP — PAM backdoors, sudoers, kernel modules, shell-init, at/timers,
//    MOTD hooks, immutable implants, reverse shells, webshells, hidden execs,
//    recently-modified system binaries.  (the "deep scan")
// =====================================================================

// 7a. PAM backdoors — the Plague / PamDOORa / Quasar class
function scanPAM() {
  // pam config lines that call external programs or unknown modules
  const dir = "/etc/pam.d";
  let files = [];
  try { files = fs.readdirSync(dir); } catch { return; }
  for (const f of files) {
    const c = readFileSafe(`${dir}/${f}`);
    if (!c) continue;
    for (const line of c.split("\n")) {
      const l = line.trim();
      if (!l || l.startsWith("#")) continue;
      if (/pam_exec\.so/.test(l) && /(\/tmp|\/dev\/shm|\.sh|curl|wget|nc\b)/.test(l))
        finding("critical", `PAM pam_exec backdoor in ${dir}/${f}`, "A PAM rule runs an external script on auth — used to log passwords or grant hidden access.", l.slice(0, 160), "Remove the pam_exec line; investigate the script it calls.");
      // reference to a PAM module outside standard security dirs
      const mod = l.match(/\s(\/\S+\.so)\b/);
      if (mod && !/^\/(lib|usr\/lib|lib64|usr\/lib64)/.test(mod[1]))
        finding("critical", `PAM module from a non-standard path in ${f}`, "A PAM stack references a .so outside system library dirs — classic PAM rootkit.", mod[1], "This is almost certainly malicious. Capture the .so and rebuild.");
    }
  }
  // unknown / recently-modified PAM .so modules
  for (const secdir of ["/lib/x86_64-linux-gnu/security", "/lib/security", "/lib64/security", "/usr/lib/x86_64-linux-gnu/security"]) {
    let mods = [];
    try { mods = fs.readdirSync(secdir); } catch { continue; }
    for (const m of mods) {
      try {
        const st = fs.statSync(`${secdir}/${m}`);
        const ageDays = (Date.now() - st.mtimeMs) / 86400000;
        if (ageDays < 60)
          finding("high", `Recently-modified PAM module: ${secdir}/${m}`, `PAM module changed ${ageDays.toFixed(1)} days ago — verify it came from a package update, not an attacker.`, null, `Check ownership: dpkg -S ${secdir}/${m}`);
      } catch { /* */ }
    }
  }
}

// 7b. Sudoers — NOPASSWD backdoors
function scanSudoers() {
  const files = ["/etc/sudoers"];
  try { for (const f of fs.readdirSync("/etc/sudoers.d")) files.push(`/etc/sudoers.d/${f}`); } catch { /* */ }
  for (const p of files) {
    const c = readFileSafe(p);
    if (!c) continue;
    for (const line of c.split("\n")) {
      const l = line.trim();
      if (!l || l.startsWith("#")) continue;
      if (/NOPASSWD:\s*ALL/i.test(l) && !/^%sudo|^%admin|^root\b/.test(l))
        finding("high", `Passwordless sudo grant in ${p}`, "A user/group can run anything as root with no password — a common privilege backdoor.", l.slice(0, 140), `Verify you added this. If not, remove the line from ${p}.`);
    }
  }
}

// 7c. Kernel modules — rootkits
function scanKernelModules() {
  const out = sh("lsmod 2>/dev/null");
  if (!out) return;
  for (const line of out.split("\n").slice(1)) {
    const name = line.trim().split(/\s+/)[0];
    if (!name) continue;
    // module with no backing file on disk = hidden/injected
    const info = sh(`modinfo ${name} 2>/dev/null`);
    if (info && !/filename:/.test(info))
      finding("critical", `Loaded kernel module with no on-disk file: ${name}`, "A kernel module is loaded but has no filename — a strong rootkit indicator.", name, "Treat the kernel as compromised. Rebuild; do not trust this box.");
    if (/\b(diamorphine|reptile|azazel|beurk|jynx|kbeast|suterusu)\b/i.test(name))
      finding("critical", `Known rootkit kernel module: ${name}`, "Module name matches a known LKM rootkit family.", name, "Full rebuild required.");
  }
}

// 7d. Shell-init persistence
function scanShellInit() {
  const targets = ["/etc/bash.bashrc", "/etc/profile"];
  try { for (const f of fs.readdirSync("/etc/profile.d")) targets.push(`/etc/profile.d/${f}`); } catch { /* */ }
  const homes = ["/root"];
  try { for (const d of fs.readdirSync("/home")) homes.push(`/home/${d}`); } catch { /* */ }
  for (const h of homes) for (const rc of [".bashrc", ".bash_profile", ".profile", ".zshrc", ".bash_login"]) targets.push(`${h}/${rc}`);
  for (const p of targets) {
    const c = readFileSafe(p);
    if (!c) continue;
    for (const line of c.split("\n")) {
      const l = line.trim();
      if (!l || l.startsWith("#")) continue;
      if (/(curl|wget)\b.*\|\s*(sh|bash)|\/dev\/tcp\/|base64\s+-d|\/dev\/shm|nc\s+-e|bash\s+-i|python.*socket/.test(l))
        finding("high", `Suspicious shell-init line in ${p}`, "A login/shell rc file runs a download-exec or reverse-shell payload every session.", l.slice(0, 140), `Remove the line from ${p}.`);
    }
  }
}

// 7e. Extra schedulers — at jobs + systemd timers
function scanScheduledExtra() {
  const at = sh("atq 2>/dev/null");
  if (at && at.trim())
    finding("medium", "Pending 'at' jobs exist", "The 'at' scheduler has queued jobs — a less-watched persistence channel.", at.trim().slice(0, 200), "Review with: for j in $(atq|awk '{print $1}'); do at -c $j; done");
  const timers = sh("systemctl list-timers --all --no-legend --no-pager 2>/dev/null");
  for (const line of timers.split("\n")) {
    const unit = (line.trim().split(/\s+/).pop() || "");
    if (unit.endsWith(".timer") && !ALLOW.systemd_units.includes(unit)) {
      const svc = unit.replace(/\.timer$/, ".service");
      const exec = sh(`systemctl show -p ExecStart --value ${svc} 2>/dev/null`).trim();
      if (/\/tmp\/|\/dev\/shm|curl|wget|base64|\/home\/[^/]+\/\./.test(exec))
        finding("critical", `Suspicious systemd timer: ${unit}`, "A timer triggers a service running from a suspicious location.", exec.slice(0, 140), `systemctl disable --now ${unit}`);
    }
  }
}

// 7f. MOTD / login hooks
function scanMOTD() {
  for (const dir of ["/etc/update-motd.d"]) {
    let files = [];
    try { files = fs.readdirSync(dir); } catch { continue; }
    for (const f of files) {
      const c = readFileSafe(`${dir}/${f}`);
      if (c && /(curl|wget|\/tmp\/|\/dev\/shm|base64|nc\s+-e|\/dev\/tcp)/.test(c))
        finding("high", `Suspicious MOTD script: ${dir}/${f}`, "MOTD scripts run on every login — a stealthy execution trigger.", (c.match(/.*(curl|wget|base64|nc|dev\/tcp).*/) || [""])[0].slice(0, 140), `Review/remove ${dir}/${f}.`);
    }
  }
}

// 7g. Immutable files — attackers chattr +i their implants
function scanImmutable() {
  const out = sh("lsattr -R /etc /root /usr/local/bin /tmp /dev/shm 2>/dev/null | grep -E '^....i' 2>/dev/null");
  for (const line of (out || "").split("\n")) {
    if (!line.trim()) continue;
    finding("high", "Immutable (chattr +i) file", "Attackers set files immutable so you can't delete their backdoor. Legit on very few files.", line.trim().slice(0, 160), "Inspect it; if malicious: chattr -i <file> then remove.");
  }
}

// 7h. Reverse-shell processes
function scanReverseShell() {
  const ps = sh("ps -eo pid,args --no-headers 2>/dev/null");
  for (const line of ps.split("\n")) {
    if (/\/dev\/tcp\/|bash\s+-i|nc\s+-e|ncat\s+-e|socat\b.*exec|python.*socket.*subprocess|perl.*socket|\bsh\s+-i\b/.test(line))
      finding("critical", "Possible reverse shell / C2 process", "A running process matches a reverse-shell / remote-control pattern.", line.trim().slice(0, 160), "Identify the PID + parent, capture, then kill. Find its persistence.");
  }
}

// 7i. Webshells in served web roots
function scanWebshells() {
  const roots = ["/var/www", "/usr/share/nginx", "/opt/kaali/kaali/packages/kaali-cloud/public"];
  const bad = /(eval\s*\(\s*(base64_decode|gzinflate|\$_(POST|GET|REQUEST))|passthru\s*\(|shell_exec\s*\(|assert\s*\(\s*\$_|preg_replace\s*\(.*\/e|system\s*\(\s*\$_)/;
  const walk = (dir, depth) => {
    if (depth > 6) return;
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const p = `${dir}/${e.name}`;
      if (e.isDirectory()) { if (e.name !== "node_modules" && e.name !== ".git") walk(p, depth + 1); }
      else if (/\.(php|phtml|phar|jsp|asp|aspx)$/i.test(e.name)) {
        const c = readFileSafe(p);
        if (c && bad.test(c))
          finding("critical", `Possible webshell: ${p}`, "A web-served file contains an obfuscated code-execution pattern.", (c.match(bad) || [""])[0].slice(0, 100), "Quarantine + delete; check web-server access logs for how it was uploaded.");
      }
    }
  };
  for (const r of roots) walk(r, 0);
}

// 7j. Hidden executables in temp/system dirs
function scanHidden() {
  const out = sh("find /tmp /dev/shm /var/tmp /etc -type f \\( -name '.*' -o -perm -111 \\) 2>/dev/null");
  for (const p of (out || "").split("\n")) {
    if (!p.trim()) continue;
    if (/\/(tmp|dev\/shm|var\/tmp)\//.test(p) && /\.(sh|py|pl|elf|bin)$|\/\.[^/]+$/.test(p))
      finding("medium", `Hidden/executable file in temp dir: ${p}`, "Executables or dotfiles in world-writable temp dirs are a common malware staging spot.", p, "Inspect before deleting; correlate with running processes.");
  }
}

// 7k. Recently-modified system binaries (trojaned binaries)
function scanRecentBinaries() {
  const out = sh("find /bin /sbin /usr/bin /usr/sbin -type f -mtime -30 2>/dev/null");
  const lines = (out || "").split("\n").filter(Boolean);
  if (lines.length)
    finding("medium", `${lines.length} system binaries modified in the last 30 days`, "Trojaned core binaries (ls, ps, sshd, etc.) are a rootkit technique. Some may be legit package updates — verify.", lines.slice(0, 8).map((p) => p.split("/").pop()).join(", ") + (lines.length > 8 ? " …" : ""), "Verify integrity: debsums -c 2>/dev/null (Debian/Ubuntu) or rpm -Va.");
}

// =====================================================================
// run + report
// =====================================================================
function run() {
  if (!isRoot) warn("not running as root — /etc/shadow, some logs, and full process info are unavailable. Re-run with sudo for complete coverage.");
  const mods = [
    ["users", scanUsers], ["ssh", scanSSH], ["persistence", scanPersistence],
    ["runtime", scanRuntime], ["files", scanFiles], ["logs", scanLogs],
    // deep modules
    ["pam", scanPAM], ["sudoers", scanSudoers], ["kernel-modules", scanKernelModules],
    ["shell-init", scanShellInit], ["schedulers", scanScheduledExtra], ["motd", scanMOTD],
    ["immutable", scanImmutable], ["reverse-shell", scanReverseShell],
    ["webshells", scanWebshells], ["hidden", scanHidden], ["recent-binaries", scanRecentBinaries],
  ];
  for (const [name, fn] of mods) {
    try { fn(); } catch (e) { finding("info", `Scanner '${name}' errored`, String(e.message || e)); }
  }

  findings.sort((a, b) => SEV[b.severity] - SEV[a.severity]);
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;
  const worst = findings[0] ? SEV[findings[0].severity] : 0;

  const report = {
    host: os.hostname(),
    scanned_at: new Date().toISOString(),
    root: isRoot,
    counts,
    findings,
  };

  if (opt.json) {
    process.stdout.write(JSON.stringify(report, null, 2) + "\n");
  } else {
    printTerminal(report);
  }
  if (opt.cloudKey) postCloud(report).catch((e) => warn(`cloud post failed: ${e.message}`));

  process.exitCode = worst >= SEV.high ? 2 : 0;
}

function printTerminal(r) {
  const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
  const c = (code, s) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : String(s));
  const col = { critical: 31, high: 31, medium: 33, low: 34, info: 90 };
  console.log("");
  console.log(`  ${c(1, "Kaali Sentinel — host scan")}  ${c(90, r.host + " · " + r.scanned_at)}`);
  console.log(`  ${c(90, r.root ? "running as root (full coverage)" : "NOT root — partial coverage")}`);
  console.log("");
  if (!r.findings.length) { console.log("  " + c(32, "✓ No indicators of compromise found.")); return; }
  for (const f of r.findings) {
    console.log(`  ${c(col[f.severity], "[" + f.severity.toUpperCase() + "]")} ${c(1, f.title)}`);
    if (f.detail) console.log(`     ${f.detail}`);
    if (f.evidence) console.log(c(2, `     evidence: ${f.evidence}`));
    if (f.fix) console.log(c(32, `     fix: ${f.fix}`));
    console.log("");
  }
  console.log("  " + c(1, "──────────────────────────────────────────────"));
  const line = ["critical","high","medium","low","info"].map((s) => `${r.counts[s]} ${s}`).join("  ");
  const bad = r.counts.critical + r.counts.high;
  console.log(`  ${bad ? c(31, "⚠ " + bad + " critical/high") : c(32, "clean")}    ${c(90, line)}`);
  console.log("");
}

async function postCloud(report) {
  // Reuse the Kaali Cloud /ingest contract (source=guard-ish host event).
  const body = JSON.stringify({
    source: "guard",
    target: report.host,
    direction: "host-scan",
    blocked: report.counts.critical + report.counts.high > 0,
    reason: report.counts.critical ? "critical host findings" : report.counts.high ? "high host findings" : null,
    threats: report.findings.filter((f) => SEV[f.severity] >= SEV.high).map((f) => ({ type: f.title, severity: f.severity, detail: f.evidence })),
  });
  const res = await fetch(opt.cloudUrl, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${opt.cloudKey}` },
    body,
  });
  if (!res.ok) throw new Error(`${res.status}`);
  if (!opt.json) console.log(`  → reported to Kaali Cloud (${opt.cloudUrl})`);
}

run();
