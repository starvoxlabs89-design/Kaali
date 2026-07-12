import { hashPassword, verifyPassword } from "./password.js";
import { randomToken, hashToken } from "./tokens.js";
import { q, qOne } from "./db.js";
import { readJson, json, parseCookies, setCookie, clientIp } from "./util.js";
import { limit } from "./ratelimit.js";
import { sendEmail, verifyEmailTemplate, resetEmailTemplate } from "./email.js";

const SESSION_DAYS = 30;
const VERIFY_HOURS = 24;
const RESET_HOURS = 1;
const POLICY_VERSION = "v1-2026-07";

const EMAIL_RE = /^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$/;
function validEmail(s) { return typeof s === "string" && s.length <= 254 && EMAIL_RE.test(s); }
function normEmail(s) { return String(s).trim().toLowerCase(); }

function dashboard() { return process.env.DASHBOARD_URL || "https://app.kaali.io"; }
function api() { return process.env.PUBLIC_URL || "https://api.kaali.io"; }

// --- signup ------------------------------------------------------------------
export async function signup(req, res) {
  const ip = clientIp(req);
  if (!limit(`signup:ip:${ip}`, 5, 60 * 60 * 1000)) return json(res, 429, { error: "too many signups from this IP" });

  const body = await readJson(req).catch(() => null);
  if (!body) return json(res, 400, { error: "bad body" });
  const email = normEmail(body.email);
  const password = String(body.password || "");
  const consent = body.consent === true;
  if (!validEmail(email)) return json(res, 400, { error: "invalid email" });
  if (password.length < 8) return json(res, 400, { error: "password must be at least 8 characters" });
  if (!consent) return json(res, 400, { error: "consent to the privacy policy is required (DPDP §6)" });

  const existing = await qOne("SELECT id, verified_at FROM users WHERE email=$1", [email]);
  if (existing) {
    // Never confirm-or-deny the account. Send a fresh verify link if unverified.
    if (!existing.verified_at) await sendVerify(existing.id, email);
    return json(res, 200, { ok: true });   // opaque success
  }

  const hash = await hashPassword(password);
  const u = await qOne(
    "INSERT INTO users(email, password_hash) VALUES($1,$2) RETURNING id",
    [email, hash],
  );
  await q("INSERT INTO consent_log(user_id, kind, policy_ver, ip, user_agent) VALUES($1,$2,$3,$4,$5)",
    [u.id, "signup", POLICY_VERSION, ip, req.headers["user-agent"] || null]);
  await q("INSERT INTO auth_events(email, ip, kind) VALUES($1,$2,$3)", [email, ip, "signup"]);
  await sendVerify(u.id, email);
  return json(res, 200, { ok: true });
}

async function sendVerify(userId, email) {
  const tok = randomToken(32);
  const expires = new Date(Date.now() + VERIFY_HOURS * 3600 * 1000);
  await q("INSERT INTO auth_tokens(user_id, kind, token_hash, expires_at) VALUES($1,'verify',$2,$3)",
    [userId, hashToken(tok), expires]);
  const link = `${api()}/auth/verify?tok=${tok}`;
  const tpl = verifyEmailTemplate({ link });
  await sendEmail({ to: email, ...tpl }).catch((e) => console.error("[verify email]", e.message));
}

// --- verify (link click) -----------------------------------------------------
export async function verify(req, res) {
  const url = new URL(req.url, "http://x");
  const tok = url.searchParams.get("tok");
  if (!tok) return json(res, 400, { error: "missing token" });
  const row = await qOne(
    "SELECT id, user_id, expires_at, used_at FROM auth_tokens WHERE kind='verify' AND token_hash=$1",
    [hashToken(tok)],
  );
  if (!row || row.used_at || new Date(row.expires_at) < new Date()) {
    return json(res, 400, { error: "invalid or expired verify link" });
  }
  await q("UPDATE auth_tokens SET used_at=NOW() WHERE id=$1", [row.id]);
  await q("UPDATE users SET verified_at=NOW() WHERE id=$1 AND verified_at IS NULL", [row.user_id]);
  res.statusCode = 302;
  res.setHeader("Location", `${dashboard()}/signin.html?verified=1`);
  return res.end();
}

// --- login -------------------------------------------------------------------
export async function login(req, res) {
  const ip = clientIp(req);
  if (!limit(`login:ip:${ip}`, 10, 60 * 1000)) return json(res, 429, { error: "too many attempts" });

  const body = await readJson(req).catch(() => null);
  if (!body) return json(res, 400, { error: "bad body" });
  const email = normEmail(body.email);
  const password = String(body.password || "");
  if (!validEmail(email)) return json(res, 401, { error: "invalid credentials" });

  const u = await qOne("SELECT id, password_hash, verified_at FROM users WHERE email=$1", [email]);
  const okHash = u ? await verifyPassword(password, u.password_hash) : false;
  await q("INSERT INTO auth_events(email, ip, kind) VALUES($1,$2,$3)", [email, ip, okHash ? "login" : "login_fail"]);
  if (!u || !okHash) return json(res, 401, { error: "invalid credentials" });
  if (!u.verified_at) return json(res, 403, { error: "verify your email first" });

  const tok = randomToken(32);
  const expires = new Date(Date.now() + SESSION_DAYS * 86400 * 1000);
  await q(
    "INSERT INTO sessions(user_id, token_hash, expires_at, ip, user_agent) VALUES($1,$2,$3,$4,$5)",
    [u.id, hashToken(tok), expires, ip, req.headers["user-agent"] || null],
  );
  setCookie(res, "kaali_sess", tok, { maxAge: SESSION_DAYS * 86400, sameSite: "Lax" });
  return json(res, 200, { ok: true });
}

// --- logout ------------------------------------------------------------------
export async function logout(req, res) {
  const cookies = parseCookies(req.headers.cookie);
  const tok = cookies.kaali_sess;
  if (tok) await q("DELETE FROM sessions WHERE token_hash=$1", [hashToken(tok)]).catch(() => {});
  setCookie(res, "kaali_sess", "", { maxAge: 0 });
  return json(res, 200, { ok: true });
}

// --- forgot / reset ----------------------------------------------------------
export async function forgot(req, res) {
  const ip = clientIp(req);
  const body = await readJson(req).catch(() => null);
  if (!body) return json(res, 400, { error: "bad body" });
  const email = normEmail(body.email);
  if (!validEmail(email)) return json(res, 200, { ok: true }); // opaque
  if (!limit(`forgot:email:${email}`, 3, 60 * 60 * 1000)) return json(res, 200, { ok: true });

  const u = await qOne("SELECT id FROM users WHERE email=$1", [email]);
  if (u) {
    const tok = randomToken(32);
    const expires = new Date(Date.now() + RESET_HOURS * 3600 * 1000);
    await q("INSERT INTO auth_tokens(user_id, kind, token_hash, expires_at) VALUES($1,'reset',$2,$3)",
      [u.id, hashToken(tok), expires]);
    const link = `${dashboard()}/reset.html?tok=${tok}`;
    const tpl = resetEmailTemplate({ link });
    await sendEmail({ to: email, ...tpl }).catch((e) => console.error("[reset email]", e.message));
  }
  await q("INSERT INTO auth_events(email, ip, kind) VALUES($1,$2,$3)", [email, ip, "reset_req"]).catch(() => {});
  return json(res, 200, { ok: true });
}

export async function reset(req, res) {
  const body = await readJson(req).catch(() => null);
  if (!body) return json(res, 400, { error: "bad body" });
  const password = String(body.password || "");
  const tok = String(body.tok || "");
  if (password.length < 8) return json(res, 400, { error: "password must be at least 8 characters" });

  const row = await qOne(
    "SELECT id, user_id, expires_at, used_at FROM auth_tokens WHERE kind='reset' AND token_hash=$1",
    [hashToken(tok)],
  );
  if (!row || row.used_at || new Date(row.expires_at) < new Date()) {
    return json(res, 400, { error: "invalid or expired reset link" });
  }
  const hash = await hashPassword(password);
  await q("UPDATE users SET password_hash=$1 WHERE id=$2", [hash, row.user_id]);
  await q("UPDATE auth_tokens SET used_at=NOW() WHERE id=$1", [row.id]);
  // Kill all existing sessions on password reset — a good default.
  await q("DELETE FROM sessions WHERE user_id=$1", [row.user_id]);
  await q("INSERT INTO auth_events(email, ip, kind) VALUES(NULL,$1,$2)", [clientIp(req), "reset"]);
  return json(res, 200, { ok: true });
}

// --- session guard -----------------------------------------------------------
export async function requireUser(req) {
  const cookies = parseCookies(req.headers.cookie);
  const tok = cookies.kaali_sess;
  if (!tok) return null;
  const s = await qOne(
    `SELECT s.id AS session_id, u.id, u.email, u.plan, u.verified_at
     FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token_hash=$1 AND s.expires_at > NOW()`,
    [hashToken(tok)],
  );
  return s;
}

// --- whoami / DPDP erasure ---------------------------------------------------
export async function me(req, res) {
  const u = await requireUser(req);
  if (!u) return json(res, 401, { error: "not signed in" });
  return json(res, 200, { id: u.id, email: u.email, plan: u.plan });
}

export async function eraseMe(req, res) {
  const u = await requireUser(req);
  if (!u) return json(res, 401, { error: "not signed in" });
  // DPDP §12: right to erasure. Cascade drops sessions/tokens/keys/events/consent.
  await q("DELETE FROM users WHERE id=$1", [u.id]);
  setCookie(res, "kaali_sess", "", { maxAge: 0 });
  return json(res, 200, { ok: true, erased: true });
}
