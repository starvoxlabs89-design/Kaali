// OAuth 2.0 with PKCE (S256) for Google and Meta (Facebook Login).
// No external SDK — plain `fetch`. State + code_verifier travel in short-lived
// HttpOnly cookies so we don't need a server-side "pending auth" store.

import { createHash, randomBytes } from "node:crypto";
import { q, qOne } from "./db.js";
import { randomToken, hashToken } from "./tokens.js";
import { json, parseCookies, setCookie, clientIp } from "./util.js";
import { limit } from "./ratelimit.js";
import { sendEmail, welcomeEmailTemplate } from "./email.js";

const POLICY_VERSION = "v1-2026-07";
const SESSION_DAYS = 30;

function apiUrl() { return process.env.PUBLIC_URL || "https://api.kaali.io"; }
function dashUrl() { return process.env.DASHBOARD_URL || "https://app.kaali.io"; }

// --- Provider config ---------------------------------------------------------
const PROVIDERS = {
  google: {
    authUrl: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenUrl: "https://oauth2.googleapis.com/token",
    userUrl: "https://www.googleapis.com/oauth2/v3/userinfo",
    scope: "openid email profile",
    clientId: () => process.env.GOOGLE_CLIENT_ID,
    clientSecret: () => process.env.GOOGLE_CLIENT_SECRET,
    // v3/userinfo returns: { sub, email, email_verified, name, picture }
    parseUser: (u) => ({
      providerId: String(u.sub),
      email: u.email ? String(u.email).toLowerCase() : null,
      emailVerified: u.email_verified === true || u.email_verified === "true",
    }),
  },
  meta: {
    authUrl: "https://www.facebook.com/v19.0/dialog/oauth",
    tokenUrl: "https://graph.facebook.com/v19.0/oauth/access_token",
    userUrl: "https://graph.facebook.com/me?fields=id,email,name",
    scope: "email public_profile",
    clientId: () => process.env.META_APP_ID,
    clientSecret: () => process.env.META_APP_SECRET,
    // Meta returns: { id, email?, name }; email present only if user granted it.
    parseUser: (u) => ({
      providerId: String(u.id),
      email: u.email ? String(u.email).toLowerCase() : null,
      // Meta doesn't return an emailVerified flag; if they gave us an email,
      // it's the one on file with Meta — treat as verified.
      emailVerified: !!u.email,
    }),
  },
};

function configured(name) {
  const p = PROVIDERS[name];
  return p && p.clientId() && p.clientSecret();
}

export function enabledProviders() {
  return Object.keys(PROVIDERS).filter(configured);
}

// --- Public: expose /auth/providers so the UI can hide missing buttons -------
export async function providersList(req, res) {
  return json(res, 200, { providers: enabledProviders() });
}

// --- Redirect to provider ----------------------------------------------------
function base64url(buf) { return buf.toString("base64").replace(/=/g,"").replace(/\+/g,"-").replace(/\//g,"_"); }

export async function begin(req, res, providerName) {
  const p = PROVIDERS[providerName];
  if (!p || !configured(providerName)) return json(res, 404, { error: `provider ${providerName} not configured` });

  if (!limit(`oauth:${providerName}:ip:${clientIp(req)}`, 20, 60 * 1000)) {
    return json(res, 429, { error: "too many attempts" });
  }

  const state = randomToken(24);
  const verifier = randomToken(48);
  const challenge = base64url(createHash("sha256").update(verifier).digest());

  const nextParam = new URL(req.url, "http://x").searchParams.get("next") || "/";
  const cookiePayload = `${state}.${verifier}.${encodeURIComponent(nextParam)}`;
  setCookie(res, `kaali_oauth_${providerName}`, cookiePayload, {
    maxAge: 10 * 60, sameSite: "Lax",
  });

  const url = new URL(p.authUrl);
  url.searchParams.set("client_id", p.clientId());
  url.searchParams.set("redirect_uri", `${apiUrl()}/auth/${providerName}/callback`);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", p.scope);
  url.searchParams.set("state", state);
  url.searchParams.set("code_challenge", challenge);
  url.searchParams.set("code_challenge_method", "S256");
  // Google: request offline access implicitly? For login we only need one-shot.

  res.statusCode = 302;
  res.setHeader("Location", url.toString());
  return res.end();
}

// --- Callback ----------------------------------------------------------------
export async function callback(req, res, providerName) {
  const p = PROVIDERS[providerName];
  if (!p || !configured(providerName)) return textRedirect(res, `${dashUrl()}/?oauth_error=not_configured`);

  const url = new URL(req.url, "http://x");
  const code = url.searchParams.get("code");
  const returnedState = url.searchParams.get("state");
  const err = url.searchParams.get("error");
  if (err) return textRedirect(res, `${dashUrl()}/?oauth_error=${encodeURIComponent(err)}`);
  if (!code || !returnedState) return textRedirect(res, `${dashUrl()}/?oauth_error=missing_code`);

  const cookies = parseCookies(req.headers.cookie);
  const raw = cookies[`kaali_oauth_${providerName}`];
  if (!raw) return textRedirect(res, `${dashUrl()}/?oauth_error=missing_state`);
  const [state, verifier, nextEncoded] = raw.split(".");
  if (!state || !verifier || state !== returnedState) {
    return textRedirect(res, `${dashUrl()}/?oauth_error=state_mismatch`);
  }
  // Consume the state cookie
  setCookie(res, `kaali_oauth_${providerName}`, "", { maxAge: 0 });

  // Exchange code for token
  const tokRes = await fetch(p.tokenUrl, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: `${apiUrl()}/auth/${providerName}/callback`,
      client_id: p.clientId(),
      client_secret: p.clientSecret(),
      code_verifier: verifier,
    }).toString(),
  });
  if (!tokRes.ok) {
    console.error(`[oauth:${providerName}] token exchange`, tokRes.status, await tokRes.text());
    return textRedirect(res, `${dashUrl()}/?oauth_error=token_exchange`);
  }
  const tokJson = await tokRes.json();
  const accessToken = tokJson.access_token;
  if (!accessToken) return textRedirect(res, `${dashUrl()}/?oauth_error=no_token`);

  // Fetch user info
  const userRes = await fetch(p.userUrl, {
    headers: { authorization: `Bearer ${accessToken}` },
  });
  if (!userRes.ok) {
    console.error(`[oauth:${providerName}] user fetch`, userRes.status);
    return textRedirect(res, `${dashUrl()}/?oauth_error=user_fetch`);
  }
  const u = p.parseUser(await userRes.json());
  if (!u.providerId) return textRedirect(res, `${dashUrl()}/?oauth_error=no_provider_id`);
  if (!u.email) return textRedirect(res, `${dashUrl()}/?oauth_error=email_required`);
  if (!u.emailVerified) return textRedirect(res, `${dashUrl()}/?oauth_error=email_not_verified`);

  const userId = await upsertIdentity(providerName, u, req);
  await grantSession(userId, req, res);

  const next = nextEncoded ? decodeURIComponent(nextEncoded) : "/dashboard.html";
  const dest = next.startsWith("/") ? `${dashUrl()}${next}` : `${dashUrl()}/dashboard.html`;
  return textRedirect(res, dest);
}

// --- Identity linking --------------------------------------------------------
// Rules:
// 1. If (provider, provider_user_id) already linked → return that user_id.
// 2. Else if a user with this verified email exists → link identity, return them.
// 3. Else create a new user (verified since provider verified their email),
//    log DPDP consent (kind='signup_oauth'), and link identity.
async function upsertIdentity(providerName, u, req) {
  const ip = clientIp(req);
  const ua = req.headers["user-agent"] || null;

  const existing = await qOne(
    "SELECT user_id FROM oauth_identities WHERE provider=$1 AND provider_user_id=$2",
    [providerName, u.providerId],
  );
  if (existing) return existing.user_id;

  const byEmail = await qOne("SELECT id, verified_at FROM users WHERE email=$1", [u.email]);
  if (byEmail) {
    await q(
      "INSERT INTO oauth_identities(user_id, provider, provider_user_id, email) VALUES($1,$2,$3,$4)",
      [byEmail.id, providerName, u.providerId, u.email],
    );
    if (!byEmail.verified_at) await q("UPDATE users SET verified_at=NOW() WHERE id=$1", [byEmail.id]);
    return byEmail.id;
  }

  const newUser = await qOne(
    "INSERT INTO users(email, password_hash, verified_at) VALUES($1, NULL, NOW()) RETURNING id",
    [u.email],
  );
  await q(
    "INSERT INTO oauth_identities(user_id, provider, provider_user_id, email) VALUES($1,$2,$3,$4)",
    [newUser.id, providerName, u.providerId, u.email],
  );
  await q(
    "INSERT INTO consent_log(user_id, kind, policy_ver, ip, user_agent) VALUES($1, $2, $3, $4, $5)",
    [newUser.id, `signup_${providerName}`, POLICY_VERSION, ip, ua],
  );
  await q("INSERT INTO auth_events(email, ip, kind) VALUES($1,$2,$3)", [u.email, ip, `signup_${providerName}`]);
  // Optional welcome — best-effort, branded template.
  sendEmail({
    to: u.email,
    ...welcomeEmailTemplate({ dashboardUrl: dashUrl() }),
  }).catch(() => {});
  return newUser.id;
}

async function grantSession(userId, req, res) {
  const tok = randomToken(32);
  const expires = new Date(Date.now() + SESSION_DAYS * 86400 * 1000);
  await q(
    "INSERT INTO sessions(user_id, token_hash, expires_at, ip, user_agent) VALUES($1,$2,$3,$4,$5)",
    [userId, hashToken(tok), expires, clientIp(req), req.headers["user-agent"] || null],
  );
  setCookie(res, "kaali_sess", tok, { maxAge: SESSION_DAYS * 86400, sameSite: "Lax" });
}

function textRedirect(res, url) {
  res.statusCode = 302;
  res.setHeader("Location", url);
  return res.end();
}
