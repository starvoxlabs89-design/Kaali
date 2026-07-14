// Admin API — tracking snippet CRUD + audit log.
// Gated by requireAdmin: user must have is_admin=TRUE.
import { q, qOne } from "./db.js";
import { readJson, json, clientIp } from "./util.js";
import { requireUser } from "./auth.js";

async function requireAdmin(req, res) {
  const u = await requireUser(req);
  if (!u) { json(res, 401, { error: "not signed in" }); return null; }
  const row = await qOne("SELECT is_admin FROM users WHERE id=$1", [u.id]);
  if (!row?.is_admin) { json(res, 403, { error: "admin only" }); return null; }
  return u;
}

const VALID_POSITIONS = new Set(["head", "body-start", "body-end"]);
const VALID_PROVIDERS = new Set(["meta-pixel", "google-analytics", "google-ads", "linkedin", "tiktok", "custom"]);

function sanitize(body) {
  const name = String(body.name || "").trim().slice(0, 100);
  if (!name) throw new Error("name required");
  const code = String(body.code || "").trim();
  if (!code) throw new Error("code required");
  if (code.length > 20_000) throw new Error("code too long (max 20 KB)");
  const position = VALID_POSITIONS.has(body.position) ? body.position : "head";
  const provider = VALID_PROVIDERS.has(body.provider) ? body.provider : "custom";
  const enabled = body.enabled !== false;
  const notes = body.notes ? String(body.notes).slice(0, 500) : null;
  const targets = Array.isArray(body.targets) && body.targets.length
    ? body.targets.slice(0, 20).map((t) => String(t).slice(0, 100))
    : ["/"];
  return { name, code, position, provider, enabled, notes, targets };
}

async function audit(snippetId, userId, action, diff, req) {
  await q(
    "INSERT INTO tracking_audit(snippet_id, user_id, action, diff, ip) VALUES($1,$2,$3,$4,$5)",
    [snippetId, userId, action, diff, clientIp(req)],
  ).catch((e) => console.error("[audit]", e.message));
}

// GET /admin/snippets — list all
export async function listSnippets(req, res) {
  const u = await requireAdmin(req, res); if (!u) return;
  const rows = await q(
    `SELECT s.id, s.name, s.provider, s.position, s.code, s.enabled, s.targets, s.notes,
            s.created_at, s.updated_at,
            uc.email AS created_by_email, uu.email AS updated_by_email
     FROM tracking_snippets s
     LEFT JOIN users uc ON uc.id = s.created_by
     LEFT JOIN users uu ON uu.id = s.updated_by
     ORDER BY s.position, s.name`
  );
  return json(res, 200, { snippets: rows });
}

// POST /admin/snippets — create
export async function createSnippet(req, res) {
  const u = await requireAdmin(req, res); if (!u) return;
  let body;
  try { body = sanitize(await readJson(req)); }
  catch (e) { return json(res, 400, { error: e.message }); }
  const row = await qOne(
    `INSERT INTO tracking_snippets(name, provider, position, code, enabled, targets, notes, created_by, updated_by)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$8) RETURNING *`,
    [body.name, body.provider, body.position, body.code, body.enabled, body.targets, body.notes, u.id],
  );
  await audit(row.id, u.id, "create", body, req);
  return json(res, 200, { snippet: row });
}

// PATCH /admin/snippets/:id — update
export async function updateSnippet(req, res, id) {
  const u = await requireAdmin(req, res); if (!u) return;
  const snipId = parseInt(id, 10);
  if (!Number.isFinite(snipId)) return json(res, 400, { error: "bad id" });
  let body;
  try { body = sanitize(await readJson(req)); }
  catch (e) { return json(res, 400, { error: e.message }); }
  const row = await qOne(
    `UPDATE tracking_snippets
     SET name=$1, provider=$2, position=$3, code=$4, enabled=$5, targets=$6, notes=$7,
         updated_by=$8, updated_at=NOW()
     WHERE id=$9 RETURNING *`,
    [body.name, body.provider, body.position, body.code, body.enabled, body.targets, body.notes, u.id, snipId],
  );
  if (!row) return json(res, 404, { error: "not found" });
  await audit(snipId, u.id, "update", body, req);
  return json(res, 200, { snippet: row });
}

// POST /admin/snippets/:id/toggle — flip enabled quickly
export async function toggleSnippet(req, res, id) {
  const u = await requireAdmin(req, res); if (!u) return;
  const snipId = parseInt(id, 10);
  if (!Number.isFinite(snipId)) return json(res, 400, { error: "bad id" });
  const row = await qOne(
    "UPDATE tracking_snippets SET enabled = NOT enabled, updated_by=$1, updated_at=NOW() WHERE id=$2 RETURNING id, enabled",
    [u.id, snipId],
  );
  if (!row) return json(res, 404, { error: "not found" });
  await audit(snipId, u.id, "toggle", { enabled: row.enabled }, req);
  return json(res, 200, { id: row.id, enabled: row.enabled });
}

// DELETE /admin/snippets/:id
export async function deleteSnippet(req, res, id) {
  const u = await requireAdmin(req, res); if (!u) return;
  const snipId = parseInt(id, 10);
  if (!Number.isFinite(snipId)) return json(res, 400, { error: "bad id" });
  const row = await qOne("DELETE FROM tracking_snippets WHERE id=$1 RETURNING id", [snipId]);
  if (!row) return json(res, 404, { error: "not found" });
  await audit(snipId, u.id, "delete", null, req);
  return json(res, 200, { ok: true });
}

// GET /admin/audit?limit=100 — recent audit events
export async function listAudit(req, res) {
  const u = await requireAdmin(req, res); if (!u) return;
  const url = new URL(req.url, "http://x");
  const lim = Math.min(500, Math.max(1, parseInt(url.searchParams.get("limit") || "100", 10)));
  const rows = await q(
    `SELECT a.id, a.action, a.diff, a.ip, a.created_at,
            s.name AS snippet_name, u.email AS actor_email
     FROM tracking_audit a
     LEFT JOIN tracking_snippets s ON s.id = a.snippet_id
     LEFT JOIN users u ON u.id = a.user_id
     ORDER BY a.created_at DESC LIMIT $1`, [lim]
  );
  return json(res, 200, { events: rows });
}

// --- Helpers used by the static-file server to inject snippets ---

const CACHE_TTL_MS = 5_000; // 5-second cache; edits reflect within 5s
let snippetCache = { at: 0, snippets: [] };

async function getEnabledSnippets() {
  const now = Date.now();
  if (now - snippetCache.at < CACHE_TTL_MS) return snippetCache.snippets;
  try {
    const rows = await q(
      "SELECT position, code, targets FROM tracking_snippets WHERE enabled = TRUE"
    );
    snippetCache = { at: now, snippets: rows };
    return rows;
  } catch {
    return snippetCache.snippets;
  }
}

// Given the pathname of the current request and the raw HTML,
// splice enabled snippets into HEAD_SNIPPETS / body-start / body-end.
export async function injectSnippets(html, pathname) {
  const snippets = await getEnabledSnippets();
  if (!snippets.length) return html;

  const matchesPath = (targets) =>
    !targets || !targets.length
      ? true
      : targets.some((t) => t === "*" || t === pathname);

  const head = [], bs = [], be = [];
  for (const s of snippets) {
    if (!matchesPath(s.targets)) continue;
    (s.position === "body-start" ? bs
      : s.position === "body-end" ? be
      : head).push(s.code);
  }

  if (head.length) {
    html = html.replace(
      /<!-- HEAD_SNIPPETS[^>]*-->/,
      "<!-- HEAD_SNIPPETS -->\n" + head.join("\n") + "\n<!-- /HEAD_SNIPPETS -->",
    );
  }
  if (bs.length) html = html.replace(/<body([^>]*)>/, `<body$1>\n${bs.join("\n")}`);
  if (be.length) html = html.replace(/<\/body>/, `${be.join("\n")}\n</body>`);
  return html;
}

// Called at server startup — promote a bootstrap admin if the env var is set.
export async function bootstrapAdmin() {
  const email = (process.env.KAALI_BOOTSTRAP_ADMIN_EMAIL || "").trim().toLowerCase();
  if (!email) return;
  try {
    const row = await qOne(
      "UPDATE users SET is_admin=TRUE WHERE email=$1 AND is_admin=FALSE RETURNING id, email",
      [email],
    );
    if (row) console.log(`[bootstrap] promoted ${row.email} → admin`);
  } catch (e) {
    console.error("[bootstrap admin]", e.message);
  }
}
