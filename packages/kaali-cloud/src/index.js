// Kaali Cloud — HTTP server entry.
// Zero-dep except `pg`. Serves API + static dashboard.
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join, normalize, extname } from "node:path";

import { signup, verify, login, logout, forgot, reset, me, eraseMe } from "./auth.js";
import { listKeys, createKey, revokeKey } from "./keys.js";
import { ingest } from "./ingest.js";
import { recentEvents, stats } from "./dashboard.js";
import { scan } from "./scanroute.js";
import { begin as oauthBegin, callback as oauthCallback, providersList } from "./oauth.js";
import { json, text } from "./util.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = normalize(join(__dirname, "..", "public"));

const CT = { ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8", ".svg": "image/svg+xml", ".ico": "image/x-icon" };

async function serveStatic(req, res) {
  let p = decodeURIComponent(new URL(req.url, "http://x").pathname);
  if (p === "/") p = "/index.html";
  const abs = normalize(join(PUBLIC_DIR, p));
  if (!abs.startsWith(PUBLIC_DIR)) return text(res, 403, "forbidden");
  try {
    const body = await readFile(abs);
    res.setHeader("cache-control", "public, max-age=60");
    return text(res, 200, body, CT[extname(abs)] || "application/octet-stream");
  } catch {
    // SPA fallback so /reset.html?tok= etc. all resolve
    if (p.endsWith(".html")) {
      const body = await readFile(join(PUBLIC_DIR, "index.html")).catch(() => null);
      if (body) return text(res, 200, body, "text/html; charset=utf-8");
    }
    return text(res, 404, "not found");
  }
}

// Tiny router. Routes are (method, path pattern) tuples.
const routes = [
  ["POST", /^\/auth\/signup$/,   signup],
  ["GET",  /^\/auth\/verify$/,   verify],
  ["POST", /^\/auth\/login$/,    login],
  ["POST", /^\/auth\/logout$/,   logout],
  ["POST", /^\/auth\/forgot$/,   forgot],
  ["POST", /^\/auth\/reset$/,    reset],
  ["GET",  /^\/me$/,             me],
  ["DELETE", /^\/me$/,           eraseMe],
  ["GET",  /^\/me\/keys$/,       listKeys],
  ["POST", /^\/me\/keys$/,       createKey],
  ["POST", /^\/me\/keys\/(\d+)\/revoke$/, revokeKey],
  ["GET",  /^\/me\/events$/,     recentEvents],
  ["GET",  /^\/me\/stats$/,      stats],
  ["POST", /^\/ingest$/,         ingest],
  ["POST", /^\/scan$/,           scan],
  ["GET",  /^\/auth\/providers$/,          providersList],
  ["GET",  /^\/auth\/(google|meta)$/,       (req, res, p) => oauthBegin(req, res, p)],
  ["GET",  /^\/auth\/(google|meta)\/callback$/, (req, res, p) => oauthCallback(req, res, p)],
];

async function router(req, res) {
  const url = new URL(req.url, "http://x");
  // Permissive CORS for the dashboard on app.kaali.io + local dev.
  const origin = req.headers.origin || "";
  if (origin) {
    res.setHeader("access-control-allow-origin", origin);
    res.setHeader("access-control-allow-credentials", "true");
    res.setHeader("access-control-allow-headers", "content-type, authorization");
    res.setHeader("access-control-allow-methods", "GET, POST, DELETE, OPTIONS");
    res.setHeader("vary", "origin");
  }
  if (req.method === "OPTIONS") { res.statusCode = 204; return res.end(); }

  for (const [m, re, fn] of routes) {
    if (m !== req.method) continue;
    const match = url.pathname.match(re);
    if (match) {
      try { return await fn(req, res, ...match.slice(1)); }
      catch (e) { console.error("[route]", url.pathname, e); return json(res, 500, { error: "server error" }); }
    }
  }
  return serveStatic(req, res);
}

const port = parseInt(process.env.PORT || "4842", 10);
createServer(router).listen(port, () => {
  console.log(`kaali-cloud listening on :${port}`);
});
