import { scanUrl } from "./scanner.js";
import { q } from "./db.js";
import { readJson, json } from "./util.js";
import { requireUser } from "./auth.js";
import { limit } from "./ratelimit.js";

// POST /scan  { url } — signed-in users can scan any public URL and see
// results in-page. Also persists the scan as an event so it appears in
// "Recent events" and the 30-day stat rollup.
export async function scan(req, res) {
  const u = await requireUser(req);
  if (!u) return json(res, 401, { error: "not signed in" });

  // Modest per-user rate limit — real scanning is cheap but let's not DDoS anyone.
  if (!limit(`scan:user:${u.id}`, 30, 60_000)) return json(res, 429, { error: "too many scans; slow down" });

  const body = await readJson(req).catch(() => null);
  if (!body || typeof body.url !== "string") return json(res, 400, { error: "provide { url }" });

  const result = await scanUrl(body.url.trim());
  if (!result.ok) return json(res, 400, { error: result.error });

  // Persist as an event so the dashboard reflects it in stats + recent-events.
  await q(
    "INSERT INTO events(user_id, source, target, score, payload) VALUES($1,$2,$3,$4,$5)",
    [u.id, "cli", result.target, result.score, { findings: result.findings, dashboard: true }],
  ).catch((e) => console.error("[scan] persist failed", e.message));

  return json(res, 200, result);
}
