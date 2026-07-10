import { readFile, writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";

// Local scan history → powers the report-card trend ("F · 31 → D+ · 58").
// One JSON map (target → last result) under .vigil/ in the working dir.
// Best-effort: every operation swallows errors so a read-only FS never breaks a scan.
const DIR = ".vigil";
const FILE = join(DIR, "history.json");

async function loadAll() {
  try { return JSON.parse(await readFile(FILE, "utf8")); } catch { return {}; }
}

// The previous scan for this target, if any: { score, timestamp }.
export async function loadPrev(target) {
  const all = await loadAll();
  return all[target] || null;
}

// Record this scan as the new "last" for the target. Returns silently on failure.
export async function saveScan(target, score, timestamp) {
  try {
    const all = await loadAll();
    all[target] = { score, timestamp };
    await mkdir(DIR, { recursive: true });
    await writeFile(FILE, JSON.stringify(all, null, 2));
  } catch { /* read-only FS / CI — history is optional */ }
}
