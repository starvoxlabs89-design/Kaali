import { SCANNERS, byId } from "./scanners/index.js";
import { printReport, jsonReport, sarifReport, htmlReport } from "./report.js";
import { c, vigilScore } from "./util.js";
import { loadPrev, saveScan } from "./history.js";

const HELP = `
${c.bold("vigil")} — open-source security scanner + 24/7 monitor for AI agents, LLM apps & websites.

${c.bold("USAGE")}
  vigil scan <target> [options]
  vigil monitor <target> [options]
  vigil list

${c.bold("TARGET")}
  A URL (https://example.com)  → runs web checks
  A local path (./my-app)      → runs secrets + Indian-PII/DPDP checks

${c.bold("OPTIONS")}
  --ai <endpoint>        Probe an LLM/chat endpoint for DIRECT prompt injection (LLM01)
  --ai-indirect <ep>     Probe for INDIRECT injection via poisoned retrieved content
  --ai-field <name>      JSON body field to inject (default: message)
  --mcp <url>            Scan a DEPLOYED MCP server for no-auth + tool poisoning
  --mcp-discover         Find local MCP configs + flag risky servers (Bumblebee bridge)
  --from-bumblebee <f>   Ingest Bumblebee NDJSON output (with --mcp-discover)
  --only <ids>           Comma-separated scanner ids (see 'vigil list')
  --json                 Machine-readable output (for CI/CD)
  --sarif                SARIF 2.1.0 output (GitHub code-scanning)
  --html                 Shareable "report card" — graded, with a lesson per finding
  --no-history            Don't read/write the local .vigil/ trend history
  --fail-on <sev>        Exit non-zero if a finding >= severity (critical|high|medium|low)
  -h, --help             Show this help

${c.bold("EXAMPLES")}
  vigil scan https://mysite.in
  vigil scan ./repo --fail-on high
  vigil scan https://docs.mysite.in --only content      # hidden-instruction / invisible-unicode
  vigil scan x --ai https://api.myapp.com/chat
  vigil scan x --ai-indirect https://api.myapp.com/chat
  vigil scan x --mcp http://localhost:8000/mcp
  vigil scan x --mcp-discover                            # reads local MCP configs
`;

function parseArgs(argv) {
  const opts = { only: null };
  const positional = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--json") opts.json = true;
    else if (a === "--sarif") opts.sarif = true;
    else if (a === "--html") opts.html = true;
    else if (a === "--no-history") opts.noHistory = true;
    else if (a === "--ai") opts.aiEndpoint = argv[++i];
    else if (a === "--ai-indirect") opts.aiIndirect = argv[++i];
    else if (a === "--ai-field") opts.aiField = argv[++i];
    else if (a === "--mcp") opts.mcpUrl = argv[++i];
    else if (a === "--mcp-discover") opts.mcpDiscover = true;
    else if (a === "--from-bumblebee") opts.fromBumblebee = argv[++i];
    else if (a === "--only") opts.only = argv[++i].split(",").map((s) => s.trim());
    else if (a === "--fail-on") opts.failOn = argv[++i];
    else if (a === "-h" || a === "--help") opts.help = true;
    else positional.push(a);
  }
  return { opts, positional };
}

function selectScanners(target, opts) {
  if (opts.only) return SCANNERS.filter((s) => opts.only.includes(s.meta.id));
  const selected = SCANNERS.filter((s) => s.meta.applies(target));
  if (opts.aiEndpoint) selected.push(byId("ai"));
  if (opts.aiIndirect) selected.push(byId("ai-indirect"));
  if (opts.mcpUrl) selected.push(byId("mcp"));
  if (opts.mcpDiscover || opts.fromBumblebee) selected.push(byId("mcp-discover"));
  return [...new Set(selected)];
}

const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export async function main(argv) {
  const cmd = argv[0];
  const { opts, positional } = parseArgs(argv.slice(1));

  if (!cmd || opts.help || cmd === "help" || cmd === "-h" || cmd === "--help") { console.log(HELP); return 0; }

  if (cmd === "list") {
    console.log(c.bold("\n  Available scanners:\n"));
    for (const s of SCANNERS) console.log(`  ${c.cyan(s.meta.id.padEnd(10))} ${s.meta.title}`);
    console.log("");
    return 0;
  }

  if (cmd === "monitor") {
    console.log(c.yellow("\n  vigil monitor — continuous mode is on the roadmap (see SPEC.md).\n") +
      c.gray("  v0.1 ships the scan engine; monitoring wraps it on an interval + OTEL stream + alerting.\n"));
    return 0;
  }

  if (cmd !== "scan") { console.log(c.red(`Unknown command: ${cmd}`)); console.log(HELP); return 1; }

  const target = positional[0];
  if (!target) { console.log(c.red("Missing <target>.")); console.log(HELP); return 1; }

  const scanners = selectScanners(target, opts);
  if (scanners.length === 0) { console.log(c.yellow("No scanners matched this target. Try --only or --help.")); return 1; }

  const quiet = opts.json || opts.sarif || opts.html;
  if (!quiet) console.log(c.gray(`\n  Running: ${scanners.map((s) => s.meta.id).join(", ")}`));

  const results = [];
  for (const s of scanners) {
    try {
      const findings = await s.run(target, opts);
      results.push({ scanner: s.meta.id, findings });
    } catch (e) {
      results.push({ scanner: s.meta.id, findings: [{ id: `${s.meta.id}-crash`, title: `Scanner error`, severity: "info", detail: String(e.message || e) }] });
    }
  }

  // Trend: load the prior score for this target, then persist the current one.
  const allFindings = results.flatMap((r) => r.findings).filter((f) => f.severity !== "info");
  const score = vigilScore(allFindings);
  if (opts.html && !opts.noHistory) {
    const prev = await loadPrev(target);
    if (prev) opts.prevScore = prev.score;
  }

  if (opts.sarif) console.log(sarifReport(target, results));
  else if (opts.json) console.log(jsonReport(target, results));
  else if (opts.html) console.log(htmlReport(target, results, opts));
  else printReport(target, results);

  if (!opts.noHistory) await saveScan(target, score, new Date().toISOString());

  if (opts.failOn) {
    const threshold = SEV_RANK[opts.failOn] ?? 99;
    const hit = results.some((r) => r.findings.some((f) => (SEV_RANK[f.severity] ?? 0) >= threshold));
    return hit ? 2 : 0;
  }
  return 0;
}
