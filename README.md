# 🛡️ Vigil

**Open-source security scanner + 24/7 monitor for AI agents, LLM apps & websites. DPDP-ready.**

Everyone is shipping LLM apps and AI agents. Almost nobody is watching them for prompt injection, leaked secrets, exposed MCP servers, or personal data spilling into logs. The observability tools (Langfuse, OpenLIT) watch *cost and quality* — they're blind to *security*. Vigil watches the security layer.

```bash
npx @starvoxlabs89-design/vigil scan https://your-app.com
npx @starvoxlabs89-design/vigil scan ./your-repo --fail-on high
```

No install. No account. One command → a report you'll want to screenshot.

> Prefer the short command? `npm i -g @starvoxlabs89-design/vigil` then just `vigil scan …`

---

## What it checks

| Scanner | What it finds | Maps to |
|---|---|---|
| `web` | Missing security headers, TLS, version/info disclosure | OWASP Web |
| `content` | **Invisible-Unicode** & hidden AI instructions in pages/docs (the GlassWorm vector) | OWASP **LLM01:2025** |
| `secrets` | Hardcoded API keys (OpenAI, Anthropic, AWS, Slack…), private keys, JWTs | OWASP Web |
| `pii` | **Indian PII** — Aadhaar (Verhoeff-validated), PAN, mobile, email in source/logs | **DPDP Act** |
| `ai` | **Direct prompt injection** against your own LLM endpoint (canary probes) | OWASP **LLM01:2025** |
| `ai-indirect` | **Indirect injection** via poisoned retrieved content (web/tool/email/unicode) | OWASP **LLM01:2025** |
| `mcp` | **Deployed MCP servers** exposed with no auth + **tool-poisoning** | LLM-Agent |
| `mcp-discover` | Local MCP configs + risky launch commands (**reads what Bumblebee reads, then tests it**) | LLM-Agent |

Every run produces a **Vigil Score (0–100)** and severity-ranked findings with concrete fixes.

### The report card (`--html`)

`--html` turns any scan into a self-contained, shareable **report card** — a letter grade (A–F), a prioritized "fix these first" list, and a lesson for every finding: **what we found → the attack an adversary runs → the copy-paste fix → the concept to learn.** Re-scan and it shows your grade trend (`F · 31 → D+ · 58`), so security becomes something you watch improve, not a one-off wall of red.

```bash
npx @starvoxlabs89-design/vigil scan https://mysite.in --html > report.html && open report.html
```

---

## Quick start

```bash
# Scan a website's security posture
npx @starvoxlabs89-design/vigil scan https://mysite.in

# Scan a codebase for secrets + Indian PII (DPDP exposure)
npx @starvoxlabs89-design/vigil scan ./my-app

# Probe your own chatbot/agent endpoint for prompt injection
npx @starvoxlabs89-design/vigil scan x --ai https://api.myapp.com/chat --ai-field message

# Check an MCP server you run
npx @starvoxlabs89-design/vigil scan x --mcp http://localhost:8000/mcp

# Get a shareable, graded "report card" that explains each finding
npx @starvoxlabs89-design/vigil scan https://mysite.in --html > report.html

# CI/CD gate — fail the build on High+ findings
npx @starvoxlabs89-design/vigil scan ./my-app --fail-on high --json
```

```bash
vigil list        # list scanners
vigil --help      # all options
```

---

## Why Vigil exists

The first wave of AI-security tools (Protect AI, Lakera, CalypsoAI) got acquired into big platforms in 2025 — and their open-source tooling is going stale. Meanwhile **prompt injection is #1 on the OWASP LLM Top 10 two years running**, 200k+ MCP servers were found exposed, and India's **DPDP Act** carries penalties up to **₹250 crore**. Developers need a free, fast, local-first tool that checks all of this in one shot — and a hosted version that watches it 24/7. That's Vigil.

- 🆓 **Free & MIT-licensed.** The scanner runs locally, no account, no data leaves your machine.
- ⚡ **Zero-dependency.** Pure Node ≥20. Clone and run.
- 🇮🇳 **DPDP-aware for the AI layer.** Catches Aadhaar/PAN leaking through your **code, logs, LLM responses, and agent traffic** — the surface data-at-rest scanners never look at — and maps it to DPDP obligations.
- 🔌 **CI/CD-ready.** `--json` + `--fail-on` for pipelines.

> **Vigil Cloud** (coming soon) wraps this engine in 24/7 continuous monitoring, historical trends, alerting, and the **DPDP / ISO-42001 evidence report** your auditor accepts. See [SPEC.md](SPEC.md).

---

## Where Vigil fits (and where it doesn't)

The AI-security space is crowded — but every tool watches a *different* surface. Vigil deliberately sits in the one gap no one owns: **the security of the AI app you ship**.

| Tool | Watches | Surface | Mode | License |
|---|---|---|---|---|
| **Perplexity Bumblebee** | your dev **machine** | supply chain (packages, extensions, local MCP *configs*) | one-shot | OSS |
| **Trivy / Socket / Chainguard** | your **dependencies** | software supply chain (SCA) | CI point-in-time | OSS/comm |
| **Lakera** (Check Point) | the **enterprise** | runtime AI defense | continuous | closed, $$$ |
| **promptfoo / garak** | your **model/prompts** | LLM red-team eval | one-shot | OSS |
| **KavachOne / Securiti** | your **databases** | PII *at rest* (DBs, buckets) | scan | closed |
| **Cisco MCP Scanner** | an MCP server's **code** | MCP, pre-deployment | CI point-in-time | OSS |
| **🛡️ Vigil** | the **app you ship** | runtime AI/agent + **deployed** MCP + PII in code/logs/LLM output | **scan → continuous** | **OSS, dev-first** |

**One line:** *Bumblebee secures your laptop. Lakera secures the Fortune 500 (closed, enterprise-priced). KavachOne scans your databases. Vigil is the open-source scanner for the AI you ship — and the only one that watches a **deployed** MCP server and rolls PII-in-your-AI-layer into DPDP evidence.*

**What Vigil is NOT** (we don't overclaim):
- ❌ Not a supply-chain / SCA / SAST tool — use Trivy, Socket, Snyk for that.
- ❌ Not the "first DPDP PII scanner" — KavachOne and others own data-at-rest PII. Vigil covers the *AI/app layer* they don't.
- ❌ Not the "first runtime AI security" — Lakera exists. Vigil is the *open-source, developer-first* one.

Our defensible wedge is the **intersection**: open-source **+** developer-first **+** continuous runtime AI/agent security (incl. deployed MCP) **+** DPDP evidence for the AI app itself. No single tool above sits in all four.

## Authorized use only

The `ai` and `mcp` scanners send active probes to endpoints. **Only scan systems you own or are authorized to test.** Vigil is a defensive tool.

## Roadmap

See [SPEC.md](SPEC.md) for the full product spec, architecture, and the open-source → Cloud path.

## License

MIT © 2026
