# Vigil — Launch Kit

> Copy-paste assets for launch day. Voice: sharp-operator (human, no listicles, no AI avatars). Anchor channels: GitHub + X + LinkedIn + Hacker News. Reels = repurposed clips only, never the origin.

---

## 0. Pre-launch checklist (the blockers, in order)

1. **Lock the name.** "vigil" is likely taken on npm + GitHub. Decide the brand architecture: **Starvox Labs** (house) → **Praman** (flagship) → the scanner is the OSS engine. Check npm + GitHub org + trademark before publishing. Candidate package names if Praman/Vigil collide: `@starvoxlabs89-design/vigil`, `praman`, `praman-scan`, `vigilscan`.
2. **Publish to npm** under the locked name (scoped `@starvoxlabs89-design/*` is always available). Until this is done, `npx <name>` in the README is a broken promise.
3. **Public GitHub repo** under the org, with README, LICENSE, SPEC, a pinned good-first-issues list, and the GitHub Action (`action.yml`) referenced.
4. **Record a 20–30s demo** (asciinema or a terminal GIF): `npx <name> scan https://…` → scary score. Embed at top of README + use in every post.
5. **Landing page** at starvoxlabs.io: one screen — the one-command demo, the Vigil Score, "secure the AI you ship," GitHub + Cloud-waitlist CTAs.
6. **Cloud waitlist** live (email capture) so launch traffic converts to pipeline.

---

## 1. Hacker News — "Show HN"

**Title:**
`Show HN: Vigil – open-source security scanner for AI apps, agents and MCP servers`

**Body:**
```
Hi HN — I built Vigil because everyone's shipping LLM apps and AI agents, and
almost no one is scanning them for the AI-specific stuff: prompt injection,
exposed/poisoned MCP servers, hidden-Unicode instructions in retrieved content,
and PII (incl. Indian Aadhaar/PAN) leaking through code, logs and LLM output.

The observability tools (Langfuse, OpenLIT) watch cost/quality — they're blind to
security. The runtime-AI-security tools (Lakera etc.) went closed/enterprise after
2025's acquisitions. So the open-source, developer-first lane is empty.

One command, no install, no account, runs locally:

    npx <name> scan https://your-app.com
    npx <name> scan ./your-repo --fail-on high

It's zero-dependency (pure Node 20+), MIT, and emits a 0–100 score + severity-ranked
findings with fixes, plus --json/--fail-on for CI.

What it does NOT do (I'm not overclaiming): it's not an SCA/SAST tool (use Trivy/Socket),
not the "first DPDP PII scanner" (KavachOne et al. own data-at-rest PII — Vigil covers
the AI/app layer they don't), and not the first runtime AI security (Lakera exists — Vigil
is the open-source, dev-first one). The wedge is the intersection: OSS + dev-first +
runtime AI/agent + deployed-MCP + DPDP evidence for the app itself.

A hosted tier (24/7 monitoring + a DPDP/ISO-42001 evidence report) is coming, but the
scanner is and stays free.

Repo: <github url>   |   Would love feedback on the scanner design and false-positive rates.
```
*Post Tue–Thu, ~8–9am PT. Be in the thread all day. Answer every comment; don't get defensive about competitors.*

---

## 2. X (Twitter) launch thread

**1/**
Everyone's shipping AI agents. Almost no one is scanning them for the ways they actually leak.

So I built Vigil — open-source security scanner for the AI you ship. One command:

`npx <name> scan https://your-app.com`

No install. No account. 🧵

**2/**
The observability tools (Langfuse, OpenLIT) watch cost & quality.
They're blind to security.

Vigil watches the security layer: prompt injection, exposed MCP servers, hidden-Unicode instructions, secrets, and PII in your code/logs/LLM output.

**3/**
The AI-security OSS leaders got acquired into big closed platforms in 2025 (Protect AI, Lakera, CalypsoAI).

The free, developer-first lane is empty. Vigil fills it. MIT. Zero-dependency. Pure Node.

**4/**
🇮🇳 The India twist: it catches Aadhaar (Verhoeff-validated) + PAN leaking through your AI layer and maps it to the DPDP Act — penalties up to ₹250 crore, enforcement 2027.

Data-at-rest scanners never look at your code, logs, or LLM output. Vigil does.

**5/**
8 scanners, one command:
web · content (invisible-Unicode) · secrets · pii · ai (prompt injection) · ai-indirect · mcp (deployed servers) · mcp-discover

Every run → a 0–100 score + ranked findings with fixes. `--json` + `--fail-on` for CI.

**6/**
What it's NOT (no overclaiming):
– not SCA/SAST (use Trivy/Socket)
– not the first PII scanner (others own data-at-rest)
– not the first runtime AI security (Lakera exists)

The wedge is the intersection none of them sit in. ⬇️ [score screenshot]

**7/**
Free scanner stays free.
A hosted tier — 24/7 monitoring + the DPDP/ISO-42001 evidence report your auditor accepts — is coming.

⭐ the repo, scan something you own, tell me what breaks: <github url>

*(Pin tweet 1. Lead the quote-replies with the scariest real finding once you've run the public scan.)*

---

## 3. LinkedIn post (for enterprise / government / investor eyeballs)

```
India is about to have an AI-security problem it can't see.

Every company is shipping LLM apps and AI agents. Very few are scanning them for
prompt injection, exposed MCP servers, or personal data leaking through code, logs
and model output — exactly the surface the DPDP Act (penalties to ₹250 crore,
enforcement 2027) will hold them accountable for.

The tools that watch this either went closed and enterprise-priced, or only scan
databases at rest — never the AI app itself.

So we open-sourced Vigil: a free, one-command security scanner for the AI you ship.
`npx <name> scan https://your-app.com` → a score and a fix list in seconds.

A hosted tier with 24/7 monitoring and an auditor-ready DPDP / ISO-42001 evidence
report is coming next.

If you're deploying AI in a regulated business in India, I'd genuinely like 20
minutes of your time to learn what "AI risk" means inside your org today.

Repo + waitlist 👇
```
*This post doubles as buyer-discovery outreach — the comments/DMs ARE your discovery calls.*

---

## 4. The launch-amplifier: the vulnerability-scan REPORT

This is the content flywheel — the artifact that makes press + investors notice. Run Vigil across a real, public, *authorized-scope* sample and publish the aggregate (anonymized) findings.

**Working title:** *"The State of AI App Security in India — what we found scanning 1,000 public sites & AI apps"*

**Outline:**
1. **Why we looked** — AI apps everywhere, security tooling blind, DPDP clock ticking.
2. **Method** — what Vigil scanned (public posture only: headers/TLS, exposed secrets in client JS, invisible-Unicode, publicly reachable MCP endpoints), sample size, anonymized, scope/ethics note (only externally observable, no exploitation).
3. **Headline findings** — the screenshot-able stats: *X% missing CSP/HSTS · Y% leak an API key or PAN in client JS · Z exposed MCP servers with no auth · N pages carrying hidden-Unicode instructions.*
4. **The DPDP angle** — how many would fail a DPDP exposure check, translated to ₹-risk.
5. **The five fixes** — concrete, so it's useful, not just scary.
6. **What this means** — the AI-security gap, why OSS + dev-first, why now.
7. **CTA** — scan your own app: `npx <name> scan`.

*Distribution: blog on starvoxlabs.io → X thread of the top stats → LinkedIn for enterprise → pitch to Indian tech press (Inc42, YourStory, MediaNama — MediaNama loves DPDP angles) → submit to HN as a follow-up "we scanned 1,000 sites" post (often outperforms the tool launch itself).*

**⚠️ Ethics/legal guardrail:** scan only externally-observable posture, never send active `ai`/`mcp` probes to systems you don't own, anonymize everything, and say so loudly. A trust brand caught doing unauthorized scanning is dead on arrival.

---

## 5. Sustain rhythm (post-launch)

- **X:** "injection of the week" — one real finding, in operator voice.
- **LinkedIn:** weekly long-form for buyers (CISO/gov/risk).
- **GitHub:** ship visibly — close issues, merge community scanner PRs, public roadmap.
- **Integrations as distribution:** a GitHub Action, a Bumblebee-interop story ("Bumblebee tells you which MCP servers you have; Vigil tells you which are dangerous"), SARIF for code-scanning.
- **Reels:** only as 30s repurposed clips of the above. Never the origin.
