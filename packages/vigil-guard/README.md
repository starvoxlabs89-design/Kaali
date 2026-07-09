# 🛡️ @starvoxlabs89-design/vigil-guard

**Runtime AI security guard for Node.js.** Drop-in Express/Next middleware that blocks prompt injection, decodes invisible-Unicode smuggling, redacts Indian PII (DPDP), and firewalls MCP tool calls — in ~2 microseconds per request. Zero dependencies.

```bash
npm install @starvoxlabs89-design/vigil-guard
```

```js
import express from "express";
import { guard } from "@starvoxlabs89-design/vigil-guard";

const g = guard({
  block: ["prompt-injection", "invisible-unicode"],
  redactTypes: ["aadhaar", "pan", "phone_in", "email"],
  mcp: { allow: ["search", "fs.read"] },
  onEvent: (e) => console.log(e),  // stream to your logger / Vigil Cloud
});

const app = express();
app.use(express.json());
app.use("/chat", g.middleware({ field: "message" }));

app.post("/chat", async (req, res) => {
  // req.body.message is already sanitized (PII masked, invisible-unicode stripped).
  // Injection attempts already returned 400 before your handler ran.
  const reply = await callYourLLM(req.body.message);
  const out = g.checkOutput(reply);
  res.json({ reply: out.sanitized });        // Aadhaar/PAN in the LLM reply are masked
});
```

## What it blocks

| Threat | How | Cost |
|---|---|---|
| **Direct prompt injection** | Curated heuristic regex (OWASP LLM01 patterns) | ~2µs |
| **Invisible-Unicode smuggling** | Detects + **decodes** U+E00xx tag chars, zero-width, bidi override | ~1µs |
| **Indian PII leakage** | Aadhaar (Verhoeff-validated), PAN, mobile, email — **masked in flight** | ~3µs |
| **MCP tool-call abuse** | Allowlist / denylist + threat scan of tool arguments | ~2µs |

All in-process. No network hop. No API key. No telemetry unless you wire `onEvent`.

## Latency (measured, honest)

```
20,000 iterations · 38.2ms total · 1.91µs per call · 523,623 req/s single-threaded
```

For context: Meta's Llama Prompt Guard 2 (86M) takes **92.4ms** per classification on an A100 GPU at 512 tokens ([model card](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M)). Hosted guards' advertised sub-50ms figures are network-bound and only plausible via smaller models, shorter inputs, or hybrid regex-first pipelines. Vigil-guard skips the classifier entirely and is pure in-process regex — different tradeoffs (see below).

## API

```js
const g = guard(opts);
g.checkInput(text)  // { allowed, blocked, reason, threats, pii, sanitized }
g.checkOutput(text) // same shape — use it on LLM responses too
g.checkToolCall({ name, args })  // { allowed, violations }
g.redact(text)      // just the sanitizer
g.middleware(opts)  // Express-compatible middleware
```

### Next.js App Router

```js
import { withGuard } from "@starvoxlabs89-design/vigil-guard/next";
export const POST = withGuard(async (req) => {
  const { message } = await req.json();       // already sanitized
  return Response.json({ reply: await callLLM(message) });
}, { field: "message" });
```

### Monitor mode (don't block, just observe)

```js
guard({ mode: "monitor", onEvent: (e) => metrics.write(e) });
```

## How this compares (honest, June 2026)

| | vigil-guard | Superagent (`safety-agent`) | Cloudflare Firewall for AI | Lakera Guard | NeMo Guardrails | Guardrails AI | llm-guard |
|---|---|---|---|---|---|---|---|
| **Runtime shape** | Node middleware | TS/Python SDK | edge reverse proxy | hosted API | Python library | Python library | Python library |
| **Language** | **Node/JS** | TS + Python | proxy (any) | any (HTTP) | Python 99% | Python | Python |
| **License** | MIT | MIT | closed | closed | Apache-2.0 | Apache-2.0 | MIT |
| **Detection** | regex | classifier + heuristic | Presidio NER + regex (+classifier) | classifier | classifier + rails | classifiers + validators | classifier + regex |
| **Latency** | ~2µs | ~classifier | edge hop | claimed <50ms | classifier | classifier | classifier |
| **DPDP / Aadhaar / PAN** | ✅ Verhoeff | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Invisible-Unicode decode** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **MCP tool-call firewall** | ✅ | agent-level | ❌ | partial | ❌ | ❌ | ❌ |
| **Dependencies** | **0** | many | N/A (proxy) | HTTP client | heavy | heavy | heavy |
| **Express/Next middleware form** | ✅ | ❌ (SDK) | N/A (proxy) | ❌ (HTTP) | ❌ | ❌ | ❌ |

**Where vigil-guard sits:** the only OSS that combines **Node/Express middleware form-factor + zero-dependency offline mode + MCP-aware filtering + DPDP-native PII redaction + invisible-Unicode decode.** Any one of those axes is contested; the *bundle* is unclaimed.

## Honest tradeoffs

- **Regex-first, no classifier.** Fast and FP-lean, but sophisticated *encoded* injections will slip past — same as every OSS guard until a classifier is plugged in. A pluggable classifier hook is on the roadmap.
- **Not a substitute for output-side canary filtering + instruction-hierarchy enforcement** in your prompt. This is defence-in-depth, not a magic shield.
- **Benchmark reality check:** academic evals (arXiv 2506.19109) show classifier scanners hit 0.968–1.000 recall at **1.4%–15.7% FPR** — sentence-mode LLM-Guard hits ~100% recall at ~15.7% FPR, destructive for benign traffic. Vigil-guard trades a lower recall ceiling for near-zero FPR on ordinary prompts.
- **Name note:** an alpha OSS project `deadbits/vigil-llm` exists (last release Dec 2023). This package is the maintained Node runtime guard; no code lineage.

## Pairs with the Vigil scanner

```bash
npx @starvoxlabs89-design/vigil scan https://your-site.com   # CI / scan-time
npm install @starvoxlabs89-design/vigil-guard                # request-time
```

The scanner tells you what's broken. The guard blocks it as it happens. Same detection primitives; same events shape.

## License

MIT © 2026
