// Server-side URL scanner used by POST /scan. Reimplements the two web-observable
// scanners from the CLI (headers + poisoned-content) so the Cloud can run them
// without shell-executing the CLI. Zero deps (Node built-in fetch).
//
// SSRF-hardened: blocks private/loopback/cloud-metadata targets.
import { lookup } from "node:dns/promises";

const SEVERITY_WEIGHT = { critical: 40, high: 20, medium: 8, low: 3, info: 0 };

// --- SSRF guard --------------------------------------------------------------
const PRIVATE_RANGES = [
  /^127\./, /^10\./, /^192\.168\./, /^0\./, /^169\.254\./,     // v4 private + link-local
  /^172\.(1[6-9]|2\d|3[01])\./,                                // 172.16/12
  /^::1$/, /^fe80::/i, /^fc00::/i, /^fd00::/i,                 // v6 loopback + private
];
const BAD_HOSTS = new Set(["localhost", "0.0.0.0", "metadata.google.internal", "instance-data"]);

async function ssrfSafe(urlStr) {
  let u;
  try { u = new URL(urlStr); } catch { return { ok: false, reason: "invalid URL" }; }
  if (!/^https?:$/.test(u.protocol)) return { ok: false, reason: "only http/https allowed" };
  if (BAD_HOSTS.has(u.hostname.toLowerCase())) return { ok: false, reason: "host not allowed" };
  try {
    const addrs = await lookup(u.hostname, { all: true });
    for (const { address } of addrs) {
      if (PRIVATE_RANGES.some((re) => re.test(address))) {
        return { ok: false, reason: "target resolves to a private address" };
      }
    }
  } catch {
    return { ok: false, reason: "DNS lookup failed" };
  }
  return { ok: true };
}

async function safeFetch(url, opts = {}, timeoutMs = 10000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try { return await fetch(url, { redirect: "follow", ...opts, signal: ctrl.signal }); }
  finally { clearTimeout(t); }
}

// --- Web headers scanner -----------------------------------------------------
const HEADER_CHECKS = [
  { header: "strict-transport-security", severity: "medium", title: "Missing HSTS", fix: "Add Strict-Transport-Security: max-age=63072000; includeSubDomains" },
  { header: "content-security-policy",   severity: "medium", title: "Missing Content-Security-Policy", fix: "Define a CSP to mitigate XSS / data injection" },
  { header: "x-frame-options",           severity: "low",    title: "Missing X-Frame-Options", fix: "Set X-Frame-Options: DENY (or use CSP frame-ancestors)" },
  { header: "x-content-type-options",    severity: "low",    title: "Missing X-Content-Type-Options", fix: "Set X-Content-Type-Options: nosniff" },
  { header: "referrer-policy",           severity: "info",   title: "Missing Referrer-Policy", fix: "Set Referrer-Policy: strict-origin-when-cross-origin" },
];

function checkHeaders(res, target) {
  const findings = [];
  const h = res.headers;
  for (const c of HEADER_CHECKS) {
    if (!h.get(c.header)) findings.push({ id: `web-${c.header}`, title: c.title, severity: c.severity, fix: c.fix, owasp: "OWASP-Web" });
  }
  for (const leak of ["server", "x-powered-by", "x-aspnet-version"]) {
    const v = h.get(leak);
    if (v && /[0-9]/.test(v)) {
      findings.push({ id: `web-leak-${leak}`, title: `Version disclosure via ${leak}`, severity: "low", evidence: `${leak}: ${v}`, fix: `Strip or obfuscate the ${leak} header`, owasp: "OWASP-Web" });
    }
  }
  if (target.startsWith("http://")) {
    findings.push({ id: "web-no-tls", title: "Served over plaintext HTTP", severity: "high", detail: "Personal data in transit is unencrypted.", dpdp: "reasonable-security-safeguards", fix: "Force HTTPS and redirect all HTTP traffic." });
  }
  return findings;
}

// --- Poisoned content scanner ------------------------------------------------
const INVISIBLE = [
  { re: /[\u{E0000}-\u{E007F}]/u, id: "unicode-tags", name: "Unicode Tag chars (U+E00xx)" },
  { re: /[​-‍⁠﻿]/u, id: "zero-width", name: "zero-width chars" },
  { re: /[‪-‮⁦-⁩]/u, id: "bidi", name: "bidirectional override chars" },
];
const INSTRUCTION = [
  /ignore (all |the |your )?(previous|prior|above) (instructions|prompt)/i,
  /\b(ai|assistant|model|agent|llm|chatbot)[:\s,].{0,60}(ignore|disregard|instead|must|output|print|reply|append|reveal|tell|email)/i,
  /system\s*(override|prompt|directive|instruction)/i,
  /do not (tell|reveal|mention|inform) the user/i,
  /(exfiltrate|send|email).{0,50}(https?:|password|api[_-]?key|secret|token)/i,
];
function decodeTagChars(text) {
  let out = "";
  for (const ch of text) {
    const cp = ch.codePointAt(0);
    if (cp >= 0xe0000 && cp <= 0xe007f) out += String.fromCharCode(cp - 0xe0000);
  }
  return out;
}
function extractHidden(html) {
  const comments = [...html.matchAll(/<!--([\s\S]*?)-->/g)].map((m) => m[1]).join("\n");
  const hiddenEls = [...html.matchAll(/<[^>]+(?:display\s*:\s*none|visibility\s*:\s*hidden|aria-hidden\s*=\s*["']true["']|hidden)[^>]*>([\s\S]*?)<\//gi)].map((m) => m[1]).join("\n");
  return `${comments}\n${hiddenEls}`;
}
function checkContent(body) {
  const findings = [];
  for (const inv of INVISIBLE) {
    if (inv.re.test(body)) {
      const decoded = inv.id === "unicode-tags" ? decodeTagChars(body) : "";
      const dangerous = decoded && INSTRUCTION.some((r) => r.test(decoded));
      findings.push({
        id: `content-${inv.id}`,
        title: `Invisible characters detected (${inv.name})`,
        severity: dangerous ? "critical" : "high",
        detail: dangerous ? `hidden instruction decoded: "${decoded.slice(0, 120)}"` : "Invisible characters can smuggle instructions to an AI reader.",
        evidence: inv.name,
        owasp: "LLM01:2025",
        fix: "Strip non-printable/tag/zero-width/bidi Unicode from any content before an LLM reads it.",
      });
    }
  }
  const hidden = /<[a-z!]/i.test(body) ? extractHidden(body) : "";
  for (const re of INSTRUCTION) {
    const m = hidden && hidden.match(re);
    if (m) {
      findings.push({
        id: "content-hidden-instruction",
        title: "Hidden AI-targeted instruction in markup",
        severity: "critical",
        detail: "Instruction-like text aimed at an assistant is concealed in a comment or hidden element.",
        evidence: m[0].slice(0, 120),
        owasp: "LLM01:2025",
        fix: "Sanitize HTML comments/hidden nodes from agent-ingested content; render to plain text first.",
      });
      break;
    }
  }
  return findings;
}

// --- Public entry ------------------------------------------------------------
export async function scanUrl(target) {
  const guard = await ssrfSafe(target);
  if (!guard.ok) return { ok: false, error: guard.reason };

  let res;
  try { res = await safeFetch(target); }
  catch (e) { return { ok: false, error: `unreachable: ${e.message || e}` }; }

  const findings = checkHeaders(res, target);
  try {
    const body = (await res.text()).slice(0, 500_000);
    findings.push(...checkContent(body));
  } catch { /* body read failure — headers still count */ }

  findings.sort((a, b) => (SEVERITY_WEIGHT[b.severity] || 0) - (SEVERITY_WEIGHT[a.severity] || 0));
  let penalty = 0; for (const f of findings) penalty += SEVERITY_WEIGHT[f.severity] || 0;
  const score = Math.max(0, 100 - penalty);
  return { ok: true, target, score, findings, http_status: res.status };
}
