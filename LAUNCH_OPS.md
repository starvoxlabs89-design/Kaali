# Vigil — Launch Ops (npm + GitHub + demo GIF)

Everything below is copy-paste. Do them in order. `<>` = fill in. Run from the repo root: `cd /Volumes/AI/vigil`.

---

## 0. One-time prerequisites

- **npm account** on the `starvoxlabs89-design` org/scope. Create the org (free for public packages): npmjs.com → your avatar → *Add Organization* → name it `starvoxlabs89-design` → **Unlimited / public**.
- **GitHub org** `starvoxlabs89-design` — already created; the `origin` remote already points at `github.com/starvoxlabs89-design/vigil`.
- Node ≥20 (you have v24 ✓).

---

## 1. Publish `@starvoxlabs89-design/vigil` to npm

The package is already configured: scoped name, `publishConfig.access=public`, `files` allow-list, `bin` → `vigil`.

```bash
cd /Volumes/AI/vigil

# sanity: exactly what will ship (should be bin/, src/, README, LICENSE, package.json — nothing else)
npm pack --dry-run

# log in (opens browser)
npm login

# publish (scoped + public)
npm publish --access public
```

Verify it works from a clean machine / npx cache:

```bash
npx @starvoxlabs89-design/vigil@latest scan https://example.com
```

**Version bumps later:** edit code → `npm version patch` (or `minor`) → `npm publish`.

> If `npm login` is 2FA-gated in CI, create an automation token (npm → Access Tokens → *Automation*) and `npm publish` with `NPM_TOKEN` in the env.

---

## 2. Public GitHub repo `github.com/starvoxlabs89-design/vigil`

```bash
cd /Volumes/AI/vigil

# make sure secrets/screenshots aren't committed
cat .gitignore   # confirm node_modules, .DS_Store, *.png scratch, .claude/ are ignored

git init -b main
git add -A
git commit -m "Vigil v0.1 — open-source security scanner for AI apps, agents & MCP"

# create the repo under the org and push (needs gh CLI: brew install gh && gh auth login)
gh repo create starvoxlabs89-design/vigil --public --source=. --remote=origin \
  --description "Open-source security scanner for AI agents, LLM apps & MCP servers. DPDP-ready." --push
```

No `gh`? Create the empty repo in the GitHub UI, then:

```bash
git remote add origin https://github.com/starvoxlabs89-design/vigil.git
git push -u origin main
```

**After push — 10-minute credibility polish:**
- Repo *About*: set the description + `starvoxlabs.io` as the website + topics: `ai-security llm-security prompt-injection mcp dpdp appsec security-tools`.
- Pin `good first issue`s (e.g. "add secrets provider X", "new injection probe") — invites contributors = the community-scanner moat.
- Add the GitHub Action to the Marketplace later (`action.yml` already exists).

---

## 3. Demo GIF (the single highest-ROI launch asset)

A terminal GIF of `vigil scan` finding scary things goes at the top of the README + into every launch post. Best tool: **asciinema + agg** (crisp, tiny, reproducible).

```bash
brew install asciinema agg     # macOS

# record a tight ~20s session
asciinema rec vigil-demo.cast --overwrite
#   in the recording, type slowly and deliberately:
#     npx @starvoxlabs89-design/vigil scan https://example.com
#   let the report render, then:  exit
# (Ctrl-D stops the recording)

# render to GIF (theme + size tuned for README)
agg vigil-demo.cast docs/demo.gif --theme monokai --font-size 26 --cols 92 --rows 30
```

Then reference it at the top of README.md:

```markdown
<p align="center"><img src="docs/demo.gif" alt="Vigil scanning an app" width="760"></p>
```

**Want a scarier demo than example.com?** Stand up the throwaway target in `demo/` (it intentionally leaks a fake key + PII) and scan `http://localhost:<port>` so the GIF shows CRITICAL/HIGH findings + a low score — far more shareable than a clean 78. **Only ever scan targets you own.**

No-Homebrew fallback: record with **[terminalizer](https://github.com/faressoft/terminalizer)** (`npm i -g terminalizer` → `terminalizer record demo` → `terminalizer render demo`), or QuickTime screen-record the terminal and convert with `ffmpeg`.

---

## 4. Launch-day order (from LAUNCH_KIT.md)

1. npm published ✓ → `npx @starvoxlabs89-design/vigil` works from anywhere.
2. GitHub repo public ✓ with demo GIF + polished About.
3. Site live on `labs.starvoxlabs.io` ✓.
4. Post the **Show HN** + **X thread** + **LinkedIn** (all pre-written in `LAUNCH_KIT.md`), Tue–Thu ~8–9am PT.
5. Follow up ~1 week later with the **vulnerability-scan report** ("we scanned N Indian AI apps…") — often outperforms the tool launch itself.

---

## Done-check
- [ ] `npm view @starvoxlabs89-design/vigil` returns the package
- [ ] `npx @starvoxlabs89-design/vigil scan https://example.com` runs on a clean machine
- [ ] `github.com/starvoxlabs89-design/vigil` is public with README + demo GIF
- [ ] `labs.starvoxlabs.io` resolves to the landing page
- [ ] Show HN / X / LinkedIn drafts reviewed and scheduled
