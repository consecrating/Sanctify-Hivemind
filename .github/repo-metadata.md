# GitHub repo metadata (paste into the "About" panel)

> The **description / website / topics** live in GitHub's repo settings, not in the
> code. Set them once via **the repo home page → About → ⚙️ (Edit)**, or with the
> `gh` commands below. Copy-paste ready.

---

## Description (≈ short, one line)
Pick one:

**Full:**
```
🧠 Multi-agent orchestration framework for autonomous operations on live systems — plan→execute→verify→rollback with capability-scoped tools, an actor-critic loop, and an MCP server. First environment: WordPress (malware/CVE + Japanese/Russian keyword-hack & cloaking detection). By Sanctify.
```

**Concise (fits GitHub's ~350-char limit comfortably):**
```
🧠 Multi-agent framework for autonomous, safe operations on live WordPress sites: recon, malware/CVE + SEO-spam detection, capability-scoped tools, actor-critic verification, snapshot→rollback, and an MCP server for Kiro/ChatGPT/Codex/Gemini. By Sanctify.
```

## Website
```
https://www.sanctify.in/
```

## Topics (tags)
```
multi-agent  ai-agents  agent-orchestration  autonomous-agents  actor-critic
mcp  model-context-protocol  wordpress  wordpress-security  malware-detection
seo  cybersecurity  python  llm-agents  devsecops
```

---

## Set it with the GitHub CLI (if you have edit rights)

```bash
# Description + website
gh api -X PATCH repos/consecrating/Sanctify-Hivemind \
  -f description="🧠 Multi-agent framework for autonomous, safe operations on live WordPress sites: recon, malware/CVE + SEO-spam detection, capability-scoped tools, actor-critic verification, snapshot→rollback, and an MCP server for Kiro/ChatGPT/Codex/Gemini. By Sanctify." \
  -f homepage="https://www.sanctify.in/"

# Topics
gh api -X PUT repos/consecrating/Sanctify-Hivemind/topics \
  -H "Accept: application/vnd.github+json" \
  -f "names[]=multi-agent" -f "names[]=ai-agents" -f "names[]=agent-orchestration" \
  -f "names[]=autonomous-agents" -f "names[]=actor-critic" -f "names[]=mcp" \
  -f "names[]=model-context-protocol" -f "names[]=wordpress" -f "names[]=wordpress-security" \
  -f "names[]=malware-detection" -f "names[]=seo" -f "names[]=cybersecurity" \
  -f "names[]=python" -f "names[]=llm-agents" -f "names[]=devsecops"
```

## Or in the browser (30 seconds)
1. Open https://github.com/consecrating/Sanctify-Hivemind
2. Click the **⚙️ gear** next to **About** (top-right of the page).
3. Paste the **Description**, set **Website** to `https://www.sanctify.in/`, add the
   **Topics**, tick *"Use your GitHub Pages website"* off, then **Save changes**.

---

_Maintained by [Sanctify — Digital Marketing Agency, Goa](https://www.sanctify.in/)._
