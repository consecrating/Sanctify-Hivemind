# Using Sanctify-Hivemind from Kiro / ChatGPT / Codex / Gemini / Grok

Sanctify-Hivemind can be consumed two ways:

- **A) As an MCP tool** — the recommended, native path. One server exposes Hivemind's
  agents as Model Context Protocol tools. **Kiro, ChatGPT (desktop), Codex, and the
  Gemini CLI all speak MCP**, so they get Hivemind as first-class tools.
- **B) As a Python library / CLI** — any assistant that can run code (Codex, ChatGPT
  code-interpreter, Gemini CLI, **Grok** code mode) can `import hivemind` or call the
  `hivemind` CLI directly.

> **Credentials never touch the model.** The MCP server reads the target site + creds
> from **its own environment / a gitignored `.env`**. The model can only *invoke* tools;
> it cannot supply the target URL or secrets. This is a deliberate safety boundary
> (prevents prompt-driven SSRF and credential leakage).

---

## 0. One-time install

```bash
git clone https://github.com/consecrating/Sanctify-Hivemind.git
cd Sanctify-Hivemind
pip install -e ".[mcp,wordpress]"     # MCP server + WordPress adapter
cp .env.example .env                   # set WP_URL (+ creds only if acting, not just recon)
```

Sanity check (no live site needed):
```bash
python examples/demo_offline.py        # end-to-end demo
hivemind-mcp                            # starts the MCP stdio server (Ctrl-C to stop)
```

The MCP server exposes these tools:

| Tool | Access | What it does |
|------|--------|--------------|
| `hivemind.recon` | read-only | Fingerprint the site (stack, plugins, exposed files, headers) |
| `hivemind.security_scan` | read-only | Malware IOCs (SCV family) + vulnerable-plugin CVEs |
| `hivemind.seo_spam_scan` | read-only | Japanese/Russian keyword-hack + **cloaking** (Googlebot-vs-browser diff) |
| `hivemind.run_goal` | varies | Run a natural-language goal through the orchestrator |

---

## A) MCP configuration (copy-paste per assistant)

The launch command is the same everywhere: run `hivemind-mcp` over **stdio**, with the
target site in the server's env.

### Kiro
`.kiro/settings/mcp.json` (a ready example ships in this repo):
```json
{
  "mcpServers": {
    "sanctify-hivemind": {
      "command": "hivemind-mcp",
      "env": { "WP_URL": "https://your-site.com" },
      "disabled": false,
      "autoApprove": ["hivemind.recon", "hivemind.security_scan", "hivemind.seo_spam_scan"]
    }
  }
}
```
Kiro also auto-loads the bundled `.kiro/steering` + `hivemind` skill, so it knows *when*
to reach for these tools. (Already wired into SuperBrain's bootstrap.)

### ChatGPT (desktop app → Settings → Connectors / MCP)
```json
{
  "mcpServers": {
    "sanctify-hivemind": {
      "command": "hivemind-mcp",
      "env": { "WP_URL": "https://your-site.com" }
    }
  }
}
```
If the app requires an absolute path, use the venv binary, e.g.
`"command": "/path/to/venv/bin/hivemind-mcp"`, or
`"command": "python", "args": ["-m", "hivemind.mcp_server"]`.

### Codex (Codex CLI → `~/.codex/config.toml`)
```toml
[mcp_servers.sanctify-hivemind]
command = "hivemind-mcp"
args = []
env = { WP_URL = "https://your-site.com" }
```
(Equivalently `command = "python"`, `args = ["-m", "hivemind.mcp_server"]`.)

### Gemini CLI (`~/.gemini/settings.json`)
```json
{
  "mcpServers": {
    "sanctify-hivemind": {
      "command": "hivemind-mcp",
      "env": { "WP_URL": "https://your-site.com" }
    }
  }
}
```
Then in a Gemini CLI session the tools appear as `sanctify-hivemind.*`.

After configuring, ask the assistant e.g. *"Run a security scan on the site with
sanctify-hivemind"* and it will call `hivemind.security_scan`.

---

## B) Code / CLI path (works for Grok and any code-running assistant)

Grok has no first-class MCP/tool ecosystem yet, so drive Hivemind as code. Any
assistant with a code sandbox or shell can do the same.

### CLI (machine-readable output)
```bash
export WP_URL="https://your-site.com"
hivemind run "audit and secure this site" --json
hivemind run "scan for japanese/russian keyword hack and cloaking" --json
```

### Python
```python
import os
os.environ["WP_URL"] = "https://your-site.com"

from hivemind.app import build_wordpress_orchestrator
orch = build_wordpress_orchestrator(offline=False)   # reads creds from env/.env
report = orch.run("audit and secure this site")

print(report.ok, report.findings["security"]["counts"])
for tid, r in report.results.items():
    print(tid, r.summary)
```

### Call individual tools directly (no MCP needed)
```python
from hivemind.mcp_server import tool_recon, tool_security_scan, tool_seo_spam_scan
import os; os.environ["WP_URL"] = "https://your-site.com"

print(tool_seo_spam_scan())   # returns a JSON-serialisable dict
```

---

## Safety notes for every integration
1. **Secrets stay server-side.** Put `WP_URL` (and, only if you need write actions,
   `WP_USER` / `WP_APP_PASSWORD` / `FTP_*`) in the server's env or a gitignored `.env`.
2. **Least privilege.** Recon and all `*_scan` tools are **read-only**. Write actions
   go through the capability model's approval gate + `SafeChange` rollback.
3. **Auto-approve only reads.** In client config, only auto-approve the read-only tools
   (as in the Kiro example); leave `run_goal` manual so writes stay gated.
4. **One site per server instance.** The target is fixed by env, so a running server
   can only act on the site it was configured for.

---

Built by **[Sanctify — Digital Marketing Agency, Goa](https://www.sanctify.in/)**.
