"""Recon agent — READ-only site reconnaissance.

Given only a URL (no credentials), it fingerprints the site: WordPress?, theme,
detectable plugins, generator/version leaks, exposed sensitive files, and basic
security-header posture. It publishes a structured ``stack`` to the blackboard and
persists durable facts to the environment world-model so future runs start warm.

Capability: READ only, scoped to public HTTP. It cannot change anything — enforced by
the capability model, not by good behaviour.
"""

from __future__ import annotations

import re

from ..core.agent import Agent, AgentContext, Task, TaskResult
from ..core.tools import Access, CapabilityGrant


class ReconAgent(Agent):
    name = "recon"
    capabilities = CapabilityGrant(max_access=Access.READ, scopes={"wp.http"})

    # Lightweight fingerprints — extend freely.
    _PLUGIN_RE = re.compile(r"/wp-content/plugins/([a-z0-9\-_]+)/", re.I)
    _THEME_RE = re.compile(r"/wp-content/themes/([a-z0-9\-_]+)/", re.I)
    _GEN_RE = re.compile(r'<meta name="generator" content="([^"]+)"', re.I)

    def run(self, task: Task, ctx: AgentContext) -> TaskResult:
        home = ctx.tools.invoke("wp.http_get", path="/")
        html = home.get("text", "") or ""
        headers = home.get("headers", {}) or {}

        is_wp = ("/wp-content/" in html) or ("wp-json" in html) or ("wp-includes" in html)
        plugins = sorted(set(self._PLUGIN_RE.findall(html)))
        themes = sorted(set(self._THEME_RE.findall(html)))
        gen = self._GEN_RE.search(html)

        # Cheap sensitive-file exposure probes (READ only).
        exposed = {}
        for path in ("/readme.html", "/wp-content/debug.log", "/.user.ini"):
            r = ctx.tools.invoke("wp.http_get", path=path)
            code = r.get("status")
            if code and int(code) == 200 and r.get("text"):
                exposed[path] = "accessible"

        # Security-header posture (informational).
        sec_headers = {
            h: (h.lower() in {k.lower() for k in headers})
            for h in ("Strict-Transport-Security", "X-Frame-Options",
                      "Content-Security-Policy", "X-Content-Type-Options")
        }

        stack = {
            "is_wordpress": is_wp,
            "themes": themes,
            "plugins": plugins,
            "generator": gen.group(1) if gen else None,
            "exposed_files": exposed,
            "security_headers": sec_headers,
            "home_status": home.get("status"),
        }

        # Coordinate: publish to blackboard for downstream agents; persist to world-model.
        ctx.blackboard.put("stack", stack)
        ctx.memory.remember("stack", stack)
        self._log(ctx, "recon complete",
                  wordpress=is_wp, plugins=len(plugins), themes=themes)

        summary = (
            f"WordPress={is_wp}; theme(s)={themes or 'unknown'}; "
            f"{len(plugins)} plugin(s) detected; "
            f"{len(exposed)} exposed sensitive file(s)."
        )
        return TaskResult(ok=True, summary=summary, findings={"stack": stack})
