#!/usr/bin/env python3
"""End-to-end offline demo — proves the whole architecture without a live site.

We build the WordPress orchestrator in OFFLINE mode and swap the adapter's HTTP
handler for a tiny *mock infected site* fixture (mimicking cpofficial.in's SCV
infection: a hex-named payload reachable, ThemeREX Addons present, exposed readme).

Run:
    python examples/demo_offline.py

You'll see: the plan (DAG), recon → security running with the actor→critic loop,
findings (malware + CVE), and the audit-trace summary.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hivemind.core.critic import Critic
from hivemind.core.memory import EnvironmentMemory
from hivemind.core.orchestrator import Orchestrator
from hivemind.core.safety import AuditTrace
from hivemind.core.tools import Access, ToolRegistry
from hivemind.agents import ReconAgent, SecurityAgent
from hivemind.environments.wordpress import WordPressAdapter, WPConfig
from hivemind.planners import rule_based_planner


# ── a mock infected site (fixture) ───────────────────────────────────────
INFECTED_HOME = """
<html><head>
<meta name="generator" content="WordPress 6.4.2" />
</head><body>
<link rel='stylesheet' href='/wp-content/themes/nuts/style.css' />
<script src='/wp-content/plugins/trx_addons/js/app.js'></script>
<script src='/wp-content/plugins/revslider/rs6.min.js'></script>
<script src='/wp-content/plugins/elementor/frontend.min.js'></script>
</body></html>
"""

# paths the mock returns 200 for (the "infection")
INFECTED_200 = {
    "/", "/readme.html",
    "/wp-content/64f6b5eb.php",                 # SCV loader IOC
    "/wp-content/mu-plugins/smooth-backup-ink.php",  # SCV mu-plugin IOC
}


# Cloaked SEO spam: the page served to GOOGLEBOT carries Japanese counterfeit-goods
# spam ("正規品" / "限定モデル") that a normal browser never sees — the exact hack
# from the SERP screenshot. A normal visitor gets the clean casino homepage.
CLOAKED_SPAM_HOME = """
<html><head>
<title>HOT！シャクティワンダーボール 正規品</title>
<meta name="description" content="みびょ品です。※WWW.CPOFFICIAL.IN 限定モデル 激安 通販" />
</head><body><h1>正規品</h1></body></html>
"""

GOOGLEBOT = "Googlebot"


def mock_http_get(path: str = "/", user_agent: str = None) -> dict:
    if path == "/" or path == "":
        # Cloaking: serve spam to Googlebot, clean page to everyone else.
        if user_agent and "Googlebot" in user_agent:
            return {"url": path, "status": 200, "headers": {}, "text": CLOAKED_SPAM_HOME, "ua": user_agent}
        return {"url": path, "status": 200, "headers": {}, "text": INFECTED_HOME}
    if path in INFECTED_200:
        return {"url": path, "status": 200, "headers": {}, "text": "<?php /* SCV:4.3.24 */"}
    return {"url": path, "status": 404, "headers": {}, "text": ""}


def mock_rest_get(route: str, params=None):
    if route == "/wp/v2/plugins":
        return [
            {"plugin": "trx_addons/trx_addons.php", "version": "2.29.0", "status": "active"},
            {"plugin": "revslider/revslider.php", "version": "6.6.20", "status": "active"},
            {"plugin": "elementor/elementor.php", "version": "4.2.4", "status": "active"},
        ]
    return {"route": route}


def main() -> int:
    cfg = WPConfig(url="https://demo.example", user="demo", app_password="x")
    registry = ToolRegistry()
    adapter = WordPressAdapter(cfg, offline=True)
    # inject the mock fixture in place of live network calls
    adapter.http_get = mock_http_get          # type: ignore[assignment]
    adapter.rest_get = mock_rest_get          # type: ignore[assignment]
    adapter.register(registry)

    orch = Orchestrator(
        registry=registry,
        agents={"recon": ReconAgent(), "security": SecurityAgent()},
        planner=rule_based_planner,
        env_memory=EnvironmentMemory(cfg.url),
        critic=Critic(max_retries=1),
        trace=AuditTrace(),
    )

    report = orch.run("audit and secure this site")

    print("\n🧠 Sanctify-Hivemind — offline demo")
    print("=" * 60)
    print("GOAL:", report.goal)
    print("\nPLAN (DAG):")
    for t in report.tasks:
        deps = f"  ⇐ {t.deps}" if t.deps else ""
        print(f"  [{t.status.value:7}] {t.id} → agent:{t.agent}{deps}")

    print("\nRESULTS (actor → critic):")
    for tid, r in report.results.items():
        print(f"  {'✅' if r.ok else '❌'} {tid}: {r.summary}")

    sec = report.findings.get("security", {})
    print("\nSECURITY FINDINGS:")
    print(f"  infected: {sec.get('infected')} | counts: {sec.get('counts')} | rules: {sec.get('rules_version')}")
    for f in sec.get("findings", []):
        print(f"   • [{f['severity']:8}] {f['ref']:16} {f['detail'][:80]}")

    print("\nTRACE SUMMARY:", report.trace_summary)
    print("=" * 60)
    # Demo asserts the architecture actually detected the planted infection.
    assert sec.get("infected") is True, "expected infection to be detected"
    assert any(f["kind"] == "cve" for f in sec.get("findings", [])), "expected CVE findings"
    assert sec.get("seo_spam") is True, "expected SEO-spam to be detected"
    assert any(f["ref"] == "cloaking" for f in sec.get("findings", [])), \
        "expected CLOAKING (Googlebot-only spam) to be detected"
    print("✅ architecture verified: recon→security ran; malware + CVEs + cloaked "
          "Japanese-keyword SEO spam detected; trace recorded.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
