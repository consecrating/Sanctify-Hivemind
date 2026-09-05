"""MCP server — exposes Sanctify-Hivemind capabilities as Model Context Protocol tools.

MCP is the common denominator across assistants (Kiro, ChatGPT desktop, Codex, and the
Gemini CLI all speak it), so one server makes Hivemind a first-class *tool* for all of
them — not just something they drive by writing code.

Tools exposed (all credential-free; secrets come from the server's env / a gitignored
.env, never from the model):

  - hivemind.recon         : READ-only site fingerprint (stack, plugins, exposure)
  - hivemind.security_scan : malware IOCs + vulnerable-plugin CVEs
  - hivemind.seo_spam_scan : Japanese/Russian keyword-hack + cloaking detection
  - hivemind.run_goal      : run a natural-language goal through the orchestrator

Transport: stdio (the format every MCP client launches). Run with:
    hivemind-mcp                 # console entry point
    python -m hivemind.mcp_server

If the optional ``mcp`` package is not installed, importing this module still works
(so the rest of the framework is unaffected); ``main()`` prints an install hint.
"""

from __future__ import annotations

import json
import os
from typing import Any

# ── target site comes from env, NEVER from the model (prevents SSRF-by-prompt) ──
def _target_url() -> str:
    url = os.environ.get("WP_URL", "").strip().rstrip("/")
    if not url:
        raise RuntimeError(
            "WP_URL is not set. Configure it in the MCP server's env / .env "
            "(the model cannot supply the target — this is a safety boundary)."
        )
    return url


def _run(goal: str, offline: bool = False) -> dict:
    """Run a goal through the WordPress orchestrator and return a compact JSON report."""
    from .app import build_wordpress_orchestrator

    orch = build_wordpress_orchestrator(offline=offline)
    report = orch.run(goal)
    return {
        "goal": report.goal,
        "ok": report.ok,
        "target": _target_url(),
        "findings": report.findings,
        "trace": report.trace_summary,
        "results": {tid: {"ok": r.ok, "summary": r.summary} for tid, r in report.results.items()},
    }


# Tool implementations return JSON-serialisable dicts.
def tool_recon(offline: bool = False) -> dict:
    return _run("recon: fingerprint the site", offline=offline)


def tool_security_scan(offline: bool = False) -> dict:
    return _run("audit and secure this site: malware IOCs and vulnerable components", offline=offline)


def tool_seo_spam_scan(offline: bool = False) -> dict:
    return _run("scan for SEO spam, japanese/russian keyword hack and cloaking", offline=offline)


def tool_run_goal(goal: str, offline: bool = False) -> dict:
    if not goal or not goal.strip():
        raise ValueError("goal must be a non-empty instruction")
    return _run(goal.strip(), offline=offline)


TOOLS = {
    "hivemind.recon": {
        "fn": tool_recon,
        "description": "READ-only reconnaissance of the configured WordPress site: "
                       "detects stack, theme, plugins, exposed sensitive files, and "
                       "security-header posture. No credentials required.",
        "schema": {
            "type": "object",
            "properties": {
                "offline": {"type": "boolean", "default": False,
                            "description": "Dry-run with no live network (testing)."}
            },
        },
    },
    "hivemind.security_scan": {
        "fn": tool_security_scan,
        "description": "Detect malware IOCs (the self-healing 'Smooth Backup Ink'/SCV "
                       "family) and vulnerable plugins/themes via a versioned CVE rules "
                       "library. Returns prioritized findings.",
        "schema": {
            "type": "object",
            "properties": {"offline": {"type": "boolean", "default": False}},
        },
    },
    "hivemind.seo_spam_scan": {
        "fn": tool_seo_spam_scan,
        "description": "Detect the Japanese/Russian keyword-hack and cloaked SEO spam "
                       "class by fetching pages AS Googlebot and diffing against a normal "
                       "browser (catches spam invisible to visitors but indexed by Google).",
        "schema": {
            "type": "object",
            "properties": {"offline": {"type": "boolean", "default": False}},
        },
    },
    "hivemind.run_goal": {
        "fn": tool_run_goal,
        "description": "Run a natural-language goal (e.g. 'audit and secure this site') "
                       "through the multi-agent orchestrator: plan -> execute -> verify.",
        "schema": {
            "type": "object",
            "properties": {
                "goal": {"type": "string", "description": "Natural-language objective."},
                "offline": {"type": "boolean", "default": False},
            },
            "required": ["goal"],
        },
    },
}


def _build_modern_server():
    """mcp >= 2.x — high-level MCPServer with @tool decorators (schema auto-derived)."""
    from mcp.server.mcpserver import MCPServer

    server = MCPServer(name="sanctify-hivemind", version="0.1.0",
                       instructions="Autonomous WordPress security/SEO operations "
                                     "(recon, malware/CVE, keyword-hack/cloaking).")

    @server.tool(name="hivemind.recon", description=TOOLS["hivemind.recon"]["description"])
    def recon(offline: bool = False) -> dict:
        return tool_recon(offline=offline)

    @server.tool(name="hivemind.security_scan", description=TOOLS["hivemind.security_scan"]["description"])
    def security_scan(offline: bool = False) -> dict:
        return tool_security_scan(offline=offline)

    @server.tool(name="hivemind.seo_spam_scan", description=TOOLS["hivemind.seo_spam_scan"]["description"])
    def seo_spam_scan(offline: bool = False) -> dict:
        return tool_seo_spam_scan(offline=offline)

    @server.tool(name="hivemind.run_goal", description=TOOLS["hivemind.run_goal"]["description"])
    def run_goal(goal: str, offline: bool = False) -> dict:
        return tool_run_goal(goal=goal, offline=offline)

    return server


def _run_legacy_server() -> None:
    """mcp 1.x — low-level Server with list_tools/call_tool decorators."""
    import anyio
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import TextContent, Tool

    server = Server("sanctify-hivemind")

    @server.list_tools()
    async def list_tools() -> list["Tool"]:
        return [Tool(name=n, description=s["description"], inputSchema=s["schema"])
                for n, s in TOOLS.items()]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any] | None) -> list["TextContent"]:
        spec = TOOLS.get(name)
        if not spec:
            return [TextContent(type="text", text=json.dumps({"error": f"unknown tool: {name}"}))]
        try:
            result = await anyio.to_thread.run_sync(lambda: spec["fn"](**(arguments or {})))
            text = json.dumps(result, indent=2, default=str)
        except Exception as exc:  # noqa: BLE001
            text = json.dumps({"error": f"{type(exc).__name__}: {exc}"}, indent=2)
        return [TextContent(type="text", text=text)]

    async def _serve() -> None:
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())

    anyio.run(_serve)


def main() -> int:
    """Launch the MCP stdio server. Requires the optional 'mcp' package.

    Supports both the modern (mcp >= 2.x, MCPServer) and legacy (mcp 1.x, Server) SDK
    APIs so it keeps working across SDK versions.
    """
    import sys

    try:
        import mcp  # noqa: F401
    except ImportError:
        sys.stderr.write(
            "The MCP server needs the 'mcp' package. Install it with:\n"
            "    pip install \"sanctify-hivemind[mcp]\"   (or)   pip install mcp\n"
        )
        return 1

    # Prefer the modern high-level API; fall back to the legacy low-level one.
    try:
        server = _build_modern_server()
    except Exception:  # noqa: BLE001 — SDK too old / API absent → legacy path
        server = None

    if server is not None:
        server.run("stdio")
        return 0

    _run_legacy_server()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
