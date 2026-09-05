"""Assembly — wire the core, WordPress adapter, agents, planner, and critic into a
ready-to-run Orchestrator. This is the one place environment + agents are composed."""

from __future__ import annotations

from typing import Optional

from .agents import ReconAgent, SecurityAgent
from .core.critic import Critic
from .core.memory import EnvironmentMemory
from .core.orchestrator import Orchestrator
from .core.safety import AuditTrace
from .core.tools import Access, Tool, ToolRegistry
from .environments.wordpress import WordPressAdapter, WPConfig
from .planners import rule_based_planner


def auto_approver(tool: Tool, kwargs: dict) -> bool:
    """Demo approver: allow WRITE, deny DESTRUCTIVE. Real deployments swap this for a
    human prompt, a policy engine, or a Telegram approval message."""
    return tool.access < Access.DESTRUCTIVE


def build_wordpress_orchestrator(
    config: Optional[WPConfig] = None,
    offline: bool = False,
    remediate: bool = False,
    trace_path: Optional[str] = None,
    memory_path: Optional[str] = None,
) -> Orchestrator:
    cfg = config or WPConfig.from_env()

    registry = ToolRegistry()
    adapter = WordPressAdapter(cfg, offline=offline)
    adapter.register(registry)

    agents = {
        "recon": ReconAgent(),
        "security": SecurityAgent(remediate=remediate),
    }

    env_id = cfg.url
    memory = EnvironmentMemory(env_id, path=memory_path)
    trace = AuditTrace(path=trace_path)

    return Orchestrator(
        registry=registry,
        agents=agents,
        planner=rule_based_planner,
        env_memory=memory,
        critic=Critic(max_retries=1),
        trace=trace,
        approver=auto_approver,
    )
