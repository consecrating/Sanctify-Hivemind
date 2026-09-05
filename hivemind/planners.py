"""Planners — turn a free-text goal into a task DAG.

Rule-based planner for the vertical slice; it recognises intents ("audit", "harden",
"secure", "scan") and emits the right tasks with dependencies. An LLM / SuperBrain
planner implements the same ``(goal, env_facts) -> list[Task]`` contract and can be
dropped in without touching the orchestrator.
"""

from __future__ import annotations

from .core.agent import Task


def rule_based_planner(goal: str, env_facts: dict) -> list[Task]:
    g = goal.lower()
    tasks: list[Task] = []

    # Recon is the foundation for almost everything and depends on nothing.
    want_recon = any(k in g for k in ("audit", "recon", "scan", "secure", "harden",
                                      "check", "assess", "analyze", "analyse"))
    if want_recon or True:  # always recon first — cheap, credential-free, high value
        tasks.append(Task(id="recon", goal="Fingerprint the site (stack, plugins, exposure)",
                          agent="recon"))

    # Security assessment depends on recon's stack.
    if any(k in g for k in ("secure", "security", "malware", "harden", "audit", "scan", "vuln", "cve")):
        tasks.append(Task(id="security",
                          goal="Detect malware IOCs and vulnerable components; propose patches",
                          agent="security", deps=["recon"]))

    return tasks
