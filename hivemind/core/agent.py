"""Base agent contract + shared task types.

An ``Agent`` is a specialist worker. It declares:
  - a ``name`` and the ``capabilities`` (CapabilityGrant) it needs, and
  - a ``run(task, ctx)`` method that does bounded work and returns a ``TaskResult``.

Agents receive an ``AgentContext`` giving them scoped access to: their ToolContext
(the only way to touch the environment), the shared Blackboard, the EnvironmentMemory
(world-model), and the AuditTrace. Agents never see raw credentials or unscoped tools.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from .memory import Blackboard, EnvironmentMemory
from .safety import AuditTrace
from .tools import CapabilityGrant, ToolContext


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    SKIPPED = "skipped"
    NEEDS_VERIFY = "needs_verify"


@dataclass
class Task:
    """A unit of work in the orchestration DAG."""

    id: str
    goal: str                       # human-readable objective for this task
    agent: str                      # name of the agent that should run it
    deps: list[str] = field(default_factory=list)   # task ids this depends on
    params: dict = field(default_factory=dict)
    status: TaskStatus = TaskStatus.PENDING


@dataclass
class TaskResult:
    """What an agent returns. ``findings`` feed the blackboard + final report;
    ``verify`` is an optional post-condition the critic will check."""

    ok: bool
    summary: str
    findings: dict = field(default_factory=dict)
    changed: bool = False           # did this task mutate the environment?
    verify: Optional[str] = None    # a claim the critic should independently confirm
    error: Optional[str] = None


@dataclass
class AgentContext:
    """Everything an agent is allowed to touch, and nothing more."""

    tools: ToolContext
    blackboard: Blackboard
    memory: EnvironmentMemory
    trace: AuditTrace


class Agent:
    """Base class for specialist agents."""

    #: unique name used by the orchestrator to route tasks
    name: str = "agent"
    #: what this agent needs to do its job (least privilege)
    capabilities: CapabilityGrant = CapabilityGrant()

    def run(self, task: Task, ctx: AgentContext) -> TaskResult:  # pragma: no cover - abstract
        raise NotImplementedError

    # Convenience for subclasses.
    def _log(self, ctx: AgentContext, msg: str, **data: Any) -> None:
        ctx.trace.record("note", agent=self.name, msg=msg, **data)
