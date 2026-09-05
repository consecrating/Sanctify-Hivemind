"""Typed tool registry + capability / permission model.

This is the layer that lets agents act on a live system *without* being able to do
whatever they want. Every capability an agent might use is declared here as a
``Tool`` with:

  - an explicit ``access`` level (READ vs WRITE vs DESTRUCTIVE),
  - a scope tag (which environment/resource family it touches),
  - a typed handler.

Agents never call the environment directly. They call tools through a
``ToolContext`` that enforces:

  - the agent's granted capability grant (least privilege),
  - an approval gate for WRITE / DESTRUCTIVE actions,
  - audit logging of every invocation (via the injected recorder).

The result: an agent's blast radius is bounded by policy, not by hope.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, Optional


class Access(IntEnum):
    """Ordered access levels. Higher = more dangerous. Grants are a ceiling."""

    READ = 1          # observe only; cannot change state
    WRITE = 2         # mutate state, but reversible / low blast radius
    DESTRUCTIVE = 3   # delete/overwrite; requires snapshot + approval


class PermissionError_(Exception):
    """Raised when a tool call exceeds the caller's capability grant."""


class ApprovalRequired(Exception):
    """Raised when a gated action has no approval and no approver is available."""


@dataclass(frozen=True)
class Tool:
    """A single, typed capability.

    ``handler`` receives keyword args and returns any JSON-serialisable result.
    ``access`` declares how dangerous it is. ``scope`` groups tools by the resource
    family they touch (e.g. "wp.files", "wp.db", "http") so grants can be scoped.
    """

    name: str
    access: Access
    scope: str
    handler: Callable[..., Any]
    description: str = ""

    def __call__(self, **kwargs: Any) -> Any:  # direct call bypasses policy — internal use only
        return self.handler(**kwargs)


@dataclass
class CapabilityGrant:
    """What a given agent is allowed to do. Least privilege by default.

    - ``max_access``: ceiling on the danger level of any tool the agent may call.
    - ``scopes``: allowlist of scope tags (``{"*"}`` = all). Empty = nothing.
    - ``auto_approve_write``: if False, WRITE/DESTRUCTIVE calls hit the approval gate.
    """

    max_access: Access = Access.READ
    scopes: set[str] = field(default_factory=lambda: {"*"})
    auto_approve_write: bool = False

    def allows(self, tool: Tool) -> bool:
        if tool.access > self.max_access:
            return False
        if "*" in self.scopes:
            return True
        return tool.scope in self.scopes


# An approver decides whether a gated (WRITE/DESTRUCTIVE) action may proceed.
# Signature: (tool, kwargs) -> bool. Return True to allow.
Approver = Callable[[Tool, dict], bool]


class ToolRegistry:
    """Holds all declared tools for a process. Environments register their tools here."""

    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        if tool.name in self._tools:
            raise ValueError(f"tool already registered: {tool.name}")
        self._tools[tool.name] = tool

    def add(
        self,
        name: str,
        handler: Callable[..., Any],
        access: Access,
        scope: str,
        description: str = "",
    ) -> Tool:
        tool = Tool(name=name, access=access, scope=scope, handler=handler, description=description)
        self.register(tool)
        return tool

    def get(self, name: str) -> Tool:
        if name not in self._tools:
            raise KeyError(f"unknown tool: {name}")
        return self._tools[name]

    def list(self) -> list[Tool]:
        return list(self._tools.values())


@dataclass
class ToolCall:
    """Record of one invocation, for the audit trace."""

    tool: str
    access: Access
    scope: str
    kwargs: dict
    ok: bool
    result: Any = None
    error: Optional[str] = None
    approved: Optional[bool] = None
    ts: float = field(default_factory=time.time)


class ToolContext:
    """The *only* way an agent should invoke tools.

    Enforces the capability grant, runs the approval gate for dangerous actions,
    and records every call to the recorder (audit trace). This is where "policy"
    is applied — agents stay dumb about permissions; the context is the guardrail.
    """

    def __init__(
        self,
        registry: ToolRegistry,
        grant: CapabilityGrant,
        recorder: Optional[Callable[[ToolCall], None]] = None,
        approver: Optional[Approver] = None,
    ) -> None:
        self.registry = registry
        self.grant = grant
        self._recorder = recorder or (lambda call: None)
        self._approver = approver

    def invoke(self, name: str, **kwargs: Any) -> Any:
        tool = self.registry.get(name)

        # 1) Capability check — least privilege ceiling.
        if not self.grant.allows(tool):
            call = ToolCall(tool.name, tool.access, tool.scope, kwargs, ok=False,
                            error="permission denied (grant exceeded)")
            self._recorder(call)
            raise PermissionError_(
                f"'{tool.name}' needs {tool.access.name}/{tool.scope}; "
                f"grant allows {self.grant.max_access.name}/{sorted(self.grant.scopes)}"
            )

        # 2) Approval gate — WRITE/DESTRUCTIVE require explicit sign-off unless auto-approved.
        approved: Optional[bool] = None
        if tool.access >= Access.WRITE and not self.grant.auto_approve_write:
            if self._approver is None:
                call = ToolCall(tool.name, tool.access, tool.scope, kwargs, ok=False,
                                error="approval required, no approver", approved=False)
                self._recorder(call)
                raise ApprovalRequired(f"'{tool.name}' requires approval")
            approved = bool(self._approver(tool, kwargs))
            if not approved:
                call = ToolCall(tool.name, tool.access, tool.scope, kwargs, ok=False,
                                error="approval denied", approved=False)
                self._recorder(call)
                raise ApprovalRequired(f"'{tool.name}' was not approved")

        # 3) Execute + record.
        try:
            result = tool.handler(**kwargs)
            call = ToolCall(tool.name, tool.access, tool.scope, kwargs, ok=True,
                            result=_summarize(result), approved=approved)
            self._recorder(call)
            return result
        except Exception as exc:  # noqa: BLE001 — we record then re-raise
            call = ToolCall(tool.name, tool.access, tool.scope, kwargs, ok=False,
                            error=f"{type(exc).__name__}: {exc}", approved=approved)
            self._recorder(call)
            raise


def _summarize(result: Any, limit: int = 500) -> Any:
    """Keep the audit trace compact — truncate big string results."""
    if isinstance(result, str) and len(result) > limit:
        return result[:limit] + f"...<+{len(result) - limit} chars>"
    return result
