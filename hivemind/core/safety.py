"""Safety engine: audit trace + transactional changes with rollback.

Two responsibilities:

1. ``AuditTrace`` — an append-only, replayable log of every decision and tool call.
   This is what makes an agent run debuggable and trustworthy: you can reconstruct
   exactly what happened and why.

2. ``SafeChange`` — the "every write is a transaction" primitive:
       snapshot → act → health-check → commit  (or)  rollback
   A change is only kept if a post-condition health check passes. Otherwise the
   engine restores the snapshot. This is the discipline that lets agents write to
   production without a bad step causing an outage.

Both are environment-agnostic. An environment adapter supplies the concrete
``snapshot`` / ``restore`` callables (e.g. download a file before editing it).
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from .tools import ToolCall


# ─────────────────────────────────────────────────────────── Audit trace ──

@dataclass
class TraceEvent:
    kind: str            # "goal" | "plan" | "task_start" | "tool_call" | "verify" |
                         # "rollback" | "task_done" | "note" | "error"
    ts: float
    data: dict


class AuditTrace:
    """Append-only event log. Optionally mirrored to a JSONL file for replay."""

    def __init__(self, run_id: Optional[str] = None, path: Optional[str] = None) -> None:
        self.run_id = run_id or uuid.uuid4().hex[:12]
        self.events: list[TraceEvent] = []
        self._fh = None
        if path:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            self._fh = open(path, "a", encoding="utf-8")

    def record(self, kind: str, **data: Any) -> None:
        ev = TraceEvent(kind=kind, ts=time.time(), data=data)
        self.events.append(ev)
        if self._fh:
            self._fh.write(json.dumps({"run": self.run_id, **asdict(ev)}, default=str) + "\n")
            self._fh.flush()

    def record_tool_call(self, call: ToolCall) -> None:
        self.record(
            "tool_call",
            tool=call.tool, access=call.access.name, scope=call.scope,
            ok=call.ok, approved=call.approved, error=call.error,
        )

    def summary(self) -> dict:
        counts: dict[str, int] = {}
        for e in self.events:
            counts[e.kind] = counts.get(e.kind, 0) + 1
        tool_calls = [e for e in self.events if e.kind == "tool_call"]
        return {
            "run_id": self.run_id,
            "events": len(self.events),
            "by_kind": counts,
            "tool_calls": len(tool_calls),
            "tool_failures": sum(1 for e in tool_calls if not e.data.get("ok")),
            "rollbacks": counts.get("rollback", 0),
        }

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None


# ────────────────────────────────────────────────── Transactional change ──

@dataclass
class ChangeResult:
    ok: bool
    committed: bool
    rolled_back: bool
    detail: str = ""
    health_before: Optional[bool] = None
    health_after: Optional[bool] = None
    error: Optional[str] = None


@dataclass
class SafeChange:
    """Wrap a mutating action so it is snapshot-guarded and auto-reverts on failure.

    Callables (all optional except ``act``):
      - ``snapshot()``   -> token   : capture current state before the change
      - ``act()``        -> Any      : perform the change
      - ``health()``     -> bool     : post-condition; True = healthy
      - ``restore(token)``           : revert to the snapshot
    """

    name: str
    act: Callable[[], Any]
    snapshot: Optional[Callable[[], Any]] = None
    restore: Optional[Callable[[Any], None]] = None
    health: Optional[Callable[[], bool]] = None
    trace: Optional[AuditTrace] = None
    _log: list[str] = field(default_factory=list)

    def _note(self, msg: str) -> None:
        self._log.append(msg)
        if self.trace:
            self.trace.record("note", change=self.name, msg=msg)

    def run(self) -> ChangeResult:
        # Pre-change health (informational baseline).
        health_before = None
        if self.health:
            try:
                health_before = bool(self.health())
            except Exception as exc:  # noqa: BLE001
                self._note(f"pre-health check errored: {exc}")

        # Snapshot.
        token = None
        if self.snapshot:
            try:
                token = self.snapshot()
                self._note("snapshot captured")
            except Exception as exc:  # noqa: BLE001
                return ChangeResult(False, False, False,
                                    detail="snapshot failed — refusing to act",
                                    error=str(exc))

        # Act.
        try:
            self.act()
            self._note("action applied")
        except Exception as exc:  # noqa: BLE001
            rolled = self._rollback(token, reason=f"action raised: {exc}")
            return ChangeResult(False, False, rolled, detail="action failed",
                                health_before=health_before, error=str(exc))

        # Verify health after.
        health_after = None
        if self.health:
            try:
                health_after = bool(self.health())
            except Exception as exc:  # noqa: BLE001
                health_after = False
                self._note(f"post-health check errored: {exc}")
            if not health_after:
                rolled = self._rollback(token, reason="post-change health check failed")
                return ChangeResult(False, False, rolled,
                                    detail="unhealthy after change",
                                    health_before=health_before, health_after=False)

        self._note("committed")
        if self.trace:
            self.trace.record("task_done", change=self.name, committed=True)
        return ChangeResult(True, True, False, detail="committed",
                            health_before=health_before, health_after=health_after)

    def _rollback(self, token: Any, reason: str) -> bool:
        self._note(f"rolling back: {reason}")
        if self.trace:
            self.trace.record("rollback", change=self.name, reason=reason)
        if self.restore is None or token is None:
            self._note("no restore available — manual intervention may be required")
            return False
        try:
            self.restore(token)
            self._note("rollback complete")
            return True
        except Exception as exc:  # noqa: BLE001
            self._note(f"ROLLBACK FAILED: {exc}")
            if self.trace:
                self.trace.record("error", change=self.name, msg=f"rollback failed: {exc}")
            return False
