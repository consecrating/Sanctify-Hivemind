"""Orchestrator — goal → task DAG → scheduled execution with the actor-critic loop.

The orchestrator is the top of the hierarchy. It:

  1. Turns a goal into a **task DAG** via a planner (rule-based here; an LLM/SuperBrain
     planner plugs into the same ``Planner`` contract).
  2. Schedules tasks respecting dependencies, running **independent tasks in parallel**
     and dependent ones in order.
  3. For each task: dispatches to the named specialist **agent** (actor), then runs the
     **critic** (verifier). On REJECT the task fails (its change was already rolled back
     by the Safety engine); on RETRY it re-runs within a bounded budget.
  4. Publishes each agent's findings to the shared **blackboard** so downstream agents
     start warm, and records everything to the **audit trace**.

It knows nothing about WordPress — only about tasks, agents, and verification.
"""

from __future__ import annotations

import concurrent.futures as cf
from dataclasses import dataclass, field
from typing import Callable, Optional

from .agent import Agent, AgentContext, Task, TaskResult, TaskStatus
from .critic import Critic, Verdict
from .memory import Blackboard, EnvironmentMemory
from .safety import AuditTrace
from .tools import CapabilityGrant, ToolContext, ToolRegistry


# A planner turns a free-text goal + environment facts into a list of Tasks (a DAG
# expressed via each task's ``deps``). Rule-based by default; swap for an LLM planner.
Planner = Callable[[str, dict], list[Task]]


@dataclass
class RunReport:
    goal: str
    ok: bool
    tasks: list[Task]
    results: dict[str, TaskResult]
    blackboard: dict
    trace_summary: dict
    findings: dict = field(default_factory=dict)


class Orchestrator:
    def __init__(
        self,
        registry: ToolRegistry,
        agents: dict[str, Agent],
        planner: Planner,
        env_memory: EnvironmentMemory,
        critic: Optional[Critic] = None,
        trace: Optional[AuditTrace] = None,
        approver=None,
        max_parallel: int = 4,
    ) -> None:
        self.registry = registry
        self.agents = agents
        self.planner = planner
        self.env_memory = env_memory
        self.critic = critic or Critic()
        self.trace = trace or AuditTrace()
        self.approver = approver
        self.max_parallel = max_parallel
        self.blackboard = Blackboard()

    # ── public API ────────────────────────────────────────────────────────
    def run(self, goal: str) -> RunReport:
        self.trace.record("goal", goal=goal, env=self.env_memory.env_id)

        tasks = self.planner(goal, self.env_memory.all())
        self.trace.record("plan", tasks=[{"id": t.id, "agent": t.agent, "deps": t.deps} for t in tasks])
        by_id = {t.id: t for t in tasks}
        results: dict[str, TaskResult] = {}

        # Schedule in dependency waves; run each wave's independent tasks in parallel.
        remaining = set(by_id)
        while remaining:
            ready = [
                by_id[tid] for tid in remaining
                if all(d in results and results[d].ok for d in by_id[tid].deps)
            ]
            if not ready:
                # Anything left is blocked by a failed/absent dependency → skip it.
                for tid in list(remaining):
                    by_id[tid].status = TaskStatus.SKIPPED
                    self.trace.record("task_done", task=tid, status="skipped",
                                      reason="dependency unmet")
                    remaining.discard(tid)
                break

            with cf.ThreadPoolExecutor(max_workers=self.max_parallel) as pool:
                futures = {pool.submit(self._run_task, t): t for t in ready}
                for fut in cf.as_completed(futures):
                    t = futures[fut]
                    results[t.id] = fut.result()
                    remaining.discard(t.id)

        findings = self._collect_findings(results)
        ok = all(r.ok for r in results.values()) and bool(results)
        report = RunReport(
            goal=goal, ok=ok, tasks=list(by_id.values()), results=results,
            blackboard=self.blackboard.snapshot(), trace_summary=self.trace.summary(),
            findings=findings,
        )
        self.trace.record("task_done", task="__run__", ok=ok, findings_keys=list(findings))
        return report

    # ── task execution (actor → critic, bounded retries) ──────────────────
    def _run_task(self, task: Task) -> TaskResult:
        agent = self.agents.get(task.agent)
        if agent is None:
            task.status = TaskStatus.FAILED
            return TaskResult(ok=False, summary=f"no agent named '{task.agent}'",
                              error="unknown agent")

        ctx = self._context_for(agent)
        attempts = 0
        budget = 1 + self.critic.max_retries
        last: Optional[TaskResult] = None

        while attempts < budget:
            attempts += 1
            task.status = TaskStatus.RUNNING
            self.trace.record("task_start", task=task.id, agent=agent.name, attempt=attempts)
            try:
                result = agent.run(task, ctx)
            except Exception as exc:  # noqa: BLE001 — isolate agent failures
                result = TaskResult(ok=False, summary="agent raised", error=f"{type(exc).__name__}: {exc}")
            last = result

            judgement = self.critic.judge(task, result, ctx)
            if judgement.verdict is Verdict.ACCEPT:
                task.status = TaskStatus.DONE if result.ok else TaskStatus.FAILED
                self._publish(agent, result)
                return result
            if judgement.verdict is Verdict.RETRY and attempts < budget:
                self.trace.record("note", task=task.id, msg=f"retry ({judgement.reason})")
                continue
            # REJECT (or retry budget exhausted)
            task.status = TaskStatus.FAILED
            rejected = TaskResult(
                ok=False,
                summary=f"rejected by critic: {judgement.reason}",
                findings=result.findings, error=judgement.reason,
            )
            self._publish(agent, rejected)
            return rejected

        return last or TaskResult(ok=False, summary="no result", error="unreachable")

    # ── helpers ───────────────────────────────────────────────────────────
    def _context_for(self, agent: Agent) -> AgentContext:
        grant: CapabilityGrant = agent.capabilities
        tool_ctx = ToolContext(
            registry=self.registry,
            grant=grant,
            recorder=self.trace.record_tool_call,
            approver=self.approver,
        )
        return AgentContext(
            tools=tool_ctx, blackboard=self.blackboard,
            memory=self.env_memory, trace=self.trace,
        )

    def _publish(self, agent: Agent, result: TaskResult) -> None:
        if result.findings:
            self.blackboard.merge(f"findings:{agent.name}", result.findings)

    def _collect_findings(self, results: dict[str, TaskResult]) -> dict:
        merged: dict = {}
        for r in results.values():
            for k, v in r.findings.items():
                merged[k] = v
        return merged
