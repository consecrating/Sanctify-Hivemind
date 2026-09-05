"""Critic / verifier — the actor-critic loop on real infrastructure.

After an agent (the *actor*) completes a task, an independent *critic* checks the
outcome against the task's stated goal / verify-claim. The critic can:

  - ACCEPT  — the outcome satisfies the goal,
  - RETRY   — transient/incomplete; run the task again (bounded), or
  - REJECT  — the outcome does not satisfy the goal (and the change, if any, should
              already have been rolled back by the Safety engine).

The critic is deliberately *separate* from the actor: an agent asserting "done" is
not evidence. Verification uses independent checks (re-fetch state, re-scan, compare
against expected post-conditions). A ``Verifier`` callable performs the actual check;
by default we use a structured heuristic verifier, but this is where a second LLM /
SuperBrain judgment plugs in.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional

from .agent import AgentContext, Task, TaskResult


class Verdict(str, Enum):
    ACCEPT = "accept"
    RETRY = "retry"
    REJECT = "reject"


@dataclass
class Judgement:
    verdict: Verdict
    reason: str
    confidence: float = 1.0


# A verifier independently checks a completed task. It gets the task, the actor's
# result, and the agent context (so it can re-observe the environment via READ tools).
Verifier = Callable[[Task, TaskResult, AgentContext], Judgement]


def default_verifier(task: Task, result: TaskResult, ctx: AgentContext) -> Judgement:
    """Heuristic critic used when no domain/LLM verifier is supplied.

    Rules (conservative — favour catching failures over false confidence):
      1. If the actor failed outright → REJECT.
      2. If the task published a ``verify`` claim and a matching verifier hook exists
         on the blackboard (key ``verify:<task.id>``), run it.
      3. Otherwise ACCEPT a well-formed success, but flag low confidence when the
         actor claims a change with no independent post-condition.
    """
    if not result.ok:
        return Judgement(Verdict.REJECT, f"actor reported failure: {result.error}", 1.0)

    # Independent post-condition hook (a callable the agent left for verification).
    hook = ctx.blackboard.get(f"verify:{task.id}")
    if callable(hook):
        try:
            passed = bool(hook())
        except Exception as exc:  # noqa: BLE001
            return Judgement(Verdict.RETRY, f"verification hook errored: {exc}", 0.5)
        if passed:
            return Judgement(Verdict.ACCEPT, "independent post-condition passed", 1.0)
        return Judgement(Verdict.REJECT, "independent post-condition failed", 1.0)

    if result.changed and not result.verify:
        return Judgement(
            Verdict.ACCEPT,
            "accepted, but change had no independent post-condition (low confidence)",
            0.6,
        )
    return Judgement(Verdict.ACCEPT, "outcome consistent with goal", 0.9)


class Critic:
    """Runs verification and enforces a bounded retry budget per task."""

    def __init__(self, verifier: Optional[Verifier] = None, max_retries: int = 1) -> None:
        self.verifier = verifier or default_verifier
        self.max_retries = max_retries

    def judge(self, task: Task, result: TaskResult, ctx: AgentContext) -> Judgement:
        j = self.verifier(task, result, ctx)
        ctx.trace.record(
            "verify", task=task.id, verdict=j.verdict.value,
            reason=j.reason, confidence=j.confidence,
        )
        return j
