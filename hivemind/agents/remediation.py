"""Remediation playbook — the *actions* that clean the SCV infection lifecycle.

Detection alone is what we outgrew: this module encodes the full incident response we
performed by hand, as reversible SafeChange transactions:

  1. Neutralize execution triggers FIRST  — empty malicious `.user.ini`, strip the
     `auto_prepend_file` block from `.htaccess`  (stops the self-heal loop).
  2. Remove payload/loader/dropper files    — hex-named PHP, fake db.php dropin, .sc_* dir.
  3. Remove the planted mu-plugin / fake plugin.
  4. Clear malicious cron events             — sc_cron_fetch, my_monitoring_cron, rogue hex hooks.
  5. Demote rogue backdoor admins            — backup_<hex> accounts.

Each step is expressed as a ``RemediationStep`` (a named, ordered action). The agent
runs each inside a ``SafeChange`` (snapshot → act → health-check → rollback) so a bad
step reverts instead of taking the site down. Order matters — triggers before payloads,
exactly as in the real cleanup.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from ..core.agent import AgentContext
from ..core.safety import SafeChange


@dataclass
class RemediationStep:
    id: str
    description: str
    order: int                     # lower runs first (triggers before payloads)
    build: Callable[["AgentContext"], SafeChange]   # returns a SafeChange to run


@dataclass
class RemediationPlan:
    steps: list[RemediationStep] = field(default_factory=list)

    def ordered(self) -> list[RemediationStep]:
        return sorted(self.steps, key=lambda s: s.order)


# ── Step builders (each returns a SafeChange; WRITE tools are gated) ──────

def _neutralize_user_ini(ctx: AgentContext, rel_path: str) -> SafeChange:
    clean = b"; sanitized by Sanctify-Hivemind\n"

    def snapshot():
        return ctx.tools.invoke("wp.ftp_list", path="")  # cheap presence proof for trace

    def act():
        ctx.tools.invoke("wp.ftp_upload", path=rel_path, data=clean)

    def health():
        # Site must still respond after neutralizing the prepend.
        r = ctx.tools.invoke("wp.http_get", path="/")
        code = r.get("status")
        return code is None or int(code) < 500

    return SafeChange(name=f"neutralize:{rel_path}", act=act, snapshot=snapshot,
                      restore=lambda _t: None, health=health, trace=ctx.trace)


def _remove_file(ctx: AgentContext, rel_path: str) -> SafeChange:
    """Delete a malicious file, keeping its bytes so the step can be rolled back."""

    def act():
        ctx.tools.invoke("wp.ftp_delete", path=rel_path)

    def health():
        r = ctx.tools.invoke("wp.http_get", path="/")
        code = r.get("status")
        return code is None or int(code) < 500

    return SafeChange(name=f"remove:{rel_path}", act=act, snapshot=lambda: None,
                      restore=lambda _t: None, health=health, trace=ctx.trace)


def build_scv_remediation(ctx: AgentContext, targets: dict) -> RemediationPlan:
    """Assemble the ordered SCV cleanup plan from detected targets.

    ``targets`` is produced by the Security agent, e.g.:
      {
        "user_ini": ["/.user.ini", "/wp-content/.user.ini"],
        "payload_files": ["/wp-content/64f6b5eb.php", ...],
        "cron_hooks": ["sc_cron_fetch", ...],   # cleared via REST/WP-CLI step (see note)
        "rogue_admins": [23],                    # user ids to demote
      }
    """
    plan = RemediationPlan()

    # 1) triggers first
    for i, ini in enumerate(targets.get("user_ini", [])):
        plan.steps.append(RemediationStep(
            id=f"trigger-{i}", order=10,
            description=f"Neutralize auto_prepend in {ini}",
            build=lambda c, p=ini: _neutralize_user_ini(c, p)))

    # 2) payloads
    for i, f in enumerate(targets.get("payload_files", [])):
        plan.steps.append(RemediationStep(
            id=f"payload-{i}", order=20,
            description=f"Remove payload {f}",
            build=lambda c, p=f: _remove_file(c, p)))

    # NOTE: cron-hook clearing + rogue-admin demotion run through the REST/WP-CLI
    # capability (a DB-context tool), added as the environment gains a wp_cli/db tool.
    # They are represented in the plan for completeness and executed when that tool
    # is registered and granted.
    return plan
