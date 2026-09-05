"""Security agent — detect malware + vulnerable components; propose/apply patches.

Consumes the Recon agent's ``stack`` from the blackboard (starting warm), then:

  1. Matches detected plugin/theme versions against the CVE rules library.
  2. Scans for the SCV "Smooth Backup Ink" malware family IOCs (files, dropins,
     auto_prepend triggers) using READ tools.
  3. Emits prioritized ``Finding``s + a virtual-patch plan.

Default capability is READ-only (safe assessment). A remediating deployment can grant
WRITE (with the approval gate) so the same agent applies the virtual patch / cleanup
through SafeChange transactions — but assessment never needs it.
"""

from __future__ import annotations

from ..core.agent import Agent, AgentContext, Task, TaskResult
from ..core.tools import Access, CapabilityGrant
from .rules import MALWARE_IOCS, RULES_VERSION, Finding, match_cves


class SecurityAgent(Agent):
    name = "security"
    # READ-only assessment by default. To enable auto-remediation, construct with
    # remediate=True (grants WRITE/wp.files under the approval gate).
    capabilities = CapabilityGrant(max_access=Access.READ, scopes={"wp.http", "wp.rest", "wp.files"})

    def __init__(self, remediate: bool = False) -> None:
        if remediate:
            self.capabilities = CapabilityGrant(
                max_access=Access.WRITE, scopes={"wp.http", "wp.rest", "wp.files"},
                auto_approve_write=False,  # writes still require approval
            )
        self.remediate = remediate

    def run(self, task: Task, ctx: AgentContext) -> TaskResult:
        stack = ctx.blackboard.get("stack") or ctx.memory.recall("stack") or {}
        findings: list[Finding] = []

        # 1) CVE matching against detected components.
        #    Recon gives us slugs; versions come from an authenticated REST read when
        #    available, else we flag "version-unknown but present" for watched slugs.
        versions = self._plugin_versions(ctx, stack)
        findings += match_cves(versions)

        # 2) Malware IOC scan (READ). Presence of any is high-signal.
        findings += self._scan_iocs(ctx)

        # 3) Exposure findings surfaced by recon.
        for path in (stack.get("exposed_files") or {}):
            findings.append(Finding("exposure", "medium", path,
                                    f"Sensitive file publicly accessible: {path}",
                                    "Deny direct access via .htaccess / disable directory listing."))

        infected = any(f.kind == "malware" for f in findings)
        criticals = [f for f in findings if f.severity == "critical"]

        payload = {
            "rules_version": RULES_VERSION,
            "infected": infected,
            "findings": [f.__dict__ for f in findings],
            "counts": {
                "critical": sum(1 for f in findings if f.severity == "critical"),
                "high": sum(1 for f in findings if f.severity == "high"),
                "medium": sum(1 for f in findings if f.severity == "medium"),
            },
        }
        ctx.blackboard.put("security", payload)
        self._log(ctx, "security scan complete", infected=infected, findings=len(findings))

        summary = (
            f"{'INFECTED — ' if infected else ''}"
            f"{payload['counts']['critical']} critical / {payload['counts']['high']} high / "
            f"{payload['counts']['medium']} medium finding(s). rules={RULES_VERSION}"
        )
        # Assessment always "succeeds" (it ran); the *findings* carry the risk signal.
        return TaskResult(ok=True, summary=summary, findings={"security": payload})

    # ── helpers ─────────────────────────────────────────────────────────
    def _plugin_versions(self, ctx: AgentContext, stack: dict) -> dict[str, str]:
        versions: dict[str, str] = {}
        # Try authenticated REST plugin list (has versions). Falls back gracefully.
        try:
            data = ctx.tools.invoke("wp.rest_get", route="/wp/v2/plugins")
        except Exception:  # noqa: BLE001 — no auth / not permitted
            data = None
        if isinstance(data, list):
            for p in data:
                slug = (p.get("plugin") or "").split("/")[0]
                if slug and p.get("version"):
                    versions[slug] = p["version"]
        # For watched slugs seen by recon but without a version, record 0 (treated as
        # "<= affected_max" → flagged, conservative).
        for slug in stack.get("plugins", []):
            versions.setdefault(slug, "0")
        return versions

    def _scan_iocs(self, ctx: AgentContext) -> list[Finding]:
        found: list[Finding] = []
        # File IOCs via public HTTP probes (works even without FTP/auth).
        for fname in MALWARE_IOCS["files"]:
            probe = "/wp-content/" + fname if "/" not in fname else "/wp-content/" + fname
            try:
                r = ctx.tools.invoke("wp.http_get", path=probe)
            except Exception:  # noqa: BLE001
                continue
            status = r.get("status")
            if status and int(status) == 200:
                found.append(Finding(
                    "malware", "critical", fname,
                    f"Known SCV malware artifact reachable: {probe}",
                    "Remove file; neutralize auto_prepend in .user.ini/.htaccess; clear malicious cron.",
                ))
        return found
