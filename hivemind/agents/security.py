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

import re

from ..core.agent import Agent, AgentContext, Task, TaskResult
from ..core.tools import Access, CapabilityGrant
from .rules import (
    MALWARE_IOCS, RULES_VERSION, SEO_SPAM_IOCS, Finding, match_cves, scan_seo_spam,
)


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

        # 2b) SEO-spam / Japanese-keyword-hack + cloaking scan (READ).
        findings += self._scan_seo_spam(ctx)

        # 3) Exposure findings surfaced by recon.
        for path in (stack.get("exposed_files") or {}):
            findings.append(Finding("exposure", "medium", path,
                                    f"Sensitive file publicly accessible: {path}",
                                    "Deny direct access via .htaccess / disable directory listing."))

        infected = any(f.kind in ("malware", "seo_spam") for f in findings)
        spammed = any(f.kind == "seo_spam" for f in findings)

        payload = {
            "rules_version": RULES_VERSION,
            "infected": infected,
            "seo_spam": spammed,
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

    def _scan_seo_spam(self, ctx: AgentContext) -> list[Finding]:
        """Detect the Japanese-keyword-hack / cloaked SEO-spam class.

        Fetches the homepage BOTH as a normal browser and as Googlebot, then diffs +
        scans for foreign-script/spam content. Also scans the sitemap for spam URLs.
        This catches the hack that is invisible in a browser but indexed by Google.
        """
        try:
            normal = ctx.tools.invoke("wp.http_get", path="/")
        except Exception:  # noqa: BLE001
            return []
        normal_html = normal.get("text", "") or ""

        bot_html = None
        try:
            bot = ctx.tools.invoke(
                "wp.http_get", path="/", user_agent=SEO_SPAM_IOCS["googlebot_user_agent"]
            )
            bot_html = bot.get("text", "") or ""
        except TypeError:
            # adapter without user_agent support — skip cloaking diff gracefully
            bot_html = None
        except Exception:  # noqa: BLE001
            bot_html = None

        # Pull sitemap URLs (best-effort) for spam-URL detection.
        sitemap_urls: list[str] = []
        for name in SEO_SPAM_IOCS["suspect_sitemap_names"]:
            try:
                r = ctx.tools.invoke("wp.http_get", path="/" + name)
            except Exception:  # noqa: BLE001
                continue
            if r.get("status") and int(r["status"]) == 200 and r.get("text"):
                sitemap_urls += re.findall(r"<loc>(.*?)</loc>", r["text"])
                break

        findings = scan_seo_spam(normal_html, bot_html=bot_html, sitemap_urls=sitemap_urls or None)

        # DEEP scan: injected spam usually lives on a deep URL, not the homepage
        # (e.g. paikane.com/…/pinko-casino). Sample sitemap URLs + probe common spam
        # paths, fetching each AS Googlebot (cloaked pages hide from normal visitors).
        deep_findings = self._scan_deep_pages(ctx, sitemap_urls)
        findings += deep_findings

        if findings:
            self._log(ctx, "SEO-spam signals detected", count=len(findings),
                      cloaking=any(f.ref == "cloaking" for f in findings),
                      deep=len(deep_findings))
        return findings

    def _scan_deep_pages(self, ctx: AgentContext, sitemap_urls: list[str]) -> list[Finding]:
        """Fetch a bounded sample of deep pages AS Googlebot and scan each for spam.

        Prioritises: (a) sitemap URLs whose slug already looks spammy, then (b) a small
        sample of other sitemap URLs, then (c) known spam probe paths. Bounded so the
        scan stays cheap.
        """
        from urllib.parse import urlparse

        out: list[Finding] = []
        seen: set[str] = set()
        gbot = SEO_SPAM_IOCS["googlebot_user_agent"]
        frags = SEO_SPAM_IOCS["spam_slug_fragments"]

        # Build a prioritized, de-duped path list (max ~12 fetches).
        def to_path(u: str) -> str:
            try:
                p = urlparse(u)
                return (p.path or "/") + (("?" + p.query) if p.query else "")
            except Exception:  # noqa: BLE001
                return u

        suspicious = [to_path(u) for u in sitemap_urls
                      if any(fr in u.lower() for fr in frags)]
        sample = [to_path(u) for u in sitemap_urls[:8]]
        candidates = suspicious + sample + list(SEO_SPAM_IOCS["spam_probe_paths"])

        for path in candidates:
            if len(seen) >= 12:
                break
            if not path or path in seen:
                continue
            seen.add(path)
            try:
                r = ctx.tools.invoke("wp.http_get", path=path, user_agent=gbot)
            except TypeError:
                r = ctx.tools.invoke("wp.http_get", path=path)
            except Exception:  # noqa: BLE001
                continue
            if not (r.get("status") and int(r["status"]) == 200):
                continue
            page_findings = scan_seo_spam(r.get("text", "") or "")
            for f in page_findings:
                # Re-tag with the offending path so remediation knows where to look.
                out.append(Finding(
                    f.kind, f.severity, f"{f.ref}@{path}",
                    f"[{path}] {f.detail}", f.remediation,
                ))
        return out
