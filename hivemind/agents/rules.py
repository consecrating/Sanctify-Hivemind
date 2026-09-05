"""Security rules library — malware IOCs + CVE signatures.

Versioned, expandable knowledge distilled from real incident response. Two kinds:

- ``MALWARE_IOCS``: indicators of the self-healing "Smooth Backup Ink" (SCV) family —
  filenames, content markers, cron hook shapes, rogue-admin patterns. Used to decide
  whether a site is infected.

- ``CVE_RULES``: plugin/theme vulnerabilities keyed by slug, with the affected version
  range and the virtual-patch hint. Used to flag exploitable, unpatched components.

This is the artifact that makes the swarm smarter over time: new incidents → new rules.
"""

from __future__ import annotations

from dataclasses import dataclass, field

RULES_VERSION = "2026.09.1"

# ── Malware family indicators (Smooth Backup Ink / SCV) ──────────────────
MALWARE_IOCS = {
    "files": [
        "64f6b5eb.php", ".64f6b5eb.php", "ed0c7e2b.php", "865fa429.zip",
        "bce0f3b9.php", "mu-plugins/smooth-backup-ink.php",
    ],
    "dir_globs": [".sc_*", "plugins/smooth-backup-ink"],
    "content_markers": ["SCV:4.3.24", "SC_DB_BEGIN", "Smooth Backup Ink"],
    "prepend_markers": ["auto_prepend_file"],   # in .user.ini / .htaccess pointing at hex payloads
    "cron_hooks": ["sc_cron_fetch", "my_monitoring_cron"],  # + rogue 16+ char hex hooks
    "rogue_admin_pattern": r"^backup_[0-9a-f]{6,}",
    "db_dropin_marker": "SC_DB",                # a db.php dropin carrying this = malicious
}


@dataclass(frozen=True)
class CVERule:
    slug: str                 # plugin/theme slug
    cve: str
    affected_max: str         # vulnerable if installed_version <= this
    severity: str             # critical | high | medium
    summary: str
    virtual_patch: str = ""   # how Falcon-style WAF neutralises it
    fixed_in: str = ""


# ── Known-vulnerable components (expand as new CVEs land) ────────────────
CVE_RULES: list[CVERule] = [
    CVERule(
        slug="trx_addons", cve="CVE-2024-13448", affected_max="2.32.0", severity="critical",
        summary="ThemeREX Addons unauthenticated arbitrary file upload via AI-helper AJAX "
                "actions reaching trx_addons_uploads_save_data.",
        virtual_patch="Block unauthenticated admin-ajax actions: trx_addons_ai_helper_* and "
                      "trx_addons_uploads_save_data/save_file (return 403).",
        fixed_in="2.45.0",
    ),
    CVERule(
        slug="trx_addons", cve="CVE-2026-1969", affected_max="2.34.0", severity="critical",
        summary="ThemeREX Addons incomplete fix of the file-upload flaw (still unauth).",
        virtual_patch="Same as CVE-2024-13448 unauthenticated AJAX block.",
        fixed_in="2.45.0",
    ),
    CVERule(
        slug="revslider", cve="CVE-2026-9050", affected_max="6.7.55", severity="high",
        summary="Slider Revolution missing authorization: contributor+ can deactivate any "
                "plugin; related info-disclosure CVEs affect <= 6.7.55.",
        virtual_patch="Block unauthenticated revslider* admin-ajax actions (return 403).",
        fixed_in="6.7.58",
    ),
]


@dataclass
class Finding:
    kind: str          # "malware" | "cve" | "exposure"
    severity: str
    ref: str           # IOC name / CVE id
    detail: str
    remediation: str = ""


def _ver_tuple(v: str) -> tuple:
    parts = []
    for p in str(v).split("."):
        num = "".join(ch for ch in p if ch.isdigit())
        parts.append(int(num) if num else 0)
    return tuple(parts)


def version_leq(installed: str, ceiling: str) -> bool:
    """True if installed <= ceiling (i.e. still in the vulnerable range)."""
    return _ver_tuple(installed) <= _ver_tuple(ceiling)


def match_cves(installed: dict[str, str]) -> list[Finding]:
    """Given {slug: version}, return findings for any vulnerable components."""
    out: list[Finding] = []
    for rule in CVE_RULES:
        if rule.slug in installed and version_leq(installed[rule.slug], rule.affected_max):
            out.append(Finding(
                kind="cve", severity=rule.severity, ref=rule.cve,
                detail=f"{rule.slug} {installed[rule.slug]} ≤ {rule.affected_max}: {rule.summary}",
                remediation=f"Update to {rule.fixed_in}. Virtual patch: {rule.virtual_patch}",
            ))
    return out
