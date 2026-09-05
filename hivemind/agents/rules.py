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
from typing import Optional

RULES_VERSION = "2026.09.3"

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


# ── SEO-spam / "Japanese keyword hack" indicators ────────────────────────
# A different class from file malware: the attacker injects spam pages/content that
# often render ONLY to search-engine crawlers (cloaking), so the site looks clean in
# a browser while Google indexes counterfeit-goods / pharma / foreign-language spam.
# Symptoms: foreign-script titles in SERPs (Japanese/Chinese/Cyrillic), fake product
# spam ("正規品", "限定モデル"), a bloated/rogue sitemap with unknown URLs, and
# injected posts with non-site languages.
SEO_SPAM_IOCS = {
    # Unicode script ranges whose *unexpected* presence in <title>/<h1>/meta on an
    # English/Hindi casino site is a strong spam signal.
    "foreign_script_ranges": [
        ("Japanese", 0x3040, 0x30FF),   # Hiragana + Katakana
        ("CJK", 0x4E00, 0x9FFF),        # CJK Unified Ideographs
        ("Cyrillic", 0x0400, 0x04FF),
        ("Arabic", 0x0600, 0x06FF),
        ("Thai", 0x0E00, 0x0E7F),
    ],
    # High-signal spam phrases seen in these hacks. Grouped by campaign family so the
    # list is easy to extend. Matched case-insensitively; unicode terms matched as-is.
    "spam_phrases": [
        # Japanese counterfeit-goods ("正規品" = genuine article, "限定モデル" = limited model)
        "正規品", "限定モデル", "激安", "通販", "スーパーコピー", "みびょ",
        # Russian gambling/casino spam (the "pinco/pinup kazino" campaign family)
        "казино", "игроков", "игроки", "азартны", "азартные игры", "ставки",
        "отзывы", "игорн", "бонус", "букмекер", "слоты", "выигрыш",
        "пинко", "пин ап", "пин-ап", "вавада", "1вин", "1win",
        # Latin-script transliterations / brand spam (script check won't catch these)
        "kazino", "pinco casino", "pinup", "pin-up casino", "vavada", "mostbet",
        "casino online", "casino-online", "online kasino", "onlayn kazino",
        "bookmaker", "betting", "slots bonus", "azino",
        # Pharma / counterfeit (other common keyword-hack payloads)
        "viagra", "cialis", "replica", "rolex", "louis vuitton", "outlet",
        "cheap", "wholesale", "escort",
    ],
    # Cloaking test: content served to Googlebot differs materially from a normal UA.
    "googlebot_user_agent": (
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    ),
    # A spam sitemap is often a distinct file or a huge jump in URL count with
    # foreign-language / product-looking slugs.
    "suspect_sitemap_names": ["sitemap.xml", "sitemap_index.xml", "sitemap-1.xml"],
    # spammy slug fragments in URLs (romaji/product spam + gambling campaigns)
    "spam_slug_fragments": [
        "seihin", "gekiyasu", "copy", "replica", "outlet", "-jp-", "wanda",
        "kazino", "casino", "pinco", "pinup", "pin-up", "vavada", "mostbet",
        "1win", "azino", "stavki", "bukmeker", "sloty", "bonus", "otzyvy", "igrok",
    ],
    # Common deep paths where injected spam pages/directories are found — probed as
    # Googlebot because the pages often cloak to normal visitors.
    "spam_probe_paths": [
        "/casino/", "/kazino/", "/pinco/", "/pin-up/", "/slots/", "/bonus/",
        "/wp-content/uploads/sitemap.xml", "/sitemap-spam.xml",
    ],
}


def contains_foreign_script(text: str) -> Optional[str]:
    """Return the name of the first unexpected foreign script found in ``text``, else None."""
    if not text:
        return None
    for name, lo, hi in SEO_SPAM_IOCS["foreign_script_ranges"]:
        for ch in text:
            if lo <= ord(ch) <= hi:
                return name
    return None


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
    kind: str          # "malware" | "cve" | "exposure" | "seo_spam"
    severity: str
    ref: str           # IOC name / CVE id / spam signal
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


# ── SEO-spam / Japanese-keyword-hack analysis ────────────────────────────

def _extract_titleish(html: str) -> str:
    """Pull the text most likely to surface in a SERP: <title>, meta description, h1s."""
    import re
    chunks = []
    for pat in (r"<title[^>]*>(.*?)</title>",
                r'<meta[^>]+name=["\']description["\'][^>]+content=["\'](.*?)["\']',
                r"<h1[^>]*>(.*?)</h1>"):
        chunks += re.findall(pat, html or "", re.I | re.S)
    return " ".join(re.sub(r"<[^>]+>", "", c) for c in chunks)


def scan_seo_spam(
    normal_html: str,
    bot_html: Optional[str] = None,
    sitemap_urls: Optional[list[str]] = None,
    site_lang_ok: tuple = ("Japanese", "CJK", "Cyrillic", "Arabic", "Thai"),
) -> list[Finding]:
    """Detect the Japanese-keyword-hack / cloaked SEO-spam class.

    Signals (any one is actionable; combined = high confidence):
      1. Foreign-script text in the SERP-facing content (title/desc/h1).
      2. Known counterfeit/pharma spam phrases in the content.
      3. **Cloaking** — the Googlebot-fetched HTML differs materially from the normal
         UA HTML (spam shown only to the crawler). This is the strongest signal and
         explains why the site "looks clean" in a browser.
      4. Spam-looking slugs / foreign-language URLs in the sitemap.
    """
    findings: list[Finding] = []
    normal_html = normal_html or ""

    # 1) foreign script in SERP-facing content
    serp_text = _extract_titleish(normal_html)
    script = contains_foreign_script(serp_text)
    if script:
        findings.append(Finding(
            "seo_spam", "high", f"foreign-script:{script}",
            f"Unexpected {script} text in title/description/H1 — likely injected SEO spam.",
            "Find and remove injected posts/pages; check DB (wp_posts) and rogue templates; "
            "purge from Google via Search Console removals + re-index clean pages.",
        ))

    # 2) spam phrases (case-insensitive)
    low = normal_html.lower()
    hit_phrases = [p for p in SEO_SPAM_IOCS["spam_phrases"] if p.lower() in low or p in normal_html]
    if hit_phrases:
        findings.append(Finding(
            "seo_spam", "high", "spam-phrases",
            f"Counterfeit/pharma spam phrases present: {', '.join(hit_phrases[:6])}",
            "Locate injection source (theme header/footer, injected posts, malicious "
            "must-use plugin, or DB option) and remove; then request Google re-crawl.",
        ))

    # 3) cloaking — Googlebot sees different content than a browser
    if bot_html is not None and bot_html != normal_html:
        bot_serp = _extract_titleish(bot_html)
        bot_script = contains_foreign_script(bot_serp)
        bot_phrases = [p for p in SEO_SPAM_IOCS["spam_phrases"]
                       if p.lower() in (bot_html or "").lower() or p in (bot_html or "")]
        if bot_script or bot_phrases:
            findings.append(Finding(
                "seo_spam", "critical", "cloaking",
                "CLOAKING detected: content served to Googlebot contains spam "
                f"({bot_script or ''} {','.join(bot_phrases[:4])}) that a normal visitor does NOT see. "
                "This is why the hack is invisible in a browser.",
                "Remove the cloaking handler (checks User-Agent/IP for crawlers). Inspect "
                ".htaccess, mu-plugins, functions.php, and any code branching on Googlebot. "
                "Verify with Search Console 'URL Inspection > View crawled page'.",
            ))

    # 4) sitemap spam URLs
    if sitemap_urls:
        spammy = []
        for u in sitemap_urls:
            if contains_foreign_script(u) or any(f in u.lower() for f in SEO_SPAM_IOCS["spam_slug_fragments"]):
                spammy.append(u)
        if spammy:
            findings.append(Finding(
                "seo_spam", "high", "sitemap-spam",
                f"{len(spammy)} spam/foreign-language URL(s) in sitemap "
                f"(e.g. {spammy[0][:80]}).",
                "Remove injected posts and regenerate the sitemap; submit the clean "
                "sitemap in Search Console and request removal of the spam URLs.",
            ))

    return findings
