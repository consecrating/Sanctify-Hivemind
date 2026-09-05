"""WordPress adapter: registers capability-scoped tools onto a ToolRegistry.

Tool access levels (this is the whole point of the capability model):

  READ         — public HTTP GET, REST GET, FTP list/download   (scope: wp.http / wp.rest / wp.files)
  WRITE        — REST POST (update post/meta), FTP upload         (scope: wp.rest / wp.files)
  DESTRUCTIVE  — FTP delete                                       (scope: wp.files)

A Recon agent is granted READ-only; a Security remediator would be granted WRITE with
the approval gate on. The adapter also provides ``snapshot_file`` / ``restore_file``
helpers so mutating file ops run inside a SafeChange transaction.

Network/FTP libs are imported lazily so the core is testable without them, and so a
dry-run / offline mode works for the demo.
"""

from __future__ import annotations

import io
from typing import Any, Optional

from ...core.tools import Access, ToolRegistry
from .config import WPConfig


class WordPressAdapter:
    def __init__(self, config: WPConfig, offline: bool = False) -> None:
        self.cfg = config
        self.offline = offline          # offline=True → no real network (demo/testing)
        self._session = None

    # ── lazy HTTP session ──────────────────────────────────────────────
    def _http(self):
        if self._session is not None:
            return self._session
        try:
            import requests  # noqa: PLC0415 - optional dep
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("the 'wordpress' extra needs `requests` (pip install requests)") from exc
        self._session = requests.Session()
        self._session.headers["User-Agent"] = "Sanctify-Hivemind/0.1 (+https://www.sanctify.in/)"
        return self._session

    # ── READ capabilities ──────────────────────────────────────────────
    def http_get(self, path: str = "/") -> dict:
        """Public GET (recon). No credentials used."""
        url = self.cfg.url + path if path.startswith("/") else path
        if self.offline:
            return {"url": url, "status": None, "offline": True, "text": ""}
        r = self._http().get(url, timeout=25)
        return {"url": url, "status": r.status_code,
                "headers": dict(r.headers), "text": r.text[:200000]}

    def rest_get(self, route: str, params: Optional[dict] = None) -> Any:
        """Authenticated REST GET (e.g. /wp/v2/plugins)."""
        if self.offline:
            return {"offline": True, "route": route}
        headers = self.cfg.rest_headers() if self.cfg.has_rest_auth else {}
        r = self._http().get(self.cfg.url + "/wp-json" + route, headers=headers,
                             params=params or {}, timeout=25)
        try:
            return r.json()
        except Exception:  # noqa: BLE001
            return {"status": r.status_code, "text": r.text[:2000]}

    def ftp_list(self, path: str = "") -> list[str]:
        if self.offline or not self.cfg.has_ftp:
            return []
        with self._ftp() as ftp:
            entries: list[str] = []
            ftp.retrlines("LIST " + (self.cfg.ftp_root + path), entries.append)
            return entries

    # ── WRITE capabilities (gated; use inside SafeChange) ───────────────
    def rest_post(self, route: str, json: Optional[dict] = None) -> Any:
        if self.offline:
            return {"offline": True, "route": route, "would_send": json}
        headers = self.cfg.rest_headers()
        r = self._http().post(self.cfg.url + "/wp-json" + route, headers=headers,
                              json=json or {}, timeout=30)
        return {"status": r.status_code, "body": _safe_json(r)}

    def ftp_upload(self, path: str, data: bytes) -> dict:
        if self.offline:
            return {"offline": True, "path": path, "bytes": len(data)}
        with self._ftp() as ftp:
            ftp.storbinary("STOR " + self.cfg.ftp_root + path, io.BytesIO(data))
        return {"path": path, "bytes": len(data), "ok": True}

    # ── DESTRUCTIVE capability ──────────────────────────────────────────
    def ftp_delete(self, path: str) -> dict:
        if self.offline:
            return {"offline": True, "deleted": path}
        with self._ftp() as ftp:
            ftp.delete(self.cfg.ftp_root + path)
        return {"deleted": path, "ok": True}

    # ── snapshot / restore for SafeChange transactions ─────────────────
    def snapshot_file(self, path: str) -> Optional[bytes]:
        """Download a file's current bytes so a change can be reverted."""
        if self.offline or not self.cfg.has_ftp:
            return None
        buf = io.BytesIO()
        with self._ftp() as ftp:
            ftp.retrbinary("RETR " + self.cfg.ftp_root + path, buf.write)
        return buf.getvalue()

    def restore_file(self, path: str, data: bytes) -> None:
        if self.offline or data is None:
            return
        self.ftp_upload(path, data)

    def _ftp(self):
        import ftplib  # noqa: PLC0415
        ftp = ftplib.FTP(self.cfg.ftp_host, timeout=40)
        ftp.login(self.cfg.ftp_user, self.cfg.ftp_pass)
        ftp.set_pasv(True)
        return ftp

    # ── register tools onto a registry with correct access levels ──────
    def register(self, registry: ToolRegistry) -> ToolRegistry:
        registry.add("wp.http_get", self.http_get, Access.READ, "wp.http",
                     "Public HTTP GET a path (recon; no credentials).")
        registry.add("wp.rest_get", self.rest_get, Access.READ, "wp.rest",
                     "Authenticated WP REST GET.")
        registry.add("wp.ftp_list", self.ftp_list, Access.READ, "wp.files",
                     "List a directory over FTP.")
        registry.add("wp.rest_post", self.rest_post, Access.WRITE, "wp.rest",
                     "WP REST POST (update post/meta/etc).")
        registry.add("wp.ftp_upload", self.ftp_upload, Access.WRITE, "wp.files",
                     "Upload/overwrite a file over FTP.")
        registry.add("wp.ftp_delete", self.ftp_delete, Access.DESTRUCTIVE, "wp.files",
                     "Delete a file over FTP.")
        return registry


def _safe_json(resp) -> Any:
    try:
        return resp.json()
    except Exception:  # noqa: BLE001
        return resp.text[:1000]
