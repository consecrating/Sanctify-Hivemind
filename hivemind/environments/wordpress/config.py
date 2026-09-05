"""Credential-free WordPress configuration.

Loads connection settings from environment variables or a local, gitignored ``.env``.
No secret is ever written to the repo. Recon-only usage needs just ``WP_URL``;
authenticated REST needs ``WP_USER`` + ``WP_APP_PASSWORD``; FTP ops need ``FTP_*``.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


def _load_dotenv(explicit: Optional[str] = None) -> None:
    """Minimal .env loader (no dependency). Does not override real env vars."""
    candidates = []
    if explicit:
        candidates.append(Path(explicit))
    candidates += [Path.cwd() / ".env", Path(__file__).resolve().parents[3] / ".env"]
    for env_path in candidates:
        if not env_path.is_file():
            continue
        for raw in env_path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


@dataclass
class WPConfig:
    url: str
    user: str = ""
    app_password: str = ""
    ftp_host: str = ""
    ftp_user: str = ""
    ftp_pass: str = ""
    ftp_root: str = "/"

    @classmethod
    def from_env(cls, dotenv: Optional[str] = None) -> "WPConfig":
        _load_dotenv(dotenv)
        url = os.environ.get("WP_URL", "").rstrip("/")
        if not url:
            raise SystemExit("WP_URL is required (set env var or .env). No credentials in repo.")
        return cls(
            url=url,
            user=os.environ.get("WP_USER", ""),
            app_password=os.environ.get("WP_APP_PASSWORD", ""),
            ftp_host=os.environ.get("FTP_HOST", ""),
            ftp_user=os.environ.get("FTP_USER", ""),
            ftp_pass=os.environ.get("FTP_PASS", ""),
            ftp_root=os.environ.get("FTP_ROOT", "/"),
        )

    # ── capability probes (what can this config actually do?) ──
    @property
    def has_rest_auth(self) -> bool:
        return bool(self.user and self.app_password)

    @property
    def has_ftp(self) -> bool:
        return bool(self.ftp_host and self.ftp_user and self.ftp_pass)

    def rest_headers(self) -> dict:
        if not self.has_rest_auth:
            raise RuntimeError("REST auth needs WP_USER + WP_APP_PASSWORD")
        token = base64.b64encode(f"{self.user}:{self.app_password}".encode()).decode()
        return {"Authorization": f"Basic {token}", "Content-Type": "application/json"}
