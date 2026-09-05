"""WordPress environment adapter — the first concrete environment for Hivemind.

Exposes WordPress capabilities (public HTTP recon, authenticated REST reads/writes,
FTP file ops) as capability-scoped tools. Credentials come from the environment /
a WPConfig loaded from env vars or a gitignored .env — never hardcoded.
"""

from .config import WPConfig
from .adapter import WordPressAdapter

__all__ = ["WPConfig", "WordPressAdapter"]
