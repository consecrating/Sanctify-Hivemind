"""Memory: per-environment world-model, shared blackboard, and pattern store.

Three distinct memory systems, on purpose:

- **World-model** (``EnvironmentMemory``): durable, per-environment facts that let an
  agent start *warm* instead of re-discovering an environment every run — e.g. "this
  site renders H1s via Elementor", "sitemap.xml is a physical file", "the ThemeREX key
  403s". Persisted to disk (JSON).

- **Blackboard** (``Blackboard``): ephemeral, shared, run-scoped scratch space that
  agents read/write to coordinate within a single orchestration (e.g. the Recon agent
  publishes the detected stack; the Security agent consumes it).

- **Pattern store** (``PatternStore``): reusable "when you see X, do Y" playbook
  fragments accumulated across runs, so the swarm gets better over time.

All are plain, dependency-free stores. Cognition backends can wrap them.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


class Blackboard:
    """Thread-safe, run-scoped shared memory for inter-agent coordination."""

    def __init__(self) -> None:
        self._data: dict[str, Any] = {}
        self._lock = threading.Lock()

    def put(self, key: str, value: Any) -> None:
        with self._lock:
            self._data[key] = value

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            return self._data.get(key, default)

    def merge(self, key: str, value: dict) -> None:
        """Merge a dict into an existing dict value (shallow)."""
        with self._lock:
            cur = self._data.get(key)
            if isinstance(cur, dict) and isinstance(value, dict):
                cur.update(value)
            else:
                self._data[key] = value

    def snapshot(self) -> dict:
        with self._lock:
            return dict(self._data)


class EnvironmentMemory:
    """Durable per-environment world-model, persisted as JSON.

    Keyed by an environment id (e.g. a site URL). Facts are free-form; the point is
    that an agent can consult prior knowledge before acting.
    """

    def __init__(self, env_id: str, path: Optional[str] = None) -> None:
        self.env_id = env_id
        self._path = Path(path) if path else None
        self._facts: dict[str, Any] = {}
        if self._path and self._path.exists():
            try:
                self._facts = json.loads(self._path.read_text(encoding="utf-8"))
            except Exception:  # noqa: BLE001 — corrupt/empty file starts fresh
                self._facts = {}

    def remember(self, key: str, value: Any) -> None:
        self._facts[key] = {"value": value, "updated": time.time()}
        self._flush()

    def recall(self, key: str, default: Any = None) -> Any:
        entry = self._facts.get(key)
        return entry["value"] if entry else default

    def all(self) -> dict:
        return {k: v["value"] for k, v in self._facts.items()}

    def _flush(self) -> None:
        if self._path:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(json.dumps(self._facts, indent=2, default=str), encoding="utf-8")


@dataclass
class Pattern:
    """A reusable playbook fragment: 'when <trigger>, do <action>' with rationale."""

    trigger: str
    action: str
    rationale: str = ""
    tags: list[str] = field(default_factory=list)


class PatternStore:
    """Accumulated, reusable patterns. Grows across runs so the swarm improves."""

    def __init__(self, path: Optional[str] = None) -> None:
        self._path = Path(path) if path else None
        self._patterns: list[Pattern] = []
        if self._path and self._path.exists():
            try:
                raw = json.loads(self._path.read_text(encoding="utf-8"))
                self._patterns = [Pattern(**p) for p in raw]
            except Exception:  # noqa: BLE001
                self._patterns = []

    def add(self, pattern: Pattern) -> None:
        self._patterns.append(pattern)
        self._flush()

    def match(self, tag: str) -> list[Pattern]:
        return [p for p in self._patterns if tag in p.tags]

    def all(self) -> list[Pattern]:
        return list(self._patterns)

    def _flush(self) -> None:
        if self._path:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(
                json.dumps([p.__dict__ for p in self._patterns], indent=2), encoding="utf-8"
            )
