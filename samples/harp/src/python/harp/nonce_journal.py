"""Append-only nonce replay journal with TTL pruning and compaction.

Mirrors Harp.Common/NonceJournalStore.cs from the C# implementation.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path


class NonceJournalStore:
    """File-based nonce journal for replay protection."""

    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._compact_path = Path(path + ".compact")
        self._active: dict[str, datetime] = {}
        self._load()

    def seen(self, replay_key: str, now: datetime, ttl_seconds: float) -> bool:
        """Check whether replay_key has been seen within the TTL window."""
        self._prune_in_memory(now, ttl_seconds)
        return replay_key in self._active

    def record(self, replay_key: str, now: datetime) -> None:
        """Record a new replay key."""
        self._active[replay_key] = now
        self._append_line(json.dumps({"k": replay_key, "ts": now.isoformat()}))

    def compact_if_needed(
        self,
        now: datetime,
        ttl_seconds: float,
        max_bytes: int = 2 * 1024 * 1024,
    ) -> None:
        """Compact the journal file if it exceeds max_bytes."""
        self._prune_in_memory(now, ttl_seconds)

        if not self._path.exists():
            return
        if self._path.stat().st_size < max_bytes:
            return

        lines = "\n".join(
            json.dumps({"k": k, "ts": ts.isoformat()})
            for k, ts in self._active.items()
        ) + "\n"

        self._compact_path.write_text(lines, encoding="utf-8")
        self._path.write_text(lines, encoding="utf-8")

        try:
            self._compact_path.unlink()
        except OSError:
            pass

    # ──────────────── internals ────────────────

    def _load(self) -> None:
        if not self._path.exists():
            return

        for line in self._path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                if entry.get("k"):
                    self._active[entry["k"]] = datetime.fromisoformat(entry["ts"])
            except (json.JSONDecodeError, KeyError, ValueError):
                # Ignore malformed lines; journal is append-only
                pass

    def _append_line(self, line: str) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()
            os.fsync(f.fileno())

    def _prune_in_memory(self, now: datetime, ttl_seconds: float) -> None:
        from datetime import timedelta

        cutoff = now - timedelta(seconds=ttl_seconds)
        to_remove = [k for k, ts in self._active.items() if ts < cutoff]
        for k in to_remove:
            del self._active[k]
