"""D0.6 — environment fingerprint captured with every result.

Reproducibility policy: seeds, environment, hardware, source commit, dataset
version and checksums. A result that cannot state the commit it came from, or
that was produced from a dirty tree, is still recorded — but it is recorded as
such, so nobody later mistakes it for a reproducible measurement.
"""

from __future__ import annotations

import os
import platform
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pocketsec.stage0.repro.seeds import SeedSet

__all__ = ["EnvironmentFingerprint", "git_state"]

_GIT_TIMEOUT_SECONDS = 5


def _git(args: list[str], cwd: Path) -> str | None:
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=_GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


def git_state(root: Path | None = None) -> tuple[str | None, bool | None]:
    """Return ``(commit, dirty)``; ``(None, None)`` outside a git work tree."""
    cwd = root or Path(__file__).resolve().parents[3]
    commit = _git(["rev-parse", "HEAD"], cwd)
    if commit is None:
        return None, None
    status = _git(["status", "--porcelain"], cwd)
    return commit, bool(status) if status is not None else None


@dataclass(frozen=True, slots=True)
class EnvironmentFingerprint:
    """Everything needed to judge whether two results are comparable."""

    captured_at_ns: int
    python_version: str
    python_implementation: str
    platform_summary: str
    kernel: str
    machine: str
    cpu_count: int | None
    git_commit: str | None
    git_dirty: bool | None
    pythonhashseed: str | None
    seeds: dict[str, int]
    source_root: str

    @property
    def is_reproducible(self) -> bool:
        """True only when the exact source state is pinned and clean."""
        return self.git_commit is not None and self.git_dirty is False

    @property
    def caveats(self) -> tuple[str, ...]:
        notes: list[str] = []
        if self.git_commit is None:
            notes.append("no git commit recorded: source state is not pinned")
        elif self.git_dirty:
            notes.append("working tree was dirty: source state is not reproducible")
        if self.pythonhashseed is None:
            notes.append("PYTHONHASHSEED unset: hash-ordered iteration is not reproducible")
        return tuple(notes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "captured_at_ns": self.captured_at_ns,
            "python_version": self.python_version,
            "python_implementation": self.python_implementation,
            "platform": self.platform_summary,
            "kernel": self.kernel,
            "machine": self.machine,
            "cpu_count": self.cpu_count,
            "git_commit": self.git_commit,
            "git_dirty": self.git_dirty,
            "pythonhashseed": self.pythonhashseed,
            "seeds": dict(self.seeds),
            "source_root": self.source_root,
            "is_reproducible": self.is_reproducible,
            "caveats": list(self.caveats),
        }

    @classmethod
    def capture(cls, *, seeds: SeedSet, root: Path | None = None) -> EnvironmentFingerprint:
        source_root = root or Path(__file__).resolve().parents[3]
        commit, dirty = git_state(source_root)
        return cls(
            captured_at_ns=time.time_ns(),
            python_version=sys.version.split()[0],
            python_implementation=platform.python_implementation(),
            platform_summary=platform.platform(),
            kernel=platform.release(),
            machine=platform.machine(),
            cpu_count=os.cpu_count(),
            git_commit=commit,
            git_dirty=dirty,
            pythonhashseed=os.environ.get("PYTHONHASHSEED"),
            seeds=seeds.as_dict(),
            source_root=str(source_root),
        )
