"""Deterministic seed derivation (D0.6).

One master seed is recorded per experiment; every component seed is derived
from it by hash, so a result can be replayed exactly from a single integer, and
two components never accidentally share a stream.
"""

from __future__ import annotations

import hashlib
import os
import random
from dataclasses import dataclass

__all__ = ["SeedSet"]

#: Components that get a derived stream. Adding one never changes existing seeds.
COMPONENTS = ("dataset_split", "model_init", "sampling", "augmentation", "evaluation")

_MASK_64 = (1 << 64) - 1


@dataclass(frozen=True, slots=True)
class SeedSet:
    """A master seed plus its deterministically derived component seeds."""

    master: int

    def __post_init__(self) -> None:
        if not isinstance(self.master, int) or isinstance(self.master, bool) or self.master < 0:
            raise ValueError(f"master seed must be a non-negative int, got {self.master!r}")

    def derive(self, component: str) -> int:
        """Return the stable 64-bit seed for ``component``."""
        material = f"pocketsec-seed-v1:{self.master}:{component}".encode()
        return int.from_bytes(hashlib.sha256(material).digest()[:8], "big") & _MASK_64

    def as_dict(self) -> dict[str, int]:
        seeds = {"master": self.master}
        seeds.update({component: self.derive(component) for component in COMPONENTS})
        return seeds

    def apply(self) -> None:
        """Seed the stdlib RNG for this process.

        ``PYTHONHASHSEED`` cannot be set after interpreter start, so it is
        reported by :class:`EnvironmentFingerprint` rather than silently
        assumed. A run that needs hash-order determinism must export it before
        launch; the fingerprint records whether it did.
        """
        random.seed(self.derive("sampling"))

    @classmethod
    def from_env(cls, default: int = 0) -> SeedSet:
        raw = os.environ.get("POCKETSEC_SEED")
        return cls(int(raw)) if raw is not None and raw.isdigit() else cls(default)
