"""ADR-0054 — source-independence bookkeeping: which independence groups showed each pattern.

Split out of ``homeostasis.poisoning`` (which re-exports both names) so that module stays
under the repository's file-size rule. It is the gateway's per-(pattern, meaning) record of
distinct source groups — the evidence behind "repetition is not normality" — and nothing
else: it scores nothing and promotes nothing; the gateway reads its counts.

Stdlib plus Stage 2's pattern key and meaning vector.
"""

from __future__ import annotations

import hashlib
import sys
from collections import OrderedDict, deque
from collections.abc import Sequence
from dataclasses import dataclass

from pocketsec.stage2.adaptation.quarantine import meaning_vector, pattern_key
from pocketsec.stage2.encoder.ssir_encoder import EncodedTransition

__all__ = ["SourceIndependence", "track_key"]


def track_key(encoded: EncodedTransition) -> str:
    """Stage 2's pattern key refined by the exact meaning it would anchor.

    Independence is counted per this key. Stage 2's key is the relation alone, and
    counting groups per relation would let one attacker free-ride on groups earned
    by unrelated legitimate behaviour sharing the relation. The admission keeps
    Stage 2's ``pattern_key`` (spec Rule A); only the group accounting is finer.
    """
    meaning = ",".join(f"{v:.6f}" for v in meaning_vector(encoded))
    digest = hashlib.sha256(meaning.encode("utf-8")).hexdigest()[:16]
    return f"{pattern_key(encoded)}|{digest}"


@dataclass
class _Track:
    groups: set[str]
    eligible_capsules: deque[str]
    evidence: deque[str]
    recent: deque[str]

    def memory_bytes(self) -> int:
        strings = [*self.groups, *self.eligible_capsules, *self.evidence, *self.recent]
        return sum(sys.getsizeof(s) for s in strings) + 256


class SourceIndependence:
    """Which independence groups showed each (pattern, meaning), bounded twice.

    At most ``max_groups`` groups per key; a group past that cap is refused and counted.
    At most ``max_patterns`` keys: a new key past that cap *retires* the least recently
    seen key — first one no group ever corroborated (it only saw ineligible steps), else
    the least recently seen of all — and counts it in ``pattern_evictions``.

    Why retire rather than refuse (review S6-AUTH-07): tracks were never removed, so 512
    distinct keys — from one low-privilege source, or from ordinary diversity over a long
    horizon — refused every later key and ended normality learning for the gateway's
    lifetime. Retiring can only *lose* corroboration (a retired key restarts at zero
    groups), so overflow still never promotes.
    """

    def __init__(self, *, max_patterns: int, max_groups: int, max_refs: int) -> None:
        self._max_patterns = max_patterns
        self._max_groups = max_groups
        self._max_refs = max_refs
        self._tracks: OrderedDict[str, _Track] = OrderedDict()
        self.pattern_overflow = 0  # only a zero-capacity tracker refuses now
        self.pattern_evictions = 0
        self.group_overflow = 0

    def observe(self, key: str, capsule_id: str) -> bool:
        """Note that a capsule offered this key; always tracked (a full map retires one)."""
        track = self._tracks.get(key)
        if track is None:
            if self._max_patterns < 1:  # a tracker with no room tracks nothing
                self.pattern_overflow += 1
                return False
            if len(self._tracks) >= self._max_patterns:
                self._retire_one()
            track = _Track(set(), deque(maxlen=self._max_refs), deque(maxlen=self._max_refs),
                           deque(maxlen=self._max_groups))
            self._tracks[key] = track
        self._tracks.move_to_end(key)
        if capsule_id not in track.recent:
            track.recent.append(capsule_id)
        return True

    def _retire_one(self) -> None:
        """Drop the least recently seen uncorroborated key, else the least recently seen."""
        victim = next((k for k, t in self._tracks.items() if not t.groups), None)
        if victim is None:
            victim = next(iter(self._tracks))
        del self._tracks[victim]
        self.pattern_evictions += 1

    def record_group(
        self, key: str, *, group: str, capsule_id: str, evidence: Sequence[str]
    ) -> int | None:
        """Record an eligible step's group; the distinct-group count, or ``None`` if untracked."""
        track = self._tracks.get(key)
        if track is None:
            return None
        self._tracks.move_to_end(key)
        if group not in track.groups:
            if len(track.groups) >= self._max_groups:
                self.group_overflow += 1
            else:
                track.groups.add(group)
        if capsule_id not in track.eligible_capsules:
            track.eligible_capsules.append(capsule_id)
        for digest in evidence:
            if digest not in track.evidence:
                track.evidence.append(digest)
        return len(track.groups)

    def lineage(self, key: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
        """(capsule ids, evidence digests) that corroborated the key, each <= ``max_refs``."""
        track = self._tracks.get(key)
        if track is None:
            return (), ()
        return tuple(track.eligible_capsules), tuple(track.evidence)

    def groups(self, key: str) -> int:
        track = self._tracks.get(key)
        return 0 if track is None else len(track.groups)

    def related(self, keys: Sequence[str]) -> tuple[str, ...]:
        """Recent capsule ids that offered any of ``keys``, first-seen order."""
        ids = (cid for k in keys if (t := self._tracks.get(k)) is not None for cid in t.recent)
        return tuple(dict.fromkeys(ids))

    def __len__(self) -> int:
        return len(self._tracks)

    def memory_bytes(self) -> int:
        return sum(sys.getsizeof(k) + t.memory_bytes() for k, t in self._tracks.items())
