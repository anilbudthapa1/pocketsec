"""D4.5b — tombstones for killed worlds: the oscillation guard and the rebuild record.

§13: "Killed worlds remain in a compact tombstone record to prevent oscillation
and support later reopening." Two jobs, and they pull in opposite directions from
the bound, so both are spelled out here.

*   **Oscillation.** Without a memory of what was killed, a residual that keeps
    recurring spawns the same world, kills it, and spawns it again — a
    spawn→kill→spawn loop that burns the entropy budget and looks, from outside,
    like the system changing its mind. ``TombstoneLedger.oscillating`` is the
    guard the birth path consults.
*   **Rebuild.** A tombstone carries ``evidence_digests``, so a world killed for
    the wrong reason can be reconstructed from retained evidence references
    (§45's last rule).

What this module refuses to do: **it never deletes an evidence digest.** The
project forbids deleting counterexamples, provenance or rollback information, and
a killed world's digests are exactly that. The record count is bounded at
``MAX_TOMBSTONES`` and evicting a *narrative* record is allowed, but its digests
stay in the retained set. When the digest set itself reaches its bound the ledger
refuses the **new** digests, with an explicit ``Truncation`` — old provenance is
never traded for new.
"""

from __future__ import annotations

import math
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    require_identifier,
    require_non_negative_int,
)
from pocketsec.stage4.graph.sparse_world_graph import Truncation

if TYPE_CHECKING:  # pragma: no cover - annotation only; see _require_death_cause
    from pocketsec.stage4.worlds.lifecycle import DeathCause

__all__ = [
    "MAX_RETAINED_DIGESTS",
    "MAX_TOMBSTONES",
    "MAX_TRACKED_MECHANISMS",
    "NON_REOPENABLE_CAUSES",
    "OSCILLATION_KILL_THRESHOLD",
    "TombstoneLedger",
    "WorldTombstone",
    "reopenable_for",
]

#: §13 / the Stage 4 constant table.
MAX_TOMBSTONES: int = 32

#: Digests are ~71 bytes each, so this ceiling is ~290 KB — comfortably inside
#: MAX_INCIDENT_BYTES (8 MiB) and far above any bounded incident's real death
#: count. Reaching it refuses NEW digests rather than evicting old ones.
MAX_RETAINED_DIGESTS: int = 4096

#: A mechanism killed once and reopened once has had its second chance. A third
#: spawn is oscillation, not evidence.
OSCILLATION_KILL_THRESHOLD: int = 1

#: Mechanisms the oscillation guard tracks. The death count and the refuted set
#: must outlive tombstone eviction — forgetting them is how a bounded ledger
#: quietly re-enables the loop it exists to stop — so they are bounded separately
#: and, like the digests, refuse NEW entries rather than dropping old ones.
MAX_TRACKED_MECHANISMS: int = 512

#: Death causes that close the question. A hard contradiction and a sustained
#: tension are both *evidential* refutations, and an epoch invalidation means the
#: world was about a host configuration that no longer exists — reopening any of
#: them needs a fresh world from fresh evidence, not a resurrection. DOMINATED,
#: BUDGET_TRUNCATION and ASSURANCE_BELOW_THRESHOLD are resource or bookkeeping
#: deaths, so those worlds stay reopenable: the evidence never refuted them.
NON_REOPENABLE_CAUSES = frozenset(
    {"HARD_CONTRADICTION", "SUSTAINED_TENSION", "EPOCH_INVALIDATION"}
)

_DIGEST_PREFIX = "sha256:"
_TOMBSTONE_SCALAR_BYTES: int = 2 * sys.getsizeof(0.0) + 2 * sys.getsizeof(0)


def _require_death_cause(value: object) -> DeathCause:
    """Validate ``cause`` against the real ``DeathCause`` vocabulary.

    Imported inside the function on purpose: ``lifecycle`` imports this module to
    build tombstones, so a module-level import here would be a cycle. Duplicating
    the six names as a local frozenset would be worse — two vocabularies drift.
    """
    from pocketsec.stage4.worlds.lifecycle import DeathCause

    try:
        return DeathCause(value)
    except ValueError as exc:
        raise ContractError(f"WorldTombstone.cause must be a DeathCause, got {value!r}") from exc


def _require_digests(value: object) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ContractError("WorldTombstone.evidence_digests must be a sequence of digests")
    seen: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.startswith(_DIGEST_PREFIX):
            raise ContractError(f"evidence digest must be 'sha256:<hex>', got {item!r}")
        if len(item) != len(_DIGEST_PREFIX) + 64:
            raise ContractError(f"evidence digest must be 'sha256:<64 hex>', got {item!r}")
        if item not in seen:
            seen.append(item)
    return tuple(sorted(seen))


@dataclass(frozen=True, slots=True)
class WorldTombstone:
    """The compact record of a world that died.

    ``retired_at_sequence`` is *not* named ``killed_at_sequence``: ``kill`` is a
    ``FORBIDDEN_AUTHORITY_FIELDS`` token (``threat_prediction_v1.py:48``) and trust
    rule T5 forbids it in any Stage 4 dataclass field name. See the deviation note
    in the package report — the spec's own D4.5 field list conflicts with its §2.4.

    ``consequence`` is an addition to the spec's field list, required because
    eviction is specified as "oldest-lowest-consequence" and none of the other
    fields carries consequence. It is the dead world's Φ-scale consequence.
    """

    world_id: str
    mechanism_id: str
    cause: DeathCause
    detail: str
    retired_at_sequence: int
    support_at_death: float
    reopenable: bool
    evidence_digests: tuple[str, ...]
    consequence: float = 0.0

    def __post_init__(self) -> None:
        require_identifier(self.world_id, "WorldTombstone.world_id")
        require_identifier(self.mechanism_id, "WorldTombstone.mechanism_id")
        object.__setattr__(self, "cause", _require_death_cause(self.cause))
        if not isinstance(self.detail, str) or not self.detail:
            raise ContractError("WorldTombstone.detail must be a non-empty string")
        require_non_negative_int(self.retired_at_sequence, "WorldTombstone.retired_at_sequence")
        for name in ("support_at_death", "consequence"):
            numeric = getattr(self, name)
            if isinstance(numeric, bool) or not isinstance(numeric, (int, float)):
                raise ContractError(f"WorldTombstone.{name} must be a number, got {numeric!r}")
            if not math.isfinite(float(numeric)):
                raise ContractError(f"WorldTombstone.{name} must be finite, got {numeric!r}")
            object.__setattr__(self, name, float(numeric))
        if not isinstance(self.reopenable, bool):
            raise ContractError("WorldTombstone.reopenable must be a bool")
        object.__setattr__(self, "evidence_digests", _require_digests(self.evidence_digests))

    def memory_bytes(self) -> int:
        return (
            sys.getsizeof(self.world_id)
            + sys.getsizeof(self.mechanism_id)
            + sys.getsizeof(str(self.cause))
            + sys.getsizeof(self.detail)
            + sum(sys.getsizeof(d) for d in self.evidence_digests)
            + _TOMBSTONE_SCALAR_BYTES
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "world_id": self.world_id,
            "mechanism_id": self.mechanism_id,
            "cause": str(self.cause),
            "detail": self.detail,
            "retired_at_sequence": self.retired_at_sequence,
            "support_at_death": round(self.support_at_death, 6),
            "reopenable": self.reopenable,
            "evidence_digests": list(self.evidence_digests),
            "consequence": round(self.consequence, 6),
        }


class TombstoneLedger:
    """Bounded memory of dead worlds.

    Insertion-ordered so "oldest" needs no clock the tombstone does not carry;
    eviction is lowest-consequence first, oldest breaking the tie.
    """

    def __init__(self, *, max_tombstones: int = MAX_TOMBSTONES) -> None:
        if max_tombstones < 1 or max_tombstones > MAX_TOMBSTONES:
            raise ContractError(
                f"max_tombstones must be in [1, {MAX_TOMBSTONES}], got {max_tombstones}"
            )
        self.max_tombstones = max_tombstones
        self._stones: dict[str, WorldTombstone] = {}
        self._kills: dict[str, int] = {}
        #: Mechanisms whose death was evidential. Never removed: a refutation that
        #: expires would let the spawn->kill->spawn loop restart.
        self._refuted: set[str] = set()
        self._retained_digests: set[str] = set()
        self._refused_digests: int = 0
        self._untracked_mechanisms: int = 0

    # --- inspection ------------------------------------------------------

    def __len__(self) -> int:
        return len(self._stones)

    def tombstones(self) -> tuple[WorldTombstone, ...]:
        """Insertion order — oldest first."""
        return tuple(self._stones.values())

    def digests(self) -> frozenset[str]:
        """Every digest ever recorded here, including those whose narrative
        record was evicted. Never shrinks."""
        return frozenset(self._retained_digests)

    def deaths(self, mechanism_id: str) -> int:
        """How many times this mechanism has died, including evicted records."""
        return self._kills.get(mechanism_id, 0)

    def refuted(self, mechanism_id: str) -> bool:
        """Whether the evidence closed this mechanism, surviving eviction."""
        return mechanism_id in self._refuted

    def memory_bytes(self) -> int:
        total = sys.getsizeof(self._stones) + sys.getsizeof(self._retained_digests)
        total += sum(stone.memory_bytes() for stone in self._stones.values())
        total += sum(sys.getsizeof(d) for d in self._retained_digests)
        total += sum(sys.getsizeof(k) + sys.getsizeof(0) for k in self._kills)
        total += sum(sys.getsizeof(k) for k in self._refuted)
        return total

    def report(self) -> Mapping[str, int]:
        return {
            "tombstones": len(self._stones),
            "max_tombstones": self.max_tombstones,
            "retained_digests": len(self._retained_digests),
            "refused_digests": self._refused_digests,
            "tracked_mechanisms": len(self._kills),
            "untracked_mechanisms": self._untracked_mechanisms,
            "mechanisms": len(self._kills),
            "memory_bytes": self.memory_bytes(),
        }

    # --- mutation --------------------------------------------------------

    def record(self, stone: WorldTombstone) -> tuple[Truncation, ...]:
        """Record a death, returning every loss recording it caused.

        Returns a tuple rather than the spec's ``None``: eviction at
        ``MAX_TOMBSTONES`` and digest refusal at ``MAX_RETAINED_DIGESTS`` are both
        losses, and a silent drop is a defect. Callers that ignore the result
        behave exactly as the ``-> None`` signature intended.
        """
        if not isinstance(stone, WorldTombstone):
            raise ContractError("TombstoneLedger.record expects a WorldTombstone")
        losses = list(self._retain_digests(stone))
        losses.extend(self._track_mechanism(stone))
        if stone.world_id in self._stones:
            self._stones[stone.world_id] = stone
            return tuple(losses)
        if len(self._stones) >= self.max_tombstones:
            losses.extend(self._evict_one())
        self._stones[stone.world_id] = stone
        return tuple(losses)

    def _track_mechanism(self, stone: WorldTombstone) -> tuple[Truncation, ...]:
        """Record the death against the oscillation guard, bounded by refusing new
        mechanisms rather than forgetting tracked ones."""
        known = stone.mechanism_id in self._kills
        if not known and len(self._kills) >= MAX_TRACKED_MECHANISMS:
            self._untracked_mechanisms += 1
            return (
                Truncation(
                    what="tombstone",
                    identifier=stone.mechanism_id,
                    reason="mechanism_tracking_capacity_oscillation_guard_not_armed",
                    consequence_lost=stone.consequence,
                ),
            )
        self._kills[stone.mechanism_id] = self._kills.get(stone.mechanism_id, 0) + 1
        if not stone.reopenable:
            self._refuted.add(stone.mechanism_id)
        return ()

    def _retain_digests(self, stone: WorldTombstone) -> tuple[Truncation, ...]:
        """Add digests to the never-shrinking retained set, refusing new ones
        rather than evicting old ones when the bound is reached."""
        losses: list[Truncation] = []
        for digest in stone.evidence_digests:
            if digest in self._retained_digests:
                continue
            if len(self._retained_digests) >= MAX_RETAINED_DIGESTS:
                self._refused_digests += 1
                losses.append(
                    Truncation(
                        what="evidence_digest",
                        identifier=digest,
                        reason="retained_digest_capacity_new_digest_refused",
                        consequence_lost=stone.consequence,
                    )
                )
                continue
            self._retained_digests.add(digest)
        return tuple(losses)

    def _evict_one(self) -> tuple[Truncation, ...]:
        """Oldest-lowest-consequence. Digests stay behind in the retained set."""
        order = {stone.world_id: index for index, stone in enumerate(self._stones.values())}
        victim = min(
            self._stones.values(),
            key=lambda s: (s.consequence, order[s.world_id]),
        )
        del self._stones[victim.world_id]
        return (
            Truncation(
                what="tombstone",
                identifier=victim.world_id,
                reason="tombstone_capacity_evicted_oldest_lowest_consequence",
                consequence_lost=victim.consequence,
            ),
        )

    # --- the two questions the birth path asks ---------------------------

    def oscillating(self, mechanism_id: str) -> bool:
        """True when re-spawning this mechanism would be a spawn→kill→spawn loop.

        A mechanism whose death was evidential (see ``NON_REOPENABLE_CAUSES``) is
        oscillating on its first re-spawn: the evidence already refuted it.
        A mechanism that died for resource reasons gets one reopening, and dying
        again past ``OSCILLATION_KILL_THRESHOLD`` closes it.
        """
        if not isinstance(mechanism_id, str) or not mechanism_id:
            raise ContractError("oscillating() needs a non-empty mechanism_id")
        if mechanism_id in self._refuted:
            return True
        return self._kills.get(mechanism_id, 0) > OSCILLATION_KILL_THRESHOLD

    def reopen(self, mechanism_id: str) -> WorldTombstone | None:
        """Consume and return the most recent reopenable tombstone, or None.

        Consuming it is the point: the stone is a one-shot licence to rebuild, so
        a caller cannot reopen the same dead world indefinitely. Its digests stay
        in the retained set, so the rebuild is still possible from evidence.
        """
        if not isinstance(mechanism_id, str) or not mechanism_id:
            raise ContractError("reopen() needs a non-empty mechanism_id")
        candidates = [
            stone
            for stone in self._stones.values()
            if stone.mechanism_id == mechanism_id and stone.reopenable
        ]
        if not candidates:
            return None
        stone = candidates[-1]
        del self._stones[stone.world_id]
        return stone


def reopenable_for(cause: str) -> bool:
    """Whether a death of this cause leaves the world reopenable.

    Exported so the birth path and the tombstone agree on one table rather than
    two: a world that is reopenable in one place and refuted in the other is how
    an oscillation guard silently stops guarding.
    """
    return str(cause) not in NON_REOPENABLE_CAUSES
