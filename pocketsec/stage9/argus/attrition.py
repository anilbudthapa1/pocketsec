"""How many of the fittest genomes die under attack, and whether an attack killed them.

The lead's question is "how many 'fittest' genomes die under attack". A worst case is never
above its clean AP, so a rule that kills any genome below the Φ-oracle's worst case also kills
every genome that was merely weaker than the incumbent on clean data, with every attack a
no-op (S9-R2, S9-FC-01, S9-CX-03). This module therefore splits the deaths by cause and
headlines only the attack-induced ones. ``argus.adversary`` re-exports both names.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage9.ontogenesis.fitness import FitnessRecord

__all__ = ["FittestAttrition", "fittest_die_under_attack"]


@dataclass(frozen=True, slots=True)
class FittestAttrition:
    """How many of the fittest (by clean train AP) genomes die, and WHY (S9-R2, S9-FC-01).

    ``died`` is the disjunctive rule (below the reference, or a large drop, or unmeasured).
    It is NOT an attack count: worst case <= clean AP always, so a genome whose clean AP is
    already below the reference "dies" with every attack a no-op. ``died_without_attack`` is
    that control (the same rule with worst case := clean AP), and ``died_under_attack`` is
    the headline: genomes an attack actually killed (clean - worst > tolerance, or pushed
    from at/above the reference to below it).
    """

    examined: int
    died: int
    died_digests: tuple[str, ...]
    died_under_attack: int = 0
    died_under_attack_digests: tuple[str, ...] = ()
    died_without_attack: int = 0
    unmeasured: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "examined": self.examined,
            "died": self.died,
            "died_digests": list(self.died_digests),
            "died_under_attack": self.died_under_attack,
            "died_under_attack_digests": list(self.died_under_attack_digests),
            "died_without_attack": self.died_without_attack,
            "unmeasured": self.unmeasured,
        }

    def summary(self) -> str:
        """The headline is the attack-induced count; the rest is its context."""
        return (
            f"{self.died_under_attack}/{self.examined} killed by an attack; "
            f"{self.died_without_attack}/{self.examined} would die with NO attack (clean AP "
            f"already below the reference); {self.unmeasured} unmeasured; disjunctive rule "
            f"{self.died}/{self.examined}"
        )


def _killed_by_attack(record: FitnessRecord, reference: float, tolerance: float) -> bool:
    clean, worst = record.clean_ap, record.worst_case_ap
    if clean is None or worst is None:
        return False
    return clean - worst > tolerance or (clean >= reference > worst)


def fittest_die_under_attack(
    records: Sequence[FitnessRecord],
    *,
    reference_worst_case: float,
    top_k: int = 10,
    drop_tolerance: float = 0.05,
) -> FittestAttrition:
    """Top ``top_k`` by CLEAN AP; one dies if its worst case falls below the Φ-oracle's
    worst case on the same suite, or drops more than ``drop_tolerance`` below its own
    clean AP. An unmeasured worst case is a death: survival must be shown, not assumed.
    The deaths are then split by cause (see :class:`FittestAttrition`): only
    ``died_under_attack`` is evidence about the attacks.
    """
    if top_k < 1:
        raise ContractError(f"top_k must be >= 1, got {top_k}")
    fittest = sorted(
        records,
        key=lambda r: (-(r.clean_ap if r.clean_ap is not None else float("-inf")), r.genome_digest),
    )[:top_k]
    died = tuple(
        r.genome_digest
        for r in fittest
        if r.worst_case_ap is None
        or r.clean_ap is None
        or r.worst_case_ap < reference_worst_case
        or r.clean_ap - r.worst_case_ap > drop_tolerance
    )
    by_attack = tuple(
        r.genome_digest
        for r in fittest
        if _killed_by_attack(r, reference_worst_case, drop_tolerance)
    )
    without_attack = sum(
        1 for r in fittest if r.clean_ap is not None and r.clean_ap < reference_worst_case
    )
    unmeasured = sum(1 for r in fittest if r.clean_ap is None or r.worst_case_ap is None)
    return FittestAttrition(
        examined=len(fittest),
        died=len(died),
        died_digests=died,
        died_under_attack=len(by_attack),
        died_under_attack_digests=by_attack,
        died_without_attack=without_attack,
        unmeasured=unmeasured,
    )
