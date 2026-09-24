"""D2.7 — lattice restructuring: merge (DTL-F13), fission (DTL-F14), and undo.

The lattice has to shrink to be compilable and split to stay meaningful, and both
operations are ways to be wrong. This module makes each one *accountable*:

* **Every merge carries its evidence.** A :class:`MacroState` stores the
  :class:`~pocketsec.stage2.lattice.equivalence.EquivalenceVerdict` objects that
  justified it. A macro state with no recorded verdict cannot exist, which is the
  same construction rule the Stage 3 exporter applies to candidates.
* **Every refusal is counted, by reason.** ``RestructureReport.reason_counts`` is
  the honest half of the report. A run that merged nothing because the evidence
  was thin looks different from a run that merged nothing because the atoms
  genuinely differ, and conflating them is how a broken quantizer passes for a
  stable one.
* **Merging is reversible** (spec §13). :meth:`LatticeRestructurer.unmerge`
  dissolves a macro state back to singletons. Reversal granularity is the macro
  state, not the individual merge step: when merging starts from singletons —
  which is the only way :meth:`merge_equivalent_atoms` starts — dissolving to
  singletons *is* the exact pre-merge partition.
* **Fission needs measured heterogeneity, never a heuristic urge.** The three
  admissible reasons are a successor distribution too spread out, a state summary
  that disagrees with a fellow member on one of the nine ``DIMENSIONS``, or a
  member whose uncertainty envelope is wider than the atom's own. No reason, no
  split, and the refusal is counted.

``max_macro=0`` disables restructuring completely. That is not a degenerate
setting: it is the **fixed-K control** D2.7 must be measured against (spec §5).
"""

from __future__ import annotations

import math
from collections.abc import Hashable
from dataclasses import dataclass
from typing import Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.state.security_state import DIMENSIONS
from pocketsec.stage2.lattice.atom import CompileStatus
from pocketsec.stage2.lattice.equivalence import (
    EquivalenceVerdict,
    predictive_equivalence,
    successor_distribution,
)
from pocketsec.stage2.lattice.quantizer import BehaviourQuantizer
from pocketsec.stage2.lattice.transitions import LatticeTransition, TransitionLattice

__all__ = [
    "MAX_MACRO_STATES",
    "REASON_DISABLED",
    "REASON_FISSION_REFUSED",
    "REASON_MACRO_BUDGET",
    "REASON_NOT_HETEROGENEOUS",
    "REASON_STATE_DISAGREEMENT",
    "REASON_SUCCESSOR_ENTROPY",
    "REASON_UNCERTAINTY_ENVELOPE",
    "REASON_UNKNOWN_ATOM",
    "LatticeRestructurer",
    "MacroState",
    "RestructureReport",
    "normalised_successor_entropy",
    "successor_entropy",
]

MAX_MACRO_STATES: int = 64

REASON_DISABLED = "RESTRUCTURING_DISABLED"
REASON_MACRO_BUDGET = "MACRO_BUDGET_EXHAUSTED"
REASON_UNKNOWN_ATOM = "UNKNOWN_ATOM"
REASON_NOT_HETEROGENEOUS = "NOT_HETEROGENEOUS"
REASON_SUCCESSOR_ENTROPY = "SUCCESSOR_ENTROPY"
REASON_STATE_DISAGREEMENT = "STATE_DISAGREEMENT"
REASON_UNCERTAINTY_ENVELOPE = "UNCERTAINTY_ENVELOPE"
REASON_FISSION_REFUSED = "FISSION_REFUSED"


def successor_entropy(
    lattice: TransitionLattice, source: int, *, epoch_id: int | None = None
) -> float:
    """Shannon entropy of P(next | source) in bits, unseen bucket included."""
    distribution = successor_distribution(lattice, source, epoch_id=epoch_id)
    return -sum(p * math.log2(p) for p in distribution.values() if p > 0.0)


def normalised_successor_entropy(
    lattice: TransitionLattice, source: int, *, epoch_id: int | None = None
) -> float:
    """Entropy as a fraction of the maximum over the smoothed bucket space.

    Normalised because a raw bit count is not comparable between a source with
    two recorded continuations and one with forty: the heterogeneity threshold has
    to mean the same thing for both.
    """
    buckets = lattice.bucket_count(source, epoch_id=epoch_id)
    if buckets < 2:
        return 0.0
    return successor_entropy(lattice, source, epoch_id=epoch_id) / math.log2(buckets)


@dataclass(frozen=True, slots=True)
class MacroState:
    """A set of atoms judged predictively equivalent, with its justification."""

    macro_id: int
    members: frozenset[int]
    created_at_sequence: int
    #: The verdicts that built this macro state. Non-empty by construction: a
    #: merge without recorded evidence is exactly the artefact ADR-0010 found in
    #: the router's path accounting.
    merge_evidence: tuple[EquivalenceVerdict, ...]

    def __post_init__(self) -> None:
        if len(self.members) < 2:
            raise ContractError(
                f"macro {self.macro_id}: a macro state needs >= 2 members, "
                f"got {sorted(self.members)}"
            )
        if not self.merge_evidence:
            raise ContractError(
                f"macro {self.macro_id}: refusing a merge with no recorded verdict"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "macro_id": self.macro_id,
            "members": sorted(self.members),
            "created_at_sequence": self.created_at_sequence,
            "merge_evidence": [v.to_dict() for v in self.merge_evidence],
        }


@dataclass(frozen=True, slots=True)
class RestructureReport:
    """What one restructuring pass did, and everything it declined to do."""

    merges: int
    fissions: int
    refused: int
    macro_states: int
    reason_counts: dict[str, int]

    def __post_init__(self) -> None:
        object.__setattr__(self, "reason_counts", dict(self.reason_counts))

    def to_dict(self) -> dict[str, Any]:
        return {
            "merges": self.merges,
            "fissions": self.fissions,
            "refused": self.refused,
            "macro_states": self.macro_states,
            "reason_counts": dict(sorted(self.reason_counts.items())),
        }


class LatticeRestructurer:
    """Owns the atom -> macro-state partition, and the evidence for it."""

    __slots__ = ("_assignment", "_epsilon", "_heterogeneity", "_macro", "_max_macro", "_next_macro", "_universe")

    def __init__(
        self,
        *,
        epsilon: float = 0.05,
        heterogeneity: float = 0.25,
        max_macro: int = MAX_MACRO_STATES,
    ) -> None:
        if epsilon < 0.0:
            raise ContractError(f"epsilon must be >= 0, got {epsilon}")
        if not 0.0 <= heterogeneity <= 1.0:
            raise ContractError(
                f"heterogeneity must be a normalised entropy in [0, 1], "
                f"got {heterogeneity}"
            )
        if max_macro < 0:
            raise ContractError(f"max_macro must be >= 0, got {max_macro}")
        self._epsilon = epsilon
        self._heterogeneity = heterogeneity
        self._max_macro = max_macro
        self._macro: dict[int, MacroState] = {}
        self._assignment: dict[int, int] = {}
        self._universe: set[int] = set()
        self._next_macro = 0

    # --- read side -----------------------------------------------------------

    @property
    def max_macro(self) -> int:
        return self._max_macro

    def macro_states(self) -> tuple[MacroState, ...]:
        return tuple(self._macro[key] for key in sorted(self._macro))

    def macro_of(self, atom_id: int) -> int | None:
        return self._assignment.get(atom_id)

    def universe(self) -> frozenset[int]:
        """Atom ids this restructurer has examined. The domain of the partition."""
        return frozenset(self._universe)

    def partition(self) -> frozenset[frozenset[int]]:
        """The current partition of :meth:`universe` into blocks."""
        blocks: dict[Hashable, set[int]] = {}
        for atom_id in self._universe:
            blocks.setdefault(self._label(atom_id), set()).add(atom_id)
        return frozenset(frozenset(block) for block in blocks.values())

    def _label(self, atom_id: int) -> Hashable:
        macro_id = self._assignment.get(atom_id)
        return ("macro", macro_id) if macro_id is not None else ("atom", atom_id)

    def stability(self, other: LatticeRestructurer) -> float:
        """Rand-style pairwise agreement in ``[0, 1]`` between two partitions.

        Counts, over every unordered pair of atoms in the shared universe, how
        often the two restructurers agree about whether the pair belongs together.
        Label-invariant, so two runs that produced the same grouping under
        different macro ids score 1.0 — which is the property G2.4 actually cares
        about. Fewer than two shared atoms scores 1.0: there is no pair to
        disagree about, and inventing a penalty would be inventing a measurement.
        """
        shared = sorted(self._universe & other._universe)
        if len(shared) < 2:
            return 1.0
        agree = 0
        total = 0
        for index, left in enumerate(shared):
            for right in shared[index + 1 :]:
                total += 1
                mine = self._label(left) == self._label(right)
                theirs = other._label(left) == other._label(right)
                if mine == theirs:
                    agree += 1
        return agree / total

    # --- merge (DTL-F13) -----------------------------------------------------

    def merge_equivalent_atoms(
        self, quantizer: BehaviourQuantizer, lattice: TransitionLattice
    ) -> RestructureReport:
        """DTL-F13. Merge every predictively equivalent pair the budget allows.

        Deterministic: atoms are considered in id order and pairs in lexicographic
        order, so the same lattice always yields the same partition. That is what
        makes :meth:`stability` a measurement of the *quantizer* rather than of
        dictionary iteration order.
        """
        atoms = quantizer.atoms()
        self._universe.update(atom.atom_id for atom in atoms)
        if self._max_macro == 0:
            # The fixed-K control. Report it explicitly rather than silently
            # returning an empty pass, so a report cannot be mistaken for
            # "restructuring ran and found nothing".
            return RestructureReport(
                merges=0,
                fissions=0,
                refused=0,
                macro_states=0,
                reason_counts={REASON_DISABLED: 1},
            )
        merges = 0
        refused = 0
        reasons: dict[str, int] = {}
        for index, left in enumerate(atoms):
            for right in atoms[index + 1 :]:
                left_macro = self._assignment.get(left.atom_id)
                right_macro = self._assignment.get(right.atom_id)
                if left_macro is not None and left_macro == right_macro:
                    continue
                verdict = predictive_equivalence(
                    lattice, left, right, epsilon=self._epsilon
                )
                if not verdict.equivalent:
                    refused += 1
                    reasons[verdict.reason] = reasons.get(verdict.reason, 0) + 1
                    continue
                sequence = max(left.last_sequence, right.last_sequence)
                if self._apply_merge(left.atom_id, right.atom_id, verdict, sequence):
                    merges += 1
                else:
                    refused += 1
                    reasons[REASON_MACRO_BUDGET] = (
                        reasons.get(REASON_MACRO_BUDGET, 0) + 1
                    )
        return RestructureReport(
            merges=merges,
            fissions=0,
            refused=refused,
            macro_states=len(self._macro),
            reason_counts=reasons,
        )

    def _apply_merge(
        self, left: int, right: int, verdict: EquivalenceVerdict, sequence: int
    ) -> bool:
        left_macro = self._assignment.get(left)
        right_macro = self._assignment.get(right)
        if left_macro is None and right_macro is None:
            if len(self._macro) >= self._max_macro:
                return False
            macro_id = self._next_macro
            self._next_macro += 1
            self._macro[macro_id] = MacroState(
                macro_id=macro_id,
                members=frozenset({left, right}),
                created_at_sequence=sequence,
                merge_evidence=(verdict,),
            )
            self._assignment[left] = macro_id
            self._assignment[right] = macro_id
            return True
        if left_macro is not None and right_macro is None:
            self._extend(left_macro, right, verdict)
            return True
        if right_macro is not None and left_macro is None:
            self._extend(right_macro, left, verdict)
            return True
        # Both already grouped, in different macros: fold into the lower id so the
        # outcome does not depend on which pair happened to be examined first.
        assert left_macro is not None and right_macro is not None
        keep, drop = sorted((left_macro, right_macro))
        kept, dropped = self._macro[keep], self._macro[drop]
        self._macro[keep] = MacroState(
            macro_id=keep,
            members=kept.members | dropped.members,
            created_at_sequence=max(kept.created_at_sequence, sequence),
            merge_evidence=kept.merge_evidence + dropped.merge_evidence + (verdict,),
        )
        for member in dropped.members:
            self._assignment[member] = keep
        del self._macro[drop]
        return True

    def _extend(self, macro_id: int, atom_id: int, verdict: EquivalenceVerdict) -> None:
        existing = self._macro[macro_id]
        self._macro[macro_id] = MacroState(
            macro_id=macro_id,
            members=existing.members | {atom_id},
            created_at_sequence=existing.created_at_sequence,
            merge_evidence=existing.merge_evidence + (verdict,),
        )
        self._assignment[atom_id] = macro_id

    def unmerge(self, macro_id: int) -> RestructureReport:
        """Dissolve one macro state back to singletons (spec §13: reversible)."""
        existing = self._macro.pop(macro_id, None)
        if existing is None:
            return RestructureReport(
                merges=0,
                fissions=0,
                refused=1,
                macro_states=len(self._macro),
                reason_counts={REASON_UNKNOWN_ATOM: 1},
            )
        for member in existing.members:
            if self._assignment.get(member) == macro_id:
                del self._assignment[member]
        return RestructureReport(
            merges=0,
            fissions=0,
            refused=0,
            macro_states=len(self._macro),
            reason_counts={"UNMERGED": len(existing.members)},
        )

    # --- fission (DTL-F14) ---------------------------------------------------

    def heterogeneity_reasons(
        self, quantizer: BehaviourQuantizer, lattice: TransitionLattice, atom_id: int
    ) -> tuple[str, ...]:
        """Measured reasons to split ``atom_id``, in a stable order.

        Empty means the atom is homogeneous *as far as the recorded evidence
        goes*. It is not a claim that the atom is pure; the quantizer keeps no
        samples, so purity is not observable from here.
        """
        atom = quantizer.get(atom_id)
        if atom is None:
            return ()
        reasons: list[str] = []
        if (
            normalised_successor_entropy(lattice, atom_id)
            > self._heterogeneity
        ):
            reasons.append(REASON_SUCCESSOR_ENTROPY)
        macro_id = self._assignment.get(atom_id)
        if macro_id is not None:
            members = self._macro[macro_id].members - {atom_id}
            own_width = atom.envelope_width()
            for member in sorted(members):
                other = quantizer.get(member)
                if other is None:
                    continue
                if any(
                    atom.state_summary.level(name) != other.state_summary.level(name)
                    for name in DIMENSIONS
                ):
                    if REASON_STATE_DISAGREEMENT not in reasons:
                        reasons.append(REASON_STATE_DISAGREEMENT)
                if other.envelope_width() > own_width:
                    if REASON_UNCERTAINTY_ENVELOPE not in reasons:
                        reasons.append(REASON_UNCERTAINTY_ENVELOPE)
        return tuple(reasons)

    def split_heterogeneous_atom(
        self, quantizer: BehaviourQuantizer, lattice: TransitionLattice, atom_id: int
    ) -> RestructureReport:
        """DTL-F14. Split ``atom_id`` when heterogeneity is *measured*, else refuse.

        The split moves the atom's least likely recorded continuations onto a new
        sibling atom, which lowers the parent's successor entropy by construction.
        It does **not** re-route incoming edges: which predecessors belong to which
        half is not recoverable without the samples the quantizer deliberately does
        not keep, so incoming attribution is re-learned from subsequent events
        rather than guessed here.
        """
        atom = quantizer.get(atom_id)
        if atom is None:
            return RestructureReport(0, 0, 1, len(self._macro), {REASON_UNKNOWN_ATOM: 1})
        reasons = self.heterogeneity_reasons(quantizer, lattice, atom_id)
        if not reasons:
            return RestructureReport(
                0, 0, 1, len(self._macro), {REASON_NOT_HETEROGENEOUS: 1}
            )
        sibling_id = quantizer.fission_atom(atom_id, sequence=atom.last_sequence)
        if sibling_id is None:
            return RestructureReport(
                0, 0, 1, len(self._macro), {REASON_FISSION_REFUSED: 1}
            )
        self._universe.add(sibling_id)
        self._reroute(lattice, atom_id, sibling_id)
        counts = {reason: 1 for reason in reasons}
        return RestructureReport(
            merges=0,
            fissions=1,
            refused=0,
            macro_states=len(self._macro),
            reason_counts=counts,
        )

    def _reroute(
        self, lattice: TransitionLattice, parent: int, sibling: int
    ) -> None:
        """Move the parent's weaker half of recorded continuations to ``sibling``."""
        ranked = lattice.successors(parent, limit=lattice.max_transitions)
        if len(ranked) < 2:
            return
        keep = (len(ranked) + 1) // 2
        for target, _probability in ranked[keep:]:
            edge = lattice.remove_edge(parent, target)
            if edge is None:  # pragma: no cover - successors() only lists live edges
                continue
            lattice.reinsert(
                LatticeTransition(
                    source=sibling,
                    target=target,
                    count=edge.count,
                    epoch_counts=dict(edge.epoch_counts),
                    delta_phi_sum=edge.delta_phi_sum,
                    uncertainty_mean=edge.uncertainty_mean,
                    # A re-routed edge is no longer the edge that was measured, so
                    # it drops back to NEURAL: a compile candidate must not inherit
                    # a validity claim from an edge that has since been split.
                    compile_status=CompileStatus.NEURAL,
                )
            )
