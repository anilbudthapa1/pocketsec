"""DTL-F10 — the Causal Credit Ledger (architecture spec section 17).

    Credit(e_i) = Δ predicted security outcome when e_i is masked,
                  approximated under a strict compute budget.

Stage 1 already keeps bounded causal memory. What it cannot do is say *which*
of the transitions it kept an analyst actually has to read. This ledger keeps
only the transitions a counterfactual probe showed materially changed the
predicted security future, and reports the one number that decides whether that
was worth doing: ``nodes_inspected`` — how many nodes an analyst must read —
against the naive full-ancestry control, at equal recall of the ground-truth
attack chain. That is the ORTHRUS-style Quality-of-Attribution framing the
architecture document cites, and it is deliberately not a detection metric.

What this module refuses to do:

* **It refuses to credit an unmeasured probe.** A probe the twin's budget turned
  away carries :data:`~pocketsec.stage2.counterfactual.twin.PROBE_REFUSED_EVIDENCE`
  and gets no credit, ever. Its divergence is a real 0.0 for a comparison that
  never happened, and treating that as "no responsibility" would let a starved
  budget quietly exonerate an attack step.
* **It refuses to report a quality number it did not measure.**
  ``chain_recall`` and ``conciseness_gain`` are ``None`` without ground truth —
  never 0.0, which would read as a measured failure.
* **It refuses to grow.** 256 entries, lowest credit evicted first, every
  eviction counted.

Stdlib only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.causal.memory import CausalMemory, CausalNode
from pocketsec.stage2.counterfactual.twin import (
    PROBE_REFUSED_EVIDENCE,
    CounterfactualProbe,
)

__all__ = [
    "MATERIAL_DELTA_PHI_SHIFT",
    "MATERIAL_DIVERGENCE",
    "MAX_EVIDENCE_PER_ENTRY",
    "MAX_LEDGER_ENTRIES",
    "AttributionReport",
    "CausalCreditLedger",
    "CreditEntry",
    "chain_recall",
    "naive_ancestry",
    "top_k_by_delta_phi",
]

#: Hard entry cap. The ledger is endpoint state on a 2 GB host.
MAX_LEDGER_ENTRIES: int = 256
#: Evidence locators kept per entry, so a long lineage cannot inflate one entry.
MAX_EVIDENCE_PER_ENTRY: int = 8

#: "Materially changed the predicted security state" (architecture spec §17),
#: made numeric. Below both thresholds the probe found nothing and the
#: transition is not worth an analyst's attention — the ledger returns None
#: rather than recording a near-zero row that dilutes the spine it exists to
#: concentrate.
MATERIAL_DIVERGENCE: float = 0.01
MATERIAL_DELTA_PHI_SHIFT: float = 0.01


@dataclass(frozen=True, slots=True)
class CreditEntry:
    """One transition the counterfactual twin found to matter."""

    signature: str
    parent_signature: str
    sequence: int
    #: Divergence between predicted futures when this transition was masked,
    #: under the probe budget. Not a probability and not a threat score.
    credit: float
    delta_phi: float
    probes_spent: int
    evidence: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "signature": self.signature,
            "parent_signature": self.parent_signature,
            "sequence": self.sequence,
            "credit": round(self.credit, 6),
            "delta_phi": round(self.delta_phi, 4),
            "probes_spent": self.probes_spent,
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True, slots=True)
class AttributionReport:
    """What an analyst would have to read, ours versus naive."""

    spine: tuple[CreditEntry, ...]
    #: The metric that matters. Smaller is better *only* at equal recall.
    nodes_inspected: int
    #: The control: ``CausalMemory.spine(min_responsibility=0.0)``.
    naive_ancestry_nodes: int
    #: ``None`` when no ground truth was supplied. Never 0.0 in that case.
    chain_recall: float | None
    #: naive / ours, and only when our recall is at least the naive path's.
    conciseness_gain: float | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "spine": [entry.to_dict() for entry in self.spine],
            "nodes_inspected": self.nodes_inspected,
            "naive_ancestry_nodes": self.naive_ancestry_nodes,
            "chain_recall": (
                round(self.chain_recall, 4) if self.chain_recall is not None else None
            ),
            "conciseness_gain": (
                round(self.conciseness_gain, 4)
                if self.conciseness_gain is not None
                else None
            ),
        }


def naive_ancestry(memory: CausalMemory) -> tuple[CausalNode, ...]:
    """THE CONTROL: every node Stage 1 retained, in sequence order.

    ``min_responsibility=0.0`` admits everything, because responsibility is
    ``max(0, ΔΦ)`` and therefore never negative. This is what an analyst reads
    if nobody narrows the ancestry for them.
    """
    return memory.spine(min_responsibility=0.0)


def top_k_by_delta_phi(memory: CausalMemory, *, k: int) -> tuple[CausalNode, ...]:
    """THE SECOND CONTROL: the k highest-ΔΦ nodes, no counterfactual at all.

    A strong control precisely because Stage 1's ΔΦ is free. If the ledger
    cannot beat this, the counterfactual twin is buying latency and nothing else
    (architecture spec §36, falsification criterion 4).
    """
    if k < 0:
        raise ContractError("k must be >= 0")
    ranked = sorted(
        naive_ancestry(memory), key=lambda node: (-node.delta_phi, node.sequence)
    )
    return tuple(sorted(ranked[:k], key=lambda node: node.sequence))


def chain_recall(
    signatures: frozenset[str], *, ground_truth: frozenset[str] | None
) -> float | None:
    """Recall of ground-truth chain nodes, or ``None`` when unmeasurable.

    ``None`` is the whole point: an attribution mechanism with no labelled chain
    to compare against has not been shown to be good or bad, and 0.0 would claim
    it had been shown to be bad.
    """
    if not ground_truth:
        return None
    return len(signatures & ground_truth) / len(ground_truth)


class CausalCreditLedger:
    """Bounded credit assignment over counterfactual probes."""

    __slots__ = ("capacity", "probe_budget", "_entries", "_evictions", "_probes", "_refused")

    def __init__(
        self, *, capacity: int = MAX_LEDGER_ENTRIES, probe_budget: int = 64
    ) -> None:
        if capacity < 1:
            raise ContractError("ledger capacity must be >= 1")
        if probe_budget < 1:
            raise ContractError("probe budget must be >= 1")
        self.capacity = capacity
        self.probe_budget = probe_budget
        self._entries: dict[str, CreditEntry] = {}
        self._evictions = 0
        self._probes = 0
        self._refused = 0

    # --- credit ---------------------------------------------------------

    def assign_causal_credit(
        self, probe: CounterfactualProbe, node: CausalNode
    ) -> CreditEntry | None:
        """DTL-F10. Returns ``None`` when the probe changed nothing material.

        ``node`` is authoritative for identity: the probe names its target by
        window position, which is provenance, not an identity the ledger trusts.
        """
        if PROBE_REFUSED_EVIDENCE in probe.evidence:
            # Unmeasured is not measured. A refused probe proves nothing about
            # this transition in either direction.
            self._refused += 1
            return None
        if self._probes >= self.probe_budget:
            self._refused += 1
            return None
        self._probes += 1
        if not self._material(probe):
            return None
        entry = self._merge(probe, node)
        self._entries[entry.signature] = entry
        self._evict()
        return entry

    @staticmethod
    def _material(probe: CounterfactualProbe) -> bool:
        return (
            probe.divergence >= MATERIAL_DIVERGENCE
            or abs(probe.delta_phi_shift) >= MATERIAL_DELTA_PHI_SHIFT
        )

    def _merge(self, probe: CounterfactualProbe, node: CausalNode) -> CreditEntry:
        """Fold a new probe into any existing entry for the same signature.

        Credit takes the maximum rather than the sum: it is a divergence, not a
        quantity that accumulates, and summing would reward re-probing.
        """
        existing = self._entries.get(node.signature)
        evidence = _bounded_evidence(node, probe, existing)
        return CreditEntry(
            signature=node.signature,
            parent_signature=node.parent_signature,
            sequence=node.sequence,
            credit=max(probe.divergence, existing.credit if existing else 0.0),
            delta_phi=node.delta_phi,
            probes_spent=(existing.probes_spent if existing else 0) + 1,
            evidence=evidence,
        )

    def _evict(self) -> None:
        """Drop the least-credited entries. Oldest breaks a credit tie."""
        while len(self._entries) > self.capacity:
            victim = min(
                self._entries.values(), key=lambda e: (e.credit, e.sequence)
            )
            self._entries.pop(victim.signature)
            self._evictions += 1

    # --- reporting ------------------------------------------------------

    def report(
        self, memory: CausalMemory, *, ground_truth: frozenset[str] | None = None
    ) -> AttributionReport:
        """The spine, the naive control, and the two quality numbers or ``None``."""
        spine = tuple(sorted(self._entries.values(), key=lambda e: e.sequence))
        naive = naive_ancestry(memory)
        ours = chain_recall(
            frozenset(entry.signature for entry in spine), ground_truth=ground_truth
        )
        theirs = chain_recall(
            frozenset(node.signature for node in naive), ground_truth=ground_truth
        )
        return AttributionReport(
            spine=spine,
            nodes_inspected=len(spine),
            naive_ancestry_nodes=len(naive),
            chain_recall=ours,
            conciseness_gain=_conciseness_gain(
                ours=ours, theirs=theirs, nodes=len(spine), naive_nodes=len(naive)
            ),
        )

    def entries(self) -> tuple[CreditEntry, ...]:
        return tuple(sorted(self._entries.values(), key=lambda e: e.sequence))

    def evictions(self) -> int:
        return self._evictions

    def probes_spent(self) -> int:
        return self._probes

    def probes_refused(self) -> int:
        """Probes the ledger declined to credit: refused by the twin, or over budget."""
        return self._refused

    def memory_bytes(self) -> int:
        """Measured footprint: signatures, scalars and retained locators."""
        return sum(
            64
            + len(entry.signature)
            + len(entry.parent_signature)
            + sum(len(locator) for locator in entry.evidence)
            for entry in self._entries.values()
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "entries": len(self._entries),
            "capacity": self.capacity,
            "probe_budget": self.probe_budget,
            "probes_spent": self._probes,
            "probes_refused": self._refused,
            "evictions": self._evictions,
            "memory_bytes": self.memory_bytes(),
        }


def _bounded_evidence(
    node: CausalNode, probe: CounterfactualProbe, existing: CreditEntry | None
) -> tuple[str, ...]:
    """Union of node, probe and prior locators, order-stable and capped."""
    seen: dict[str, None] = {}
    for locator in (
        *(existing.evidence if existing else ()),
        *node.evidence_locators,
        *probe.evidence,
    ):
        if locator and locator not in seen:
            seen[locator] = None
        if len(seen) >= MAX_EVIDENCE_PER_ENTRY:
            break
    return tuple(seen)


def _conciseness_gain(
    *, ours: float | None, theirs: float | None, nodes: int, naive_nodes: int
) -> float | None:
    """naive/ours, but only when the comparison is honest.

    Requires ground truth on both sides, a non-empty spine, and recall at least
    as good as the naive path's. A conciseness figure quoted at lower recall is
    just a smaller number, which is why it is reported as ``None`` instead.
    """
    if ours is None or theirs is None or nodes <= 0:
        return None
    if ours < theirs:
        return None
    return naive_nodes / nodes
