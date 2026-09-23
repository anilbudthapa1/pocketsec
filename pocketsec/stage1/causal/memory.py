"""D1.8 — multi-resolution causal state and responsibility (spec section 14).

PocketSec needs causality without an unbounded provenance graph — retaining one
is an explicit Stage 1 non-goal, and on a 2 GB host it is also just impossible.

The design is resolution tiers, not truncation:

    L0  exact recent responsible relations
    L1  compact summary of near ancestry
    L2  fingerprint/sketch of older ancestry
    L3  long-horizon causal signature + extrema

Causal signature (spec section 14)::

    P_t = H(P_parent, actor_semantics, relation, object_semantics, state_delta)

Signatures chain, so two processes that arrived at the same state by the same
*route* share a signature even with different pids, paths and names. That is the
property the renamed-tool tests exercise.

Acceptance criterion 6 is that causal compression retains the attack-relevant
spine in multi-branch scenarios. Responsibility scoring is what decides which
branch is the spine: a transition matters in proportion to how much removing it
would change downstream security potential.
"""

from __future__ import annotations

import hashlib
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

from pocketsec.stage1.state.security_state import StateDelta

__all__ = [
    "CausalMemory",
    "CausalNode",
    "CausalResolution",
    "ResponsibilityReport",
    "causal_signature",
]

GENESIS_SIGNATURE = "0" * 16


def causal_signature(
    *,
    parent_signature: str,
    actor_semantics: frozenset[str],
    relation: int,
    object_semantics: frozenset[str],
    state_delta: StateDelta,
) -> str:
    """Compute ``P_t``.

    Deliberately built from *semantics*, not identities: no pid, path, inode or
    command line participates. Rename the binary and the signature is unchanged;
    change what it actually does and the signature diverges.
    """
    material = "|".join(
        [
            parent_signature,
            ",".join(sorted(actor_semantics)),
            str(relation),
            ",".join(sorted(object_semantics)),
            str(state_delta.bitmask()),
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


class CausalResolution:
    """Retention tiers, in descending fidelity."""

    L0_EXACT = 0
    L1_SUMMARY = 1
    L2_FINGERPRINT = 2
    L3_SIGNATURE = 3


@dataclass(frozen=True, slots=True)
class CausalNode:
    """One transition's place in the causal record."""

    signature: str
    parent_signature: str
    sequence: int
    relation: int
    state_delta_mask: int
    #: ΔΦ this transition caused. Stored directly rather than as a pair of
    #: absolute Φ values: responsibility is defined as the *change* a
    #: transition caused, and keeping only the change keeps the node small.
    delta_phi: float
    resolution: int = CausalResolution.L0_EXACT
    actor_identity: str = ""
    evidence_locators: tuple[str, ...] = ()

    def demote(self, resolution: int) -> CausalNode:
        """Drop to a coarser tier, shedding exactly what that tier discards.

        L2 and beyond drop identity and evidence locators — that is the storage
        win. ΔΦ and the state-delta mask survive every tier, because they are
        what makes the spine recoverable later.
        """
        if resolution <= self.resolution:
            return self
        keep_identity = resolution < CausalResolution.L2_FINGERPRINT
        return CausalNode(
            signature=self.signature,
            parent_signature=self.parent_signature,
            sequence=self.sequence,
            relation=self.relation,
            state_delta_mask=self.state_delta_mask,
            delta_phi=self.delta_phi,
            resolution=resolution,
            actor_identity=self.actor_identity if keep_identity else "",
            evidence_locators=self.evidence_locators if keep_identity else (),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "signature": self.signature,
            "parent_signature": self.parent_signature,
            "sequence": self.sequence,
            "relation": self.relation,
            "state_delta_mask": self.state_delta_mask,
            "delta_phi": round(self.delta_phi, 4),
            "resolution": self.resolution,
            "actor_identity": self.actor_identity,
            "evidence_locators": list(self.evidence_locators),
        }


@dataclass(frozen=True, slots=True)
class ResponsibilityReport:
    """Which transitions carry the security weight."""

    spine: tuple[str, ...]
    scores: dict[str, float]
    total_phi_gain: float
    retained_at_l0: int
    compressed: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "spine": list(self.spine),
            "scores": {k: round(v, 4) for k, v in self.scores.items()},
            "total_phi_gain": round(self.total_phi_gain, 4),
            "retained_at_l0": self.retained_at_l0,
            "compressed": self.compressed,
        }


class CausalMemory:
    """Bounded, responsibility-aware causal retention.

    Capacity is a hard node count. When it is reached, the *least responsible*
    nodes are demoted rather than the oldest being dropped: an attack step from
    ten minutes ago outranks a build-system file read from two seconds ago.
    """

    def __init__(self, *, capacity: int = 512, l0_budget: int = 64) -> None:
        if capacity < 1 or l0_budget < 1:
            raise ValueError("capacity and l0_budget must be >= 1")
        self.capacity = capacity
        self.l0_budget = l0_budget
        self._nodes: OrderedDict[str, CausalNode] = OrderedDict()
        self._sequence = 0
        self._dropped = 0

    @property
    def dropped(self) -> int:
        return self._dropped

    def __len__(self) -> int:
        return len(self._nodes)

    @property
    def memory_bytes(self) -> int:
        """Rough measured footprint: signatures, scalars and retained locators."""
        return sum(
            64 + len(node.actor_identity) + sum(len(loc) for loc in node.evidence_locators)
            for node in self._nodes.values()
        )

    def record(
        self,
        *,
        parent_signature: str,
        actor_semantics: frozenset[str],
        relation: int,
        object_semantics: frozenset[str],
        state_delta: StateDelta,
        delta_phi: float,
        actor_identity: str = "",
        evidence_locators: tuple[str, ...] = (),
    ) -> CausalNode:
        """Append one transition and rebalance retention."""
        signature = causal_signature(
            parent_signature=parent_signature,
            actor_semantics=actor_semantics,
            relation=relation,
            object_semantics=object_semantics,
            state_delta=state_delta,
        )
        self._sequence += 1
        node = CausalNode(
            signature=signature,
            parent_signature=parent_signature,
            sequence=self._sequence,
            relation=relation,
            state_delta_mask=state_delta.bitmask(),
            delta_phi=delta_phi,
            actor_identity=actor_identity,
            evidence_locators=evidence_locators,
        )
        self._nodes[signature] = node
        self._nodes.move_to_end(signature)
        self._rebalance()
        return node

    def _rebalance(self) -> None:
        """Demote the least responsible nodes, then drop beyond capacity."""
        if len(self._nodes) > self.l0_budget:
            ranked = sorted(
                self._nodes.values(), key=lambda n: (self.responsibility(n), n.sequence)
            )
            demote_count = len(self._nodes) - self.l0_budget
            for node in ranked[:demote_count]:
                target = (
                    CausalResolution.L1_SUMMARY
                    if self.responsibility(node) > 0.0
                    else CausalResolution.L2_FINGERPRINT
                )
                self._nodes[node.signature] = node.demote(target)

        while len(self._nodes) > self.capacity:
            victim = min(
                self._nodes.values(), key=lambda n: (self.responsibility(n), -n.sequence)
            )
            self._nodes.pop(victim.signature)
            self._dropped += 1

    @staticmethod
    def responsibility(node: CausalNode) -> float:
        """How much this transition moved security potential.

        The spec defines responsibility as the downstream change caused by
        removing or masking a transition. ΔΦ is the direct, measurable
        realisation of that on a bounded window: a transition that raised no
        capability scores zero and is compressed first.
        """
        return max(0.0, node.delta_phi)

    def spine(self, *, min_responsibility: float = 0.01) -> tuple[CausalNode, ...]:
        """The attack-relevant spine: transitions that actually raised Φ."""
        return tuple(
            sorted(
                (n for n in self._nodes.values() if self.responsibility(n) >= min_responsibility),
                key=lambda n: n.sequence,
            )
        )

    def report(self) -> ResponsibilityReport:
        spine = self.spine()
        return ResponsibilityReport(
            spine=tuple(node.signature for node in spine),
            scores={n.signature: self.responsibility(n) for n in self._nodes.values()},
            total_phi_gain=sum(self.responsibility(n) for n in self._nodes.values()),
            retained_at_l0=sum(
                1 for n in self._nodes.values() if n.resolution == CausalResolution.L0_EXACT
            ),
            compressed=sum(
                1 for n in self._nodes.values() if n.resolution != CausalResolution.L0_EXACT
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": len(self._nodes),
            "capacity": self.capacity,
            "dropped": self._dropped,
            "memory_bytes": self.memory_bytes,
            "report": self.report().to_dict(),
        }
