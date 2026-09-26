"""D7.6 — knowledge gravity: is this capsule worth the receiver's local validation work?

Architecture §8 proposes a transfer utility that "determines whether a capsule deserves
expensive local validation. It never bypasses Stage 6." That is the whole job here:
**triage, not belief.** A capsule whose gravity falls below the ingress floor is kept as
metadata only and never replayed locally; one above it is merely *eligible to be
validated*. No gravity value makes anything trusted, and nothing downstream reads gravity
as evidence that a capsule is true.

    validation    = (true_matches + 1) / (true_matches + false_matches + 2)
    independence  = 1 / size of the contributor's dependence cluster (caller supplies it)
    compatibility = 1.0 if every invariant relation is observable here, else 0.0
    recency       = max(0, 1 - (round_index - created_round) / MAX_EXPIRY_HORIZON_ROUNDS)
    value         = validation * independence * compatibility * recency
                    / (1 + distance.total + suspicion)

**``validation`` is SELF-REPORTED by the contributor and forgeable.** An adversary can
claim any match counts it likes; the Laplace-smoothed ratio only keeps an honest "0 of 0"
from being read as certainty. Gravity is therefore a cost-saving filter an adversary can
pass for free, which is exactly why it gates only *which* capsules get local validation
and never *whether* local validation happens.

``compatibility`` is the visibility adjustment: an invariant over a relation this host's
sensors cannot observe can never be locally validated, so spending work on it is waste
and gravity is 0.0. An invariant with no rows (only a REVOCATION has none, and ingress
routes those before relevance) is also 0.0: there is nothing local to validate.

Architecture §8's ``PrivacyCost(K)`` term is **not bound**: the receiver cannot observe
what disclosing a capsule cost its sender, and the sender's ``PrivacyLedger`` enforces
disclosure instead (ADR-0065). :class:`KnowledgeGravity` has no field for it.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from pocketsec.stage0.contracts.common import (
    ContractError,
    require_finite_unit_interval,
    require_non_negative_int,
)
from pocketsec.stage7.capsule.knowledge_capsule import MAX_EXPIRY_HORIZON_ROUNDS, KnowledgeCapsuleV1
from pocketsec.stage7.relevance.epistemic_distance import EpistemicDistance, LocalContext

__all__ = ["KnowledgeGravity", "knowledge_gravity"]


@dataclass(frozen=True, slots=True)
class KnowledgeGravity:
    value: float
    validation: float       # SELF-REPORTED by the contributor; forgeable
    independence: float
    compatibility: float
    recency: float
    distance: float         # the EpistemicDistance total it was divided by
    suspicion: float

    def __post_init__(self) -> None:
        for name in ("value", "validation", "independence", "compatibility", "recency"):
            require_finite_unit_interval(getattr(self, name), name)
        for name in ("distance", "suspicion"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or \
                    not math.isfinite(value) or value < 0.0:
                raise ContractError(f"{name} must be finite and >= 0, got {value!r}")


def knowledge_gravity(capsule: KnowledgeCapsuleV1, *, distance: EpistemicDistance, independence: float,
                      suspicion: float, local: LocalContext, round_index: int) -> KnowledgeGravity:
    """Triage value of ``capsule`` at this receiver; see the module docstring for each term."""
    independence = require_finite_unit_interval(independence, "independence")
    if isinstance(suspicion, bool) or not isinstance(suspicion, (int, float)) or \
            not math.isfinite(suspicion) or suspicion < 0.0:
        raise ContractError(f"suspicion must be finite and >= 0, got {suspicion!r}")
    require_non_negative_int(round_index, "round_index")
    if not isinstance(distance, EpistemicDistance):
        raise ContractError(f"distance must be an EpistemicDistance, got {type(distance).__name__}")
    summary = capsule.validation_summary
    validation = (summary.true_matches + 1) / (summary.true_matches + summary.false_matches + 2)
    rows = capsule.semantic_invariant
    compatibility = 1.0 if rows and all(
        row.relation in local.observable_relations for row in rows) else 0.0
    age = round_index - capsule.created_round
    # A future-dated capsule is not "fresher than new": recency is clamped to [0, 1].
    recency = min(1.0, max(0.0, 1.0 - age / MAX_EXPIRY_HORIZON_ROUNDS))
    value = validation * independence * compatibility * recency / (
        1.0 + distance.total + float(suspicion))
    return KnowledgeGravity(value=value, validation=validation, independence=independence,
                            compatibility=compatibility, recency=recency,
                            distance=distance.total, suspicion=float(suspicion))
