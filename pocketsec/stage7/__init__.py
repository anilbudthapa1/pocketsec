"""Stage 7 — ORPHEUS + HIVELOCK: zero-trust collective security intelligence.

The stage where foreign knowledge arrives, and therefore the stage whose deliverable is a
boundary rather than a sharing protocol: foreign bytes enter only through
``HivelockIngress.receive``; foreign knowledge leaves Stage 7 only through
``Stage6Bridge.hand_over``, as ``ExperienceCapsuleV1`` values passed to Stage 6's
``QuarantineGateway.admit`` and to nothing else; no collective outcome, however unanimous,
changes a local decision without local evidence; every store is bounded; nothing
host-identifying leaves the host.

**This package's public surface is lazy, and deliberately narrow** (spec §2.1 permits an
``__init__`` that is empty or a lazy surface, ``stage6/__init__.py`` shape, never a re-export
chain): importing ``pocketsec.stage7`` imports nothing else, and each name below loads its
leaf module on first access. Consumers inside the stage import leaf modules directly. The
names are the Stage 8 / Stage 12 handoff of spec §3.3; none of them carries authority.

Nothing from ``labs/`` is here (the runtime never imports the labs, boundary rule 10), and
neither is the gate or the CLI: they are reached through ``pocketsec-stage7``, so their lab
rigs cannot become a library. The fleet is simulated in-process and every corpus is
synthetic; nothing this stage reports is a detection result.
"""

from __future__ import annotations

import importlib
from types import MappingProxyType
from typing import Any

_S7 = "pocketsec.stage7."

#: Public name -> the leaf module that defines it. Read by ``__getattr__`` only.
_SURFACE = MappingProxyType({
    name: _S7 + module
    for module, names in (
        ("capsule.knowledge_capsule", ("KnowledgeCapsuleV1", "KNOWLEDGE_CAPSULE_V1_ID",
                                       "KnowledgeType")),
        ("identity.peer", ("PeerIdentity", "PeerTable")),
        ("privacy.ledger", ("PrivacyLedger",)),
        ("relevance.epistemic_distance", ("EpistemicDistance", "LocalContext")),
        ("relevance.gravity", ("KnowledgeGravity",)),
        ("hivelock.ingress", ("HivelockIngress", "IngressVerdict", "IngressOutcome",
                              "PooledCapsule")),
        ("hivelock.stage6_bridge", ("Stage6Bridge", "BridgeReceipt")),
        ("graph.dependence", ("DependenceGraph",)),
        ("graph.sybil", ("SybilReport",)),
        ("echo.inference", ("EchoEngine", "EchoInference", "EchoDecision", "EchoStatus")),
        ("antibody.forge", ("KnowledgeAntibody", "LocalValidation")),
        ("reconstruct.partial_world", ("PartialWorld",)),
        ("campaign.hypergraph", ("CampaignHypergraph",)),
        ("novelty.collective", ("CollectiveNovelty",)),
        ("falsifier.consensus", ("ConsensusFalsification",)),
        ("lineage.cross_host", ("Revocation", "CrossHostLineageDAG")),
        ("governor.communication", ("CommunicationBudget", "ExchangeMode")),
        ("orpheus.fabric", ("OrpheusFabric",)),
        ("constitution.collective", ("COLLECTIVE_CONSTITUTION", "COLLECTIVE_EXCHANGE_ENABLED")),
        ("core_ids", ("STAGE7_FUNCTIONS",)),
    )
    for name in names
})

__all__ = sorted(_SURFACE)


def __getattr__(name: str) -> Any:
    module = _SURFACE.get(name)
    if module is None:
        raise AttributeError(f"module 'pocketsec.stage7' has no attribute {name!r}")
    return getattr(importlib.import_module(module), name)


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(_SURFACE))
