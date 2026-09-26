"""Stage 6 — HELIOS + MNEMOSYNE: quarantined long-horizon learning.

The stage where learning is allowed to change **trusted** state, and therefore the stage
whose deliverable is a boundary rather than a learner: raw telemetry never rewrites
trusted memory; the one write path runs quarantine gateway -> evolution chamber ->
conservation gate -> shadow -> canary -> ``LearningPromotionController``; every change is
reversible to a byte-identical fossil named by its digest; every store is bounded.

**This package's public surface is lazy, and deliberately narrow.** Spec §2.1 permits an
``__init__`` that is empty or a lazy surface (``stage5/__init__.py`` shape), never a
re-export chain: importing ``pocketsec.stage6`` imports nothing else, and each name below
loads its leaf module on first access. Consumers inside the stage import leaf modules
directly, as every other stage does. The names are the Stage 7 handoff of spec §3.3.

Three things are absent on purpose. ``TrustedMind`` is not here: only
``promotion/controller.py`` may name or construct it (boundary rule 4, ADR-0052), and a
package-level alias would be a way round that rule. Nothing from ``labs/`` is here: the
runtime never imports the labs (rule 6). The gate and CLI are not here either: they are
reached through ``pocketsec-stage6``, so their lab rigs cannot become a library.

Every corpus this stage measures on is synthetic and every Stage 5 record it learns from
is ``simulated=True``; nothing it reports is a detection result.
"""

from __future__ import annotations

import importlib
from types import MappingProxyType
from typing import Any

#: Public name -> the leaf module that defines it. Read by ``__getattr__`` only.
_SURFACE = MappingProxyType(
    {
        "ExperienceCapsuleV1": "pocketsec.stage6.capsule.experience_capsule",
        "EXPERIENCE_CAPSULE_V1_ID": "pocketsec.stage6.capsule.experience_capsule",
        "QuarantineGateway": "pocketsec.stage6.capsule.quarantine",
        "QuarantineVerdict": "pocketsec.stage6.capsule.quarantine",
        "QuarantineBucket": "pocketsec.stage6.capsule.quarantine",
        "ProvenanceLedger": "pocketsec.stage6.provenance.ledger",
        "TrustRecord": "pocketsec.stage6.provenance.ledger",
        "EpisodicMemory": "pocketsec.stage6.memory.episodic",
        "SemanticMemory": "pocketsec.stage6.memory.semantic",
        "TrustedKnowledgeState": "pocketsec.stage6.memory.semantic",
        "ProceduralMemory": "pocketsec.stage6.memory.procedural",
        "EpistemicHalfLife": "pocketsec.stage6.memory.half_life",
        "PlasticityField": "pocketsec.stage6.plasticity.field",
        "PlasticityMask": "pocketsec.stage6.plasticity.masks",
        "KnowledgeFossil": "pocketsec.stage6.fossils.store",
        "KnowledgeLineageDAG": "pocketsec.stage6.fossils.lineage",
        "EvolutionChamber": "pocketsec.stage6.chamber.evolution",
        "Consolidation": "pocketsec.stage6.consolidator.mnemosyne",
        "ShadowMind": "pocketsec.stage6.shadow.mind",
        "ConservationVerdict": "pocketsec.stage6.conservation.gate",
        "CanaryReport": "pocketsec.stage6.shadow.canary",
        "LearningPromotionController": "pocketsec.stage6.promotion.controller",
        "LearningRollback": "pocketsec.stage6.promotion.controller",
        "QuantizedCandidate": "pocketsec.stage6.export.quantized_candidates",
        "LearningRecordV1": "pocketsec.stage6.export.learning_record",
        "LEARNING_RECORD_V1_ID": "pocketsec.stage6.export.learning_record",
        "KnowledgePackageV1": "pocketsec.stage6.fleet.package",
        "LEARNING_CONSTITUTION": "pocketsec.stage6.constitution.learning",
        "STAGE6_FUNCTIONS": "pocketsec.stage6.core_ids",
    }
)

__all__ = sorted(_SURFACE)


def __getattr__(name: str) -> Any:
    module = _SURFACE.get(name)
    if module is None:
        raise AttributeError(f"module 'pocketsec.stage6' has no attribute {name!r}")
    return getattr(importlib.import_module(module), name)


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(_SURFACE))
