"""Stage 8 — PROMETHEUS + ORACLE + FORGE: bounded defensive discovery and falsification.

A research stage, never a deployed component. PROMETHEUS proposes typed mechanisms from TRAIN
residuals only; every hypothesis is an immutable, content-addressed genome whose refutation
rule is preregistered in an append-only ledger before any held-out split is read; each held-out
split is evaluated once, as one Bonferroni family. FORGE compiles a survivor only into a
representation that can express it, and the only exit is ``Stage6Adapter.hand_over`` →
Stage 6's ``QuarantineGateway.admit``, as evidence capsules. No Stage 8 module reaches Stage 5
(ADR-0071, ADR-0076).

**This package's public surface is exactly the Stage 9 interface of spec §3.3, and nothing
else**: ``forge/package.py`` and the typed mechanism it carries. It is re-exported eagerly,
not through a lazy ``importlib`` table, because boundary rule 13 confines string-symbol
resolution to three named files and a fourth would be a second place names can be spelled.
Both leaf modules are foundation modules every other Stage 8 module already imports, so the
eager import costs nothing a Stage 8 consumer was not already paying. Consumers inside the
stage import leaf modules directly, and the subsystem ``__init__`` files stay empty. None of
these names carries authority: a ``DiscoveryPackageV1`` reaches an endpoint only as evidence
capsules through ``adapters/stage6.py``.

Nothing from ``labs/`` is here (the runtime never imports the labs, boundary rule 10), and
neither is the gate or the CLI: they are reached through ``pocketsec-stage8``, so their lab
rigs cannot become a library. Every corpus is synthetic; nothing this stage reports is a
detection result.
"""

from __future__ import annotations

from pocketsec.stage8.forge.package import (
    DISCOVERY_PACKAGE_V1_ID,
    DISCOVERY_PACKAGE_V1_VERSION,
    DiscoveryPackageV1,
    FailureCondition,
    FalsificationRecord,
    IdentifiabilityClass,
    NoveltyClass,
    RepresentationKind,
    RepresentationMeasurement,
    ReproducibilityRecord,
    ReproducibilityStatus,
    ResourceProfile,
    RobustnessProfile,
    TournamentResult,
    verify_package,
)
from pocketsec.stage8.genome.grammar import Mechanism, MechanismRelation, Modifier, StepPredicate

__all__ = [
    "DISCOVERY_PACKAGE_V1_ID",
    "DISCOVERY_PACKAGE_V1_VERSION",
    "DiscoveryPackageV1",
    "FailureCondition",
    "FalsificationRecord",
    "IdentifiabilityClass",
    "Mechanism",
    "MechanismRelation",
    "Modifier",
    "NoveltyClass",
    "RepresentationKind",
    "RepresentationMeasurement",
    "ReproducibilityRecord",
    "ReproducibilityStatus",
    "ResourceProfile",
    "RobustnessProfile",
    "StepPredicate",
    "TournamentResult",
    "verify_package",
]
