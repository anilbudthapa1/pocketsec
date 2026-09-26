"""Stage 9 — ONTOGENESIS: search for the minimum sufficient security computation.

A research search, never a deployed component. A *typed computational genome* is a bounded
DAG program over Stage 2's ``EncodedTransition`` fields: every well-typed genome terminates
in a static number of work units and allocates bounded bytes, and an ill-typed one cannot be
constructed. The language provably expresses the zero-parameter Φ-oracle; an adversarially
tested, cost-aware search over it is compared at equal work-unit budget with random search
and exhaustive enumeration, and on held-out data with the Φ-oracle and two hand-written
per-lineage rules (H1, H2). Its output is a ``ProofCarryingSuccessorV1`` *candidate* whose
only exit is Stage 6's quarantine gateway (ADR-0081). Nothing here reaches Stage 5.

**This package's public surface is lazy, and deliberately narrow** (the ``stage6``/``stage7``
``__init__`` shape; spec §2.1 asks for an ``__init__`` that imports nothing): importing
``pocketsec.stage9`` imports nothing else, and each name below loads its leaf module on first
access. Consumers inside the stage import leaf modules directly. The names are spec §3.3's
nineteen Stage 10 handoff types plus the entry points that build and run them; none of them
carries authority.

Three things are absent on purpose. ``Stage6Exit`` is not here: ``successor/stage6_exit.py``
is the one door and a package alias would be a second spelling of it. Nothing from ``labs/``
is here beyond what §3.3 names. The gate and the CLI are reached through
``pocketsec-stage9``, so their lab rigs cannot become a library. Every corpus is synthetic.
"""

from __future__ import annotations

import importlib
from types import MappingProxyType
from typing import Any

_S9 = "pocketsec.stage9."

#: Public name -> the leaf module that defines it. Read by ``__getattr__`` only.
_SURFACE = MappingProxyType(
    {
        name: _S9 + module
        for module, names in (
            (
                "spec.mssc",
                (
                    "MSSCConstraints",
                    "ObjectiveVector",
                    "DetectorComparison",
                    "MechanismVerdict",
                    "check_constraints",
                    "pareto_front",
                    "beats",
                ),
            ),
            (
                "genome.computational",
                ("ComputationalGenomeV1", "COMPUTATIONAL_GENOME_V1_ID", "build_genome"),
            ),
            (
                "genome.expressibility",
                ("phi_oracle_genome", "hand_designed_genomes", "check_expressibility"),
            ),
            ("chemistry.typed_ir", ("TypedIR", "IRProgram", "IRNode", "RegisterSpec", "IRError")),
            ("chemistry.phenotype", ("Phenotype", "SessionAggregation")),
            ("foundry.primitives", ("Primitive", "SEED_ALPHABET")),
            ("foundry.promotion", ("PromotionVerdict", "PromotionDecision")),
            ("laplace.state_discovery", ("DiscoveredState",)),
            ("laplace.law_discovery", ("DiscoveredLaw",)),
            ("renormalization.laboratory", ("RenormalizationResult",)),
            ("symmetry.suite", ("SymmetryTest",)),
            ("symmetry.conservation", ("ConservationTest",)),
            ("geometry.phase", ("PhaseObservation",)),
            ("compression.msdl", ("MSDLScore",)),
            ("chronos.forgetting_law", ("ForgettingLaw",)),
            ("daedalus.synthesizer", ("SynthesizedSystem", "synthesize")),
            ("genesis.speciation", ("Speciation",)),
            ("gaia.qd_ecology", ("QualityDiversityArchive",)),
            ("argus.adversary", ("ArgusAttack", "ArgusFinding")),
            ("runtime.homeostatic", ("HomeostaticController", "Regime")),
            (
                "successor.proof_carrying",
                ("ProofCarryingSuccessorV1", "PROOF_CARRYING_SUCCESSOR_V1_ID", "CandidateRegistry"),
            ),
            ("harness.hardware_in_loop", ("HardwareMeasurement",)),
            ("ontogenesis.search", ("SearchConfig", "SearchRun", "SearchStrategy", "run_search")),
            ("ontogenesis.fitness", ("EvaluationSuite", "FitnessRecord", "evaluate")),
            ("core_ids", ("STAGE9_FUNCTIONS",)),
        )
        for name in names
    }
)

__all__ = sorted(_SURFACE)


def __getattr__(name: str) -> Any:
    module = _SURFACE.get(name)
    if module is None:
        raise AttributeError(f"module 'pocketsec.stage9' has no attribute {name!r}")
    return getattr(importlib.import_module(module), name)


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(_SURFACE))
