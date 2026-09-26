"""Stage 5 — SAFE + AEGIS + SENTINEL: minimum sufficient defensive intervention.

The only stage that touches privilege. Everything upstream produces beliefs; this stage
turns an uncertain ``CBFResolutionV1`` into the smallest typed, authority-bounded,
expiring, evidence-preserving and post-verified change it can justify — and must be able
to choose NO ACTION as a first-class outcome.

**This package's public surface is lazy, and deliberately narrow.** Spec §2.1 permits an
``__init__`` that is empty or a lazy surface, never a re-export chain: importing
``pocketsec.stage5`` imports nothing else, and each name below loads its leaf module on
first access. Consumers inside the stage import leaf modules directly, as every other
stage does.

Two things are absent on purpose. ``TransactionalExecutor`` is not here: only
``executor/``, ``recovery/`` and ``gate.py`` may name it (ADR-0041), and a package-level
alias would be a way round that rule. The gate is not here either: it is reached through
``pocketsec-stage5 gate``, so the executor factories it holds cannot become a library.

The host is simulated. Every in-simulator figure this stage produces is a property of
``host/simulated.py``; rollback reliability against a real Linux host is UNMEASURED
(ADR-0046).
"""

from __future__ import annotations

import importlib
from types import MappingProxyType
from typing import Any

#: Public name -> the leaf module that defines it. Read by ``__getattr__`` only.
_SURFACE = MappingProxyType(
    {
        "CATALOG": "pocketsec.stage5.operators.catalog",
        "DefensiveOperator": "pocketsec.stage5.operators.algebra",
        "OperatorClass": "pocketsec.stage5.operators.algebra",
        "FROZEN_CONSTITUTION": "pocketsec.stage5.constitution.invariants",
        "ResponseConstitution": "pocketsec.stage5.constitution.invariants",
        "DEFAULT_MISSION_INVARIANTS": "pocketsec.stage5.constitution.schema",
        "MissionInvariantSet": "pocketsec.stage5.constitution.schema",
        "GrantSource": "pocketsec.stage5.authority.capability",
        "CapabilityToken": "pocketsec.stage5.authority.tokens",
        "SentinelKernel": "pocketsec.stage5.sentinel.kernel",
        "SentinelVerdict": "pocketsec.stage5.sentinel.kernel",
        "AegisPlanner": "pocketsec.stage5.aegis.planner",
        "PlannerConfig": "pocketsec.stage5.aegis.planner",
        "PlanDecision": "pocketsec.stage5.aegis.planner",
        "ResponsePlan": "pocketsec.stage5.aegis.planner",
        "Outcome": "pocketsec.stage5.executor.transactional",
        "TransactionReceipt": "pocketsec.stage5.executor.transactional",
        "ResponseRecordV1": "pocketsec.stage5.stage6_interface",
        "CORE_IDS": "pocketsec.stage5.core_ids",
    }
)

__all__ = sorted(_SURFACE)


def __getattr__(name: str) -> Any:
    module = _SURFACE.get(name)
    if module is None:
        raise AttributeError(f"module 'pocketsec.stage5' has no attribute {name!r}")
    return getattr(importlib.import_module(module), name)


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(_SURFACE))
