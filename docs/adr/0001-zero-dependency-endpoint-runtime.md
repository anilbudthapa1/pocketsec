# ADR-0001 — Zero third-party dependencies in the endpoint runtime

- **Status:** Accepted
- **Date:** 2026-09-24
- **Stage:** 0
- **Deciders:** Stage 0 implementation session

## Context

PocketSec targets hosts with ~2 GB total RAM, and the Edge profile budgets the
whole agent at ≤ 100 MB RSS. Every imported package costs resident memory,
import time and supply-chain surface on that budget. Separately, the
reproducibility policy requires that a result be re-derivable from a commit plus
a seed; a floating dependency set makes that weaker.

The measured Stage 0 smoke run sits at ~25 MB peak RSS with the stdlib alone —
a quarter of the Edge budget before any intelligence exists.

## Decision

The endpoint runtime (`pocketsec/`) has **zero** third-party runtime
dependencies. `project.dependencies` is empty and stays empty.

Development tooling (pytest, ruff, mypy) lives in the `dev` extra and never
imports into runtime code. Offline research and training components may take
heavier dependencies, but only outside the deployed agent path.

## Options considered

| Option | Resource cost | Complexity | Why not chosen |
|---|---|---|---|
| stdlib only | lowest; ~25 MB measured | hand-written metrics | **chosen** |
| pydantic for contracts | +~15 MB import | lower validation code | contracts are ~10 fields; not worth a quarter of the remaining budget |
| numpy/scikit-learn for metrics | +~90 MB import | lowest metric code | would consume the entire Edge budget for PR-AUC over ≤ 4096 items |

## Consequences

**Accepted costs.** PR-AUC, percentiles and confusion counting are hand-written
(`benchmark/security_metrics.py`), so they need real tests — they have them.
Validation is explicit `__post_init__` code rather than declarative.

**Bounded state.** Helps directly: import-time resident memory is the floor the
2 GB target is measured against.

**Reversibility.** Adding a dependency later is a one-line change plus a new
ADR. Removing one after Stage 5 would not be.

**Authority.** No effect.

## Verification

`tests/test_no_runtime_dependencies.py` walks every runtime import and asserts
each resolves to the stdlib or to `pocketsec` itself.

## Prior art

No novelty claimed.
