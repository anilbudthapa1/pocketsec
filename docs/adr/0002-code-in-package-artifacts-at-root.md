# ADR-0002 — Code lives in the package; top-level directories are artifact stores

- **Status:** Accepted
- **Date:** 2026-09-24
- **Stage:** 0
- **Deciders:** Stage 0 implementation session

## Context

The Stage 0 spec (section 16) recommends a repository skeleton containing both
obviously-code directories (`pocketsec/`) and obviously-data ones (`results/`,
`datasets/`, `models/`). Several are ambiguous: is `benchmarks/` harness code or
benchmark case definitions? Is `baselines/` baseline implementations or their
recorded outputs?

Left ambiguous, the same concern ends up implemented in two places — exactly the
"parallel duplicate subsystems" the execution contract forbids.

## Decision

- **All Python code** lives under `pocketsec/`, namespaced by stage
  (`pocketsec/stage0/...`).
- **Top-level directories are artifact and definition stores**, not import
  roots: `contracts/` (language-neutral JSON Schema), `benchmarks/` (case and
  fixture definitions), `experiments/` (the append-only registry),
  `results/`, `datasets/`, `models/`, `baselines/`, `runtime/`, `training/`.
- `runtime/` and `training/` are reserved for Stage 1+ and carry a README
  stating so, rather than sitting empty and ambiguous.

The spec skeleton is honoured — every recommended directory exists — while each
one has exactly one meaning.

## Consequences

**Accepted costs.** The layout is not literally the spec's ASCII tree; it is a
disambiguated superset. A reader expecting `benchmarks/harness.py` finds
`pocketsec/stage0/benchmark/harness.py`.

**Bounded state.** Artifact directories are the only places that grow, which
makes retention policy enforceable in one obvious set of paths.

**Reversibility.** Pure file movement.

**Authority.** No effect.

## Verification

`tests/test_repository_structure.py` asserts every spec-mandated directory
exists and that no importable Python module lives outside `pocketsec/`.

## Prior art

No novelty claimed. Standard src-layout practice.
