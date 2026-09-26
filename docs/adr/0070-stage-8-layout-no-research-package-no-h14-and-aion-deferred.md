# ADR-0070 — Stage 8 layout amendments; no research package and no numpy; no H14 (BASE, H4, H8); AION deferred to Stage 9

- **Status:** Accepted
- **Date:** 2026-09-26
- **Stage:** 8
- **Deciders:** Stage 8 integrator (decided at spec time, `docs/stage-8-spec.md` §2.1, §2.6; written in the integration session)
- **Supersedes / superseded by:** amends the Stage 8 rows of `docs/architecture/stage-3-12-integration-plan.md` §1.2 (layout) and §5.2 (hypothesis H14). Superseded by: none

> Layout and bookkeeping ADR. It records where Stage 8's code lives and which hypothesis its
> experiments bind to. It makes no detection claim.

## Context

The integration plan (§1.2) names no observation unit, no module for layer 8.21 (the research
governor), no corpus, loop or baseline module, and no home for FORGE's executors. At spec time
`pocketsec/stage8/{experiments,forge,hypotheses,oracle,prometheus}/` existed as empty
directories; ADR-0121 says an empty package directory is a defect.

`tests/test_repository_structure.py:79` still reads `RESEARCH_PREFIX = "pocketsec/stage2/research/"`
(read at spec time and again in the integration session): a numpy import under
`pocketsec/stage8/research/` would fail `test_runtime_has_no_third_party_imports`, and this wave
may not edit that shared file. `HYPOTHESES` holds H0–H8 and ADR-0012 (H9–H18) was never written.

## Decision

1. **Layout** as spec §2.1: added `episode.py`, `prometheus/engine.py`, `forge/representations.py`,
   `governor/budget.py`, `labs/discovery_corpus.py`, `labs/discovery_run.py`, `labs/baselines.py`;
   the integrator adds `__init__.py`, `gate.py`, `gate_boundary.py`, `gate_construction.py`,
   `gate_evidence.py`, `gate_measured.py`, `cli.py`. `experiments/` and `hypotheses/` are deleted
   (boundary rule 15 forbids their return). Subsystem `__init__.py` files re-export nothing.
   `pocketsec/stage8/__init__.py` re-exports exactly the Stage 9 interface of spec §3.3
   (`forge/package.py` and the grammar types), eagerly: a lazy `importlib` table would be a
   fourth dynamic-import site and boundary rule 13 permits three.
2. **No `research/` package and no numpy** anywhere under `pocketsec/stage8/`. The tiny
   MLP/1D-CNN/GRU/transformer representations of architecture §26 are NOT BUILT; every
   representation that is built is stdlib (Stage 1's `LogisticProbe` is already stdlib).
3. **No H14 is minted.** The gate binds to `BASE`
   (`EXPERIMENT_ID = "PS-S8-20260926-BASE-prometheus-gate-0001"`), FORGE rows to `H4`, ablation
   rows to `H8`.
4. **AION (architecture §59–§113) is not built**; it is Stage 9's remit. The catalogue lists
   S8X-081 … S8X-128 NOT_BUILT except S8X-114/119/125.

## Options considered

| Option | Security cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|
| A. The plan's layout verbatim | none | lower | the loop, corpus and governor would have no module | deliverables D8.18/D8.19/D8.20 need homes |
| **B. Spec §2.1 layout (chosen)** | none | +7 modules | boundary rules 1–15 report 0 offenders (`gate_boundary.rule_offenders`, integration session) | — |
| C. A `research/` package with numpy neural students | numpy on a path the shared structure test does not exempt | high | not built | would fail `tests/test_repository_structure.py`, which this wave may not edit |
| D. Mint H14 | none | edits the Stage 0 hypothesis table | not done | belongs to ADR-0012, never written |
| E. Lazy `importlib` root surface (Stage 7 shape) | a fourth string-resolution site | same | failed boundary rule 13 in this session (`tests/test_stage8_boundary.py::test_rule13_…`, 1 offender) | replaced by the eager narrow surface |

## Consequences

**Accepted costs.** No neural representation competes in FORGE; `LOGISTIC`, `PROTOTYPE`,
`STUMP_TREE` are the only learned students. Stage 8 has no hypothesis of its own.

**Bounded state.** No change to endpoint state.

**Reversibility.** Layout only; nothing is persisted.

**Authority.** None.

## Verification

`tests/test_stage8_boundary.py` (rules 1, 2, 13, 15), `tests/test_stage8_gate.py`, G8.12's
`HYPOTHESES == {H0…H8}` item.

## Prior art

No novelty claim.
