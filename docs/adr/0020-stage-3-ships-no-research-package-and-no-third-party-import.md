# ADR-0020 — Stage 3 ships no `research/` package and no third-party import

- **Status:** Accepted
- **Date:** 2026-09-25
- **Stage:** 3
- **Deciders:** Stage 3 integrator
- **Supersedes / superseded by:** none

## Context

`tests/test_repository_structure.py:73` hard-codes `RESEARCH_PREFIX =
"pocketsec/stage2/research/"` and repeats the literal at `:86`. Under those two
lines a `pocketsec/stage3/research/` directory is classified as **runtime**, so a
numpy import inside it fails `test_runtime_has_no_third_party_imports`. Widening
the literal into a `RESEARCH_PREFIXES` tuple is pre-assigned to ADR-0011 — but
that is an edit to the one test file this wave is forbidden to touch while a
second wave may be editing it.

Stage 3 was measured not to need numpy at all. The four mandated controls are a
lookup table, a depth-limited tree, the Φ-oracle and an LRU over a frozen
snapshot; all are stdlib. Oracle A is *data*, a frozen `TeacherSnapshotV1`
produced offline, so the runtime never holds a model object.

Measured: `python -c "import numpy"` fails on this interpreter, and the whole
Stage 3 gate runs to completion regardless (`pocketsec-stage3 gate`, exit 1 on
criteria, not on imports).

## Decision

Stage 3 creates no `pocketsec/stage3/research/` directory and imports no
third-party module anywhere. `tests/test_stage3_boundary.py` enforces both rules
with an AST walk over every Stage 3 module, written against
`pocketsec.stage<N>.research` rather than Stage 2's literal path so a Stage 3
module cannot reach numpy through a *future* stage's research package either.
ADR-0011 stays unspent; a later wave that genuinely needs gradient descent
inside Stage 3 writes it then.

## Options considered

| Option | Security cost | Resource cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|---|
| A: no research package, stdlib only | none | none | lowest | all five baselines run; gate completes | **chosen** |
| B: add `stage3/research/` + widen the shared test | none | numpy in dev | medium | would require editing `tests/test_repository_structure.py` during a concurrent wave | two waves editing one file corrupts both |
| C: add `stage3/research/` without widening the test | high — the boundary test would pass vacuously | numpy in dev | medium | numpy inside it fails `test_runtime_has_no_third_party_imports` | it fails the suite, correctly |

## Consequences

**Accepted costs.** The TCN-sourced `TeacherSnapshotV1` is **not produced by this
wave**. `TeacherOracle` reports `TEACHER_UNAVAILABLE` for the `"tcn"` source and
the affected divergence term is `None` (UNMEASURED), never zero. Every
dual-oracle result in this stage is against the `"phi-oracle"` source.

**Bounded state.** Unchanged. No new endpoint structure.

**Reversibility.** Spending ADR-0011 later restores the option at no cost to
anything written here.

**Authority.** No change. Nothing here moves a model output closer to execution
authority.

## Verification

`tests/test_stage3_boundary.py::test_stage3_has_no_third_party_imports`,
`::test_stage3_never_imports_research_code`,
`::test_stage3_does_not_hold_a_forbidden_directory[research]`.

## Prior art

No novelty claim. `docs/prior-art/ledger.json`, entry H4.
