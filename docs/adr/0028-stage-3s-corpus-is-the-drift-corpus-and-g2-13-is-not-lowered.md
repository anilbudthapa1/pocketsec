# ADR-0028 — Stage 3's corpus is the drift corpus; G2.13 is not lowered

- **Status:** Accepted
- **Date:** 2026-09-25
- **Stage:** 3
- **Deciders:** Stage 3 integrator
- **Supersedes / superseded by:** none

## Context

Stage 2's export gate fails G2.13 with `distinct_epochs 1 < 2`:
`CandidateStability.stable` requires two distinct epochs and the **detection**
corpus has one, so the exporter refuses the Φ-oracle candidate. "Frequency is not
corroboration" is the anti-poisoning invariant (ADR-0007). Weakening it to
unblock Stage 3 would be the exact failure this repository exists to refuse.

A corpus with genuinely distinct epochs already exists:
`pocketsec/stage2/labs/drift_corpus.py` builds three routine phases with two
corroborated epoch transitions and one uncorroborated change that must *not* open
an epoch, and `gate_measures.DRIFT_EPOCH_SIGNALS` supplies the out-of-band
`SystemChangeSignal` for each phase so behaviour alone never opens an epoch.

Measured this session: `build_crystal_corpus(count=60, seed=11)` reports
`distinct_epochs = 3` and `corroborated_transitions = 2`.

## Decision

Stage 3's corpus is `build_drift_corpus` replayed through `Stage1Pipeline` with
`DRIFT_EPOCH_SIGNALS` driving `EpochModel.evaluate`.
`pocketsec/stage3/labs/crystal_corpus.py` is a **thin composition** of existing
parts: it builds no fifth `Scenario` type and defines no second corpus builder.
**`CandidateStability`'s `distinct_epochs >= 2` is not lowered**, and
`THRESHOLDS` in `pocketsec/stage3/theory.py` sets `min_drift_stability >= 2` at
*every* consequence level including `ROUTINE`, so Stage 3 cannot crystallise on
weaker corroboration than Stage 2 needed to propose.

The gate's two labelled draws are disjoint: same named split, fit seed 3 and eval
seed 11 — Stage 1's guillotine seeds, reused rather than chosen, so that no seed
in the Stage 3 gate was selected for the result it produces.

## Options considered

| Option | Security cost | Resource cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|---|
| A: replay the drift corpus with `DRIFT_EPOCH_SIGNALS` | none | one corpus walk (~0.8 s) | low | `distinct_epochs = 3`, `corroborated = 2` | **chosen** |
| B: lower `CandidateStability` to one epoch | **critical** — reopens ADR-0007's frequency-is-not-corroboration hole | none | lowest | would "unblock" G2.13 by deleting the check | the failure this repo exists to refuse |
| C: build a fifth Scenario type for Stage 3 | none | a second corpus builder | high | a corpus property failing here would be an artefact of the new builder | reusing Stage 2's fixtures makes failures comparable |

## Consequences

**Accepted costs.** Stage 3's corpus differs from the `ambiguous` corpus the
frozen Stage 2 frontier was measured on, so G3.1 REFUSES that evidence as
UNMEASURED rather than comparing across corpora. That is a FAIL and it is
correct.

**Bounded state.** `count=60` sessions; the corpus is built per run and not
persisted.

**Reversibility.** `CRYSTAL_CORPUS_VERSION` embeds `DRIFT_VERSION`, so a table or
a snapshot carrying a different version is a different corpus and not comparable.

**Authority.** No change.

## Verification

`tests/test_stage3_runtime.py` corpus tests (session-unique identities, non-zero
median Δφ for both classes, no vocabulary signal); gate criterion G3.1's detail,
which prints both splits side by side.

## Prior art

No novelty claim. `docs/prior-art/ledger.json`, entry H4.
