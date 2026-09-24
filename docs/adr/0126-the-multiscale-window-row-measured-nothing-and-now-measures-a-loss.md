# ADR-0126 — The `multiscale_window` row measured nothing, and now measures a loss

- **Status:** Accepted
- **Date:** 2026-09-25
- **Stage:** 2
- **Deciders:** Stage 2 defect-repair wave, integrator
- **Supersedes / superseded by:** corrects `docs/stage-2-findings.md` §7 and
  **amends ADR-0123 decision 3**. Retracts registry entry
  `PS-S2-20260924-H8-multiscale-window-0013` via
  `PS-S2-20260925-H8-multiscale-window-retraction-0023`.

## Context

The `multiscale_window` ablation row was recorded as `NOT_YET_JUSTIFIED` with
`with 0.4928 vs without 0.4926 (delta 0.0002)`, attributed to `DTL-F03` /
`WindowStore`, and used to conclude that "the runtime multiscale state kept by
ADR-0119 earns nothing measurable" (ADR-0123 decision 3).

The measuring function's own docstring said it did not measure that component:

> It does not measure `WindowStore` itself: the store holds the taps, and its
> measured memory is reported in `detail`, but the accuracy figures would be the
> same for any component that supplied the same taps.

Confirmed by execution (S2-FC-12): replacing `stage2_report.WindowStore` with a
stub that holds nothing returned **bit-identical** accuracies — only the `detail`
string changed. The store was instantiated over `train[:1]` solely to print a byte
count.

The cause was the grouping. `_family_sequences` grouped relation families by
**session**, while `WindowStore` keys on the causal-signature root
(ADR-0005/ADR-0119). Sessions interleave several lineages, so the (1, 2, 4)
look-back offsets were fed a stream the store never produces.

## Measurement

`_family_sequences` now groups per lineage, reading the family off the window the
store returned. Same offsets, same predictor, same split (ambiguous, count=240,
train seed 3, eval seed 11), measured this session:

| grouping | sequences | mean length | taps (1,2,4) | window=1 | delta |
|---|---|---|---|---|---|
| by session (old) | 240 | 73.3 | 0.4928 | 0.4926 | **+0.0002** |
| by lineage (correct) | 3,576 | 5.0 | **0.5912** | **0.7099** | **−0.1187** |

The verdict moves from `NOT_YET_JUSTIFIED` (a null) to **REJECTED** (a measured
loss). The store's extra taps make next-family top-1 *worse*, and the "null" that
kept the row pending — and that ADR-0123 cites among four `|delta| <= 0.0002`
nulls when rejecting its option B — was an artefact of grouping by session.

A second measurement, because ADR-0123 decision 3 acts on this row. Truncating
every lineage window to its last step and re-scoring the **exported** Φ-oracle
candidate (`DeterministicScorerSpec`, `max_over_window`) on ambiguous count=240
seed=11:

| window | average precision |
|---|---|
| full (`MAX_WINDOW`=64) | **0.5975** |
| window=1 | **0.3243** |

168 of 240 session scores change. The gate's own `phi_oracle_scores` is
incidentally invariant because it takes a running max across steps, so that
consumer would not have shown the loss.

## Decision

1. `measure_window` is a genuine `DTL-F03` ablation: it groups by the lineage the
   store keys on, so its numbers move when the store's grouping moves. The
   docstring no longer disclaims the component the `core_ids` name.
2. The `multiscale_window` verdict is **REJECTED at −0.1187** for next-family
   top-1 under a majority-vote table. It is still not a detection result.
3. **ADR-0123 decision 3 is amended.** "Window=1" is supported for the
   *predictive* use of the taps and is refused for the window as a whole: doing
   it costs the exported Φ-oracle candidate −0.2732 average precision, and that
   candidate is the first crystallisation target. The directive becomes **narrow
   the taps, do not delete the window**: `WindowStore` keeps producing a window,
   and no component may claim value from look-back offsets beyond depth 1 without
   re-measuring per lineage.
4. `docs/stage-2-findings.md` carries the corrected figures; the +0.0002 row is
   retracted in the append-only ledger rather than edited.

## Consequences

- One more OPTIONAL-adjacent component is measured rather than pending, and the
  measurement is a loss. That is a result.
- `DTL-F03` is REQUIRED, so this does not change G2.12's unsupported list; it
  changes what the stage believes about its own state.
- Any future session reading ADR-0123 decision 3 now finds the cost of acting on
  it stated in the same place as the directive.

## Alternatives considered

**Re-label the row "context width under a majority-vote predictor" and mark
DTL-F03 UNMEASURED.** The finding offered this as the cheaper option. Rejected:
the component was measurable, the correct grouping was three lines away, and
marking a component unmeasured when it can be measured is how a stage
accumulates permanent unknowns.
