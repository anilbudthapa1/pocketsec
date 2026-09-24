# ADR-0124 — The P0 transition cache serves a different answer 98.7% of the time

- **Status:** Accepted
- **Date:** 2026-09-25
- **Stage:** 2
- **Deciders:** Stage 2 defect-repair wave, integrator
- **Supersedes / superseded by:** none. Qualifies the G2.10 figure quoted in
  `docs/stage-2-findings.md` and ADR-0114.

## Context

G2.10's headline was "4082 of 4096 events resolved from the transition cache
(0.9966)". Nothing in this repository had ever compared the answer a cache hit
served against the answer the deep path would have computed for the same event.
The finding that prompted this (S2-06) put it plainly: the figure measured **key
repetition**, not cheap-path correctness.

The mechanism is visible in the key and the payload:

- The P0 key is `(atom_id, epoch_id, state_delta_mask)` and carries **no
  lineage** (`cache/transition_cache.py::transition_cache_key`).
- The stored payload is `predicted_delta=state.delta_from(SecurityStateV1())` and
  `predicted_phi=phi(state).total` — the **current lineage state at first
  insertion**, not a prediction (`gate_measures.py::_cache_step`).

So every hit after the first on a given key serves the *first inserting
lineage's* state snapshot to a different lineage, and `runtime_pass` counted it
as `cache_resolved`, skipped the cone and the uncertainty estimate, and reported
it as sleep.

## Measurement

`runtime_pass(honour_cache=False)` already runs the deep path on every event, so
comparing the answer the cache *would* have served against the one the deep path
computes is free there. `RuntimePass.cache_agreement` is that comparison:
agreement means the cached `predicted_phi` matches `phi(state).total` to 1e-9,
the cached `predicted_delta.raised` matches `state.delta_from(SecurityStateV1())`,
and the epoch matches.

Measured this session, `python -m pocketsec.stage2.cli gate`
(ambiguous, count=60, train seed 3, eval seed 11, 4096 events):

| figure | value |
|---|---|
| events resolved from the cache | 4082 / 4096 = 0.9966 |
| would-be hits checked against the deep path | 4082 |
| hits serving the deep path's answer | 52 |
| hits serving a **different** answer | 4030 |
| **answer agreement** | **0.0127** |

The wall-clock difference is real (135.90 µs/event with the cache honoured
against 181.67 µs/event with every hit ignored) and the ledger proves the
inference genuinely did not run for 0.9966 of events — `assert_no_phantom_savings`
passes on both ledgers. What is *not* real is the interpretation: the compute was
avoided, but the answer changed.

## Decision

**A skipped inference whose cached answer differs from the inference it replaced
is not a saving, and G2.10 fails on it.**

1. `RuntimePass` carries `cache_agreements` / `cache_disagreements` /
   `cache_agreement`, populated only by the control pass, where a comparison is
   possible. `cache_agreement` is `None` — never 1.0 — when nothing was checked.
2. G2.10 requires `cache_agreement >= CACHE_AGREEMENT_FLOOR` (0.95) and reports
   the measured figure beside the skipped fraction. It currently fails on 0.0127.
3. The 0.9966 skipped fraction is not withdrawn and is not restated. It is
   correct about compute and is now quoted with the correctness number next to
   it, because quoting it alone is ADR-0010's notional accounting one layer down:
   the work was labelled avoided, and it *was* avoided, but the thing it was
   avoided in favour of was a different answer.

## Consequences

- G2.10 moves from PASS to **FAIL**. That is this wave's result, not a
  regression: the criterion was passing on a number nothing had checked.
- The fix is a cache design question and is **not** attempted here. Adding the
  lineage to the key would collapse the hit rate towards the per-lineage reuse
  rate; storing a genuine prediction rather than a state snapshot is a different
  component. Either is a measurement, not an edit, and neither belongs in a
  defect-repair wave.
- Any future claim that Stage 2 "sleeps" must quote `cache_agreement` with the
  skipped fraction. A skipped fraction alone is now, by construction, an
  incomplete claim.

## Alternatives considered

**Report the agreement and let G2.10 pass anyway.** Rejected. The criterion is
"quantify how much traffic avoids expensive inference, unfakeably". A number
that is unfakeable and means something else is exactly the failure ADR-0114 was
written about.

**Lower the floor to the measured value.** Rejected outright — that is restating
the criterion so it passes, which the gate's own module docstring calls the worst
outcome available here.
