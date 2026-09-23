# ADR-0004 — The harness maps verdicts to detection scores verdict-aware

- **Status:** Accepted
- **Date:** 2026-09-24
- **Stage:** 0
- **Deciders:** Stage 0 implementation session

## Context

`ThreatPredictionV1.confidence` is confidence **in the stated verdict**. The
benchmark needs a single scalar per item to rank for PR-AUC and to threshold for
false-positive counting.

The first implementation used `confidence` directly as the detection score. This
is wrong for a `BENIGN` verdict: a confidently-benign window scored ~1.0 and
ranked as a strong detection. Measured effect on the Stage 0 smoke fixture:
PR-AUC 0.131 (below the 0.20 base rate — anti-correlated) and 48.0 false
positives per host-day. After the fix, on identical data and seeds: PR-AUC 1.0,
0.0 false positives per host-day.

This is precisely the failure the fair-comparison rules exist to catch. It would
have made every future mechanism look good against a silently-broken baseline.

## Decision

`_detection_score` maps verdict-aware:

| Verdict | Detection score |
|---|---|
| `MALICIOUS`, `SUSPICIOUS` | `confidence` |
| `BENIGN` | `1 - confidence` |
| `UNKNOWN`, `UNIDENTIFIABLE`, `INSUFFICIENT_EVIDENCE` | `0.0` |

Non-committal verdicts score zero regardless of novelty: novelty is not
maliciousness, so a high novelty score must not leak into the detection score
and manufacture recall the model never claimed.

Two related corrections landed with it:

- `recall_at_max_fpr` now includes a "detect nothing" threshold, so a detector
  that cannot fire once inside the budget reports `0.0` rather than `None`.
  `None` must mean *not computable*, never *scored zero*.
- Unseen-technique recall applies the operating point the FP budget selected on
  the full distribution, instead of silently re-deriving a different one from an
  all-positive subset.

## Consequences

**Accepted costs.** `confidence` now has one meaning in the contract and a
different mapping in the harness. Both are documented at both ends.

**Reversibility.** Trivial; covered by tests.

**Authority.** None — this is measurement, not response.

## Verification

`tests/test_security_metrics.py::test_benign_confidence_does_not_rank_as_detection`
and `::test_recall_at_budget_is_zero_not_none_when_unachievable`.

## Prior art

No novelty claimed. Standard score-orientation handling in detection evaluation.
