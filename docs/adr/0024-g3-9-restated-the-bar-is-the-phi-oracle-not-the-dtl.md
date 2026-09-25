# ADR-0024 — G3.9 restated: the bar is the Φ-oracle, and the quality clause is UNMEASURED

- **Status:** Accepted
- **Date:** 2026-09-25
- **Stage:** 3
- **Deciders:** Stage 3 integrator
- **Supersedes / superseded by:** none

## Context

The architecture gate's G3.9 reads "End-to-end average CPU/event is materially
lower than pure DTL at comparable security quality." Both halves are void as
written. The DTL is rejected (ADR-0010) and cost 22.3 µs/event; beating a
rejected mechanism proves nothing. Substituting the TCN's 6.6 µs/event is barely
better, because the thing Stage 3 actually wraps is a zero-parameter rule at
about 0.1 µs/event.

## Decision

G3.9 is restated as the only bar worth reporting:

> In a single run, on one host, with the load average recorded, a
> `KnowledgeCellV1` reproducing the Φ-oracle must cost **no more** µs/event and
> **no more** bytes than running the Φ-oracle directly (baseline B3), while
> producing identical scores on every frame in the split.

The **security-quality half of the criterion cannot be met and is not claimed.**
"Comparable security quality" needs a corpus where security quality is
discriminable. This one is saturated: the frozen Stage 2 frontier's own recorded
reason is `ORDER_FREE_BASELINE_TIES_BEST`, and four synthetic corpora produced
only trivial or impossible tasks (ADR-0010). A PR-AUC on such a split is not
evidence of equivalence. G3.9 therefore reports the cost ratio as MEASURED and
the quality clause as UNMEASURED, and **fails** rather than passing on half a
criterion.

## Options considered

| Option | Security cost | Resource cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|---|
| A: bar = Φ-oracle on cost and bytes; quality UNMEASURED; check fails | none | none | none | 2.16× time, 29.17× bytes, scores not identical → FAIL | **chosen** |
| B: keep "lower than pure DTL" | none | none | none | trivially true against a 22.3 µs/event rejected model | it would pass while proving nothing |
| C: pass on the cost half alone | none | none | none | would report a PASS on half a criterion | passing half a criterion is the failure this repo refuses |

## Consequences

**Accepted costs.** G3.9 FAILS, and it will keep failing until either a cell
format cheaper than the rule exists or the criterion is retired with a successor
ADR.

**Bounded state.** Unchanged.

**Reversibility.** The check reads the baseline table; a future cheaper format
flips it without an edit.

**Authority.** No change.

## Verification

`pocketsec-stage3 gate` criterion G3.9, whose detail carries both ratios, the
loadavg at measurement, and the UNMEASURED quality clause with its reason.

## Prior art

No novelty claim. `docs/prior-art/ledger.json`, entry H4.
