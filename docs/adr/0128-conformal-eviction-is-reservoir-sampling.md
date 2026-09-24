# ADR-0128 — Conformal eviction is reservoir sampling, and G2.5's coverage clause was self-inflicted

- **Status:** Accepted
- **Date:** 2026-09-25
- **Stage:** 2
- **Deciders:** Stage 2 defect-repair wave, integrator
- **Supersedes / superseded by:** none. Corrects the measurement ADR-0117 relies
  on and removes a false attribution from G2.5's verdict string.

## Context

`SplitConformal` bounds its residual reservoir at `MAX_CALIBRATION` = 1024
because the 2 GB host target is a hard constraint. On overflow it evicted the
sample nearest the median — keeping both tails and hollowing out the middle. Its
docstring called the effect "biases the quantile **upward** … conservative rather
than anti-anti-conservative", which is true in direction and understates the
magnitude by an order of magnitude: the rank-α order statistic of a set with no
middle sits far out in the original stream's distribution.

G2.5's only failing clause was `conformal coverage 0.9793 is outside 0.9 ± 0.05`,
and `conformal_coverage` returned only `(coverage, radius, samples)` — discarding
`conformal.saturated()` and `conformal.evictions()`, the accessors the module
exposes with the explicit comment that they exist "so a coverage number measured
on a saturated reservoir can be recognised as one". The gate therefore attributed
to the ΔΦ predictor's calibration a bound its own eviction policy guaranteed
(S2-04).

## Measurement

The gate's train split yields 4,323 residuals against a cap of 1,024 — 3,299
evicted, saturated. Re-running that exact computation with the cap lifted is
decisive:

| reservoir | radius | empirical coverage | G2.5 clause |
|---|---|---|---|
| median-closest eviction, cap 1024 | 2.250000 | 0.9793 | **FAIL** (\|Δ\| = 0.0793) |
| no cap (all 4,323 residuals) | 0.750000 | 0.9167 | PASS (\|Δ\| = 0.0167) |

So the clause was caused entirely by the eviction rule; nothing about the
predictor's calibration was implicated.

On a synthetic control — 4,000 `gauss(0, 1)` residuals at cap 256, evaluated on
2,000 fresh draws — the old policy produced empirical coverage **0.99475** against
a nominal 0.90: a requested 90% interval delivering ~99.5%.

After the change (same control, same seeds, measured this session):

| reservoir | quantile | empirical coverage |
|---|---|---|
| bounded (256 of 4,000, reservoir sampling) | 1.5661 | **0.8800** |
| unbounded (all 4,000) | 1.6571 | 0.8945 |

The bounded estimate now tracks the unbounded one instead of standing far above
it.

## Decision

1. Once the reservoir is full, further residuals enter by **reservoir sampling**
   (Vitter's Algorithm R): the *k*-th residual replaces a uniformly chosen
   incumbent with probability `capacity / k`. The retained set stays a uniform
   sample of the stream, so its rank-α order statistic estimates the stream's.
2. The sampler is seeded at construction (`RESERVOIR_SEED` = 11) and the stream
   order fixes the result, so the same residuals in the same order always give
   the same reservoir. Randomness that makes the estimate unbiased may not also
   make it unrepeatable.
3. `saturated()` now means "subsampling, so the quantile is an unbiased estimate
   rather than an exact order statistic", and says so.
4. `conformal_coverage` returns a `ConformalCoverage` record carrying `residuals`,
   `observed`, `evictions` and `saturated` beside `coverage` and `radius`, and
   G2.5 prints all of it: "reservoir held 1024 of 4323 residuals, 3299
   subsampled away, saturated=True". A coverage figure from a bounded reservoir is
   now quoted with the bound.

## Consequences

- G2.5's conformal clause **passes**: coverage 0.9167 against 0.9 ± 0.05, radius
  0.75. The clause that kept G2.5 failing was an artefact.
- G2.5 still **FAILS**, now on the honest clause. Its held-out Brier is exactly
  0.0, which is perfect separability on this split — the same saturation G2.2
  refuses the corpus for. That clause was previously computed, printed as prose,
  and never appended to `failures` (S2-08); it is now a failure, so G2.5 cannot
  pass on evidence the same gate calls degenerate two criteria earlier.
- Any conformal figure recorded before this change was measured under the
  median-closest policy and is not comparable with one measured after it.

## Alternatives considered

**Keep only the upper tail and adjust the rank.** Cheaper and correct for a
one-sided quantile at a fixed level, but the retained set stops being a sample of
the stream, so any other statistic taken from it (and `to_dict` publishes the
whole reservoir's shape) becomes uninterpretable.

**Raise `MAX_CALIBRATION`.** Refused. 1024 floats is the bound the 2 GB target
buys; moving the bound to make a number look better is the wrong direction, and
the bound was never the defect — the eviction rule was.
