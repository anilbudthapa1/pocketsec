# ADR-0077 — Discovery verdict against the Φ-oracle, random search and exhaustive single-step search; null FDR; the trap

- **Status:** Accepted (written from measurement; the figures are the gate run recorded in `docs/stage-8-findings.md` §M.1)
- **Date:** 2026-09-26
- **Stage:** 8
- **Deciders:** Stage 8 integrator
- **Supersedes / superseded by:** none

> Measured-verdict ADR. The verdict may go against Stage 8; the lead's rule decides.

## Context

The lead's baselines: (1) no discovery — the Φ-oracle; (2) random search with the same budget;
(3) exhaustive enumeration of the simplest class. "If the discovery engine does not beat random
search at equal budget and does not find anything the Φ-oracle misses, it is
NOT-YET-JUSTIFIED." The null corpus must discover ~nothing, and the NAIVE control must do worse,
or the null test was too easy (spec §7, M0.5).

## Decision

The verdicts are those G8.12 prints on the full gate run (`python -m pocketsec.stage8.cli gate`),
copied into `docs/stage-8-findings.md` §M.1–M.3 with the command output. In summary, on the
authored PLANTED corpus:

1. **Baseline (1), the Φ-oracle:** REPRODUCED packages catch REPLICATION positives the Φ-oracle
   misses at its TRAIN FPR-budget threshold, at no measured FPR cost — `counterfactual_at_boundary`
   (Stage 6 adopts nothing, ADR-0076).
2. **Baselines (2) and (3):** the search comparison verdict and families per arm are the gate's
   G8.12 `search` row. PM1 (a same-actor two-step order) is outside the single-step class by
   construction (precondition P2), so "beyond exhaustive" is expected; that is a property of the
   authored world (lesson 6), not evidence about real telemetry.
3. **Null FDR:** DEGENERATE when the NAIVE control also selects nothing on noise — the spec's own
   rule: a null the naive selector passes is too easy to show the discipline matters. It is
   reported, never re-worded as a pass.
4. **The trap:** refuted with the discipline; see ADR-0073 for the literal G8.1(d) clause.

## Options considered

| Option | Security cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|
| A. Declare discovery JUSTIFIED on the PLANTED win | a mechanism result sold as a detection result | none | the world shares an author with the engine | lesson 6 |
| **B. Record every verdict, keep G8.12 failing on synthetic data (chosen)** | none | none | G8.12 FAILS (synthetic_data True) with the verdict list | — |
| C. Loosen the NAIVE control until it selects on noise | a control tuned to make the discipline look useful | low | not done | re-operationalising to pass |

## Consequences

**Accepted costs.** Stage 8 has no evidence of value on real telemetry. Components whose ablation
verdict is not JUSTIFIED are listed for removal in ADR-0078.

**Bounded state / Reversibility / Authority.** None changed.

## Verification

G8.12; `tests/test_stage8_experiments.py`.

## Prior art

No novelty claim: H4 and H8 are NOT_REVIEWED (G8.6(d)).

## Amendment 2026-09-27 — measurement session: the discovery engine is NOT-YET-JUSTIFIED

- **Status of this amendment:** Accepted (written from measurement; figures and commands in
  `docs/stage-8-findings.md` §M.1–M.4 and Appendix A; ledger rows `PS-S8-20260926-*-0101…0108`).
- **Why an amendment and not a new ADR:** Stage 8's block 0070–0079 is fully assigned and the lead
  forbids numbers outside it. The text above is kept unchanged; where it disagrees with this
  amendment, this amendment decides.

### What was measured

1. **The corpus is saturated for a trivial model.** The trap-free PLANTED content (the NULL arm on
   content labels) gives a pooled order-free logistic HOLDOUT AP of 1.0000. P5 (< 0.95) is met on
   PLANTED (0.8996–0.9178) only because the trap corrupts TRAIN.
2. **Against the direct model with equal information, discovery loses.** A stdlib logistic model
   on pooled features, fitted on TRAIN + HOLDOUT labels (the labels the loop reads), reaches
   REPLICATION recall 1.0 at FPR 0.0 (AP 1.0000) on 3/3 content seeds. Φ ∪ REPRODUCED packages
   reaches 0.6463 at FPR 0.0.
3. **Against random search at equal spend, PROMETHEUS wins; against the bare enumerator, it
   does not.** Random: 0/26 runs with spend ≤ 9.78 M units, 5/39 overall (each ≥ 15.05 M).
   PROMETHEUS: 9/9 at 8.92–9.42 M. The minimal engine (SYMBOLIC_ENUMERATOR plus the discipline) and
   brute force over the whole ≤ 2-step class (2539 mechanisms) through the identical discipline both
   recover the same family on every run, the former at 0.73–0.76× PROMETHEUS's work units.
4. **Baseline (3) as specified cannot express PM1**, so "beyond exhaustive single-step" is a
   construction result, not evidence.
5. **The shipped package does not transfer.** `CO_OCCURS(WRITE,SEND)` catches 0/36 and 0/44 Stage 1
   replay/hard positives and fires at FPR 0.35 / 1.00 on ambiguous / long-horizon.
   Identifiability: EQUIVALENCE_CLASS 20/20.
6. **The null is DEGENERATE for a measured reason.** In-sample significance alone admits 0–184
   false mechanisms per null seed; the registered in-sample rate rules alone admit 0/20. The vault
   is measured necessary only for the trap.

### Decision

- The discovery engine is **NOT-YET-JUSTIFIED** as a detection mechanism (lead's rule: it beats
  random search at equal spend, and it catches REPLICATION positives the Φ-oracle misses, but a
  direct model with the same labels catches all of them, and the gain does not survive outside the
  authored world).
- The PLANTED corpus is **DEGENERATE** as evidence that any discovery mechanism helps. No further
  value claim is made on it; a non-saturated corpus (trap-free order-free logistic AP well below
  0.95) is the prerequisite for re-opening this verdict.
- G8.12's direct-model baseline must be fitted on the labels the loop reads (TRAIN + HOLDOUT).
  Recorded here; the gate is not re-worded in this session (spec §12: never re-operationalise to
  pass or to fail).

### Options considered (amendment)

| Option | Security cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|
| A. Keep the integration session's "beats baselines (1)–(3)" | a construction result read as evidence | none | ENUM_MIN and brute force tie it; the direct model beats it | contradicted by measurement |
| **B. NOT-YET-JUSTIFIED; corpus DEGENERATE; keep the discipline and the boundary (chosen)** | none | none | the verdicts above | — |
| C. REJECT and delete Stage 8 | loses the discipline, bounds and boundary, which work | high | the trap kill, the bounded stores and the one-door boundary all measured working | the negative result is about value, not about the kill switch |
