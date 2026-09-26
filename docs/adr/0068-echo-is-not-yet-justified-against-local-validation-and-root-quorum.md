# ADR-0068 — ECHO verdict: NOT-YET-JUSTIFIED. It beats MEDIAN on robustness, but on detection simple local-validation baselines dominate it, and under Byzantine poison it falls to no-sharing

- **Status:** Proposed (measurement). The lead decides what ships.
- **Date:** 2026-09-26
- **Stage:** 7
- **Deciders:** Stage 7 measurement session (numbers); project lead (decision)
- **Supersedes / superseded by:** none

> Measurement ADR. Every figure below comes from code run in the 2026-09-26 measurement session.
> The commands, seeds and load averages are in `docs/stage-7-findings.md` §M. The fleet is
> simulated in-process and every corpus is synthetic. The adversaries, the defences and the
> ground truth share one author (lesson 6), so robustness figures are **mechanism** figures, not
> deployment evidence. Detection is `counterfactual_at_boundary` (ADR-0067). The fleet corpus is
> `DEGENERATE_IN_FAVOUR` of sharing (precondition P5).

## Context

The lead's rule is that the collective mechanism must beat **no sharing** on detection **and**
beat **median** on robustness. Otherwise it is NOT-YET-JUSTIFIED. Spec §7 makes this sharper:
detection must beat NO_SHARING by ≥ 0.10 at adversary share 0 **and** at share 0.2, and ECHO must
beat ROOT_QUORUM+LV on at least one robustness metric by > 0.05 without losing detection.

### Measured: detection

Recall is at FPR 0.01 on locally-unseen families, scored through Stage 0's `run_benchmark`.
The setup is corpus seed 7, fleet seed 0, and the gate's 4 receivers: 14 positives and 60
benign.

| arm | NO_SHARING | MEDIAN (no LV) | MEDIAN+LV | VALIDATION_FILTER | ROOT_QUORUM (graph clusters) | ROOT_QUORUM (declared roots) | **ECHO** |
|---|---|---|---|---|---|---|---|
| NONE, share 0 | 0/14 | 14/14 but FP 11/60 → **0.000** | 11/14, FP 0 → 0.786 | 0.786 | 0.786 | 0.786 | **8/14 → 0.571** |
| BYZANTINE_POISON 0.1–0.6 | 0.000 | 0.000 (FP 45/60) | 0.786 | 0.786 | **0.000** | 0.786 | **0.000** |
| BYZANTINE_LATENT_POISON 0.1–0.6 | 0.000 | 0.000 | 0.000 (FP 4/60) | 0.000 (FP 4/60) | 0.786 | 0.000 (FP 4/60) | 0.571 |
| SLOW_POISON 0.1–0.3 | 0.000 | 0.000 | 0.000 (FP 4/60) | 0.000 | 0.786 | 0.000 | 0.786 |
| COLLUSION_TIMING 0.1 / 0.2 / 0.3 / ≥0.4 | 0.000 | 0.000 | 0.000 all | 0.000 all | 0.000 / 0.000 / 0.000 / 0.786 | 0.000 all | 0.571 / **0.000** / **0.000** / 0.571 |
| SYBIL_ADAPTIVE S=1 / S=2 / S≥4 | 0.000 | 0.000 | 0.000 | 0.000 | 0.786 / 0.000 / 0.000 | 0.786 / 0.000 / 0.000 | 0.786 / 0.786 / **0.000** |

**Paired, arm NONE.** Across every receiver set and both corpus seeds measured, ECHO catches a
**strict subset** of the attacks that ROOT_QUORUM and VALIDATION_FILTER catch. No attack was
caught by ECHO alone. The table below is `benchmarks/stage7/paired_detection.py`, with an exact
sign test over the discordant episodes. Episodes are not independent draws, so the p-values
describe this corpus only.

| corpus seed, receivers | ECHO | ROOT_QUORUM = VALIDATION_FILTER | only ECHO | only the baseline | p |
|---|---|---|---|---|---|
| 7, 4 | 8/14 | 11/14 | 0 | 3 | 0.25 |
| 7, all 24 | 59/81 | 73/81 | 0 | 14 | 1.2e-4 |
| 11, 4 | 3/12 | 10/12 | 0 | 7 | 0.016 |
| 11, all 24 | 32/74 | 67/74 | 0 | 35 | 5.8e-11 |

**At fleet scale (every one of the 24 corpus hosts as a receiver).** The same ordering holds.
Recall at FPR 0.01:

| arm | corpus 7 (81 positives): NO_SHARING / MEDIAN+LV / ROOT_QUORUM / **ECHO** | corpus 11 (74 positives): same columns |
|---|---|---|
| NONE | 0.086 / 0.901 / 0.901 / **0.728** | 0.162 / 0.905 / 0.905 / **0.432** |
| BYZANTINE_POISON 0.2 | 0.086 / 0.901 / 0.086 / **0.086** | 0.162 / 0.905 / 0.189 / **0.162** |
| BYZANTINE_LATENT_POISON 0.2 | 0.086 / 0.000 (FP 8) / 0.901 / 0.728 | 0.162 / 0.000 (FP 8) / 0.905 / 0.432 |
| SLOW_POISON 0.2 | 0.086 / 0.000 (FP 8) / 0.901 / 0.901 | 0.162 / 0.000 (FP 8) / 0.905 / 0.905 |
| COLLUSION_TIMING 0.2 | 0.086 / 0.000 / 0.000 / 0.000 (FP 8) | 0.162 / 0.000 / 0.000 / 0.000 (FP 8) |
| SYBIL_ADAPTIVE S=4 | 0.086 / 0.000 / 0.000 / 0.000 (FP 8) | 0.162 / 0.000 / 0.000 / 0.000 (FP 8) |

### Measured: robustness

Break point = the smallest adversary share (for Sybil arms, the adversary's identity share)
at which poison acceptance ≥ 0.5. "none" = no break inside the sweep (0.1–0.6, or S = 1..128).

| arm | MEDIAN | MEDIAN+LV | TRIMMED_MEAN(+LV) | ROOT_QUORUM+LV | **ECHO** |
|---|---|---|---|---|---|
| SYBIL_DECLARED_ROOT | 0.04 (S=1) | 0.04 | 0.04 | none | **none** |
| SYBIL_FORGED_ROOTS | 0.04 | 0.04 | 0.04 | none | **none** |
| SYBIL_ADAPTIVE | 0.04 | 0.04 | 0.04 | 0.077 (S=2) | **0.143 (S=4)** |
| BYZANTINE_POISON | 0.1 | none | 0.1 / none | none | none |
| BYZANTINE_LATENT_POISON | 0.1 | 0.1 | 0.1 | none | **none** |
| SLOW_POISON | 0.1 | 0.1 | 0.1 | 0.1 (2/4) | **none** |
| COLLUSION_TIMING | 0.1 | 0.1 | 0.1 | 0.1 | **0.2** (and 0/4 again at ≥ 0.4) |

The gate's G7.4 figures in the same session match. Amplification on SYBIL_ADAPTIVE was
4.590–12.467 for ECHO and 2.595–16.136 for MEDIAN. It was 0.000 at every S for ECHO on the
declared and forged arms.

## Decision

1. **ECHO as shipped (`EchoConfig()`) is NOT-YET-JUSTIFIED.** It clears the robustness half of
   the lead's rule: its break point is strictly above MEDIAN's on every Sybil arm and at or
   above it on every Byzantine arm. It fails the detection half:
   - under BYZANTINE_POISON at share 0.1–0.6 its detection gain over NO_SHARING is **0.000**,
     where the spec requires ≥ 0.10 at share 0.2;
   - at share 0 it catches a strict subset of what VALIDATION_FILTER and ROOT_QUORUM catch;
   - per spec §7, "ECHO's extra terms" lose detection against ROOT_QUORUM+LV. The rule
     therefore says reduce.
2. **Epistemic distance is to be switched off by default** (ADR-0069). Measured on identical
   traffic, `EchoConfig(epistemic_distance=False)` has detection ≥ the shipped ECHO and poison
   acceptance ≤ it on **every** arm and share in the grid (`benchmarks/stage7/config_grid.py`,
   corpus seed 7). Examples:
   - NONE: 0.786 against 0.571;
   - LATENT_POISON: 0.786 against 0.571, poison 0 for both;
   - SYBIL_ADAPTIVE: the same break point (S = 4) and lower amplification (6.174 against 8.212
     at S = 4).
   The dominance also holds on corpus seed 11 (fleet seed 1): no worse in 55 of 55
   (arm, share) cases and strictly higher recall in 39 of them. At NONE the recall is 0.667
   against 0.250.
   The ECHO-without-distance variant still collapses under BYZANTINE_POISON (0.071), still
   breaks on COLLUSION_TIMING 0.2–0.3, and still breaks on SYBIL_ADAPTIVE at S ≥ 4. It is
   therefore also NOT-YET-JUSTIFIED. It is simply the better-measured default.
3. **No aggregator measured here is safe to open Stage 6 to.** Every method, ECHO included,
   accepts poison on at least one arm at share ≤ 0.2 (see the break-point table). Until a
   non-synthetic corpus exists and B7-1 is resolved, the recommended shipped configuration is
   **the boundary only, with exchange off by default**. This is spec §7's "ship nothing but the
   boundary" outcome. ECHO without epistemic distance stays the research default.

## Options considered

| Option | Security (measured, corpus 7, 4 receivers) | Resource | Complexity | Why not chosen |
|---|---|---|---|---|
| A. Ship ECHO as is | Best Sybil break points. Detection 0.000 under BYZANTINE_POISON; 0.571 at share 0 | fabric CPU ≈ 302× MEDIAN+LV on the same pools (within-run, loadavg 14.9) | 15 flags, 7 parameters | Fails the detection half of the rule |
| B. ECHO without epistemic distance | ≥ A on every arm measured | same order as A | one flag fewer | Still collapses under BYZANTINE_POISON and breaks on COLLUSION_TIMING and SYBIL_ADAPTIVE. Kept as the research default, not as a justified mechanism |
| C. ROOT_QUORUM over dependence clusters + local validation | detection 0.786 on NONE, LATENT, SLOW, SYBIL_DECLARED and FORGED. **0.000 under BYZANTINE_POISON** (the dependence graph merges honest peers once adversaries appear). Breaks at 0.1 on SLOW and COLLUSION, and at S=2 on ADAPTIVE | ≪ A | small | Weaker than A on SLOW_POISON, COLLUSION_TIMING and SYBIL_ADAPTIVE |
| D. MEDIAN / TRIMMED_MEAN + local validation | detection 0.786 on NONE and BYZANTINE_POISON. Breaks at 0.04 on every Sybil arm and at 0.1 on LATENT, SLOW and COLLUSION | smallest | trivial | Worst Sybil resistance; blind to latent poison |
| E. Plain MAJORITY / MEAN (FedAvg's rule) / MEDIAN, no local validation | detection **0.000 even with no adversary**: cross-role honest antibodies fire on 11/60 receiver benign episodes | smallest | trivial | Non-IID alone breaks it |
| F. Boundary only, exchange off (chosen for shipping) | detection = NO_SHARING (0 gain); poison 0 | 0 | none | — |

The simplest option (E) is rejected on a measured failure: sharing without local validation
cannot hold the receiver's FP budget on a non-IID fleet, even with no adversary present.

## Consequences

**Accepted costs.** The shipped endpoint gains no collective detection. This costs nothing
measurable today, because Stage 6 admits no foreign capsule anyway (ADR-0067).

**What would change this verdict.**
- A non-synthetic multi-host corpus on which the ECHO variant keeps a detection gain ≥ 0.10
  under the Byzantine arms.
- A fix for the dependence graph's false merges (24.5 % of honest cross-root pairs, G7.5(b)).
  Those merges drive both the BYZANTINE_POISON collapse and ROOT_QUORUM's identical collapse.
- An identity authority that binds provenance roots, which would close the SYBIL_ADAPTIVE arm
  (spec §6.1).

**Bounded state.** No change.

**Reversibility.** Configuration only: an `EchoConfig` default and the exchange default.

**Authority.** None moves. The boundary tests (G7.1, G7.2) pass in this session.

## Verification

- `PYTHONHASHSEED=0 python benchmarks/stage7/fraction_sweep.py --corpus-seed 7 --seed 0`
  (+ `--all-receivers`, + `--corpus-seed 11 --seed 1 --all-receivers`)
- `PYTHONHASHSEED=0 python benchmarks/stage7/config_grid.py --corpus-seed 7` (and `11`)
- `PYTHONHASHSEED=0 python benchmarks/stage7/paired_detection.py --corpus-seed {7,11} [--all-receivers]`
- `PYTHONHASHSEED=0 python -m pocketsec.stage7.cli --json gate` (G7.4, G7.11)

## Prior art

Median, trimmed mean, Krum and Bulyan are the established Byzantine-robust aggregation baselines.
No novelty is claimed for ECHO (architecture §53).
