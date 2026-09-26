# ADR-0069 — Sybil break point and the Stage 7 component verdicts: epistemic distance is harmful as an ECHO weight, three terms never fire, and probation is a trade-off the gate's ablation missed

- **Status:** Proposed (measurement)
- **Date:** 2026-09-26
- **Stage:** 7
- **Deciders:** Stage 7 measurement session (numbers); project lead (decision)
- **Supersedes / superseded by:** none

> Measurement ADR. Every figure below is from code run in the 2026-09-26 measurement session.
> Commands and load averages are in `docs/stage-7-findings.md` §M. Synthetic corpus, simulated
> fleet, and adversaries written by the same author as the defences (lesson 6). The ablation
> controls are **replays of identical recorded traffic** under a changed `EchoConfig`
> (`labs.partition.replay_with`). They are therefore controlled comparisons (lesson 4), not
> new simulations.

## Context

Spec §7 requires every Stage 7 mechanism to earn its existence against the control that
isolates it. Lesson 1: a component that never changes an outcome is INERT, not measured. The
gate's `run_ablation` measures each ECHO flag on **one** arm. This session re-measured the
flags across **every** arm and share, on two corpus seeds (`benchmarks/stage7/config_grid.py`,
`benchmarks/stage7/echo_refusals.py`).

## Decision: verdict per component

| component (core id) | gate ablation (this session's gate run) | cross-arm measurement (this session) | verdict | recommendation |
|---|---|---|---|---|
| epistemic distance as an ECHO weight (ORPH-F05) | HARMFUL: firing 6, true acceptance −0.273 | Switching it off gives detection ≥ and poison acceptance ≤ the shipped ECHO in 55 of 55 (arm, share) cases on corpus 7 **and** 55 of 55 on corpus 11, with strictly higher recall in 39 of each. NONE: 0.571 → 0.786 (corpus 7) and 0.250 → 0.667 (corpus 11) | **HARMFUL** | default off |
| epistemic distance as a predictor, F6: AUC of −D_E predicting local usefulness | not in the gate's printed row set | corpus 7: **0.430** (role equality 0.418). Corpus 11: **0.823** (role equality 0.580). Falsifier F6 (AUC ≤ 0.6) fires on corpus 7 and not on corpus 11 | **UNSTABLE across seeds**: NOT-YET-JUSTIFIED | Do not use it as a weight. Re-measure only on a real corpus |
| contextual trust (ORPH-F09) | INERT, firing 0 | `no_trust` leaves true and poison acceptance unchanged in all 7 cases of `echo_refusals.py`. It moved amplification only, in 3 of them (SLOW_POISON 0.2: 2.194 → 2.143; COLLUSION_TIMING 0.2: 2.177 → 2.239; SYBIL_ADAPTIVE S=16: 11.803 → 11.857) | **INERT** | remove or leave off |
| falsification weight (ORPH-F09) | INERT, firing 0 (adversaries report perfect survival) | not re-measured | **INERT** | remove: self-reports are forgeable |
| contest mass (ORPH-F09) | INERT, firing 0 | `no_contest` = full on all 7 cases | **INERT** | remove or leave off |
| probation (ORPH-F09) | NOT_YET_JUSTIFIED: firing 1, delta 0 on COLLUSION_TIMING | Blocks latent poison: LATENT_POISON 0.1–0.6, poison acceptance 1.000 → **0.000** with it, both in the shipped config and with every other optional term off. Same at 12, 24 and 36 rounds, so this is not a horizon artefact. On SLOW_POISON 0.2, removing it from the shipped config raises poison 0.000 → 0.250. Alone, with the other optional terms off, it does not stop slow poison (0.500 at 0.1, 0.250 at 0.2). Costs 1 of 11 true keys at share 0 (0.636 against 0.545 with distance on). Under BYZANTINE_POISON it drives the accept-nothing collapse: required 0.818 true against required+probation 0.273 | **TRADE-OFF: the gate's single-arm verdict is wrong** | Keep. The gate's ablation must cover LATENT_POISON |
| dependence clustering (ORPH-F08) | JUSTIFIED: amplification −10.093 on FORGED_ROOTS | ROOT_QUORUM with the graph's clusters against declared roots: blocks FORGED-root Sybils (S ≥ 2: declared 4/4 poison, graph 0/4) and latent poison (declared-root quorum installs the poison: FP 4/60). It reduces slow poison (2/4, 1/4 and 0/4 at 0.1, 0.2 and 0.3, against FP 4/60 for declared roots). **Causes a detection collapse under BYZANTINE_POISON**: 11/14 → 0/14 for ROOT_QUORUM. Merges 24.5 % of honest cross-root pairs (G7.5(b), 216/881) | **JUSTIFIED for Sybil resistance; HARMFUL to detection under poison** | Keep. The false-merge rate is the defect to fix |
| local validation (ORPH-F09) | NOT_YET_JUSTIFIED: firing 10, delta 0, measured on BYZANTINE_POISON 0.2 where ECHO accepts nothing anyway (uninformative) | On the identity aggregators it is the whole detection effect. MEDIAN → MEDIAN+LV at share 0: FP 11/60 → 0 and recall@FPR 0.01 0.000 → 0.786. BYZANTINE_POISON break 0.1 → none. It is blind to LATENT, SLOW and COLLUSION poison by construction | **JUSTIFIED** (the gate's row is the wrong control) | keep; required |
| cluster cap (ORPH-F09) | JUSTIFIED: −9.927 amplification on DECLARED_ROOT | ECHO amplification 0.000 at every S on DECLARED and FORGED | **JUSTIFIED** | keep |
| knowledge gravity (ORPH-F06) | NOT_YET_JUSTIFIED: firing 287, 0 true keys lost | Re-run on corpora 7 and 11: 287 and 296 triaged, 0 true keys lost on both. The bound is 0, so the saving cannot be told apart from "validate everything" | **NOT-YET-JUSTIFIED** | default off until work units are compared |
| antibody minimisation (ORPH-F10) | NOT_YET_JUSTIFIED: firing 31, delta 0 | not re-measured | **NOT-YET-JUSTIFIED** | — |
| secure aggregation (ORPH-F18) | HARMFUL: +8 count inflation under Sybils | not re-measured | **HARMFUL** | keep off (ADR-0066) |
| reconstruction, falsifier, collective novelty, DP (F11/F14/F12/F19) | JUSTIFIED on the campaign simulation | not re-measured. Common causes and falsifier share an author (confounded) | JUSTIFIED as mechanism only | — |
| hypergraph (ORPH-F13) | NOT_YET_JUSTIFIED: firing 18, delta 0 | not re-measured | **NOT-YET-JUSTIFIED** | — |

**Sybil break point.** The measured break point of ECHO on SYBIL_ADAPTIVE is an adversary
identity share of **0.143 (S = 4 per root)**. It is the same with epistemic distance off, and
it is S = 2 with probation and the optional terms off. Break points on the same arm: MEDIAN
0.04 (S = 1) and ROOT_QUORUM+LV 0.077 (S = 2). No break was found on DECLARED_ROOT or
FORGED_ROOTS at up to S = 128. The adaptive arm is unmeetable without an identity authority
(spec §6.1, ADR-0064).

**Threshold sensitivity (gate, this session).** The share of ECHO decisions that flip at ×0.5
and ×2 was:
- MASS_FLOOR: 0.167 / 0.333;
- TRUST_PRIOR: 0.333 / 0.167;
- VALIDATION_FLOOR (triage): 0.113 / 0.128;
- CLUSTER_CAP, CONTEST_RATIO, RELEVANCE_FLOOR, ECHO_PROBATION_ROUNDS: 0 / 0.

No single threshold flips every decision. MASS_FLOOR is the parameter named in every "below
mass floor" refusal: halving it raises true acceptance from 0.545 to 0.818 at share 0, with
no poison accepted on LATENT_POISON 0.2. On SLOW_POISON 0.2 it lets 0.250 through (shipped: 0),
and COLLUSION_TIMING 0.2 stays at 1.000.

## Options considered

| Option | Measured consequence | Why not chosen |
|---|---|---|
| Keep every flag on (status quo) | detection 0.571 (corpus 7) and 0.250 (corpus 11) at share 0; accept-nothing under BYZANTINE_POISON | dominated by distance-off on every measured arm (corpus 7) |
| Distance off, other flags as shipped (chosen as research default) | ≥ status quo on every arm, corpus 7 | still NOT-YET-JUSTIFIED as a whole (ADR-0068) |
| Required mechanisms only (clustering, cap, local validation) | best detection (0.818 true everywhere measured) but poison 1.000 on LATENT_POISON and SLOW_POISON 0.1 | loses the only defence against latent poison |
| Required + probation | LATENT held at 0 poison; BYZANTINE_POISON collapse to 0.214 detection; COLLUSION_TIMING 0.1 broken | worse than distance-off on COLLUSION 0.1 |

## Consequences

**Accepted costs.** Contextual trust, falsification weight and contest mass stay in the code
as INERT switches until someone removes them. Removing them is recommended and not done here:
it is a code change outside a measurement session's scope.

**Bounded state.** No change.

**Reversibility.** Configuration defaults only.

**Authority.** None.

## Verification

- `PYTHONHASHSEED=0 python benchmarks/stage7/config_grid.py --corpus-seed 7` and
  `--corpus-seed 11 --seed 1`
- `PYTHONHASHSEED=0 python benchmarks/stage7/echo_refusals.py`
- the horizon check (12/24/36 rounds) quoted in the findings §M.5
- `pocketsec-stage7 gate` G7.11's ablation and sensitivity rows

## Prior art

None claimed.

## Addendum (review-fix session, 2026-09-26): verdicts this ADR stated that did not hold

The table above is kept as written. These rows are superseded; the evidence and commands are in
`docs/stage-7-findings.md` §R.

| row above | superseded by | why |
|---|---|---|
| knowledge gravity: NOT_YET_JUSTIFIED, firing 287 | **INERT, firing 0** (gate after the fix) | every one of the 287 triages came from multiplying by 1/cluster size, which ECHO's cluster cap already counts (review R7-5). The fabric now passes assessed-ness, and `FabricComponents.gravity_enabled` makes "default off" a configuration change. Recommendation: remove, or default off |
| reconstruction, falsifier, collective novelty, DP: "JUSTIFIED as mechanism only" | collective novelty and DP: **INERT on the fabric path** (firing 0) | both probes ignore the corpus and run a hand-built window; no runtime path calls `observe_population` and honest traffic carries no NOVELTY capsule (review F4). DP is a utility trade-off in any case (advantage 1.000 → 0.435, recall 1.000 → 0.141 at ε = 1.0). Reconstruction's +0.900 is against a hard-coded 0.0 control, not `count_threshold_join` (F5): its gain over that baseline is UNMEASURED |
| threshold sensitivity: ECHO_PROBATION_ROUNDS 0 / 0 | **0.444 / 0.333** | the flip metric compared only final statuses; probation moves the first-ELIGIBLE round, the round the fabric bridges (S7-R7). The same richer metric gives MASS_FLOOR 0.389 / 0.333, TRUST_PRIOR 0.333 / 0.389 and CONTEST_RATIO 0.0 / 0.167; CLUSTER_CAP and RELEVANCE_FLOOR stay 0 / 0 |
| cluster cap: JUSTIFIED | the cap **cannot bind** | mass is a product of three terms each at most 1, so `min(1.0, mass)` is the mass (S7-R6). The ablation measures max-over-members against sum-over-identities, which is what makes identity count irrelevant. The cap constant itself is inert by construction |
| falsification weight: INERT, "remove" | unchanged, and now also known HARMFUL in principle | it multiplies by a self-reported survival rate, so honest reporting lowers mass and lying costs nothing (S7-AUTH-07). Still on in the code; recommendation stands: remove |

The Sybil break point, the ECHO verdict (ADR-0068) and the detection figures are unchanged by
the fixes (gate re-run in this session: same five criteria fail, 6/11).

