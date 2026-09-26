# Stage 8 — PROMETHEUS + ORACLE + FORGE — findings (D8.20)

**Measurement session, 2026-09-26 23:00 → 2026-09-27 AEST** (Python 3.14.7, Linux 7.1.5+kali-amd64,
8 cores / 16 GB; another wave was building in the same tree throughout, **loadavg 13–46**). This
document supersedes the integration session's findings of 2026-09-26 22:53, which are retained
verbatim in Appendix B (never deleted). **Every number in Part I and in the honesty ledger was
produced by running code in this session**; the command, seed, corpus and loadavg are named
beside it and the raw output is in Appendix A. A figure the integration session reported and this
session did not re-measure is labelled as theirs. Nothing here is a detection result: every corpus
is synthetic (see NOT A DETECTION RESULT).

Scripts: `benchmarks/stage8/` (Stage 5/6/7 precedent; the package never imports them). Raw JSON:
`results/stage8-bench/*.json` (git-ignored, so every figure is quoted inline). Ledger rows:
`PS-S8-20260926-*-0101 … -0108`, registered after the gate re-run (§M.8) so that G8.12's
"registry byte-identical" check was not disturbed.

## Verdict

**The stage's central claim is NOT supported by the numbers.** The claim (spec §8) is that Stage 8
"discovers defensive mechanisms the existing theory misses, beats random search and exhaustive
single-step search at equal budget, kills its own false hypotheses, preserves UNKNOWN, compiles
survivors into cheaper representations that keep their measured quality, and reaches the endpoint
only as a Stage 6 candidate." Measured against the simplest baselines that can express the
planted function, and with the isolating controls the gate lacks:

1. **The PLANTED world is saturated for a trivial model; P5 passes only because the trap poisons
   TRAIN.** The trap-free content (the NULL arm scored on content labels — the exact control
   `PreconditionReport` names) gives a pooled order-free logistic HOLDOUT AP **1.0000**. A stdlib
   logistic model on pooled max features, fitted on labels the discovery loop already reads
   (TRAIN + HOLDOUT, or HOLDOUT alone), scores REPLICATION **recall 1.0 at FPR 0.0, AP 1.0000 on
   3/3 content seeds**. The whole loop plus the Φ-oracle reaches recall **0.6463** at FPR 0.0. The
   gate's direct model loses only because it is fitted on TRAIN alone, where the trap is a perfect
   positive feature (§M.1). **Against the direct model with equal information, Stage 8 loses.**
2. **What is "discovered" is a co-occurrence that exists only in the authored world.** The one
   shipped package is `CO_OCCURS(WRITE,SEND)`; none of the 19 REPRODUCED theories has PM1's form;
   all are co-extensive with the DROP_EXEC_EGRESS family *in this corpus*; identifiability is
   EQUIVALENCE_CLASS for 20/20 (F10 fires). On Stage 1's four eval corpora (a different author) the
   package catches **0/36** (replay) and **0/44** (hard) positives, and on ambiguous and long-horizon
   it fires at FPR **0.35** and **1.00** (§M.2).
3. **PROMETHEUS beats random search at equal spend — but so does the bare enumerator, for less.**
   Random search recovers **0 families in the 26 runs** whose spend stayed ≤ 9.78 M work units;
   PROMETHEUS recovers DROP_EXEC_EGRESS on **9/9** runs at 8.92–9.42 M. Random succeeds only
   5 times in 39 runs, each at ≥ 15.05 M. **But** the minimal engine — SYMBOLIC_ENUMERATOR alone,
   with no residual motifs, analogy, null-benign generator, diversity, MDL, mutation, ORACLE,
   priority field or negative memory, and the same screens and vault — recovers the **same family
   on every run at 0.73–0.76× PROMETHEUS's work units**, and brute-force enumeration of the whole
   ≤ 2-step class (2539 mechanisms) through the identical discipline also recovers it (at
   1.59–1.67×). **Everything PROMETHEUS adds beyond the enumerator is NOT-JUSTIFIED** (§M.3); the
   re-measured ablation agrees (1 JUSTIFIED, 7 NOT-YET-JUSTIFIED, 9 INERT, identical to the gate's
   rows, §M.5).
4. **The kill switch works; the null test proves little.** *(Fix-wave note, §F.1: the in-loop
   kill described here was a decoy-vocabulary artefact; after the fix the trap is registered and the
   vault refutes it at HOLDOUT.)* The trap `SINGLE(SPAWN)` is refuted in
   every disciplined run and selected by the NAIVE control (verified by digest among its 35
   selections). On 20 null label seeds the disciplined loop reproduces **0** (FDR 0) — but NAIVE
   also selects 0 (**DEGENERATE**, reproducing the gate). The whole-class control shows why:
   selection by in-sample significance alone admits **0–184 false mechanisms per seed** (mean 32.4,
   11/20 seeds > 0), while the registered in-sample FPR ≤ 0.01 and recall ≥ 0.10 rules alone admit
   **0 on 20/20**. The rate rules, not the vault or Bonferroni, are what stop noise here (§M.4).
5. **ORACLE has a crash defect and no measured benefit.** *(Fix-wave note, §F.2: the crash was an
   absolute prune floor against large groups; fixed, and ORACLE is now default-off.)* `run_discovery` aborts with
   `ContractError: restricting a posterior must keep some probability mass` in **10 of 39**
   random-generator runs (deterministic repro in §M.9). On replay, the production default, no ORACLE
   policy ever leads with the planted mechanism and EIG spends exactly what CHEAPEST spends
   (F8 fires); it helps only with the authored lab oracle (§M.5).
6. **FORGE works by its own rule and loses to the direct model.** *(Fix-wave note, §F.6: "cheaper"
   was self-charged work units against an inflated reference; RETRACTED. The FSM is slower than the
   rule it compresses.)* The FSM (216 B, 10.24 wu/event)
   matches the typed rule exactly (recall 0.3537, FPR 0.0, agreement 1.0) and is cheaper, so it is
   deployable. Through `run_benchmark`, the deployed Φ ∪ FSM reaches recall 0.6463 / PR-AUC 0.7672.
   The equal-information direct model reaches 1.0 / 1.0000 at **4.9×** the CPU per event (within-run
   ratio, §M.6).
7. **The bounds hold; the ecology does not stay productive.** A 10 000-text flood under 200 000
   units exhausts the budget. A 100 000-text flood under the default 50 M budget is stopped by the
   external-proposal cap (199 718 refused) with +4.1 MB RSS. 12 endurance cycles plateau, but
   packages stop after cycle 6, and the 100 000-text flood changes outcomes (registered 34 → 25,
   reproduced 19 → 18: F14 fires) (§M.7).

**Recommendation (ADR-0077/0078/0079 amendments, §M.10).** Record the discovery engine as
NOT-YET-JUSTIFIED as a detection mechanism. Keep what construction and measurement justify: the
typed genome, the append-only ledger, preregistration and the one-batch vault, the in-sample and
HOLDOUT rate rules, the trap kill, the bounded stores and the one-door Stage 6 boundary. Reduce
PROMETHEUS to SYMBOLIC_ENUMERATOR by default and put every other generator and every ecology term
default-off. Put ORACLE default-off until its crash is fixed and it beats cheap selection on
replay. Before any further value claim, **replace the PLANTED corpus**: its content is solved at
AP 1.0000 by an order-free logistic model, so it cannot show that any discovery mechanism helps.
G8.12's direct-model baseline must also be fitted on the same labels the loop reads.

## M.0 How this was measured

| script (`benchmarks/stage8/…`) | what | seeds | loadavg range | ledger id |
|---|---|---|---|---|
| `saturation.py` | P1–P5 incl. the trap-stripped control; direct model D0–D3; Φ-oracle | PLANTED content 0, 1, 2; NULL content 0 | 13.3–15.6 (first run); the log in Appendix A is a deterministic re-run at ~40–44 with identical figures | …-0102 |
| `search_controls.py 0 1 2`, then `search_controls.py 2` after the crash | PROMETHEUS, RANDOM_512, RANDOM_3840, ENUM_MIN, EXH2_ENGINE (± doppelgänger screen), EXH2 Bonferroni offline | content 0 × run 0–2; content 1 × run 0; content 2 × run 0–2 | 15.6–43.0 | …-0104, …-0108 |
| `random_curve.py` (+ its first attempt's log) | random search success vs work units actually spent | content 0 × run 0–4 × 5 draw counts | 15.6–31.0 | …-0106 |
| `null_fdr.py` | engine null (disciplined vs NAIVE, 20 label seeds); whole-class controls | NULL content 0, label seeds 0–19 | 19.9–22.9 | …-0105 |
| `transfer.py` | Stage 8 artefacts on Stage 1 replay/hard/ambiguous/long-horizon eval | Stage 1 seed 11; PLANTED 0 | 21.2–27.6 | …-0101 |
| `resources.py` | research RSS/CPU, floods, endpoint via `run_benchmark`, gate footprint, endurance | PLANTED 0 | 22.6–24.9 | …-0103 |
| `components.py` | base funnel, FORGE entrants, NAIVE, trap probe, `run_ablation`, `oracle_comparison`, `threshold_sensitivity` | PLANTED 0, run 0 (ORACLE: runs 0–2) | 20.8–46 | …-0107 |
| `oracle_crash_repro.py` | the ORACLE defect | PLANTED 0, run 1 | 40.9 | — |
| `python -m pocketsec.stage8.cli gate` | the gate, re-run | 0 | §M.8 | not registered (spec §2.5) |

Every run used `PYTHONHASHSEED=0`. Work units are exact and load-independent; wall and CPU seconds
are contended and are quoted only beside loadavg and as within-run ratios.

## M.1 Saturation: P5, and the direct model with the labels the loop reads

`saturation.py`, REPLICATION split (240 episodes, 82 positives), per PLANTED content seed:

| figure | seed 0 | seed 1 | seed 2 |
|---|---|---|---|
| P5 pooled logistic HOLDOUT AP (gate precondition, must be < 0.95) | 0.9178 | 0.9049 | 0.8996 |
| P5 with the trap steps stripped (partial control; the trap also shifts the next step's features) | 0.9268 | 0.9157 | 0.9151 |
| Φ-oracle HOLDOUT AP (P1 ≤ 0.85) | 0.6379 | 0.6379 | 0.6379 |
| Φ-oracle REPLICATION recall / FPR at its TRAIN FPR-budget threshold 0.522388 | 0.2927 / 0.0 | 0.2927 / 0.0 | 0.2927 / 0.0 |
| **D0** direct model, TRAIN labels (the gate's baseline): AP; recall / FPR at 0.5 | 0.8684; 0.6463 / 0.2532 | 0.8890; 0.6951 / 0.2468 | 0.8567; 0.6220 / 0.2722 |
| **D1** direct model, HOLDOUT labels only: AP; recall / FPR at 0.5 and at the fit-side FPR ≤ 0.01 threshold | **1.0000; 1.0 / 0.0; 1.0 / 0.0** | **1.0000; 1.0 / 0.0; 1.0 / 0.0** | **1.0000; 1.0 / 0.0; 1.0 / 0.0** |
| **D2** direct model, TRAIN + HOLDOUT labels (equal information) | **1.0000; 1.0 / 0.0; 1.0 / 0.0** | **1.0000; 1.0 / 0.0; 1.0 / 0.0** | **1.0000; 1.0 / 0.0; 1.0 / 0.0** |
| D3 TRAIN with the trap steps stripped (knows the trap: an upper-bound control, not a baseline) | 0.8395; 0.6463 / 0.2911 | 0.8475; 0.6951 / 0.3291 | 0.7918; 0.6220 / 0.3608 |

NULL arm, content seed 0, scored on **content** labels (identical sessions rendered without the
trap): pooled logistic HOLDOUT AP **1.0000**. A TRAIN-fitted direct model on REPLICATION: AP 1.0,
recall 1.0 at FPR 0.0.

Reading. (a) The authored content is separable by an **order-free** model at AP 1.0000. The corpus
therefore violates the integration plan's risk-3 guard in substance while passing P5 in letter.
(b) P5 is met on PLANTED only because TRAIN carries the trap: the probe learns `SPAWN` as a perfect
positive feature and mis-ranks HOLDOUT, where the trap is label-independent. Stripping the trap
step is not enough (D3), because the trap also shifts the following step's features. The exact
control is the trap-free render, which scores 1.0000. (c) The discovery loop reads TRAIN labels for
generation and HOLDOUT labels through the vault. A direct model given those labels is perfect on
REPLICATION; the gate's direct model is given TRAIN only. **The FORGE-vs-direct and
discovery-vs-direct comparisons in the gate are therefore against a trap-poisoned baseline.**

## M.2 What is discovered, and whether it means anything outside the authored world

PROMETHEUS, PLANTED content 0, run 0. This run is identical in `search_controls.py`, `transfer.py`,
`resources.py` and `components.py`: 367 births, 34 registered, 20 survived, 19 REPRODUCED,
1 package, 9 417 205 work units — the gate's figures to the unit.

- The package mechanism is **`CO_OCCURS(WRITE,SEND)`** (the dedup representative). The 19
  REPRODUCED theories are 10 `CO_OCCURS` and 9 `PRECEDES` over WRITE/EXECUTE and SEND/CONNECT
  predicates, and **none is PM1** (`PRECEDES(EXECUTE+TEMP_LOCATION, CONNECT+EXTERNAL_ENDPOINT)`).
  Each counts as "PM1 recovered" because recovery is agreement ≥ 0.98 with PM1 over all 240
  REPLICATION episodes, and in this corpus no benign session writes and sends in one actor.
- Identifiability, interventions off: **EQUIVALENCE_CLASS 20 / 20**, IDENTIFIED share of reproduced
  **0.0**, so falsifier **F10 fires** ("IDENTIFIED in fewer than half … with interventions off").
- Novelty: `KNOWN_COMBINATION` 1 (no claim permitted). F13 ("every reproduced package is KNOWN")
  does not fire literally; no package is POTENTIALLY_NOVEL either.

**Transfer to a world Stage 8 did not author** (`transfer.py`). Each Stage 1 eval scenario is
rendered on a fresh pipeline (avoiding the pid-reuse corpus trap) and truncated to 64 steps like
every Stage 8 episode. The artefacts are fitted on PLANTED content 0 and applied unchanged. Cells
are recall / FPR:

| Stage 1 corpus (eval, seed 11) | n / positives / truncated | Φ-oracle | package `CO_OCCURS(WRITE,SEND)` | all 19 REPRODUCED | Φ ∪ package via `run_benchmark` | direct D2 |
|---|---|---|---|---|---|---|
| replay | 120 / 36 / 0 | 0.333 / 0.0 | **0.000 / 0.0** | 0.000 / 0.0 | 0.333 / 0.0 | 0.667 / 0.0 (AP 0.8542) |
| hard | 120 / 44 / 0 | 0.341 / 0.0 | **0.000 / 0.0** | 0.114 / 0.0 | 0.341 / 0.0 | 0.636 / 0.25 (AP 0.7636) |
| ambiguous | 90 / 30 / 66 | 0.100 / 0.0 | **0.500 / 0.35** | 0.500 / 0.35 | 0.533 / 0.35 | 1.000 / 1.00 (AP 0.7983) |
| long-horizon | 60 / 20 / 51 | 0.500 / 0.45 | **1.000 / 1.00** | 1.000 / 1.00 | 1.000 / 1.00 | 1.000 / 1.00 (AP 0.4556) |

The discovered rule adds nothing to the Φ-oracle on the two short corpora and is a pure false-alarm
source on the two long ones: in a 64-step multi-actor window, some actor almost always writes and
sends. The direct model does not transfer well either. This table says the *authored* world is
what makes both look good. It is still synthetic, and not a detection result.

## M.3 Search: PROMETHEUS vs random at equal spend, the minimal engine, and brute force

The gate's "equal budget" is the same `ResearchBudget` (50 M units). No arm exhausts it, so the
arms spend different amounts. Measured instead: what each arm **spends**, and what it recovers.
All arms below share the corpus, screens, one HOLDOUT batch, Bonferroni, REPLICATION and the gate's
scoring (`search_controls.py`, `random_curve.py`):

| arm | runs | families recovered | false reproduced | work units spent | CPU s |
|---|---|---|---|---|---|
| PROMETHEUS (defaults) | content 0 × run 0–4; content 1 × run 0; content 2 × run 0–2 | DROP_EXEC_EGRESS on **9/9** | 0 | 9 417 205 · 9 068 403 · 9 062 197 · 8 919 244 · 9 128 516 · 9 016 849 · 9 146 000 · 9 185 039 · 9 191 703 | 62.7–79.8 |
| RANDOM, 512 draws/cluster (gate arm) | content 0 × run 0–2; content 1 × run 0; content 2 × run 0–2 | **0/7** (content 2 run 0: ORACLE crash, re-run ORACLE-off) | 0 | 5 868 078 – 6 232 183 | 14.2–14.9 |
| RANDOM, 768 / 1024 / 1280 / 1536 draws/cluster | content 0 × run 0–4 each | **0/19** with spend ≤ 9.78 M; 1/20 overall (1536, run 0, spent **15 054 002**) | 0 | 6 531 037 – 15 054 002 | — |
| RANDOM, 2048 draws/cluster | content 0 × run 0–4 | 1/5 (run 0, spent **16 913 491**) | 0 | 11 547 052 – 16 913 491 | — |
| RANDOM, 3840 draws/cluster (the most it accepts) | content 0 × run 0–2; content 1 × run 0; content 2 × run 0–2 | 3/7 (at 23 748 940, 23 773 610, 24 054 204; content 2 run 1: ORACLE crash, re-run ORACLE-off) | 0 | 18 313 239 – 24 054 204 | 32.5–41.5 |
| **ENUM_MIN** (enumerator only; diversity, MDL, evolution, ORACLE, negative memory off; SIZE_ONLY priority; FIT_ONLY score) | content 0 × run 0–2; content 1 × run 0; content 2 × run 0–2 | DROP_EXEC_EGRESS on **7/7** | 0 | 6 842 813 · 6 852 433 · 6 860 157 · 6 848 310 · 6 888 619 · 6 866 310 · 6 872 163 | 45.3–47.7 |
| **EXH2_ENGINE** (every ≤ 2-step mechanism over TRAIN's vocabulary, 2539, fitted on TRAIN, top 256 by F1 → the identical `_Run` screens → rank → vault → reproduce → package) | as ENUM_MIN | DROP_EXEC_EGRESS on **7/7** | 0 | 14 934 378 · 14 962 502 · 14 979 777 · 15 011 586 · 15 060 167 · 15 099 448 · 15 111 779 | 138.7–153.6 |
| EXH2_ENGINE without the doppelgänger screen | as ENUM_MIN | **0/7** (0 of 64 registered survive HOLDOUT) | 0 | 8 994 161 – 9 129 649 | 37.1–38.7 |

Within-run work-unit ratios, same corpus and run seed: ENUM_MIN / PROMETHEUS = **0.727–0.760**;
EXH2_ENGINE / PROMETHEUS = 1.586–1.665. Within-run CPU ratio ENUM_MIN / PROMETHEUS on content 0 =
45.3/78.1, 46.9/70.4, 47.7/72.1 = **0.58, 0.67, 0.66** (loadavg 20–27). Every arm that recovers the
family reaches Φ ∪ packages recall **0.6463 at FPR 0.0** on REPLICATION. Every arm that does not
stays at Φ's 0.2927.

Content seeds 1 and 2 give the same picture; the table pools them. On content 2, PROMETHEUS spends
9 146 000 / 9 185 039 / 9 191 703 units (runs 0–2) and ENUM_MIN 6 888 619 / 6 866 310 / 6 872 163
(ratios 0.753, 0.748, 0.748; CPU 47.3/78.4, 46.3/79.8, 46.5/67.8 = 0.60, 0.58, 0.69 at loadavg
21–40). On content 1 run 0 the ratio is 0.760. The first `search_controls.py 0 1 2` aborted on
content 2 at RANDOM_512 run 0 with the ORACLE defect (§M.9; its log is in Appendix A).
`search_controls.py 2`, with crash recording added, re-ran content 2 in full.

**Offline full-family Bonferroni** (`EXH2_BONF_OFFLINE`). This is a statistical control, not a
Stage 8 configuration, because it runs outside the vault's 64-registration batch bound. All 2539
mechanisms are tested once on HOLDOUT at α/N = 1.97e-05 with the three registered rules, and the
survivors once on REPLICATION:

| content seed | HOLDOUT survivors | REPRODUCED | families | false | Φ ∪ reproduced recall / FPR | INDEPENDENT FP | with INDEPENDENT-FP ≤ 0.01 and doppelgänger ≤ 0.05 per mechanism |
|---|---|---|---|---|---|---|---|
| 0 | 315 | 315 | PM1, PM2, PM3 | 9 | 1.0000 / 0.0 | 26/120 | 229 kept (67 and 19 removed): PM1, PM3; false 6; 0.6463 / 0.0; 0/120 |
| 1 | 309 | 306 | PM1, PM2, PM3 | 0 | 1.0000 / 0.0 | 24/120 | 223 kept (64 and 19 removed): PM1, PM3; false 0; 0.6463 / 0.0; 0/120 |
| 2 | 312 | 312 | PM1, PM2, PM3 | 6 | 1.0000 / 0.0 | 23/120 | 229 kept (64 and 19 removed): PM1, PM3; false 6; 0.6463 / 0.0 |

The "false" survivors on content 0 include `CO_OCCURS(SPAWN,READ+CREDENTIAL)` and two variants. They
fire only on the trapped half of CREDENTIAL_EGRESS (agreement 0.958 with PM3): they are genuinely
trap-dependent rules.

Reading. (a) **Baseline (2) is beaten at equal spend** on this world: 0 of the 26 random runs within
PROMETHEUS's spend recover anything, and random needs ≥ 1.6× the spend to succeed at all (5 of 39
runs overall).
(b) **It is beaten by the enumerator, not by PROMETHEUS's machinery**: ENUM_MIN recovers the same
family on every run for about three quarters of the work units. The residual-motif, analogy,
null-benign, Stage 7-seed and external generators, diversity, MDL, mutation, ORACLE, priority field
and negative memory change which theories are tested (§M.5), but never which family is recovered,
and together they cost 32–38 % more work units (1/0.760 to 1/0.727). (c) Baseline (3) as the gate runs it (single-step only) cannot express
PM1 (precondition P2), so "beyond exhaustive" is a construction result. The exhaustive enumeration
of the simplest class that **can** express PM1 recovers the same family. (d) PM2 (REPEATED_EGRESS)
is recoverable by brute force without screens and is killed by its MONITORING_AGENT doppelgänger in
every screened arm, as the spec expected (§9.2). PM3 is recovered only by the offline arm; it is
the rediscovery control, and the Φ-oracle already catches it, so it adds no recall. (e) The
doppelgänger screen decides the brute-force engine (7/7 → 0/7 without it). It removes the broad
high-TRAIN-F1 rules that would otherwise fill the 64 HOLDOUT slots and all fail FPR. Yet
PROMETHEUS's ablation row shows the same screen changing no family (§M.5): a screen's value here
depends on what feeds it.

## M.4 Falsification: the trap and the null

- **Trap.** In every disciplined run (PROMETHEUS 9/9, ENUM_MIN 7/7, EXH2_ENGINE 7/7), `SINGLE(SPAWN)` is
  generated and refuted at `challenge:COUNTERFACTUAL_INVARIANCE` before registration. *(Fix wave,
  §F.1: that refutation came from DECOY_INSERTION adding non-escalating steps the trap names; it is
  not evidence of falsification.)* G8.1(d)'s
  literal "registered" clause is therefore still unmet (ADR-0073). `probe_trap_at_holdout`
  registers it alone, and it is refuted at HOLDOUT. The NAIVE control (`holdout_discipline=False,
  bonferroni=False`) selects 35 theories on TRAIN, and **the trap is among them** (checked by
  digest). NAIVE "recovers" DROP_EXEC_EGRESS and REPEATED_EGRESS with 1 false selection. The
  ablation's only JUSTIFIED row is `holdout_discipline` (§M.5).
- **Engine null** (`run_null_fdr(seeds=0..19, content_seed=0)`): the disciplined loop registered
  2–36 per seed, survived **0** and reproduced **0** on 20/20, so **FDR 0.000**. NAIVE tested
  1605–1873 and selected **0** on 20/20, so the verdict is **DEGENERATE** (identical to the gate).
  2171 s wall, 1094 s CPU, loadavg 20.4 → 20.0.
- **Whole-class null control** (`null_fdr.py` part B; the ≤ 2-step class over each null TRAIN,
  2381 mechanisms): in-sample significance only (p ≤ 0.05) admits **184, 0, 1, 30, 0, 0, 0, 11, 0,
  165, 2, 0, 139, 0, 64, 40, 0, 8, 0, 4** false mechanisms (mean 32.4, max 184, 11/20 seeds > 0).
  Adding the in-sample FPR ≤ 0.01 and recall ≥ 0.10 rules admits **0 on 20/20**. Top-64 by TRAIN F1
  at α/64 on HOLDOUT: 0 / 20. All 2381 at α/N on HOLDOUT: 0 / 20.

Reading. The engine discovers nothing on noise, which is good. But the null cannot show that the
vault or Bonferroni is what prevents it, because the registered rate rules already reject every
noise mechanism in-sample. On this corpus the vault is measured necessary for exactly one thing:
the trap.

## M.5 Does each component earn its existence?

`components.py` → `run_ablation(PLANTED content 0, RunConfig(seed=0))`, 2426 s wall, 1285 s CPU,
loadavg 25.8 → 29.1. Deltas are base − control. **The result is identical, row for row, to the
gate's ablation**:

| flag | verdict | firings | outcome changes | Δ planted | Δ false | Δ residual recall | Δ work units |
|---|---|---|---|---|---|---|---|
| holdout_discipline | **JUSTIFIED** | 34 | 69 | −1 | −1 | +0.3537 | +7 222 020 |
| residual_motif | NOT_YET_JUSTIFIED | 2 | 46 | 0 | 0 | 0.0 | +210 942 |
| diversity | NOT_YET_JUSTIFIED | 64 | 32 | 0 | 0 | 0.0 | +1 482 439 |
| mutation | NOT_YET_JUSTIFIED | 85 | 21 | 0 | 0 | 0.0 | +2 232 828 |
| mdl | NOT_YET_JUSTIFIED | 227 | 21 | 0 | 0 | 0.0 | +617 378 |
| score_full | NOT_YET_JUSTIFIED | 34 | 25 | 0 | 0 | 0.0 | +367 193 |
| oracle | NOT_YET_JUSTIFIED | 3 | 7 | 0 | 0 | 0.0 | +29 862 |
| doppelganger_screen | NOT_YET_JUSTIFIED | 117 | 30 | 0 | 0 | 0.0 | −124 347 |
| priority_field | INERT | 2 | 0 | 0 | 0 | 0.0 | 0 |
| cost_aware | INERT | 3 | 0 | 0 | 0 | 0.0 | +245 |
| eig | INERT | 3 | 0 | 0 | 0 | 0.0 | +166 |
| bonferroni | INERT | 34 | 0 | 0 | 0 | 0.0 | 0 |
| negative_memory | INERT | 0 | 0 | 0 | 0 | 0.0 | 0 |
| analogy | INERT | 0 | 0 | 0 | 0 | 0.0 | 0 |
| null_benign | INERT | 0 | 0 | 0 | 0 | 0.0 | 0 |
| stage7_seed | INERT | 0 | 0 | 0 | 0 | 0.0 | 0 |
| external_proposal | INERT | 0 | 0 | 0 | 0 | 0.0 | 0 |

`holdout_discipline`'s Δ planted of −1 means the NAIVE control "recovers" one more family
(REPEATED_EGRESS, which every screened arm kills by doppelgänger), along with the trap. The row is
JUSTIFIED on false reproduced and residual recall. Single-flag ablation cannot show redundancy
between components; the joint control is ENUM_MIN (§M.3), which switches off 14 of these 17 flags at
once (all but `doppelganger_screen`, `holdout_discipline` and `bonferroni`) and loses nothing. `stage7_seed`, `external_proposal` and `analogy` have no input in the base
configuration, so INERT here means "not exercised". `bonferroni` is INERT because no HOLDOUT
outcome in this run had a p-value between α/m and α with the rate rules passing.

**ORACLE policies** (`oracle_comparison(PLANTED 0, seeds=(0, 1, 2))`; 2557 s wall, 1373 s CPU,
loadavg 29.1 → 17.3). Each cell lists experiments / ORACLE work units / correct leading hypothesis
per run seed 0, 1, 2:

| policy | replay only (production default) | lab oracle on (`lab_oracle_authored`) |
|---|---|---|
| EIG_PER_COST | 3, 3, 3 / 43 252, 27 135, 30 080 / **0, 0, 0** | 7, 6, 7 / 157 409, 92 316, 112 155 / **1, 1, 1** |
| EIG_ONLY | 2, 2, 2 / 43 007, 27 009, 30 039 / 0, 0, 0 | 6, 5, 5 / 147 755, 91 223, 105 664 / 1, 1, 1 |
| RANDOM | 2, 3, 3 / 43 086, 27 281, 30 078 / 0, 0, 0 | 32, 25, 18 / 181 673, 123 882, 163 298 / 0, 0, 0 (budget stops) |
| CHEAPEST | 3, 3, 3 / **43 252, 27 135, 30 080** / 0, 0, 0 | 28, 27, 22 / 275 320, 177 074, 176 415 / 0, 0, 0 (budget stops) |

On replay — the production default — no policy ever leads with the planted mechanism, and
EIG_PER_COST spends **exactly** what CHEAPEST spends, so it is indistinguishable from cheap
selection: `eig_beats_cheap` = (replay_only False, lab_oracle_authored True), verdict
**NOT_YET_JUSTIFIED** (identical to the gate). ORACLE is useful only with the lab oracle, which is
the corpus author's planted predicate, i.e. ground truth by fiat (spec §9.1 item 3). Falsifier
**F8** ("ORACLE uses no fewer work units than RANDOM or CHEAPEST to the same stop") **fires on
replay**.

**Threshold sensitivity** (`threshold_sensitivity(PLANTED 0, RunConfig(seed=0))`; 648.7 s wall,
466.3 s CPU, loadavg 17.3 → 14.6):

| parameter | value | reproduced | planted | false | deployable | outcomes changed vs default |
|---|---|---|---|---|---|---|
| α | 0.01 / **0.05** / 0.10 | 19 / 19 / 19 | 1 / 1 / 1 | 0 | 1 | **0/34 / — / 0/34** |
| MDL gain per bit | 0.0 / **0.01** / 0.05 | 14 / 19 / 20 | 1 / 1 / 1 | 0 | 1 | 22/34 / — / 15/34 |
| FORGE tolerance | 0.0 / **0.02** / 0.05 | 19 / 19 / 19 | 1 / 1 / 1 | 0 | 1 | 0/1 / — / 0/1 |

No value flips every outcome (THRESHOLD_DECIDES empty). **α does not matter at all** across a 10×
range: consistent with `bonferroni` INERT and the null result of §M.4, the registered FPR and
recall rules, not the significance level, decide which theories survive. The MDL gain changes
which theories are tested but not which family is recovered.

## M.6 FORGE, and the endpoint through `run_benchmark`

The one tournament (`CO_OCCURS(WRITE,SEND)`, measured on REPLICATION; `components.py`):

| entrant | expressible | precision | recall | FPR | agreement with TYPED_RULE | work units / event | artifact bytes |
|---|---|---|---|---|---|---|---|
| TYPED_RULE (reference) | yes | 1.0 | 0.3537 | 0.0 | 1.0 | 11.03 | 2475 |
| **FSM (selected, deployable)** | yes | 1.0 | 0.3537 | 0.0 | 1.0 | **10.24** | **216** |
| MOTIF | **refused** `MOTIF_CANNOT_EXPRESS_CO_OCCURS` | — | — | — | — | — | — |
| THRESHOLD | yes | 0.0 | 0.0 | 0.0127 | 0.8708 | 5.52 | 113 |
| LOGISTIC | yes | 0.5333 | 0.1951 | 0.0886 | 0.8875 | 241.12 | 2979 |
| PROTOTYPE | yes | 0.3415 | 0.6829 | 0.6835 | 0.4375 | 278.12 | 1850 |
| STUMP_TREE | yes | 0.1818 | 0.1951 | 0.4557 | 0.6458 | 10.03 | 222 |

DCR 778 274.8. The expressibility check fires (MOTIF is refused). FORGE's own rule (preserve quality
within tolerance AND cost less) is met: the FSM equals the typed rule and is 7 % cheaper per event
and 91 % smaller. **RETRACTED (fix wave, §F.6):** both figures are self-charged work units and a
reference inflated by genome metadata; the FSM is slower than the typed rule in the same run. It is a compression of a rule that itself does not transfer (§M.2).

**Endpoint, through `run_benchmark`** (`resources.py`). REPLICATION is written as a checksum-bound
Stage 0 dataset: 240 sequences, 1324 events (one per encoded step). The case is
`stage8-counterfactual-at-boundary` with FPR budget 0.01; loadavg 22.8–23.0.

| slot | recall / FPR (threshold 0.5) | PR-AUC | CPU s / event | ratio to Φ ∪ FORGE |
|---|---|---|---|---|
| Φ-oracle | 0.2927 / 0.0 | 0.5343 | 3.07e-06 | 0.60 |
| FORGE FSM (loaded from its artefact) | 0.3537 / 0.0 | 0.5745 | 4.68e-06 | 0.91 |
| **Φ ∪ FORGE (the deployed union)** | **0.6463 / 0.0** | **0.7672** | 5.12e-06 | 1.00 |
| direct model D2 (equal information) | **1.0000 / 0.0** | **1.0000** | 2.53e-05 | **4.93** |

The harness's edge-profile check reports `within_target False` for every slot (`agent_rss 201.1 MB
> 100 MB`). That is the **measuring process**, which holds the corpus and the research run, not the
artefact. The artefact's own increment, from `measure_endpoint_footprint` over the same 240
episodes, is **4096 B incremental RSS** (idle 210 894 848 → sampled peak 210 898 944 B) at 10.24
wu/event, within the 20 MiB Stage 8 ceiling and the 100 MB edge target. Script defect disclosed: the
first `resources.py` passed `model_bytes = 9` to `run_benchmark` — the key count of the JSON
artefact mapping, not bytes. The correct size is the tournament's 216 B. The line is fixed; the
recorded `artefact_bytes: 9` in `results/stage8-bench/resources.json` is wrong and is not quoted.

## M.7 Resources and bounds

| run (`resources.py`, PLANTED 0) | idle → sampled peak RSS | incremental | CPU s | work units | loadavg |
|---|---|---|---|---|---|
| one `run_discovery` | 72 454 144 → 220 368 896 B | **147 914 752 B** | 83.48 (**8.86 µs / work unit**) | 9 417 205 | 24.9 → 23.7 |
| gate flood: 10 000 texts, 200 000 units | 208 834 560 → 208 838 656 B | 4 096 B | 8.24 | 197 142 (**budget exhausted**) | 23.7 → 23.5 |
| 10× flood: 100 000 texts, default 50 M units | 206 737 408 → 210 841 600 B | 4 104 192 B | 78.47 | 9 111 522 (not exhausted) | 23.5 → 22.6 |

- Gate flood: 32 births, 32 ledger entries, 34 lineage nodes, 9 859 texts refused, governor refusal
  `work_units: 1`. **The runaway hits the budget, not the host.**
- 10× flood under the default budget: the proposal cap refused 199 718 external texts (counted per
  cluster). Ledger 1160 entries / 352 theories and lineage 489 nodes, every store far below its cap.
  **The flood still changes outcomes**: registered 34 → 25, reproduced 19 → 18, planted recovery
  unchanged. **F14 fires under the flood** as well as under the injection suite.
- Endurance, `run_endurance(cycles=12, seed=0)`: **plateau_ok True**, 12/12 cycles. Final sizes:
  ledger entries 9191, theories 2048 (cap), negative results 1024 (cap), lineage 290, population
  256 (cap). Evictions are counted (theories folded 1749, negative evicted 1776, population evicted
  390, evicted_folded 2). Capsules created = admitted = 48. Research RSS 210 911 232 → sampled peak
  266 149 888 B (+55.2 MB); 697.2 s wall and 272.9 s CPU at loadavg 23.0 → 24.1. **Packages stop
  after cycle 6** (adapter receipts 1…6, then flat): the long-lived population fills with earlier
  cycles' theories and new candidates are evicted. The stores stay bounded but are no longer
  productive.
- Against the Stage 0 edge envelope: the deployed artefact adds 4 KB. The offline research run adds
  ~148 MB per run in this process (research may be heavier; it is not shipped). A device-side figure
  on a 2 GB target is UNMEASURED.

## M.8 The gate, re-run in this session

`PYTHONHASHSEED=0 python -m pocketsec.stage8.cli gate` → **GATE: FAILED (2), exit 1, 10/12**,
start 2026-09-27T00:01:02 at loadavg 29.78, end 01:19:36 at loadavg 3.04 (78.6 min wall; the whole
output is in Appendix A). This is the same verdict as the integration session, with every
decisive figure identical: **G8.1 FAIL** (trap `generated=True registered=False refuted=True at
challenge:COUNTERFACTUAL_INVARIANCE`); **G8.12 FAIL** (by construction, `synthetic_data True`, plus
null FDR DEGENERATE, ORACLE NOT_YET_JUSTIFIED and 16 of 17 ablation rows not JUSTIFIED); G8.2–G8.11
PASS. G8.2 reports **F14 FIRED** (with the injection suite, 7 held-out outcomes of non-injected
theories disappear and 6 appear). G8.9 reports Stage 6 buckets `{'UNCERTAIN': 8}` with a predicted
provenance score of 0.4, so realised adoption is 0 (B8-1). G8.11 reports endpoint incremental RSS
28 672 B (the gate process; `resources.py` read 4 096 B in its own process) and the whole gate
process at 281.4 MB against the 100 MB edge target (recorded, not asserted). G8.12 reports
`registry.jsonl byte-identical True`, `findings headings missing []` and `ADRs missing []`. The
gate passes 10/12 **while its own G8.12 inputs contain the saturation (NULL P5 1.0000) and the
trap-poisoned direct model (FPR 0.2532) this report identifies**: it reports them, but no criterion
reads them as a verdict on the discovery claim. That is recorded here, not re-worded in the gate.

## M.9 Defects found

1. **ORACLE aborts the research run (new; FIXED in the fix wave, §F.2).** `oracle/information_gain.py`'s `Posterior.restricted`
   raises `ContractError("restricting a posterior must keep some probability mass")` when an
   experiment's outcome eliminates every live hypothesis. `oracle/planner.py:_execute` calls it
   unguarded, and `labs/discovery_run.py:_execute` catches only `WorkBudgetExceeded`, so one ORACLE
   experiment ends the whole run with no report. Measured: **10 of 39** random-generator runs:
   8 of 25 in the curve (draw counts 768: 2/5, 1024: 1/5, 1280: 2/5, 1536: 3/5, 2048: 0/5),
   RANDOM_512 on content 2 run 0 and RANDOM_3840 on content 2 run 1. It was not observed in the 9
   default PROMETHEUS runs, the 7 ENUM_MIN runs (ORACLE off) or the brute-force runs (ORACLE off). Deterministic repro:
   `PYTHONHASHSEED=0 python benchmarks/stage8/oracle_crash_repro.py` → `RAISED
   pocketsec.stage0.contracts.common.ContractError: restricting a posterior must keep some
   probability mass`. The same config with `oracle_policy=None` completes (64 registered,
   0 reproduced, 6 531 037 units). Crashed cells in this report were re-run with ORACLE off and are
   labelled so. **Not fixed here**: this is a measurement session, and the fix changes ORACLE's
   semantics. An all-eliminated posterior should end in an UNIDENTIFIABLE/INSUFFICIENT_EVIDENCE
   stop, not an exception; that is the ORACLE owner's decision (ADR-0078 amendment).
2. **P5 is passed for the wrong reason** (§M.1). The precondition that guards against a
   vocabulary-separable corpus reads 0.90–0.92 on PLANTED only because the trap corrupts TRAIN; the
   trap-free world is 1.0000.
3. **G8.12's direct-model baseline is trap-poisoned** (§M.1; FIXED in the fix wave, §F.7). Fitted on TRAIN alone, the trap is a
   perfect feature for it; fitted on the labels the loop reads, it is perfect.
4. **Planted "recovery" is agreement over the whole split** (§M.2). It accepts any rule
   co-extensive with the family in this corpus: with 29 family members in 240 episodes, a rule that
   misses up to 4 of them still "recovers" the family.
5. **The ledger does not keep FALSIFIED theories' fits retrievable** after folding.
   `hypothesis_ids(FALSIFIED)` returned 14 ids whose TRAIN F1 came back undefined in
   `components.py`, so F7's second clause (TRAIN F1 of the HOLDOUT-killed) could not be computed.
   Its first clause decides it: kill rate 14/34 = 0.41 ≥ 0.2, so F7 does not fire.

## M.10 ADRs

Stage 8's block (0070–0079) is fully assigned and the lead forbids numbers outside it. The
rejection is therefore recorded as dated **amendments** appended to the existing verdict ADRs;
nothing in them is deleted:

- **ADR-0077**: discovery is NOT-YET-JUSTIFIED against the equal-information direct model and the
  minimal engine; the corpus is saturated; the null is DEGENERATE, and the rate rules, not the
  vault, stop noise.
- **ADR-0078**: the ORACLE crash defect and ORACLE default-off; every ecology and generator term
  default-off; the enumerator is the only generator with a measured role.
- **ADR-0079**: the statement that the direct model "pays far more work units per event at a far
  higher FPR" is retracted; FORGE's FSM is deployable by its own rule and loses on recall to the
  equal-information direct model, at 1/4.9 of its CPU per event.

## F. Fix wave (2026-09-27): confirmed review findings, fixed and re-measured

Every figure in this section was produced by a command run in the fix-wave session; each names
its command and the load average it ran at. Figures quoted from the reviewers are labelled as
theirs. Regression tests: `tests/test_stage8_regressions.py` (each docstring names its finding),
plus the updated door tests in `tests/test_stage8_forge.py`.

### F.1 The trap: where it really dies (F1)

`PYTHONHASHSEED=0 python benchmarks/stage8/trap_placement.py` (PLANTED content 0,
`RunConfig(seed=0)`), run on a copy of the pre-fix tree and on the fixed tree. Invariance is the
trap genome's agreement under each PRESERVING relation.

| tree | trap placement | decoy-relation agreement (other 4 relations) | `run_discovery` TrapOutcome | vault-alone probe | loadavg |
|---|---|---|---|---|---|
| pre-fix | `fork` → `SINGLE(SPAWN)` (authored, non-escalating) | 0.492 (1.0) | generated, not registered, refuted at `challenge:COUNTERFACTUAL_INVARIANCE` | refuted at HOLDOUT | 10.8 |
| pre-fix | `setuid uid 0` → `SINGLE(IMPERSONATE^privilege)` (escalating) | 1.0 (1.0) | **not generated** | refuted at HOLDOUT | 12.0 |
| fixed | `fork` → `SINGLE(SPAWN)` | 1.0 (1.0) | generated, **registered, refuted at HOLDOUT** | refuted at HOLDOUT | 9.7 |
| fixed | `setuid uid 0` → `SINGLE(IMPERSONATE^privilege)` | 1.0 (1.0) | **not generated** | refuted at HOLDOUT | 12.5 |

Reading. The pre-fix in-loop kill was the decoy relation's vocabulary: DECOY_INSERTION adds
non-escalating donor steps under new actors, and a SINGLE over a non-escalating step fires on such
an actor. Judged relative to the hypothesis (a decoyed world the hypothesis names is not
applicable), the trap passes every invariance relation, is registered, and **the vault** refutes
it. Placed on an escalating step the engine never generates it on either tree (why is UNMEASURED),
so the in-loop test of that placement is vacuous; the vault alone refutes it. The trap's in-loop
death now rests on the vault, for one placement, and the author confound (lesson 6) still holds:
the trap, the corpus and the engine share an author.

A consequence measured on the small test configuration (`tests/test_stage8_experiments.py`,
PLANTED content 3, SMALL budget): the counterfactual-invariance screen ran on 64 candidates and
changed **0** outcomes (it was deciding only through the decoy artefact), while the doppelgänger
screen changed 43 and the necessary-step screen 11. On that configuration the counterfactual screen
is INERT.

### F.2 ORACLE (F2, S8-RES-2)

The crash's cause was an absolute prune floor: `PRUNE_POSTERIOR` 0.01 against a group of n > 100
theories whose near-uniform posterior is below 0.01 for every member (the reviewer instrumented
n = 129, max 0.00781). Every member was written FOSSILIZED before `Posterior.restricted([])` raised.
Fix: prune below `PRUNE_POSTERIOR` × the leader's posterior (the leader always survives), restrict
before writing anything to the ledger; ORACLE default-off. The repository's crash config with ORACLE
explicitly on (content 0, run seed 1, RANDOM count 768) now completes in 7.0 s at loadavg 3.4:
groups of 56 and 129, stops `no_experiments` and `observationally_equivalent`, 1 theory pruned,
64 registered, 0 reproduced. The pre-fix tree raised `ContractError` on the regression test's
configuration.

### F.3 TheoryScore's screen terms (F3)

On the pre-fix tree, at `rank()` every kept genome's cached (falsification survival, adversarial
fragility) was (0.0, 0.0) while the ledger said (1.0, 0.0) (regression test run against the pre-fix
copy). Fixed by `HypothesisPopulation.refresh_screen_terms` after the screens run. Every genome
reaching `rank()` passed every screen, so survival is 1.0 for all and cannot reorder them; only the
fragility term can change a ranking.

### F.4 Negative memory and the ledger (F4, F5, S8-RES-1, F1-medium)

Memory is keyed by (mechanism digest, direction); a retirement never overwrites a refutation;
folded ids keep a bounded tombstone (refused re-birth; `status()` answers); a reading already tested
on a split digest cannot be preregistered on it again under another id. The reviewer's F5 probe
(three genomes, `max_theories=1`) now refuses the re-birth and keeps the dead end.

### F.5 The one door (S8-AUTH-01, S8-LIN-06)

The adapter requires the run's ledger: REPRODUCED, genome, mechanism and direction are the
ledger's. Every evidence session must be matched by the mechanism, carry the direction's lab label
and list only the package's digests; a session handed over by one run cannot be handed over by
another into the same gateway; a partial hand-over keeps a receipt. The reviewer's three cases
(8 benign non-matching sessions admitted; REPRODUCED beside a failed replication; 48 capsules from
6 runs) are each refused with nothing admitted (regression tests).

### F.6 FORGE's cost (F2, honesty lens)

"Costs less" now also requires the recorded within-run wall ratio to TYPED_RULE ≤ 1.0 (median of 9
interleaved pairs), and TYPED_RULE's bytes are its decision-relevant content. Measured on PM1
(PLANTED content 3, loadavg ~11), 20 re-measurements of the ratio at 5 pairs each:

| REPLICATION episodes | entrant | min | median | max | re-measurements > 1.0 |
|---|---|---|---|---|---|
| 60 | MOTIF | 0.745 | 0.965 | 1.004 | 1 / 20 |
| 60 | FSM | 0.91 | 1.099 | 1.309 | 18 / 20 |
| 240 | MOTIF | 0.811 | 0.959 | 1.144 | 2 / 20 |
| 240 | FSM | 0.855 | 1.081 | 1.213 | 19 / 20 |

One PM1 tournament on the 60-episode corpus (loadavg 10.2): TYPED_RULE 5.25 wu/event, 132 B
decision-relevant; MOTIF 5.25, 89 B, ratio 0.938 (**selected**); FSM 5.62, 194 B, ratio 1.086
(`not_cheaper_than_reference`). The FSM is slower than the rule it compresses; "7 % cheaper, 91 %
smaller" is RETRACTED. Selection near a ratio of 1.0 is a timing measurement and can flip between
runs. A MOTIF patched with a 200 us busy-wait is now refused `slower_than_reference` and the gate's
restatement agrees (regression test).

### F.7 Baselines (F7, F8, F11)

`search_verdict` counts a family as "beyond exhaustive" only if EXHAUSTIVE_SINGLE can express it (no
planted family is single-step without REPEATED, so none can count), and random is "beaten" only if
it spent at least as much: on this corpus the search comparison can no longer be JUSTIFIED by
construction. The direct model is fitted on TRAIN + HOLDOUT, the labels the loop reads. A BENIGN
theory gets no challenger robustness figure (it was a malicious-label recall, inverted).
Adversarial generation refuses non-synthetic telemetry (S8-DEF-07).

### F.8 Not fixed (accepted known defects)

- **One batch per held-out split across runs** (F6, S8-FALS-03): enforced per vault and per reading
  within one ledger only; the gate's many runs re-read the same HOLDOUT/REPLICATION, and defaults
  chosen from them were chosen on held-out data. A cross-run split registry is persistent state
  the stage does not write (lesson 7).
- **The ledger trusts the vault's `TestOutcome`** (S8-FALS-02); it does not recompute the rules.
- **Vacuous screens** (F12): no PROPOSED → INSUFFICIENT_EVIDENCE transition exists, and recording
  them as failures would make "unknown" a dead end (DL-06).
- **The AST boundary proof misses aliasing forms** (S8-BND-04, F4-medium): rules 6, 7, 8 and 14 are
  literal denylists; `DiscoveryLaw`'s symbol pattern admits `stage5`. Not rewritten here.
- **The endpoint footprint is measured in a warm process** (F6-medium): the 4096 B figure of §M.6
  cannot fail for a realistic artifact; a cold-process figure was not measured here.
- **The gate's only automated test runs `GateConfig.small()`** (F8-medium), where every check is
  forced to FAIL; no test asserts a full-size check's own verdict.
- **Performance** (S8-RES-3, S8-RES-4, S8-RES-5): the Reproducibility Gate re-runs metamorphic
  transforms per survivor; failure contexts are built for every survivor; the work unit does not
  track CPU or memory, and `corpus_preconditions` is unmetered. Unchanged.

### F.9 The gate and the tests, re-run after the fixes

`python -m pocketsec.stage8.cli gate` (02:47:21 → 03:24:51, 37.5 min wall, loadavg 2.66 at start,
3.75 at end, up to 10.55 during the ORACLE comparison; a full repository test run overlapped it):
**10/12, exit 1**. Changes against the integration session's 10/12:

- **G8.1 now PASSES in the loop**: trap `generated=True registered=True refuted=True at HOLDOUT`
  (§F.1). Its detail text still carries the old caveat sentence about a pre-holdout screen; the
  run it reports shows no such screen kill.
- **G8.11 now FAILS**: (c) shipped detectors **0 (VACUOUS)**. The main run's one package
  (`CO_OCCURS`, as before) has `selected=None`: MOTIF cannot express CO_OCCURS and no other entrant
  is both no-worse on bytes and work units and no slower than TYPED_RULE, so nothing compressed is
  deployable. This is the honest consequence of §F.6: the only previously shipped detector was the
  FSM that is slower than the rule. (a) flood and (b) endurance still hold: 12/12 cycles, plateau
  ok, capsules created/admitted 26/26, research RSS start 246 755 328 B, sampled peak
  322 224 128 B.
- G8.7 passes with deployable 1/2 (the lab-on run's package selects MOTIF).
- G8.12 still fails by construction. Search is **NOT_YET_JUSTIFIED** with `beats random False`
  (random spent 5.82-5.86 M work units against PROMETHEUS's 10.34-10.68 M) and `beyond exhaustive
  []`. "FORGE vs direct model" is UNMEASURED (no package selected a representation); the direct
  model, now fitted on TRAIN + HOLDOUT, reaches REPLICATION recall 1.0 at FPR 0.0 (529.6 wu/event).
  Ablation: 1 JUSTIFIED (`holdout_discipline`), 9 NOT_YET_JUSTIFIED, 7 INERT; the ORACLE rows are
  measured from the all-on base (`oracle` changed 9 outcomes, `cost_aware` and `eig` 1 each).
  ORACLE comparison: NOT_YET_JUSTIFIED (EIG beats cheap on replay False, lab-authored True).

The G8.7 detail's "LOGISTIC on TRAIN labels" label was stale after F8 and was corrected in the code
after this run; the figure it printed is the TRAIN + HOLDOUT fit.

Tests: `PYTHONHASHSEED=0 python -m pytest -q` over the whole repository (02:55:25 → 03:26:05,
loadavg 3.75 → 3.16) failed 4 tests, none of them Stage 8's: Stage 1's two gate tests (G1.12 peak
RSS 155 MB vs the 100 MB edge target, measured inside the shared pytest process while the Stage 8
gate ran), Stage 5's SENTINEL surface ratchet (1370 > 1330 lines) and Stage 9's transitive-Stage-5
boundary rule (`pocketsec/stage9/...`); Stage 5 and Stage 9 files belong to other waves and were not
touched here.

## What would change this conclusion

- **A non-saturated corpus.** Suppose a corpus exists on which the pooled order-free logistic
  model, fitted on TRAIN + HOLDOUT, stays well below AP 0.95 on REPLICATION (checked on the
  trap-free render), and on which PROMETHEUS still recovers a family. Then the direct-model verdict
  would have to be re-measured. No such corpus exists in this repository today (M0.3/M0.4 and
  §M.1).
- **A family only the full engine finds.** If, on some corpus, ENUM_MIN (or brute force through the
  same discipline) fails where PROMETHEUS succeeds at comparable spend, the non-enumerator machinery
  would have its first measured benefit. None was found in 7 content/run combinations.
- **Transfer.** A reproduced package that catches positives the Φ-oracle misses, at FPR ≤ 0.01, on
  a corpus Stage 8 did not author. On Stage 1's four corpora there is none (§M.2).
- **A non-degenerate null.** A NAIVE control that applies the same rate rules and still selects
  mechanisms on noise (for example with a larger hypothesis class or a smaller TRAIN split), while
  the disciplined loop selects none, would show that the vault/Bonferroni stop noise. On this
  corpus the rate rules alone admit 0/20.
- **ORACLE fixed, and beating cheap selection on replay**, would move it from default-off.
- **Real telemetry and a Stage 6 detector-candidate kind** (B8-1) would be needed before any of this
  is a detection result.

## Appendix A — every command, with its real output

Each block is the verbatim log the command wrote (stdout and stderr), in the order run. Long lines are the scripts' own output, unedited.

### A — `PYTHONHASHSEED=0 python benchmarks/stage8/saturation.py`

```text
### 00:11:41 planted seed 0 loadavg [33.95, 34.59, 29.76]
seed 0: P5 0.9178 trap-stripped 0.9268 phi HOLDOUT AP 0.6379 problems ()
  D0_train: REPLICATION AP 0.8684 @0.5 {'tp': 53, 'fp': 40, 'positives': 82, 'negatives': 158, 'recall': 0.6463414634146342, 'fpr': 0.25316455696202533} @fitFPR {'tp': 53, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.6463414634146342, 'fpr': 0.0}
  D1_holdout: REPLICATION AP 1.0000 @0.5 {'tp': 82, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 1.0, 'fpr': 0.0} @fitFPR {'tp': 82, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 1.0, 'fpr': 0.0}
  D2_train_plus_holdout: REPLICATION AP 1.0000 @0.5 {'tp': 82, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 1.0, 'fpr': 0.0} @fitFPR {'tp': 82, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 1.0, 'fpr': 0.0}
  D3_train_trap_stripped_ORACLE_CONTROL: REPLICATION AP 0.8395 @0.5 {'tp': 53, 'fp': 46, 'positives': 82, 'negatives': 158, 'recall': 0.6463414634146342, 'fpr': 0.2911392405063291} @fitFPR {'tp': 43, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.524390243902439, 'fpr': 0.0}
  phi: {'threshold': 0.522388, 'recall': 0.2926829268292683, 'fpr': 0.0, 'ap': 0.6379210220673635, 'missed_positives': 58}
### 00:12:31 planted seed 1 loadavg [36.33, 35.25, 30.25]
seed 1: P5 0.9049 trap-stripped 0.9157 phi HOLDOUT AP 0.6379 problems ()
  D0_train: REPLICATION AP 0.8890 @0.5 {'tp': 57, 'fp': 39, 'positives': 82, 'negatives': 158, 'recall': 0.6951219512195121, 'fpr': 0.2468354430379747} @fitFPR {'tp': 57, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.6951219512195121, 'fpr': 0.0}
  D1_holdout: REPLICATION AP 1.0000 @0.5 {'tp': 82, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 1.0, 'fpr': 0.0} @fitFPR {'tp': 82, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 1.0, 'fpr': 0.0}
  D2_train_plus_holdout: REPLICATION AP 1.0000 @0.5 {'tp': 82, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 1.0, 'fpr': 0.0} @fitFPR {'tp': 82, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 1.0, 'fpr': 0.0}
  D3_train_trap_stripped_ORACLE_CONTROL: REPLICATION AP 0.8475 @0.5 {'tp': 57, 'fp': 52, 'positives': 82, 'negatives': 158, 'recall': 0.6951219512195121, 'fpr': 0.3291139240506329} @fitFPR {'tp': 49, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.5975609756097561, 'fpr': 0.0}
  phi: {'threshold': 0.522388, 'recall': 0.2926829268292683, 'fpr': 0.0, 'ap': 0.6379210220673635, 'missed_positives': 58}
### 00:13:22 planted seed 2 loadavg [40.08, 36.49, 30.96]
seed 2: P5 0.8996 trap-stripped 0.9151 phi HOLDOUT AP 0.6379 problems ()
  D0_train: REPLICATION AP 0.8567 @0.5 {'tp': 51, 'fp': 43, 'positives': 82, 'negatives': 158, 'recall': 0.6219512195121951, 'fpr': 0.2721518987341772} @fitFPR {'tp': 51, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.6219512195121951, 'fpr': 0.0}
  D1_holdout: REPLICATION AP 1.0000 @0.5 {'tp': 82, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 1.0, 'fpr': 0.0} @fitFPR {'tp': 82, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 1.0, 'fpr': 0.0}
  D2_train_plus_holdout: REPLICATION AP 1.0000 @0.5 {'tp': 82, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 1.0, 'fpr': 0.0} @fitFPR {'tp': 82, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 1.0, 'fpr': 0.0}
  D3_train_trap_stripped_ORACLE_CONTROL: REPLICATION AP 0.7918 @0.5 {'tp': 51, 'fp': 57, 'positives': 82, 'negatives': 158, 'recall': 0.6219512195121951, 'fpr': 0.36075949367088606} @fitFPR {'tp': 39, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.47560975609756095, 'fpr': 0.0}
  phi: {'threshold': 0.522388, 'recall': 0.2926829268292683, 'fpr': 0.0, 'ap': 0.6379210220673635, 'missed_positives': 58}
### 00:14:16 null content seed 0 loadavg [43.04, 37.79, 31.69]
NULL content (trap-free) P5 1.0000; direct on REPLICATION {'fit_n': 240, 'test_n': 240, 'replication_ap': 1.0, 'at_0.5': {'tp': 82, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 1.0, 'fpr': 0.0}, 'fit_side_fpr_threshold': 0.8425162187769585, 'at_fit_fpr_budget': {'tp': 82, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 1.0, 'fpr': 0.0}}
### 00:15:01 done loadavg [45.73, 39.14, 32.43]
wrote /home/anil/Documents/Research/pocketsec/results/stage8-bench/saturation.json
exit=0
```

### A — `PYTHONHASHSEED=0 python benchmarks/stage8/search_controls.py 0 1 2`

```text
### 23:12:53 corpus seed 0 loadavg [21.51, 23.16, 17.39]
  <=2-step class over TRAIN vocabulary: 2539 mechanisms; Φ REPLICATION recall 0.2926829268292683 FPR 0.0
  EXH2_BONF_OFFLINE           N 2539 alpha/N 1.97e-05 holdout surv 315 screened out {'independent_fp': 0, 'doppelganger': 0} repro 315 recovered ['CREDENTIAL_EGRESS', 'DROP_EXEC_EGRESS', 'REPEATED_EGRESS'] false 9 Φ∪repro {'tp': 82, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 1.0, 'fpr': 0.0} indep FP 26/120 trap survived False wall 6.5s
  EXH2_BONF_OFFLINE_SCREENED  N 2539 alpha/N 1.97e-05 holdout surv 315 screened out {'independent_fp': 67, 'doppelganger': 19} repro 229 recovered ['CREDENTIAL_EGRESS', 'DROP_EXEC_EGRESS'] false 6 Φ∪repro {'tp': 53, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.6463414634146342, 'fpr': 0.0} indep FP 0/120 trap survived False wall 6.4s
  PROMETHEUS           seed 0 recovered ['DROP_EXEC_EGRESS'] false 0 births 367 reg 34 surv 20 repro 19 pkgs 1 wu 9417205 Φ∪pkg recall 0.6463414634146342 fpr 0.0 Φ∪all {'tp': 53, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.6463414634146342, 'fpr': 0.0} wall 127.5s cpu 78.1s load [[20.78, 22.88, 17.42], [22.13, 22.8, 18.09]]
  RANDOM_512           seed 0 recovered [] false 0 births 367 reg 64 surv 0 repro 0 pkgs 0 wu 5948165 Φ∪pkg recall 0.2926829268292683 fpr 0.0 Φ∪all {'tp': 24, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.2926829268292683, 'fpr': 0.0} wall 24.1s cpu 14.2s load [[22.13, 22.8, 18.09], [22.13, 22.75, 18.2]]
  RANDOM_3840          seed 0 recovered ['DROP_EXEC_EGRESS'] false 0 births 371 reg 64 surv 1 repro 1 pkgs 1 wu 23748940 Φ∪pkg recall 0.6463414634146342 fpr 0.0 Φ∪all {'tp': 53, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.6463414634146342, 'fpr': 0.0} wall 60.3s cpu 40.7s load [[22.13, 22.75, 18.2], [20.18, 22.08, 18.26]]
  ENUM_MIN             seed 0 recovered ['DROP_EXEC_EGRESS'] false 0 births 64 reg 8 surv 8 repro 8 pkgs 1 wu 6842813 Φ∪pkg recall 0.6463414634146342 fpr 0.0 Φ∪all {'tp': 53, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.6463414634146342, 'fpr': 0.0} wall 73.0s cpu 45.3s load [[20.18, 22.08, 18.26], [24.66, 22.72, 18.76]]
  EXH2_ENGINE          seed 0 recovered ['DROP_EXEC_EGRESS'] false 0 births 256 reg 64 surv 36 repro 35 pkgs 1 wu 14934378 Φ∪pkg recall 0.6463414634146342 fpr 0.0 Φ∪all {'tp': 53, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.6463414634146342, 'fpr': 0.0} wall 308.2s cpu 141.0s load [[24.66, 22.72, 18.76], [22.73, 23.95, 20.52]]
  EXH2_ENGINE_NODOPP   seed 0 recovered [] false 0 births 256 reg 64 surv 0 repro 0 pkgs 0 wu 9002485 Φ∪pkg recall 0.2926829268292683 fpr 0.0 Φ∪all {'tp': 24, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.2926829268292683, 'fpr': 0.0} wall 57.7s cpu 37.4s load [[22.73, 23.95, 20.52], [23.07, 23.89, 20.71]]
wrote /home/anil/Documents/Research/pocketsec/results/stage8-bench/search_controls.json
  PROMETHEUS           seed 1 recovered ['DROP_EXEC_EGRESS'] false 0 births 343 reg 22 surv 15 repro 14 pkgs 1 wu 9068403 Φ∪pkg recall 0.6463414634146342 fpr 0.0 Φ∪all {'tp': 53, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.6463414634146342, 'fpr': 0.0} wall 123.6s cpu 70.4s load [[23.07, 23.89, 20.71], [24.01, 23.71, 21.03]]
  RANDOM_512           seed 1 recovered [] false 0 births 353 reg 64 surv 0 repro 0 pkgs 0 wu 5988550 Φ∪pkg recall 0.2926829268292683 fpr 0.0 Φ∪all {'tp': 24, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.2926829268292683, 'fpr': 0.0} wall 20.4s cpu 14.8s load [[24.01, 23.71, 21.03], [23.48, 23.63, 21.06]]
  RANDOM_3840          seed 1 recovered [] false 0 births 360 reg 52 surv 2 repro 0 pkgs 0 wu 18461042 Φ∪pkg recall 0.2926829268292683 fpr 0.0 Φ∪all {'tp': 24, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.2926829268292683, 'fpr': 0.0} wall 57.1s cpu 32.7s load [[23.48, 23.63, 21.06], [22.19, 23.2, 21.06]]
  ENUM_MIN             seed 1 recovered ['DROP_EXEC_EGRESS'] false 0 births 64 reg 8 surv 8 repro 8 pkgs 1 wu 6852433 Φ∪pkg recall 0.6463414634146342 fpr 0.0 Φ∪all {'tp': 53, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.6463414634146342, 'fpr': 0.0} wall 80.5s cpu 46.9s load [[22.19, 23.2, 21.06], [22.32, 23.12, 21.21]]
  EXH2_ENGINE          seed 1 recovered ['DROP_EXEC_EGRESS'] false 0 births 256 reg 64 surv 40 repro 37 pkgs 1 wu 14962502 Φ∪pkg recall 0.6463414634146342 fpr 0.0 Φ∪all {'tp': 53, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.6463414634146342, 'fpr': 0.0} wall 308.2s cpu 151.0s load [[22.32, 23.12, 21.21], [25.53, 25.35, 22.74]]
  EXH2_ENGINE_NODOPP   seed 1 recovered [] false 0 births 256 reg 64 surv 0 repro 0 pkgs 0 wu 8994161 Φ∪pkg recall 0.2926829268292683 fpr 0.0 Φ∪all {'tp': 24, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.2926829268292683, 'fpr': 0.0} wall 82.1s cpu 37.6s load [[25.53, 25.35, 22.74], [25.63, 25.46, 23.01]]
wrote /home/anil/Documents/Research/pocketsec/results/stage8-bench/search_controls.json
  PROMETHEUS           seed 2 recovered ['DROP_EXEC_EGRESS'] false 0 births 348 reg 18 surv 16 repro 15 pkgs 1 wu 9062197 Φ∪pkg recall 0.6463414634146342 fpr 0.0 Φ∪all {'tp': 53, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.6463414634146342, 'fpr': 0.0} wall 176.9s cpu 72.1s load [[25.63, 25.46, 23.01], [26.22, 25.2, 23.29]]
  RANDOM_512           seed 2 recovered [] false 0 births 355 reg 64 surv 0 repro 0 pkgs 0 wu 5937876 Φ∪pkg recall 0.2926829268292683 fpr 0.0 Φ∪all {'tp': 24, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.2926829268292683, 'fpr': 0.0} wall 30.0s cpu 14.9s load [[26.22, 25.2, 23.29], [24.44, 24.87, 23.24]]
  RANDOM_3840          seed 2 recovered [] false 0 births 355 reg 64 surv 2 repro 0 pkgs 0 wu 18313239 Φ∪pkg recall 0.2926829268292683 fpr 0.0 Φ∪all {'tp': 24, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.2926829268292683, 'fpr': 0.0} wall 75.1s cpu 32.5s load [[24.44, 24.87, 23.24], [26.75, 25.54, 23.61]]
  ENUM_MIN             seed 2 recovered ['DROP_EXEC_EGRESS'] false 0 births 64 reg 8 surv 8 repro 8 pkgs 1 wu 6860157 Φ∪pkg recall 0.6463414634146342 fpr 0.0 Φ∪all {'tp': 53, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.6463414634146342, 'fpr': 0.0} wall 125.3s cpu 47.7s load [[26.75, 25.54, 23.61], [26.78, 26.62, 24.29]]
  EXH2_ENGINE          seed 2 recovered ['DROP_EXEC_EGRESS'] false 0 births 256 reg 64 surv 41 repro 39 pkgs 1 wu 14979777 Φ∪pkg recall 0.6463414634146342 fpr 0.0 Φ∪all {'tp': 53, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.6463414634146342, 'fpr': 0.0} wall 274.2s cpu 149.1s load [[26.78, 26.62, 24.29], [17.88, 21.21, 22.6]]
  EXH2_ENGINE_NODOPP   seed 2 recovered [] false 0 births 256 reg 64 surv 0 repro 0 pkgs 0 wu 9011835 Φ∪pkg recall 0.2926829268292683 fpr 0.0 Φ∪all {'tp': 24, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.2926829268292683, 'fpr': 0.0} wall 58.4s cpu 37.1s load [[17.88, 21.21, 22.6], [16.09, 20.15, 22.15]]
wrote /home/anil/Documents/Research/pocketsec/results/stage8-bench/search_controls.json
### 23:47:35 corpus seed 1 loadavg [16.09, 20.15, 22.15]
  <=2-step class over TRAIN vocabulary: 2539 mechanisms; Φ REPLICATION recall 0.2926829268292683 FPR 0.0
  EXH2_BONF_OFFLINE           N 2539 alpha/N 1.97e-05 holdout surv 309 screened out {'independent_fp': 0, 'doppelganger': 0} repro 306 recovered ['CREDENTIAL_EGRESS', 'DROP_EXEC_EGRESS', 'REPEATED_EGRESS'] false 0 Φ∪repro {'tp': 82, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 1.0, 'fpr': 0.0} indep FP 24/120 trap survived False wall 8.4s
  EXH2_BONF_OFFLINE_SCREENED  N 2539 alpha/N 1.97e-05 holdout surv 309 screened out {'independent_fp': 64, 'doppelganger': 19} repro 223 recovered ['CREDENTIAL_EGRESS', 'DROP_EXEC_EGRESS'] false 0 Φ∪repro {'tp': 53, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.6463414634146342, 'fpr': 0.0} indep FP 0/120 trap survived False wall 6.5s
  PROMETHEUS           seed 0 recovered ['DROP_EXEC_EGRESS'] false 0 births 352 reg 22 surv 14 repro 14 pkgs 1 wu 9016849 Φ∪pkg recall 0.6463414634146342 fpr 0.0 Φ∪all {'tp': 53, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.6463414634146342, 'fpr': 0.0} wall 147.8s cpu 65.3s load [[15.63, 19.71, 21.95], [21.98, 21.26, 22.22]]
  RANDOM_512           seed 0 recovered [] false 0 births 364 reg 64 surv 0 repro 0 pkgs 0 wu 6232183 Φ∪pkg recall 0.2926829268292683 fpr 0.0 Φ∪all {'tp': 24, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.2926829268292683, 'fpr': 0.0} wall 24.6s cpu 14.4s load [[21.98, 21.26, 22.22], [20.56, 20.99, 22.11]]
  RANDOM_3840          seed 0 recovered ['DROP_EXEC_EGRESS'] false 0 births 380 reg 64 surv 1 repro 1 pkgs 1 wu 23773610 Φ∪pkg recall 0.6463414634146342 fpr 0.0 Φ∪all {'tp': 53, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.6463414634146342, 'fpr': 0.0} wall 67.2s cpu 41.3s load [[20.56, 20.99, 22.11], [19.67, 20.62, 21.9]]
  ENUM_MIN             seed 0 recovered ['DROP_EXEC_EGRESS'] false 0 births 64 reg 8 surv 8 repro 7 pkgs 1 wu 6848310 Φ∪pkg recall 0.6463414634146342 fpr 0.0 Φ∪all {'tp': 53, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.6463414634146342, 'fpr': 0.0} wall 83.9s cpu 46.8s load [[19.67, 20.62, 21.9], [19.31, 20.47, 21.75]]
  EXH2_ENGINE          seed 0 recovered ['DROP_EXEC_EGRESS'] false 0 births 256 reg 64 surv 36 repro 35 pkgs 1 wu 15011586 Φ∪pkg recall 0.6463414634146342 fpr 0.0 Φ∪all {'tp': 53, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.6463414634146342, 'fpr': 0.0} wall 207.6s cpu 138.7s load [[19.31, 20.47, 21.75], [21.65, 19.92, 21.17]]
  EXH2_ENGINE_NODOPP   seed 0 recovered [] false 0 births 256 reg 64 surv 0 repro 0 pkgs 0 wu 9077181 Φ∪pkg recall 0.2926829268292683 fpr 0.0 Φ∪all {'tp': 24, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.2926829268292683, 'fpr': 0.0} wall 72.8s cpu 37.8s load [[21.65, 19.92, 21.17], [23.51, 20.89, 21.42]]
wrote /home/anil/Documents/Research/pocketsec/results/stage8-bench/search_controls.json
### 23:58:02 corpus seed 2 loadavg [23.51, 20.89, 21.42]
  <=2-step class over TRAIN vocabulary: 2539 mechanisms; Φ REPLICATION recall 0.2926829268292683 FPR 0.0
  EXH2_BONF_OFFLINE           N 2539 alpha/N 1.97e-05 holdout surv 312 screened out {'independent_fp': 0, 'doppelganger': 0} repro 312 recovered ['CREDENTIAL_EGRESS', 'DROP_EXEC_EGRESS', 'REPEATED_EGRESS'] false 6 Φ∪repro {'tp': 82, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 1.0, 'fpr': 0.0} indep FP 23/120 trap survived False wall 11.5s
  EXH2_BONF_OFFLINE_SCREENED  N 2539 alpha/N 1.97e-05 holdout surv 312 screened out {'independent_fp': 64, 'doppelganger': 19} repro 229 recovered ['CREDENTIAL_EGRESS', 'DROP_EXEC_EGRESS'] false 6 Φ∪repro {'tp': 53, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.6463414634146342, 'fpr': 0.0} indep FP 0/120 trap survived False wall 11.8s
  PROMETHEUS           seed 0 recovered ['DROP_EXEC_EGRESS'] false 0 births 354 reg 26 surv 20 repro 19 pkgs 1 wu 9146000 Φ∪pkg recall 0.6463414634146342 fpr 0.0 Φ∪all {'tp': 53, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.6463414634146342, 'fpr': 0.0} wall 158.5s cpu 78.4s load [[25.88, 21.76, 21.69], [30.28, 24.42, 22.65]]
Traceback (most recent call last):
  File "/home/anil/Documents/Research/pocketsec/benchmarks/stage8/search_controls.py", line 385, in <module>
    main(cseeds, [0, 1, 2])
    ~~~~^^^^^^^^^^^^^^^^^^^
  File "/home/anil/Documents/Research/pocketsec/benchmarks/stage8/search_controls.py", line 356, in main
    rows.append(run_arm("RANDOM_512", corpus,
                ~~~~~~~^^^^^^^^^^^^^^^^^^^^^^
                        replace(base, generators=(GeneratorKind.RANDOM_BASELINE,)), phi))
                        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/anil/Documents/Research/pocketsec/benchmarks/stage8/search_controls.py", line 160, in run_arm
    report = dr._execute(corpus, config, gateway=None, knobs=knobs or dr._Knobs(), stores=None)
  File "/home/anil/Documents/Research/pocketsec/pocketsec/stage8/labs/discovery_run.py", line 1040, in _execute
    _drive(run)
    ~~~~~~^^^^^
  File "/home/anil/Documents/Research/pocketsec/pocketsec/stage8/labs/discovery_run.py", line 1052, in _drive
    registered = run.rank(run.run_oracle(run.screen(candidates)))
                          ~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/anil/Documents/Research/pocketsec/pocketsec/stage8/labs/discovery_run.py", line 640, in run_oracle
    report = planner.run(group, self.lab_pool, visibility_share=share)
  File "/home/anil/Documents/Research/pocketsec/pocketsec/stage8/oracle/planner.py", line 491, in run
    self._loop(state)
    ~~~~~~~~~~^^^^^^^
  File "/home/anil/Documents/Research/pocketsec/pocketsec/stage8/oracle/planner.py", line 515, in _loop
    self._execute(state, plan, scored[index][1])
    ~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/anil/Documents/Research/pocketsec/pocketsec/stage8/oracle/planner.py", line 542, in _execute
    state.posterior = posterior.restricted(survivors) if survivors != list(alive) else posterior
                      ~~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^
  File "/home/anil/Documents/Research/pocketsec/pocketsec/stage8/oracle/information_gain.py", line 108, in restricted
    raise ContractError("restricting a posterior must keep some probability mass")
pocketsec.stage0.contracts.common.ContractError: restricting a posterior must keep some probability mass
exit=1
```

### A — `PYTHONHASHSEED=0 python benchmarks/stage8/search_controls.py 2`

```text
### 00:02:20 corpus seed 2 loadavg [36.87, 26.94, 23.62]
  <=2-step class over TRAIN vocabulary: 2539 mechanisms; Φ REPLICATION recall 0.2926829268292683 FPR 0.0
  EXH2_BONF_OFFLINE           N 2539 alpha/N 1.97e-05 holdout surv 312 screened out {'independent_fp': 0, 'doppelganger': 0} repro 312 recovered ['CREDENTIAL_EGRESS', 'DROP_EXEC_EGRESS', 'REPEATED_EGRESS'] false 6 Φ∪repro {'tp': 82, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 1.0, 'fpr': 0.0} indep FP 23/120 trap survived False wall 11.8s
  EXH2_BONF_OFFLINE_SCREENED  N 2539 alpha/N 1.97e-05 holdout surv 312 screened out {'independent_fp': 64, 'doppelganger': 19} repro 229 recovered ['CREDENTIAL_EGRESS', 'DROP_EXEC_EGRESS'] false 6 Φ∪repro {'tp': 53, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.6463414634146342, 'fpr': 0.0} indep FP 0/120 trap survived False wall 11.4s
  PROMETHEUS           seed 0 recovered ['DROP_EXEC_EGRESS'] false 0 births 354 reg 26 surv 20 repro 19 pkgs 1 wu 9146000 Φ∪pkg recall 0.6463414634146342 fpr 0.0 Φ∪all {'tp': 53, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.6463414634146342, 'fpr': 0.0} wall 181.9s cpu 78.4s load [[40.16, 28.99, 24.43], [38.3, 34.4, 27.38]]
  RANDOM_512           seed 0 CRASHED ContractError: restricting a posterior must keep some probability mass; re-running with oracle_policy=None
  RANDOM_512_ORACLE_OFF_AFTER_CRASH seed 0 recovered [] false 0 births 364 reg 64 surv 0 repro 0 pkgs 0 wu 5880627 Φ∪pkg recall 0.2926829268292683 fpr 0.0 Φ∪all {'tp': 24, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.2926829268292683, 'fpr': 0.0} wall 26.8s cpu 14.4s load [[35.43, 34.04, 27.48], [34.34, 33.83, 27.58]]
  RANDOM_3840          seed 0 recovered ['DROP_EXEC_EGRESS'] false 0 births 382 reg 64 surv 1 repro 1 pkgs 1 wu 24054204 Φ∪pkg recall 0.6463414634146342 fpr 0.0 Φ∪all {'tp': 53, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.6463414634146342, 'fpr': 0.0} wall 78.4s cpu 41.5s load [[34.34, 33.83, 27.58], [40.43, 35.84, 28.81]]
  ENUM_MIN             seed 0 recovered ['DROP_EXEC_EGRESS'] false 0 births 64 reg 8 surv 8 repro 8 pkgs 1 wu 6888619 Φ∪pkg recall 0.6463414634146342 fpr 0.0 Φ∪all {'tp': 53, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.6463414634146342, 'fpr': 0.0} wall 93.6s cpu 47.3s load [[40.43, 35.84, 28.81], [36.97, 36.11, 29.57]]
  EXH2_ENGINE          seed 0 recovered ['DROP_EXEC_EGRESS'] false 0 births 256 reg 64 surv 36 repro 35 pkgs 1 wu 15060167 Φ∪pkg recall 0.6463414634146342 fpr 0.0 Φ∪all {'tp': 53, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.6463414634146342, 'fpr': 0.0} wall 343.3s cpu 142.2s load [[36.97, 36.11, 29.57], [42.97, 39.02, 32.57]]
  EXH2_ENGINE_NODOPP   seed 0 recovered [] false 0 births 256 reg 64 surv 0 repro 0 pkgs 0 wu 9104031 Φ∪pkg recall 0.2926829268292683 fpr 0.0 Φ∪all {'tp': 24, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.2926829268292683, 'fpr': 0.0} wall 88.2s cpu 38.5s load [[42.97, 39.02, 32.57], [36.23, 38.08, 32.86]]
wrote /home/anil/Documents/Research/pocketsec/results/stage8-bench/search_controls_2.json
  PROMETHEUS           seed 1 recovered ['DROP_EXEC_EGRESS'] false 0 births 344 reg 25 surv 20 repro 19 pkgs 1 wu 9185039 Φ∪pkg recall 0.6463414634146342 fpr 0.0 Φ∪all {'tp': 53, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.6463414634146342, 'fpr': 0.0} wall 142.3s cpu 79.8s load [[36.23, 38.08, 32.86], [27.35, 34.75, 32.41]]
  RANDOM_512           seed 1 recovered [] false 0 births 342 reg 64 surv 0 repro 0 pkgs 0 wu 5868078 Φ∪pkg recall 0.2926829268292683 fpr 0.0 Φ∪all {'tp': 24, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.2926829268292683, 'fpr': 0.0} wall 20.7s cpu 14.4s load [[27.35, 34.75, 32.41], [25.56, 33.87, 32.18]]
  RANDOM_3840          seed 1 CRASHED ContractError: restricting a posterior must keep some probability mass; re-running with oracle_policy=None
  RANDOM_3840_ORACLE_OFF_AFTER_CRASH seed 1 recovered [] false 0 births 347 reg 64 surv 4 repro 0 pkgs 0 wu 18394771 Φ∪pkg recall 0.2926829268292683 fpr 0.0 Φ∪all {'tp': 24, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.2926829268292683, 'fpr': 0.0} wall 58.0s cpu 34.3s load [[21.24, 31.89, 31.58], [23.88, 30.43, 31.08]]
  ENUM_MIN             seed 1 recovered ['DROP_EXEC_EGRESS'] false 0 births 64 reg 8 surv 8 repro 7 pkgs 1 wu 6866310 Φ∪pkg recall 0.6463414634146342 fpr 0.0 Φ∪all {'tp': 53, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.6463414634146342, 'fpr': 0.0} wall 70.7s cpu 46.3s load [[23.88, 30.43, 31.08], [22.48, 28.79, 30.47]]
  EXH2_ENGINE          seed 1 recovered ['DROP_EXEC_EGRESS'] false 0 births 256 reg 64 surv 40 repro 37 pkgs 1 wu 15099448 Φ∪pkg recall 0.6463414634146342 fpr 0.0 Φ∪all {'tp': 53, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.6463414634146342, 'fpr': 0.0} wall 271.0s cpu 152.2s load [[22.48, 28.79, 30.47], [22.92, 26.74, 29.26]]
  EXH2_ENGINE_NODOPP   seed 1 recovered [] false 0 births 256 reg 64 surv 0 repro 0 pkgs 0 wu 9093965 Φ∪pkg recall 0.2926829268292683 fpr 0.0 Φ∪all {'tp': 24, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.2926829268292683, 'fpr': 0.0} wall 68.9s cpu 38.3s load [[22.92, 26.74, 29.26], [20.82, 25.28, 28.57]]
wrote /home/anil/Documents/Research/pocketsec/results/stage8-bench/search_controls_2.json
  PROMETHEUS           seed 2 recovered ['DROP_EXEC_EGRESS'] false 0 births 357 reg 20 surv 14 repro 14 pkgs 1 wu 9191703 Φ∪pkg recall 0.6463414634146342 fpr 0.0 Φ∪all {'tp': 53, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.6463414634146342, 'fpr': 0.0} wall 126.8s cpu 67.8s load [[20.82, 25.28, 28.57], [23.01, 24.5, 27.85]]
  RANDOM_512           seed 2 recovered [] false 0 births 350 reg 64 surv 0 repro 0 pkgs 0 wu 5933085 Φ∪pkg recall 0.2926829268292683 fpr 0.0 Φ∪all {'tp': 24, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.2926829268292683, 'fpr': 0.0} wall 53.4s cpu 14.8s load [[23.01, 24.5, 27.85], [28.58, 25.76, 28.08]]
  RANDOM_3840          seed 2 recovered [] false 0 births 366 reg 64 surv 2 repro 0 pkgs 0 wu 18575091 Φ∪pkg recall 0.2926829268292683 fpr 0.0 Φ∪all {'tp': 24, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.2926829268292683, 'fpr': 0.0} wall 70.3s cpu 32.5s load [[28.58, 25.76, 28.08], [25.34, 25.35, 27.77]]
  ENUM_MIN             seed 2 recovered ['DROP_EXEC_EGRESS'] false 0 births 64 reg 8 surv 8 repro 7 pkgs 1 wu 6872163 Φ∪pkg recall 0.6463414634146342 fpr 0.0 Φ∪all {'tp': 53, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.6463414634146342, 'fpr': 0.0} wall 90.9s cpu 46.5s load [[25.34, 25.35, 27.77], [22.14, 24.55, 27.27]]
  EXH2_ENGINE          seed 2 recovered ['DROP_EXEC_EGRESS'] false 0 births 256 reg 64 surv 41 repro 39 pkgs 1 wu 15111779 Φ∪pkg recall 0.6463414634146342 fpr 0.0 Φ∪all {'tp': 53, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.6463414634146342, 'fpr': 0.0} wall 261.3s cpu 153.6s load [[22.14, 24.55, 27.27], [15.76, 19.88, 24.65]]
  EXH2_ENGINE_NODOPP   seed 2 recovered [] false 0 births 256 reg 64 surv 0 repro 0 pkgs 0 wu 9129649 Φ∪pkg recall 0.2926829268292683 fpr 0.0 Φ∪all {'tp': 24, 'fp': 0, 'positives': 82, 'negatives': 158, 'recall': 0.2926829268292683, 'fpr': 0.0} wall 59.6s cpu 38.7s load [[15.76, 19.88, 24.65], [18.27, 19.73, 24.29]]
wrote /home/anil/Documents/Research/pocketsec/results/stage8-bench/search_controls_2.json
### 00:39:03 done loadavg [18.27, 19.73, 24.29]
wrote /home/anil/Documents/Research/pocketsec/results/stage8-bench/search_controls_2.json
exit=0
```

### A — `PYTHONHASHSEED=0 python benchmarks/stage8/random_curve.py   (first attempt: PROMETHEUS runs 3-4, then the ORACLE crash)`

```text
### 23:17:30 PROMETHEUS seeds 3, 4 (seeds 0-2 are in search_controls) loadavg [21.22, 22.01, 18.43]
  PROMETHEUS seed 3: {'seed': 3, 'recovered': ['DROP_EXEC_EGRESS'], 'false_reproduced': 0, 'reproduced': 12, 'work_units': 8919244, 'exhausted': False, 'wall_s': 139.05741316900094, 'cpu_s': 62.65485501599999, 'loadavg': [[21.22, 22.01, 18.43], [25.61, 23.7, 19.59]]}
  PROMETHEUS seed 4: {'seed': 4, 'recovered': ['DROP_EXEC_EGRESS'], 'false_reproduced': 0, 'reproduced': 15, 'work_units': 9128516, 'exhausted': False, 'wall_s': 170.7773960209961, 'cpu_s': 73.103068239, 'loadavg': [[25.61, 23.7, 19.59], [23.67, 24.18, 20.5]]}
### 23:22:40 RANDOM count 768 loadavg [23.67, 24.18, 20.5]
  RANDOM 768 seed 0: recovered [] false 0 wu 6847298 wall 25.1s load [[23.67, 24.18, 20.5], [22.73, 23.95, 20.52]]
Traceback (most recent call last):
  File "/home/anil/Documents/Research/pocketsec/benchmarks/stage8/random_curve.py", line 71, in <module>
    main()
    ~~~~^^
  File "/home/anil/Documents/Research/pocketsec/benchmarks/stage8/random_curve.py", line 56, in main
    row = one(corpus, replace(base, seed=seed,
                              generators=(GeneratorKind.RANDOM_BASELINE,)))
  File "/home/anil/Documents/Research/pocketsec/benchmarks/stage8/random_curve.py", line 32, in one
    r = dr.run_discovery(corpus, config)
  File "/home/anil/Documents/Research/pocketsec/pocketsec/stage8/labs/discovery_run.py", line 1031, in run_discovery
    return _execute(corpus, config, gateway=gateway, knobs=_Knobs(), stores=None)
  File "/home/anil/Documents/Research/pocketsec/pocketsec/stage8/labs/discovery_run.py", line 1040, in _execute
    _drive(run)
    ~~~~~~^^^^^
  File "/home/anil/Documents/Research/pocketsec/pocketsec/stage8/labs/discovery_run.py", line 1052, in _drive
    registered = run.rank(run.run_oracle(run.screen(candidates)))
                          ~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/anil/Documents/Research/pocketsec/pocketsec/stage8/labs/discovery_run.py", line 640, in run_oracle
    report = planner.run(group, self.lab_pool, visibility_share=share)
  File "/home/anil/Documents/Research/pocketsec/pocketsec/stage8/oracle/planner.py", line 491, in run
    self._loop(state)
    ~~~~~~~~~~^^^^^^^
  File "/home/anil/Documents/Research/pocketsec/pocketsec/stage8/oracle/planner.py", line 515, in _loop
    self._execute(state, plan, scored[index][1])
    ~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/anil/Documents/Research/pocketsec/pocketsec/stage8/oracle/planner.py", line 542, in _execute
    state.posterior = posterior.restricted(survivors) if survivors != list(alive) else posterior
                      ~~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^
  File "/home/anil/Documents/Research/pocketsec/pocketsec/stage8/oracle/information_gain.py", line 108, in restricted
    raise ContractError("restricting a posterior must keep some probability mass")
pocketsec.stage0.contracts.common.ContractError: restricting a posterior must keep some probability mass
exit=1
```

### A — `PYTHONHASHSEED=0 python benchmarks/stage8/random_curve.py --random-only`

```text
### 23:33:50 PROMETHEUS seeds 3, 4 (seeds 0-2 are in search_controls) loadavg [25.53, 25.35, 22.74]
### 23:33:50 RANDOM count 768 loadavg [25.53, 25.35, 22.74]
  RANDOM 768 seed 0: crashed None recovered [] false 0 wu 6847298 wall 30.0s load [[25.53, 25.35, 22.74], [26.46, 25.6, 22.9]]
  RANDOM 768 seed 1: crashed ContractError: restricting a posterior must keep some probability mass recovered [] false 0 wu 6531037 wall 36.5s load [[25.42, 25.42, 22.93], [25.66, 25.48, 23.04]]
  RANDOM 768 seed 2: crashed None recovered [] false 0 wu 7062418 wall 37.7s load [[25.66, 25.48, 23.04], [23.82, 25.06, 22.99]]
  RANDOM 768 seed 3: crashed None recovered [] false 0 wu 7046206 wall 33.4s load [[23.82, 25.06, 22.99], [21.92, 24.45, 22.86]]
  RANDOM 768 seed 4: crashed ContractError: restricting a posterior must keep some probability mass recovered [] false 0 wu 6663054 wall 40.9s load [[24.08, 24.73, 23.03], [26.04, 25.14, 23.25]]
wrote /home/anil/Documents/Research/pocketsec/results/stage8-bench/random_curve_random.json
### 23:38:00 RANDOM count 1024 loadavg [26.04, 25.14, 23.25]
  RANDOM 1024 seed 0: crashed None recovered [] false 0 wu 7812484 wall 36.7s load [[26.04, 25.14, 23.25], [24.57, 24.9, 23.24]]
  RANDOM 1024 seed 1: crashed None recovered [] false 0 wu 7822924 wall 35.7s load [[24.57, 24.9, 23.24], [26.79, 25.39, 23.46]]
  RANDOM 1024 seed 2: crashed None recovered [] false 0 wu 7870697 wall 35.4s load [[26.79, 25.39, 23.46], [25.81, 25.32, 23.52]]
  RANDOM 1024 seed 3: crashed None recovered [] false 0 wu 7813429 wall 44.0s load [[25.81, 25.32, 23.52], [30.99, 26.7, 24.06]]
  RANDOM 1024 seed 4: crashed ContractError: restricting a posterior must keep some probability mass recovered [] false 0 wu 7673128 wall 52.0s load [[29.72, 26.82, 24.2], [26.78, 26.62, 24.29]]
wrote /home/anil/Documents/Research/pocketsec/results/stage8-bench/random_curve_random.json
### 23:42:00 RANDOM count 1280 loadavg [26.78, 26.62, 24.29]
  RANDOM 1280 seed 0: crashed None recovered [] false 0 wu 8694798 wall 46.4s load [[26.78, 26.62, 24.29], [23.34, 25.73, 24.1]]
  RANDOM 1280 seed 1: crashed ContractError: restricting a posterior must keep some probability mass recovered [] false 0 wu 8517625 wall 33.7s load [[20.48, 24.72, 23.83], [18.12, 23.74, 23.53]]
  RANDOM 1280 seed 2: crashed None recovered [] false 0 wu 8850291 wall 35.7s load [[18.12, 23.74, 23.53], [19.85, 23.51, 23.46]]
  RANDOM 1280 seed 3: crashed ContractError: restricting a posterior must keep some probability mass recovered [] false 0 wu 8667791 wall 32.5s load [[17.53, 22.53, 23.13], [17.0, 21.92, 22.91]]
  RANDOM 1280 seed 4: crashed None recovered [] false 0 wu 8850038 wall 30.4s load [[17.0, 21.92, 22.91], [17.18, 21.45, 22.72]]
wrote /home/anil/Documents/Research/pocketsec/results/stage8-bench/random_curve_random.json
### 23:46:10 RANDOM count 1536 loadavg [17.18, 21.45, 22.72]
  RANDOM 1536 seed 0: crashed None recovered ['DROP_EXEC_EGRESS'] false 0 wu 15054002 wall 64.7s load [[17.18, 21.45, 22.72], [16.79, 20.56, 22.33]]
  RANDOM 1536 seed 1: crashed ContractError: restricting a posterior must keep some probability mass recovered [] false 0 wu 9692536 wall 33.8s load [[15.62, 19.92, 22.05], [15.72, 19.48, 21.83]]
  RANDOM 1536 seed 2: crashed None recovered [] false 0 wu 9750770 wall 46.9s load [[15.72, 19.48, 21.83], [22.12, 20.56, 22.08]]
  RANDOM 1536 seed 3: crashed ContractError: restricting a posterior must keep some probability mass recovered [] false 0 wu 9780035 wall 40.9s load [[24.55, 21.57, 22.36], [21.54, 21.18, 22.19]]
  RANDOM 1536 seed 4: crashed ContractError: restricting a posterior must keep some probability mass recovered [] false 0 wu 9490280 wall 29.5s load [[20.58, 20.96, 22.08], [19.74, 20.73, 21.97]]
wrote /home/anil/Documents/Research/pocketsec/results/stage8-bench/random_curve_random.json
### 23:51:34 RANDOM count 2048 loadavg [19.74, 20.73, 21.97]
  RANDOM 2048 seed 0: crashed None recovered ['DROP_EXEC_EGRESS'] false 0 wu 16913491 wall 72.0s load [[19.74, 20.73, 21.97], [20.87, 20.84, 21.91]]
  RANDOM 2048 seed 1: crashed None recovered [] false 0 wu 11547052 wall 35.0s load [[20.87, 20.84, 21.91], [18.81, 20.35, 21.7]]
  RANDOM 2048 seed 2: crashed None recovered [] false 0 wu 11720215 wall 35.6s load [[18.81, 20.35, 21.7], [18.26, 19.99, 21.53]]
  RANDOM 2048 seed 3: crashed None recovered [] false 0 wu 11779823 wall 26.5s load [[18.26, 19.99, 21.53], [16.43, 19.43, 21.3]]
  RANDOM 2048 seed 4: crashed None recovered [] false 0 wu 11641987 wall 26.8s load [[16.43, 19.43, 21.3], [16.7, 19.26, 21.2]]
wrote /home/anil/Documents/Research/pocketsec/results/stage8-bench/random_curve_random.json
### 23:54:50 done loadavg [16.7, 19.26, 21.2]
wrote /home/anil/Documents/Research/pocketsec/results/stage8-bench/random_curve_random.json
exit=0
```

### A — `PYTHONHASHSEED=0 python benchmarks/stage8/null_fdr.py`

```text
### 23:13:30 part B: whole <=2-step class under 20 null label draws loadavg [21.25, 22.88, 17.54]
  null seed  0: N 2381 naive_p 184 naive_rules 0 top64 HOLDOUT 0 REPL 0 | all HOLDOUT 0 REPL 0
  null seed  1: N 2381 naive_p 0 naive_rules 0 top64 HOLDOUT 0 REPL 0 | all HOLDOUT 0 REPL 0
  null seed  2: N 2381 naive_p 1 naive_rules 0 top64 HOLDOUT 0 REPL 0 | all HOLDOUT 0 REPL 0
  null seed  3: N 2381 naive_p 30 naive_rules 0 top64 HOLDOUT 0 REPL 0 | all HOLDOUT 0 REPL 0
  null seed  4: N 2381 naive_p 0 naive_rules 0 top64 HOLDOUT 0 REPL 0 | all HOLDOUT 0 REPL 0
  null seed  5: N 2381 naive_p 0 naive_rules 0 top64 HOLDOUT 0 REPL 0 | all HOLDOUT 0 REPL 0
  null seed  6: N 2381 naive_p 0 naive_rules 0 top64 HOLDOUT 0 REPL 0 | all HOLDOUT 0 REPL 0
  null seed  7: N 2381 naive_p 11 naive_rules 0 top64 HOLDOUT 0 REPL 0 | all HOLDOUT 0 REPL 0
  null seed  8: N 2381 naive_p 0 naive_rules 0 top64 HOLDOUT 0 REPL 0 | all HOLDOUT 0 REPL 0
  null seed  9: N 2381 naive_p 165 naive_rules 0 top64 HOLDOUT 0 REPL 0 | all HOLDOUT 0 REPL 0
  null seed 10: N 2381 naive_p 2 naive_rules 0 top64 HOLDOUT 0 REPL 0 | all HOLDOUT 0 REPL 0
  null seed 11: N 2381 naive_p 0 naive_rules 0 top64 HOLDOUT 0 REPL 0 | all HOLDOUT 0 REPL 0
  null seed 12: N 2381 naive_p 139 naive_rules 0 top64 HOLDOUT 0 REPL 0 | all HOLDOUT 0 REPL 0
  null seed 13: N 2381 naive_p 0 naive_rules 0 top64 HOLDOUT 0 REPL 0 | all HOLDOUT 0 REPL 0
  null seed 14: N 2381 naive_p 64 naive_rules 0 top64 HOLDOUT 0 REPL 0 | all HOLDOUT 0 REPL 0
  null seed 15: N 2381 naive_p 40 naive_rules 0 top64 HOLDOUT 0 REPL 0 | all HOLDOUT 0 REPL 0
  null seed 16: N 2381 naive_p 0 naive_rules 0 top64 HOLDOUT 0 REPL 0 | all HOLDOUT 0 REPL 0
  null seed 17: N 2381 naive_p 8 naive_rules 0 top64 HOLDOUT 0 REPL 0 | all HOLDOUT 0 REPL 0
  null seed 18: N 2381 naive_p 0 naive_rules 0 top64 HOLDOUT 0 REPL 0 | all HOLDOUT 0 REPL 0
  null seed 19: N 2381 naive_p 4 naive_rules 0 top64 HOLDOUT 0 REPL 0 | all HOLDOUT 0 REPL 0
wrote /home/anil/Documents/Research/pocketsec/results/stage8-bench/null_fdr.json
### 23:16:54 part A: run_null_fdr (engine, disciplined vs NAIVE) loadavg [20.38, 22.03, 18.3]
part A: disciplined mean reproduced 0.000 (any 0.000); NAIVE mean selected 0.000 (any 0.000); verdict DEGENERATE; wall 2171.2s cpu 1094.3s
  {'label_seed': 0, 'registered': 19, 'survived': 0, 'reproduced': 0, 'naive_tested': 1870, 'naive_selected': 0, 'budget_exhausted': False}
  {'label_seed': 1, 'registered': 6, 'survived': 0, 'reproduced': 0, 'naive_tested': 1856, 'naive_selected': 0, 'budget_exhausted': False}
  {'label_seed': 2, 'registered': 10, 'survived': 0, 'reproduced': 0, 'naive_tested': 1866, 'naive_selected': 0, 'budget_exhausted': False}
  {'label_seed': 3, 'registered': 31, 'survived': 0, 'reproduced': 0, 'naive_tested': 1605, 'naive_selected': 0, 'budget_exhausted': False}
  {'label_seed': 4, 'registered': 28, 'survived': 0, 'reproduced': 0, 'naive_tested': 1683, 'naive_selected': 0, 'budget_exhausted': False}
  {'label_seed': 5, 'registered': 9, 'survived': 0, 'reproduced': 0, 'naive_tested': 1733, 'naive_selected': 0, 'budget_exhausted': False}
  {'label_seed': 6, 'registered': 12, 'survived': 0, 'reproduced': 0, 'naive_tested': 1846, 'naive_selected': 0, 'budget_exhausted': False}
  {'label_seed': 7, 'registered': 10, 'survived': 0, 'reproduced': 0, 'naive_tested': 1753, 'naive_selected': 0, 'budget_exhausted': False}
  {'label_seed': 8, 'registered': 28, 'survived': 0, 'reproduced': 0, 'naive_tested': 1738, 'naive_selected': 0, 'budget_exhausted': False}
  {'label_seed': 9, 'registered': 36, 'survived': 0, 'reproduced': 0, 'naive_tested': 1860, 'naive_selected': 0, 'budget_exhausted': False}
  {'label_seed': 10, 'registered': 5, 'survived': 0, 'reproduced': 0, 'naive_tested': 1720, 'naive_selected': 0, 'budget_exhausted': False}
  {'label_seed': 11, 'registered': 13, 'survived': 0, 'reproduced': 0, 'naive_tested': 1783, 'naive_selected': 0, 'budget_exhausted': False}
  {'label_seed': 12, 'registered': 2, 'survived': 0, 'reproduced': 0, 'naive_tested': 1743, 'naive_selected': 0, 'budget_exhausted': False}
  {'label_seed': 13, 'registered': 25, 'survived': 0, 'reproduced': 0, 'naive_tested': 1854, 'naive_selected': 0, 'budget_exhausted': False}
  {'label_seed': 14, 'registered': 22, 'survived': 0, 'reproduced': 0, 'naive_tested': 1867, 'naive_selected': 0, 'budget_exhausted': False}
  {'label_seed': 15, 'registered': 17, 'survived': 0, 'reproduced': 0, 'naive_tested': 1833, 'naive_selected': 0, 'budget_exhausted': False}
  {'label_seed': 16, 'registered': 28, 'survived': 0, 'reproduced': 0, 'naive_tested': 1873, 'naive_selected': 0, 'budget_exhausted': False}
  {'label_seed': 17, 'registered': 15, 'survived': 0, 'reproduced': 0, 'naive_tested': 1627, 'naive_selected': 0, 'budget_exhausted': False}
  {'label_seed': 18, 'registered': 9, 'survived': 0, 'reproduced': 0, 'naive_tested': 1859, 'naive_selected': 0, 'budget_exhausted': False}
  {'label_seed': 19, 'registered': 17, 'survived': 0, 'reproduced': 0, 'naive_tested': 1722, 'naive_selected': 0, 'budget_exhausted': False}
### 23:53:05 done loadavg [19.99, 20.65, 21.83]
wrote /home/anil/Documents/Research/pocketsec/results/stage8-bench/null_fdr.json
exit=0
```

### A — `PYTHONHASHSEED=0 python benchmarks/stage8/transfer.py`

```text
### 23:15:51 fit artefacts on PLANTED seed 0 loadavg [21.18, 22.53, 18.18]
  packages ['CO_OCCURS(WRITE,SEND)']; reproduced 19; Φ threshold 0.522388
### 23:18:01 render stage1-replay-eval loadavg [24.52, 22.73, 18.78]
  stage1-replay-eval: n 120 pos 36 trunc 0 | PHI {'tp': 12, 'fp': 0, 'positives': 36, 'negatives': 84, 'recall': 0.3333333333333333, 'fpr': 0.0} | PACKAGES {'tp': 0, 'fp': 0, 'positives': 36, 'negatives': 84, 'recall': 0.0, 'fpr': 0.0} | ALL_REPRODUCED {'tp': 0, 'fp': 0, 'positives': 36, 'negatives': 84, 'recall': 0.0, 'fpr': 0.0} | DIRECT_D2 {'tp': 24, 'fp': 0, 'positives': 36, 'negatives': 84, 'recall': 0.6666666666666666, 'fpr': 0.0} AP 0.8542 | harness recall 0.3333333333333333 fpr 0.0
### 23:18:02 render stage1-hard-eval loadavg [24.52, 22.73, 18.78]
  stage1-hard-eval: n 120 pos 44 trunc 0 | PHI {'tp': 15, 'fp': 0, 'positives': 44, 'negatives': 76, 'recall': 0.3409090909090909, 'fpr': 0.0} | PACKAGES {'tp': 0, 'fp': 0, 'positives': 44, 'negatives': 76, 'recall': 0.0, 'fpr': 0.0} | ALL_REPRODUCED {'tp': 5, 'fp': 0, 'positives': 44, 'negatives': 76, 'recall': 0.11363636363636363, 'fpr': 0.0} | DIRECT_D2 {'tp': 28, 'fp': 19, 'positives': 44, 'negatives': 76, 'recall': 0.6363636363636364, 'fpr': 0.25} AP 0.7636 | harness recall 0.3409090909090909 fpr 0.0
### 23:18:03 render stage1-ambiguous-eval loadavg [24.52, 22.73, 18.78]
  stage1-ambiguous-eval: n 90 pos 30 trunc 66 | PHI {'tp': 3, 'fp': 0, 'positives': 30, 'negatives': 60, 'recall': 0.1, 'fpr': 0.0} | PACKAGES {'tp': 15, 'fp': 21, 'positives': 30, 'negatives': 60, 'recall': 0.5, 'fpr': 0.35} | ALL_REPRODUCED {'tp': 15, 'fp': 21, 'positives': 30, 'negatives': 60, 'recall': 0.5, 'fpr': 0.35} | DIRECT_D2 {'tp': 30, 'fp': 60, 'positives': 30, 'negatives': 60, 'recall': 1.0, 'fpr': 1.0} AP 0.7983 | harness recall 0.5333333333333333 fpr 0.35
### 23:18:18 render stage1-longhorizon-eval loadavg [27.57, 23.51, 19.1]
  stage1-longhorizon-eval: n 60 pos 20 trunc 51 | PHI {'tp': 10, 'fp': 18, 'positives': 20, 'negatives': 40, 'recall': 0.5, 'fpr': 0.45} | PACKAGES {'tp': 20, 'fp': 40, 'positives': 20, 'negatives': 40, 'recall': 1.0, 'fpr': 1.0} | ALL_REPRODUCED {'tp': 20, 'fp': 40, 'positives': 20, 'negatives': 40, 'recall': 1.0, 'fpr': 1.0} | DIRECT_D2 {'tp': 20, 'fp': 40, 'positives': 20, 'negatives': 40, 'recall': 1.0, 'fpr': 1.0} AP 0.4556 | harness recall 1.0 fpr 1.0
### 23:18:27 done loadavg [27.0, 23.52, 19.15]
wrote /home/anil/Documents/Research/pocketsec/results/stage8-bench/transfer.json
exit=0
```

### A — `PYTHONHASHSEED=0 python benchmarks/stage8/resources.py`

```text
### 23:18:41 build PLANTED seed 0 loadavg [25.43, 23.35, 19.17]
### 23:18:49 1. research side: run_discovery under the sampler loadavg [24.85, 23.29, 19.19]
  {'idle_rss_bytes': 72454144, 'peak_sampled_rss_bytes': 220368896, 'incremental_rss_bytes': 147914752, 'cpu_seconds': 83.478504911, 'wall_seconds': 232.363682049996, 'samples': 11809, 'loadavg': [[24.85, 23.29, 19.19], [23.67, 24.18, 20.5]], 'cpu_us_per_work_unit': 8.86446720773308, 'work_units': 9417205, 'budget_exhausted': False, 'births': 367, 'registered': 34, 'reproduced': 19, 'packages': 1, 'planted_recovered': ['DROP_EXEC_EGRESS'], 'ledger': {'births': 367, 'negative_results_written': 325, 'status_changes': 398, 'challenges': 351, 'preregistrations': 54, 'results': 54, 'identifiability': 20, 'entries': 1244, 'theories': 367, 'capacity': 16384, 'record_items_overflow': 13}, 'lineage': {'added': 522, 'collected': 0, 'collections': 0, 'keep_unknown': 0, 'walks_truncated': 0, 'refused_full': 0, 'refused_unknown_parent': 0, 'refused_duplicate': 0, 'refused_shape': 0, 'nodes': 522, 'edges': 561, 'max_nodes': 8192, 'max_edges': 16384, 'refused': 0}, 'external_refused': 0, 'governor_refusals': {}, 'edge_target_bytes': 104857600}
### 23:22:42 2a. gate flood: 10 000 texts, 200 000 units loadavg [23.67, 24.18, 20.5]
  {'idle_rss_bytes': 208834560, 'peak_sampled_rss_bytes': 208838656, 'incremental_rss_bytes': 4096, 'cpu_seconds': 8.238011168, 'wall_seconds': 15.62354740700539, 'samples': 908, 'loadavg': [[23.67, 24.18, 20.5], [23.49, 24.13, 20.55]], 'work_units': 197142, 'budget_exhausted': True, 'births': 32, 'registered': 0, 'reproduced': 0, 'packages': 0, 'planted_recovered': [], 'ledger': {'births': 32, 'entries': 32, 'theories': 32, 'capacity': 16384, 'record_items_overflow': 0}, 'lineage': {'added': 34, 'collected': 0, 'collections': 0, 'keep_unknown': 0, 'walks_truncated': 0, 'refused_full': 0, 'refused_unknown_parent': 0, 'refused_duplicate': 0, 'refused_shape': 0, 'nodes': 34, 'edges': 32, 'max_nodes': 8192, 'max_edges': 16384, 'refused': 0}, 'external_refused': 9859, 'governor_refusals': {'work_units': 1}}
### 23:22:57 2b. 10x flood: 100 000 texts, default 50 000 000 units loadavg [23.49, 24.13, 20.55]
  {'idle_rss_bytes': 206737408, 'peak_sampled_rss_bytes': 210841600, 'incremental_rss_bytes': 4104192, 'cpu_seconds': 78.47250340400001, 'wall_seconds': 161.36693462599942, 'samples': 8636, 'loadavg': [[23.49, 24.13, 20.55], [22.56, 23.45, 20.86]], 'work_units': 9111522, 'budget_exhausted': False, 'births': 352, 'registered': 25, 'reproduced': 18, 'packages': 1, 'planted_recovered': ['DROP_EXEC_EGRESS'], 'ledger': {'births': 352, 'negative_results_written': 315, 'status_changes': 377, 'challenges': 324, 'preregistrations': 44, 'results': 44, 'identifiability': 19, 'entries': 1160, 'theories': 352, 'capacity': 16384, 'record_items_overflow': 3}, 'lineage': {'added': 489, 'collected': 0, 'collections': 0, 'keep_unknown': 0, 'walks_truncated': 0, 'refused_full': 0, 'refused_unknown_parent': 0, 'refused_duplicate': 0, 'refused_shape': 0, 'nodes': 489, 'edges': 519, 'max_nodes': 8192, 'max_edges': 16384, 'refused': 0}, 'external_refused': 199718, 'governor_refusals': {}}
### 23:25:39 3. endpoint side through run_benchmark on REPLICATION loadavg [22.56, 23.45, 20.86]
  PHI: recall 0.2926829268292683 fpr 0.0 pr_auc 0.5343495934959349 cpu s/event 3.0698640483371306e-06 peak RSS 219811840 edge within False load [22.75, 23.47, 20.88]
  FORGE: recall 0.35365853658536583 fpr 0.0 pr_auc 0.5744918699186992 cpu s/event 4.6779259818792175e-06 peak RSS 219811840 edge within False load [22.75, 23.47, 20.88]
  PHI_OR_FORGE: recall 0.6463414634146342 fpr 0.0 pr_auc 0.7671747967479675 cpu s/event 5.1222167673797115e-06 peak RSS 219811840 edge within False load [23.01, 23.52, 20.91]
  DIRECT_D2: recall 1.0 fpr 0.0 pr_auc 1.0 cpu s/event 2.525762839879498e-05 peak RSS 219811840 edge within False load [23.01, 23.52, 20.91]
  gate footprint {'detectors': 1, 'events': 240, 'incremental_rss_bytes': 4096, 'peak_sampled_rss_bytes': 210898944, 'within_ceiling': True, 'work_units_per_event': 10.241666666666667, 'wall_seconds': 0.002509632002329454, 'loadavg': (23.01, 23.52, 20.91)}
wrote /home/anil/Documents/Research/pocketsec/results/stage8-bench/resources.json
### 23:25:45 4. endurance 12 cycles loadavg [23.01, 23.52, 20.91]
  endurance plateau_ok True problems () packages 6 rss 210911232 -> 266149888 sizes (('ledger_entries', (1243, 2321, 3196, 4049, 4839, 5560, 6160, 6800, 7420, 8044, 8628, 9191)), ('ledger_theories', (361, 695, 1016, 1343, 1674, 1998, 2048, 2048, 2048, 2048, 2048, 2048)), ('negative_results', (299, 547, 784, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024)), ('lineage_nodes', (126, 214, 265, 293, 297, 294, 290, 290, 290, 290, 290, 290)), ('population', (120, 208, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256)), ('adapter_receipts', (1, 2, 3, 4, 5, 6, 6, 6, 6, 6, 6, 6))) evictions (('adapter.refused', 0), ('ledger.negative_results_written', 3726), ('ledger.theories_folded', 1749), ('lineage.collected', 3977), ('lineage.refused', 0), ('lineage.refused_duplicate', 0), ('lineage.refused_full', 0), ('lineage.refused_shape', 0), ('lineage.refused_unknown_parent', 0), ('negative_results.evicted', 1776), ('negative_results.replaced', 926), ('population.births_refused', 0), ('population.depth_refused', 58), ('population.evicted', 390), ('population.evicted_folded', 2), ('population.evicted_not_proposed', 78), ('population.fossilized', 2837), ('population.merges_refused', 0), ('population.pending_depth_evicted', 0)) wall 697.2s
### 23:37:22 done loadavg [24.07, 24.71, 23.03]
wrote /home/anil/Documents/Research/pocketsec/results/stage8-bench/resources.json
exit=0
```

### A — `PYTHONHASHSEED=0 python benchmarks/stage8/components.py`

```text
### 23:17:28 base run loadavg [20.8, 21.94, 18.39]
  base run: wall 183.1s cpu 80.8s load [[20.8, 21.94, 18.39], [26.31, 24.15, 19.92]]
  funnel births 367 challenged_out 76 registered 34 survived 20 reproduced 19 packages 1; HOLDOUT kill rate 0.4117647058823529; identifiability {'EQUIVALENCE_CLASS': 20} IDENTIFIED share of reproduced 0.0; trap {'generated': True, 'registered': False, 'refuted': True, 'hypothesis_id': 'hyp-1a3d48b446e9393854c45f57', 'refuted_at': 'challenge:COUNTERFACTUAL_INVARIANCE'}
  tournament CO_OCCURS(WRITE,SEND): selected FSM deployable True reasons ['TYPED_RULE:reference', 'MOTIF:refused.MOTIF_CANNOT_EXPRESS_CO_OCCURS', 'THRESHOLD:recall_below_tolerance', 'LOGISTIC:recall_below_tolerance', 'PROTOTYPE:precision_below_tolerance', 'STUMP_TREE:recall_below_tolerance', 'selected:FSM'] dcr 778274.7925142392
    {'kind': <RepresentationKind.TYPED_RULE: 'TYPED_RULE'>, 'expressible': True, 'refusal': None, 'precision': 1.0, 'recall': 0.35365853658536583, 'false_positive_rate': 0.0, 'pr_auc': 0.5744918699186992, 'decision_agreement': 1.0, 'work_units_per_event': 11.033333333333333, 'artifact_bytes': 2475, 'wall_ratio_to_reference': 1.0, 'loadavg': (26.34, 23.96, 19.74), 'robustness_recall': 0.5, 'interpretability': 2}
    {'kind': <RepresentationKind.MOTIF: 'MOTIF'>, 'expressible': False, 'refusal': 'MOTIF_CANNOT_EXPRESS_CO_OCCURS', 'precision': None, 'recall': None, 'false_positive_rate': None, 'pr_auc': None, 'decision_agreement': None, 'work_units_per_event': None, 'artifact_bytes': None, 'wall_ratio_to_reference': None, 'loadavg': (26.34, 23.96, 19.74), 'robustness_recall': None, 'interpretability': None}
    {'kind': <RepresentationKind.FSM: 'FSM'>, 'expressible': True, 'refusal': None, 'precision': 1.0, 'recall': 0.35365853658536583, 'false_positive_rate': 0.0, 'pr_auc': 0.5744918699186992, 'decision_agreement': 1.0, 'work_units_per_event': 10.241666666666667, 'artifact_bytes': 216, 'wall_ratio_to_reference': 1.090348359517002, 'loadavg': (26.34, 23.96, 19.74), 'robustness_recall': 0.5, 'interpretability': 5}
    {'kind': <RepresentationKind.THRESHOLD: 'THRESHOLD'>, 'expressible': True, 'refusal': None, 'precision': 0.0, 'recall': 0.0, 'false_positive_rate': 0.012658227848101266, 'pr_auc': 0.3416666666666667, 'decision_agreement': 0.8708333333333333, 'work_units_per_event': 5.516666666666667, 'artifact_bytes': 113, 'wall_ratio_to_reference': 0.08751480956433168, 'loadavg': (26.34, 23.96, 19.74), 'robustness_recall': None, 'interpretability': 1}
    {'kind': <RepresentationKind.LOGISTIC: 'LOGISTIC'>, 'expressible': True, 'refusal': None, 'precision': 0.5333333333333333, 'recall': 0.1951219512195122, 'false_positive_rate': 0.08860759493670886, 'pr_auc': 0.4974914697770366, 'decision_agreement': 0.8875, 'work_units_per_event': 241.11666666666667, 'artifact_bytes': 2979, 'wall_ratio_to_reference': 3.2897667134727024, 'loadavg': (26.34, 23.96, 19.74), 'robustness_recall': 0.0, 'interpretability': 37}
    {'kind': <RepresentationKind.PROTOTYPE: 'PROTOTYPE'>, 'expressible': True, 'refusal': None, 'precision': 0.34146341463414637, 'recall': 0.6829268292682927, 'false_positive_rate': 0.6835443037974683, 'pr_auc': 0.5488903561522761, 'decision_agreement': 0.4375, 'work_units_per_event': 278.1166666666667, 'artifact_bytes': 1850, 'wall_ratio_to_reference': 2.4454362019823948, 'loadavg': (26.34, 23.96, 19.74), 'robustness_recall': 0.875, 'interpretability': 74}
    {'kind': <RepresentationKind.STUMP_TREE: 'STUMP_TREE'>, 'expressible': True, 'refusal': None, 'precision': 0.18181818181818182, 'recall': 0.1951219512195122, 'false_positive_rate': 0.45569620253164556, 'pr_auc': 0.3104767184035477, 'decision_agreement': 0.6458333333333334, 'work_units_per_event': 10.029166666666667, 'artifact_bytes': 222, 'wall_ratio_to_reference': 0.5324131739388682, 'loadavg': (26.34, 23.96, 19.74), 'robustness_recall': 0.3333333333333333, 'interpretability': 5}
wrote /home/anil/Documents/Research/pocketsec/results/stage8-bench/components.json
### 23:20:31 NAIVE control on PLANTED loadavg [26.31, 24.15, 19.92]
  NAIVE control on PLANTED: wall 17.0s cpu 9.9s load [[26.31, 24.15, 19.92], [25.77, 24.15, 19.98]]
  NAIVE: {'selected': 35, 'trap': {'generated': True, 'registered': False, 'refuted': False, 'hypothesis_id': 'hyp-1a3d48b446e9393854c45f57', 'refuted_at': None}, 'planted_recovered': ['DROP_EXEC_EGRESS', 'REPEATED_EGRESS'], 'false_selected': 1, 'wall_s': 17.034244043999934, 'cpu_s': 9.93494038, 'loadavg': [[26.31, 24.15, 19.92], [25.77, 24.15, 19.98]]}
### 23:20:48 trap probe loadavg [25.77, 24.15, 19.98]
  trap probe: wall 0.0s cpu 0.0s load [[25.77, 24.15, 19.98], [25.77, 24.15, 19.98]]
  probe: {'generated': True, 'registered': True, 'refuted': True, 'hypothesis_id': 'hyp-16038b9062680255be17d81e', 'refuted_at': 'HOLDOUT', 'wall_s': 0.004012165001768153, 'cpu_s': 0.003993984999993927, 'loadavg': [[25.77, 24.15, 19.98], [25.77, 24.15, 19.98]]}
wrote /home/anil/Documents/Research/pocketsec/results/stage8-bench/components.json
### 23:20:48 run_ablation loadavg [25.77, 24.15, 19.98]
  run_ablation: wall 2426.3s cpu 1285.2s load [[25.77, 24.15, 19.98], [29.14, 24.28, 22.61]]
  priority_field       INERT              fired 2     changed 0    d_planted 0 d_false 0 d_recall 0.0 d_wu 0
  residual_motif       NOT_YET_JUSTIFIED  fired 2     changed 46   d_planted 0 d_false 0 d_recall 0.0 d_wu 210942
  analogy              INERT              fired 0     changed 0    d_planted 0 d_false 0 d_recall 0.0 d_wu 0
  null_benign          INERT              fired 0     changed 0    d_planted 0 d_false 0 d_recall 0.0 d_wu 0
  stage7_seed          INERT              fired 0     changed 0    d_planted 0 d_false 0 d_recall 0.0 d_wu 0
  external_proposal    INERT              fired 0     changed 0    d_planted 0 d_false 0 d_recall 0.0 d_wu 0
  diversity            NOT_YET_JUSTIFIED  fired 64    changed 32   d_planted 0 d_false 0 d_recall 0.0 d_wu 1482439
  mutation             NOT_YET_JUSTIFIED  fired 85    changed 21   d_planted 0 d_false 0 d_recall 0.0 d_wu 2232828
  mdl                  NOT_YET_JUSTIFIED  fired 227   changed 21   d_planted 0 d_false 0 d_recall 0.0 d_wu 617378
  score_full           NOT_YET_JUSTIFIED  fired 34    changed 25   d_planted 0 d_false 0 d_recall 0.0 d_wu 367193
  oracle               NOT_YET_JUSTIFIED  fired 3     changed 7    d_planted 0 d_false 0 d_recall 0.0 d_wu 29862
  cost_aware           INERT              fired 3     changed 0    d_planted 0 d_false 0 d_recall 0.0 d_wu 245
  eig                  INERT              fired 3     changed 0    d_planted 0 d_false 0 d_recall 0.0 d_wu 166
  doppelganger_screen  NOT_YET_JUSTIFIED  fired 117   changed 30   d_planted 0 d_false 0 d_recall 0.0 d_wu -124347
  negative_memory      INERT              fired 0     changed 0    d_planted 0 d_false 0 d_recall 0.0 d_wu 0
  holdout_discipline   JUSTIFIED          fired 34    changed 69   d_planted -1 d_false -1 d_recall 0.3536585365853659 d_wu 7222020
  bonferroni           INERT              fired 34    changed 0    d_planted 0 d_false 0 d_recall 0.0 d_wu 0
wrote /home/anil/Documents/Research/pocketsec/results/stage8-bench/components.json
### 00:01:15 oracle_comparison loadavg [29.14, 24.28, 22.61]
  oracle_comparison: wall 2557.0s cpu 1373.0s load [[29.14, 24.28, 22.61], [17.29, 18.97, 22.84]]
  eig_per_cost   lab False seed 0 experiments 3 wu 43252 correct_leading 0 stops ('observationally_equivalent', 'observationally_equivalent')
  eig_per_cost   lab False seed 1 experiments 3 wu 27135 correct_leading 0 stops ('observationally_equivalent', 'observationally_equivalent')
  eig_per_cost   lab False seed 2 experiments 3 wu 30080 correct_leading 0 stops ('observationally_equivalent', 'identified')
  eig_only       lab False seed 0 experiments 2 wu 43007 correct_leading 0 stops ('observationally_equivalent', 'observationally_equivalent')
  eig_only       lab False seed 1 experiments 2 wu 27009 correct_leading 0 stops ('observationally_equivalent', 'observationally_equivalent')
  eig_only       lab False seed 2 experiments 2 wu 30039 correct_leading 0 stops ('observationally_equivalent', 'identified')
  random         lab False seed 0 experiments 2 wu 43086 correct_leading 0 stops ('observationally_equivalent', 'observationally_equivalent')
  random         lab False seed 1 experiments 3 wu 27281 correct_leading 0 stops ('observationally_equivalent', 'observationally_equivalent')
  random         lab False seed 2 experiments 3 wu 30078 correct_leading 0 stops ('observationally_equivalent', 'identified')
  cheapest       lab False seed 0 experiments 3 wu 43252 correct_leading 0 stops ('observationally_equivalent', 'observationally_equivalent')
  cheapest       lab False seed 1 experiments 3 wu 27135 correct_leading 0 stops ('observationally_equivalent', 'observationally_equivalent')
  cheapest       lab False seed 2 experiments 3 wu 30080 correct_leading 0 stops ('observationally_equivalent', 'identified')
  eig_per_cost   lab True  seed 0 experiments 7 wu 157409 correct_leading 1 stops ('identified', 'observationally_equivalent')
  eig_per_cost   lab True  seed 1 experiments 6 wu 92316 correct_leading 1 stops ('identified', 'observationally_equivalent')
  eig_per_cost   lab True  seed 2 experiments 7 wu 112155 correct_leading 1 stops ('identified', 'identified')
  eig_only       lab True  seed 0 experiments 6 wu 147755 correct_leading 1 stops ('identified', 'observationally_equivalent')
  eig_only       lab True  seed 1 experiments 5 wu 91223 correct_leading 1 stops ('identified', 'observationally_equivalent')
  eig_only       lab True  seed 2 experiments 5 wu 105664 correct_leading 1 stops ('identified', 'identified')
  random         lab True  seed 0 experiments 32 wu 181673 correct_leading 0 stops ('budget', 'budget')
  random         lab True  seed 1 experiments 25 wu 123882 correct_leading 0 stops ('budget', 'observationally_equivalent')
  random         lab True  seed 2 experiments 18 wu 163298 correct_leading 0 stops ('budget', 'identified')
  cheapest       lab True  seed 0 experiments 28 wu 275320 correct_leading 0 stops ('budget', 'observationally_equivalent')
  cheapest       lab True  seed 1 experiments 27 wu 177074 correct_leading 0 stops ('budget', 'observationally_equivalent')
  cheapest       lab True  seed 2 experiments 22 wu 176415 correct_leading 0 stops ('budget', 'identified')
  eig_beats_cheap (('replay_only', False), ('lab_oracle_authored', True)) verdict NOT_YET_JUSTIFIED
wrote /home/anil/Documents/Research/pocketsec/results/stage8-bench/components.json
### 00:43:52 threshold_sensitivity loadavg [17.29, 18.97, 22.84]
  threshold_sensitivity: wall 648.7s cpu 466.3s load [[17.29, 18.97, 22.84], [14.62, 18.88, 21.17]]
  alpha                  0.01   default False repro 19  planted 1 false 0 deployable 1 changed 0/34 
  alpha                  0.05   default True  repro 19  planted 1 false 0 deployable 1 changed 0/34 
  alpha                  0.1    default False repro 19  planted 1 false 0 deployable 1 changed 0/34 
  mdl_gain_per_bit       0.0    default False repro 14  planted 1 false 0 deployable 1 changed 22/34 
  mdl_gain_per_bit       0.01   default True  repro 19  planted 1 false 0 deployable 1 changed 0/34 
  mdl_gain_per_bit       0.05   default False repro 20  planted 1 false 0 deployable 1 changed 15/34 
  forge_tolerance        0.0    default False repro 19  planted 1 false 0 deployable 1 changed 0/1 
  forge_tolerance        0.02   default True  repro 19  planted 1 false 0 deployable 1 changed 0/1 
  forge_tolerance        0.05   default False repro 19  planted 1 false 0 deployable 1 changed 0/1 
### 00:54:40 done loadavg [14.62, 18.88, 21.17]
wrote /home/anil/Documents/Research/pocketsec/results/stage8-bench/components.json
exit=0
```

### A — `PYTHONHASHSEED=0 python benchmarks/stage8/oracle_crash_repro.py`

```text
loadavg [44.08, 39.1, 32.53]
RAISED pocketsec.stage0.contracts.common.ContractError: restricting a posterior must keep some probability mass
oracle_policy=None: completed, registered 64, reproduced 0, work units 6531037
exit=0
```

### A — `PYTHONHASHSEED=0 python -m pocketsec.stage8.cli gate`

```text
start 2026-09-27T00:01:02+10:00 loadavg 29.78 24.22 22.58 51/2729 1283069
PocketSec Stage 8 acceptance gate (synthetic discovery corpus, author-confounded; see docs/stage-8-spec.md §6.1)

  [FAIL] G8.1  Every hypothesis has explicit falsification conditions
         (a) malformed genomes refused 6/6; (b) 1631 genomes born over 4 runs, 117 registered, 117 tested, problems 0; (c) edits after test refused 3/3; (d) trap in run_discovery: generated=True registered=False refuted=True at challenge:COUNTERFACTUAL_INVARIANCE. The spec requires generated AND registered AND refuted in the loop; a pre-holdout screen refuting it before registration does NOT meet the literal clause (reported, not re-worded). Isolated vault probe (probe_trap_at_holdout): registered=True refuted=True at HOLDOUT. F2 (trap survives HOLDOUT) did not fire
  [PASS] G8.2  Free-form LLM text is never the canonical scientific state
         (a) injection suite 24 texts: 8 parsed (exactly their mechanisms: True), 16 refused, source_digest = sha256(text): True; (b) canary scan over 1542 ledger/genome/package payloads of the injection run: 0 of 23 non-empty raw proposal strings found; 13 external-proposal genomes born, each carrying only a sha256 source digest; (c) undeclared string fields in the state modules: 0 (declared: 50 ids/digests/codes); (d) equal content -> equal id: True; render() absent from the stored form: True; from_dict(to_dict()) round-trips: True. Reported beside the criterion: F14 FIRED: with the suite, 7 held-out outcomes of non-injected theories disappeared and 6 appeared (REPRODUCED 19 -> 18; planted families recovered 1 -> 1): injected theories displace others in the bounded population and registration batch. No LLM is built (ADR-0074).
  [PASS] G8.3  All active emulation is isolated and authorised
         (a) ExperimentClass = the 6 safe classes + ISOLATED_EMULATION, no production-intervention member: True; (b) emulation refusals 4 (no clearance, expired, wrong scope, valid clearance -> REFUSED_NO_EMULATOR), wrong outcomes 0, audited 4/4; (c) ORACLE experiment records in the gate's runs: 17, not ALLOWED-and-safe 0; (d) boundary rule 8 offenders 0. There is no emulator (ADR-0075): isolation of a real emulation is UNMEASURED; this criterion holds by construction only
  [PASS] G8.4  Unknown/unidentifiable outcomes are preserved rather than forced into conclusions
         (a) PM1 vs CO_OCCURS twin, interventions off: EQUIVALENCE_CLASS; with 44 REORDER worlds + lab oracle: IDENTIFIED (lab_oracle_authored); (b) DROPOUT PM1 vs PRECEDES(WRITE+TEMP_LOCATION,CONNECT+EXTERNAL_ENDPOINT): UNIDENTIFIABLE/ONLY_UNDER_INCOMPLETE_OBSERVATION; (c) 5-match candidate: INSUFFICIENT_EVIDENCE -> INSUFFICIENT_EVIDENCE; ORACLE stops on DROPOUT (stop, visibility share): [('telemetry_failure', 1.0), ('observationally_equivalent', 0.0), ('observationally_equivalent', 0.0)]: TELEMETRY_FAILURE fired True; (d) run verdicts 66, non-IDENTIFIED 65, problems 0; (e) unlabelled LAB_POOL (120 episodes): residual kinds {'UNEXPLAINED_ESCALATION': 105}; none assigned a known class: True. Met as mechanism; value on real sensor loss is UNMEASURED
  [PASS] G8.5  Validated discoveries reproduce across predefined independent splits
         PLANTED preconditions OK; SURVIVED 20; REPLICATION preregistrations 20 in one batch (batch sizes [20]), results 20, all registered first: True; REPRODUCED 19; packages 1 by status {'REPRODUCED': 1}; built from a non-REPRODUCED theory 0; independent_positives_available [False]; INDEPENDENT FP rates [0.0]. Predefined synthetic splits (hosts h09-h12, epoch 2, family variants); independence from the corpus author is UNMEASURED
  [PASS] G8.6  Novelty is classified conservatively and not claimed without prior-art review
         (a) packages 2, novelty classes {'KNOWN_COMBINATION': 1, 'CONTEXT_EXTENSION': 1}, claims permitted 0, non-local technique ids 0; (b) rediscovery control PM3 -> KNOWN, matched ['stage1:ATTACK_EXFIL']; (c) 'novel' outside POTENTIALLY_NOVEL 0; (d) prior-art reviews {'H4': ('NOT_REVIEWED', 'NOT_REVIEWED'), 'H8': ('NOT_REVIEWED', 'NOT_REVIEWED')}. ATT&CK/Sigma/YARA/literature indexes are NOT BUILT: novelty against them is UNMEASURED
  [PASS] G8.7  FORGE selects by measured security/resource Pareto performance
         tournaments 2; (a)+(b) entrant/reselection problems 0; (c) refusals in tournaments {'MOTIF_CANNOT_EXPRESS_CO_OCCURS': 1}, PM2 compiled directly -> MOTIF refusal MOTIF_CANNOT_EXPRESS_REPEATED; (d) deployable 2/2, selected {'FSM': 1, 'MOTIF': 1}, deployability violations 0; (e) DCR [778274.7925142392, 1399975.1057401812]; direct model (LOGISTIC on TRAIN labels) REPLICATION recall 0.6463414634146342 FPR 0.25316455696202533 wu/event 529.6
  [PASS] G8.8  Every DiscoveryPackage has complete lineage and failure conditions
         packages 2; lineage/ledger/verify problems 0; sign_record/verify_record round-trips 2/2 (HMAC: local integrity, not identity, ADR-0064 precedent); one flipped artifact byte detected 2/2 packages with an artifact; one edited ledger entry detected 2/2
  [PASS] G8.9  All endpoint adoption passes Stage 6
         (a) boundary rules 5, 6, 7, 10, 11 offenders 0; rule 16 in-gate: the adapter refused 2/2 non-package objects (the gateway/Stage 5 type refusals are tests/test_stage8_boundary.py::test_rule16_*: calling admit or importing Stage 5 here would itself break rules 3 and 7); (b) capsules 8, problems none; (c) Stage 6 buckets verbatim {'UNCERTAIN': 8}, predicted provenance scores [0.4]. Realised adoption (TRUSTED_CANDIDATE) = 0: B8-1, ADR-0076 — met as a path only
  [PASS] G8.10  Stage 8 does not create a new direct path to Stage 5 authority
         boundary rules 3, 8, 9, 12, 13 offenders 0; verify_discovery_constitution() problems 0; authority words refused 108/108 at every probed depth of HypothesisGenome.from_dict and DiscoveryPackageV1.from_dict; closed-vocabulary members matching OFFENSIVE_TOKENS 0. No Stage 8 module imports Stage 5; the Stage 5 entry-guard refusal of a package is tested in tests/test_stage8_boundary.py (the gate may not import Stage 5)
  [PASS] G8.11  Research cost is allowed to be high offline; deployed intelligence remains lightweight
         (a) flood of 10000 texts under 200000 units: budget_exhausted True, spent 197142, stores within caps True (theories 32, entries 32, lineage nodes 34), external texts refused 9859, governor refusals {'work_units': 1}; (b) endurance 12/12 cycles, plateau_ok True, problems [], final store sizes {'ledger_entries': 9191, 'ledger_theories': 2048, 'negative_results': 1024, 'lineage_nodes': 290, 'population': 256, 'adapter_receipts': 6}, packages 6, capsules created/admitted 48/48, research RSS start 243986432 B sampled peak 299057152 B (research side, not the endpoint), wall 609.8 s at loadavg (23.41, 27.71, 29.96); (c) shipped detectors 1, artifact bytes [216] (max 65536); endpoint incremental RSS 28672 B vs ceiling 20971520 B: within; 240 events, 10.241666666666667 wu/event, wall 0.0025 s at loadavg (23.41, 27.71, 29.96); whole gate process vs the edge profile (recorded, not asserted; includes research state): {'profile': 'edge', 'within_target': False, 'observations': ['peak agent RSS 281.4 MB'], 'exceeded': ['agent_rss 281.4 MB > 100 MB target'], 'unmeasured': ['model_bytes']}; DCR [778274.7925142392], knowledge_bytes_saved [5111]. In-process on the dev host; device figures on a real 2 GB endpoint are UNMEASURED
  [FAIL] G8.12  Advanced mechanisms beat or justify themselves against simpler baselines
         FAILS BY CONSTRUCTION: synthetic_data True (PASS requires False, spec §6.1). Preconditions per arm {'PLANTED': [], 'DROPOUT': ['P5: 0.9669 violates pooled logistic HOLDOUT AP < 0.95'], 'NULL': ['P5: 1.0000 violates pooled logistic HOLDOUT AP < 0.95']}; search JUSTIFIED: PROMETHEUS recovered (1, 1, 1) families ['DROP_EXEC_EGRESS'] false (0, 0, 0) wu (9417205, 9068403, 9062197) exhausted (False, False, False), RANDOM_BASELINE recovered (0, 0, 0) families [] false (0, 0, 0) wu (5948165, 5988550, 5937876) exhausted (False, False, False), EXHAUSTIVE_SINGLE_BASELINE recovered (0, 0, 0) families [] false (0, 0, 0) wu (7274061, 7416962, 7235433) exhausted (False, False, False); beats random True; beyond exhaustive ['DROP_EXEC_EGRESS']; residual gain over the Φ-oracle (counterfactual_at_boundary): Φ missed 58, packages caught 29, recall Φ 0.2926829268292683 -> Φ OR packages 0.6463414634146342, FPR 0.0 -> 0.0, beats Φ True; null FDR DEGENERATE over 20 label seeds: disciplined mean reproduced 0.000 (share with any 0.000), NAIVE mean selected 0.000 (share 0.000); ORACLE NOT_YET_JUSTIFIED: EIG beats cheap (('replay_only', False), ('lab_oracle_authored', True)); PLANTED trap refuted with discipline True; selected by the NAIVE control True (NAIVE selected 35); FORGE vs direct model (recall 0.6463414634146342, FPR 0.25316455696202533, 529.6 wu/event): selected (kind, recall, FPR, wu/event, wins) [('FSM', 0.35365853658536583, 0.0, 10.241666666666667, False)]; ablation rows 17 (missing OPTIONAL flags []): {'priority_field': 'INERT(fired 2, changed 0)', 'residual_motif': 'NOT_YET_JUSTIFIED(fired 2, changed 46)', 'analogy': 'INERT(fired 0, changed 0)', 'null_benign': 'INERT(fired 0, changed 0)', 'stage7_seed': 'INERT(fired 0, changed 0)', 'external_proposal': 'INERT(fired 0, changed 0)', 'diversity': 'NOT_YET_JUSTIFIED(fired 64, changed 32)', 'mutation': 'NOT_YET_JUSTIFIED(fired 85, changed 21)', 'mdl': 'NOT_YET_JUSTIFIED(fired 227, changed 21)', 'score_full': 'NOT_YET_JUSTIFIED(fired 34, changed 25)', 'oracle': 'NOT_YET_JUSTIFIED(fired 3, changed 7)', 'cost_aware': 'INERT(fired 3, changed 0)', 'eig': 'INERT(fired 3, changed 0)', 'doppelganger_screen': 'NOT_YET_JUSTIFIED(fired 117, changed 30)', 'negative_memory': 'INERT(fired 0, changed 0)', 'holdout_discipline': 'JUSTIFIED(fired 34, changed 69)', 'bonferroni': 'INERT(fired 34, changed 0)'}; threshold_sensitivity rows 9, THRESHOLD_DECIDES []; catalogue problems 0 []; registry.jsonl byte-identical True; findings headings missing []; ADRs missing []; HYPOTHESES == H0..H8 True. Not justified here: ['null FDR DEGENERATE', 'ORACLE NOT_YET_JUSTIFIED', 'ablation:analogy', 'ablation:bonferroni', 'ablation:cost_aware', 'ablation:diversity', 'ablation:doppelganger_screen', 'ablation:eig', 'ablation:external_proposal', 'ablation:mdl', 'ablation:mutation', 'ablation:negative_memory', 'ablation:null_benign', 'ablation:oracle', 'ablation:priority_field', 'ablation:residual_motif', 'ablation:score_full', 'ablation:stage7_seed']

  timings (label, wall s, loadavg) — observations, never asserted:
    corpus planted               9.789  (28.72, 24.27, 22.62)
    corpus dropout               8.637  (28.43, 24.28, 22.64)
    preconditions PLANTED       14.419  (27.87, 24.37, 22.69)
    preconditions DROPOUT       20.364  (29.17, 24.87, 22.89)
    corpus null                 19.321  (36.87, 26.94, 23.62)
    preconditions NULL          22.022  (40.89, 28.53, 24.21)
    run planted                198.078  (37.0, 34.2, 27.35)
    run planted lab-on          76.808  (38.55, 34.82, 28.08)
    run planted injected       141.957  (36.97, 36.11, 29.57)
    run planted naive           13.866  (34.4, 35.58, 29.5)
    trap probe                   0.004  (34.4, 35.58, 29.5)
    run dropout                184.215  (38.96, 35.9, 30.59)
    run flood                   27.646  (40.08, 36.49, 30.96)
    endurance                  610.569  (23.41, 27.71, 29.96)
    endpoint footprint           0.079  (23.41, 27.71, 29.96)
    phi-oracle baseline          0.008  (23.41, 27.71, 29.96)
    residual gain                0.006  (23.41, 27.71, 29.96)
    direct model                 3.412  (23.78, 27.72, 29.95)
    compare search             659.321  (19.29, 23.35, 26.7)
    null fdr                  1489.654  (16.89, 17.83, 20.03)
    oracle comparison          288.035  (5.46, 10.53, 16.32)
    ablation                   715.421  (3.56, 5.64, 10.79)
    threshold sensitivity      200.241  (3.13, 4.72, 9.45)

loadavg at end of run: 3.04 4.68 9.41
10/12 criteria met
GATE: FAILED (2)
exit=1
end 2026-09-27T01:19:36+10:00 loadavg 3.04 4.68 9.41 3/2146 1802804
```

### A — `PYTHONHASHSEED=0 python benchmarks/stage8/register.py`

```text
$ PYTHONHASHSEED=0 python benchmarks/stage8/register.py
recorded PS-S8-20260926-BASE-transfer-stage1-0101 -> results/PS-S8-20260926-BASE-transfer-stage1-0101.json
recorded PS-S8-20260926-BASE-saturation-direct-model-0102 -> results/PS-S8-20260926-BASE-saturation-direct-model-0102.json
recorded PS-S8-20260926-H4-endpoint-harness-0103 -> results/PS-S8-20260926-H4-endpoint-harness-0103.json
recorded PS-S8-20260926-BASE-search-controls-0104 -> results/PS-S8-20260926-BASE-search-controls-0104.json
recorded PS-S8-20260926-BASE-null-fdr-0105 -> results/PS-S8-20260926-BASE-null-fdr-0105.json
recorded PS-S8-20260926-BASE-random-spend-curve-0106 -> results/PS-S8-20260926-BASE-random-spend-curve-0106.json
recorded PS-S8-20260926-BASE-search-controls-seed2-0108 -> results/PS-S8-20260926-BASE-search-controls-seed2-0108.json
recorded PS-S8-20260926-H8-ablation-rerun-0107 -> results/PS-S8-20260926-H8-ablation-rerun-0107.json
exit=0
verify_integrity problems: []
PS-S8 entries: ['PS-S8-20260926-BASE-transfer-stage1-0101', 'PS-S8-20260926-BASE-saturation-direct-model-0102', 'PS-S8-20260926-H4-endpoint-harness-0103', 'PS-S8-20260926-BASE-search-controls-0104', 'PS-S8-20260926-BASE-null-fdr-0105', 'PS-S8-20260926-BASE-random-spend-curve-0106', 'PS-S8-20260926-BASE-search-controls-seed2-0108', 'PS-S8-20260926-H8-ablation-rerun-0107']
```

### A — `(ad-hoc checks run in this session; each command is shown above its output)`

```text
$ PYTHONHASHSEED=0 python count_space.py   (in benchmarks/stage8)
observed signatures 17 predicates (<=1 prop, <=1 raised) 31
pair mechanisms (incl. CO_OCCURS both orders) 2756 approx unique 2756
train episodes 240 steps 1169 mean steps 4.870833333333334
per matches call us 10.53400583259645
exit=0
$ PYTHONHASHSEED=0 python naive_trap_check.py   (in benchmarks/stage8)
loadavg [28.25, 28.34, 30.01] NAIVE selected 35 trap among selected: True trap DSL SINGLE(SPAWN)
exit=0
$ PYTHONHASHSEED=0 python -m pytest -q -p no:cacheprovider tests/test_repository_structure.py tests/test_stage8_boundary.py --junitxml=results/stage8-bench/struct.xml
........................................................................ [ 53%]
...............................................................          [100%]
exit=0
junit {'tests': '135', 'failures': '0', 'errors': '0', 'skipped': '0', 'time': '94.995'}
loadavg 42.97 39.02 32.57 43/2657 1403205
```

## Appendix B — the integration session's findings (2026-09-26 22:53), retained verbatim

Superseded by Part I where the two disagree (see RETRACTED); never deleted. Its figures were produced by that session; the ones re-measured here are identical unless Part I says otherwise. sha256 of the retained file: `77ab778db1040275e399fe61c1ac624a77ef331a81da1bbba81279144c295dbd`.

````markdown
# Stage 8 — PROMETHEUS + ORACLE + FORGE — findings (D8.20)

Integration session, 2026-09-26 (Python 3.14.7, Linux 7.1.5+kali-amd64). Every figure below was
produced by running code in this session; the command is named beside it. Timings carry
`/proc/loadavg`, are contended (another wave was building in the same tree), and are never
asserted. **Nothing here is a detection result** (see the honesty ledger).

## Summary

- `python -m pocketsec.stage8.cli gate` → **GATE: FAILED (2)**, exit 1, **10/12** criteria met,
  ~40 min wall at loadavg 2.8–9.5 (§M.1). FAIL: **G8.1** (the literal trap clause, §M.2) and
  **G8.12** (by construction on synthetic data, plus the verdicts below).
- **The kill switch works on this world.** The trap `SINGLE(SPAWN)` (true on TRAIN by
  construction) is refuted in every disciplined run; the NAIVE control selects it. The vault alone
  refutes it at HOLDOUT. No hypothesis was tested before its preregistration (117/117).
- **Discovery beats baselines (1)–(3) on the authored PLANTED world, for ONE family only.**
  PROMETHEUS recovers DROP_EXEC_EGRESS (PM1) on 3/3 seeds; random search and exhaustive
  single-step recover nothing at equal budget; REPRODUCED packages catch 29 of 58 REPLICATION
  positives the Φ-oracle misses at FPR 0.0 → 0.0. PM2 and PM3 are never recovered (§M.3).
  This is a mechanism result on a world built to contain what it looks for (lesson 6).
- **The null test is DEGENERATE.** On 20 null label seeds the disciplined loop reproduces 0 — but
  the NAIVE control also selects 0, so this null cannot show the discipline matters (spec §7).
- **Most mechanisms do not justify themselves.** Of 17 ablation rows: 1 JUSTIFIED
  (`holdout_discipline`), 7 NOT_YET_JUSTIFIED, 9 INERT. ORACLE is NOT_YET_JUSTIFIED on replay
  (it beats cheap selection only with the authored lab oracle) (§M.4).
- **F14 fires** (measured in this session, §M.6): adding the 24-text injection suite changes which
  non-injected theories reproduce (7 lost, 6 gained) without changing planted recovery.
- **Stage 6 adopts nothing (B8-1):** 8 capsules handed over, all `UNCERTAIN`, predicted provenance
  score 0.4, TRUSTED_CANDIDATE 0 (§M.7).
- FORGE compresses the one package into an FSM of 216 bytes at 10.24 work units per event that
  agrees with the typed rule; it does **not** beat the direct model on recall (§M.5).

## M.0 How this was measured

| what | command | loadavg |
|---|---|---|
| the gate | `PYTHONHASHSEED=0 python -m pocketsec.stage8.cli gate` (Appendix A, verbatim; final run) | start 2.75 3.53 4.81, end 11.43 9.23 6.96. A first full run (before F14 was added to G8.2's detail) gave identical criteria and figures; only timings and RSS differ |
| the tests | `PYTHONHASHSEED=0 python -m pytest -q -p no:cacheprovider --junitxml=…` | start 3.61 4.74 4.64, end 3.72 5.81 6.16 |
| F14 | scratch probe: `run_discovery` on PLANTED seed 0 with and without `external_texts=INJECTION_SUITE` | 3.11 3.68 4.90 |
| the prune fix | scratch probe: `run_discovery(PLANTED seed 0)` before and after the ORACLE prune fix | 3.24 → 4.94 / 4.78 → 6.50 |
| endurance before the fix | `run_endurance(cycles=12, seed=0)` after the population fix | 4.24 → 3.13 |

Corpora: `build_discovery_corpus(arm, seed=0)` at `DEFAULT_COUNTS` (TRAIN/HOLDOUT/REPLICATION 240,
LAB_POOL/INDEPENDENT 120). Every figure is `synthetic_data=True`.

## M.1 The gate

| id | result | the number that decided it |
|---|---|---|
| G8.1 | **FAIL** | (a) 6/6 malformed genomes refused; (b) 1631 genomes, 117 registered, 117 tested, 0 tested-before-registered, chains verify; (c) 3/3 edits after test refused; (d) **trap generated, refuted at `challenge:COUNTERFACTUAL_INVARIANCE`, registered=False** — the literal "registered" clause is unmet; the vault probe registers it and refutes it at HOLDOUT |
| G8.2 | PASS | 8 parsed / 16 refused; canary scan 0 of 23 non-empty raw strings in 1542 payloads; 0 undeclared string fields; F14 reported beside it (§M.6) |
| G8.3 | PASS (by construction) | 4 emulation refusals (no clearance, expired, scope, no emulator), 17 ORACLE experiment records all ALLOWED-and-safe; rule 8 offenders 0. No emulator exists |
| G8.4 | PASS | PM1 vs CO_OCCURS twin: EQUIVALENCE_CLASS off → IDENTIFIED with 44 REORDER worlds (lab_oracle_authored); DROPOUT: UNIDENTIFIABLE/ONLY_UNDER_INCOMPLETE_OBSERVATION; ORACLE stopped TELEMETRY_FAILURE (visibility 1.0); 5-match → INSUFFICIENT_EVIDENCE; 66 run verdicts, 65 non-IDENTIFIED, 0 forced; 105 open-world residuals all UNEXPLAINED_ESCALATION |
| G8.5 | PASS | 20 SURVIVED → 20 REPLICATION preregistrations in one batch → 19 REPRODUCED; 1 package, REPRODUCED; INDEPENDENT FP 0.0; independent positives available: False |
| G8.6 | PASS | 0 claims permitted; PM3 control → KNOWN (`stage1:ATTACK_EXFIL`); H4, H8 NOT_REVIEWED |
| G8.7 | PASS | 2 tournaments, reselection reproduces both; PM2 → `MOTIF_CANNOT_EXPRESS_REPEATED`; deployable 2/2 (FSM, MOTIF); 0 deployability violations |
| G8.8 | PASS | lineage RESIDUAL→…→FORGE_CANDIDATE complete for 2/2; HMAC round-trips 2/2; flipped artifact byte and edited ledger entry detected 2/2 |
| G8.9 | PASS (path only) | boundary rules 5/6/7/10/11: 0 offenders; 8 capsules: created = admitted = gateway offered = 8, all TRANSITION_EPISODE, DERIVED_INFERENCE, INFERENCE, one group, SIMULATED_RECORD; buckets {UNCERTAIN: 8}; TRUSTED_CANDIDATE 0 |
| G8.10 | PASS | rules 3/8/9/12/13: 0 offenders; constitution 0 problems; 108/108 authority-key injections refused; 0 offensive vocabulary members |
| G8.11 | PASS | flood: budget exhausted at 197142 units, 9859 texts refused, stores within caps; endurance 12/12 cycles plateau_ok; one 216-byte artifact, endpoint incremental RSS 28672 B ≤ 20 MiB |
| G8.12 | **FAIL** | by construction (synthetic); plus: null DEGENERATE, ORACLE NOT_YET_JUSTIFIED, 16 of 17 ablation rows not JUSTIFIED, FORGE loses to the direct model on recall |

## M.2 The trap, and why G8.1 fails

In `run_discovery` the trap is born (SYMBOLIC_ENUMERATOR proposes `SINGLE(SPAWN)`), then the
pre-holdout `COUNTERFACTUAL_INVARIANCE` screen refutes it: `DECOY_INSERTION` copies fork steps
from other LAB_POOL sessions, so the trap is not invariant. It is never registered. G8.1(d) as
written requires generated AND registered AND refuted, so G8.1 FAILS. `probe_trap_at_holdout`
registers the trap alone and the vault falsifies it at HOLDOUT. Rewording (d) to read the probe
would be re-operationalising a criterion to pass (spec §12); it is left to the lead (ADR-0073).
The NAIVE control (select on TRAIN at the genome's own HOLDOUT rules, no vault, no screens)
selects the trap among its 35 selections: the trap is refuted only with the discipline.

## M.3 Against the baselines (spec §7)

From G8.12 of the gate run (same corpus, same `ResearchBudget`, seeds 0–2):

| arm | families recovered per seed | false reproduced | work units per seed |
|---|---|---|---|
| PROMETHEUS | 1, 1, 1 (DROP_EXEC_EGRESS) | 0, 0, 0 | 9417205, 9068403, 9062197 |
| RANDOM_BASELINE | 0, 0, 0 | 0, 0, 0 | 5948165, 5988550, 5937876 |
| EXHAUSTIVE_SINGLE_BASELINE | 0, 0, 0 | 0, 0, 0 | 7274061, 7416962, 7235433 |

- Verdict JUSTIFIED by the spec's rule (strictly more families than random, beyond exhaustive).
  Neither baseline exhausted its budget; PROMETHEUS spent ~1.5× random's work units.
- Baseline (1): Φ-oracle REPLICATION recall 0.2927 at FPR 0.0; with the packages 0.6463 at
  FPR 0.0; 29 of 58 Φ-missed positives caught. `counterfactual_at_boundary`.
- **PM2 (REPEATED_EGRESS) and PM3 (CREDENTIAL_EGRESS) are never recovered.** PM2 was expected to
  die to its MONITORING_AGENT doppelgänger (spec §9.2); PM3 is the rediscovery control.
- Null FDR over 20 label seeds (content seed 0): disciplined mean reproduced 0.000, NAIVE mean
  selected 0.000 → **DEGENERATE**. The NAIVE control applies the genome's HOLDOUT rules (FPR ≤ 0.01,
  recall ≥ 0.10) in-sample, which already selects nothing on noise. M0.5 predicted this risk.

## M.4 Does each component earn its existence? (ablation, one row per flag)

| flag | verdict | firings | outcome changes |
|---|---|---|---|
| holdout_discipline | JUSTIFIED | 34 | 69 |
| residual_motif | NOT_YET_JUSTIFIED | 2 | 46 |
| diversity | NOT_YET_JUSTIFIED | 64 | 32 |
| mutation | NOT_YET_JUSTIFIED | 85 | 21 |
| mdl | NOT_YET_JUSTIFIED | 227 | 21 |
| score_full | NOT_YET_JUSTIFIED | 34 | 25 |
| oracle | NOT_YET_JUSTIFIED | 3 | 7 |
| doppelganger_screen | NOT_YET_JUSTIFIED | 117 | 30 |
| priority_field | INERT | 2 | 0 |
| cost_aware | INERT | 3 | 0 |
| eig | INERT | 3 | 0 |
| bonferroni | INERT | 34 | 0 |
| negative_memory | INERT | 0 | 0 |
| analogy | INERT | 0 | 0 |
| null_benign | INERT | 0 | 0 |
| stage7_seed | INERT | 0 | 0 |
| external_proposal | INERT | 0 | 0 |

- `stage7_seed`, `external_proposal` and `analogy` have **no input** in the base configuration (no
  Stage 7 capsules, no external texts, no validated known mechanisms at start): INERT here means
  "not exercised", not "measured useless". `negative_memory` never hits within one run; it can only
  matter across cycles (endurance), which the ablation does not measure.
- ORACLE: EIG beats RANDOM/CHEAPEST only with the lab oracle (`lab_oracle_authored` True, replay
  False) → NOT_YET_JUSTIFIED under the production default (replay only).
- `threshold_sensitivity`: 9 rows (α, MDL gain per bit, FORGE tolerance); no value flips every
  outcome (THRESHOLD_DECIDES empty).
- Recommendation (lead's call, ADR-0078): the INERT rows are candidates for removal or default-off;
  none is flipped on one synthetic world.

## M.5 FORGE

- The one PLANTED package (`CO_OCCURS(WRITE,SEND)`, the dedup representative of the PM1 class)
  compiles to FSM: 216 bytes, 10.24 work units per event, deployable; the lab-on package selected
  MOTIF. DCR 778274.8 and 1399975.1 (discovery work units / deployed work units per event).
- Against the direct model (LOGISTIC on TRAIN labels, pooled features): direct REPLICATION recall
  0.6463 at FPR 0.2532 and 529.6 wu/event; the FSM recall 0.3537 at FPR 0.0 and 10.24 wu/event.
  The §7 rule (recall ≥ direct − 0.02 at ≤ its FPR) is **not met**: one mechanism covers one family.
- Endpoint footprint: 240 events, incremental RSS 28672 B (ceiling 20 MiB); the whole gate
  process (research state included) read 281.7 MB (final run; 285.0 MB in the first) against the 100 MB edge profile — recorded,
  not the endpoint figure.

## M.6 F14: the injection suite changes outcomes (measured in this session)

`run_discovery(PLANTED, seed 0)` with `external_texts=INJECTION_SUITE` vs without: REPRODUCED 19
→ 18, SURVIVED 20 → 19; among theories the suite did NOT propose, 7 REPRODUCED outcomes
disappeared and 6 appeared; planted recovery unchanged (DROP_EXEC_EGRESS only, both); the 3
injected theories that reached HOLDOUT were FALSIFIED. The injected genomes displace others in the
bounded population and the registration batch. Spec §8 F14 therefore **fires**: the research-agent
surface can steer which honest theories are tested, even though no injected theory survives. The
gate now reports F14 beside G8.2 (Appendix A).

## M.7 Stage 6 (B8-1)

8 capsules (one package, ≤ 8 evidence episodes), all `UNCERTAIN`, predicted provenance score 0.4
(`SIMULATED_RECORD`), TRUSTED_CANDIDATE 0. Realised adoption is 0 (ADR-0076, F15 fires).

## M.8 Resources and bounds

- Flood: 10 000 texts under 200 000 units → budget exhausted at 197142, 9859 texts refused,
  ledger 32 theories, lineage 34 nodes.
- Endurance, 12 cycles at half size, one long-lived ledger/memory/lineage/population: plateau_ok;
  final sizes ledger entries 9191, theories 2048 (cap), negative results 1024 (cap), lineage 290,
  population 256 (cap), adapter receipts 6; research-side RSS 247242752 → sampled peak 301420544 B;
  105.6 s wall at loadavg 2.27 (final run; the first run read 248664064 → 301793280 B, 120.2 s at 5.71). **Packages stop after cycle 6** (receipts 1..6 then flat): the
  long-lived population fills with earlier cycles' theories and new cycles' candidates are evicted.
  This is a finding about the long-lived ecology, not a bound violation.

## M.9 Defects and seams the integration fixed

1. **ORACLE prunes were refused by the ledger** (spec said CHALLENGED_OUT; the ledger admits that
   only after a failed challenge). Pruned theories stayed PROPOSED and were registered anyway, so
   ORACLE could change nothing. Now FOSSILIZED `oracle_posterior` (ADR-0078). PLANTED seed 0:
   registered 41 → 34, HOLDOUT-falsified 21 → 14, REPRODUCED 19 → 19.
2. **`run_endurance` crashed at cycle 8** (`LedgerError: … is not in the ledger`): a population
   member folded out of the ledger could not be evicted. Now counted `evicted_folded` (2 in the
   12-cycle run); pinned by `tests/test_stage8_gate.py`.
3. Boundary checker moved into `pocketsec/stage8/gate_boundary.py` (one copy; the test attacks it).
4. `pocketsec/stage8/__init__.py` written (eager, Stage 9 interface only; a lazy table failed rule 13).
5. `PENDING_MODULES` emptied; every core-id symbol resolves.
6. Run report carries the run's ledger, lineage and adapter counters; receipts carry
   capsule kinds and SIMULATED_RECORD counts, so the gate audits the run rather than a summary.

## M.10 Tests

`PYTHONHASHSEED=0 python -m pytest -q -p no:cacheprovider --junitxml=…`: **4750 tests, 4 failed,
0 errors**, 1953.6 s. Stage 8: **508 tests, 0 failed**. The 4 failures belong to other stages:
`test_stage1_pipeline.py::test_stage1_acceptance_gate_passes` and `::test_gate_cli_exits_zero`
(G1.12 reads the whole pytest process's peak RSS — MEMORY Stage 9 trap 4),
`test_stage5_sentinel.py::test_the_sentinel_trusted_surface_stays_inside_its_ratchet`
(1370 > 1330 lines) and `test_stage9_boundary.py::…[transitive_stage5_reach]` (Stage 9's
harness reaches Stage 5 via `stage6.memory`). None of their files was touched by this session.

## Honesty ledger

### MEASURED
| claim | value | how it was produced (module:function) | experiment id | synthetic? |
|---|---|---|---|---|
| M0.1–M0.7 | see `docs/stage-8-spec.md` §0 | spec-time probes | — | yes |
| gate | 10/12, FAIL G8.1, G8.12 | `stage8.gate:run_gate` | PS-S8-20260926-BASE-prometheus-gate-0001 (not registered) | yes |
| trap refuted with discipline, selected without | refuted at screen; vault probe refutes at HOLDOUT; NAIVE selects it | `labs.discovery_run:run_discovery`, `probe_trap_at_holdout` | — | yes |
| search at equal budget | PROMETHEUS 1/1/1 families, RANDOM 0/0/0, EXHAUSTIVE 0/0/0 | `labs.baselines:compare_search` | — | yes |
| residual gain over Φ-oracle | recall 0.2927 → 0.6463 at FPR 0.0 → 0.0 | `labs.baselines:residual_gain` | — | yes |
| null FDR | disciplined 0.000, NAIVE 0.000 over 20 seeds → DEGENERATE | `labs.baselines:run_null_fdr` | — | yes |
| ablation | 1 JUSTIFIED, 7 NOT_YET_JUSTIFIED, 9 INERT | `labs.baselines:run_ablation` | — | yes |
| F14 | 7 lost / 6 gained REPRODUCED outcomes with the injection suite | scratch probe over `run_discovery` | — | yes |
| endpoint footprint | 28672 B incremental, 10.24 wu/event, 216 B artifact | `forge.tournament:measure_endpoint_footprint` | — | yes |
| Stage 6 buckets | UNCERTAIN 8, score 0.4, TRUSTED_CANDIDATE 0 | `adapters.stage6:Stage6Adapter.hand_over` | — | yes |

### UNMEASURED
| claim the architecture makes | why not measured | what would measure it | blocking? |
|---|---|---|---|
| discovery finds mechanisms in real telemetry | every corpus is authored | a real, labelled corpus with unknown mechanisms | yes (G8.12) |
| isolated active emulation is safe | no emulator | a real lab and an emulator | no (refused by construction) |
| identifiability under real sensor loss | synthetic dropout only | real telemetry outages | no |
| novelty against ATT&CK/Sigma/YARA/literature | no offline index, no network | an index | no (no claim is made) |
| endpoint cost on a 2 GB device | dev host only | a device run | no |
| realised Stage 6 adoption | B8-1: Stage 6 admits nothing | a Stage 6 decision | yes (F15) |
| INERT generators with input (stage7_seed, external_proposal, analogy) | the base config supplies none | ablation with Stage 7 capsules / texts / known mechanisms | no |

### REJECTED
| component | measured effect | verdict (REJECTED / NOT-YET-JUSTIFIED / RETRACTED / INERT / DEGENERATE / HARMFUL) | ADR |
|---|---|---|---|
| null test as evidence for the discipline | NAIVE also selects 0 | DEGENERATE | ADR-0077 |
| ORACLE (EIG) on replay | does not beat RANDOM/CHEAPEST without the lab oracle | NOT-YET-JUSTIFIED | ADR-0078 |
| priority field, cost_aware, eig, bonferroni, negative memory | 0 outcome changes | INERT | ADR-0078 |
| residual_motif, diversity, mutation, mdl, score_full, oracle, doppelgänger screen | change outcomes, no primary-metric gain | NOT-YET-JUSTIFIED | ADR-0078 |
| FORGE vs direct model on recall | 0.3537 vs 0.6463 | NOT-YET-JUSTIFIED (on recall) | ADR-0079 |

### RETRACTED
| retracted claim | where it was published | the defect | corrected value |
|---|---|---|---|
| "ORACLE prunes theories" (spec D8.6) | builder's OracleReport.pruned count as outcome changes | prunes were refused by the ledger and the theories were registered anyway | fixed: FOSSILIZED; 7 fewer registrations on PLANTED seed 0 |

### NOT A DETECTION RESULT
Every corpus is synthetic and its planted truth shares an author with the engine; every detection
gain is a counterfactual at the Stage 8→Stage 6 boundary, because Stage 6 adopts no Stage 8 discovery.

### PARAMETERS
Every §4.21 constant is chosen, not measured: `MAX_EPISODE_STEPS` 64, `MAX_EPISODE_EVIDENCE` 32,
`MAX_MECHANISM_STEPS` 2, `MAX_REPEAT` 8, `MAX_DSL_BYTES` 256; scope/forbidden/competitor/
falsifier/parent/request caps 16/64/4/8/8/2/4; α 0.05, HOLDOUT FPR ceiling 0.01, min recall 0.10,
invariance 0.98, necessary-step drop 0.50, doppelgänger share 0.05; `DEFAULT_RESEARCH_WORK_UNITS`
50 000 000; `ResearchBudget` caps 16, 32, 256, 4, 8, 128, 64, 256, 64; `MAX_RESIDUALS` 4096,
`MAX_CLUSTER_MEMBERS` 64, `FPR_BUDGET` 0.01; `RECURRENCE_SATURATION` 8; `MIN_BENIGN_SHARE` 0.2;
`MAX_STAGE7_SEEDS` 64; population 256, depth 4, 64 mutations, 3 generations, MDL gain 0.01;
lineage 8192/16384/256; ORACLE noise 0.05, stop 0.95, EIG/unit 1e-4, prune 0.01, 16 experiments;
16 doppelgängers per family, 32 challenges per kind; identifiability 3 and 10; ledger 16384/2048,
negative 1024; sandbox 4096, 1 batch, 2048 episodes, vault log 1024; imbalance 20, 0.5,
independent FP 0.01; FSM 8 states, stump depth 2; FORGE tolerances 0.02/0.02/0.0, agreement 0.98,
64 KiB, 20 MiB; 8 capsules per package, 1024 receipts; the corpus counts, mix and trap probability
of §4.19; `NULL_SEEDS` 20, 0.10, 0.10. Chosen, not measured.

## Appendix A — the final gate run, verbatim

`PYTHONHASHSEED=0 python -m pocketsec.stage8.cli gate; echo "exit=$?"`, run after the last code
change of this session:

```text
start 2026-09-26T22:20:30+10:00 loadavg 2.75 3.53 4.81 2/2094 510343
PocketSec Stage 8 acceptance gate (synthetic discovery corpus, author-confounded; see docs/stage-8-spec.md §6.1)

  [FAIL] G8.1  Every hypothesis has explicit falsification conditions
         (a) malformed genomes refused 6/6; (b) 1631 genomes born over 4 runs, 117 registered, 117 tested, problems 0; (c) edits after test refused 3/3; (d) trap in run_discovery: generated=True registered=False refuted=True at challenge:COUNTERFACTUAL_INVARIANCE. The spec requires generated AND registered AND refuted in the loop; a pre-holdout screen refuting it before registration does NOT meet the literal clause (reported, not re-worded). Isolated vault probe (probe_trap_at_holdout): registered=True refuted=True at HOLDOUT. F2 (trap survives HOLDOUT) did not fire
  [PASS] G8.2  Free-form LLM text is never the canonical scientific state
         (a) injection suite 24 texts: 8 parsed (exactly their mechanisms: True), 16 refused, source_digest = sha256(text): True; (b) canary scan over 1542 ledger/genome/package payloads of the injection run: 0 of 23 non-empty raw proposal strings found; 13 external-proposal genomes born, each carrying only a sha256 source digest; (c) undeclared string fields in the state modules: 0 (declared: 50 ids/digests/codes); (d) equal content -> equal id: True; render() absent from the stored form: True; from_dict(to_dict()) round-trips: True. Reported beside the criterion: F14 FIRED: with the suite, 7 held-out outcomes of non-injected theories disappeared and 6 appeared (REPRODUCED 19 -> 18; planted families recovered 1 -> 1): injected theories displace others in the bounded population and registration batch. No LLM is built (ADR-0074).
  [PASS] G8.3  All active emulation is isolated and authorised
         (a) ExperimentClass = the 6 safe classes + ISOLATED_EMULATION, no production-intervention member: True; (b) emulation refusals 4 (no clearance, expired, wrong scope, valid clearance -> REFUSED_NO_EMULATOR), wrong outcomes 0, audited 4/4; (c) ORACLE experiment records in the gate's runs: 17, not ALLOWED-and-safe 0; (d) boundary rule 8 offenders 0. There is no emulator (ADR-0075): isolation of a real emulation is UNMEASURED; this criterion holds by construction only
  [PASS] G8.4  Unknown/unidentifiable outcomes are preserved rather than forced into conclusions
         (a) PM1 vs CO_OCCURS twin, interventions off: EQUIVALENCE_CLASS; with 44 REORDER worlds + lab oracle: IDENTIFIED (lab_oracle_authored); (b) DROPOUT PM1 vs PRECEDES(WRITE+TEMP_LOCATION,CONNECT+EXTERNAL_ENDPOINT): UNIDENTIFIABLE/ONLY_UNDER_INCOMPLETE_OBSERVATION; (c) 5-match candidate: INSUFFICIENT_EVIDENCE -> INSUFFICIENT_EVIDENCE; ORACLE stops on DROPOUT (stop, visibility share): [('telemetry_failure', 1.0), ('observationally_equivalent', 0.0), ('observationally_equivalent', 0.0)]: TELEMETRY_FAILURE fired True; (d) run verdicts 66, non-IDENTIFIED 65, problems 0; (e) unlabelled LAB_POOL (120 episodes): residual kinds {'UNEXPLAINED_ESCALATION': 105}; none assigned a known class: True. Met as mechanism; value on real sensor loss is UNMEASURED
  [PASS] G8.5  Validated discoveries reproduce across predefined independent splits
         PLANTED preconditions OK; SURVIVED 20; REPLICATION preregistrations 20 in one batch (batch sizes [20]), results 20, all registered first: True; REPRODUCED 19; packages 1 by status {'REPRODUCED': 1}; built from a non-REPRODUCED theory 0; independent_positives_available [False]; INDEPENDENT FP rates [0.0]. Predefined synthetic splits (hosts h09-h12, epoch 2, family variants); independence from the corpus author is UNMEASURED
  [PASS] G8.6  Novelty is classified conservatively and not claimed without prior-art review
         (a) packages 2, novelty classes {'KNOWN_COMBINATION': 1, 'CONTEXT_EXTENSION': 1}, claims permitted 0, non-local technique ids 0; (b) rediscovery control PM3 -> KNOWN, matched ['stage1:ATTACK_EXFIL']; (c) 'novel' outside POTENTIALLY_NOVEL 0; (d) prior-art reviews {'H4': ('NOT_REVIEWED', 'NOT_REVIEWED'), 'H8': ('NOT_REVIEWED', 'NOT_REVIEWED')}. ATT&CK/Sigma/YARA/literature indexes are NOT BUILT: novelty against them is UNMEASURED
  [PASS] G8.7  FORGE selects by measured security/resource Pareto performance
         tournaments 2; (a)+(b) entrant/reselection problems 0; (c) refusals in tournaments {'MOTIF_CANNOT_EXPRESS_CO_OCCURS': 1}, PM2 compiled directly -> MOTIF refusal MOTIF_CANNOT_EXPRESS_REPEATED; (d) deployable 2/2, selected {'FSM': 1, 'MOTIF': 1}, deployability violations 0; (e) DCR [778274.7925142392, 1399975.1057401812]; direct model (LOGISTIC on TRAIN labels) REPLICATION recall 0.6463414634146342 FPR 0.25316455696202533 wu/event 529.6
  [PASS] G8.8  Every DiscoveryPackage has complete lineage and failure conditions
         packages 2; lineage/ledger/verify problems 0; sign_record/verify_record round-trips 2/2 (HMAC: local integrity, not identity, ADR-0064 precedent); one flipped artifact byte detected 2/2 packages with an artifact; one edited ledger entry detected 2/2
  [PASS] G8.9  All endpoint adoption passes Stage 6
         (a) boundary rules 5, 6, 7, 10, 11 offenders 0; rule 16 in-gate: the adapter refused 2/2 non-package objects (the gateway/Stage 5 type refusals are tests/test_stage8_boundary.py::test_rule16_*: calling admit or importing Stage 5 here would itself break rules 3 and 7); (b) capsules 8, problems none; (c) Stage 6 buckets verbatim {'UNCERTAIN': 8}, predicted provenance scores [0.4]. Realised adoption (TRUSTED_CANDIDATE) = 0: B8-1, ADR-0076 — met as a path only
  [PASS] G8.10  Stage 8 does not create a new direct path to Stage 5 authority
         boundary rules 3, 8, 9, 12, 13 offenders 0; verify_discovery_constitution() problems 0; authority words refused 108/108 at every probed depth of HypothesisGenome.from_dict and DiscoveryPackageV1.from_dict; closed-vocabulary members matching OFFENSIVE_TOKENS 0. No Stage 8 module imports Stage 5; the Stage 5 entry-guard refusal of a package is tested in tests/test_stage8_boundary.py (the gate may not import Stage 5)
  [PASS] G8.11  Research cost is allowed to be high offline; deployed intelligence remains lightweight
         (a) flood of 10000 texts under 200000 units: budget_exhausted True, spent 197142, stores within caps True (theories 32, entries 32, lineage nodes 34), external texts refused 9859, governor refusals {'work_units': 1}; (b) endurance 12/12 cycles, plateau_ok True, problems [], final store sizes {'ledger_entries': 9191, 'ledger_theories': 2048, 'negative_results': 1024, 'lineage_nodes': 290, 'population': 256, 'adapter_receipts': 6}, packages 6, capsules created/admitted 48/48, research RSS start 247242752 B sampled peak 301420544 B (research side, not the endpoint), wall 105.6 s at loadavg (2.27, 2.89, 4.24); (c) shipped detectors 1, artifact bytes [216] (max 65536); endpoint incremental RSS 28672 B vs ceiling 20971520 B: within; 240 events, 10.241666666666667 wu/event, wall 0.0010 s at loadavg (2.27, 2.89, 4.24); whole gate process vs the edge profile (recorded, not asserted; includes research state): {'profile': 'edge', 'within_target': False, 'observations': ['peak agent RSS 281.7 MB'], 'exceeded': ['agent_rss 281.7 MB > 100 MB target'], 'unmeasured': ['model_bytes']}; DCR [778274.7925142392], knowledge_bytes_saved [5111]. In-process on the dev host; device figures on a real 2 GB endpoint are UNMEASURED
  [FAIL] G8.12  Advanced mechanisms beat or justify themselves against simpler baselines
         FAILS BY CONSTRUCTION: synthetic_data True (PASS requires False, spec §6.1). Preconditions per arm {'PLANTED': [], 'DROPOUT': ['P5: 0.9669 violates pooled logistic HOLDOUT AP < 0.95'], 'NULL': ['P5: 1.0000 violates pooled logistic HOLDOUT AP < 0.95']}; search JUSTIFIED: PROMETHEUS recovered (1, 1, 1) families ['DROP_EXEC_EGRESS'] false (0, 0, 0) wu (9417205, 9068403, 9062197) exhausted (False, False, False), RANDOM_BASELINE recovered (0, 0, 0) families [] false (0, 0, 0) wu (5948165, 5988550, 5937876) exhausted (False, False, False), EXHAUSTIVE_SINGLE_BASELINE recovered (0, 0, 0) families [] false (0, 0, 0) wu (7274061, 7416962, 7235433) exhausted (False, False, False); beats random True; beyond exhaustive ['DROP_EXEC_EGRESS']; residual gain over the Φ-oracle (counterfactual_at_boundary): Φ missed 58, packages caught 29, recall Φ 0.2926829268292683 -> Φ OR packages 0.6463414634146342, FPR 0.0 -> 0.0, beats Φ True; null FDR DEGENERATE over 20 label seeds: disciplined mean reproduced 0.000 (share with any 0.000), NAIVE mean selected 0.000 (share 0.000); ORACLE NOT_YET_JUSTIFIED: EIG beats cheap (('replay_only', False), ('lab_oracle_authored', True)); PLANTED trap refuted with discipline True; selected by the NAIVE control True (NAIVE selected 35); FORGE vs direct model (recall 0.6463414634146342, FPR 0.25316455696202533, 529.6 wu/event): selected (kind, recall, FPR, wu/event, wins) [('FSM', 0.35365853658536583, 0.0, 10.241666666666667, False)]; ablation rows 17 (missing OPTIONAL flags []): {'priority_field': 'INERT(fired 2, changed 0)', 'residual_motif': 'NOT_YET_JUSTIFIED(fired 2, changed 46)', 'analogy': 'INERT(fired 0, changed 0)', 'null_benign': 'INERT(fired 0, changed 0)', 'stage7_seed': 'INERT(fired 0, changed 0)', 'external_proposal': 'INERT(fired 0, changed 0)', 'diversity': 'NOT_YET_JUSTIFIED(fired 64, changed 32)', 'mutation': 'NOT_YET_JUSTIFIED(fired 85, changed 21)', 'mdl': 'NOT_YET_JUSTIFIED(fired 227, changed 21)', 'score_full': 'NOT_YET_JUSTIFIED(fired 34, changed 25)', 'oracle': 'NOT_YET_JUSTIFIED(fired 3, changed 7)', 'cost_aware': 'INERT(fired 3, changed 0)', 'eig': 'INERT(fired 3, changed 0)', 'doppelganger_screen': 'NOT_YET_JUSTIFIED(fired 117, changed 30)', 'negative_memory': 'INERT(fired 0, changed 0)', 'holdout_discipline': 'JUSTIFIED(fired 34, changed 69)', 'bonferroni': 'INERT(fired 34, changed 0)'}; threshold_sensitivity rows 9, THRESHOLD_DECIDES []; catalogue problems 0 []; registry.jsonl byte-identical True; findings headings missing []; ADRs missing []; HYPOTHESES == H0..H8 True. Not justified here: ['null FDR DEGENERATE', 'ORACLE NOT_YET_JUSTIFIED', 'ablation:analogy', 'ablation:bonferroni', 'ablation:cost_aware', 'ablation:diversity', 'ablation:doppelganger_screen', 'ablation:eig', 'ablation:external_proposal', 'ablation:mdl', 'ablation:mutation', 'ablation:negative_memory', 'ablation:null_benign', 'ablation:oracle', 'ablation:priority_field', 'ablation:residual_motif', 'ablation:score_full', 'ablation:stage7_seed']

  timings (label, wall s, loadavg) — observations, never asserted:
    corpus planted               1.391  (2.61, 3.49, 4.79)
    corpus dropout               1.448  (2.61, 3.49, 4.79)
    preconditions PLANTED        3.254  (2.56, 3.47, 4.77)
    preconditions DROPOUT        3.243  (2.56, 3.47, 4.77)
    corpus null                  1.582  (2.52, 3.44, 4.76)
    preconditions NULL           3.297  (2.52, 3.44, 4.76)
    run planted                 32.918  (2.78, 3.41, 4.7)
    run planted lab-on          15.838  (2.75, 3.37, 4.66)
    run planted injected        30.498  (2.71, 3.3, 4.6)
    run planted naive            4.227  (2.65, 3.28, 4.58)
    trap probe                   0.002  (2.65, 3.28, 4.58)
    run dropout                 36.803  (2.5, 3.17, 4.5)
    run flood                    3.303  (2.46, 3.15, 4.48)
    endurance                  105.775  (2.27, 2.89, 4.24)
    endpoint footprint           0.012  (2.27, 2.89, 4.24)
    phi-oracle baseline          0.001  (2.27, 2.89, 4.24)
    residual gain                0.001  (2.27, 2.89, 4.24)
    direct model                 0.766  (2.27, 2.89, 4.24)
    compare search             133.593  (2.46, 2.74, 4.0)
    null fdr                   443.729  (4.03, 3.1, 3.59)
    oracle comparison          200.034  (2.16, 2.76, 3.37)
    ablation                   663.050  (18.04, 11.39, 6.82)
    threshold sensitivity      263.228  (10.31, 8.94, 6.84)

loadavg at end of run: 11.43 9.23 6.96
10/12 criteria met
GATE: FAILED (2)
exit=1
end 2026-09-26T22:53:13+10:00 loadavg 11.43 9.23 6.96 6/2235 745785
```
````

## Honesty ledger

Every row below was produced by running code in this measurement session (2026-09-26/27). Figures
the integration session published and this session did not re-measure appear only in Appendix B.
Experiment ids are `PS-S8-20260926-…`; the prefix is omitted below.

### MEASURED
| claim | value | how it was produced (module:function) | experiment id | synthetic? |
|---|---|---|---|---|
| trap-free PLANTED content is solved by an order-free model | pooled logistic HOLDOUT AP **1.0000** (NULL content 0, content labels) | `stage8.labs.discovery_corpus:corpus_preconditions` via `benchmarks/stage8/saturation.py:null_content` | BASE-saturation-direct-model-0102 | yes |
| P5 on PLANTED passes only with the trap | 0.9178 / 0.9049 / 0.8996 (seeds 0/1/2); trap steps stripped 0.9268 / 0.9157 / 0.9151 | `corpus_preconditions` (`pooled_logistic_holdout_ap`, `…_trap_stripped_…`) | …-0102 | yes |
| direct model, equal information (TRAIN + HOLDOUT labels) | REPLICATION AP **1.0000**, recall **1.0** at FPR **0.0**, 3/3 seeds (HOLDOUT-only: identical) | `stage1.guillotine.features:LogisticProbe` on `stage8.forge.representations:pooled_features` (`saturation.py:direct`) | …-0102 | yes |
| direct model as the gate fits it (TRAIN labels) | AP 0.8684 / 0.8890 / 0.8567; recall / FPR at 0.5: 0.6463 / 0.2532, 0.6951 / 0.2468, 0.6220 / 0.2722 | same | …-0102 | yes |
| Φ-oracle on REPLICATION (baseline 1) | recall 0.2927, FPR 0.0, 58 positives missed, threshold 0.522388, 3/3 seeds | `stage8.labs.baselines:phi_oracle_baseline` | …-0102 | yes |
| PROMETHEUS planted recovery | DROP_EXEC_EGRESS on 9/9 runs (3 content seeds), false 0, 8 919 244 – 9 417 205 work units | `stage8.labs.discovery_run:run_discovery` | BASE-search-controls-0104, -0106, -0108 | yes |
| Φ ∪ REPRODUCED packages on REPLICATION | recall **0.6463** at FPR 0.0 (29 of 58 Φ-missed caught) in every recovering arm | `stage8.labs.baselines:residual_gain` | …-0104 | yes |
| random search at ≤ PROMETHEUS's spend | **0 / 26** runs recover anything (spend 5.87 – 9.78 M); 5 / 39 overall, each at ≥ 15 054 002 units | `run_discovery` with `RandomGenerator(count=512…3840)` | …-0104, BASE-random-spend-curve-0106 | yes |
| minimal engine (enumerator + discipline) | DROP_EXEC_EGRESS on 7/7, false 0; work units 0.727–0.760 of PROMETHEUS's | `run_discovery` (`search_controls.py:minimal_config`) | …-0104, …-0108 | yes |
| brute force of the ≤ 2-step class (2539) through the identical discipline | DROP_EXEC_EGRESS on 7/7, false 0, 1.586–1.665× PROMETHEUS's work units; without the doppelgänger screen 0/7 | `search_controls.py:run_exhaustive_engine` over `stage8.labs.discovery_run:_Run` | …-0104, …-0108 | yes |
| full-family Bonferroni over the class (offline) | PM1, PM2, PM3; Φ ∪ reproduced recall 1.0 / FPR 0.0; INDEPENDENT FP 26/120 and 24/120; with the per-mechanism INDEPENDENT and doppelgänger rules: PM1, PM3; 0.6463 / 0.0; 0/120 | `search_controls.py:exhaustive_bonferroni` (`sandbox.integrity:binomial_upper_tail`) | …-0104, …-0108 | yes |
| what is shipped | 1 package, `CO_OCCURS(WRITE,SEND)`; 19 REPRODUCED, none is PM1's form | `run_discovery` report | …-0104 | yes |
| transfer to Stage 1 eval corpora (package) | recall / FPR: replay 0.000 / 0.0, hard 0.000 / 0.0, ambiguous 0.500 / 0.35, long-horizon 1.000 / 1.00 | `benchmarks/stage8/transfer.py` (+ `stage0.benchmark.harness:run_benchmark` for Φ ∪ package) | BASE-transfer-stage1-0101 | yes |
| identifiability, interventions off | EQUIVALENCE_CLASS 20 / 20; IDENTIFIED share of reproduced 0.0 (F10 fires) | `stage8.identifiability.gate:IdentifiabilityGate.assess` via `run_discovery` | H8-ablation-rerun-0107 | yes |
| trap | refuted before registration in every disciplined run; `probe_trap_at_holdout` refutes at HOLDOUT; NAIVE selects it among 35 | `run_discovery`, `probe_trap_at_holdout` | …-0107 | yes |
| null FDR, engine | disciplined mean reproduced **0.000** (20 seeds, registered 2–36 each); NAIVE 0.000 → DEGENERATE | `stage8.labs.baselines:run_null_fdr` | BASE-null-fdr-0105 | yes |
| null, whole class (2381) | significance-only in-sample: mean 32.4, max 184, 11/20 seeds > 0; + rate rules: 0/20; HOLDOUT at α/64 and α/N: 0/20 | `benchmarks/stage8/null_fdr.py:part_b` | …-0105 | yes |
| ablation | 1 JUSTIFIED (`holdout_discipline`), 7 NOT_YET_JUSTIFIED, 9 INERT; identical to the gate's rows | `stage8.labs.baselines:run_ablation` | …-0107 | yes |
| ORACLE policies | replay: correct leading 0/3 for every policy; EIG_PER_COST work units = CHEAPEST's exactly (43 252, 27 135, 30 080); lab oracle: EIG 3/3 correct, RANDOM/CHEAPEST 0/3 → NOT_YET_JUSTIFIED | `stage8.labs.baselines:oracle_comparison` | …-0107 | yes |
| threshold sensitivity | α 0.01–0.10: 0/34 outcomes change; MDL gain 0.0/0.05: 22/34 and 15/34 change, family unchanged; FORGE tolerance: 0 change; THRESHOLD_DECIDES empty | `stage8.labs.baselines:threshold_sensitivity` | …-0107 | yes |
| ORACLE crash defect | 10 / 39 random-generator runs abort with `ContractError` (8/25 curve, 2/14 search controls); deterministic repro | `stage8.oracle.planner:OraclePlanner.run` → `oracle.information_gain` `restricted` | …-0106 | yes |
| FORGE tournament | FSM 216 B, 10.24 wu/event, recall 0.3537, FPR 0.0, agreement 1.0 = TYPED_RULE (11.03 wu/event, 2475 B); MOTIF refused | `stage8.forge.tournament:run_tournament` via `run_discovery` | …-0107 | yes |
| endpoint through the Stage 0 harness | Φ ∪ FORGE recall 0.6463 / FPR 0.0 / PR-AUC 0.7672 at 5.12e-06 CPU s/event; D2 1.0 / 0.0 / 1.0000 at 2.53e-05 (**4.93×**), loadavg 23 | `stage0.benchmark.harness:run_benchmark` | H4-endpoint-harness-0103 | yes |
| deployed artefact footprint | 4096 B incremental RSS over 240 episodes; within the 20 MiB ceiling | `stage8.forge.tournament:measure_endpoint_footprint` | …-0103 | yes |
| research-side cost of one run | +147 914 752 B sampled RSS; 83.48 CPU s; 8.86 µs per work unit (loadavg 24.9) | `stage0.benchmark.resource_metrics:ResourceSampler` around `run_discovery` | …-0103 | yes |
| runaway flood hits the budget | 10 000 texts / 200 000 units: exhausted at 197 142; 9 859 refused; +4 KB | `run_discovery(external_texts=stage8.gate:flood_texts())` | …-0103 | yes |
| 10× flood under the default budget | 199 718 refused by the proposal cap; +4.1 MB; registered 34 → 25, reproduced 19 → 18 (F14 fires) | same, 100 000 texts | …-0103 | yes |
| endurance | 12/12 cycles, plateau_ok; stores at caps; packages stop after cycle 6; RSS +55.2 MB; 697.2 s at loadavg 23–24 | `stage8.labs.discovery_run:run_endurance` | …-0103 | yes |
| gate re-run | 10/12, GATE: FAILED (2), exit 1 (G8.1, G8.12); identical decisive figures to the integration session; 78.6 min at loadavg 29.8 → 3.0; registry byte-identical True | `stage8.gate:run_gate` (`python -m pocketsec.stage8.cli gate`) | not registered (spec §2.5) | yes |
| structure and Stage 8 boundary tests with `benchmarks/stage8/` present | 135 tests, 0 failed, 0 errors | `pytest tests/test_repository_structure.py tests/test_stage8_boundary.py` | — | n/a |
| gate tests (incl. every cited ADR exists), structure and boundary, after this document and the ADR amendments were installed | 146 tests, 0 failed, 0 errors, 309.1 s at loadavg ~5 | `pytest tests/test_stage8_gate.py tests/test_repository_structure.py tests/test_stage8_boundary.py --junitxml` | — | n/a |

### UNMEASURED
| claim the architecture makes | why not measured | what would measure it | blocking? |
|---|---|---|---|
| discovery finds useful mechanisms in real telemetry | every corpus is authored; the one non-Stage-8 synthetic check (Stage 1 corpora) shows no transfer | a real, labelled corpus with unknown mechanisms | yes |
| PROMETHEUS machinery beyond the enumerator helps on any corpus | the only corpus where discovery can beat the Φ-oracle is saturated for an order-free model | a non-saturated corpus (trap-free logistic AP well below 0.95) on which ENUM_MIN fails and PROMETHEUS succeeds | yes |
| the vault and Bonferroni stop noise | on this null the in-sample rate rules already admit 0/20 | a null on which rate-rule NAIVE selection admits mechanisms | no |
| ORACLE beats cheap experiment selection on replay | ORACLE crashes in 10 measured runs; on replay it never leads correctly and costs what CHEAPEST costs | a fixed ORACLE on a corpus with non-trivial clusters | no |
| endpoint cost on a 2 GB device | dev host only; the harness's process RSS includes research state | a device run of the shipped artefact | no |
| realised Stage 6 adoption | B8-1: Stage 6 has no detector-candidate kind | a Stage 6 decision | yes (F15) |
| isolated active emulation | no emulator exists | a lab and an emulator | no |
| novelty against ATT&CK / Sigma / YARA / literature | no offline index, no network | an index | no |
| STAGE7_SEED, EXTERNAL_PROPOSAL, ANALOGY with input | the base configuration supplies none | ablation with Stage 7 capsules, honest texts, validated known mechanisms | no |
| F7's second clause (TRAIN F1 of HOLDOUT-killed theories) | the folded ledger does not keep them retrievable (§M.9 item 5) | retain fits of FALSIFIED theories | no (the first clause decides F7) |

### REJECTED
| component | measured effect | verdict (REJECTED / NOT-YET-JUSTIFIED / RETRACTED / INERT / DEGENERATE / HARMFUL) | ADR |
|---|---|---|---|
| the discovery engine as a detection mechanism, against the equal-information direct model | recall 0.6463 (Φ ∪ packages) vs 1.0, both at FPR 0.0, 3/3 seeds | NOT-YET-JUSTIFIED | ADR-0077 |
| PROMETHEUS generators other than SYMBOLIC_ENUMERATOR, and the ecology terms (diversity, MDL, mutation, full score), priority field, negative memory | jointly removed (ENUM_MIN): same family on every run at 0.727–0.760 of the work units | NOT-YET-JUSTIFIED (recommend default-off) | ADR-0078 |
| the shipped package `CO_OCCURS(WRITE,SEND)` as a detector outside the authored world | 0/36, 0/44 on Stage 1 replay/hard; FPR 0.35 and 1.00 on ambiguous/long-horizon | REJECTED (as a transferable detector) | ADR-0077 |
| the PLANTED corpus as evidence that any discovery mechanism helps | trap-free content AP 1.0000 for an order-free model | DEGENERATE | ADR-0077 |
| the null test as evidence for the vault and Bonferroni | the rate rules alone admit 0/20; NAIVE also selects 0 | DEGENERATE | ADR-0077 |
| ORACLE (EIG) | crash defect in 10 runs; replay-only: 0/3 correct leaders, cost identical to CHEAPEST (F8 fires); helps only with the authored lab oracle | NOT-YET-JUSTIFIED (recommend default-off) | ADR-0078 |
| priority_field, cost_aware, eig, bonferroni, negative_memory, analogy, null_benign, stage7_seed, external_proposal | 0 outcome changes each | INERT | ADR-0078 |
| FORGE output against the equal-information direct model | recall 0.3537 (FSM alone) / 0.6463 (with Φ) vs 1.0, at 1/4.93 of its CPU per event | NOT-YET-JUSTIFIED (deployable by FORGE's own rule) | ADR-0079 |

### RETRACTED
| retracted claim | where it was published | the defect | corrected value |
|---|---|---|---|
| "random search and exhaustive single-step recover nothing **at equal budget**" read as PROMETHEUS's advantage | `docs/stage-8-findings.md` (integration session) Summary and §M.3; ADR-0077 Decision 2; MEMORY "Durable Stage 8 facts" | equal cap is not equal spend (RANDOM_512 spent 0.63×); single-step cannot express PM1 by construction; no control removed PROMETHEUS's own machinery | PROMETHEUS 9/9 vs random 0/26 at ≤ equal spend, but the enumerator alone 7/7 at 0.727–0.760 of the spend and brute force of the ≤ 2-step class 7/7 |
| "the direct model pays far more work units per event at a far higher FPR" | ADR-0079 Decision 5; findings §M.5 (FPR 0.2532) | the direct model was fitted on TRAIN alone, where the trap is a perfect feature | with the labels the loop reads: recall 1.0 at FPR 0.0; 4.93× the CPU per event |
| "PLANTED preconditions OK" (P5) | gate G8.12 detail `Preconditions per arm {'PLANTED': []…}` | P5 is passed only because the trap corrupts TRAIN | trap-free content AP 1.0000 |
| "PROMETHEUS recovers DROP_EXEC_EGRESS (PM1)" | findings Summary, PROGRESS, MEMORY | recovery is ≥ 0.98 agreement over the whole split; the recovered rule is `CO_OCCURS(WRITE,SEND)`, not PM1, and does not transfer | "recovers a rule co-extensive with the DROP_EXEC_EGRESS family in the authored corpus" |
| "the trap is refuted in every disciplined run" at `challenge:COUNTERFACTUAL_INVARIANCE` as evidence of falsification | findings Verdict 4 and §M.4; `TrapOutcome.refuted_at` | DECOY_INSERTION was PRESERVING for every hypothesis and adds non-escalating steps that a SINGLE over a non-escalating step matches (F1) | after the fix: trap agreement 1.0 under all five relations; registered; refuted at HOLDOUT by the vault (§F.1) |
| "the FSM is 7 % cheaper per event and 91 % smaller"; ADR-0079 amendment 1 "measured, cheaper" | findings §M.6; ADR-0079 | work units are self-charged; TYPED_RULE's bytes included genome metadata; the reviewer measured the FSM 1.23-1.26x slower in CPU | FSM wall ratio to TYPED_RULE median 1.081-1.099 (§F.6); FSM no longer deployable (194 B > 132 B decision-relevant, PM1 test corpus) |
| "search JUSTIFIED ... beats random True; beyond exhaustive [DROP_EXEC_EGRESS]" (gate output) | G8.12 detail; `compare_search` | an inexpressible single-step baseline and an unequal spend made it JUSTIFIED by construction (F7) | `search_verdict` counts only families the exhaustive arm can express and requires random to have spent at least as much (§F.7) |

### NOT A DETECTION RESULT
Every corpus is synthetic. The Stage 8 corpus's planted truth shares an author with the engine; the
Stage 1 corpora used for transfer share an author with each other but not with Stage 8, and are
still synthetic. Every detection gain is a counterfactual at the Stage 8 → Stage 6 boundary,
because Stage 6 adopts no Stage 8 discovery (B8-1). The strongest measured statement is negative:
on the authored world a trivial model with the same labels does better, and outside it the
discovered rule does not help.

### PARAMETERS
Every §4.21 constant of `docs/stage-8-spec.md` is chosen, not measured: `MAX_EPISODE_STEPS` 64,
`MAX_EPISODE_EVIDENCE` 32, `MAX_MECHANISM_STEPS` 2, `MAX_REPEAT` 8, `MAX_DSL_BYTES` 256; α 0.05,
HOLDOUT FPR ceiling 0.01, min recall 0.10, invariance 0.98, necessary-step drop 0.50, doppelgänger
share 0.05; `DEFAULT_RESEARCH_WORK_UNITS` 50 000 000 and the `ResearchBudget` caps (16, 32, 256, 4,
8, 128, 64, 256, 64); `FPR_BUDGET` 0.01; population 256, 3 generations, MDL gain 0.01; ORACLE noise
0.05, stop 0.95, prune 0.01; ledger 16384 / 2048, negative 1024; FORGE tolerances 0.02 / 0.02 / 0.0,
agreement 0.98, 64 KiB, 20 MiB; `NULL_SEEDS` 20; planted agreement 0.98. This session's own choices,
also chosen, not measured: the ≤ 2-step class (≤ 1 property bit and ≤ 1 raised bit per predicate
over TRAIN's observed steps, REPEATED k 2–8); EXH2_ENGINE's population cut (top 256 by TRAIN F1);
random draw counts 512, 768, 1024, 1280, 1536, 2048, 3840; the direct model's fit-side FPR ≤ 0.01
threshold and `LogisticProbe` defaults (learning rate 0.1, 400 iterations, L2 0.01); Stage 1
transfer counts (120, 120, 90, 60) and seed 11; flood sizes 10 000 and 100 000.
