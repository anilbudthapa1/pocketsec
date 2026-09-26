# Stage 9 — ONTOGENESIS — findings

- **Date:** 2026-09-26
- **Revision:** measurement-engineer re-measurement. Part I holds every figure this session
  produced by running code, with the command and its real output (Appendix A). Part II is the
  integration session's findings, **kept verbatim** with demoted headings. Where Part I
  contradicts Part II, Part I's measurement stands and the Part II claim is listed under
  RETRACTED in the ledger at the end. Nothing was deleted. **Part R** (review-wave fixes,
  2026-09-26/27) records confirmed defects fixed after Part I, with its own gate run; where
  Part R contradicts Part I or II, Part R stands and the claim is listed under RETRACTED.
- **Gate:** `python -m pocketsec.stage9.cli gate` → **GATE: FAILED (6)**, exit 1 (this
  session's run; 4 of 10 pass: G9.3 G9.5 G9.6 G9.10). Search evaluation counts, winners,
  held-out figures and the shuffled control reproduce Part II exactly. All six 96M-WU search
  determinism digests match between the gate process and an independent probe process.
- **Host:** 16,452,296,704 B MemTotal, 8 cores, shared. Another wave ran the Stage 8 gate and a
  full pytest during parts of this session. Load averages are printed beside every timing.
  Timings are within-run ratios on a contended host, never device figures.
- **Every corpus is synthetic and project-authored** (Stage 1 ambiguous corpus, count 240,
  seeds 3/11/17; ARGUS attacks authored by Stage 9). Nothing here is a detection result.

# Part R — review-wave fixes (2026-09-26/27)

Seven HIGH findings of an independent review survived refutation. Each was fixed in code with a
regression test that names the finding, and the gate was re-run on the fixed code. Every figure
below comes from that run or from a probe run in this session, pasted in R.4.

## R.1 What was wrong, and what the code does now

| finding | defect | fix | regression test |
|---|---|---|---|
| S9-R1, S9-CX-05 | fossil avoidance skipped only digests the run had already recorded, which the main arm also refused at 0 WU with no rng draw, so it could never change an outcome. `compare_arm` reported `fired = fossils_avoided` (4) instead of changed outcomes | `fired` counts seeds whose trajectory (recorded digests, WU at each record, winner, WU spent) differs; an arm that replays the main arm on every seed is **REJECTED as INERT** (ADR-0085 addendum C) | `test_fossil_avoidance_changes_no_outcome_and_is_rejected_as_inert` |
| S9-R7, S9-CX-07 (MEDIUM) | "already recorded" was checked after `evaluate`, so a duplicate evicted from the 4096-entry cache was re-scored at full cost and thrown away | checked before evaluation against the `known` set (bounded by `MAX_RECORDS`); the unreachable per-run cache was removed. No reported run exceeded 4096 evaluations, so their WU, records and determinism digests are unchanged | `test_a_re_proposed_digest_is_never_evaluated_again` |
| S9-R2, S9-FC-01, S9-CX-03 | "died under attack" killed every top-10 genome whose worst case was below the Φ-oracle's train worst case 0.5872; worst ≤ clean, so every genome weaker than the incumbent on clean data "died" with no attack | `FittestAttrition` headlines `died_under_attack` and prints `died_without_attack` (the no-attack control) and the old disjunctive count beside it (ADR-0083 addendum B) | `test_attrition_separates_attack_deaths_from_genomes_already_below_the_reference` |
| S9-R3 | the tampering trial's fallback swapped in a primitive of the wrong type for COUNT/SELECT/DECAY/B2F/side-table updates; the attacker's own IRError was counted as the digest check refusing | a same-signature partner is searched over every APPLY node, else a register-init change; a tampered artefact that cannot be built, or is refused for a reason other than `digest mismatch`, counts as NOT refused | `test_the_digest_trial_is_refused_by_the_digest_check_even_without_a_swap_partner`, `test_a_tampered_artefact_the_attacker_cannot_build_is_not_a_refusal` |
| S9-FC-02, S9-CX-01, S9-BOUND-01 | a session over `MAX_SESSION_EVENTS = 4096` was scored on its first 4096 events and returned an ordinary score; `truncated_events` reached nothing | such a session **abstains** unprocessed, overflow counted; `FitnessRecord.truncated_sessions` carries it; new ARGUS DEFENCE `session_cap_padding` (ADR-0082 addendum A) | `test_events_beyond_the_session_cap_are_counted_and_never_processed` (rewritten: it used to pin the fail-open score), `test_padding_a_session_past_the_event_cap_buys_unknown_not_a_benign_score`, `test_fitness_carries_sessions_that_hit_the_event_cap` |
| S9-R5, S9-FC-05 (MEDIUM) | G9.6's rollback parent is the Φ-oracle and one successor IS the Φ-oracle, so "restored scores = parent scores" held whatever the registry did; the registry's active genome was never checked | the evidence records the registry's active genome after install and after rollback and the installed genome's scores; G9.6 fails if the registry does not end on the parent, and fails if every rollback is indistinguishable from no rollback | `test_g9_6_refuses_a_rollback_that_cannot_be_told_from_no_rollback` |
| S9-R6, S9-INT-02 (MEDIUM) | 0.0 == -0.0 but canonical JSON differs, so a memoised genome digest depended on hashing order | FLOAT literals normalise -0.0 to +0.0 (`coerce_value`); no seed primitive distinguishes them | `test_signed_zero_has_one_identity_whatever_was_hashed_first` |
| S9-AUTH-01 (MEDIUM) | aliased `import_module`, `builtins` aliases, and literal-name `getattr`/subscript lookups of eval/exec passed the dynamic-execution rule | caught; `runpy` and `multiprocessing` banned. S9-AUTH-02's residuals (bound-then-called `admit`, `methodcaller`) are declared in `successor/boundary.py`, not detected | six new fixtures in `test_dynamic_execution_is_caught` |
| S9-FC-06 (MEDIUM) | §3.5's table rewrote two LEAK_SUSPECTED verdicts | table corrected in place, with a note on G9.1 precondition (c) | (document) |

## R.2 The gate on the fixed code

`python -m pocketsec.stage9.cli gate` → **GATE: FAILED (6)**, exit 1; PASS G9.3 G9.5 G9.6 G9.10,
the same set as Part I. Wall clock 23:34:37 → 00:30:32 at load 25.55 → 25.12 (this session's own
full pytest and other waves' work ran concurrently; timings are not comparable with Part I's).
What changed:

- **G9.8, fittest under attack (the lead's question).** Killed by an attack: **3/10, 6/10, 1/10**
  (evolutionary seeds 101/202/303). With the attack set removed the same rule kills **10/10** in
  every run, because every top-10 genome's CLEAN AP is already below 0.5872. The old headline
  "10/10 died under attack" measured "weaker than the incumbent", not the attacks.
- **G9.8, cap padding.** `session_cap_padding` on the subject (the Φ-oracle): 240/240 held-out
  sessions abstained; AP 0.5975 → 0.3333 (base rate). The defence holds; detection does not. An
  attacker who can emit 4096 events now buys UNKNOWN instead of a benign score. The
  worst-case-over-attacks fitness does **not** cover this attack (ADR-0083 addendum B).
- **G9.8, tampering.** The digest trial on the subject is refused by `digest mismatch`, not by an
  IRError. 35 findings (34 before: the new DEFENCE). MODEL is still uncovered.
- **G9.9.** FOSSIL_AVOIDANCE: **REJECTED, fired 0 INERT** (was UNMEASURED, "fired 4"). Two
  UNMEASURED flags remain: subtractive bias and QD niches. Recommendation: remove fossil
  avoidance; the three ablation arms at 4x (§UNMEASURED) are now two.
- **G9.6.** Still PASS, now with evidence: the registry's active genome is the installed
  successor after install and the parent after rollback for both successors; the exhaustive
  winner's rollback (`sha256:717e9f47fb54`, the Φ-oracle itself) is reported as
  indistinguishable from no rollback. The random-s202 winner (`sha256:fdb7289b5dfc`) is the only
  successor whose rollback proves anything.

## R.3 Not fixed (accepted, with the reason)

| finding | why not fixed here |
|---|---|
| S9-CX-06 GA breeds from inadmissible parents | changes the search trajectory and every search figure; needs a re-run of Part I §3.2-§3.3, not a patch |
| S9-CX-02 every variant is charged even when the clean AP already makes the genome inadmissible | same: it changes the equal-budget comparison, so it needs its own measured arm |
| S9-FC-04 G9.5's degraded regimes run the same genome (H1); catalog selected on held-out AP | a runtime-catalog redesign. G9.5 already reports the loss path INERT (0/100); it still PASSes on that, which Part II §II.2 states |
| S9-LIN-01, S9-INT-01 successor package does not bind the held-out split or cross-check its executable | a successor contract change needs a new schema `$id` and an ADR; Stage 9's ADR block is exhausted |
| S9-REG-01 `register` trusts a report file | the registry is shared infrastructure; re-verification belongs to a registry change, not a Stage 9 patch |
| S9-AUTH-02 method-binding residuals of rule 3 | declared in `successor/boundary.py`'s docstring; AST cannot follow a bound method in general |
| `FossilStore` payloads built on every evaluation and never read (S9-CX-05, second half) | harmless and bounded; goes with the recommended removal of fossil avoidance |

## R.4 Probe output (this session)

```text
$ PYTHONPATH=<repo> python cap_probe.py   # Φ-oracle phenotype, synthetic events, load 24.08
events offered     16 processed    16 truncated      0 score 0.99 work_units 64 meter 64 lineages 16 evictions 0
events offered    256 processed   256 truncated      0 score 0.99 work_units 1024 meter 1024 lineages 16 evictions 240
events offered   4096 processed  4096 truncated      0 score 0.99 work_units 16384 meter 16384 lineages 16 evictions 4080
events offered   4097 processed     0 truncated      1 score None work_units 0 meter 0 lineages 0 evictions 0
events offered  65536 processed     0 truncated  61440 score None work_units 0 meter 0 lineages 0 evictions 0
head-padded attack: 4096 zero-signal + 4 phi=0.99 -> score None, truncated 4, work 0
```

Full suite after the fixes (`PYTHONHASHSEED=0 python -m pytest -q`, load 5.16 → 3.98; the
repository's `addopts = "-q"` doubles the flag and suppresses pytest's count line, so the counts
are tallied from the progress output): 4759 passed, 5 failed, 1 error. Stage 9's only failure is
`test_every_boundary_rule_holds_on_the_real_tree[transitive_stage5_reach]`, the unresolved §2.3
STOP (§6), unchanged. The other failures are in Stage 1 (G1.12 peak RSS in a shared pytest
process, as Part II §II.L records), Stage 5 (`test_the_sentinel_trusted_surface_stays_inside_its_ratchet`,
1370 > 1330 lines) and Stage 6 (`experiments/registry.jsonl` changed during its gate-context
build; this session never wrote it). They belong to other waves and were not touched.

§3.7's 65,536-event row ("4096 processed, 61,440 truncated") describes the pre-fix head cut; on
the fixed code that session abstains with 0 processed, as above.

# Part I — measurement-engineer session

## 1. The answer, in one paragraph

**Stage 9's central claim is not supported.** The claim is that minimum sufficient security
computation is empirically discoverable by typed, adversarially tested, cost-aware search, and
that the search is worth its research complexity. On the only split with headroom (ambiguous
count 240), the minimum sufficient computation is a one-register per-lineage accumulator of ΔΦ
at 3 WU/event, which a person writes in one line. *Which* accumulator Stage 9 reports is
decided by one chosen threshold, the MSSC robustness ratio `r_min`:

- at `r_min ≥ 0.82` (the shipped 0.85) the answer is the **Φ-oracle** (per-lineage max);
- at `r_min ≤ 0.81`, or with the ratio removed, it is **Σ ΔΦ** (per-lineage running sum). Σ ΔΦ
  beats the Φ-oracle on held-out worst-case AP by +0.0281 on seed 11 and +0.1178 on seed 17, at
  identical cost.

Σ ΔΦ is score-identical to hand rule H1 (ΔΦ is never negative, so H1's clamp is dead code). Only
**exhaustive enumeration of an author-designed 126-genome space** finds either one reliably. Even
that result cannot be told apart from what the same enumeration returns on shuffled labels:
empirical p = 0.149 over 200 shuffles. The space, not the labels, carries the answer.
Evolutionary search is NOT-YET-JUSTIFIED at the gate's budget and **REJECTED** at 4x the budget:
it loses to random search on 3/3 seeds, median −0.0882. Its winners score at chance on held-out
data. The honest expected outcome the lead wrote down ("rediscover the Φ-oracle") happened, but
it happened because of how the space and the constraint were written, not because of the search
machinery.

## 2. Verdict on the central claim

| clause of the claim | measured | verdict |
|---|---|---|
| a typed language that terminates in bounded WU and bytes, with ill-typed genomes unconstructible | 377 of 378 Stage 9 tests pass. The one failure is the §2.3 boundary contradiction (§6), not typing. Flood probes keep real memory flat (§3.7) | **SUPPORTED** (by construction; not author-confounded) |
| the language expresses the incumbent | Φ-oracle squashed and raw exact (max abs error 0.0, 60 sessions), from the gate | **SUPPORTED** |
| search discovers the minimum sufficient computation | exhaustive enumeration returns a one-line ΔΦ accumulator. Which one depends on `r_min` (§3.4). Exhaustive on shuffled labels matches or beats the true-label pick in 29 of 200 shuffles (§3.6) | **NOT SUPPORTED as evidence of discovery**: the 126-genome space was written after reading the generator (author confound, ADR-0084) |
| structured search is worth its complexity | evolution vs random, held-out worst-case AP: 1x no winners; 4x −0.1491/−0.0479/−0.0882; 16x (seed 101) 0.3376 vs 0.4819 | **REJECTED** (sensitivity runs); NOT-YET-JUSTIFIED at the gate's budget |
| adversarial testing is part of fitness | worst-case fitness is implemented. *Corrected in Part R:* the "10/10 of the fittest die under attack" first quoted here counted genomes already below the Φ-oracle on clean data; the attack-induced count is 3/10, 6/10 and 1/10 (seeds 101/202/303), and 10/10 die with no attack at all. Its companion ratio constraint decides the answer (§3.4) | mechanism fires (on 1-6 of the top 10 per run); its threshold is an unjustified parameter |

## 3. Measurements (this session)

Every row names the probe. Appendix A has the commands and verbatim output, and §7 has the
experiment ids.

### 3.1 Hand baselines on three seeds (P1; train s3, held-out s11, extra held-out s17)

Worst case is over clean plus the six ARGUS scenario attacks. Base rate 0.3333 on every split.

| genome | WU/event (static) | charged WU/event (with per-lineage readout; s3) | s3 clean / worst | s11 clean / worst | s17 clean / worst | in the 126-genome exhaustive space |
|---|---|---|---|---|---|---|
| Φ-oracle | 3 | 3.2222 | 0.5897 / 0.5872 | 0.5975 / 0.5975 | 0.5904 / 0.5705 | yes |
| H1 Σ max(ΔΦ,0) | 4 | 4.2222 | 0.7279 / 0.5940 | 0.7680 / 0.6256 | 0.7687 / 0.6883 | no |
| H2 popcount(OR mask) | 3 | 3.4443 | 0.7312 / 0.4377 | 0.8111 / 0.5980 | 0.7720 / 0.5454 | yes |
| order-free control | 4 | 4.2222 | 0.2929 / 0.2852 | 0.3091 / 0.3057 | 0.3103 / 0.2997 | yes |

- H1 is the strongest hand rule on held-out worst-case AP on both held-out seeds. H2 is
  strongest on clean AP, and the lineage-table flood alone drops it to 0.4377/0.5980/0.5454.
- The Pareto axis "WU/event" is the static update cost. The meter also charges the readout once
  per lineage, so every genome is charged about 0.22 WU/event more than its axis value (charged
  WU is never `static × events`: 446,730 vs 415,929 for the Φ-oracle on s3). The ordering is
  unchanged. This is recorded, not a defect: `test_work_units_equal_the_static_bound_exactly`
  pins the formula `events*update + readouts*readout`.
- Saturation (from the gate): at count 60 the Φ-oracle and H1 both read 1.0000, and H2 reads 0.79.
  Count 60 is saturated and is used for nothing here.

### 3.2 Search at the gate's budget (the gate plus P2 at 1x)

These figures are identical in the gate process and the probe process (determinism digests
6/6 equal).

| run | evaluations | admissible (MSSC) | constant-output | winner | best-effort (unconstrained argmax) held-out s11 worst |
|---|---|---|---|---|---|
| evolutionary s101 / s202 / s303 | 72 / 66 / 61 | 0 / 0 / 0 | 43 / 22 / 32 | none / none / none | 0.3277 / 0.3648 / 0.3789 |
| random s101 / s202 / s303 | 67 / 62 / 66 | 0 / 1 / 0 | 30 / 22 / 32 | none / `fdb7289b` (17 WU, held-out worst 0.4262, s17 worst 0.3719) / none | 0.3277 / 0.4262 / 0.3207 |
| exhaustive | 126 (65,577,033 WU) | 6 | — | Φ-oracle `717e9f47` | — |

- **Operator firing (evolutionary, 1x):** `improved_archive` is **0 for every one of the 13
  operators on every seed**. Every evolutionary best genome came from the initial random 32.
  `MOVE` and `MACRO_INSERT`: 0 valid children.
- The random-s202 winner fails the MSSC quality floor on seed 17 (0.3719 < 0.3833). It does not
  generalise.

### 3.3 Budget sensitivity (P2 at 4x and 16x): evolution loses to random

This was run after the gate, as a sensitivity check. The gate's verdict is still decided at 96M
WU. A larger budget could only help evolution.

| budget | run | evaluations | winner held-out s11 worst (clean) | held-out s17 worst | train worst | from variation |
|---|---|---|---|---|---|---|
| 4x | evolutionary s101 | 313 | 0.3328 (0.3900) | 0.3302 | 0.4049 | yes |
| 4x | evolutionary s202 | 258 | 0.3149 (0.3265) | 0.3441 | 0.3869 | yes |
| 4x | evolutionary s303 | 236 | 0.3937 (0.4135) | 0.3564 | 0.3975 | yes |
| 4x | random s101 | 262 | 0.4819 (0.5690) | 0.6151 | 0.5146 | — |
| 4x | random s202 | 256 | 0.3628 (0.4370) | 0.3498 | 0.4190 | — |
| 4x | random s303 | 255 | 0.4819 (0.5690) | 0.6151 | 0.5146 | — |
| 16x | evolutionary s101 | 1316 | 0.3376 (0.4064) | 0.3569 | 0.4181 | yes |
| 16x | random s101 | 986 | 0.4819 (0.5690) | 0.6151 | 0.5146 | — |

`strategy_verdict` (the module's own rule) at 4x gives **REJECTED**. Vs random: −0.1491, −0.0479,
−0.0882 (median −0.0882). Vs exhaustive: −0.2647, −0.2826, −0.2038. Evolution's winners have
train-vs-held-out gaps of +0.0721, +0.0720, +0.0038, below the 0.10 falsifier. They land **at or
below the 0.3333 base rate** on held-out, so the loop climbs train noise. At 4x the operators do
fire (improved_archive: REMOVE 1, CROSSOVER 1, INSERT 3, SPARSIFY 2, DEVELOPMENTAL 1, over three
seeds). `MOVE` and `MACRO_INSERT` still produce 0 valid children at every budget, including 328
proposals at 16x (156 `MOVE`, 172 `MACRO_INSERT`).

### 3.4 The uncalibrated robustness ratio decides the answer (P6, P7)

All 126 exhaustive genomes were evaluated once on train, and the winner re-selected under an
`r_min` sweep. Selection uses train only, as `run_search` does.

| r_min | admissible of 126 | exhaustive winner | held-out s11 worst | held-out s17 worst |
|---|---|---|---|---|
| removed | 16 | Σ ΔΦ `sha256:59a57874` (3 WU, 1184 B) | 0.6256 | 0.6883 |
| 0.70 / 0.80 / 0.81 | 14 / 10 / 10 | Σ ΔΦ | 0.6256 | 0.6883 |
| 0.82 / **0.85 (shipped)** / 0.90 / 0.95 | 6 | Φ-oracle `sha256:717e9f47` (3 WU, 1184 B) | 0.5975 | 0.5705 |

- Top of the unconstrained train ranking: Σ ΔΦ (worst 0.5940, ratio 0.816), Σ |ΔΦ| (the same
  scores at 4 WU), then Σ features[90] (0.5934), and only then the Φ-oracle (0.5872, ratio 0.996).
- ΔΦ < 0 on **0 of 138,643** train steps and 0 held-out steps. Σ ΔΦ therefore equals H1 without
  its clamp. Its held-out clean score vector is **identical** to H1's (P6).
- `beats(Σ ΔΦ, Φ-oracle)` on held-out is **True on worst_case_ap** (0.6256 vs 0.5975), and
  `beats(Σ ΔΦ, H1)` is **True on wu_per_event** (3 vs 4), both with `candidate_ok=True`. With the
  shipped constraint (`candidate_ok=False`) both are False. §8 falsifier 1 therefore fires or not
  depending on `r_min`. Even in the case where it does not fire, the "winner" is a hand rule with
  a redundant node removed.
- Random search at 4x drew Σ ΔΦ on seed 202 (draw #172) and discarded it for the same ratio. Its
  admitted winner scores 0.3628 on held-out.
- Measured wall-clock check of the WU claim (P9, load 2.06-2.14): Σ ΔΦ 1.251 µs/transition vs H1
  1.500, in the same run, best of 5.

### 3.5 Is the shuffled-label control informative? (P5)

The gate's procedure (search, winner or best-effort pick, 200 held-out label permutations, prior
over 64 random genomes) was run on shuffled labels and on **true** labels:

| strategy, seed | shuffled labels (9): held-out AP / p / verdict | TRUE labels: held-out AP / p / verdict |
|---|---|---|
| evolutionary s101 (the gate's control) | 0.3148 / 0.8507 / NULL_HELD | 0.3564 / **0.3184 / NULL_HELD** |
| evolutionary s202 | 0.3151 / 0.8060 / NULL_HELD | 0.4435 / 0.0149 / **LEAK_SUSPECTED** (prior percentile 1.0000) |
| evolutionary s303 | 0.3289 / 0.7015 / NULL_HELD | 0.3923 / 0.0299 / PRIOR_INFORMATIVE |
| exhaustive | 0.5975 / 0.0050 / LEAK_SUSPECTED | 0.5975 / 0.0050 / **LEAK_SUSPECTED** (the pick is the Φ-oracle) |

*Corrected by the review wave (S9-FC-06):* this table first printed the two TRUE-label
LEAK_SUSPECTED verdicts of Appendix A.9 as "(significant, above prior)" and "(Φ-oracle)". The
code emitted LEAK_SUSPECTED for both. So `null_verdict` labels genuine label signal as
LEAK_SUSPECTED: it cannot tell a leak from an informative search, and a LEAK_SUSPECTED or
NULL_HELD from it is not evidence either way. G9.1 precondition (c) ("shuffled-label null not
LEAK_SUSPECTED", printed True) is computed on the evolutionary-s101 control alone; the only
winner reported as BEATS comes from the exhaustive arm, whose own shuffled-label control is
LEAK_SUSPECTED (p 0.0050, row 4). A control whose search yields no evaluable genome also
returns NULL_HELD, which passes (c) vacuously.

The gate's NULL_HELD at seed 101 **has no power**: the same procedure on real labels also
"holds the null" there. On shuffle seed 9 the exhaustive space returns a Φ-oracle-equivalent
(`features[90]` MAX) with **no label information at all**.

### 3.6 What the exhaustive search returns on noise (P8, 200 label shuffles)

Scores do not depend on labels, so each genome's score vectors were computed once and the search's
selection rule was applied under 200 train-label shuffles. Each pick was then scored on the TRUE
held-out labels.

- The true-label pick is the Φ-oracle, held-out AP 0.5975.
- The shuffled-label picks have held-out AP mean 0.3808, median 0.3179, range 0.2185-0.8111.
  29 of 200 reach at least 0.5975, so the empirical **p = (1+29)/201 = 0.1493**. 9 of 200 are
  Φ-equivalents and 36 of 200 are ≥ 0.55.
- The space itself: 16 of the 126 exhaustive genomes reach ≥ 0.55 held-out clean AP, against
  **0 of 64** random-generator genomes (max 0.4269).

The gate's null uses the random-generator prior, which is the wrong prior for the exhaustive arm.
Against the correct prior, the exhaustive search's success is not significant.

### 3.7 Bounds under flood (P3; synthetic events, bound properties only)

| structure | flood | result |
|---|---|---|
| phenotype lineage table (Φ-oracle, H1, H2) | 16 → 256 → 4096 → 65,536 events over as many distinct lineages | live lineages 16, evictions counted (240; 4080), events above 4096 truncated and counted (61,440). Accounted peak = bound (1184/1200/1192 B). **Real** tracemalloc peak 28,936-34,128 B, flat from 256 to 65,536 events |
| phenotype side table (FIRST_SEEN) | 65,536 distinct relation keys | 3840 side-table evictions; accounted peak 5288 = bound; real peak 87,968 → 90,136 B from 4096 to 65,536 events (flat) |
| `EvaluationCache` | 40,960 distinct keys (10x) | len 4096, evictions 36,864, real peak 1,605,488 B |
| `FossilStore` | 20,480 fossils (10x) | len 2048, evictions 18,432, real peak 912,064 B |
| QD archive (niches) | 5040 distinct genomes (10x 504 cells) | bound held 5040/5040; occupied 72; rejected 4771 |
| QD archive (single cell) | 10 genomes (10x of 1) | bound held 10/10 (a trivially small flood, reported as such) |
| search records / population | random and evolutionary, unlimited budget, 30-session clean suite | both stopped at `RECORD_BOUND` with 8192 records; population evictions 8128 (= 8192 − 64); WU spent 192,897,723 / 315,417,347 |
| work budget | every budgeted run | `wu_spent ≤ budget` on all 29 budgeted runs printed this session (15 gate, 14 P2), e.g. 1,535,999,733 of 1,536,000,000; `SearchRun.__post_init__` refuses any run that overspends |

The typed-genome refusals (self-reference, forward-reference loop, recursive macro, macro depth
and size, a ring of 10^6, and bounds that understate) are pinned by named tests in
`tests/test_stage9_ir.py` and `tests/test_stage9_genome.py`. All of them pass this session (§3.10).

### 3.8 Resource cost through `run_benchmark` (P4, P9; held-out s11 clean, 240 sessions, 17,898 transitions)

Adapter: a lookup slot that follows Stage 1's `SSIRSlotBase` precedent (`stage1/slot.py`). SSIR
compilation happens outside the measured loop, which is stated here and not hidden.
`synthetic_data=True`. `calibrated=False`.

| slot | PR-AUC (run_benchmark) | equals Stage 9's AP | CPU/transition (one pass, load 1.99) | best-of-5 CPU µs/transition (P9, load 2.06-2.14) | ratio to the direct Φ loop, same run (P4 / P9) |
|---|---|---|---|---|---|
| Φ-oracle direct loop | 0.5975 | — | 1.74e-07 s | 0.108 | 1.0x |
| Φ-oracle genome | 0.5975 | yes | 1.42e-06 s | 1.393 | 8.2x / 12.9x |
| H1 | 0.7680 | yes | 1.52e-06 s | 1.500 | 8.8x / 13.9x |
| H2 | 0.8111 | yes | 1.83e-06 s | 1.120 | 10.5x / 10.3x |
| Σ ΔΦ | 0.7680 | yes | 1.45e-06 s | 1.251 | 8.4x / 11.6x |
| random-s202 winner | 0.4415 | yes | 4.50e-06 s | 4.082 | 25.9x / 37.7x |

- **Edge envelope (100 MB): exceeded.** `check_profile` reports "agent_rss 106.4 MB > 100 MB
  target" for every slot. Peak sampled RSS was 111,587,328 B and `time -v` max RSS 125,116 kB.
  Decomposition in a fresh process (P9): bare Python 11,980,800 B; plus Stage 9 imports (88
  pocketsec modules) 27,336,704 B; plus the in-memory replay split 111,337,472 B. Scoring adds
  ≤ 299,008 B (the delta RSS). **The overrun is the replay harness holding all 240 sessions, not
  the phenotype.** A streaming endpoint would hold one session. That design is not built or
  measured here.
- The gate's own HIL figures (`measure_phenotype`, load 7.96): 23.94x (H1), 23.02x (Φ-oracle),
  13.36x (H2); incremental RSS 159,744 / 4,096 / 4,096 B; WU-vs-wall Spearman 0.866 (n = 3). The
  interpreter-to-direct-loop ratio therefore swings from 8x to 24x with host load. Only the
  ordering transfers.
- Research-side cost (offline, not the endpoint): the gate process peaked at 1,514,296 kB max
  RSS (`time -v`), 1017.29 s user CPU, 20:19.73 wall at load 3.37 → 7.56. Each probe process
  holding three 7-variant splits held about 1.77 GB RSS (`ps`).
- **2 GB target: UNMEASURED** (MemTotal 16,452,296,704 B, B9-4).

### 3.9 Component ablations: does each component earn its existence?

The G9.9 verdicts come from this session's gate run, and the firing counts are the gate's.

| component (flag) | verdict this run | firing count | recommendation |
|---|---|---|---|
| evolutionary search (GENESIS + GAIA loop) | NOT_YET_JUSTIFIED at 1x; **REJECTED at 4x** (§3.3) | 0 winners from variation at 1x; improved_archive 0 on all operators at 1x | remove from the roadmap on this corpus; flag stays `False` |
| `MOVE`, `MACRO_INSERT` operators | — | **0 valid children in every run** (1x, 4x, 16x) | INERT: remove or repair |
| subtractive bias, fossil avoidance, QD niches | UNMEASURED (no winner in main or arm) | 0 / 4 fossils avoided / 0 | NOT-JUSTIFIED (never exercised to an outcome); default-off |
| primitive foundry | NOT_YET_JUSTIFIED | 0 (INERT) | default-off |
| morphogenesis / speciation | REJECTED (universal phenotype 0.6256 in every niche) | 0 (INERT) | remove |
| symmetry-breaking | REJECTED (0.3583 vs Φ 0.5975) | 34 | remove |
| conservation | REJECTED (0.5975 vs H2 0.8111) | 45 | remove |
| MSDL selection | REJECTED (0.3333 vs Pareto choice 0.3648) | 3 | remove |
| surprise | REJECTED (0.3636 vs Φ 0.5975) | 35 | remove |
| phase observatory | NOT_YET_JUSTIFIED (0.5971 vs CUSUM 0.5863, Φ 0.5975) | 4 | default-off |
| causal geometry | JUSTIFIED vs its spec controls (0.6672 vs kNN 0.4313, Φ 0.5975) | 57 | NOT ADOPTED: loses to H2 (0.8111) and to Σ ΔΦ/H1 (0.7680) on clean held-out AP |
| renormalization | JUSTIFIED (vs random drop 0.3333) | 240 | NOT ADOPTED: an artefact of a ΔΦ-only subject (Part II §II.5) |
| learned forgetting | JUSTIFIED (0.0035 vs EXACT_RING 0.0018 utility/byte) | 2 | NOT ADOPTED: isolating control missing (Part II §II.5) |
| learning-law search | NOT_YET_JUSTIFIED (FP 0.0 vs 0.0) | 15 | default-off |
| hysteresis | NOT_YET_JUSTIFIED (value 0.4706; 17 → 9 transitions against the 50% bar) | 35 | default-off |
| MSSC robustness ratio `r_min` | not a flag. It decides the headline (§3.4) | excludes 4 of the top 4 exhaustive genomes | NOT-YET-JUSTIFIED as a constraint; the lead decides (ADR-0083 addendum A) |
| shuffled-label control (as implemented) | underpowered at the gate's seed (§3.5); wrong prior for the exhaustive arm (§3.6) | — | replace with each arm's own label-noise distribution and several seeds |
| typed IR, static bounds, exhaustive enumeration, successor rollback | proven by construction / tested | fire on every run | **keep**: these are the only parts of Stage 9 with a measured value |

### 3.10 Tests and the gate this session

- Stage 9's 11 test files: **378 collected, 377 passed, 1 failed**,
  `test_every_boundary_rule_holds_on_the_real_tree[transitive_stage5_reach]` (the STOP in §6);
  38.2 s at load 2.11 → 2.32.
- Gate: FAILED (6). PASS: G9.3, G9.5, G9.6, G9.10. FAIL: G9.1 (BLOCKED_ON_STAGE8), G9.2 (VACUOUS),
  G9.4 (16 GB host), G9.7 (transitive Stage 5 reach), G9.8 (MODEL surface INERT), G9.9 (3
  UNMEASURED flags). This matches Part II. `experiments/registry.jsonl` was byte-identical across
  the gate run (G9.7 detail).
- The full repository suite was **not** run this session: another wave's full pytest and Stage 8
  gate were running on this host. Stage 9 is judged on its own files and its gate.

## 4. Recommendations

1. **Record Stage 9's search thesis as rejected on this corpus.** The finding "minimum sufficient
   computation = a one-register ΔΦ accumulator" is real. It was not produced by adversarially
   tested evolutionary search. It was produced by enumerating a space whose inputs were chosen
   after reading the generator, and that enumeration reaches the true-label result on shuffled labels in 29 of 200 shuffles (14.5%).
2. **Keep** the typed IR, static bounds, the exhaustive enumerator, the ARGUS harness and the
   successor rollback. They are measured, and bounded by construction.
3. **Remove or freeze** the evolutionary loop and GAIA ecology, and delete `MOVE` and
   `MACRO_INSERT` (INERT). Remove every REJECTED physics-inspired module per ADR-0086.
4. **The lead decides `r_min`.** Until then, report both answers (Φ-oracle under 0.85; Σ ΔΦ ≡ H1
   minus a dead clamp without it). Do not quote "the answer is the Φ-oracle" unqualified.
5. **Replace the null control.** For every arm, use a label-noise distribution of that arm's own
   selection rule (§3.6), with several seeds. A single-seed permutation test against the
   random-generator prior has no power here (§3.5).

## 5. What would change this conclusion

- **A second, independently authored corpus with headroom** on which evolutionary search beats
  random and exhaustive enumeration at equal budget on held-out worst-case AP (≥ +0.02 median,
  positive on every seed). That would re-open the search thesis. This corpus cannot.
- **A search space not written by the corpus author**, for example exhaustive enumeration over
  all input slots rather than the seven chosen ones, or real telemetry. If the one-register ΔΦ
  accumulator still wins there with p < 0.05 against that arm's own label-noise distribution,
  "discoverable" becomes a measured claim.
- **A justified `r_min`** (calibrated from a real attack model, or dropped). Either choice fixes
  which of the two accumulators is the answer. Neither changes the verdict on the search
  machinery.
- **A streaming replay harness** measured on a 2 GB target would settle the Edge envelope. The
  phenotype's own state is about 34 KB of real memory, so the phenotype is unlikely to be the
  limiting factor.
- **Real telemetry** in which ΔΦ can be negative would separate Σ ΔΦ from H1 and could reorder
  the whole Pareto front.

## 6. Blockers and STOP conditions (unchanged from Part II)

- **B9-1** Stage 8's interface carries no hand-designed baseline Stage 9 may consume, so G9.1 is
  blocked (ADR-0087). The Stage 8 wave was mid-run during this session and was not touched.
- **B9-2** Stage 6 has no genome executor (ADR-0088). **B9-4** there is no 2 GB target
  (ADR-0089).
- **STOP (unresolved):** spec §2.3's harness grants reach Stage 5 through
  `stage6.memory.procedural` (ADR-0081). The test and G9.7 fail, and nothing was loosened.
- **ADR block exhausted:** 0080-0089 are all written, and Stage 9 may use no other number. This
  session's rejection is therefore recorded as addenda to ADR-0083 and ADR-0085, not as a new
  ADR.

## 7. Experiment ids registered this session

Registration is explicit (A.14); the gate itself never writes the ledger.

| experiment id | what it holds | section |
|---|---|---|
| PS-S9-20260926-H5-ontogenesis-gate-0001 | the gate report (`gate --save`), registered with the `register` subcommand | §3.10, A.1 |
| PS-S9-20260926-BASE-hand-baselines-three-seeds-0001 | P0 split compilation + P1 hand baselines | §3.1 |
| PS-S9-20260926-H5-search-budget-sensitivity-0001 | P2 1x/4x/16x runs + P10 determinism and `strategy_verdict` | §3.2, §3.3 |
| PS-S9-20260926-H5-robustness-threshold-sweep-0001 | P7 r_min sweep | §3.4 |
| PS-S9-20260926-H5-random-genome-decode-0001 | P6 genome decode, Σ ΔΦ ≡ H1 | §3.4 |
| PS-S9-20260926-BASE-null-control-power-0001 | P5 null control on shuffled and true labels | §3.5 |
| PS-S9-20260926-BASE-exhaustive-label-noise-0001 | P8 exhaustive search under 200 shuffles | §3.6 |
| PS-S9-20260926-H5-bounds-under-flood-0001 | P3 floods | §3.7 |
| PS-S9-20260926-BASE-scoring-rss-timing-0001 | P9 RSS decomposition, best-of-5 CPU ratios | §3.8 |
| PS-S9-20260926-BASE-heldout-benchmark-{phi-oracle-direct-loop, phi-oracle-genome, h1, h2, sum-dphi, random-s202-winner}-0001 | P4 `run_benchmark` records (`BenchmarkResult.to_dict()`) | §3.8 |

`experiments/registry.jsonl` `verify_integrity()` returned no problems after these 15 appends.

## Appendix A — every command this session ran for a figure above, with its real output

Probe scripts are in the session scratchpad (`<scratchpad>/s9/`), and their outputs are also stored in
`results/<experiment id>.json`. `<scratchpad>` abbreviates `/tmp/claude-1000/-home-anil-Documents-Research/4d447431-f910-4701-b132-7d03c949be5c/scratchpad`.
Output is verbatim except where a line says otherwise.

### A.1 The gate (this session)

```text
$ cd /home/anil/Documents/Research/pocketsec && /usr/bin/time -v python -m pocketsec.stage9.cli gate --save <scratchpad>/s9/gate-report.json
loadavg start: 3.37 3.85 4.26 4/2093 407139
2026-09-26T21:47:40+10:00
loadavg before: 3.37 3.85 4.26
PocketSec Stage 9 acceptance gate (ONTOGENESIS)

  [FAIL] G9.1  A Stage-9 computation beats the strongest Stage-8 hand-designed baseline
         BLOCKED_ON_STAGE8: the criterion names Stage 8's hand-designed baseline; Stage 8's named interface (docs/stage-8-spec.md §3.3, DiscoveryPackageV1) carries none Stage 9 may consume and Stage 9 imports nothing from Stage 8 (ADR-0087). Rebound comparison against {Φ-oracle, H1, H2}: pre-conditions {'(a) phi-oracle exact in the IR': True, '(b) count-240 held-out not degenerate': True, '(c) shuffled-label null not LEAK_SUSPECTED': True, '(d) 0 train/held-out overlap': True}; strongest hand baseline on held-out worst-case AP = H1; winners: ['sha256:fdb7289b5dfc: does not beat (candidate is dominated by the baseline)', 'sha256:717e9f47fb54 (IS the phi-oracle genome, rediscovered): BEATS (wu_per_event: 3 vs baseline 4)']; §8 falsifier 1 FIRES: no search winner that is NOT itself a hand baseline beats the strongest hand rule (1 such winners); literal spec reading, rediscoveries included: a winner beats it. Train-vs-held-out worst-case gap per run winner: ['random-s202 -0.0323', 'exhaustive-s101 -0.0103'] (falsifier 3 at > 0.1). held-out count-240 Pareto (* = on the front): phi-oracle (AP 0.5975, 3 WU/ev, 1184 B) *, H1 (AP 0.6256, 4 WU/ev, 1200 B) *, H2 (AP 0.5980, 3 WU/ev, 1192 B) *, sha256:fdb7289b5dfc (AP 0.4262, 17 WU/ev, 1568 B), sha256:717e9f47fb54 (AP 0.5975, 3 WU/ev, 1184 B) *. Count-60 (saturated, the trap): Φ-oracle AP 1.0000; TCN AP 1.0000 (clean, count 60), 6984 WU/ev analytic, 55688 B analytic lower bound (AP 1.0000: registered Stage 2 frontier evidence PS-S2-20260924-H8-baseline-frontier-0019 (ambiguous count 60 seed 11, degenerate=True, ORDER_FREE_BASELINE_TIES_BEST); CLEAN AP, an upper bound on worst case. WU 6984 ANALYTIC (3*96*24 + 3*24 MACs/event from architecture constants, not measured). Bytes 55688 ANALYTIC lower bound (6961 weights x 8 B, activations excluded; the frontier carries no model bytes). Description length ANALYTIC lower bound.)
  [FAIL] G9.2  Every promoted primitive/law has independent-run reproduction and ablation evidence
         VACUOUS: no candidate subgraph was examined, so nothing was tested. 0 candidate subgraphs examined over 3 main-arm runs; decisions none; PROMOTED without reproduction/ablation none; law statuses none (0 laws can be promoted: cross_host is None on one synthetic host); convergence no candidate subgraph
  [PASS] G9.3  Every abstraction has semantic-conservation and counterfactual tests
         11 abstractions of 11 expected on the subject genome (the evolutionary arm produced no MSSC-satisfying winner; best winner of any arm by train worst-case AP); absent none; without both tests none; lost a counterfactual distinction: ['precision:1 lost 38/80']. coarse:R1_DROP_NOVELTY_TEMPORAL: agreement 1.0000, AP 0.5975->0.5975, bytes 768->664, pairs 63->63/80; coarse:R2_RELATION_TO_FAMILY: agreement 1.0000, AP 0.5975->0.5975, bytes 768->576, pairs 63->63/80; coarse:R3_STATE_ONLY: agreement 1.0000, AP 0.5975->0.5975, bytes 768->104, pairs 63->63/80; coarse:R4_LINEAGE_EPISODE: agreement 1.0000, AP 0.5975->0.5975, bytes 768->768, pairs 63->63/80; precision:1: agreement 0.9292, AP 0.5975->0.4500, bytes 1184->1088, pairs 63->25/80; precision:2: agreement 1.0000, AP 0.5975->0.5749, bytes 1184->1088, pairs 63->63/80; precision:4: agreement 1.0000, AP 0.5975->0.5975, bytes 1184->1088, pairs 63->63/80; precision:8: agreement 0.8125, AP 0.5975->0.5975, bytes 1184->1104, pairs 63->63/80; precision:16: agreement 1.0000, AP 0.5975->0.5975, bytes 1184->1120, pairs 63->63/80; precision:32: agreement 1.0000, AP 0.5975->0.5975, bytes 1184->1152, pairs 63->63/80; minimal_state: agreement 1.0000, AP 0.5975->0.5975, bytes 1184->1184, pairs 63->63/80
  [FAIL] G9.4  Every phenotype has measured 2 GB target-machine resource data
         3 phenotypes measured on this host (MemTotal 16452296704 B, is_reference_target False: NOT a 2 GB target, B9-4); RSS/CPU unmeasured for none; proxy Spearman (WU vs wall) 0.8660254037844387; timings are host-contended ratios, not device figures. sha256:6897396d2432: 4 WU/ev, incremental RSS 159744 B, 23.9380x the direct Φ-oracle loop, load (7.96, 7.99, 6.74)->(7.96, 7.99, 6.74); sha256:717e9f47fb54: 3 WU/ev, incremental RSS 4096 B, 23.0151x the direct Φ-oracle loop, load (7.96, 7.99, 6.74)->(7.96, 7.99, 6.74); sha256:1ba910ff2694: 3 WU/ev, incremental RSS 4096 B, 13.3619x the direct Φ-oracle loop, load (7.96, 7.99, 6.74)->(7.96, 7.99, 6.74)
  [PASS] G9.5  Every resource-degradation mode exposes lost coverage and uncertainty
         SIMULATED degradation trace, 140 decisions, 100 outside ADAPTIVE; missing coverage/loss/uncertainty at steps none; transitions into each regime {'ADAPTIVE': 1, 'REDUCED': 2, 'REFLEX': 2, 'SURVIVAL': 1}; unvisited none; lost coverage by regime [('REDUCED', ()), ('REFLEX', ()), ('SURVIVAL', ())]; decisions with a non-empty loss 0 of 100 (INERT: every catalog phenotype reads the same inputs, so the coverage-loss path never fired on this catalog); uncertainty penalty by regime [('REDUCED', 0.0), ('REFLEX', 0.0), ('SURVIVAL', 0.028141928109759795)]; coverage basis STATIC_INPUT_READ (what the phenotype reads, not measured recall)
  [PASS] G9.6  Every successor is rollbackable
         2 successors; problems none; Stage 6 verdicts recorded verbatim by bucket {'UNCERTAIN': 16} (none acted on); PCB-lowerable {False: 2}; rollback is proven in Stage 9's lab registry only: Stage 6 has no genome executor (B9-2)
  [FAIL] G9.7  All architecture-search artifacts remain outside direct production authority
         11 AST predicates over pocketsec/stage9 (boundary.py + bucket rule); offenders {'transitive_stage5_reach': ('pocketsec/stage9/cli.py bypassing pocketsec.stage6.capsule: pocketsec.stage9.cli -> pocketsec.stage9.gate -> pocketsec.stage9.gate_labs -> pocketsec.stage9.gate_exit -> pocketsec.stage6.memory.semantic -> pocketsec.stage6.memory.procedural -> pocketsec.stage5', 'pocketsec/stage9/gate.py bypassing pocketsec.stage6.capsule: pocketsec.stage9.gate -> pocketsec.stage9.gate_labs -> pocketsec.stage9.gate_exit -> pocketsec.stage6.memory.semantic -> pocketsec.stage6.memory.procedural -> pocketsec.stage5', 'pocketsec/stage9/gate_exit.py bypassing pocketsec.stage6.capsule: pocketsec.stage9.gate_exit -> pocketsec.stage6.memory.semantic -> pocketsec.stage6.memory.procedural -> pocketsec.stage5', 'pocketsec/stage9/gate_labs.py bypassing pocketsec.stage6.capsule: pocketsec.stage9.gate_labs -> pocketsec.stage9.gate_exit -> pocketsec.stage6.memory.semantic -> pocketsec.stage6.memory.procedural -> pocketsec.stage5')}; experiments/registry.jsonl byte-identical across the gate run: True. The declared residual (ADR-0081): gate_exit.py, successor/stage6_exit.py and the harness reach Stage 5 only through stage6.capsule.*
  [FAIL] G9.8  ARGUS adversarial tests cover the ML/search/system lifecycle
         34 findings; surfaces without a non-inert finding ['MODEL']; DEFENCE findings that did not refuse every trial none; lifecycle attacks never run none; INERT (attack: genomes) {'reorder_across_actors': 4, 'timing_stretch': 4, 'benign_duplicate_flood': 2, 'lineage_table_flood': 1, 'constant_corruption': 1}; fired {'rename_binaries': 4, 'benign_duplicate_flood': 2, 'sensor_drop_10': 4, 'lineage_table_flood': 3, 'state_reset_midsession': 1, 'work_budget_starvation': 1, 'tampered_genome': 1, 'benchmark_contamination': 1, 'train_label_noise': 1, 'shuffled_label_search': 1, 'hypothesis_explosion': 1, 'tampered_successor': 2}; fittest-under-attack ['evolutionary-s101: 10/10 of the fittest died', 'evolutionary-s202: 10/10 of the fittest died', 'evolutionary-s303: 10/10 of the fittest died']. The attacks, the corpus and H1/H2 share an author (lesson 6)
  [FAIL] G9.9  Novel physics-inspired mechanisms must beat simpler baselines or be removed
         16 of 16 flags have a verdict; problems ['SUBTRACTIVE_BIAS_DEFAULT_ENABLED: UNMEASURED', 'QD_ARCHIVE_DEFAULT_ENABLED: UNMEASURED', 'FOSSIL_AVOIDANCE_DEFAULT_ENABLED: UNMEASURED']. ONTO-F03 LEARNING_LAW_SEARCH_DEFAULT_ENABLED=False -> NOT_YET_JUSTIFIED (value 0.0000, controls (('NO_LEARNING', 0.0),) [NO_LEARNING], fired 15); ONTO-F04 PRIMITIVE_FOUNDRY_DEFAULT_ENABLED=False -> NOT_YET_JUSTIFIED (value 0.0000, controls (('seed alphabet', 0.0),) [seed alphabet], fired 0 INERT); ONTO-F06 RENORMALIZATION_DEFAULT_ENABLED=False -> JUSTIFIED (value None, controls (('random_drop_control_ap', 0.3333333333333333),) [raw representation + equal-byte random group drop], fired 240); ONTO-F07 SYMMETRY_BREAKING_DEFAULT_ENABLED=False -> REJECTED (value 0.3583, controls (('rarity-novelty-peak', 0.3333333333333333), ('phi-oracle', 0.5975079744816587)) [rarity (max features[83]), Φ-oracle], fired 34); ONTO-F07 CONSERVATION_DEFAULT_ENABLED=False -> REJECTED (value 0.5975, controls (('phi-oracle', 0.5975079744816587), ('H2', 0.8111256544502619)) [Φ-oracle, H2], fired 45); ONTO-F08 CAUSAL_GEOMETRY_DEFAULT_ENABLED=False -> JUSTIFIED (value 0.6672, controls (('pooled-knn', 0.4312519989915568), ('phi-oracle', 0.5975079744816587)) [pooled-feature kNN, Φ-oracle], fired 57); ONTO-F08 PHASE_OBSERVATORY_DEFAULT_ENABLED=False -> NOT_YET_JUSTIFIED (value 0.5971, controls (('cusum-abs-dphi', 0.5862679708403707), ('phi-oracle', 0.5975079744816587)) [CUSUM on ΔΦ, Φ-oracle], fired 4); ONTO-F09 MSDL_SELECTION_DEFAULT_ENABLED=False -> REJECTED (value 0.3333, controls (('pareto-choice', 0.3648155305047969),) [Pareto choice], fired 3); ONTO-F09 SURPRISE_DEFAULT_ENABLED=False -> REJECTED (value 0.3636, controls (('novelty-peak', 0.3333333333333333), ('phi-oracle', 0.5975079744816587)) [Stage 1 novelty peak, Φ-oracle], fired 35); ONTO-F10 LEARNED_FORGETTING_DEFAULT_ENABLED=False -> JUSTIFIED (value 0.0035, controls (('EXACT_RING', 0.001757562570149009),) [EXACT_RING], fired 2); ONTO-F12 EVOLUTIONARY_SEARCH_DEFAULT_ENABLED=False -> NOT_YET_JUSTIFIED (value None, controls (('random_median_delta', None), ('exhaustive_median_delta', None)) [random search + exhaustive enumeration at equal budget], fired 0 INERT); ONTO-F12 SUBTRACTIVE_BIAS_DEFAULT_ENABLED=False -> UNMEASURED (value None, controls (('main_median_wu_per_event', 0.0), ('arm_median_wu_per_event', 0.0), ('median_heldout_ap_delta', None)) [no forced deletion], fired 0 INERT); ONTO-F12 MORPHOGENESIS_DEFAULT_ENABLED=False -> REJECTED (value 0.0000, controls (('very_low_memory:universal', 0.6256499025914185), ('reflex:universal', 0.6256499025914185), ('sensor_limited:universal', 0.6256499025914185), ('full:universal', 0.6256499025914185)) [one universal phenotype], fired 0 INERT); ONTO-F13 QD_ARCHIVE_DEFAULT_ENABLED=False -> UNMEASURED (value None, controls (('single_cell_median_heldout_worst_case_ap', None), ('niches_median_heldout_worst_case_ap', None), ('max_single_elite_dominance_share', 0.8333333333333334)) [single-cell elitist archive], fired 0 INERT); ONTO-F13 FOSSIL_AVOIDANCE_DEFAULT_ENABLED=False -> UNMEASURED (value None, controls (('main_median_wu_to_final_best', 0.0), ('arm_median_wu_to_final_best', 0.0), ('median_heldout_ap_delta', None)) [no fossil avoidance], fired 4); ONTO-F15 HYSTERESIS_DEFAULT_ENABLED=False -> NOT_YET_JUSTIFIED (value 0.4706, controls (('no-hysteresis transitions', 17.0), ('hysteresis transitions', 9.0), ('extra lower-regime fraction', 0.0875)) [no hysteresis], fired 35)
  [PASS] G9.10  The final endpoint remains useful with Stage 7-9 networking/research absent
         (a) Stage 0-6 importers of Stage 7+ none; (b) child AP 0.5975 vs in-process 0.5975 (base rate 0.3333), exit 0; Stage 7-9 modules loaded in the child: none; the finder refused 1 import attempt(s); in-process base rate 0.3333333333333333; agree to 1e-12 True, above base rate True, absence enforced True; (c) no-catalog controller -> SURVIVAL:sha256:717e9f47fb54ef9c70d5935e6f80e69c43da5ca6253b2e86fbccd46364a9d154 (Φ-oracle SURVIVAL True)

Steps (wall clock is host-contended; loadavg before -> after):
  splits             232.20 s  (3.37, 3.85, 4.26) -> (7.51, 5.76, 4.94)
  audit                1.29 s  (7.51, 5.76, 4.94) -> (7.51, 5.76, 4.94)
  references           1.72 s  (7.51, 5.76, 4.94) -> (7.39, 5.76, 4.94)
  expressibility       2.71 s  (7.39, 5.76, 4.94) -> (7.39, 5.76, 4.94)
  search             797.18 s  (7.39, 5.76, 4.94) -> (8.31, 7.93, 6.52)
  comparisons          8.09 s  (8.31, 7.93, 6.52) -> (8.44, 7.96, 6.54)
  argus               22.23 s  (8.44, 7.96, 6.54) -> (8.57, 8.03, 6.6)
  physics             82.70 s  (8.57, 8.03, 6.6) -> (8.34, 8.06, 6.74)
  laws                14.69 s  (8.34, 8.06, 6.74) -> (8.04, 8.01, 6.74)
  abstractions         4.73 s  (8.04, 8.01, 6.74) -> (7.96, 7.99, 6.74)
  runtime              0.68 s  (7.96, 7.99, 6.74) -> (7.96, 7.99, 6.74)
  hardware             0.59 s  (7.96, 7.99, 6.74) -> (7.96, 7.99, 6.74)
  successor            3.61 s  (7.96, 7.99, 6.74) -> (7.88, 7.97, 6.74)
  isolation           38.28 s  (7.88, 7.97, 6.74) -> (7.52, 7.88, 6.76)

Search runs (train only; WU are the primary cost):
  evolutionary-s101                    72 evals   95999189 WU WORK_BUDGET_EXCEEDED  winner NONE                train worst None phi-rediscovered False
  evolutionary-s202                    66 evals   95999850 WU WORK_BUDGET_EXCEEDED  winner NONE                train worst None phi-rediscovered False
  evolutionary-s303                    61 evals   95999371 WU WORK_BUDGET_EXCEEDED  winner NONE                train worst None phi-rediscovered False
  random-s101                          67 evals   95999967 WU WORK_BUDGET_EXCEEDED  winner NONE                train worst None phi-rediscovered False
  random-s202                          62 evals   95999805 WU WORK_BUDGET_EXCEEDED  winner sha256:fdb7289b5dfc train worst 0.3939 phi-rediscovered False
  random-s303                          66 evals   95999786 WU WORK_BUDGET_EXCEEDED  winner NONE                train worst None phi-rediscovered False
  exhaustive-s101                     126 evals   65577033 WU EXHAUSTED_SPACE       winner sha256:717e9f47fb54 train worst 0.5872 phi-rediscovered True
  evolutionary-s101-subtractive        79 evals   95999937 WU WORK_BUDGET_EXCEEDED  winner NONE                train worst None phi-rediscovered False
  evolutionary-s202-subtractive        58 evals   95998878 WU WORK_BUDGET_EXCEEDED  winner NONE                train worst None phi-rediscovered False
  evolutionary-s303-subtractive        60 evals   95999189 WU WORK_BUDGET_EXCEEDED  winner NONE                train worst None phi-rediscovered False
  evolutionary-s101-fossil_avoidance   72 evals   95999189 WU WORK_BUDGET_EXCEEDED  winner NONE                train worst None phi-rediscovered False
  evolutionary-s202-fossil_avoidance   66 evals   95999850 WU WORK_BUDGET_EXCEEDED  winner NONE                train worst None phi-rediscovered False
  evolutionary-s303-fossil_avoidance   61 evals   95999371 WU WORK_BUDGET_EXCEEDED  winner NONE                train worst None phi-rediscovered False
  evolutionary-s101-niches             74 evals   95999682 WU WORK_BUDGET_EXCEEDED  winner NONE                train worst None phi-rediscovered False
  evolutionary-s202-niches             67 evals   95999424 WU WORK_BUDGET_EXCEEDED  winner NONE                train worst None phi-rediscovered False
  evolutionary-s303-niches             59 evals   95999955 WU WORK_BUDGET_EXCEEDED  winner NONE                train worst None phi-rediscovered False
  held-out random-s202               worst 0.4262 clean 0.4415 gap -0.0323
  held-out exhaustive-s101           worst 0.5975 clean 0.5975 gap -0.0103

Shuffled-label control: NULL_HELD, permutation p 0.8507462686567164, prior percentile 0.0625, held-out AP 0.3147609406724301

GATE: FAILED (6)
Command exited with non-zero status 1
	Command being timed: "python -m pocketsec.stage9.cli gate --save /tmp/claude-1000/-home-anil-Documents-Research/4d447431-f910-4701-b132-7d03c949be5c/scratchpad/s9/gate-report.json"
	User time (seconds): 1017.29
	System time (seconds): 2.26
	Percent of CPU this job got: 83%
	Elapsed (wall clock) time (h:mm:ss or m:ss): 20:19.73
	Average shared text size (kbytes): 0
	Average unshared data size (kbytes): 0
	Average stack size (kbytes): 0
	Average total size (kbytes): 0
	Maximum resident set size (kbytes): 1514296
	Average resident set size (kbytes): 0
	Major (requiring I/O) page faults: 23934
	Minor (reclaiming a frame) page faults: 513645
	Voluntary context switches: 30524
	Involuntary context switches: 171214
	Swaps: 0
	File system inputs: 989760
	File system outputs: 0
	Socket messages sent: 0
	Socket messages received: 0
	Signals delivered: 0
	Page size (bytes): 4096
	Exit status: 1
exit=1
loadavg end: 7.56 7.88 6.77 7/2102 471877
2026-09-26T22:08:00+10:00
```

### A.2 P0: compile and cache the count-240 splits (seeds 3, 11, 17; clean + 6 ARGUS attacks)

```text
$ cd <scratchpad>/s9 && PYTHONPATH=/home/anil/Documents/Research/pocketsec:. python p0_compile.py 3 11 17
3 clean 240 17595 audit_failures= [] digest sha256:1398274b4ccd1602
3 rename_binaries 240 17595 audit_failures= [] digest sha256:82ca219a9d01d7fb
3 reorder_across_actors 240 17595 audit_failures= [] digest sha256:6a9805a30d9a850a
3 benign_duplicate_flood 240 19403 audit_failures= [] digest sha256:6253dfd3ebca292c
3 timing_stretch 240 17595 audit_failures= [] digest sha256:f4f4f1ec074f78b1
3 sensor_drop_10 240 15905 audit_failures= [] digest sha256:2567639541f5c80b
3 lineage_table_flood 240 32955 audit_failures= [] digest sha256:051fc2b672119e50
seed 3: compiled 7 variants in 98.3s (host-contended) loadavg (6.35, 4.91, 4.61) -> (6.78, 5.71, 4.94)
11 clean 240 17898 audit_failures= [] digest sha256:4b4799f96f34ec7e
11 rename_binaries 240 17898 audit_failures= [] digest sha256:7817aa9fe4913096
11 reorder_across_actors 240 17898 audit_failures= [] digest sha256:841cfcd537beb9ca
11 benign_duplicate_flood 240 19609 audit_failures= [] digest sha256:38d9982d94cd190a
11 timing_stretch 240 17898 audit_failures= [] digest sha256:0890c1f97fa4c93b
11 sensor_drop_10 240 16155 audit_failures= [] digest sha256:b15b718dfbdd734f
11 lineage_table_flood 240 33258 audit_failures= [] digest sha256:4fe657900b00e09f
seed 11: compiled 7 variants in 98.2s (host-contended) loadavg (6.78, 5.71, 4.94) -> (6.84, 6.22, 5.21)
17 clean 240 17302 audit_failures= [] digest sha256:d354f6208e7035fc
17 rename_binaries 240 17302 audit_failures= [] digest sha256:cabdca1813bd82e9
17 reorder_across_actors 240 17302 audit_failures= [] digest sha256:e192c0716c8f2a17
17 benign_duplicate_flood 240 19045 audit_failures= [] digest sha256:0fde2d69aff9a5fc
17 timing_stretch 240 17302 audit_failures= [] digest sha256:a38102ed218c135d
17 sensor_drop_10 240 15549 audit_failures= [] digest sha256:06e9c86db8365858
17 lineage_table_flood 240 32662 audit_failures= [] digest sha256:84877b8f05fbec31
seed 17: compiled 7 variants in 94.6s (host-contended) loadavg (6.84, 6.22, 5.21) -> (6.54, 6.42, 5.39)
```

### A.3 P1: hand baselines on three seeds, and charged vs static WU

```text
$ cd <scratchpad>/s9 && PYTHONPATH=/home/anil/Documents/Research/pocketsec:. python p1_references.py
loadavg (6.03, 6.32, 5.37)
phi-oracle   digest sha256:717e9f47fb54ef9c in_exhaustive=True wu/event=3 bytes=1184
H1           digest sha256:6897396d2432749b in_exhaustive=False wu/event=4 bytes=1200
H2           digest sha256:1ba910ff26947bd1 in_exhaustive=True wu/event=3 bytes=1192
order-free   digest sha256:4e42204d685aa081 in_exhaustive=True wu/event=4 bytes=1192
--- seed 3: sessions 240 base rate 0.3333 events(all variants) 138643
phi-oracle   clean 0.5897 worst 0.5872 (sensor_drop_10) WU charged 446730 == static*events False | clean=0.5897 rename_bin=0.6099 reorder_ac=0.5897 benign_dup=0.5897 timing_str=0.5897 sensor_dro=0.5872 lineage_ta=0.5897
H1           clean 0.7279 worst 0.5940 (lineage_table_flood) WU charged 585373 == static*events False | clean=0.7279 rename_bin=0.7643 reorder_ac=0.7279 benign_dup=0.7105 timing_str=0.7279 sensor_dro=0.7383 lineage_ta=0.5940
H2           clean 0.7312 worst 0.4377 (lineage_table_flood) WU charged 477531 == static*events False | clean=0.7312 rename_bin=0.7804 reorder_ac=0.7312 benign_dup=0.7312 timing_str=0.7312 sensor_dro=0.6527 lineage_ta=0.4377
order-free   clean 0.2929 worst 0.2852 (benign_duplicate_flood) WU charged 585373 == static*events False | clean=0.2929 rename_bin=0.2904 reorder_ac=0.2929 benign_dup=0.2852 timing_str=0.2929 sensor_dro=0.2911 lineage_ta=0.2929
--- seed 11: sessions 240 base rate 0.3333 events(all variants) 140614
phi-oracle   clean 0.5975 worst 0.5975 (clean) WU charged 452567 == static*events False | clean=0.5975 rename_bin=0.6095 reorder_ac=0.5975 benign_dup=0.5975 timing_str=0.5975 sensor_dro=0.6095 lineage_ta=0.5975
H1           clean 0.7680 worst 0.6256 (lineage_table_flood) WU charged 593181 == static*events False | clean=0.7680 rename_bin=0.7942 reorder_ac=0.7680 benign_dup=0.7548 timing_str=0.7680 sensor_dro=0.7639 lineage_ta=0.6256
H2           clean 0.8111 worst 0.5980 (lineage_table_flood) WU charged 483292 == static*events False | clean=0.8111 rename_bin=0.8476 reorder_ac=0.8111 benign_dup=0.8111 timing_str=0.8111 sensor_dro=0.7337 lineage_ta=0.5980
order-free   clean 0.3091 worst 0.3057 (sensor_drop_10) WU charged 593181 == static*events False | clean=0.3091 rename_bin=0.3108 reorder_ac=0.3091 benign_dup=0.3318 timing_str=0.3091 sensor_dro=0.3057 lineage_ta=0.3091
--- seed 17: sessions 240 base rate 0.3333 events(all variants) 136464
phi-oracle   clean 0.5904 worst 0.5705 (sensor_drop_10) WU charged 440017 == static*events False | clean=0.5904 rename_bin=0.6010 reorder_ac=0.5904 benign_dup=0.5904 timing_str=0.5904 sensor_dro=0.5705 lineage_ta=0.5904
H1           clean 0.7687 worst 0.6883 (lineage_table_flood) WU charged 576481 == static*events False | clean=0.7687 rename_bin=0.7873 reorder_ac=0.7687 benign_dup=0.7330 timing_str=0.7687 sensor_dro=0.7554 lineage_ta=0.6883
H2           clean 0.7720 worst 0.5454 (lineage_table_flood) WU charged 470642 == static*events False | clean=0.7720 rename_bin=0.8359 reorder_ac=0.7720 benign_dup=0.7720 timing_str=0.7720 sensor_dro=0.7078 lineage_ta=0.5454
order-free   clean 0.3103 worst 0.2997 (rename_binaries) WU charged 576481 == static*events False | clean=0.3103 rename_bin=0.2997 reorder_ac=0.3103 benign_dup=0.3210 timing_str=0.3103 sensor_dro=0.3194 lineage_ta=0.3103
loadavg (5.95, 6.3, 5.37)
```

### A.4 P2: evolutionary vs random at 1x, 4x, 16x (formatted from the probe's JSON lines)

```text
$ for s in 101 202 303; do cd <scratchpad>/s9 && PYTHONPATH=/home/anil/Documents/Research/pocketsec:. python p2_search.py $s 1 EVOLUTIONARY,RANDOM; cd <scratchpad>/s9 && PYTHONPATH=/home/anil/Documents/Research/pocketsec:. python p2_search.py $s 4 EVOLUTIONARY,RANDOM; done; cd <scratchpad>/s9 && PYTHONPATH=/home/anil/Documents/Research/pocketsec:. python p2_search.py 101 16 EVOLUTIONARY,RANDOM; python fmt.py p2-*.jsonl
evolutionary-s101    budget   96000000 evals   72 hits 2 wu 95999189 stop WORK_BUDGET_EXCEEDED pop_evict 8 fossils 71 elites 1 wall 54.9s load [[4.88, 5.92, 5.29], [6.7, 6.27, 5.44]]
   ops(proposed,valid,improved): [('REPLACE', 5, 5, 0), ('MERGE', 6, 2, 0), ('SPLIT', 7, 4, 0), ('FACTORIZE', 8, 4, 0), ('SPARSIFY', 6, 5, 0), ('SPECIALIZE', 1, 0, 0), ('REMOVE', 12, 10, 0), ('MOVE', 6, 0, 0), ('COMPRESS', 2, 1, 0), ('DEVELOPMENTAL', 4, 4, 0), ('INSERT', 4, 4, 0), ('CROSSOVER', 6, 4, 0), ('MACRO_INSERT', 5, 0, 0)]
   census: admissible 0 constant 43 violations {'detection_quality': 72, 'robustness': 1} rediscovered_phi False
   winner      NONE
   best_effort sha256:11bc4ac279d635bf nodes 9 wu 5 B 5320 train worst 0.3747 clean 0.3834 | held11 worst 0.3277 clean 0.3564 | held17 worst 0.3348 | from_variation False
   determinism sha256:de129b42ae43533f366f8b6
random-s101          budget   96000000 evals   67 hits 0 wu 95999967 stop WORK_BUDGET_EXCEEDED pop_evict 3 fossils 66 elites 1 wall 49.4s load [[6.7, 6.27, 5.44], [7.09, 6.47, 5.56]]
   ops(proposed,valid,improved): []
   census: admissible 0 constant 30 violations {'detection_quality': 67, 'robustness': 3} rediscovered_phi False
   winner      NONE
   best_effort sha256:11bc4ac279d635bf nodes 9 wu 5 B 5320 train worst 0.3747 clean 0.3834 | held11 worst 0.3277 clean 0.3564 | held17 worst 0.3348 | from_variation None
   determinism sha256:dfb9ef3aff9dfb6155d1a01
evolutionary-s202    budget   96000000 evals   66 hits 2 wu 95999850 stop WORK_BUDGET_EXCEEDED pop_evict 2 fossils 63 elites 1 wall 50.9s load [[4.88, 5.92, 5.29], [6.5, 6.22, 5.42]]
   ops(proposed,valid,improved): [('REPLACE', 6, 6, 0), ('MERGE', 6, 1, 0), ('SPLIT', 6, 2, 0), ('FACTORIZE', 4, 2, 0), ('SPARSIFY', 6, 5, 0), ('SPECIALIZE', 8, 2, 0), ('REMOVE', 3, 3, 0), ('MOVE', 5, 0, 0), ('COMPRESS', 4, 4, 0), ('DEVELOPMENTAL', 5, 5, 0), ('INSERT', 5, 5, 0), ('CROSSOVER', 2, 2, 0), ('MACRO_INSERT', 8, 0, 0)]
   census: admissible 0 constant 22 violations {'detection_quality': 66, 'robustness': 6} rediscovered_phi False
   winner      NONE
   best_effort sha256:2479b6d17781807b nodes 9 wu 9 B 1224 train worst 0.3762 clean 0.4360 | held11 worst 0.3648 clean 0.4435 | held17 worst 0.3383 | from_variation False
   determinism sha256:9ff2ca9df7f1bb6190180c4
random-s202          budget   96000000 evals   62 hits 0 wu 95999805 stop WORK_BUDGET_EXCEEDED pop_evict 0 fossils 58 elites 1 wall 49.8s load [[6.7, 6.27, 5.44], [7.18, 6.47, 5.56]]
   ops(proposed,valid,improved): []
   census: admissible 1 constant 22 violations {'detection_quality': 61, 'robustness': 2} rediscovered_phi False
   winner      sha256:fdb7289b5dfcee2a nodes 20 wu 17 B 1568 train worst 0.3939 clean 0.3939 | held11 worst 0.4262 clean 0.4415 | held17 worst 0.3719 | from_variation None
   best_effort sha256:fdb7289b5dfcee2a nodes 20 wu 17 B 1568 train worst 0.3939 clean 0.3939 | held11 worst 0.4262 clean 0.4415 | held17 worst 0.3719 | from_variation None
   determinism sha256:0e455f8802b6f6e7ef8520f
evolutionary-s303    budget   96000000 evals   61 hits 0 wu 95999371 stop WORK_BUDGET_EXCEEDED pop_evict 0 fossils 57 elites 1 wall 53.8s load [[4.88, 5.92, 5.29], [6.7, 6.27, 5.44]]
   ops(proposed,valid,improved): [('REPLACE', 6, 6, 0), ('MERGE', 5, 1, 0), ('SPLIT', 5, 0, 0), ('FACTORIZE', 5, 1, 0), ('SPARSIFY', 5, 2, 0), ('SPECIALIZE', 7, 2, 0), ('REMOVE', 6, 5, 0), ('MOVE', 7, 0, 0), ('COMPRESS', 4, 3, 0), ('DEVELOPMENTAL', 3, 3, 0), ('INSERT', 4, 4, 0), ('CROSSOVER', 12, 3, 0), ('MACRO_INSERT', 5, 0, 0)]
   census: admissible 0 constant 32 violations {'detection_quality': 61, 'robustness': 1} rediscovered_phi False
   winner      NONE
   best_effort sha256:035f06c4100edd13 nodes 9 wu 8 B 1608 train worst 0.3751 clean 0.4156 | held11 worst 0.3789 clean 0.3923 | held17 worst 0.3591 | from_variation False
   determinism sha256:3a8e10dbbacecafa73eaff1
random-s303          budget   96000000 evals   66 hits 0 wu 95999786 stop WORK_BUDGET_EXCEEDED pop_evict 2 fossils 61 elites 1 wall 46.9s load [[6.7, 6.27, 5.44], [7.09, 6.47, 5.56]]
   ops(proposed,valid,improved): []
   census: admissible 0 constant 32 violations {'detection_quality': 66, 'robustness': 1} rediscovered_phi False
   winner      NONE
   best_effort sha256:13e8905a098c1d81 nodes 13 wu 12 B 5736 train worst 0.3792 clean 0.3792 | held11 worst 0.3207 clean 0.3995 | held17 worst 0.3306 | from_variation None
   determinism sha256:67979fdc6e0efce5d1c2188
evolutionary-s101    budget  384000000 evals  313 hits 22 wu 383999961 stop WORK_BUDGET_EXCEEDED pop_evict 249 fossils 310 elites 1 wall 279.6s load [[5.86, 5.97, 5.48], [8.45, 7.94, 6.51]]
   ops(proposed,valid,improved): [('REPLACE', 32, 31, 0), ('MERGE', 40, 8, 0), ('SPLIT', 49, 31, 0), ('FACTORIZE', 38, 17, 0), ('SPARSIFY', 38, 26, 0), ('SPECIALIZE', 28, 15, 0), ('REMOVE', 49, 46, 1), ('MOVE', 26, 0, 0), ('COMPRESS', 32, 30, 0), ('DEVELOPMENTAL', 42, 42, 0), ('INSERT', 26, 26, 0), ('CROSSOVER', 51, 32, 1), ('MACRO_INSERT', 37, 0, 0)]
   census: admissible 3 constant 135 violations {'detection_quality': 310, 'robustness': 2} rediscovered_phi False
   winner      sha256:e21671a67d77e8d1 nodes 11 wu 5 B 5336 train worst 0.4049 clean 0.4261 | held11 worst 0.3328 clean 0.3900 | held17 worst 0.3302 | from_variation True
   best_effort sha256:e21671a67d77e8d1 nodes 11 wu 5 B 5336 train worst 0.4049 clean 0.4261 | held11 worst 0.3328 clean 0.3900 | held17 worst 0.3302 | from_variation True
   determinism sha256:d831c8736107abad7bae34d
random-s101          budget  384000000 evals  262 hits 1 wu 383999196 stop WORK_BUDGET_EXCEEDED pop_evict 198 fossils 259 elites 1 wall 211.8s load [[8.45, 7.94, 6.51], [6.61, 7.64, 6.72]]
   ops(proposed,valid,improved): []
   census: admissible 2 constant 130 violations {'detection_quality': 260, 'robustness': 8} rediscovered_phi False
   winner      sha256:f5dbde044b798d2f nodes 12 wu 9 B 1888 train worst 0.5146 clean 0.5419 | held11 worst 0.4819 clean 0.5690 | held17 worst 0.6151 | from_variation None
   best_effort sha256:f5dbde044b798d2f nodes 12 wu 9 B 1888 train worst 0.5146 clean 0.5419 | held11 worst 0.4819 clean 0.5690 | held17 worst 0.6151 | from_variation None
   determinism sha256:3ca7d30f708229068d66738
evolutionary-s202    budget  384000000 evals  258 hits 11 wu 383999515 stop WORK_BUDGET_EXCEEDED pop_evict 194 fossils 252 elites 1 wall 229.3s load [[5.86, 5.97, 5.48], [8.89, 7.93, 6.43]]
   ops(proposed,valid,improved): [('REPLACE', 24, 24, 0), ('MERGE', 23, 6, 0), ('SPLIT', 28, 18, 0), ('FACTORIZE', 19, 11, 0), ('SPARSIFY', 28, 22, 0), ('SPECIALIZE', 25, 13, 0), ('REMOVE', 29, 28, 0), ('MOVE', 32, 0, 0), ('COMPRESS', 26, 20, 0), ('DEVELOPMENTAL', 31, 31, 0), ('INSERT', 32, 32, 3), ('CROSSOVER', 38, 33, 0), ('MACRO_INSERT', 27, 0, 0)]
   census: admissible 1 constant 45 violations {'detection_quality': 257, 'robustness': 6} rediscovered_phi False
   winner      sha256:268a2068023cde0d nodes 16 wu 10 B 9600 train worst 0.3869 clean 0.4292 | held11 worst 0.3149 clean 0.3265 | held17 worst 0.3441 | from_variation True
   best_effort sha256:268a2068023cde0d nodes 16 wu 10 B 9600 train worst 0.3869 clean 0.4292 | held11 worst 0.3149 clean 0.3265 | held17 worst 0.3441 | from_variation True
   determinism sha256:c7593bd0dec7b09d9e1474c
random-s202          budget  384000000 evals  256 hits 5 wu 383999810 stop WORK_BUDGET_EXCEEDED pop_evict 192 fossils 251 elites 1 wall 225.8s load [[8.89, 7.93, 6.43], [7.71, 7.93, 6.77]]
   ops(proposed,valid,improved): []
   census: admissible 6 constant 107 violations {'detection_quality': 249, 'robustness': 5} rediscovered_phi False
   winner      sha256:207cd4d569679b4c nodes 19 wu 3 B 2072 train worst 0.4190 clean 0.4250 | held11 worst 0.3628 clean 0.4370 | held17 worst 0.3498 | from_variation None
   best_effort sha256:59a57874c8a2d1ba nodes 4 wu 3 B 1184 train worst 0.5940 clean 0.7279 | held11 worst 0.6256 clean 0.7680 | held17 worst 0.6883 | from_variation None
   determinism sha256:f7cd19a9e9ff39f3c0f4565
evolutionary-s303    budget  384000000 evals  236 hits 7 wu 383999993 stop WORK_BUDGET_EXCEEDED pop_evict 172 fossils 228 elites 1 wall 248.5s load [[5.86, 5.97, 5.48], [8.75, 7.95, 6.47]]
   ops(proposed,valid,improved): [('REPLACE', 39, 37, 0), ('MERGE', 25, 5, 0), ('SPLIT', 32, 8, 0), ('FACTORIZE', 27, 17, 0), ('SPARSIFY', 30, 19, 2), ('SPECIALIZE', 35, 13, 0), ('REMOVE', 32, 30, 0), ('MOVE', 39, 0, 0), ('COMPRESS', 19, 14, 0), ('DEVELOPMENTAL', 22, 22, 1), ('INSERT', 23, 23, 0), ('CROSSOVER', 47, 24, 1), ('MACRO_INSERT', 26, 0, 0)]
   census: admissible 7 constant 77 violations {'detection_quality': 229, 'robustness': 1} rediscovered_phi False
   winner      sha256:153309a475c35c0a nodes 9 wu 6 B 1608 train worst 0.3975 clean 0.4111 | held11 worst 0.3937 clean 0.4135 | held17 worst 0.3564 | from_variation True
   best_effort sha256:153309a475c35c0a nodes 9 wu 6 B 1608 train worst 0.3975 clean 0.4111 | held11 worst 0.3937 clean 0.4135 | held17 worst 0.3564 | from_variation True
   determinism sha256:df19fcc7650cc3cc0faf5e1
random-s303          budget  384000000 evals  255 hits 2 wu 383998825 stop WORK_BUDGET_EXCEEDED pop_evict 191 fossils 249 elites 1 wall 224.3s load [[8.75, 7.95, 6.47], [7.35, 7.83, 6.76]]
   ops(proposed,valid,improved): []
   census: admissible 3 constant 108 violations {'detection_quality': 251, 'robustness': 8} rediscovered_phi False
   winner      sha256:422fcb03fa33a7ad nodes 13 wu 12 B 1768 train worst 0.5146 clean 0.5419 | held11 worst 0.4819 clean 0.5690 | held17 worst 0.6151 | from_variation None
   best_effort sha256:422fcb03fa33a7ad nodes 13 wu 12 B 1768 train worst 0.5146 clean 0.5419 | held11 worst 0.4819 clean 0.5690 | held17 worst 0.6151 | from_variation None
   determinism sha256:b69962eb28cc272bdf593f6
evolutionary-s101    budget 1536000000 evals 1316 hits 171 wu 1535999733 stop WORK_BUDGET_EXCEEDED pop_evict 1252 fossils 1295 elites 1 wall 770.7s load [[5.86, 5.97, 5.48], [3.02, 5.0, 5.84]]
   ops(proposed,valid,improved): [('REPLACE', 156, 155, 4), ('MERGE', 179, 110, 2), ('SPLIT', 183, 152, 0), ('FACTORIZE', 156, 129, 4), ('SPARSIFY', 168, 152, 0), ('SPECIALIZE', 146, 20, 0), ('REMOVE', 170, 167, 6), ('MOVE', 156, 0, 0), ('COMPRESS', 145, 143, 1), ('DEVELOPMENTAL', 164, 164, 2), ('INSERT', 160, 160, 0), ('CROSSOVER', 221, 104, 1), ('MACRO_INSERT', 172, 0, 0)]
   census: admissible 591 constant 192 violations {'detection_quality': 725, 'robustness': 38} rediscovered_phi False
   winner      sha256:9605b1adf5f7b522 nodes 10 wu 6 B 5456 train worst 0.4181 clean 0.4312 | held11 worst 0.3376 clean 0.4064 | held17 worst 0.3569 | from_variation True
   best_effort sha256:9605b1adf5f7b522 nodes 10 wu 6 B 5456 train worst 0.4181 clean 0.4312 | held11 worst 0.3376 clean 0.4064 | held17 worst 0.3569 | from_variation True
   determinism sha256:cfc0a487387c0452830fcf8
random-s101          budget 1536000000 evals  986 hits 12 wu 1535999817 stop WORK_BUDGET_EXCEEDED pop_evict 922 fossils 983 elites 1 wall 439.3s load [[3.02, 5.0, 5.84], [2.79, 3.57, 4.83]]
   ops(proposed,valid,improved): []
   census: admissible 11 constant 465 violations {'detection_quality': 969, 'robustness': 33} rediscovered_phi False
   winner      sha256:f5dbde044b798d2f nodes 12 wu 9 B 1888 train worst 0.5146 clean 0.5419 | held11 worst 0.4819 clean 0.5690 | held17 worst 0.6151 | from_variation None
   best_effort sha256:25fdf9b5bf20448b nodes 16 wu 14 B 1408 train worst 0.5150 clean 0.7273 | held11 worst 0.5162 clean 0.7529 | held17 worst 0.5617 | from_variation None
   determinism sha256:d0d1d63508107b2a9b73792
```

### A.5 P10: determinism digests (gate vs probe) and `strategy_verdict` on the 1x and 4x evidence

```text
$ cd <scratchpad>/s9 && PYTHONPATH=/home/anil/Documents/Research/pocketsec:. python p10_verdict.py
evolutionary-s101 gate sha256:de129b42ae43533f366f8b6 probe sha256:de129b42ae43533f366f8b6 MATCH
evolutionary-s202 gate sha256:9ff2ca9df7f1bb6190180c4 probe sha256:9ff2ca9df7f1bb6190180c4 MATCH
evolutionary-s303 gate sha256:3a8e10dbbacecafa73eaff1 probe sha256:3a8e10dbbacecafa73eaff1 MATCH
random-s101 gate sha256:dfb9ef3aff9dfb6155d1a01 probe sha256:dfb9ef3aff9dfb6155d1a01 MATCH
random-s202 gate sha256:0e455f8802b6f6e7ef8520f probe sha256:0e455f8802b6f6e7ef8520f MATCH
random-s303 gate sha256:67979fdc6e0efce5d1c2188 probe sha256:67979fdc6e0efce5d1c2188 MATCH
x1 NOT_YET_JUSTIFIED vs random [None, None, None] median None | vs exhaustive [None, None, None] median None
   train-vs-heldout gap of evolutionary winners [None, None, None] random [None, -0.0323, None]
x4 REJECTED vs random [-0.1491, -0.0479, -0.0882] median -0.08815109428454754 | vs exhaustive [-0.2647, -0.2826, -0.2038] median -0.2646984980326084
   train-vs-heldout gap of evolutionary winners [0.0721, 0.072, 0.0038] random [0.0327, 0.0562, 0.0327]
```

### A.6 P3: bounds under flood

```text
$ cd <scratchpad>/s9 && PYTHONPATH=/home/anil/Documents/Research/pocketsec:. python p3_bounds.py
loadavg (6.92, 6.44, 5.56)
== 1. phenotype lineage / side-table / event-cap flood (real peak bytes via tracemalloc) ==
phi-oracle               events offered     16 processed    16 truncated      0 lineages  16 evictions     0 side_evict     0 accounted_peak   1184 (bound 1184) tracemalloc_peak 29072
phi-oracle               events offered    256 processed   256 truncated      0 lineages  16 evictions   240 side_evict     0 accounted_peak   1184 (bound 1184) tracemalloc_peak 31688
phi-oracle               events offered   4096 processed  4096 truncated      0 lineages  16 evictions  4080 side_evict     0 accounted_peak   1184 (bound 1184) tracemalloc_peak 31680
phi-oracle               events offered  65536 processed  4096 truncated  61440 lineages  16 evictions  4080 side_evict     0 accounted_peak   1184 (bound 1184) tracemalloc_peak 31672
H1                       events offered     16 processed    16 truncated      0 lineages  16 evictions     0 side_evict     0 accounted_peak   1200 (bound 1200) tracemalloc_peak 28952
H1                       events offered    256 processed   256 truncated      0 lineages  16 evictions   240 side_evict     0 accounted_peak   1200 (bound 1200) tracemalloc_peak 32016
H1                       events offered   4096 processed  4096 truncated      0 lineages  16 evictions  4080 side_evict     0 accounted_peak   1200 (bound 1200) tracemalloc_peak 31928
H1                       events offered  65536 processed  4096 truncated  61440 lineages  16 evictions  4080 side_evict     0 accounted_peak   1200 (bound 1200) tracemalloc_peak 34128
H2                       events offered     16 processed    16 truncated      0 lineages  16 evictions     0 side_evict     0 accounted_peak   1192 (bound 1192) tracemalloc_peak 28936
H2                       events offered    256 processed   256 truncated      0 lineages  16 evictions   240 side_evict     0 accounted_peak   1192 (bound 1192) tracemalloc_peak 31920
H2                       events offered   4096 processed  4096 truncated      0 lineages  16 evictions  4080 side_evict     0 accounted_peak   1192 (bound 1192) tracemalloc_peak 31856
H2                       events offered  65536 processed  4096 truncated  61440 lineages  16 evictions  4080 side_evict     0 accounted_peak   1192 (bound 1192) tracemalloc_peak 31848
first-seen(side table)   events offered     16 processed    16 truncated      0 lineages  16 evictions     0 side_evict     0 accounted_peak   1448 (bound 5288) tracemalloc_peak 30632
first-seen(side table)   events offered    256 processed   256 truncated      0 lineages  16 evictions   240 side_evict     0 accounted_peak   5288 (bound 5288) tracemalloc_peak 53224
first-seen(side table)   events offered   4096 processed  4096 truncated      0 lineages  16 evictions  4080 side_evict  3840 accounted_peak   5288 (bound 5288) tracemalloc_peak 87968
first-seen(side table)   events offered  65536 processed  4096 truncated  61440 lineages  16 evictions  4080 side_evict  3840 accounted_peak   5288 (bound 5288) tracemalloc_peak 90136
== 2. EvaluationCache flooded with 10x capacity distinct keys ==
cache capacity 4096 offered 40960 len 4096 evictions 36864 tracemalloc_peak 1605488
== 3. FossilStore flooded with 10x capacity ==
fossil capacity 2048 offered 20480 len 2048 evictions 18432 tracemalloc_peak 912064
== 4. QD archive hypothesis explosion (10x cell bound) ==
niches=True: hypothesis_explosion fired 5040/5040 | offered 5040 distinct genomes (target 5040, 5180 draws) to an archive bounded at 504 cells; occupied 72; rejected 4771; bound held after 5040/5040 offers; fitness synthetic
niches=False: hypothesis_explosion fired 10/10 | offered 10 distinct genomes (target 10, 10 draws) to an archive bounded at 1 cells; occupied 1; rejected 8; bound held after 10/10 offers; fitness synthetic
== 5. search record bound and population bound on a tiny clean-only suite (budget effectively unlimited) ==
tiny labels positives 10 of 30
RANDOM: stop RECORD_BOUND evaluations 8192 records 8192 (MAX_RECORDS 8192) wu_spent 192897723 cache_hits 263 population_evictions 8128 (MAX_POPULATION 64) fossils_recorded 8183 archive_elites 1 wall 66.1s
EVOLUTIONARY: stop RECORD_BOUND evaluations 8192 records 8192 (MAX_RECORDS 8192) wu_spent 315417347 cache_hits 984 population_evictions 8128 (MAX_POPULATION 64) fossils_recorded 8143 archive_elites 1 wall 186.6s
loadavg (10.05, 7.65, 6.18)
```

### A.7 P6: decode the random-search genomes; compare with H1

```text
$ cd <scratchpad>/s9 && PYTHONPATH=/home/anil/Documents/Research/pocketsec:. python p6_decode.py
MSSC constraints: MSSCConstraints(q_min_margin=0.05, r_min=0.85, k_min=None, ram_bytes_max=65536, wu_per_event_max=64)
--- H1 (hand) digest sha256:6897396d2432749b wu/event 4 readout_wu 1 bytes 1200 agg MAX
   registers [{'type': 'FLOAT', 'ring': 1, 'precision_bits': 64, 'init': 0.0}]
   update  [{'kind': 'REG', 'type': 'FLOAT', 'primitive': '', 'args': [], 'source': None, 'index': 0, 'lag': 0, 'value': None}, {'kind': 'INPUT', 'type': 'FLOAT', 'primitive': '', 'args': [], 'source': 'DELTA_PHI', 'index': 0, 'lag': 0, 'value': None}, {'kind': 'CONST', 'type': 'FLOAT', 'primitive': '', 'args': [], 'source': None, 'index': 0, 'lag': 0, 'value': 0.0}, {'kind': 'APPLY', 'type': 'FLOAT', 'primitive': 'MAX', 'args': [1, 2], 'source': None, 'index': 0, 'lag': 0, 'value': None}, {'kind': 'APPLY', 'type': 'FLOAT', 'primitive': 'ADD', 'args': [0, 3], 'source': None, 'index': 0, 'lag': 0, 'value': None}] outputs (4,)
   readout [{'kind': 'REG', 'type': 'FLOAT', 'primitive': '', 'args': [], 'source': None, 'index': 0, 'lag': 0, 'value': None}]
   train    clean 0.7279 worst 0.5940 ratio 0.8160 charged WU/event 4.2222 MSSC violations ('robustness',)
   heldout  clean 0.7680 worst 0.6256 ratio 0.8146 charged WU/event 4.2185 MSSC violations ('robustness',)
   h17      clean 0.7687 worst 0.6883 ratio 0.8955 charged WU/event 4.2244 MSSC violations ()
--- phi-oracle (hand) digest sha256:717e9f47fb54ef9c wu/event 3 readout_wu 1 bytes 1184 agg MAX
   registers [{'type': 'FLOAT', 'ring': 1, 'precision_bits': 64, 'init': 0.0}]
   update  [{'kind': 'REG', 'type': 'FLOAT', 'primitive': '', 'args': [], 'source': None, 'index': 0, 'lag': 0, 'value': None}, {'kind': 'INPUT', 'type': 'FLOAT', 'primitive': '', 'args': [], 'source': 'FEATURE', 'index': 73, 'lag': 0, 'value': None}, {'kind': 'APPLY', 'type': 'FLOAT', 'primitive': 'MAX', 'args': [0, 1], 'source': None, 'index': 0, 'lag': 0, 'value': None}] outputs (2,)
   readout [{'kind': 'REG', 'type': 'FLOAT', 'primitive': '', 'args': [], 'source': None, 'index': 0, 'lag': 0, 'value': None}]
   train    clean 0.5897 worst 0.5872 ratio 0.9959 charged WU/event 3.2222 MSSC violations ()
   heldout  clean 0.5975 worst 0.5975 ratio 1.0000 charged WU/event 3.2185 MSSC violations ()
   h17      clean 0.5904 worst 0.5705 ratio 0.9664 charged WU/event 3.2244 MSSC violations ()
--- random draw #172 (seed 202) digest sha256:59a57874c8a2d1ba wu/event 3 readout_wu 1 bytes 1184 agg MAX
   registers [{'type': 'FLOAT', 'ring': 1, 'precision_bits': 64, 'init': 0.0}]
   update  [{'kind': 'REG', 'type': 'FLOAT', 'primitive': '', 'args': [], 'source': None, 'index': 0, 'lag': 0, 'value': None}, {'kind': 'INPUT', 'type': 'FLOAT', 'primitive': '', 'args': [], 'source': 'DELTA_PHI', 'index': 0, 'lag': 0, 'value': None}, {'kind': 'APPLY', 'type': 'FLOAT', 'primitive': 'ADD', 'args': [0, 1], 'source': None, 'index': 0, 'lag': 0, 'value': None}] outputs (2,)
   readout [{'kind': 'REG', 'type': 'FLOAT', 'primitive': '', 'args': [], 'source': None, 'index': 0, 'lag': 0, 'value': None}]
   train    clean 0.7279 worst 0.5940 ratio 0.8160 charged WU/event 3.2222 MSSC violations ('robustness',)
   heldout  clean 0.7680 worst 0.6256 ratio 0.8146 charged WU/event 3.2185 MSSC violations ('robustness',)
   h17      clean 0.7687 worst 0.6883 ratio 0.8955 charged WU/event 3.2244 MSSC violations ()
   held-out clean score vector identical to H1's: True | rank-identical: [True]
--- random draw #235 (seed 101) digest sha256:f5dbde044b798d2f wu/event 9 readout_wu 1 bytes 1888 agg MAX
   registers [{'type': 'FLOAT', 'ring': 3, 'precision_bits': 64, 'init': 0.0}, {'type': 'FLOAT', 'ring': 3, 'precision_bits': 64, 'init': 0.0}]
   update  [{'kind': 'REG', 'type': 'FLOAT', 'primitive': '', 'args': [], 'source': None, 'index': 0, 'lag': 1, 'value': None}, {'kind': 'INPUT', 'type': 'FLOAT', 'primitive': '', 'args': [], 'source': 'DELTA_PHI', 'index': 0, 'lag': 0, 'value': None}, {'kind': 'APPLY', 'type': 'FLOAT', 'primitive': 'ADD', 'args': [0, 1], 'source': None, 'index': 0, 'lag': 0, 'value': None}, {'kind': 'INPUT', 'type': 'FLOAT', 'primitive': '', 'args': [], 'source': 'FEATURE', 'index': 58, 'lag': 0, 'value': None}, {'kind': 'CONST', 'type': 'BOOL', 'primitive': '', 'args': [], 'source': None, 'index': 0, 'lag': 0, 'value': False}, {'kind': 'APPLY', 'type': 'FLOAT', 'primitive': 'B2F', 'args': [4], 'source': None, 'index': 0, 'lag': 0, 'value': None}, {'kind': 'CONST', 'type': 'BOOL', 'primitive': '', 'args': [], 'source': None, 'index': 0, 'lag': 0, 'value': True}, {'kind': 'CONST', 'type': 'FLOAT', 'primitive': '', 'args': [], 'source': None, 'index': 0, 'lag': 0, 'value': 0.0}, {'kind': 'APPLY', 'type': 'FLOAT', 'primitive': 'SELECT', 'args': [6, 1, 7], 'source': None, 'index': 0, 'lag': 0, 'value': None}, {'kind': 'APPLY', 'type': 'FLOAT', 'primitive': 'DECAY', 'args': [5, 1, 8], 'source': None, 'index': 0, 'lag': 0, 'value': None}, {'kind': 'APPLY', 'type': 'FLOAT', 'primitive': 'MIN', 'args': [3, 9], 'source': None, 'index': 0, 'lag': 0, 'value': None}] outputs (2, 10)
   readout [{'kind': 'REG', 'type': 'FLOAT', 'primitive': '', 'args': [], 'source': None, 'index': 0, 'lag': 0, 'value': None}]
   train    clean 0.5419 worst 0.5146 ratio 0.9496 charged WU/event 9.2222 MSSC violations ()
   heldout  clean 0.5690 worst 0.4819 ratio 0.8469 charged WU/event 9.2185 MSSC violations ('robustness',)
   h17      clean 0.6322 worst 0.6151 ratio 0.9730 charged WU/event 9.2244 MSSC violations ()
   held-out clean score vector identical to H1's: False | rank-identical: [False]
--- random draw #114 (seed 303) digest sha256:422fcb03fa33a7ad wu/event 12 readout_wu 1 bytes 1768 agg MAX
   registers [{'type': 'INT', 'ring': 3, 'precision_bits': 64, 'init': 0}, {'type': 'FLOAT', 'ring': 1, 'precision_bits': 64, 'init': 0.0}, {'type': 'FLOAT', 'ring': 1, 'precision_bits': 64, 'init': 0.0}]
   update  [{'kind': 'INPUT', 'type': 'INT', 'primitive': '', 'args': [], 'source': 'TIME_BUCKET', 'index': 0, 'lag': 0, 'value': None}, {'kind': 'REG', 'type': 'FLOAT', 'primitive': '', 'args': [], 'source': None, 'index': 2, 'lag': 0, 'value': None}, {'kind': 'APPLY', 'type': 'FLOAT', 'primitive': 'ABS', 'args': [1], 'source': None, 'index': 0, 'lag': 0, 'value': None}, {'kind': 'APPLY', 'type': 'FLOAT', 'primitive': 'ABS', 'args': [2], 'source': None, 'index': 0, 'lag': 0, 'value': None}, {'kind': 'CONST', 'type': 'FLOAT', 'primitive': '', 'args': [], 'source': None, 'index': 0, 'lag': 0, 'value': 1.0}, {'kind': 'APPLY', 'type': 'FLOAT', 'primitive': 'MUL', 'args': [3, 4], 'source': None, 'index': 0, 'lag': 0, 'value': None}, {'kind': 'REG', 'type': 'FLOAT', 'primitive': '', 'args': [], 'source': None, 'index': 1, 'lag': 0, 'value': None}, {'kind': 'INPUT', 'type': 'FLOAT', 'primitive': '', 'args': [], 'source': 'DELTA_PHI', 'index': 0, 'lag': 0, 'value': None}, {'kind': 'REG', 'type': 'INT', 'primitive': '', 'args': [], 'source': None, 'index': 0, 'lag': 0, 'value': None}, {'kind': 'APPLY', 'type': 'FLOAT', 'primitive': 'POPCOUNT', 'args': [8], 'source': None, 'index': 0, 'lag': 0, 'value': None}, {'kind': 'APPLY', 'type': 'FLOAT', 'primitive': 'ABS', 'args': [9], 'source': None, 'index': 0, 'lag': 0, 'value': None}, {'kind': 'APPLY', 'type': 'FLOAT', 'primitive': 'DECAY', 'args': [6, 7, 10], 'source': None, 'index': 0, 'lag': 0, 'value': None}] outputs (0, 5, 11)
   readout [{'kind': 'REG', 'type': 'FLOAT', 'primitive': '', 'args': [], 'source': None, 'index': 2, 'lag': 0, 'value': None}]
   train    clean 0.5419 worst 0.5146 ratio 0.9496 charged WU/event 12.2222 MSSC violations ()
   heldout  clean 0.5690 worst 0.4819 ratio 0.8469 charged WU/event 12.2185 MSSC violations ('robustness',)
   h17      clean 0.6322 worst 0.6151 ratio 0.9730 charged WU/event 12.2244 MSSC violations ()
   held-out clean score vector identical to H1's: False | rank-identical: [False]
--- random draw #48 (seed 202) digest sha256:fdb7289b5dfcee2a wu/event 17 readout_wu 1 bytes 1568 agg MAX
   registers [{'type': 'INT', 'ring': 1, 'precision_bits': 64, 'init': 0}, {'type': 'INT', 'ring': 1, 'precision_bits': 64, 'init': 0}, {'type': 'FLOAT', 'ring': 1, 'precision_bits': 64, 'init': 0.0}]
   update  [{'kind': 'REG', 'type': 'INT', 'primitive': '', 'args': [], 'source': None, 'index': 0, 'lag': 0, 'value': None}, {'kind': 'APPLY', 'type': 'INT', 'primitive': 'HASH', 'args': [0], 'source': None, 'index': 0, 'lag': 0, 'value': None}, {'kind': 'APPLY', 'type': 'INT', 'primitive': 'NOT', 'args': [1], 'source': None, 'index': 0, 'lag': 0, 'value': None}, {'kind': 'REG', 'type': 'INT', 'primitive': '', 'args': [], 'source': None, 'index': 1, 'lag': 0, 'value': None}, {'kind': 'APPLY', 'type': 'INT', 'primitive': 'BIND', 'args': [2, 3], 'source': None, 'index': 0, 'lag': 0, 'value': None}, {'kind': 'CONST', 'type': 'INT', 'primitive': '', 'args': [], 'source': None, 'index': 0, 'lag': 0, 'value': 90}, {'kind': 'APPLY', 'type': 'INT', 'primitive': 'SHIFT', 'args': [5, 0], 'source': None, 'index': 0, 'lag': 0, 'value': None}, {'kind': 'INPUT', 'type': 'INT', 'primitive': '', 'args': [], 'source': 'TIME_BUCKET', 'index': 0, 'lag': 0, 'value': None}, {'kind': 'APPLY', 'type': 'INT', 'primitive': 'AND', 'args': [7, 0], 'source': None, 'index': 0, 'lag': 0, 'value': None}, {'kind': 'CONST', 'type': 'INT', 'primitive': '', 'args': [], 'source': None, 'index': 0, 'lag': 0, 'value': 63}, {'kind': 'APPLY', 'type': 'INT', 'primitive': 'OR', 'args': [8, 9], 'source': None, 'index': 0, 'lag': 0, 'value': None}, {'kind': 'APPLY', 'type': 'INT', 'primitive': 'BIND', 'args': [6, 10], 'source': None, 'index': 0, 'lag': 0, 'value': None}, {'kind': 'CONST', 'type': 'FLOAT', 'primitive': '', 'args': [], 'source': None, 'index': 0, 'lag': 0, 'value': 1.0}, {'kind': 'REG', 'type': 'FLOAT', 'primitive': '', 'args': [], 'source': None, 'index': 2, 'lag': 0, 'value': None}, {'kind': 'APPLY', 'type': 'FLOAT', 'primitive': 'SUB', 'args': [12, 13], 'source': None, 'index': 0, 'lag': 0, 'value': None}, {'kind': 'INPUT', 'type': 'FLOAT', 'primitive': '', 'args': [], 'source': 'DELTA_PHI', 'index': 0, 'lag': 0, 'value': None}, {'kind': 'APPLY', 'type': 'FLOAT', 'primitive': 'MUL', 'args': [12, 15], 'source': None, 'index': 0, 'lag': 0, 'value': None}, {'kind': 'APPLY', 'type': 'FLOAT', 'primitive': 'ADD', 'args': [14, 16], 'source': None, 'index': 0, 'lag': 0, 'value': None}, {'kind': 'APPLY', 'type': 'FLOAT', 'primitive': 'ABS', 'args': [17], 'source': None, 'index': 0, 'lag': 0, 'value': None}] outputs (4, 11, 18)
   readout [{'kind': 'REG', 'type': 'FLOAT', 'primitive': '', 'args': [], 'source': None, 'index': 2, 'lag': 0, 'value': None}]
   train    clean 0.3939 worst 0.3939 ratio 1.0000 charged WU/event 17.2222 MSSC violations ()
   heldout  clean 0.4415 worst 0.4262 ratio 0.9655 charged WU/event 17.2185 MSSC violations ()
   h17      clean 0.3719 worst 0.3719 ratio 1.0000 charged WU/event 17.2244 MSSC violations ('detection_quality',)
   held-out clean score vector identical to H1's: False | rank-identical: [False]
```

### A.8 P7: the r_min sweep over the exhaustive space

```text
$ cd <scratchpad>/s9 && PYTHONPATH=/home/anil/Documents/Research/pocketsec:. python p7_rmin.py
loadavg (2.79, 4.85, 5.77)
train steps with delta_phi < 0: 0 of 138643
held-out steps with delta_phi < 0: 0
exhaustive train WU 65576907
top 8 by train worst-case AP (no constraints):
  sha256:59a57874c8a2 DELTA_PHI[0] ['ADD'] agg MAX                 wu 3 B 1184 train worst 0.5940 clean 0.7279 ratio 0.816 | held11 worst 0.6256 | held17 worst 0.6883 | violations ('robustness',)
  sha256:2ce9743a2d72 DELTA_PHI[0] ['ABS', 'ADD'] agg MAX          wu 4 B 1192 train worst 0.5940 clean 0.7279 ratio 0.816 | held11 worst 0.6256 | held17 worst 0.6883 | violations ('robustness',)
  sha256:aa83e8ec9a2b FEATURE[90] ['ADD'] agg MAX                  wu 3 B 1184 train worst 0.5934 clean 0.7279 ratio 0.815 | held11 worst 0.6255 | held17 worst 0.6889 | violations ('robustness',)
  sha256:f60993a8da07 FEATURE[90] ['ABS', 'ADD'] agg MAX           wu 4 B 1192 train worst 0.5934 clean 0.7279 ratio 0.815 | held11 worst 0.6255 | held17 worst 0.6889 | violations ('robustness',)
  sha256:717e9f47fb54 FEATURE[73] ['MAX'] agg MAX                  wu 3 B 1184 train worst 0.5872 clean 0.5897 ratio 0.996 | held11 worst 0.5975 | held17 worst 0.5705 | violations ()
  sha256:3c824ebbad1c FEATURE[90] ['MAX'] agg MAX                  wu 3 B 1184 train worst 0.5872 clean 0.5897 ratio 0.996 | held11 worst 0.5975 | held17 worst 0.5705 | violations ()
  sha256:c7d12aa7cb91 DELTA_PHI[0] ['MAX'] agg MAX                 wu 3 B 1184 train worst 0.5872 clean 0.5897 ratio 0.996 | held11 worst 0.5975 | held17 worst 0.5705 | violations ()
  sha256:50ea61682ed0 FEATURE[73] ['ABS', 'MAX'] agg MAX           wu 4 B 1192 train worst 0.5872 clean 0.5897 ratio 0.996 | held11 worst 0.5975 | held17 worst 0.5705 | violations ()
winner selection under an r_min sweep (quality margin fixed at 0.05):
  robustness constraint removed  admissible  16/126 winner sha256:59a57874c8a2 DELTA_PHI[0] ['ADD'] agg MAX                 train worst 0.5940 held11 worst 0.6256 held17 worst 0.6883 wu 3
  r_min=0.7                      admissible  14/126 winner sha256:59a57874c8a2 DELTA_PHI[0] ['ADD'] agg MAX                 train worst 0.5940 held11 worst 0.6256 held17 worst 0.6883 wu 3
  r_min=0.8                      admissible  10/126 winner sha256:59a57874c8a2 DELTA_PHI[0] ['ADD'] agg MAX                 train worst 0.5940 held11 worst 0.6256 held17 worst 0.6883 wu 3
  r_min=0.81                     admissible  10/126 winner sha256:59a57874c8a2 DELTA_PHI[0] ['ADD'] agg MAX                 train worst 0.5940 held11 worst 0.6256 held17 worst 0.6883 wu 3
  r_min=0.82                     admissible   6/126 winner sha256:717e9f47fb54 FEATURE[73] ['MAX'] agg MAX                  train worst 0.5872 held11 worst 0.5975 held17 worst 0.5705 wu 3
  r_min=0.85                     admissible   6/126 winner sha256:717e9f47fb54 FEATURE[73] ['MAX'] agg MAX                  train worst 0.5872 held11 worst 0.5975 held17 worst 0.5705 wu 3
  r_min=0.9                      admissible   6/126 winner sha256:717e9f47fb54 FEATURE[73] ['MAX'] agg MAX                  train worst 0.5872 held11 worst 0.5975 held17 worst 0.5705 wu 3
  r_min=0.95                     admissible   6/126 winner sha256:717e9f47fb54 FEATURE[73] ['MAX'] agg MAX                  train worst 0.5872 held11 worst 0.5975 held17 worst 0.5705 wu 3
held-out beats(sum-dphi, H1, candidate_ok=True): BeatVerdict(beats=True, dimension='wu_per_event', detail='wu_per_event: 3 vs baseline 4')
held-out beats(sum-dphi, phi-oracle, candidate_ok=True): BeatVerdict(beats=True, dimension='worst_case_ap', detail='worst_case_ap: 0.6256499025914185 vs baseline 0.5975079744816587')
held-out beats(sum-dphi, H1, candidate_ok=False): BeatVerdict(beats=False, dimension=None, detail='candidate violates a hard MSSC requirement')
held-out beats(sum-dphi, phi-oracle, candidate_ok=False): BeatVerdict(beats=False, dimension=None, detail='candidate violates a hard MSSC requirement')
loadavg (3.04, 4.65, 5.67)
```

### A.9 P5: shuffled-label control on shuffled and on TRUE labels

```text
$ cd <scratchpad>/s9 && PYTHONPATH=/home/anil/Documents/Research/pocketsec:. python p5_null_power.py
loadavg (2.8, 4.37, 5.52)
EVOLUTIONARY s101 labels=SHUFFLED(9)  pick sha256:12a4d893df93 (no genome met the MSSC constraints on sh) train clean 0.3750 held-out AP 0.3148 p 0.8507 prior_pct 0.0625 verdict NULL_HELD
EVOLUTIONARY s101 labels=TRUE         pick sha256:11bc4ac279d6 (no genome met the MSSC constraints on sh) train clean 0.3834 held-out AP 0.3564 p 0.3184 prior_pct 0.9062 verdict NULL_HELD
EVOLUTIONARY s202 labels=SHUFFLED(9)  pick sha256:59418606834a (no genome met the MSSC constraints on sh) train clean 0.3853 held-out AP 0.3151 p 0.8060 prior_pct 0.1406 verdict NULL_HELD
EVOLUTIONARY s202 labels=TRUE         pick sha256:2479b6d17781 (no genome met the MSSC constraints on sh) train clean 0.4360 held-out AP 0.4435 p 0.0149 prior_pct 1.0000 verdict LEAK_SUSPECTED
EVOLUTIONARY s303 labels=SHUFFLED(9)  pick sha256:03f361b2aeca (no genome met the MSSC constraints on sh) train clean 0.3989 held-out AP 0.3289 p 0.7015 prior_pct 0.3281 verdict NULL_HELD
EVOLUTIONARY s303 labels=TRUE         pick sha256:035f06c4100e (no genome met the MSSC constraints on sh) train clean 0.4156 held-out AP 0.3923 p 0.0299 prior_pct 0.9375 verdict PRIOR_INFORMATIVE
EXHAUSTIVE   s101 labels=SHUFFLED(9)  pick sha256:3c824ebbad1c (no genome met the MSSC constraints on sh) train clean 0.3692 held-out AP 0.5975 p 0.0050 prior_pct 1.0000 verdict LEAK_SUSPECTED
EXHAUSTIVE   s101 labels=TRUE         pick sha256:717e9f47fb54 (constraint-satisfying winner) train clean 0.5897 held-out AP 0.5975 p 0.0050 prior_pct 1.0000 verdict LEAK_SUSPECTED
module run_shuffled_label_control(seed=101): NULL_HELD 0.8507462686567164 0.0625 0.3147609406724301
loadavg (3.06, 3.7, 4.92)
```

### A.10 P8: exhaustive search under 200 label shuffles

```text
$ cd <scratchpad>/s9 && PYTHONPATH=/home/anil/Documents/Research/pocketsec:. python p8_exhaustive_noise.py
loadavg (2.27, 2.67, 3.93)
TRUE labels: pick #3 sha256:717e9f47fb54 admissible=True held-out AP 0.5975
SHUFFLED x200: admissible picks 75/200; picks with held-out AP == phi-oracle's 0.5975: 9/200; held-out AP of picks: mean 0.3808 median 0.3179 min 0.2185 max 0.8111; >= 0.55: 36/200; distinct genomes picked 43
most common picks: [('sha256:9763679a', 21, 0.2931), ('sha256:31932a58', 13, 0.3537), ('sha256:5ab3cd9d', 11, 0.3927), ('sha256:152925f4', 11, 0.3352), ('sha256:fc375297', 11, 0.3129), ('sha256:afbf3119', 8, 0.2185)]
empirical p of the TRUE-label pick against the exhaustive-on-noise distribution: (1+29)/201 = 0.1493
all 126 exhaustive genomes, held-out clean AP: mean 0.3651; >= 0.55: 16/126
64 random-generator genomes (the gate's prior): mean 0.3353 max 0.4269; >= 0.55: 0/64
loadavg (2.38, 2.63, 3.84)
```

### A.11 P4: phenotypes through `run_benchmark` (fresh process, clean held-out split only)

```text
$ cd <scratchpad>/s9 && PYTHONPATH=/home/anil/Documents/Research/pocketsec:. python p4_benchmark.py found_genomes.pkl   # under /usr/bin/time -v; JSON rows omitted here, kept in results/
loadavg (1.99, 2.53, 3.78) sessions 240 transitions 17898
phi-oracle-direct-loop   PR-AUC(run_benchmark) 0.5975079744816587 stage9 AP None CPU/transition 1.737e-07 s ratio to direct loop (same run) 1.0x peak RSS 111095808 delta 299008 within_target False
phi-oracle-genome        PR-AUC(run_benchmark) 0.5975079744816587 stage9 AP 0.5975079744816587 CPU/transition 1.419e-06 s ratio to direct loop (same run) 8.2x peak RSS 111587328 delta 147456 within_target False
H1                       PR-AUC(run_benchmark) 0.7680353814606341 stage9 AP 0.7680353814606341 CPU/transition 1.522e-06 s ratio to direct loop (same run) 8.8x peak RSS 111616000 delta 0 within_target False
H2                       PR-AUC(run_benchmark) 0.8111256544502619 stage9 AP 0.8111256544502619 CPU/transition 1.831e-06 s ratio to direct loop (same run) 10.5x peak RSS 111620096 delta 0 within_target False
sum-dphi                 PR-AUC(run_benchmark) 0.7680353814606341 stage9 AP 0.7680353814606341 CPU/transition 1.454e-06 s ratio to direct loop (same run) 8.4x peak RSS 111636480 delta 0 within_target False
random-s202-winner       PR-AUC(run_benchmark) 0.44145865870766526 stage9 AP 0.44145865870766526 CPU/transition 4.504e-06 s ratio to direct loop (same run) 25.9x peak RSS 111652864 delta 12288 within_target False
	Command being timed: "python p4_benchmark.py found_genomes.pkl"
	User time (seconds): 0.64
	System time (seconds): 0.07
	Percent of CPU this job got: 99%
	Elapsed (wall clock) time (h:mm:ss or m:ss): 0:00.72
	Average shared text size (kbytes): 0
	Average unshared data size (kbytes): 0
	Average stack size (kbytes): 0
	Average total size (kbytes): 0
	Maximum resident set size (kbytes): 125116
	Average resident set size (kbytes): 0
	Major (requiring I/O) page faults: 0
	Minor (reclaiming a frame) page faults: 27539
	Voluntary context switches: 159
	Involuntary context switches: 27
	Swaps: 0
	File system inputs: 0
	File system outputs: 96
	Socket messages sent: 0
	Socket messages received: 0
	Signals delivered: 0
	Page size (bytes): 4096
	Exit status: 0
```

### A.12 P9: RSS decomposition and best-of-5 CPU ratios

```text
$ cd <scratchpad>/s9 && PYTHONPATH=/home/anil/Documents/Research/pocketsec:. python p9_rss.py split-240-s11-clean.pkl found_genomes.pkl
python only {'VmHWM': 11980800, 'VmRSS': 11980800}
after stage9 genome+phenotype imports {'VmHWM': 27336704, 'VmRSS': 27336704} modules 205 pocketsec modules 88
after loading held-out s11 clean replay split (240 sessions, 17898 transitions) {'VmHWM': 111337472, 'VmRSS': 110415872}
after scoring {'VmHWM': 111337472, 'VmRSS': 110579712} loadavg ['2.14', '2.52', '3.74']
direct               best 0.108 us/transition (CPU) worst 0.114  best-ratio to direct loop 1.0x
phi-genome           best 1.393 us/transition (CPU) worst 1.447  best-ratio to direct loop 12.9x
H1                   best 1.500 us/transition (CPU) worst 1.613  best-ratio to direct loop 13.9x
H2                   best 1.120 us/transition (CPU) worst 1.310  best-ratio to direct loop 10.3x
sum-dphi             best 1.251 us/transition (CPU) worst 1.280  best-ratio to direct loop 11.6x
random-s202-winner   best 4.082 us/transition (CPU) worst 4.230  best-ratio to direct loop 37.7x
```

### A.13 Stage 9 test files

```text
$ python -m pytest tests/test_stage9_argus.py tests/test_stage9_boundary.py tests/test_stage9_evaluation.py tests/test_stage9_gate.py tests/test_stage9_genome.py tests/test_stage9_ir.py tests/test_stage9_laws.py tests/test_stage9_physics.py tests/test_stage9_runtime.py tests/test_stage9_search.py tests/test_stage9_successor.py -p no:cacheprovider --junitxml=<scratchpad>/s9/stage9-junit.xml -rfE | tail -25
load start 2.11 2.48 3.71 3/2107 537678
2026-09-26T22:29:23+10:00
predicate = <function transitive_stage5_reach at 0x7f23962cfa00>

    @pytest.mark.parametrize("predicate", [
        b.direct_stage5_imports,
        b.transitive_stage5_reach,
        b.stage6_allow_list_offenders,
        b.admit_call_sites,
        b.stage6_writer_names,
        b.authority_field_offenders,
        b.dynamic_execution_offenders,
        b.numpy_or_research_offenders,
        b.earlier_stage_importers,
        b.outside_importers_of_stage9,
    ], ids=lambda f: f.__name__)
    def test_every_boundary_rule_holds_on_the_real_tree(predicate: Predicate) -> None:
>       assert predicate() == ()
E       AssertionError: assert ('pocketsec/s...etsec.stage5') == ()
E         
E         Left contains 4 more items, first extra item: 'pocketsec/stage9/cli.py bypassing pocketsec.stage6.capsule: pocketsec.stage9.cli -> pocketsec.stage9.gate -> pocketse...cketsec.stage9.gate_exit -> pocketsec.stage6.memory.semantic -> pocketsec.stage6.memory.procedural -> pocketsec.stage5'
E         Use -v to get more diff

tests/test_stage9_boundary.py:69: AssertionError
=========================== short test summary info ============================
FAILED tests/test_stage9_boundary.py::test_every_boundary_rule_holds_on_the_real_tree[transitive_stage5_reach]
1 failed, 377 passed in 38.20s
exit=1
2026-09-26T22:30:03+10:00
load end 2.32 2.49 3.65 3/2055 539975
```

### A.14 Explicit registration (after the gate and after the other wave's Stage 8 gate finished)

```text
$ python -m pocketsec.stage9.cli register --report results/PS-S9-20260926-H5-ontogenesis-gate-0001.json && python register_probes.py
$ python -m pocketsec.stage9.cli register --report results/PS-S9-20260926-H5-ontogenesis-gate-0001.json
registered PS-S9-20260926-H5-ontogenesis-gate-0001; gate FAILED
exit=0
$ python register_probes.py
registered PS-S9-20260926-BASE-hand-baselines-three-seeds-0001
registered PS-S9-20260926-H5-search-budget-sensitivity-0001
registered PS-S9-20260926-H5-robustness-threshold-sweep-0001
registered PS-S9-20260926-H5-random-genome-decode-0001
registered PS-S9-20260926-BASE-null-control-power-0001
registered PS-S9-20260926-BASE-exhaustive-label-noise-0001
registered PS-S9-20260926-H5-bounds-under-flood-0001
registered PS-S9-20260926-BASE-scoring-rss-timing-0001
registered PS-S9-20260926-BASE-heldout-benchmark-h1-0001
registered PS-S9-20260926-BASE-heldout-benchmark-h2-0001
registered PS-S9-20260926-BASE-heldout-benchmark-phi-oracle-direct-loop-0001
registered PS-S9-20260926-BASE-heldout-benchmark-phi-oracle-genome-0001
registered PS-S9-20260926-BASE-heldout-benchmark-random-s202-winner-0001
registered PS-S9-20260926-BASE-heldout-benchmark-sum-dphi-0001
integrity problems []
exit=0
```

# Part II — the integration session's findings (kept verbatim; Part I supersedes where they differ)


- **Date:** 2026-09-26
- **Written by:** the Stage 9 integration session, after eight work packages landed.
- **Gate:** `python -m pocketsec.stage9.cli gate` → **GATE: FAILED (6)**, exit 1. 4 of 10
  criteria pass. The verbatim output is in the integration report; every figure below was
  produced by that command or by a probe named in its row, in this session, on this host.
- **Host:** 16 GB RAM, 8 cores, shared with another wave building Stage 8. Load averages are
  printed beside every timing; timings are host-contended ratios, never device figures.

## II.1 The answer, in one paragraph

On the only split with headroom (ambiguous corpus, count 240; search on seed 3, report on seed
11), **the minimum sufficient computation Stage 9 found is the zero-parameter Φ-oracle itself.**
The 126-genome exhaustive enumeration rediscovers it by digest (`sha256:717e9f47…`: 3 WU/event,
1184 state bytes, held-out worst-case AP 0.5975, identical to its clean AP). At the same 96M
work-unit budget, evolutionary search (3 seeds) produced **no** genome that satisfies the MSSC
constraints. Random search produced one, on seed 202 (held-out worst-case AP 0.4262 at 17
WU/event), and H1 dominates it. No computation that is not already a hand baseline beats the
strongest hand rule, so §8 falsifier 1 fires. Evolutionary search is NOT-YET-JUSTIFIED: it did
not beat random or exhaustive search (ADR-0085). The prediction written before any measurement
("exhaustive enumeration ties or beats evolution") held. **This is a negative result for the
search machinery and a positive one for Stage 1's representation.**

## II.2 The ten criteria

| id | result | the number that decided it |
|---|---|---|
| G9.1 | FAIL (BLOCKED_ON_STAGE8) | Stage 8's interface (`DiscoveryPackageV1`) carries no hand-designed baseline Stage 9 may consume (ADR-0087). Rebound comparison: all four preconditions hold (Φ-oracle exact; count 240 not degenerate; shuffled null not LEAK_SUSPECTED; 0 overlap). The strongest hand rule on held-out worst case is H1 (0.6256). The only novel winner does not beat it (it is dominated). |
| G9.2 | FAIL (VACUOUS) | 0 candidate subgraphs: no main-arm run produced a winner, so there is nothing to promote. 0 laws can be promoted anyway (`cross_host=None` on one synthetic host). |
| G9.3 | PASS | 11/11 abstractions (4 coarse-grainings, 6 precision levels, minimal state) carry both tests on 80 attribution pairs, of which the original representation distinguishes 63. `precision:1` loses 38 of those 63 and AP falls 0.5975 → 0.4500. Every other level keeps AP within 0.03 and all 63 distinctions (`precision:8` changes 18.75% of held-out decisions at unchanged AP). |
| G9.4 | FAIL | 3 phenotypes measured (RSS and CPU non-None), but `is_reference_target=False`: MemTotal 16452296704 B (B9-4, ADR-0089). |
| G9.5 | PASS, with an INERT path | 140 SIMULATED decisions; every regime entered (ADAPTIVE 1, REDUCED 2, REFLEX 2, SURVIVAL 1); every degraded decision carries coverage, a loss tuple and a non-None uncertainty penalty. **The loss tuple is empty in 100 of 100 degraded decisions**: every catalog phenotype reads ΔΦ-derived inputs, so the coverage-loss path never fired. |
| G9.6 | PASS | 2 successors (the Φ-oracle rediscovery and the random-s202 winner). Install then rollback restores byte-identical held-out scores; 4/4 tamperings refused each; 16 capsules offered to a lab gateway, 16 verdicts recorded verbatim (all `UNCERTAIN`). Neither successor lowers to Stage 3 PCB. Stage 6 cannot install a genome (B9-2). |
| G9.7 | FAIL | 10 of 11 AST predicates hold, and the ledger is byte-identical. `transitive_stage5_reach` fails on the harness (`gate.py`, `gate_labs.py`, `gate_exit.py`, `cli.py`) through `stage6.memory.semantic → stage6.memory.procedural → stage5.stage6_interface`. This is a contradiction inside spec §2.3 (§7 below). |
| G9.8 | FAIL | 7 of 8 surfaces covered by a non-inert finding; every DEFENCE refused every trial. **MODEL is uncovered**: `constant_corruption` is INERT on the subject genome, the constant-free Φ-oracle. 10/10 of the fittest died under attack in each of the 3 evolutionary runs. |
| G9.9 | FAIL | 16/16 flags have a verdict, and all read `False` from code. Three are UNMEASURED: subtractive bias, QD niches and fossil avoidance. Neither the main arm nor any ablation arm produced a winner, so there was nothing to compare. |
| G9.10 | PASS | T7 clean; a child process with Stages 7-9 unimportable computes Φ-oracle held-out AP 0.5975, equal to 1e-12 to this process's figure and above the 0.3333 base rate (the finder refused 1 import); `HomeostaticController(None)` → SURVIVAL with the Φ-oracle. |

## II.3 The lead's questions, answered with measurements

**Can the language express the incumbent? (checked first)** Yes. On ambiguous count 60, seed 11,
the gate showed `phi-oracle-squashed` and `phi-oracle-raw` exact (max abs error 0.0, 60 sessions).
So are `reduced-tcn`, `order-free-control`, H1 and H2. Of 288 deterministic Stage 2 scorers,
`max_over_window` is 96/96 exact, `last_in_window` 55/96 and `mean_over_window` 46/96. The misses
are sessions where Stage 2's causal-root window and the genome's `actor_slot` lineage partition
differ (`pocketsec-stage9 expressibility`). The full Stage 2 TCN (6961 weights) is not
expressible within `MAX_CONSTANTS = 32`; that is arithmetic, not a measurement (ADR-0082).

**Saturation (lesson 11).** Count 60: Φ-oracle AP 1.0000, `stage9_saturation` degenerate
(`PHI_ORACLE_AT_CEILING`); the registered TCN evidence also reads 1.0000 there. Count 240,
held-out: Φ-oracle 0.5975, not degenerate. No count-60 figure is used as a success.

**Does evolution beat random and exhaustive at equal budget?** No (the table in §4). A probe on
seed 101 (`check_constraints` over every evaluated record) shows why nothing was admissible: all
67 random and all 72 evolutionary genomes fail the *quality* margin (train worst-case AP below
base rate + 0.05 = 0.3833); only 3 and 1 fail robustness; 30 and 43 compute a constant. The best
of either arm is the same genome (train worst-case 0.3747), drawn by the shared generator before
any variation. Evolution found no admissible genome on any of 3 seeds; its variation operators produced 0 winners
(firing count 0, INERT). Random found one on 1 of 3 seeds. Exhaustive (65,577,033 WU, under the
96,000,000 equal budget) found the Φ-oracle. Verdict NOT_YET_JUSTIFIED; the flag stays `False`.

**How many 'fittest' die under attack?** 10 of the top 10 (by clean train AP) in each of the 3
evolutionary runs: every one has a worst case below the Φ-oracle's train worst case (0.5872) or
drops more than 0.05 from clean. Attacks that fired on at least one scored genome: rename_binaries,
sensor_drop_10, lineage_table_flood, benign_duplicate_flood. INERT on at least one genome:
reorder_across_actors and timing_stretch on all four scored genomes.

**Overfitting and Goodhart.** Train-vs-held-out worst-case gap of the winners: exhaustive −0.0103,
random-s202 −0.0323 (train 0.3939 → held-out 0.4262). Both are below the 0.10 falsifier, and
held-out came out slightly *higher*. The shuffled-label search (seed 101, shuffle seed 9, the same
96M WU) found no MSSC-satisfying genome, so the control used its best-effort argmax. Train AP on
shuffled labels 0.3750, held-out AP 0.3148, permutation p = 0.8507 (170 of 200 held-out label
permutations reached the observed AP), prior percentile 0.0625 among 64 unselected random genomes.
Verdict **NULL_HELD**: the search learns nothing from shuffled labels.

**Where do the Φ-oracle and the TCN sit on the Pareto front?** On held-out count 240
(worst-case AP, WU/event, bytes): Φ-oracle (0.5975, 3, 1184), H1 (0.6256, 4, 1200) and H2
(0.5980, 3, 1192) are all on the front. The random-s202 winner (0.4262, 17, 1568) is dominated.
The TCN sits only on the count-60 plot: AP 1.0000 clean from registered evidence, 6984 WU/event
and ≥ 55,688 B *analytic*. It ties the Φ-oracle on a saturated split at about 2300x the WU.

## II.4 Search runs (main arm, controls and ablation arms)

From the gate's evidence block (`summary.evidence.runs`). All runs were on train only, at a
96,000,000 WU budget. Exhaustive spends what its 126 genomes cost.

| arm | seeds with an MSSC-satisfying winner | held-out worst-case AP of winners |
|---|---|---|
| evolutionary (main, every flag off) | 0/3 (72, 66, 61 evaluations) | — |
| random | 1/3 (s202; 67, 62, 66 evaluations) | 0.4262 |
| exhaustive | 1/1 (126 evaluations, 65,577,033 WU) | 0.5975 (the Φ-oracle, rediscovered) |
| subtractive / fossil avoidance / niches | 0/3 each (58-79 evaluations) | — (verdicts UNMEASURED) |

Every budgeted run stopped at `WORK_BUDGET_EXCEEDED` within 1,200 WU of 96,000,000. Each run took
25-34 s of host-contended wall clock. Single-architecture dominance in the niched archives: 0.74,
0.79 and 0.83 (below the 0.9 falsifier).

## II.5 Every mechanism verdict (G9.9), with its firing count

| flag | verdict this run | against | firing count | integrator's reading |
|---|---|---|---|---|
| LEARNING_LAW_SEARCH | NOT_YET_JUSTIFIED | NO_LEARNING (FP 0.0) | 15 | THRESHOLD_QUANTILE and EWMA raise drift-corpus recall 0.1481 → 0.7037 at FP 0.0, and the FP-only rule cannot credit that; the lead decides whether the rule changes (ADR-0086 note A) |
| PRIMITIVE_FOUNDRY | NOT_YET_JUSTIFIED | seed alphabet | 0 (INERT) | nothing to promote |
| RENORMALIZATION | JUSTIFIED | random drop 0.3333 | 240 representations changed, **0 scores changed** | an artefact of the subject genome, which reads only ΔΦ, so every level that keeps ΔΦ keeps its scores; flag stays `False` (ADR-0086 note C) |
| SYMMETRY_BREAKING | REJECTED | rarity 0.3333, Φ-oracle 0.5975 | 34 | removed |
| CONSERVATION | REJECTED | Φ-oracle 0.5975, H2 0.8111 | 45 | removed |
| CAUSAL_GEOMETRY | JUSTIFIED vs its spec controls (0.6672 vs pooled kNN 0.4313, Φ-oracle 0.5975) | — | 57 | loses to H2's clean held-out AP 0.8111; flag stays `False` (ADR-0086) |
| PHASE_OBSERVATORY | NOT_YET_JUSTIFIED | CUSUM 0.5863, Φ-oracle 0.5975 | 4 | off |
| MSDL_SELECTION | REJECTED | Pareto choice 0.3648 | 3 | removed |
| SURPRISE | REJECTED | novelty peak 0.3333, Φ-oracle 0.5975 | 35 | removed |
| LEARNED_FORGETTING | JUSTIFIED (EXPONENTIAL_DECAY AP 0.5830 at 72 B vs EXACT_RING 0.5583 at 128 B) | EXACT_RING | 2 | both families are rewrites that score below the unrewritten subject (0.5975 at the same 72 B), so the isolating control is missing; flag stays `False` (ADR-0086 note D) |
| EVOLUTIONARY_SEARCH | NOT_YET_JUSTIFIED | random + exhaustive | 0 (INERT) | ADR-0085 |
| SUBTRACTIVE_BIAS | UNMEASURED | no forced deletion | 0 | no arm produced a winner |
| MORPHOGENESIS | REJECTED | universal phenotype 0.6256 | 0 (INERT) | removed |
| QD_ARCHIVE | UNMEASURED | single-cell elitist | 0 | no arm produced a winner |
| FOSSIL_AVOIDANCE | UNMEASURED | no avoidance | 4 fossils avoided | no arm produced a winner |
| HYSTERESIS | NOT_YET_JUSTIFIED (transitions 17 → 9, 47% fewer against the 50% bar) | no hysteresis | 35 | off |

Every flag ships `False`, and none was switched on. Three JUSTIFIED verdicts were measured, and
§5 of ADR-0086 records why none is adopted on this evidence.

## II.6 Seams the integrator reconciled

1. `compile_drift_corpus` made public in `laplace/law_discovery.py`; `compare_learning_laws(...,
   drift=)` reuses one compiled corpus with `promotion_gate(..., drift=)`.
2. One benign-FPR cut: `law_discovery._benign_quantile_threshold` now delegates to
   `renormalization.laboratory.fpr_threshold` (the same decision, `score > t`).
   `daedalus.permute_actor_slots_reversed` is **kept** beside `symmetry.permute_actor_slots`: the
   first is a fixed non-identity relabelling the metamorphic check needs; the second samples the
   group and can be the identity on small slot sets.
3. `core_ids.flag_value` added so G9.9 reads each flag from code.
4. `ontogenesis.search.strategy_verdict`: spec §4.9's rule restored for runs without a winner
   (errata item 5); `tests/test_stage9_search.py` updated to assert it, with an added case where
   no strategy has any winner (still UNMEASURED) and a REJECTED case with a missing seed.
5. The boundary allow-list gains `SystemIdentity` for the harness, and the root `__init__.py`
   gains an `import_module` exemption for the lazy surface.
6. The G9.3 record is named `CoarseningEvidence`, because "abstraction" contains the forbidden
   fragment "action".
7. Seam requests left open, not built: the runtime package asked for `Relation` and
   `RELATION_FAMILIES` on the allow-list (coverage stays a stated lower bound); the physics
   package asked that H2 be added as a causal-geometry control (reported in §5 instead).

## II.7 Blockers and STOP conditions

- **B9-1 (Stage 8):** G9.1 blocked (ADR-0087). Stage 8's interface was read, not imported.
- **B9-2 (Stage 6 has no genome executor):** rollback is proven in Stage 9's lab registry only.
- **B9-4 (no 2 GB target):** G9.4 fails by construction on this host.
- **STOP triggered, reported and not worked around:** spec §2.3's harness grants (`genesis_state`,
  `ProvenanceLedger`, `KnowledgeLineageDAG`) reach Stage 5 without passing through `stage6.capsule`.
  Measured with `boundary`'s own import graph, the Stage 5 reach of the harness is the same 7-entry
  set as `stage6.capsule.quarantine`'s (`pocketsec.stage5`, `pocketsec.stage5.stage6_interface` and
  five of its names). The lead chooses between restating rule 2 as a subset rule and a Stage 6
  lab-gateway factory (ADR-0081 clause 5). Until then G9.7 and
  `tests/test_stage9_boundary.py::test_every_boundary_rule_holds_on_the_real_tree[transitive_stage5_reach]`
  fail.

## II.8 Other waves' failures seen in the full suite (reported, not fixed)

- `tests/test_stage1_pipeline.py::test_stage1_acceptance_gate_passes` and `::test_gate_cli_exits_zero`:
  G1.12 reads the whole pytest process's peak RSS. Collecting every test module except Stages 8
  and 9, and running only that test: 126,373,888 B against the 104,857,600 B target (fails).
  Collecting everything: 144,211,968 B. Stage 1's test alone, or with only the Stage 8 and 9
  modules collected: passes. This failure predates Stage 9 (PROGRESS.md recorded 119,095,296 B in
  the Stage 5 session).
- `tests/test_stage5_sentinel.py` ratchet (1370 > 1330 lines) and
  `tests/test_stage8_boundary.py::test_rule15_the_stage8_root_is_a_package`: other waves' files.

## II.L The integration session's own ledger (kept; superseded by the ledger at the end)

#### Integration-session measured rows
One row per number produced by running code in this session.

| claim | value | how it was produced (module:function) | experiment id | synthetic? |
|---|---|---|---|---|
| Φ-oracle AP, ambiguous count 60 seed 11 | 1.0000 (degenerate: PHI_ORACLE_AT_CEILING) | `gate_build:measure_references` | PS-S9-20260926-H5-ontogenesis-gate-0001 (not registered) | yes |
| Φ-oracle held-out AP / worst-case AP, count 240 seed 11 | 0.5975 / 0.5975 | `gate_build:measure_references`; `gate_isolation:measure_isolation` agrees to 1e-12 | same | yes |
| H1, H2 held-out worst-case AP | 0.6256, 0.5980 | `ontogenesis.fitness:evaluate` | same | yes |
| Φ-oracle IR exactness | max abs error 0.0 on 60 sessions (squashed and raw) | `genome.expressibility:check_expressibility` | same | yes |
| deterministic scorers exact | max 96/96, last 55/96, mean 46/96 | `check_expressibility` (probe) | — | yes |
| exhaustive enumeration | 126 evaluations, 65,577,033 WU, winner = Φ-oracle digest | `ontogenesis.search:run_search` | gate | yes |
| evolutionary search, seeds 101/202/303 | 0/3 MSSC-satisfying winners at 96M WU | `run_search` | gate | yes |
| random search, seeds 101/202/303 | 1/3 winners; s202 held-out worst 0.4262 at 17 WU/event | `run_search`, `heldout_report` | gate | yes |
| fittest-under-attack | 10/10 died in each of 3 evolutionary runs | `argus.adversary:fittest_die_under_attack` | gate | yes |
| successor rollback | 2/2 byte-identical; 4/4 tamperings refused each | `gate_exit:hand_over_successors` | gate | yes |
| Stage 7-9-absent Φ-oracle AP | 0.5975, equal to 1e-12 | `gate_isolation:measure_isolation` | gate | yes |
| harness Stage 5 reach vs capsule door | identical 7-entry sets | `successor.boundary` import graph (probe) | — | n/a |
| Stage 1 G1.12 in a shared pytest process | 126,373,888 B (without Stages 8/9); 144,211,968 B (all) | pytest `-k test_stage1_acceptance_gate_passes` | — | yes |
| gate wall clock (host-contended) | 14:17 at load 5.67 → 1.89 (run 1); 13:14 at load 3.07 → 4.14 (run 2, with a probe running concurrently); 14:18 at load 3.63 → 6.22 (final run, full pytest concurrent) | `time python -m pocketsec.stage9.cli gate` | — | n/a |
| interpreted phenotype vs direct Φ-oracle loop, same run | 14.7-15.1x (run 2, load 4.79); 16.5-18.3x (final run, load 6.38, full pytest concurrent) | `harness.hardware_in_loop:measure_phenotype` | gate | yes |
| shuffled-label control | NULL_HELD, p = 0.8507, prior percentile 0.0625 | `ontogenesis.search:run_shuffled_label_control` | gate | yes |
| why random/evolution found nothing (seed 101 probe) | 67/67 and 72/72 fail the quality margin; 30 and 43 constant-output | `spec.mssc:check_constraints` over `SearchRun.records` | — | yes |

#### Integration-session unmeasured rows
| claim the architecture makes | why not measured | what would measure it | blocking? |
|---|---|---|---|
| a Stage-9 computation beats Stage 8's hand-designed baseline | Stage 8 exposes none Stage 9 may consume | a frozen Stage 8 baseline interface | yes (G9.1) |
| 2 GB target resource data | this host has 16 GB | a 2 GB reference machine | yes (G9.4) |
| subtractive bias, QD niches, fossil avoidance | no arm produced an MSSC-satisfying winner | a larger budget, or looser (re-decided) constraints | yes (G9.9) |
| cross-host laws | one synthetic host | a second host | no (G9.2 blocks earlier) |
| calibration (`k_min`) | no calibrator exists | a calibrated score | no |
| wall-clock latency on a device | host-contended | a quiet reference device | no |
| LightGBM, GRU/LSTM, tiny transformer, NAS, Isolation Forest, HDC/VSA as a model | third-party or numpy tooling barred (ADR-0080) | a research package (needs ADR-0011, which was never written) | no |

#### Integration-session rejected rows
| component | measured effect | verdict | ADR |
|---|---|---|---|
| evolutionary search (GENESIS + GAIA) | 0/3 admissible winners against exhaustive's Φ-oracle at equal budget | NOT-YET-JUSTIFIED | 0085 |
| symmetry-breaking score | 0.3583 against Φ-oracle 0.5975 | REJECTED | 0086 |
| conservation / Noether heuristic | 0.5975 against H2 0.8111 | REJECTED | 0086 |
| MSDL selection | 0.3333 against Pareto choice 0.3648 | REJECTED | 0086 |
| algorithmic / probabilistic surprise | 0.3636 against Φ-oracle 0.5975 | REJECTED | 0086 |
| morphogenesis / speciation | no niche gained over the universal phenotype | REJECTED | 0086 |
| causal geometry | JUSTIFIED against its spec controls, loses to H2 by 0.14 | NOT ADOPTED | 0086 |
| renormalization | JUSTIFIED, but an artefact of a ΔΦ-only subject | NOT ADOPTED | 0086 |
| learned forgetting | JUSTIFIED on one genome, corpus and seed | NOT ADOPTED pending reproduction | 0086 |

#### Integration-session retracted rows
| retracted claim | where it was published | the defect | corrected value |
|---|---|---|---|
| "§8 falsifier 1 does not fire: a search winner beats the strongest hand rule" | first full gate run of this session (G9.1 detail) | the "winner" was the Φ-oracle genome rediscovered by exhaustive search; it "beat" H1 only on WU (3 vs 4) | falsifier 1 fires for novel computations; the check now names rediscoveries |
| "strategy verdict UNMEASURED" for evolution | the search package's preview | spec §4.9 has no UNMEASURED branch for a missing winner | NOT_YET_JUSTIFIED (ADR-0085) |

#### Integration session: not a detection result
Every corpus in this stage is synthetic and project-authored: Stage 1's ambiguous corpus, its
ARGUS-attacked variants, the attribution-counterfactual pairs and Stage 2's drift corpus. The
headroom split's label is the generator's own attribution rule, which H1 and H2 restate (author
confound, ADR-0084). Nothing here says anything about detection on real telemetry, and nothing
here was deployed: every output is a candidate, and Stage 6 cannot install one (B9-2).

## Honesty ledger

Figures below were produced by running code in the measurement-engineer session (2026-09-26).
The integration session's own ledger is kept verbatim in Part II (§II.L). Probe scripts live in
the session scratchpad. Their verbatim output is in Appendix A and in `results/<id>.json`, and
their ledger rows are the ids below. Seeds: corpus train 3, held-out 11, extra held-out 17;
search 101/202/303.

### MEASURED
| claim | value | how it was produced (module:function) | experiment id | synthetic? |
|---|---|---|---|---|
| gate verdict | FAILED (6); PASS G9.3 G9.5 G9.6 G9.10; 20:19.73 wall, 1017.29 s user, max RSS 1,514,296 kB, load 3.37 → 7.56 | `python -m pocketsec.stage9.cli gate` (`stage9.gate:build_context`) under `/usr/bin/time -v` | PS-S9-20260926-H5-ontogenesis-gate-0001 | yes |
| search determinism across processes | 6/6 digests equal (gate vs P2) | `ontogenesis.search:run_search` | gate + PS-S9-20260926-H5-search-budget-sensitivity-0001 | yes |
| hand baselines, held-out worst-case AP s11 / s17 | Φ 0.5975 / 0.5705; H1 0.6256 / 0.6883; H2 0.5980 / 0.5454; order-free 0.3057 / 0.2997 | `ontogenesis.fitness:evaluate` | PS-S9-20260926-BASE-hand-baselines-three-seeds-0001 | yes |
| charged vs static WU/event (s3) | Φ 3.2222 vs 3; H1 4.2222 vs 4; H2 3.4443 vs 3 | `WorkMeter.spent / EvaluationSuite.events_total` | same | yes |
| evolution vs random at 1x | 0/3 vs 1/3 admissible winners; improved_archive 0 for all 13 operators | `run_search` | PS-S9-20260926-H5-search-budget-sensitivity-0001 | yes |
| evolution vs random at 4x | winners held-out worst 0.3328/0.3149/0.3937 vs 0.4819/0.3628/0.4819; `strategy_verdict` REJECTED (median −0.0882 vs random, −0.2647 vs exhaustive) | `run_search`, `strategy_verdict` | same | yes |
| evolution vs random at 16x (s101) | 0.3376 vs 0.4819 held-out worst | `run_search` | same | yes |
| INERT operators | MOVE, MACRO_INSERT: 0 valid children in every run (1x/4x/16x) | `OperatorStats` | same | yes |
| r_min decides the exhaustive winner | Σ ΔΦ for r_min ≤ 0.81 or removed (held-out worst 0.6256 / s17 0.6883); Φ-oracle for r_min ≥ 0.82 (0.5975 / 0.5705) | `enumerate_exhaustive`, `evaluate`, `spec.mssc:check_constraints` | PS-S9-20260926-H5-robustness-threshold-sweep-0001 | yes |
| ΔΦ sign | 0 of 138,643 train steps negative; 0 held-out | direct scan of `EncodedTransition.delta_phi` | same | yes |
| Σ ΔΦ ≡ H1 | held-out clean score vectors identical; 3 vs 4 static WU/event; 1.251 vs 1.500 µs/transition (same run, load 2.1) | `fitness:session_scores`; P9 timing | PS-S9-20260926-H5-random-genome-decode-0001, PS-S9-20260926-BASE-scoring-rss-timing-0001 | yes |
| null control power (gate procedure on TRUE labels, s101) | held-out 0.3564, p 0.3184, NULL_HELD | re-implementation of `run_shuffled_label_control` with labels unshuffled | PS-S9-20260926-BASE-null-control-power-0001 | yes |
| exhaustive on shuffled labels (shuffle 9) | picks `features[90]` MAX, held-out 0.5975, p 0.0050 | same | same | yes |
| exhaustive-on-noise distribution | 200 shuffles: held-out mean 0.3808; 29/200 ≥ 0.5975; p of the true-label pick = 0.1493; 16/126 genomes ≥ 0.55 vs 0/64 random-generator genomes | `enumerate_exhaustive` + `EvaluationSuite.with_shuffled_labels` + stage0 `average_precision` | PS-S9-20260926-BASE-exhaustive-label-noise-0001 | yes |
| bounds under 10x flood | phenotype real peak 28,936-34,128 B flat to 65,536 events; cache 4096/40,960 (36,864 evicted); fossils 2048/20,480; archive bound 5040/5040; records 8192 (`RECORD_BOUND`); population evictions 8128 | `Phenotype.run_session`, `EvaluationCache`, `FossilStore`, `gaia.qd_ecology:hypothesis_explosion`, `run_search` + tracemalloc | PS-S9-20260926-H5-bounds-under-flood-0001 | yes (synthetic events) |
| PR-AUC via `run_benchmark` equals Stage 9 AP | 6/6 slots equal (Φ 0.5975, H1 0.7680, H2 0.8111, Σ ΔΦ 0.7680, random-s202 winner 0.4415) | `stage0.benchmark.harness:run_benchmark` | PS-S9-20260926-BASE-heldout-benchmark-{phi-oracle-direct-loop,phi-oracle-genome,h1,h2,sum-dphi,random-s202-winner}-0001 | yes |
| Edge envelope of the scoring process | exceeded: agent_rss 106.4 MB > 100 MB; peak sampled 111,587,328 B | `run_benchmark` → `profiles:check_profile` | same | yes |
| RSS decomposition | Python 11,980,800 → imports 27,336,704 → replay split 111,337,472 B; scoring delta ≤ 299,008 B | `/proc/self/status` VmRSS/VmHWM | PS-S9-20260926-BASE-scoring-rss-timing-0001 | yes |
| interpreter vs direct Φ loop, same run | 8.2-12.9x (load 2.0-2.1); gate HIL 13.4-23.9x (load 7.96) | P4/P9 `time.process_time`; `harness.hardware_in_loop:measure_phenotype` | same; gate | yes |
| Stage 9 tests | 378 collected, 377 passed, 1 failed (`transitive_stage5_reach`); 38.2 s, load 2.11 → 2.32 | `pytest tests/test_stage9_*.py --junitxml` | — | n/a |

### UNMEASURED
| claim the architecture makes | why not measured | what would measure it | blocking? |
|---|---|---|---|
| resource cost on a 2 GB target | this host has 16,452,296,704 B | a 2 GB reference machine | yes (G9.4) |
| endpoint RSS of a streaming phenotype | no streaming replay harness exists; the measured process holds the whole split | a streaming slot fed one session at a time, run through `run_benchmark` | no |
| a Stage 9 computation beats Stage 8's hand-designed baseline | Stage 8's interface carries none Stage 9 may consume | a frozen Stage 8 baseline interface | yes (G9.1) |
| subtractive bias, QD niches benefit | no arm produced a winner at the gate's budget; not re-run at 4x | the two ablation arms at 4x, seed-matched (fossil avoidance is REJECTED as INERT by construction, Part R) | yes (G9.9) |
| evolution vs random at 16x on seeds 202 and 303 | time: one seed only | two more 1.5B-WU runs per strategy | no |
| calibration (`k_min`) | no calibrator exists | a calibrated score | no |
| full-repository test suite | another wave's full pytest and Stage 8 gate were running | a quiet host | no |
| LightGBM, GRU/LSTM, transformer, NAS, HDC/VSA baselines | third-party or numpy tooling is barred in Stage 9 (ADR-0080) | a research package approved by the lead | no |
| detection quality on real telemetry | every corpus is synthetic | real telemetry | yes (for any detection claim) |

### REJECTED
| component | measured effect | verdict (REJECTED / NOT-YET-JUSTIFIED / RETRACTED) | ADR |
|---|---|---|---|
| Stage 9 central claim (search is worth its complexity) | only exhaustive enumeration of an author-designed space finds the answer, and it does so on shuffled labels in 29 of 200 shuffles (14.5%); evolution loses to random | REJECTED on this corpus | ADR-0085 addenda A, B |
| evolutionary search (GENESIS + GAIA) | 1x: 0/3 winners; 4x: −0.0882 median vs random, −0.2647 vs exhaustive; 16x s101: 0.3376 vs 0.4819 | REJECTED (4x sensitivity); NOT-YET-JUSTIFIED at the gate's budget | ADR-0085 addendum A |
| `MOVE`, `MACRO_INSERT` operators | 0 valid children in every run | REJECTED (INERT) | ADR-0085 addendum A |
| MSSC robustness ratio `r_min = 0.85` | alone flips the exhaustive answer between 0.81 and 0.82; refuses genomes with a higher worst case | NOT-YET-JUSTIFIED (the lead decides) | ADR-0083 addendum A |
| shuffled-label control as implemented | NULL_HELD on TRUE labels at the gate's seed (p 0.3184) | NOT-YET-JUSTIFIED as a control | ADR-0083 addendum A |
| subtractive bias, fossil avoidance, QD niches | never exercised to an outcome | NOT-YET-JUSTIFIED | ADR-0085 |
| symmetry, conservation, MSDL, surprise, morphogenesis | see §3.9 | REJECTED | ADR-0086 |
| causal geometry, renormalization, learned forgetting | JUSTIFIED vs spec controls, lose to H2/H1 or lack an isolating control | NOT ADOPTED | ADR-0086 |

### RETRACTED
| retracted claim | where it was published | the defect | corrected value |
|---|---|---|---|
| "the minimum sufficient computation Stage 9 found is the zero-parameter Φ-oracle itself" (unqualified) | Part II §II.1; ADR-0085 decision 1; MEMORY.md "Durable Stage 9 facts" (not edited by this session) | decided by the chosen `r_min = 0.85`; the top 4 exhaustive genomes by train worst case are refused by that ratio alone | Φ-oracle under r_min ≥ 0.82; Σ ΔΦ (≡ H1, 3 WU, held-out worst 0.6256 / s17 0.6883) under r_min ≤ 0.81 |
| "exhaustive enumeration rediscovers the Φ-oracle" read as evidence that search discovers it | Part II §II.1, §II.3; ADR-0085 title | the same enumeration on shuffled labels reaches the same held-out AP in 29/200 shuffles | p = 0.1493 against its own label-noise distribution: not significant |
| "Verdict NULL_HELD: the search learns nothing from shuffled labels" as an overfitting guard | Part II §II.3 | the procedure has no power at seed 101 (NULL_HELD on TRUE labels, p 0.3184) | uninformative at the gate's seed |
| "the binding constraint is quality, not robustness" | ADR-0085 context | true for random/evolution records at 1x only | for the exhaustive answer the binding constraint is robustness |
| "§8 falsifier 1 does not fire: a search winner beats the strongest hand rule" | first gate run of the integration session (retracted there; lineage kept) | a rediscovered hand baseline | unchanged: see Part II |
| "strategy verdict UNMEASURED" for evolution | the search package's preview (retracted there) | spec §4.9 has no UNMEASURED branch | NOT_YET_JUSTIFIED at 1x; REJECTED at 4x |
| "10/10 of the fittest die under attack in each evolutionary run" as evidence about the attacks | §2 table, A.1 G9.8 detail, Part II §II.2/§II.3/§II.L | the rule also killed every genome already below the Φ-oracle on clean data; 10/10 die with no attack | attack-induced 3/10, 6/10, 1/10 (Part R.2) |
| FOSSIL_AVOIDANCE "fired 4", and its benefit listed as UNMEASURED | A.1 G9.9 detail, §3.9, Part II §II.5 | "fired" counted skipped genomes; the skip cannot change an outcome | fired 0, REJECTED (INERT) (Part R.2) |
| "cut by the bound, with the bound recorded" as a safe property of the event cap | §3.7, ADR-0082 | the cut kept the head and returned a confident score: a padding evasion | the session abstains (ADR-0082 addendum A) |
| G9.6 "install then rollback restores byte-identical held-out scores" as proof for both successors | Part II §II.2 | for the Φ-oracle successor, installed = parent, so equality holds with no rollback | proven for the random-s202 successor only (Part R.2) |
| §3.5 "(significant, above prior)" and "(Φ-oracle)" | §3.5 table | the code emitted LEAK_SUSPECTED for both | corrected in place |

### NOT A DETECTION RESULT
Every corpus here is synthetic and project-authored: Stage 1's ambiguous corpus (count 240,
seeds 3/11/17), its ARGUS-attacked variants (attacks authored by Stage 9), the flood events of
P3, and the attribution-counterfactual pairs. The headroom split's label is the generator's own
attribution rule. H1, H2 and the seven exhaustive inputs were chosen after reading that rule
(author confound, ADR-0084), and §3.6 measures how much of the "discovery" that choice explains.
Nothing here says anything about detection on real telemetry, and nothing was deployed.
