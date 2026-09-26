# ADR-0078 — ORACLE (EIG) verdict against RANDOM/CHEAPEST/no-ORACLE; ecology, priority, doppelgänger and negative-memory verdicts; ORACLE prunes are FOSSILIZED

- **Status:** Accepted (written from measurement; the figures are the gate run recorded in `docs/stage-8-findings.md` §M.4)
- **Date:** 2026-09-26
- **Stage:** 8
- **Deciders:** Stage 8 integrator
- **Supersedes / superseded by:** amends spec D8.6's "pruned → ledger CHALLENGED_OUT"

> Measured-verdict ADR plus one seam decision made in the integration session.

## Context

1. Spec D8.6 says an ORACLE prune (posterior < 0.01) sets the theory `CHALLENGED_OUT` with reason
   `oracle_posterior`. The integrity package's ledger admits `CHALLENGED_OUT` only after a failed
   preregistered `CHALLENGE_RESULT`, and no `FalsifierKind` names a posterior. As built, every
   prune was refused by the ledger, the theory stayed PROPOSED, was registered anyway, and
   ORACLE could change no outcome (measured before the fix, PLANTED seed 0 full size: 41
   registered, 21 HOLDOUT-falsified; the oracle builder measured 4/4 prunes refused).
2. Lesson 1: a component that never changes an outcome is INERT.

## Decision

1. **An ORACLE prune retires the theory `FOSSILIZED` with reason `oracle_posterior`.** It is never
   registered; it is not filed as refuted (FOSSILIZED is not a dead end for negative memory), because
   a posterior over replay experiments is not a preregistered falsifier. Measured after the fix,
   same run: 34 registered, 14 HOLDOUT-falsified, 19 REPRODUCED (unchanged) — the prune removed 7
   theories the vault would have spent on and killed.
2. The component verdicts are the ablation rows G8.12 prints on the full gate run (one row per
   OPTIONAL flag, with firings and outcome changes), copied into the findings. A row that is INERT,
   HARMFUL or NOT_YET_JUSTIFIED is a recommendation to remove or default-off that component; this
   ADR does not flip defaults on one synthetic world.

## Options considered

| Option | Security cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|
| A. Keep refusing prunes (status PROPOSED) | none | none | ORACLE changed no registration (41 registered) | INERT by construction |
| B. File the prune as CHALLENGED_OUT under another falsifier's name | a false ledger record | low | not done | dishonest |
| C. Add an ORACLE FalsifierKind | a foundation contract change after Build | medium | not done | the genome vocabulary is frozen with the Stage 9 interface |
| **D. FOSSILIZED with reason `oracle_posterior` (chosen)** | none | trivial | 34 registered, 14 falsified, 19 reproduced | — |

## Consequences

**Accepted costs.** A pruned mechanism can be proposed again in a later cycle (not a dead end).

**Bounded state / Reversibility / Authority.** None changed.

## Verification

`tests/test_stage8_oracle.py::_assert_prune_on_record`, G8.12 ablation rows `oracle`, `cost_aware`, `eig`.

## Prior art

No novelty claim.

## Amendment 2026-09-27 — measurement session: ORACLE crash defect; generators and ecology default-off recommended

- **Status of this amendment:** Accepted (figures and commands in `docs/stage-8-findings.md`
  §M.3, §M.5, §M.9 and Appendix A). The text above is kept unchanged; block 0070–0079 is full, so
  this is an amendment, not a new ADR.

### What was measured

1. **ORACLE aborts the research run.** `Posterior.restricted` (`oracle/information_gain.py`)
   raises `ContractError("restricting a posterior must keep some probability mass")` when one
   experiment eliminates every live hypothesis. `OraclePlanner._execute` does not guard it, and
   `labs/discovery_run.py:_execute` catches only `WorkBudgetExceeded`. The error fired in 10 of 39
   random-generator runs; it did not fire in the 9 default PROMETHEUS runs. Deterministic repro: `PYTHONHASHSEED=0 python benchmarks/stage8/oracle_crash_repro.py`.
2. **ORACLE comparison, re-run:** on replay (the production default) EIG_PER_COST, EIG_ONLY, RANDOM and
   CHEAPEST all lead with the wrong theory on 3/3 seeds, and EIG_PER_COST spends exactly CHEAPEST's
   work units (43 252, 27 135, 30 080). With the authored lab oracle, EIG leads correctly on 3/3 while
   RANDOM and CHEAPEST stop at their budget. The verdict is NOT_YET_JUSTIFIED; F8 fires on replay.
3. **The ablation, re-run, is identical to the gate's:** 1 JUSTIFIED (`holdout_discipline`),
   7 NOT_YET_JUSTIFIED, 9 INERT.
4. **The joint control.** SYMBOLIC_ENUMERATOR alone, with diversity, MDL, evolution, ORACLE and
   negative memory off, SIZE_ONLY priority and FIT_ONLY score, recovers the same planted family on
   every run (7/7: content 0 × runs 0–2, content 1 × run 0, content 2 × runs 0–2) at 0.73–0.76× PROMETHEUS's work
   units. No single-flag row could show this.
5. **The doppelgänger screen's value depends on its feed:** it changes no family in PROMETHEUS, but
   in the brute-force engine it decides everything (7/7 runs recover the family with the screen, 0/7 without).

### Decision

- **ORACLE is recommended default-off** until (a) an all-eliminated posterior ends in an
  UNIDENTIFIABLE/INSUFFICIENT_EVIDENCE stop instead of an exception (owner's fix; not made in the
  measurement session) and (b) EIG beats RANDOM/CHEAPEST on replay.
- **SYMBOLIC_ENUMERATOR is the only generator with a measured role.** RESIDUAL_MOTIF, ANALOGY,
  NULL_BENIGN, STAGE7_SEED and EXTERNAL_PROPOSAL, and the diversity, MDL, mutation, full-score,
  priority-field and negative-memory terms, are recommended default-off. The INERT rows are
  candidates for removal.
- The doppelgänger screen, the counterfactual-invariance screen and the vault stay on: they carry
  the trap kill and the brute-force result.
- Defaults are not flipped in this session (a measurement session changes no code paths). The lead
  decides.

### Options considered (amendment)

| Option | Security cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|
| A. Keep every component on | ~30 % more work units, one crash path | high | no family gained over ENUM_MIN | not justified |
| **B. Recommend enumerator-only defaults, ORACLE off until fixed (chosen)** | none measured | lower | same families at 0.73–0.76× the work units | — |
| C. Catch the ORACLE exception in the harness and continue | hides a defect as a silent skip | trivial | not done | would turn a crash into an unmeasured stop |

## Amendment 2 2026-09-27 — fix wave: the crash's real cause, relative pruning, ORACLE default-off; the score's screen terms

- **Status of this amendment:** Accepted (code and regression tests in this wave; §F of
  `docs/stage-8-findings.md`). The text above is kept; block 0070–0079 is full.

### What was found (F2, S8-RES-2, F3)

1. **The crash was misdiagnosed.** It was not "an experiment eliminates every live hypothesis".
   `PRUNE_POSTERIOR` = 0.01 was an absolute floor; in a cluster group of n > 100 theories a
   near-uniform posterior puts every theory under it (the reviewer's instrumented repro: n = 129,
   max 0.00781). `_execute` wrote FOSSILIZED for all 129, then `Posterior.restricted([])` raised,
   leaving 129 theories fossilized with no evidence against any, and the run returned no report.
2. **Two TheoryScore terms were INERT (F3).** Scores were cached before the screens wrote any
   CHALLENGE_RESULT, so at `rank()` falsification survival and adversarial fragility read
   (0.0, 0.0) for every candidate while the ledger said (1.0, 1 − invariance). Reproduced on the
   pre-fix tree by `tests/test_stage8_regressions.py::test_f3_rank_reads_the_screens_that_ran`:
   cached `(0.0, 0.0)` vs ledger `(1.0, 0.0)`.

### Decision

1. A theory is pruned when its posterior is under `PRUNE_POSTERIOR` × the leader's. The leader is
   always kept, so the restriction is never empty; the restricted posterior is built **before**
   any FOSSILIZED is written. The repo's crash config
   (`benchmarks/stage8/oracle_crash_repro.py`, ORACLE on) now completes: groups of 56 and 129,
   stops `no_experiments` and `observationally_equivalent`, 1 theory pruned, 64 registered
   (this session, loadavg 3.4).
2. **ORACLE is default-off** (`RunConfig.oracle_policy = None`): condition (b) of amendment 1
   (EIG beats RANDOM/CHEAPEST on replay) is still unmet. The gate turns it on explicitly for the
   runs that test ORACLE's own properties (lab-on, DROPOUT), and the ablation measures each
   ORACLE flag from an all-on base (`baselines.ablation_base`), so the rows stay measurable.
3. `HypothesisPopulation.refresh_screen_terms` re-reads the two ledger-backed terms after the
   screens run (TRAIN terms kept, nothing re-charged). Every genome that reaches `rank()` passed
   every screen, so survival is 1.0 for all of them and cannot reorder them; the fragility term
   now charges invariance agreement below 1.0.

### Options considered (amendment 2)

| Option | Security cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|
| A. Map the empty posterior to an UNIDENTIFIABLE stop (amendment 1's proposal) | 129 theories fossilized with no evidence | low | not done | keeps the wrong ledger state |
| **B. Relative prune, restrict before writing, default-off (chosen)** | none | low | repro completes, 1 pruned of 185 | — |

## Verification (amendment 2)

`tests/test_stage8_regressions.py::test_f2_s8_res_2_*`, `test_f2_oracle_is_default_off`,
`test_f3_rank_reads_the_screens_that_ran`.
