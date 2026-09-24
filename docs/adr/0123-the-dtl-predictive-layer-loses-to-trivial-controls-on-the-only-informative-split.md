# ADR-0123 — The DTL predictive layer loses to trivial controls on the only non-degenerate split

- **Status:** Proposed
- **Date:** 2026-09-25
- **Stage:** 2
- **Deciders:** Stage 2 measurement wave (measurement engineer)
- **Supersedes:** nothing. **Extends:** ADR-0009 and ADR-0010 (the recurrent core is
  rejected; the Stage 2 core is a TCN), ADR-0115 (Behaviour Atoms rejected), ADR-0116
  (Future Cone and hazard rejected), ADR-0119 (runtime multiscale state is a bounded
  window), ADR-0120 (corpus degeneracy guard), ADR-0122 (counterfactual credit rejected).
- **Partially supersedes:** one summary sentence of ADR-0120 — see *Consequences*.

## Context

ADR-0009 flagged three Stage 2 components as `NOT_YET_JUSTIFIED` rather than rejected,
because the corpora they were measured on were saturated and *a task solved at 1.0000
cannot show that any component helps*. ADR-0120 then built a four-condition degeneracy
guard and concluded that on the corpora this repository has, the guard refuses — leaving
nine of the thirteen specification §5 rows `UNMEASURABLE` and Stage 2's component
justification genuinely undecided rather than negative.

**That conclusion was drawn without running `saturation_check` across the full corpus ×
size grid.** ADR-0120 measured the Φ-oracle alone at count=240, and ran the full suite only
at `ambiguous`/30 and `hard`/6. This session ran all nine cells.

```
PYTHONPATH=/home/anil/Documents/Research/pocketsec PYTHONHASHSEED=0 python3 sweep.py
```

| corpus | count | base | best | median | spread | order-free | Φ-oracle | degenerate | reason |
|---|---|---|---|---|---|---|---|---|---|
| ambiguous | 60 | 0.3333 | 1.0000 | 0.6586 | 0.3414 | 1.0000 | 1.0000 | True | ORDER_FREE_BASELINE_TIES_BEST |
| ambiguous | 120 | 0.3333 | 1.0000 | 0.8475 | 0.1525 | 1.0000 | 0.8495 | True | ORDER_FREE_BASELINE_TIES_BEST |
| **ambiguous** | **240** | **0.3333** | **1.0000** | **0.9125** | **0.0875** | **0.9125** | **0.5975** | **False** | **INFORMATIVE** |
| hard | 60/120/240 | — | ≥0.9902 | — | ≤0.0064 | ties best | ≤0.8436 | True | DEGENERATE_SPREAD |
| long | 60/120/240 | 0.3333 | 1.0000 | ≈0.334 | ≈0.66 | ≈0.334 | ≈0.317 | True | BASELINE_BELOW_BASE_RATE |

**One cell is informative**, by the guard's own thresholds, fixed in code before this
measurement and pinned by
`tests/test_stage2_report.py::test_every_degeneracy_condition_is_enforced_at_its_stated_threshold`.
That makes a component ablation with headroom possible for the first time, and
`build_report(count=240)` therefore records measured deltas instead of `UNMEASURABLE`.

Repeating the guard at count=240 across eval seeds 11/17/23/29 gives **INFORMATIVE on three
of four**; seed 23 is refused because `markov-bigram` scores 0.3307 against a base rate of
0.3333, a margin of 0.0026. In all four seeds `gru` and `tcn` tie at exactly 1.0000 and the
Φ-oracle sits in 0.5886 – 0.5975.

## Decision

**Record the measured verdicts, and resolve the outstanding `NOT_YET_JUSTIFIED` flags in
the direction the measurement points: against the mechanisms.**

`pocketsec.stage2.research.cli report --count 240`
(`ambiguous`, train seed=3, test seed=11, encoder `dtl-encoder.1.0.0`, 17,595/17,898
transitions, base rate 0.3333, `synthetic_data: true`, ≈68 min wall at load average 11–21):

| verdict | component | metric | with | without | delta | control |
|---|---|---|---|---|---|---|
| REJECTED | behaviour_atom_quantizer | transition_log_loss | 3.5881 | 1.8460 | −1.7420 | HashBucketQuantizer |
| **REJECTED** | **transition_lattice** | next_family_top1 | 0.4367 | 0.4926 | **−0.0558** | relation_family_bigram |
| NOT_YET_JUSTIFIED | merge_fission | log_loss_per_kib | 0.0042 | 0.0042 | −0.0000 | max_macro=0 |
| JUSTIFIED* | future_cone | branch_brier | 1.5548 | 1.8660 | +0.3112 | marginal_cone |
| REJECTED | hazard_heads | hazard_brier | 0.1631 | 0.0768 | −0.0862 | constant_hazard |
| **REJECTED** | **uncertainty** | expected_calibration_error | 0.5904 | 0.5739 | **−0.0165** | one_minus_max |
| **NOT_YET_JUSTIFIED** | **multiscale_window** | next_family_top1 | 0.4928 | 0.4926 | **+0.0002** | window=1 |
| NOT_YET_JUSTIFIED | transition_cache | hit_rate | 0.0136 | 0.0136 | 0.0000 | lru_control |
| NOT_YET_JUSTIFIED | utility_forgetting | hit_rate | 0.0136 | 0.0136 | 0.0000 | lru/random |
| JUSTIFIED | epoch_guard | malicious_patterns_normalised | 0 | 377 | +377 | accept_everything |
| JUSTIFIED | quarantine_promotion | poisoned_promotions | 0 | 64 | +64 | accept_everything |
| REJECTED | causal_credit | chain_recall | 0.0000 | 1.0000 | −1.0000 | naive_ancestry |
| UNMEASURABLE | compile_candidate_export | µs/event | None | None | None | phi_oracle |

Three decisions follow.

**1. The transition lattice is rejected.** It predicts the next `relation_family` *worse
than an order-1 bigram* (0.4367 vs 0.4926). The structure Stage 2 is named after loses to
counting pairs. `DTL-F13`/`DTL-F14` keep no ablation-supported reason to exist.

**2. D2.9's calibrated uncertainty is rejected as a detection-side improvement.** Its ECE is
worse than `1 − max p` (0.5904 vs 0.5739). ADR-0117's `calibration_id` remains correct and
valuable — Stage 2 ships a real identity where Stage 1 honestly ships `None` — but the
*module* does not beat the one-line control, and G2.5 independently fails on conformal
coverage (0.9793 against nominal 0.9 ± 0.05 over 4,297 edges).

**3. `DTL-F03` (runtime multiscale window) stays NOT-YET-JUSTIFIED and must default to
`window=1` unless a future measurement moves it.** +0.0002 against remembering only the most
recent transition is not a reason to keep per-lineage multiscale state. ADR-0119's *shape*
decision (a bounded window, not recurrence) is untouched and correct; what is now measured
is that the window's depth buys nothing.

***`future_cone` is the one JUSTIFIED learned row, and this ADR does not promote it.**
`multiclass_brier` has a maximum of 2.0 and both predictors sit near it. Measured this
session on the same split, at `max_depth=1`:

```
contexts scored              4000
mean cone unresolved mass    0.646407
cone argmax is UNKNOWN       0/4000 = 0.0000
```

The cone holds 64.6% of its mass on `UNKNOWN` — never the observed label — while still
always naming a concrete branch as argmax. Its advantage is being *less confidently wrong*
than a control that is more confidently wrong. ADR-0116's rejection stands and
`FUTURE_CONE_DEFAULT_ENABLED = False` remains correct.

## Options considered

| Option | Security cost | Resource cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|---|
| **A. Keep every flag at NOT_YET_JUSTIFIED pending real telemetry** | Eleven unjustified mechanisms stay live for a later stage to trust | Carries 1.05 MB of model bytes and a 25.36× lattice lookup on every event | none | **Measured: a headroom-bearing split now exists and five components lose to trivial controls on it.** "Not yet measured" is no longer true for those five | Rejected. It was the right call under ADR-0009; the measurement it was waiting for has now been taken |
| **B. Reject everything the table does not mark JUSTIFIED** | Would remove `epoch_guard`/`quarantine_promotion`-adjacent machinery on a metric that cannot show benefit | Lowest | low | **Measured: `merge_fission`, `multiscale_window`, `transition_cache`, `utility_forgetting` all sit at \|delta\| ≤ 0.0002 — indistinguishable from zero, not demonstrably harmful** | Rejected. A null result is not a negative result, and ADR-0009 exists because this repository once collapsed the two |
| **C. Reject the three that lose to a control; hold the four nulls (chosen)** | None. Every rejected component is default-off or removed; nothing gains authority | Removes the 25.36×-cost lattice lookup from the justified set | moderate | **Measured: −0.0558, −0.0165, −0.0862 against bigram / `1−max p` / constant are losses, not nulls; +0.0002 and 0.0000 are nulls** | Chosen | — |
| **D. Raise `GATE_COUNT` to 240 so the gate measures on the informative split** | The gate would report PASS on G2.1 while the frontier is flat at 1.0000 (see *Consequences*) | An ~68-minute report becomes a gate precondition | high | **Measured: at count=240 the latent frontier is 1.0000 at every dimension 12→96, knee = 12, the smallest tried** | Rejected. A criterion-1 PASS earned on a split with no headroom above the winner is the ADR-0120 failure mode wearing a larger corpus |

Option B, the aggressive one, was rejected **on measurement**: four components sit within
0.0002 of their controls, which is a null, and this repository has already paid for
collapsing NOT-YET-JUSTIFIED into REJECTED.

## Consequences

**What this changes about acceptance criterion 1.** On `ambiguous` count=240 the cost
frontier reports `"dominated": []` and the Φ-oracle falls to 0.5975, so it no longer
dominates. Criterion 1's *reason* for failing changes; **criterion 1 does not pass**, for
four measured reasons:

1. The undominated model is the **TCN**. In the same run `dtl-conv` is
   `"dominated_by": ["tcn"]` at equal 1.0000 PR-AUC. **ADR-0010 is untouched.**
2. The latent frontier is **1.0000 at every dimension 12 → 96**, knee = 12. "Not dominated"
   here means "saturates the metric at 5,055 parameters".
3. `TIMED_MODELS` times three of nine baselines. `gru` also reaches 1.0000 and **was never
   timed**, so `"dominated": []` is a claim about three models. **UNMEASURED.**
4. `gate.py` refuses frontier evidence whose `(corpus, count, seed)` differs from the split
   the gate ran, by design. Nothing here licenses overriding that.

**What this says about `saturation_check` itself.** The guard asks whether a split can rank
*architecture families*; at count=240 it can. It does **not** ask whether the split leaves
headroom above the winner, and here it does not. **A fifth condition is needed — best at the
metric ceiling with no descent across the frontier — so a flat frontier is refused as loudly
as an order-free tie.** This ADR records the need; implementing it belongs to the `report`
package.

**What is superseded in ADR-0120.** Exactly one sentence — *"On the corpora this repository
has, the guard refuses."* It is false for `ambiguous` count=240 seed=11. ADR-0120's
decision, its four conditions, its thresholds, its Φ-oracle corpus-size table and every
other measurement in it stand unchanged, and its text is not edited.

**What is not affected.** ADR-0114's work ledger (verified this session: a fabricated skip
raises, and `close()` gives the caller no vote on its path), ADR-0118's compile-candidate
format, ADR-0121's empty-package rule, and the `epoch_guard` / `quarantine_promotion` pair,
which are the only unambiguously JUSTIFIED rows in the table — measured 0 vs 377 malicious
patterns normalised and 0 vs 64 poisoned promotions against `accept_everything`.

**Honest limits.**

1. **Every corpus is synthetic** (`synthetic_data: true`). No row above is a detection
   result, and no component delta here is a property of the component until it is
   re-measured on real host telemetry.
2. **The informative split saturates at the top.** Two architectures tie at 1.0000, so a
   positive ablation of the winner is impossible on it by construction. The four
   NOT-YET-JUSTIFIED rows are honestly undecidable, not disproven.
3. **The INFORMATIVE classification is seed-sensitive.** Measured at count=240 across eval
   seeds 11/17/23/29: **3 of 4 are INFORMATIVE**; seed 23 is refused on condition 4, by
   0.0026 (`markov-bigram` 0.3307 against base rate 0.3333). The facts this ADR rests on are
   stable across **all four**: `gru` and `tcn` both score exactly 1.0000 in every seed, and
   the Φ-oracle sits in 0.5886 – 0.5975. The component ablation itself was run on seed 11
   only. Full table: `docs/stage-2-findings.md` §3.3.
4. **Wall-clock figures were taken under contention** (load average 11–21 on 8 cores from
   unrelated work). PR-AUC, log-loss, Brier and byte counts are deterministic and
   unaffected; only ratios within a single run transfer.
5. **No formal verification is claimed.** Every property here is empirical; there is no
   prover module in this repository.

**Reversibility.** This ADR changes no code. It records verdicts and registers eleven
experiment ids in the append-only, digest-chained ledger
(`verify_integrity() -> []`, 20 entries). Acting on decisions 1–3 — defaulting the lattice,
the uncertainty module and the multiscale window off — is a separate, reversible change owned
by the `lattice`, `uncertainty` and `routing` packages. Nothing is deleted.

**Authority.** None. A verdict word is a research finding; it grants no privilege and
touches no execution path.

## Verification

```
cd /home/anil/Documents/Research/pocketsec && python3 -m pytest -q ; echo "EXIT=$?"
EXIT=0                                        # 755 tests collected, all passing

python3 -m pocketsec.stage2.cli gate
GATE: FAILED (7)                              # exit 1, before and after registration

python3 -c "...ExperimentRegistry(...).verify_integrity()"
[]                                            # digest chain intact, 20 entries, 11 from this wave
```

Full commands, raw outputs, the honesty ledger and the UNMEASURED list are in
`docs/stage-2-findings.md`.

## Prior art

No novelty claimed. Comparing a learned component against the dumbest control that could
work, and refusing a benchmark that cannot discriminate, is ordinary experimental hygiene;
the specific discipline here follows this repository's own precedents (ADR-0009's
NOT-YET-JUSTIFIED / REJECTED distinction, ADR-0120's degeneracy guard, and Stage 1's
`ParetoReport.degenerate`). The finding that simple baselines match far more complex models
on provenance-based intrusion detection is already cited in
`pocketsec/stage2/research/baselines.py`. No `docs/prior-art/ledger.json` entry is required.
