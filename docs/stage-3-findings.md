# Stage 3 — AICT + CRYSTAL — findings

- **Status:** PARTIAL. The Stage 3 acceptance gate **FAILS**, 6 of 13 criteria.
- **Central claim:** NOT SUPPORTED. Details in *The verdict on the central claim*.
- **Date:** 2026-09-25 · **Author:** Stage 3 measurement wave, then the Stage 3
  defect-repair wave (see *Corrections from the defect-repair wave*, which is the
  authority wherever the two disagree)
- **Gate:** `python -m pocketsec.stage3.cli gate` (exit 1). The measurement wave
  ran it twice and recorded 5 failures; the repair wave's runs record **6**,
  because G3.2 flipped to FAIL once B4 stopped being credited as a working
  control on a +0.0086 margin. Nothing was restated until it failed — the change
  is a corrected measurement, and it is itemised below.
- **Spec:** `docs/stage-3-spec.md` · **Architecture:** `docs/architecture/sources/stage-03-aict-crystal.md`
- **Hypothesis binding:** H4, "Neural-to-symbolic JIT compilation" (`pocketsec/stage0/hypotheses.py`)
- **Experiment ledger:** `PS-S3-20260925-H4-crystal-gate-0001`,
  `-cell-path-constant-0002`, `-ambiguous-saturation-0003`, `-edge-envelope-0004`
  and `-vm-cost-split-0005` in `experiments/registry.jsonl`, with payloads under
  `results/`. The ledger's integrity chain was intact before (29 entries) and
  after (30) the fifth registration.

Every number in this document was produced by running code in the session that
wrote it. A quantity that could not be produced is written `UNMEASURED` or
`None`, never a plausible-looking figure. Where an earlier Stage 3 document
carried a figure this session could not reproduce, the figure is listed under
*Corrections to the previous findings document* with what was measured instead —
nothing is silently overwritten.

**Host contention.** Every timing here was taken on a shared host while a
concurrent Stage 2 wave was running; `/proc/loadavg` is recorded beside each
figure. No absolute microsecond or CPU-second figure in this document is a device
measurement. Only within-run ratios transfer, and cost is claimed only in that
form.

---

## The verdict on the central claim

Stage 3's claim is that stable learned knowledge can be compiled into
validity-bounded executable Knowledge Cells that are cheaper than what they
replace, and melted back when reality moves. Measured on the corpus the stage
itself selected:

1. **The compiled artefact is not cheaper.** The Knowledge Cell path costs
   **1.59×–1.60×** the Φ-oracle's µs/event and **29.17×** its bytes, in the same
   run, at two different host loads.
2. **The compiled artefact does not carry the knowledge.** The Φ-oracle
   Knowledge Cell returns the constant **1.0** on all 60 evaluation sessions,
   benign and malicious alike. Its PR-AUC equals the base rate by construction.
   This session measured that directly; it is stronger than "does not reproduce
   the scores", and it is the reason the cost comparison has no quality side.
3. **CRYSTAL produces nothing promotable.** Eight regions, zero cells promoted.
4. **Melting is localised on the measured run — but `repair_locality` is not the
   evidence for it.** That ratio is 1.0 by construction: `partial_melt` touches
   only the melted cell's id and its successor's, and `KnowledgeField.insert`
   refuses rather than evicting, so no statement in its success path can remove a
   bystander. A `partial_melt` with its narrowing logic deleted reports the same
   1.0. What is now measured, in G3.7's own pass condition, is that the survivor
   is live in both containers, that its key set is a **proper subset** of the
   original's and shares no satisfiable frame with the drifted region, and that a
   frame the index answered before the melt routes to abstention after it. Cells
   built by a lab helper, not by `crystallize`.
5. **No component earns its place on the evidence available.** Both corpora
   Stage 3 can reach are DEGENERATE, so the ablation surface is untestable
   rather than tested.

So the load-bearing feature (4) works as a mechanism, and the thing it is
supposed to be load-bearing *for* (1, 2, 3) does not exist yet. Stage 3 is, on
this evidence, distillation machinery that has not yet distilled anything, plus a
melt path demonstrated on hand-built cells. That is a real negative result and
ADR-0021, ADR-0024, ADR-0026 and ADR-0027 already record parts of it.

---

## Gate result

Two independent runs by the measurement wave, `loadavg` 4.36 and 5.98 at start,
both exit 1 with five failures. The **result column below is the repair wave's**,
at `loadavg` 9.14/10.26/8.60 and 9.70/10.47/8.35: six failures, because G3.2 now
reports B4 AT_CHANCE rather than as a working control. G3.7 and G3.12 still pass,
but on strictly stronger conditions than before — see the repair-wave section.

| id | criterion | result |
|---|---|---|
| G3.1 | Stage 2 baseline frozen and reproducibly benchmarked | **FAIL** (UNMEASURED: corpus mismatch) |
| G3.2 | ≥4 alternative compilation/distillation baselines | **FAIL** (B4 is AT_CHANCE, not a working control) |
| G3.3 | Versioned schema, bounded operator, explicit boundary | PASS |
| G3.4 | Boundary Pressure beats naive random replay | **FAIL** (falsifier F3 fires) |
| G3.5 | Dual oracle prevents teacher-error crystallization | PASS |
| G3.6 | Promotion, auditing, partial and full melting end-to-end | **FAIL** (CRYSTAL refuses) |
| G3.7 | Localized drift reopens a subregion, sparing the rest | PASS |
| G3.8 | Crystallized execution preserves evidence and attribution | PASS |
| G3.9 | Crystallised path costs no more than the Φ-oracle | **FAIL** (falsifier F1 fires) |
| G3.10 | Incremental memory within the declared Edge budget | PASS |
| G3.11 | No surviving component lacks ablation-supported value | **FAIL** (DEGENERATE) |
| G3.12 | Verification claims limited to properties actually proven — see `pocketsec/stage3/bytecode/verifier.py` | PASS |
| G3.13 | Prior-art review before any novelty claim | PASS |

Five of the six failures are *results*. The sixth, G3.6, is genuinely incomplete
work — and it was also **unpassable by construction** until the repair wave: its
`passed` expression required a `recrystallised` flag that was initialised `False`
and never assigned again.

---

## Corrections from the defect-repair wave

Twenty-two confirmed CRITICAL/HIGH defects and fourteen MEDIUM ones were reported
against this stage after the measurement wave. Every one of them had survived an
independent refutation attempt. This section records what was repaired, what each
repair changed about the numbers above, and what was left alone and why. Where this
section disagrees with anything earlier in the document, **this section is the
authority**.

Two of the repairs changed a gate verdict, and neither changed it in the flattering
direction:

- **G3.2 PASS → FAIL.** B4 — the mandated "frozen-teacher cache with an LRU"
  control — beat the base rate by **+0.0086** on this split, inside the 0.01 band
  this same stage uses to declare a split unable to tell models apart. It was being
  reported as a working control, and the reportability of the whole baseline table
  turned on it. `beats_base_rate` is now tri-state and a margin inside the band is
  `AT_CHANCE`, which is not the same claim as beating chance. B4 was also neither
  frozen-teacher (nothing passed it a snapshot, so every miss fell back to a fresh
  Φ-oracle evaluation) nor LRU (hits were served through `TransitionCache.get`,
  which reads "without touching recency", so eviction was FIFO). Both are repaired.
  Measured after the repair, same split, `loadavg` 9.82 before and 10.56 after:
  B4's PR-AUC is **unchanged at 0.2919118**, margin **+0.0085784** — the LRU repair
  moved nothing, because 23 cache entries never reach a `keep` of 256 — and its
  bytes rise from **6,293 B to 179,202 B** once the snapshot it is supposed to be
  caching is actually present.
- **G3.7 and G3.12 still PASS, on strictly stronger conditions.** Both had vacuous
  conjuncts. G3.7's `set(reopened_keys) <= region_keys` was satisfied by the empty
  set and its `surviving_cell is not None` by any object, so a `partial_melt` that
  discarded the whole cell and re-inserted nothing passed the criterion that
  ADR-0025 and §4 cite as the evidence for the stage's load-bearing claim. G3.12's
  forged-A5 probe kept the cell at A1 while the state claimed A5, so the
  level-mismatch branch refused it and the verification guard was never the reason
  — the criterion passed with `_guard_verification_claims` entirely deleted, still
  printing the sentence "an A5 claim with no prover and a merely-empirical property
  is refused: True". G3.7 now asserts eight conjuncts including abstention routing;
  G3.12 now runs four single-variable probes and records which branch refused each.

### The two repaired criteria are now shown to be able to fail

A criterion that cannot fail is not evidence, so the repairs to G3.7 and G3.12 were
checked by breaking the thing each one is supposed to catch and confirming the
criterion goes red. Measured this session, by rebinding the name the criterion calls
and re-running that criterion alone against the real gate context:

```
G3.7, real partial_melt                              -> passed=True
G3.7, stub: whole-cell discard, reopens nothing,
            names the original as "survivor"         -> passed=False
G3.7, stub: the real narrowing with its two
            re-insert lines deleted                  -> passed=False
G3.7, stub: narrow_boundary returns the boundary
            unchanged (survivor still claims the
            drifted key)                              -> passed=False

G3.12, real guard                                    -> passed=True
G3.12, _guard_verification_claims stubbed to a no-op -> passed=False
```

All four regressions **passed** the pre-repair versions of those criteria. The third
G3.7 stub is the one that matters most: it is a melt in which "the melted region
keeps answering from a stale cell", which is falsifier F2's own second clause, and
the old predicate granted it a PASS with `repair_locality` reading 1.0.

### The two new boundary predicates are checked against the frame sets they claim about

The CRITICAL repair replaced two key-footprint comparisons with two frame-level
ones, so the obvious question is whether the replacements themselves hold. They were
checked by brute force rather than by argument: 300 generated `CellBoundary`
values crossed with 2,304 generated `CellFrame` values, computing each boundary's
true frame set through `CellBoundary.contains`, then testing every ordered pair.

```
frames 2304
boundaries 300
accepts_no_more_than TRUE in 4535 pairs; frame-subset violations: 0
intersects FALSE in 27132 pairs; actual-overlap violations: 0
```

So on this lattice `accepts_no_more_than(A, B)` never held while A accepted a frame B
refused, and `not A.intersects(B)` never held while some frame satisfied both. This is
a **bounded empirical check over a generated lattice, not a proof**: the lattice covers
three relation families, three semantic properties, two state dimensions, two epochs and
three (Φ, uncertainty) pairs, and `forbidden_combinations` is empty throughout — which is
exactly the clause `intersects` documents itself as approximating in the fail-safe
direction. The script is not kept in the repository; the property it checks is pinned by
`test_narrow_boundary_accepts_no_frame_the_original_refused` and
`test_partial_melt_survivor_never_answers_a_frame_the_cell_refused`, both of which assert
the frame-set property over a generated lattice rather than over key sets.

### What was repaired

| id | defect | repaired by | pinned by |
|---|---|---|---|
| S3-01 | `CrystalSlot` wrote the composed **risk** into `confidence` for both verdicts, so Stage 0's harness (which maps BENIGN through `1 - confidence`, ADR-0004) ranked the cell's most-benign windows as its strongest detections | verdict-aware `confidence`; `uncertainty` is now the distance from the decision threshold, so a risk-0.0 BENIGN no longer reports `uncertainty=1.0` with `abstained=False` | `test_detection_score_through_stage0s_harness_is_monotone_in_the_cells_risk`, `test_a_confident_benign_is_not_reported_as_maximally_uncertain` |
| S3-02 | `random_replay_control` credited a counterexample class to every axis it **drew**, including axes `perturbed_frame` refused to move; those fabricated classes were the whole basis for G3.4's "strict superset" | only applied axes are credited; ADR-0026's reason withdrawn | `test_random_replay_is_not_credited_for_an_axis_it_could_not_move` |
| S3-03 | `false_inside` counted frozen-snapshot **key misses** as missed detections, feeding the melt decision at weight 0.25 | boundary-quality counters advance only when a hard violation fired or the teacher answered; the rest are `unmeasured_probes` | `test_a_silent_teacher_is_not_counted_as_a_boundary_quality_error`, `test_a_hard_violation_counts_even_with_no_teacher` |
| S3-04 | `partial_melt`'s rollback removed the successor id unconditionally, so a failed insert deleted whatever else held that id — no `MeltReport`, no reason, no rollback record | the collision is refused up front as `SUCCESSOR_ID_TAKEN`, and rollback withdraws only what this call inserted | `test_partial_melt_refuses_when_the_successor_id_is_already_live` |
| S3-05, S3-07(rs) | `_substitution_consistency` divided actor-substitution divergences by **all** probes on all seven axes, and its "no probe ran" guard tested the same total, so an unprobed actor axis returned exactly the 1.0 its docstring called dishonest | per-axis probe and divergence counts on the report; the term is `None` when the axis never moved, and `None` refuses instead of scoring | `test_substitution_consistency_is_measured_on_its_own_axis_or_not_at_all`, `test_per_axis_probe_counts_are_recorded_for_every_axis_walked` |
| S3-06, S3-03(rs) | intelligence GC keyed duplicates on `(operator digest, epochs)` with **no region term**, so cells compiled from one rule over disjoint boundaries were deleted as `DUPLICATE_OPERATOR` | the boundary footprint is part of the key; same operator over a different region is a fusion question | `test_gc_keeps_same_operator_cells_that_cover_disjoint_regions` |
| S3-07, S3-02(rs) | the counterexample join used two disjoint keyspaces, so `_refine_or_fission` always saw an empty tuple, `fission_cell` was unreachable from `crystallize`, and 30% of the melt-trigger score was structurally 0.0 for every CRYSTAL-built cell | the lookup uses the region's `candidate_id`; a provisional cell carries it as `source_candidate_id`; `open_counterexamples` reads both keys | `test_the_pipeline_finds_the_counterexamples_it_filed_itself`, `test_a_crystal_built_cell_can_find_its_own_counterexamples_later` |
| S3-08, S3-FC-03 | `repair_locality` presented as F2's falsifier while being 1.0 by construction; G3.7 vacuous on two conjuncts | G3.7 asserts the survivor's liveness, proper-subset footprint, region disjointness and abstention routing; `partial.py` and ADR-0025 reworded | G3.7 itself; `test_melted_region_routes_to_abstention_not_to_a_stale_cell` |
| S3-09, S3-AUTH-03 | `_check_mandatory_evidence` had no abstention guard, so every abstention on a mandatory-signal frame was branded `NEVER_SUPPRESS_MANDATORY_EVIDENCE` — including every non-BYTECODE form, whose only sin is having no interpreter | abstention returns `()`, matching the module's own docstring and its two sibling checks | `test_abstention_is_not_a_benign_verdict` (repaired: its abstention now carries `evidence=()`, the only shape the VM can produce), `test_the_vm_own_abstention_is_not_charged_with_evidence_suppression` |
| S3-10 | `teacher_disagreement` read **1.0** — the maximum — when the snapshot had no entry for any audited frame | `AuditReport.teacher_silent` counts those apart; `disagreement_rate` is `None` over zero *measured* audits and `compute_cell_stress` refuses rather than scoring | `test_a_silent_teacher_is_not_reported_as_total_disagreement`, `test_a_hard_violation_is_still_a_disagreement_without_a_teacher` |
| S3-AUTH-04 | `AuditPolicy.jitter_salt` was validated, serialised and carried across the Stage 4 seam while nothing read it, so the documented mitigation — rotate a compromised cell's salt — was a no-op | the salt is mixed into `AuditSampler.draw`; `AuditPolicy`'s docstring now states precisely what it buys (separation and rotation) and what it does not (secrecy — the production values are derived from public region keys) | `test_re_salting_one_cell_changes_its_audit_schedule` |
| S3-AUTH-06 | `promote_cell` admitted a cell at **A0**, the level §25 calls candidate-only, because `ASSURANCE_EVIDENCE[A0]` is the empty tuple — and A0 is the only level this repository's cell producers emit | `MIN_PROMOTABLE_ASSURANCE = A1`, refused as `REFUSED_ASSURANCE`, with an import-time assertion that the lowest promotable rung requires evidence | `test_promote_cell_refuses_an_a0_candidate`, `test_a_fused_cell_cannot_be_promoted_before_it_re_enters_shadow` |
| S3-FC-01, S3-01(rs) | **the CRITICAL one.** `narrow_boundary` accepted a candidate on its *key footprint*, but `keys()` is a product over declared requirements while `contains` is a conjunction matched by superset — so dropping an ACTOR predicate shrank the key set and **enlarged** the frame set. A frame the pre-melt cell refused was answered committally by the survivor, with `repair_locality` still reading 1.0. Symmetrically, key-disjointness is not frame-disjointness, so a dimension-scoped drift was reported `REGION_DISJOINT` and left the stale cell live | both conditions are now frame-level: `CellBoundary.accepts_no_more_than` (per-role required/forbidden mask unions, which exactly characterise the predicate conjunction) and `CellBoundary.intersects` | `test_narrow_boundary_accepts_no_frame_the_original_refused`, `test_partial_melt_survivor_never_answers_a_frame_the_cell_refused`, `test_partial_melt_does_not_report_a_dimension_scoped_drift_as_disjoint` |
| S3-FC-04 | G3.12 passed with its guard deleted | four single-variable probes against a well-formed A5 state, plus a control that must get *past* the guard | G3.12 itself; `tests/test_stage3_lifecycle.py:730+` |
| S3-FC-08 | a false citation ("the 2.9–4.9× band `verifier.py` reports") and two replacement ratios with no producer | `pocketsec/stage3/bytecode/cost.py`, `pocketsec-stage3 vmcost`, payload in `results/`; §9 rewritten with a five-repeat range | `test_measure_vm_cost_produces_both_published_ratios`, `test_measure_vm_cost_refuses_to_time_what_it_cannot_verify` |
| S3-FC-09 | B4 exercised neither frozen teacher nor LRU nor eviction, and a +0.0086 margin made it a "working control" | snapshot threaded through `run_baselines`; `lookup_transition_cache` for hits; `AT_CHANCE_PR_AUC_BAND` | G3.2 itself |
| S3-FC-10 | G3.8 claimed non-suppression was "structural" while `RETURN_RISK` — a terminator the check never exercised — pops only a FLOAT | the claim is scoped to `RETURN_STATE`, and G3.8 now runs a verified `RETURN_RISK` program and reports what it carries plus the oracle terms that refuse it | G3.8's own detail |
| S3-FC-12 | `lifecycle_stop_reason` appended a fixed paragraph asserting two measurements that did not happen on the region the gate runs | derived from `run.outcome`, `run.reason` and `run.candidates_tried` | G3.6's own detail |
| S3-08(rs) | the pipeline hard-coded `PressureStrategy.GUIDED` while ADR-0026 said random replay was retained and that nothing in the promotion path depended on guided — and guided flatters `predictive_stability` | `CrystalConfig.strategy`, defaulting to `RANDOM_REPLAY`; ADR-0026 amended with the measured strategy-dependence | `test_crystal_config_defaults_to_the_strategy_adr_0026_retained` |
| S3-12 / S3-FC-07 | G3.6 was **unpassable by construction**: `recrystallised` was initialised `False` and never assigned | `recrystallize` is actually called, on a region from the *fit* split so the melt's own drifted samples are not recompiled and called a repair | G3.6's own detail |
| S3-14 | the saturation guard's reason said "the split cannot tell models apart" when the real finding was that the median sits at the ceiling | the reason distinguishes the two degeneracies and prints the best-worst range | `test_the_saturation_guard_says_which_degeneracy_it_found` |
| S3-15 | `Stage3ResourceReport` accepted `within_budget=True` with `incremental_rss_bytes=None` | both observations gate the verdict | `test_a_resource_report_cannot_claim_within_budget_with_no_incremental_rss` |
| S3-16 | `const.0` and `const.00` resolved to one pool slot; one value was dropped silently while the density check still passed | non-canonical index spellings are refused | `test_a_non_canonical_pool_index_is_refused_rather_than_silently_dropped` |
| S3-17 | T5's control-off arm was an assignment to a local dict — a fact about Python, not a run of PocketSec code | the arm runs the real `KnowledgeField` with the duplicate-id refusal bypassed | `test_the_certificate_rollback_control_arm_runs_real_code` |
| S3-AUTH-07 | `phi_range` accepted ±inf and NaN; the infinity then raised **ValueError**, not `ContractError`, inside `size_bytes` — past every caller's guard, including `partial_melt`'s rollback | non-finite bounds are refused at construction; `PHI_UNCONSTRAINED_HIGH = 31.0`, measured as Φ of the top of Stage 1's lattice, replaces the `inf` default | `test_phi_range_refuses_a_non_finite_bound`, `test_from_validity_boundary_does_not_default_to_an_infinite_phi_range` |
| S3-AUTH-09 | the Stage 4 seam guard rejected NaN but not ±inf, so the refusal that must run "before the bytes exist" caught one of three | all three are refused | `test_the_seam_refuses_an_infinity_before_the_bytes_exist` |
| S3-AUTH-10 | `OperatorProgram.from_dict` leaked `OverflowError`; `TeacherSnapshotV1.from_dict` leaked the `ValueError` from `parse_experiment_id` | both are converted to `ContractError` | `test_operator_program_from_dict_raises_contract_error_on_an_oversized_table`, `test_teacher_snapshot_from_dict_raises_contract_error_on_a_malformed_experiment_id` |
| S3-11 | `BoundaryIndex.near_boundary` was measured and never consulted, so §40's near-boundary escalation had no mechanism and a frame one clause outside was indistinguishable from unexplored territory | `CrystalSlot` records a distinct abstention reason for it, bounded at `MAX_NEAR_BOUNDARY_FRAMES` frames per window | `test_a_near_boundary_miss_is_reported_apart_from_unexplored_territory` |
| S3-12 (index) | `CellBoundary.from_dict` annotated `Mapping`, which the module never imported — deferred evaluation hid it until something introspected | the import, plus an AST rule over **every** Stage 3 annotation | `test_every_stage3_annotation_names_something_the_module_binds` (observed to fail when the import is removed) |
| S3-FC-11 | the two document checks skipped whole table rows, and exempted a novelty word whenever any negation appeared anywhere on its line | table rows are scanned; the negation exemption is scoped to 48 characters either side of the claim | `test_a_verification_claim_inside_a_table_row_is_scanned`, `test_a_novelty_claim_is_only_exempt_when_the_negation_is_near_it` |
| S3-10 (medium) | G3.9's failure detail printed "Scores are NOT identical" and "FALSIFIER F1 FIRES" unconditionally, so a run failing on bytes alone would contradict the two equal numbers beside it | the detail names which conjuncts failed and states the scores conditionally | G3.9's own detail |
| S3-FC-05 | G3.9's headline ratio was a single best-of-7 sample with no dispersion reported | each row carries the `(min, max)` over its repetitions and G3.9 prints the ratio band those admit, labelled "ONE sample, not a replicated estimate" | G3.9's own detail |

### Side effects of the repairs on earlier numbers

Recorded because a repair that quietly moves a published figure is the thing this
document exists to prevent.

- **`BUDGET_EXHAUSTED` became unreachable on the synthesis fixture**, and that is
  the S3-03 repair working. The refinement that drove the loop to budget exhaustion
  was triggered by `near_boundary_errors`, which was counting frozen-snapshot key
  misses; with those excluded the run refuses on its first real divergence instead.
  Two tests that asserted the outcome now use a teacher that actually has opinions
  off the corpus (`teacher_over_the_lattice`), so the assertions are unchanged and
  the path they exercise is real.
- **B4's bytes rose from 6,293 B to 179,202 B** once the frozen snapshot it exists
  to cache is supplied. The earlier figure measured the cache alone.
- **`CrystalSlot`'s abstention-reason keys gained one member.** Still bounded — the
  set is the four constants plus the `CompositionOutcome` members — and it never
  changes what the slot answers.
- **`BoundaryPressureReport`, `AuditReport`, `BaselineRow` and `BaselineTable` each
  gained fields**, all with defaults and all at the end, so no existing construction
  site changed. `narrow_boundary`'s signature did change: it takes the drifted
  region as a `CellBoundary` rather than as a key set, because the key set is what
  made it unsound. It has no caller outside melting and the tests.
- **`VmCostReport` names its interpreter timing `interpreter_us`, not
  `execute_us`.** The second contains the `execute` token from
  `FORBIDDEN_AUTHORITY_FIELDS` (ADR-0003) and Stage 3's own dataclass-field rule
  refused it — the same rule that renamed `CellResult.steps_executed`. The rule is
  broader than the harm for a timing field, and a rule with one exemption has none.

### Accepted known defects, not repaired

- **No new ADR number exists.** Stage 3's reserved block 0020–0029 is fully
  occupied, and this session was forbidden any number outside it. Every correction
  above that needed a decision record was made **additively inside** the ADR that
  carried the claim: ADR-0021 (Correction 3, the withdrawn bytecode ratios),
  ADR-0025 (what G3.7 asserted and what `repair_locality` is worth) and ADR-0026
  (the withdrawn "strict superset", and the guided-search default). Nothing was
  deleted. The block collision recorded under *ADR status* still needs a
  wave-coordination decision.
- **Between-run dispersion of G3.9's cost ratio is still not characterised.** The
  criterion now reports the band its own repetitions admit, which is a within-run
  quantity. A proper replication study — the whole `run_baselines` procedure
  repeated N times — was not run here; the five-repeat study in §9 covers the
  bytecode cost split only. G3.9's ratio remains **one sample**, and it now says so.
- **Oracle A is still the Φ-oracle.** Unchanged from the measurement wave's
  UNMEASURED entry: the D3.8 rebinding (Oracle A as a frozen `TCNBaseline` exported
  as data) is not implemented, so G3.5 remains a test of Oracle B alone.
- **`RETURN_RISK` still pops only a FLOAT.** Making it pop an EVIDENCE handle would
  make non-suppression structural for all three answering terminators, and it is
  the better fix. It changes the ISA's stack effects and would require editing the
  bytecode test suite's existing programs, so this wave took the other option the
  finding offered: G3.8 no longer describes non-suppression as structural beyond the
  `RETURN_STATE` path, and it measures the gap instead. Recommended for the next
  wave.
- **Two whole-suite failures outside Stage 3, reported and left alone.** The
  repair wave's full-suite run ends with two failures, neither in a Stage 3 file:

  The Stage 4 failure is a **different test on each run**, which is itself the
  evidence that it is live work: one run reported
  `tests/test_stage4_boundary.py::test_no_stage4_dataclass_field_names_response_authority`
  (`pocketsec/stage4/engine/lucid.py:171 UpdateOutcome.killed`, a Stage 4 field
  carrying a `FORBIDDEN_AUTHORITY_FIELDS` token) and the next reported
  `tests/test_stage4_runtime.py::test_stage0_profile_report_is_none_not_true`. The
  collected total moved too, from 2,027 to 2,031, between two runs an hour apart.
  That is the concurrent Stage 4 wave's work in progress and Stage 3 does not touch
  it.

  `tests/test_stage1_pipeline.py::test_gate_cli_exits_zero` fails only in the whole
  suite. Diagnosed rather than dismissed: Stage 1's criterion G1.12 compares
  `ctx.peak_rss_bytes` — the **pytest process's** peak RSS — against the Stage 0 Edge
  profile's 100 MB `agent_rss_target_bytes`, so anything that grows the suite can trip
  it, wherever the growth is. Measured this session: the same criterion passes at
  24,670,208 B in a clean process; at 60,473,344 B in a process that has imported all
  185 `pocketsec` modules plus three of the heaviest test modules; and the nine test
  files up to and including `test_stage1_pipeline.py` pass together (271 tests, exit 0).
  Under the whole suite, every remaining test module is imported at collection before
  Stage 1's gate runs, and the process crosses the target. The repair wave added test
  code and two modules to that import set, so it may have contributed to crossing it —
  **that is stated rather than denied**, and it could not be attributed to any one
  addition. The defect is that a product memory target is being asserted against a test
  runner's address space; it lives in `pocketsec/stage1/gate.py` and fixing it is Stage
  1's call, not this wave's.
- **Three Stage 3 modules are over the ~800-line guideline.** `gate.py` is 1,106
  lines (929 before this wave), `crystal/pipeline.py` 856 and `labs/baselines.py`
  807. The repair wave took 146 lines back out of `gate.py` into a new
  `pocketsec/stage3/gate_probes.py` — the constructed probes and region builders
  three criteria need — rather than leaving it at 1,252, but the remaining excess is
  real. The honest next split is the thirteen criteria themselves; it was not
  attempted here because a structural refactor of the file that every criterion
  lives in, at the end of a session, is how a repair wave introduces the defect it
  came to remove.
- **`lru_control` still evicts nothing in B4.** With 23 distinct cache keys and a
  `keep` of 256 the eviction path cannot fire on this corpus, so the repaired LRU
  ordering is exercised by Stage 2's own tests rather than by this row. B4's
  eviction behaviour on this split is therefore **UNMEASURED**, not confirmed.

---

## MEASURED

### 1. The cell path costs more and carries nothing (F1, G3.9)

`python -m pocketsec.stage3.cli gate`, drift corpus, `count=60`, fit seed 3, eval
seed 11, base rate 0.2833, 2040 transitions, synthetic: **yes**.

| id | baseline | PR-AUC | µs/event | bytes |
|---|---|---|---|---|
| B1 | `PlainLookupTable` | 1.0000 | 14.6 | 925 |
| B2 | `DepthLimitedTree` | 1.0000 | 16.6 | 78 |
| B3 | `PhiOracleUnchanged` | 1.0000 | 16.6 | 269 |
| B4 | `FrozenTeacherLRU` | 0.2919 | 15.1 | 6,293 |
| B5 | `NoStage3` | 1.0000 | 16.8 | 269 |
| **S3** | **Knowledge Cell path** | **0.2833** | **26.6** | **7,848** |

**B4's row moved after the repair wave, and its status changed.** Re-measured on
the same split with the frozen snapshot actually supplied and hits served through
`lookup_transition_cache` (`loadavg` 9.82 before, 10.56 after): PR-AUC
**0.2919118** — unchanged to seven places, because 23 cache entries never reach a
`keep` of 256, so the LRU ordering has nothing to evict — margin over the base rate
**+0.0085784**, and bytes **179,202 B** rather than 6,293 B, the difference being
the snapshot it exists to cache. The margin is inside `AT_CHANCE_PR_AUC_BAND`
(0.01), so B4 is reported `AT_CHANCE`: it is not a working control, which is why
G3.2 now FAILS. The earlier 6,293 B measured the cache alone, with a
`TeacherOracle(None)` answering UNKNOWN on every miss.

Within-run ratios — the only transferable form: the cell path costs **1.60×** B3's
µs/event at `loadavg` 4.36 and **1.59×** at `loadavg` 6.06, and **29.17×** its
bytes in both. The byte ratio and every PR-AUC are deterministic and do not move
with load.

A third measurement of the same comparison through Stage 0's sampler rather than
the lab's timer, over 40,800 scored transitions at `loadavg` 6.57:

| path | CPU s/event | peak sampled RSS | Δ RSS | model bytes |
|---|---|---|---|---|
| S3 cell path | 5.660e-05 | 39,288,832 B | 176,128 B | 7,848 |
| B3 Φ-oracle | 3.652e-05 | 39,546,880 B | 0 B | 269 |

Within-run CPU ratio **1.55×**, agreeing with the 1.59–1.60× wall-clock ratio.

**Falsifier F1 fires.** The cell format is rejected for this class of knowledge
(ADR-0021).

### 2. Why the cell scores at the base rate: it emits a constant

New this session, and sharper than the previous document's wording. Scoring all
60 evaluation sessions with `CellPathBaseline` and `PhiOracleUnchanged` side by
side (`results/PS-S3-20260925-H4-cell-path-constant-0002.json`):

| model | distinct session scores | benign range | malicious range |
|---|---|---|---|
| `CellPathBaseline` (S3) | `{1.0: 60}` | 1.0 – 1.0 | 1.0 – 1.0 |
| `PhiOracleUnchanged` (B3) | 6 distinct values | 0.2000 – 0.2195 | 0.3333 – 0.5224 |

The cell answers **1.0 for every session of both classes**. Its PR-AUC therefore
equals the base rate by construction and measures no discriminative capacity at
all. B3 separates the classes completely, with no overlap between the ranges.

The cause is stated in `pocketsec/stage3/labs/cell_path.py` and is structural:
the PCB ISA in `pocketsec/stage3/bytecode/isa.py` defines no division opcode, so
the Φ-oracle's `|ΔΦ| / (|ΔΦ| + 8)` cannot be expressed and the closest admissible
program is `clamp01(ΔΦ)` — which saturates at 1.0 on every session in this
corpus, because the median per-session peak `|ΔΦ|` is 2.25 for benign sessions
and 8.00 for malicious ones.

**This narrows what F1 licenses.** What is measured is that the one operator form
with an interpreter cannot express the target function, so the "at identical
scores" precondition of F1 is not met and the cost ratio is the whole of the
finding. `CellVM` executes `BYTECODE` and abstains on the other seven forms
(ADR-0027), and the `LOOKUP_TABLE` form — which B1 shows would reach 1.0000 on
this split at 925 B — has no executor. On this evidence the rejection is of
**BYTECODE-as-the-only-executable-form**, not of the Knowledge Cell format as
such. ADR-0021's title claims more than the numbers carry.

### 3. Guided Boundary Pressure finds nothing random replay misses (F3, G3.4)

`python -m pocketsec.stage3.cli pressure`, budget 256, seed family 11, one run:

- guided: 49 probes **spent**, **12** counterexample classes
- random replay at the same budget **cap**: 256 probes spent, **12** classes
- found only by guided: **NONE**
- found only by random replay: **NONE**

**Falsifier F3 fires**; ADR-0026 removes the guided search as the default, and
`CrystalConfig.strategy` now defaults to the retained one.

**Corrected.** This section previously read 14 classes for random replay and named
two `EVIDENCE_ABLATION` classes it found that guided missed, concluding "random
replay found a strict superset". Those two classes did not exist:
`random_replay_control` credited a class to every axis it *drew*, including axes
where `perturbed_frame` returned `None` and nothing was perturbed, and every
corpus seed carries exactly one `EvidenceRef`, so EVIDENCE_ABLATION cannot move
one at all. With attribution corrected the two strategies find the same 12
classes. The decision survives (guided found nothing random missed); the reason
recorded for it did not. Two further corrections: the shared 256 is a budget
**cap**, not a spend — guided spends 49 because it runs out of axes and depths,
not budget — and most of both runs' divergences are frozen-snapshot key misses
rather than oracle disagreements (guided 42 of 49, random 222 of 256), now
reported as `unmeasured_probes`.

### 4. Melting is localised (F2 does not fire, G3.7)

`python -m pocketsec.stage3.cli melt`. Four cells across four boundary regions;
drift driven into `(2, 16, 5)`:

- `reopened_keys` = `[[2, 16, 5]]`, non-empty and inside the drifted region's keys
- unrelated cells keep their exact index footprint
- the stale cell is gone from the field; survivor `cell-spanning-v2` is live in
  both the field and the index and keeps `[(1, 16, 5)]`, a **proper subset** of the
  original's `[(1, 16, 5), (2, 16, 5)]`
- the survivor's boundary shares **no satisfiable frame** with the drifted region
- a frame the index answered with `cell-spanning` before the melt routes to
  **abstention** after it
- `repair_locality` = **1.0** (3 of 3 unrelated cells retained)

**The last bullet is a sanity check, not the falsifier.** `partial_melt` touches
only two ids and `KnowledgeField.insert` refuses rather than evicting, so on every
report that exists the ratio is 1.0 or `None`; a `partial_melt` with no narrowing
logic at all reports the same 1.0, and so does one that re-inserts nothing. The
five bullets above it are the ones that can fail, and until the repair wave G3.7
asserted only the first three of them — two of its five conjuncts were satisfied
by the empty set and by any object being returned. ADR-0025 and this section both
cited "G3.7 (PASS)" for assertions the criterion did not make.

Two qualifications, both material: the cells came from
`pocketsec/stage3/labs/cell_path.py:phi_oracle_cell`, not from `crystallize`,
because CRYSTAL refuses on this corpus (G3.6); and the drift was planted by the
corpus designer. This is a mechanism demonstration, not a field claim.

### 5. Oracle B is load-bearing (F4 does not fire, G3.5)

Three constructed teacher-error cases, each refused by the dual oracle, each
accepted by a teacher-only control:

| case | dual oracle | violation kinds | teacher-only would have passed |
|---|---|---|---|
| a | refused | `NEVER_DOWNGRADE_CONSEQUENCE`, `NEVER_NORMALISE_HIGH_CONSEQUENCE` | yes |
| b | refused | `NEVER_SUPPRESS_MANDATORY_EVIDENCE` | yes |
| c | refused | `NEVER_LOWER_PHI`, `STATE_MONOTONE` | yes |

The control is what makes this a result. These are constructed corrupted
snapshots: a mechanism test, not evidence about a real teacher's error modes.

### 6. CRYSTAL promotes nothing (G3.6)

`python -m pocketsec.stage3.cli crystallize`, eight largest boundary regions:

- 5 regions `RETURNED_TO_LEARNING`, reason `NO_SATISFIED_PREDICATE`
- 3 regions `REFUSED_RESOLUTION`, reason `UNMEASURED: no admissible candidate
  carried a measured cost`
- cells promoted: **0**

The gate then ran promotion on a lab-built cell to report which later stages
work: `promote_cell` returned `REFUSED_HARD_CONSTRAINT` after `shadow_execute`
recorded **133** dual-oracle divergences over **256** frames across 18 boundary
keys with `coverage_met=True`. The field stayed inside `MAX_CELLS` and
`MAX_FIELD_BYTES`.

### 7. The resource envelope (G3.10)

`python -m pocketsec.stage3.cli resources` at `loadavg` 6.50, and the §38 budget:

| component | measured | §38 budget |
|---|---|---|
| `boundary_index` | 5,944 B | 8 MB |
| `knowledge_cells` | 1,904 B | 20 MB |
| `cell_vm` | 488 B | 8 MB |
| `audit_state` | 182 B | 5 MB |
| `counterexample_hot` | 0 B | 15 MB |
| incremental RSS | 94,208 B | 25 MB normal ceiling |
| peak sampled RSS | 43,700,224 B | — |

`within budget = True`. The gate's own two runs measured incremental RSS at
225,280 B and 159,744 B over 256 frames; all three figures are far inside the
ceiling and the variation is process noise, not growth.

Against the Stage 0 **edge** profile (100 MB agent RSS, 25 MB model bytes),
through `pocketsec.stage0.benchmark.profiles.check_profile`:

| path | `within_target` | exceeded | unmeasured |
|---|---|---|---|
| S3 cell path | True | none | none |
| B3 Φ-oracle | True | none | none |

`within_target` is `True` here rather than `None` because every term the checker
needs was observed in that run. The figures are small because the field held one
cell: this measures the machinery, not a populated field.

### 8. State, queues and caches stay bounded under flood

Measured this session (`results/PS-S3-20260925-H4-edge-envelope-0004.json`):

| pressure | result |
|---|---|
| insert cells until refusal | 512 inserted, then `FieldFull` with a named reason; `MAX_CELLS` = 512 |
| field bytes at 512 cells | 1,033,216 B of `MAX_FIELD_BYTES` 20,971,520 B |
| boundary index bytes at 512 cells | 119,072 B |
| 408,000 frame executions through `BoundaryIndex.lookup` + `CellVM.run` | Δ RSS **0 B**, 2.256e-05 CPU s/event |

Resident memory did not grow with traffic across 408,000 executions. The field
refuses rather than evicting, which is the contract in
`pocketsec/stage3/cells/field.py`: forgetting is a GC decision with a recorded
reason, never a side effect of insertion.

The nine §39 threat cases each ran with their control on and off
(`python -m pocketsec.stage3.cli threats`): **9 of 9 stopped with the control,
9 of 9 succeeded without it, none unmitigated.** T9 is the flood case for the
counterexample store — 4 incident-linked records survived a flood a plain FIFO
would have dropped.

### 9. Cell cost is dominated by verification, not execution

**Re-measured by the repair wave, from a producer that now exists.** The figures
this section used to carry (`run / _execute` = 4.06×, `run / handwritten` =
235.05×, "inside the 2.9–4.9× band `pocketsec/stage3/bytecode/verifier.py`
reports") had no code in the repository behind them, and the band citation was
false: `verifier.py` reports two *points* across a code change — 10.18× while it
decoded twice and 2.93× after it stopped — not a band, and the string "4.9"
appears nowhere in the repository. Both figures and the citation are **withdrawn**.

The producer is `pocketsec/stage3/bytecode/cost.py:measure_vm_cost`, run by
`python -m pocketsec.stage3.cli vmcost --json`, with the payload at
`results/PS-S3-20260925-H4-vm-cost-split-0005.json`. Five repeats of the identical
procedure, one process, 512 drift-corpus frames, best-of-7 each, `loadavg`
23.96/19.72/15.01 before and 23.26/19.71/15.05 after:

| repeat | `run / _execute` | `run / handwritten` |
|---|---|---|
| 1 | 5.33× | 388.51× |
| 2 | 2.77× | 414.13× |
| 3 | 5.90× | 558.64× |
| 4 | 7.06× | 640.54× |
| 5 | 6.88× | 573.62× |

**`run / _execute` ranges 2.77×–7.06×** and **`run / handwritten` ranges
388.51×–640.54×** across five repeats at load 23–24. The direction survives —
verification dominates execution, because `verify()` runs in full on every event,
and the whole bytecode layer costs two to three orders of magnitude more than a
bare Python function computing the same float. The *magnitudes* do not: a single
best-of-N ratio from this host is not a measurement with an error bar, and the
dispersion is reported rather than a mid-point. The verify-first contract was not
weakened to improve any of these numbers.

The control is `cost.handwritten_clamp01`, whose source the report carries, and it
returns a bare float rather than a `CellResult` — it carries no evidence, reports
no delta and cannot abstain. It is a floor on what the answer costs, not a
substitute for the VM.

### 10. Both corpora Stage 3 can reach are DEGENERATE (G3.11)

The gate reports G3.11 DEGENERATE on the drift corpus: saturation guard best
1.0000, median 1.0000, spread 0.0000, so **zero** ablation entries are recorded.
The guard's *stated reason* was corrected by the repair wave: with four of six
models at the ceiling the median **is** the ceiling, so `best - median` is 0.0
while best and worst differ by 0.7167. The split does separate the two groups; it
cannot rank within the upper one, and "the split cannot tell models apart" was the
wrong sentence for that. The verdict is unchanged and still fail-closed.
The obvious question is whether that is the corpus or the mechanism, so this
session re-ran the identical six models on Stage 1's *ambiguous* corpus — the one
that de-saturated Stage 2, dropping the TCN from 1.0000 to 0.5066.

`results/PS-S3-20260925-H4-ambiguous-saturation-0003.json`, `count=60`, fit seed
3, eval seed 11, base rate 0.3333, `loadavg` 12.38, synthetic: **yes**:

| id | PR-AUC | µs/event | bytes | beats base rate |
|---|---|---|---|---|
| B1 | 1.0000 | 15.16 | 1,280 | yes |
| B2 | 1.0000 | 17.55 | 78 | yes |
| B3 | 1.0000 | 17.54 | 269 | yes |
| B4 | 0.3333 | 18.24 | 2,782 | **no** |
| B5 | 1.0000 | 18.90 | 269 | yes |
| S3 | 0.3333 | 31.98 | 7,848 | no |

`run_baselines` **REFUSED** the table because B4 does not beat the base rate — the
refusal is reported here rather than worked around.

**Reclassified, not re-measured.** Under the repair wave's tri-state guard the same
row is `AT_CHANCE` rather than below chance, so `run_baselines` would report this
table with B4 flagged instead of refusing it. Checked by feeding the published
numbers to the new rule (`_beats_base_rate(0.3333, 0.3333)` → `None`, band 0.01);
B4's and S3's PR-AUCs on this corpus were not re-run, and neither figure changes.
The reading is the same either way: B4 is not a working control here. The saturation guard is
`DEGENERATE` on this corpus too: best 1.0000, median 1.0000, spread 0.0000. And
the cell path again lands exactly on the base rate.

Corpus properties, both corpora, measured before drawing anything from either:

| property | drift (the gate's corpus) | ambiguous (probe) |
|---|---|---|
| pooled order-free PR-AUC vs base rate | 0.2982 vs 0.2833 (+0.0149) | 0.5679 vs 0.3333 (**+0.2346**) |
| identities reused across sessions | 0 of 360 | 0 of 448 |
| median per-session peak \|ΔΦ\| benign / malicious | 2.25 / 8.00 | 2.25 / 8.00 |
| distinct epochs | **3** | **1** |

Three consequences, all measured:

- **Saturation is not an artefact of ADR-0028's corpus choice.** Stage 3's
  session-level scorers saturate the ambiguous corpus as well, so no corpus in
  this repository can currently support a Stage 3 ablation *of this baseline
  family*. Narrower than the sentence that stood here: what is measured on both
  corpora is that four of six models sit at the PR-AUC ceiling, so the upper group
  cannot be ranked. A split that separated the ceiling models from each other
  would support an ablation; neither of these does.
- **The ambiguous corpus leaks its label through operation vocabulary** by
  +0.2346 over the base rate, against +0.0149 for the drift corpus.
  `pocketsec/stage3/labs/crystal_corpus.py` states the rule this trips: if a
  bag-of-operations model beats the base rate, no order-sensitive result measured
  on that corpus means anything. The drift corpus is the better of the two on
  this axis, not merely the one with epochs.
- **The ambiguous corpus has one epoch**, so it could not satisfy G2.13 either.
  ADR-0028's choice of the drift corpus stands for a second measured reason.

### 11. The drift corpus does have genuinely distinct epochs

`build_crystal_corpus(count=60, seed=11)` reports `distinct_epochs = 3` and
`corroborated_epoch_transitions = 2` over 2040 transitions. G2.13's requirement
of two distinct epochs is satisfiable without lowering anything, which is what
ADR-0028 records. Nothing in this stage weakened that requirement.

### 12. Tests

The measurement wave recorded:

- Stage 3's own nine files: **429 collected, 429 pass**, exit 0.
- Full suite: **1218 collected, 1 failure** —
  `tests/test_stage2_gate.py::test_a_probe_target_signature_is_never_a_causal_node_identity`.
  That file belongs to the concurrent Stage 2 wave. Reported and left alone. No
  Stage 3 test fails.

The repair wave's own figures are in the run pasted at the end of this document.
Its regression tests name the finding they pin in their own docstrings, so the
count is checkable rather than asserted:

```
$ grep -rc "Pins S3-" tests/test_stage3_*.py | grep -v ":0" | sort
tests/test_stage3_boundary.py:1
tests/test_stage3_bytecode.py:2
tests/test_stage3_foundation.py:3
tests/test_stage3_knowledge_boundary.py:3
tests/test_stage3_lifecycle.py:8
tests/test_stage3_oracles.py:2
tests/test_stage3_runtime.py:11
tests/test_stage3_synthesis.py:4
# 34 test functions name the finding they pin
```

Stage 3's nine test files hold 440 test functions after the repair wave (`grep -c
"def test" tests/test_stage3_*.py`, summed), and `pytest -q --collect-only` reports
**2,027 tests collected** across the whole repository — up from the measurement
wave's 1,218, because the concurrent Stage 4 wave has been adding to it throughout.

The repair wave's own whole-suite result, with the summary line restored
(`python -m pytest -o addopts="--strict-markers" --tb=no -q`, loadavg 7.49 after):
**2 failed, 2029 passed in 899.54s**, and neither failure is in a Stage 3 file.

One reporting note, since it bit this wave: `pyproject.toml` sets
`addopts = "-q --strict-markers"`, so the mandated `python -m pytest -q` runs at
**double quiet** and pytest prints no "N passed, M failed" line at all. The failures
are still listed. A run needing the counts has to pass
`-o addopts="--strict-markers"`. Several findings carry more than one
pinning test — the CRITICAL narrowing defect has three, one on `narrow_boundary`
itself, one end to end through the index and the VM, and one on the symmetric
region-overlap half — which is why 34 functions cover the repairs in the table
above. Two existing tests were repaired rather than relaxed: `test_abstention_is_not_a_benign_verdict` now builds its
abstention the only way `CellVM` can (`evidence=()`), which is what made it
vacuous, and `test_report_serialises_every_field_the_gate_reads` was extended to
the three new report fields. Two more were re-pointed at a teacher that has
opinions off the corpus, because the S3-03 repair removed the only thing that was
driving them — stated under *Side effects of the repairs on earlier numbers*
rather than adjusted quietly.

---

## UNMEASURED

- **"Comparable security quality" (G3.9) is not measured and is not claimed.** It
  needs a corpus where security quality is discriminable. Both corpora Stage 3
  can reach are saturated for its baseline family (§10 above), so a PR-AUC on
  either is not evidence of equivalence. G3.9 reports the cost ratio as measured
  and **fails** rather than passing on half a criterion.
- **The Stage 2 frozen baseline does not match Stage 3's split (G3.1).**
  `results/stage2-frontier.json` was measured on the `ambiguous` corpus; Stage
  3's corpus is the drift corpus (ADR-0028). Re-running the frontier on the drift
  corpus needs numpy, which ADR-0020 keeps out of Stage 3. The gate refuses the
  mismatched evidence rather than comparing across corpora.
- **The TCN-sourced teacher snapshot does not exist.** Oracle A is the
  `"phi-oracle"` source only; `TeacherOracle` reports `TEACHER_UNAVAILABLE` for
  `"tcn"` and the affected divergence term is `None`, never zero. The D3.8
  rebinding in the brief — Oracle A as a frozen `TCNBaseline` exported as data —
  is therefore **not implemented**, and Oracle A is currently the same Φ-oracle
  the cell wraps.
- **Ablation (G3.11) is DEGENERATE, not failed on the merits.** Zero ablation
  entries were recorded, on either corpus. No OPTIONAL function has
  ablation-supported value; none has been disproven either. NOT_YET_JUSTIFIED is
  not REJECTED.
- **The multi-operator Pareto frontier (D3.7) could not be produced.** `CellVM`
  executes `BYTECODE` and abstains on the other seven forms, so their cost comes
  back `None`. Timing a refusal and calling it the operator's cost would hand the
  selector a cheap candidate that never answers (ADR-0027).
- **Whether a `LOOKUP_TABLE` cell would beat B1** is UNMEASURED, and it is the
  single most informative missing number in this document. B1 reaches 1.0000 at
  925 B on the same split, so the comparison is available the moment that form
  has an executor.
- **`ruff` and `mypy` were not run.** Neither is installed for this interpreter
  and installing them is blocked here. Lint and type status is `UNVERIFIED` —
  empirical status unknown, not clean. See `pyproject.toml` for the configured
  rules.
- **`PATH_COST_UNITS` is uncalibrated** (ADR-0114), so any "compute units per
  event" figure is a policy unit and not a cost.
- **A sixth digit of any µs or CPU-second figure here.** The host was contended
  throughout; only the ratios are claimed.

---

## REJECTED and NOT-JUSTIFIED

**REJECTED — measured, and measurably worse:**

- **`BYTECODE` as a vehicle for a deterministic scorer** (ADR-0021, F1, narrowed
  by §2 above). 1.59–1.60× the time, 29.17× the bytes, and a constant output.
- **Guided Boundary Pressure** (ADR-0026, F3). Random replay at the same budget
  cap found **every** class guided found, in the same run: 12 against 12, with
  both difference sets empty. The earlier "strict superset" reading rested on two
  fabricated counterexample classes and is withdrawn — see §3. Guided is removed
  as the default because it adds nothing, not because random beat it.
- **`RESIDUAL_MICRO_MODEL` as an operator form** (ADR-0021): it would need a
  weights blob and a numpy producer, both forbidden in Stage 3 by ADR-0020. A
  recorded decision, not an oversight.

**NOT-JUSTIFIED — no measured benefit, and recommended default-off or removal
pending a corpus that can test them:**

- Every OPTIONAL function in `pocketsec/stage3/core_ids.py`. Zero ablation
  entries exist on either corpus. This is the honest status of the whole
  OPTIONAL surface, and it is the reason G3.11 fails.
- **The seven operator forms without an executor** (ADR-0027). They cost nothing
  to keep as schema and cannot be justified as machinery until one of them runs.

**NOT-JUSTIFIED — machinery whose absence this session found:**

- **Stage 3 registered zero experiments before this session.**
  `pocketsec/stage3/gate.py` cites `EXPERIMENT_ID =
  "PS-S3-20260925-H4-crystal-gate-0001"` as the provenance of the frozen teacher
  snapshot, and that id was **not in `experiments/registry.jsonl`**. Stage 2's
  G2.12 checks registered ids; Stage 3's G3.11 short-circuits on saturation
  before it can, so the gap was invisible to the gate. Four entries were
  registered this session and `verify_integrity()` reports the chain intact
  before and after. **Recommendation:** G3.11 should check ledger registration
  *before* the saturation guard, so a missing experiment id fails loudly instead
  of hiding behind DEGENERATE.
- **`Stage3ResourceReport` never reports `cpu_seconds`.**
  `pocketsec/stage3/resources.py` reports component bytes and RSS only, so CPU
  per unit of work had to be measured outside it (§1, §8). The Stage 0 rule is
  that security quality and resource cost are co-equal; half of cost is missing
  from Stage 3's own instrument.
- **`--json` is a pre-subcommand flag**, so `pocketsec-stage3 resources --json`
  exits 2. Cosmetic, recorded so the next wave does not read the exit code as a
  measurement failure.

---

## RETRACTED

Retracted is not deleted. Each entry keeps the defect that produced the original.
The first five entries are carried forward from the previous Stage 3 findings
document and are not re-measured here; the sixth is new this session.

- **"A BYTECODE operator may not carry a table."**
  `pocketsec/stage3/cells/operator.py` refused any table on a BYTECODE program,
  reasoning that the VM reads constants from the program and a second data path
  would be unchecked. That was wrong about where the VM reads:
  `pocketsec/stage3/bytecode/isa.py` loads both the constant pool and the
  set-literal pool out of `program.table`, and
  `pocketsec/stage3/bytecode/verifier.py` range-checks every operand against the
  loaded pool length. **Consequence of the defect:** the constant pool was always
  length 0, so `LOAD_CONST` could never pass its range check, `IN_SET` could
  never name a set, and the bounded enumerative synthesiser could not emit a
  literal at all. The rule's intent is kept — a table key the ISA does not read
  is still refused — but the table is recognised as the one checked data path.
- **The "knowledge explosion via wide `state_dimensions`" threat case (T7).** The
  original attack declared a boundary over all nine state dimensions and expected
  the index to explode. It does not: `CellBoundary.keys` folds the declared
  dimensions into a single union delta mask. The case was reporting "stopped"
  while nothing stopped it. It now attacks the product that does multiply — nine
  unconstrained actor predicates across eight relation families, 72 keys against
  a cap of 64.
- **`perturbed_frame`'s `EVIDENCE_ABLATION` axis ablated to zero evidence.**
  `CellFrame` refuses an empty evidence tuple, so any pressure run seeded with a
  frame carrying a single `EvidenceRef` crashed mid-walk. The axis now floors at
  one ref and returns `None` when the frame cannot move, because returning the
  unchanged frame would have scored as "no divergence found".
- **`CellResult.steps_executed`.** Renamed to `steps_taken`: the name contained
  the `execute` token from `FORBIDDEN_AUTHORITY_FIELDS` (ADR-0003). The field is
  a past-tense instruction counter and grants no authority, so the rule is
  broader than the harm — but a rule with one exemption has none.
- **A repo-wide grep for verification language (G3.12(b)).** Implemented as the
  spec sketched it, it reported `provenance` as a claim that something is
  `proven` and `unverified` as a claim that something is `verified`. A check that
  cries wolf on its own vocabulary gets switched off, and then the real claims go
  unchecked. The claim is now checked structurally in
  `pocketsec/stage3/gate_criteria.py` and the prose scan is word-boundary matched
  over this document.
- **NEW — "a global rule cannot be crystallised as one cell."**
  `pocketsec/stage3/labs/cell_path.py` states, in its module docstring, in
  `phi_oracle_cell`'s docstring and in the comment on `CELL_STATE_DIMENSIONS`,
  that a boundary over all nine `DIMENSIONS` expands to `8 families × 512 delta
  masks = 4096` index keys and is refused at `MAX_KEYS_PER_CELL = 64`, that two
  dimensions give 32 keys and three give 64 exactly — and derives from that a
  structural result about the cell format. **Measured this session, directly:**

  | declared dimensions | index keys claimed | accepted by `BoundaryIndex` |
  |---|---|---|
  | 1 | 8 | yes |
  | 2 (`CELL_STATE_DIMENSIONS`) | 8 | yes |
  | 3 | 8 | yes |
  | 4 | 8 | yes |
  | 9 (all of `DIMENSIONS`) | **8** | **yes** |

  Every one claims 8 keys and every one is accepted. This is the **same defect
  class already retracted for T7** — `CellBoundary.keys` folds the declared
  dimensions into one union delta mask — and the repair was never propagated
  here. The narrowing of the crystallised region to `{privilege, credential}` is
  therefore **not forced by the index cap**, and the claim that a global
  zero-parameter rule cannot be crystallised as one cell is **withdrawn as
  unsupported**. It may still be true for other reasons; it is not true for this
  one.

---

## Corrections to the previous findings document

The earlier Stage 3 findings document carried figures this session could not
reproduce or could not trace to a producer. Nothing is deleted; each is paired
with what was measured instead.

| earlier figure | status here | measured this session |
|---|---|---|
| cell path 2.16× B3 µs/event at `loadavg` 16.45 | not reproduced at this load | 1.60× at `loadavg` 4.36; 1.59× at `loadavg` 6.06; 1.55× CPU-time ratio at 6.57 |
| incremental RSS 167,936 B | not reproduced exactly | 94,208 B / 159,744 B / 225,280 B across three runs, all far inside the 25 MB ceiling |
| `CellVM.run` is 15.6×–18.9× "a handwritten Python function" | **producer not found in the repository** | at the time: 235.05× against a handwritten `clamp01`, 4.06× against `_execute` — **themselves later withdrawn for the same reason**, see the repair-wave section and §9 |
| S3 "does not reproduce the Φ-oracle's scores" | true but understated | S3 returns the constant 1.0 on all 60 sessions of both classes |
| `audit_state` 183 B | 182 B this run | 182 B; a one-byte difference in a dict-size probe, recorded rather than smoothed |

The third row is the one that matters. A ratio that appears only in prose, with
no code in the repository that produces it, is not a measurement this project
accepts, and ADR-0021 cites it. Either a producer lands in
`pocketsec/stage3/bytecode/` or the figure should be withdrawn from ADR-0021 in
favour of a stated control.

**Closed by the repair wave, and it cut both ways.** The producer landed —
`pocketsec/stage3/bytecode/cost.py`, run by `pocketsec-stage3 vmcost`, payload at
`results/PS-S3-20260925-H4-vm-cost-split-0005.json`. It did **not** reproduce the
replacement figures in the right-hand column either: five repeats give
`run / _execute` 2.77×–7.06× and `run / handwritten` 388.51×–640.54×. So the row
above records one unsourced ratio being replaced by two more, and §9 now carries a
range from a named producer instead. The rule this table states was applied to the
table's own remedy.

---

## ADR status

Two documents disagree about which block Stage 3 owns, and the disagreement is
recorded rather than resolved unilaterally, because ADR numbers are a shared
resource across concurrent waves:

- `docs/architecture/stage-3-12-integration-plan.md` §5.5 assigns Stage 3
  **0013–0022**. Under that table 0013–0019 are unused, and the existing Stage 3
  ADRs 0023–0029 sit inside **Stage 4's** block 0023–0032.
- This wave's own instructions reserved Stage 3 **0020–0029** and forbade any
  number outside it. All ten of those exist in `docs/adr/`: 0020 through 0029.

Under the instruction that binds this session there is no free number, so no new
ADR was created — by either wave. The measurement wave's two records were made
**additively inside ADR-0021**, which is Stage 3's own ADR and carries the
overclaim, and are repeated here. The defect-repair wave made three more the same
way, each inside the ADR that carried the claim it corrects:

| ADR | what the repair wave added |
|---|---|
| **0021** | Correction 3 — the "2.9–4.9× band `verifier.py` reports" citation is false, and the 4.06× / 235.05× replacement ratios had no producer. A producer now exists; five repeats give ranges, not points. The decision is untouched. |
| **0025** | What G3.7 actually asserted (two of five conjuncts were vacuous), why `repair_locality` cannot falsify F2, and the flip side of the union delta mask this ADR cited as an enabler. The decision is untouched. |
| **0026** | The "strict superset" is withdrawn — two of the classes it named were fabricated by an attribution bug — and "nothing in the promotion path depends on guided search" was false when written. The decision is untouched; `CrystalConfig.strategy` now implements it. |

In all three the *decision* survived and the *recorded reason* did not. That
pattern is worth stating on its own: each ADR was correct about what to do and
wrong about why, and a reader who quoted the reason would have quoted something
that did not happen.

Nothing was deleted. A wave-coordination decision is needed before any of these
becomes a standalone ADR:

1. **Narrow ADR-0021.** Its title, "The Knowledge Cell format loses to the rule
   it wraps", claims more than the numbers support. What is measured is that the
   only executable operator form cannot express the target function and costs
   1.59–1.60× and 29.17× to return a constant. The amendment appended to
   ADR-0021 records this; the **retitling still needs a decision**, because
   renaming an accepted ADR changes how every citation of it reads.
2. **Withdraw the 4096-key structural claim.** Done in `labs/cell_path.py`, whose
   three docstring statements of it were corrected in place to what was measured,
   and in ADR-0021's amendment. Anything else citing it needs the same treatment.

---

## NOT A DETECTION RESULT

**No detection result in this document generalises.** Every corpus in this
repository is synthetic, and every run recorded here set `synthetic_data = True`.
ADR-0010 records that four synthetic corpora produced only trivial or impossible
tasks and never a middle band; real telemetry is required before any predictive
core can be judged. Stage 3 exercised parts of its **mechanism** — bytecode
bounds, boundary semantics, melt and rollback locality, the composition algebra,
the dual oracle's refusals, the field's refusal to evict — and establishes **no**
compression or detection claim that transfers to a real host.

B1, B2, B3 and B5 reaching 1.0000 says the splits are trivially separable, not
that any of them detects anything. The one figure in those tables worth carrying
forward is negative: the Knowledge Cell path sits at the base rate on **both**
corpora while every control sits at 1.0000, in the same runs.

Repair locality was measured against a corpus whose drift this project authored.
A drift the corpus designer planted is easier to localise than a drift reality
plants.

What Stage 3 has **not** shown, stated plainly so it cannot be read the other
way: that crystallisation produces a cell worth having; that the cell format
beats a plain lookup table; that guided boundary search beats random probing;
that any OPTIONAL component earns its place.

And one the defect-repair wave adds, because it is about this document rather than
about the corpus: **three of the four gate criteria this stage cited as its
strongest evidence were, until the repair wave, asserting less than the prose
around them claimed.** G3.7 passed a whole-cell discard; G3.12 passed with its
guard deleted; G3.4's stated reason named two counterexample classes that did not
exist; G3.6 could not pass under any state of the code. None of those was a wrong
detection number — they were a gate that would not have caught the regression it
existed to catch. A criterion that cannot fail is not evidence, and four of them
here could not fail in the way their own prose described.

---

## What would change this conclusion

Ranked by how much each would move the verdict, most first.

1. **An executor for `LOOKUP_TABLE`.** B1 reaches 1.0000 at 925 B on the same
   split. A `LOOKUP_TABLE` Knowledge Cell would carry the knowledge the
   `BYTECODE` cell cannot express, and the comparison against B1 — a boundary,
   an invariant, a melt path and an audit trail, against a bare dict — is the
   comparison the stage's claim actually rests on. Until that row exists, F1 is
   a statement about one ISA.
2. **A division or reciprocal opcode, or a squashing opcode, in the PCB ISA.**
   That alone would let the Φ-oracle be expressed exactly, at which point F1's
   "at identical scores" precondition can be met and the cost ratio becomes a
   real verdict rather than a partial one.
3. **A corpus with headroom for session-level scorers.** Both available corpora
   are DEGENERATE for Stage 3's baseline family. Without one, G3.11 cannot pass
   and no component can be justified or rejected on the merits. Note that the
   ambiguous corpus additionally leaks its label through vocabulary by +0.2346,
   so it is not the answer even after de-saturation work.
4. **Real telemetry.** Everything above is synthetic. A melt localisation
   measured against drift the project did not author would convert §4 from a
   mechanism demonstration into a finding.
5. **A frozen Stage 2 frontier measured on the drift corpus.** That closes G3.1
   without a cross-corpus comparison. It needs numpy in an offline producer that
   writes `results/`, the pattern Stage 2 already uses.
6. **An Oracle A that is not the Φ-oracle.** The dual oracle's job is to catch
   teacher error; while Oracle A is the same rule the cell wraps, G3.5 is a test
   of Oracle B alone, which is exactly how it is reported.

---

## Commands run, with their real output

Every figure above comes from one of these. Load averages are recorded because
this host was shared throughout. The measurement wave's commands come first; the
defect-repair wave's are under *Defect-repair wave commands* at the end, and its
loads are three to five times higher because a concurrent wave was running the
whole time. That is the reason no absolute microsecond figure from either wave is
offered as a device measurement.

```
$ uptime
 07:59:09 up 1 day, 22:18,  1 user,  load average: 3.72, 3.64, 4.89

$ cat /proc/loadavg          # before gate run 1
4.36 3.84 4.85 4/1812 3606369
$ python -m pocketsec.stage3.cli gate ; echo "exit=$?"
... full output in the gate result table above ...
GATE: FAILED (5 of 13)
exit=1
$ cat /proc/loadavg          # after gate run 1
4.73 3.92 4.88 14/1882 3606902
```

Gate run 1, criterion details that carry the numbers:

```
  [PASS] G3.2  At least four alternative baselines implemented
         5 controls on one split in one run (count=60, fit seed 3, eval seed 11,
         base rate 0.2833, loadavg 4.36): B1 PR-AUC 1.0000 at 14.6 µs/event, 925 B;
         B2 PR-AUC 1.0000 at 16.6 µs/event, 78 B; B3 PR-AUC 1.0000 at 16.6 µs/event,
         269 B; B4 PR-AUC 0.2919 at 15.1 µs/event, 6293 B; B5 PR-AUC 1.0000 at
         16.8 µs/event, 269 B; S3 PR-AUC 0.2833 at 26.6 µs/event, 7848 B.

  [FAIL] G3.9  Crystallised path costs no more than the Φ-oracle it wraps
         within one run at loadavg 4.36: the Knowledge Cell path costs 1.60x
         baseline B3's µs/event and 29.17x its bytes (7848 B vs 269 B). Scores are
         NOT identical: the cell path reaches PR-AUC 0.2833 against the base rate
         0.2833, while B3 reaches 1.0000. FALSIFIER F1 FIRES.

  [FAIL] G3.11  No surviving component lacks ablation-supported value
         saturation guard ran first and returned DEGENERATE: best 1.0000 and median
         1.0000 differ by 0.0000 <= 0.01; the split cannot tell models apart.
         0 ablation entries recorded; failed=[], not_yet_justified=[], rejected=[].

  [PASS] G3.10  Stage 3 incremental memory within the declared Edge budget
         measured through ResourceSampler over 256 frames at loadavg 4.73:
         incremental RSS 225280 B against the 26214400 B normal ceiling; per
         component boundary_index 5944/8388608 B, knowledge_cells 1904/20971520 B,
         cell_vm 488/8388608 B, audit_state 183/5242880 B,
         counterexample_hot 0/15728640 B; within_budget=True
```

Gate run 2, an independent process at a different load:

```
$ cat /proc/loadavg
5.98 8.10 8.60 ...
$ python -m pocketsec.stage3.cli --json gate ; echo "exit=$?"
passed: False
[('G3.1', False), ('G3.2', True), ('G3.3', True), ('G3.4', False), ('G3.5', True),
 ('G3.6', False), ('G3.7', True), ('G3.8', True), ('G3.9', False), ('G3.10', True),
 ('G3.11', False), ('G3.12', True), ('G3.13', True)]
exit=1
G3.9 detail: within one run at loadavg 6.06: the Knowledge Cell path costs 1.59x
baseline B3's µs/event and 29.17x its bytes (7848 B vs 269 B).
G3.10 detail: incremental RSS 159744 B against the 26214400 B normal ceiling
```

The five measurement subcommands:

```
$ python -m pocketsec.stage3.cli baselines        # loadavg 7.17
  id     PR-AUC   µs/event    bytes  description
  B1     1.0000      17.18      925  dict[BoundaryKey, float] on the quantised representation
  B2     1.0000      21.16       78  depth<=4 Gini tree on EncodedTransition features
  B3     1.0000      23.58      269  DeterministicScorerSpec at feature 73, no cell machinery
  B4     0.2919      19.69     6293  Stage 2 TransitionCache + lru_control over a frozen teacher snapshot
  B5     1.0000      20.41      269  Stage 1 Φ path plus a drift detector; invalidates everything on drift
  S3     0.2833      32.02     7848  BoundaryIndex.lookup + CellVM.run over a Φ-oracle KnowledgeCellV1

$ python -m pocketsec.stage3.cli melt             # loadavg 6.83
  repair_locality            1.0
  reopened_keys              [[2, 16, 5]]
  drifted_region_keys        [[2, 16, 5]]
  unrelated_cells_before     3
  unrelated_cells_retained   3
  surviving_cell             cell-spanning-v2
  reason                     PARTIAL_MELT: reopened 1 of 2 keys; 'cell-spanning-v2' keeps the rest

$ python -m pocketsec.stage3.cli pressure         # loadavg 6.83
  guided          49 probes, 12 classes
  random replay  256 probes, 14 classes
  found only by guided:        NONE
  found only by random replay: ['EVIDENCE_ABLATION:NEVER_DOWNGRADE_CONSEQUENCE',
                                'EVIDENCE_ABLATION:TEACHER_UNAVAILABLE']

$ python -m pocketsec.stage3.cli resources        # loadavg 6.50
  incremental RSS          94208 B
  peak sampled RSS         43700224 B
  audit_state              182 B
  boundary_index           5944 B
  cell_vm                  488 B
  counterexample_hot       0 B
  knowledge_cells          1904 B
  within budget            True

$ python -m pocketsec.stage3.cli crystallize      # loadavg 7.17
  region [0, 2048, 0]   -> RETURNED_TO_LEARNING  NO_SATISFIED_PREDICATE
  region [1, 2048, 0]   -> REFUSED_RESOLUTION    UNMEASURED: no admissible candidate carried a measured cost
  region [1, 2048, 64]  -> REFUSED_RESOLUTION    UNMEASURED: no admissible candidate carried a measured cost
  region [2, 2144, 0]   -> RETURNED_TO_LEARNING  NO_SATISFIED_PREDICATE
  region [2, 2144, 8]   -> RETURNED_TO_LEARNING  NO_SATISFIED_PREDICATE
  region [2, 2208, 8]   -> RETURNED_TO_LEARNING  NO_SATISFIED_PREDICATE
  region [2, 2208, 0]   -> RETURNED_TO_LEARNING  NO_SATISFIED_PREDICATE
  region [1, 2208, 64]  -> REFUSED_RESOLUTION    UNMEASURED: no admissible candidate carried a measured cost

$ python -m pocketsec.stage3.cli threats          # loadavg 6.68
  T1..T9 each: stopped with control: True; succeeded without it: True
  complete: True; unmitigated: none
```

The cell path's score distribution
(`results/PS-S3-20260925-H4-cell-path-constant-0002.json`):

```
cell path distinct scores: {1.0: 60}
phi oracle distinct scores: {0.2: 8, 0.219512: 35, 0.333333: 1, 0.372549: 4, 0.5: 4, 0.522388: 8}
cell score by label: {0: [1.0], 1: [1.0]}
phi score by label (min/max): {0: (0.2, 0.21951219512195122), 1: (0.3333333333333333, 0.5223880597014925)}
total frames: 2040
```

The boundary-key probe, same file:

```
MAX_KEYS_PER_CELL = 64
  1 dim(s) ['privilege']:                                    keys=8 accepted=True
  2 dim(s) ['credential', 'privilege']:                      keys=8 accepted=True
  3 dim(s) ['credential', 'persistence', 'privilege']:       keys=8 accepted=True
  4 dim(s) ['credential', 'persistence', 'privilege', 'trust']: keys=8 accepted=True
  9 dim(s) [all of DIMENSIONS]:                              keys=8 accepted=True
```

The verify-versus-execute ratio, as the measurement wave recorded it — kept
because retracted is not deleted, and **superseded**: the figures came from an
ad-hoc snippet rather than from anything in the repository, and §9 now carries a
five-repeat range from `pocketsec/stage3/bytecode/cost.py`:

```
loadavg 7.12  frames 512
CellVM.run        14.100 us/frame
CellVM._execute   3.471 us/frame
handwritten       0.060 us/frame
run / _execute    4.06x
run / handwritten 235.05x
```

The repair wave's producer, over the same 512 frames, five repeats:

```
$ cat /proc/loadavg
23.96 19.72 15.01 18/2065 574910
$ python -m pocketsec.stage3.cli vmcost
CellVM cost split, one run, best-of-7, 512 frames
  loadavg 24.98/19.69/14.92
  CellVM.run             32.494 us/frame
  CellVM._execute        7.773 us/frame
  handwritten control    0.091 us/frame
  run / _execute         4.18x
  run / handwritten      357.03x
# and, five repeats in one process (results/PS-S3-20260925-H4-vm-cost-split-0005.json):
run/_execute    min 2.77 max 7.06
run/handwritten min 388.51 max 640.54
$ cat /proc/loadavg
23.26 19.71 15.05 15/2063 575634
```

The Edge envelope and the flood bounds
(`results/PS-S3-20260925-H4-edge-envelope-0004.json`):

```
S3_cell_path loadavg 6.57
   cpu_s 2.3092 events 40800 cpu_s/event 5.659879835784313e-05
   peak_sampled_rss 39288832 delta_rss 176128 peak_rss 39092224
   model_bytes 7848 profile within_target True exceeded [] unmeasured []
B3_phi_oracle loadavg 6.57
   cpu_s 1.4901 events 40800 cpu_s/event 3.6521779705882356e-05
   peak_sampled_rss 39546880 delta_rss 0 peak_rss 39092224
   model_bytes 269 profile within_target True exceeded [] unmeasured []
within-run cpu ratio S3/B3 = 1.5497272809169012

  cells_inserted_before_refusal = 512
  field_refusal = FieldFull: KnowledgeField holds 512 cells, at its bound of 512;
                  forgetting is a GC decision with a recorded reason, never a side
                  effect of insertion
  field_bytes = 1033216      max_field_bytes = 20971520
  index_bytes = 119072       max_keys_per_cell = 64
  frame_flood: frames/pass 2040 passes 200 events 408000
     peak_sampled_rss 39714816 delta_rss 0 cpu_s/event 2.2555996345588238e-05 loadavg 6.61
```

The ambiguous-corpus probe
(`results/PS-S3-20260925-H4-ambiguous-saturation-0003.json`):

```
probe corpus stage3-ablation-probe-v0+stage1-ambiguous-v0.1.0
base_rate 0.3333 loadavg_before 12.38
refused True | baselines ['B4'] do not beat the base rate 0.3333; a control below
               chance is a bug and the comparison is refused, not reported
  B1  pr_auc=1.0    us=15.16 bytes=1280 beats_base_rate=True
  B2  pr_auc=1.0    us=17.55 bytes=78   beats_base_rate=True
  B3  pr_auc=1.0    us=17.54 bytes=269  beats_base_rate=True
  B4  pr_auc=0.3333 us=18.24 bytes=2782 beats_base_rate=False
  B5  pr_auc=1.0    us=18.9  bytes=269  beats_base_rate=True
  S3  pr_auc=0.3333 us=31.98 bytes=7848 beats_base_rate=False
saturation: {"best": 1.0, "degenerate": true, "median": 1.0, "spread": 0.0,
             "reason": "best 1.0000 and median 1.0000 differ by 0.0000 <= 0.01;
                        the split cannot tell models apart"}
identities reused across sessions: 0 of 448
median peak dphi: {'0': 2.25, '1': 8.0}
```

Corpus degeneracy, both corpora, one run:

```
drift (the gate's corpus, ADR-0028):
  pooled order-free PR-AUC 0.2982 vs base rate 0.2833 -> leak +0.0149
  identities reused across sessions 0 of 360
  median per-session peak |dPhi| by class {1: 8.0, 0: 2.25}
  distinct_epochs 3 corroborated 2
ambiguous (probe):
  pooled order-free PR-AUC 0.5679 vs base rate 0.3333 -> leak +0.2346
  identities reused across sessions 0 of 448
  median per-session peak |dPhi| by class {1: 8.0, 0: 2.25}
  distinct_epochs 1 corroborated 0
SATURATION_PR_AUC_BAND 0.01 ORDER_FREE_BAND 0.02
```

Tests:

```
$ python -m pytest tests/test_stage3_*.py -q ; echo "exit=$?"
........................................................................ [ 16%]
... 429 collected, all dots ...
exit=0

$ python -m pytest tests/ -q --tb=line -rf      # loadavg 7.78 -> 4.34
=========================== short test summary info ============================
FAILED tests/test_stage2_gate.py::test_a_probe_target_signature_is_never_a_causal_node_identity
exit=1
1218 tests collected; the one failure is in a Stage 2 file owned by the
concurrent wave.
```

Ledger:

```
$ python record.py            # appends four Stage 3 entries
integrity BEFORE: intact | entries: 25
registered PS-S3-20260925-H4-crystal-gate-0001       sha256:599be8b4...
registered PS-S3-20260925-H4-cell-path-constant-0002 sha256:323bb1f9...
registered PS-S3-20260925-H4-ambiguous-saturation-0003 sha256:a68afd44...
registered PS-S3-20260925-H4-edge-envelope-0004      sha256:5a70007b...
integrity AFTER: intact | entries: 29
```

---

## Defect-repair wave commands

Three gate runs, all six-failure, all exit 1. The host carried a concurrent wave
throughout; the load averages are three to five times the measurement wave's,
which is why no absolute microsecond figure from this wave is offered as a device
measurement and why §9 reports ranges.

```
$ cat /proc/loadavg          # before repair-wave gate run 1
9.70 10.47 8.35 16/1976 420490
$ python -m pocketsec.stage3.cli gate
...
GATE: FAILED (8 of 13)        # an intermediate state, mid-repair: G3.7 and G3.12
                              # were failing on the new conjuncts before the
                              # constructed probes they need were written

$ cat /proc/loadavg          # before repair-wave gate run 2
9.14 10.26 8.60 15/2040 441748
$ python -m pocketsec.stage3.cli gate
  [FAIL] G3.1  Stage 2 baseline frozen and reproducibly benchmarked
  [FAIL] G3.2  At least four alternative baselines implemented
  [PASS] G3.3  Cells carry versioned schema, bounded operator, explicit boundary
  [FAIL] G3.4  Boundary Pressure beats naive random replay
  [PASS] G3.5  Dual oracle prevents teacher-error crystallization
  [FAIL] G3.6  Promotion, auditing, partial and full melting work end-to-end
  [PASS] G3.7  Localized drift reopens a subregion without discarding unrelated knowledge
  [PASS] G3.8  Crystallized execution preserves evidence and causal attribution
  [FAIL] G3.9  Crystallised path costs no more than the Φ-oracle it wraps
  [PASS] G3.10  Stage 3 incremental memory within the declared Edge budget
  [FAIL] G3.11  No surviving component lacks ablation-supported value
  [PASS] G3.12  Formal-verification claims limited to properties actually proven
  [PASS] G3.13  Prior-art review completed before any external novelty claim
GATE: FAILED (6 of 13)

$ cat /proc/loadavg          # before repair-wave gate run 3 (after the gate_probes split)
15.48 20.21 18.86 8/1964 667222
$ python -m pocketsec.stage3.cli gate
... identical thirteen verdicts ...
GATE: FAILED (6 of 13)
```

B4 with and without the frozen snapshot, one process, same split:

```
$ cat /proc/loadavg
9.82 8.49 6.80 19/1970 372181
snapshot=None base_rate 0.2833333 refused False at_chance ('B4',)
    B1 pr_auc 1.0 margin 0.7166667 beats True bytes 925 us 19.74
    B2 pr_auc 1.0 margin 0.7166667 beats True bytes 78 us 30.08
    B3 pr_auc 1.0 margin 0.7166667 beats True bytes 269 us 33.15
    B4 pr_auc 0.2919118 margin 0.0085784 beats None bytes 6293 us 39.6
    B5 pr_auc 1.0 margin 0.7166667 beats True bytes 269 us 34.73
    S3 pr_auc 0.2833333 margin 0.0 beats None bytes 7848 us 53.94
snapshot=frozen base_rate 0.2833333 refused False at_chance ('B4',)
    B1 pr_auc 1.0 margin 0.7166667 beats True bytes 925 us 36.59
    B2 pr_auc 1.0 margin 0.7166667 beats True bytes 78 us 31.92
    B3 pr_auc 1.0 margin 0.7166667 beats True bytes 269 us 34.52
    B4 pr_auc 0.2919118 margin 0.0085784 beats None bytes 179202 us 44.59
    B5 pr_auc 1.0 margin 0.7166667 beats True bytes 269 us 39.97
    S3 pr_auc 0.2833333 margin 0.0 beats None bytes 7848 us 72.7
$ cat /proc/loadavg
10.56 8.69 6.88 19/2026 374076
```

Guided against random replay, after the attribution repair:

```
$ python -m pocketsec.stage3.cli pressure
Boundary Pressure: guided vs random replay at the same budget CAP (G3.4, falsifier F3).
The cap is shared; the spend is not — both probes_run figures are printed below.

  guided          49 probes, 12 classes
  random replay  256 probes, 12 classes

  found only by guided:        NONE
  found only by random replay: NONE
```

`predictive_stability` under both strategies, same cell, same seeds, one process:

```
$ cat /proc/loadavg
17.25 12.33 9.52 17/2031 462173
seeds 8
seed=11 budget=256 GUIDED: probes=49 div=48 stability=0.0204 unmeasured=42 | RANDOM_REPLAY: probes=256 div=255 stability=0.0039 unmeasured=222
seed=13 budget=64  GUIDED: probes=49 div=48 stability=0.0204 unmeasured=42 | RANDOM_REPLAY: probes=64  div=64  stability=0.0    unmeasured=57
seed=14 budget=64  GUIDED: probes=49 div=48 stability=0.0204 unmeasured=42 | RANDOM_REPLAY: probes=64  div=64  stability=0.0    unmeasured=57
$ cat /proc/loadavg
17.47 12.46 9.58 27/2026 462511
```

The melt experiment, reporting the facts F2 turns on rather than the ratio it does not:

```
$ python -m pocketsec.stage3.cli melt
Melting locality (G3.7, falsifier F2)

  reopened_keys              [[2, 16, 5]]
  drifted_region_keys        [[2, 16, 5]]
  survivor_in_field_and_index True
  survivor_keys              [[1, 16, 5]]
  survivor_keys_are_a_proper_subset True
  survivor_avoids_drifted_region True
  stale_cell_gone_from_field True
  unrelated_cells_before     3
  unrelated_cells_retained   3
  surviving_cell             cell-spanning-v2
  reason                     PARTIAL_MELT: reopened 1 of 2 keys; 'cell-spanning-v2' keeps the rest
  repair_locality_SANITY_CHECK_ONLY 1.0
```

CRYSTAL, unchanged by the repairs — 5 regions returned to learning, 3 refused on
UNMEASURED cost, zero promoted:

```
$ python -m pocketsec.stage3.cli crystallize | grep -oE "RETURNED_TO_LEARNING|REFUSED_RESOLUTION|PROMOTED" | sort | uniq -c
      3 REFUSED_RESOLUTION
      5 RETURNED_TO_LEARNING
```

The ledger, after registering the fifth Stage 3 experiment:

```
integrity BEFORE: intact | entries: 29
registered PS-S3-20260925-H4-vm-cost-split-0005 sha256:8f2854a85e6dd78...
integrity AFTER: intact | entries: 30
```
