# Stage 6 — HELIOS + MNEMOSYNE — findings

- **Date:** 2026-09-26
- **Status:** PARTIAL. **The stage's central claim is NOT supported by the measurements.**
  The boundary half holds under every attack built here (one writer, refused injections,
  byte-identical rollback, bounded stores, complete lineage on everything it installed). The
  learning half does not exist: across 4 corpus/threshold configurations x 2 mechanism
  configurations the Stage 6 learner installed **0 learned items**; the chamber issued 7
  learned candidates and the boundary refused **7 of 7** — correctly, because every one of them
  alerts on every held-out benign session (AP 0.5000, benign FP 1.0).
- **Spec:** `docs/stage-6-spec.md`. **ADRs:** 0050-0059 (block exhausted; the measurement
  verdict is a dated addendum to ADR-0058, M.14).
- **Part M** was written by the Stage 6 measurement wave. Every number in it was produced by
  running code in the measurement session; commands, seeds, corpora and loadavg are in the
  MEASURED table and Appendix B. The integration wave's document is preserved verbatim in
  Appendix A; where Part M supersedes it, Part M says so.
- **Review-fix session (later on 2026-09-26): read M.15 before quoting anything here.** An
  independent review confirmed defects that change several statements below (the drift
  discriminator's "3/3 false POISON_SUSPECT", the G6.3 PASS, stage2-only's "0 poisoned", the
  2.1x memory figure, the G6.1-on-the-current-tree claim, and a GROUND_TRUTH bypass of every
  label defence). Each affected line is marked **[CORRECTED, M.15]** where it stands; M.15
  gives the fix, the regression test and the re-measured figure.
- **Every corpus is synthetic.** Nothing here is a detection result. Load average ranged
  4.6-27.6 during the session because another wave (Stage 7) was building in this tree; only
  within-run ratios are quoted as comparisons, never an absolute time as a device figure.

## M.0 The result in one paragraph

Stage 6 was specified so that "the deliverable is the quarantine -> validation -> promotion
boundary; the cleverness of the learner is optional." Measured, that is what exists. The
boundary refuses what it should (6/6 injections with 0 digest changes; 28/28 operator
rollbacks byte-identical; 39/39 rollbacks to evicted states refused; 0 spurious rollbacks in
720 benign probation sessions; every store under its cap through a 20 000-capsule flood and
288 synthetic months), and it also refuses what the learner proposes — correctly, because the
only detector the chamber induces on this corpus is "`IMPERSONATE` followed by anything",
which matches every session. No configuration produced a candidate the boundary should have
accepted. So every Stage 6 poisoning result is accept-nothing equivalence (F10), every
anti-forgetting figure is 0.0 of nothing, and turning all six OPTIONAL mechanisms off changes
nothing in any configuration. On threshold-free ranking over the whole year, the unguarded
`FullRetrain` baseline reaches AP 0.8692 (recall@FPR0.05 0.674) where Stage 6 is at the base
rate 0.5000. A second finding cuts across every baseline: the §7 baselines' threshold refit
puts their operating threshold just above their own detector weights, so `FullRetrain`,
`Stage2Only` and `CalibrationOnly` alert on *nothing* at their own threshold; their "benign FP
0.0" is not precision (M.3). Recommendation (M.13): keep the boundary as the only writer,
reject the learner as built, default-off every OPTIONAL mechanism, ship no learned state.

## M.1 The gate, reproduced — and then broken by another wave's file

`PYTHONHASHSEED=0 .venv/bin/python -m pocketsec.stage6.cli gate` (13:06-13:16) ->
**6/13 criteria met, GATE: FAILED (7), exit 1**, 9 min 25 s wall (513.11 s user), loadavg at
end `8.16 11.62 13.41`. Identical PASS/FAIL per criterion to the integration wave.

The registration run, `pocketsec-stage6 experiments --register` (14:06-14:13), re-ran the gate
and recorded **5/13, FAILED (8), exit 1**: G6.1 flipped to FAIL. Cause, measured:
`sealed_name_violations()` now returns
`stage7/gate_boundary.py:131 _install_trusted`, `:131 _trusted_state`, `:132 _issue_verdict`,
`:132 _issued_verdicts`. The Stage 7 wave's new gate module (written 14:1x) spells four Stage 6
sealed names as string literals in its own `STAGE6_WRITER_NAMES` set, and Stage 6's rule 4
treats any spelling anywhere under `pocketsec/` as a violation. The same file makes
`tests/test_stage6_boundary.py::test_trusted_state_has_exactly_one_writer_across_the_repository`
and `::test_minting_names_appear_only_in_the_module_that_mints` fail (M.12). No Stage 6 code
changed; this is a cross-wave seam defect for the project lead (Stage 7 could import the
owners' `SEALED_NAMES` instead of spelling them), not a Stage 6 regression. This wave did not
edit Stage 7. **[CORRECTED, M.15]** This was true of the 14:06 run only. `gate_boundary.py` was
rewritten 13 seconds after this document was last saved; on the tree the review-fix session
ran against, `sealed_name_violations()`, `import_violations()` and `upstream_dependents()`
return `()`, and the two boundary tests pass. G6.1's result on the current tree is in M.15 —
and G6.1 as it stood could not see an `observe()` that writes trusted state behind the
installer (review F1, medium), so its earlier PASS is not evidence of the single-writer
invariant either; probe (d) was added.

| id | 13:06 run | the figure that decided it |
|---|---|---|
| G6.1 | PASS (FAIL at 14:06, above) | 6/6 injections refused, 0 digest changes; §0 probe 25 refusals / 0 admissions (control 3); 5 chamber faults, 0 digest changes |
| G6.2 | FAIL | VACUOUS: 0 learned items in 12- and 60-month runs; tamper probe detected; lineage-less item refused at load |
| G6.3 | PASS **[CORRECTED, M.15: vacuous]** | 1 promotion examined, 0 violations; rig F1-removal candidate REJECTED. The one promotion had identical before/after items and recall 0.0 in every family, so no regression was possible; and the metric re-chose its own threshold, so a threshold-only blinding promotion showed 0 violations |
| G6.4 | FAIL | Stage 6 poisoned 0 at x1/x4/x16 on P1, P2 — clean 0 (F10) |
| G6.5 | FAIL | VACUOUS: M01 benign FP 1.0; F1 never acquired |
| G6.6 | PASS | every isolation check holds |
| G6.7 | PASS | 0 authority/seam hits; 14 canary observations, emitted < trusted 0 |
| G6.8 | PASS | 1 automatic probation rollback, byte-identical; corrupted fossil skipped |
| G6.9 | FAIL | 11 arms fired; Stage 6 clean rate 0.0 on every arm |
| G6.10 | FAIL | incremental RSS 512000 B (ceiling 104857600); M11 deferral never fired |
| G6.11 | PASS | construction holds; work-unit ratio 84.418 (not a cost measure, M.10) |
| G6.12 | FAIL | 60 months: no cap exceeded, 8 stores still growing |
| G6.13 | FAIL | preconditions DEGENERATE; 5 of 8 OPTIONAL rows INERT/UNMEASURED; synthetic |

## M.2 The corpus has headroom, but E3 is DEGENERATE

`check_preconditions`, 12-month timeline, seed 11 (PS-S6-20260926-H6-learnability-0002):

| precondition | measured | holds? |
|---|---|---|
| E1 oracle recall at FPR 0.05 | F1 1.0, F2 1.0, F3 1.0 | yes |
| E2 control AP <= 0.9 | lineage-dPhi 0.5776 (0.5766 at 64/month), any-escalation 0.5, never-update 0.6069 | **yes — not saturated** |
| E3 naive(cap 4) F1 at M12 <= never-update - 0.10 | 0.0 vs 0.0 | **no** |
| E4 never-update F2/F3 <= 0.5 | 0.0 / 0.0 | yes |
| E5 bag-of-relations AP within 0.05 of 0.5 | 0.4951 (0.5160 at 64/month) | yes, no vocabulary leak |

E3 fails because never-update's own F1 recall at FPR 0.05 drops from 1.0 (M02-M08) to 0.0
(M09-M12) when twin T3 (admin `setuid -> read CREDENTIAL`, no egress) enters the eval
negatives. That is a genuine refinement test; `FullRetrain` passes it per month (F1 retention
1.0 at M12). The DEGENERATE verdict is about the E3 rule, not an absence of signal.

## M.3 Security quality against the §7 baselines

`benchmarks/stage6/learnability.py --spm 16 64 --threshold default 0.6`
(PS-S6-20260926-H6-learnability-0002). Identical compiled stream for every learner; all use
`induce_motifs` and `score_session`. **acq/ret** are per-month recall at FPR 0.05 (the §7
definition: the metric re-chooses the threshold). **AP** is `average_precision` over all 336
eval sessions of the year (16/month). **mean FP** is the benign rate at the learner's *own*
threshold, averaged over 12 month-ends. "poisoned" counts items whose lineage cites a poison
capsule. **[CORRECTED, M.15]** That column is *poisoned additions, label-flip blind*: a
label-flip's effect is to remove or suppress a detector, which it cannot see, and a labelled
poison session's episode id was not a poison id. Removals are now counted (M.15, table M15-2). `stage6-minimal` = Stage 6 with all six OPTIONAL mechanisms off (independence,
homeostasis, G4 stay on).

**16 sessions/month, shipped threshold 0.5:**

| learner | learned items | poisoned additions (label-flip blind) | acq F1/F2/F3 | F1 ret M08 / M12 | mean FP (own thr) | AP | work units | stored B (self-reported estimate, not comparable across learners, M.15) |
|---|---|---|---|---|---|---|---|---|
| never-update | 7 | 0 | 1.0 / 0.0 / 0.0 | 1.0 / 0.0 | 0.417 | 0.6069 | 67699 | 3045892 |
| calibration-only | 7 | 0 | 1.0 / 0.0 / 0.0 | 1.0 / 0.0 | 0.000 * | 0.6069 | 915430 | 3045892 |
| naive-finetune | 18 | 12 | 1.0 / 1.0 / 0.0 | 0.0 / 0.0 | 0.295 | 0.7237 | 440921 | 3045892 |
| reservoir-65536 | 25 | 12 | 1.0 / 1.0 / 0.0 | 0.0 / 0.0 | 0.462 | 0.6894 | 546430 | 3109187 |
| full-retrain | 16 | 12 | 1.0 / 1.0 / 1.0 | 1.0 / 1.0 | 0.000 * | **0.8790** | 252579 | 3348005 |
| prototype-centroid | 16 | 12 | 1.0 / 1.0 / 0.0 | 0.0 / 0.0 | 0.300 | 0.6894 | 56168 | 3045892 |
| stage2-only | 15 | **0** | 1.0 / 1.0 / 0.0 | 0.0 / 0.0 | 0.056 * | 0.7302 | 412138 | 3045892 |
| **stage6** | **0** | 0 | 0.0 / 0.0 / 0.0 | 0.0 / 0.0 | 1.000 | **0.5000** | 2992 | 7049317 |
| stage6-minimal | 0 | 0 | 0.0 / 0.0 / 0.0 | 0.0 / 0.0 | 1.000 | 0.5000 | 2992 | 7079632 |

\* **The baselines' own operating point alerts on nothing** (PS-S6-20260926-H6-candidate-quality-v2-0014,
final states scored on all 576 eval sessions of the year): full-retrain's refitted threshold
is 0.900001 against detector weight 0.9 — operating recall 0.0 on F1, F2 and F3, benign FP
0.0; stage2-only's is 0.666668 against its detector score 0.667 — operating recall 0.0,
FP 0.0. Only never-update keeps a working operating point (threshold 1e-06: F1 recall 1.0,
F2/F3 0.333, benign FP 0.361). The baselines' ranking is real (full-retrain AP 0.8692,
recall@FPR0.05 0.674 over the pooled year; stage2-only AP 0.6240, recall@FPR0.05 0.0); their
"FP 0.000" is not. This is a defect in `labs/continual_baselines.py`'s threshold refit, not in
Stage 6; it means the gate's FP comparisons against the baselines compare against learners
that alert on nothing.

At the diagnostic threshold 0.6 every baseline row is identical (prototype-centroid mean FP
0.222); Stage 6 and stage6-minimal move only their FP (1.000 -> 0.000: alerting on nothing
instead of everything) and still learn 0 items, AP 0.5000. At **64 sessions/month** (shadow
window full at M02 instead of M08): full-retrain AP 0.8754, 20 poisoned items; stage2-only AP
0.6025, 10 items, 0 poisoned; never-update AP 0.6069; Stage 6 and stage6-minimal 0 items, AP
0.5000 at both thresholds, stored 11685026 / 12052405 B.

Against spec §7 (all on ranking, since no learner but never-update has an operating point):

- **vs NeverUpdate:** Stage 6 R_new 0.0 vs 0.0 and R_old 0.0 vs 1.0 at M08 — fails both (F6).
- **vs FullRetrain:** R not comparable (0.0 vs 1.0 per month); cost moot; Stage 6 stores more.
- **vs Stage2Only:** ~~both 0 poisoned items on the endurance timeline~~ **[CORRECTED, M.15]**
  both 0 poisoned *additions*; but the M10 label-flip poison removed 2 of stage2-only's
  detectors in the update right after a poison capsule (measured, M15-2), which the additions
  count could not see. Stage2Only ranks better (0.7302 vs 0.5000) — F8 on this timeline.
- **vs CalibrationOnly:** CalibrationOnly AP 0.6069 > Stage 6 0.5000.

## M.4 Why Stage 6 learns nothing — every candidate, and whether refusing it was right

`benchmarks/stage6/refusal_census.py` (PS-S6-20260926-H6-refusal-census-0003) and
`benchmarks/stage6/candidate_quality.py` (PS-S6-20260926-H6-candidate-quality-0012, v2 -0014).

| config | candidates issued | carrying learned items | fate | failing check (measured) | promoted |
|---|---|---|---|---|---|
| 16/month, 0.5 | 2 | 1 (4 DETECTOR) | REJECTED | G3 recall_gain 0.0 < 0.01 | 1 CONSOLIDATION, 0 items |
| 16/month, 0.6 | 2 | 1 (4 DETECTOR) | REJECTED | G8 disagreement_rate 0.96875 > 0.10 | 1, 0 items |
| 64/month, 0.5 | 6 | 3 (4 DETECTOR each) | REJECTED x3 | G3 0.0, 0.0, UNMEASURED (holdout 0/0) | 3, 0 items |
| 64/month, 0.6 | 6 | 3 (4 DETECTOR each) | REJECTED x3 | G8 1.0, 0.984375; G3 UNMEASURED (holdout 0/0) | 3, 0 items |

**7 of 7 learned candidates refused; 8 of 8 promotions carried no learned item.** Every one of
the 7, scored on all 576 held-out eval sessions: benign FP **1.0**, F1/F2/F3 operating recall
1.0, AP **0.5000**, recall@FPR0.05 0.0 — it alerts on everything and ranks nothing. Their
motifs: `IMPERSONATE[req=0,forbid=0,raised=0]` alone, or followed by an unconstrained
`WRITE`/`READ`. The same `induce_motifs`, run by full-retrain over all retained labelled
history, yields refined motifs such as `READ[forbid=16,raised=4] -> CONNECT[req=128]` and
`IMPERSONATE -> WRITE[req=64,forbid=4]`. **The refusals were right; the chamber is what
fails.** Its input is small: in 12 months (16/month, 0.5) the gateway bucketed 139 UNCERTAIN /
77 TRUSTED_CANDIDATE / 28 HOSTILE_SUSPECT of 244 capsules; 12 learning episodes were admitted;
learning was deferred 7 month-ends (replay ring < 128) and 3 (probation); the drift
discriminator classed 3/3 corroborated changes POISON_SUSPECT and dropped 13 admissions
**[CORRECTED, M.15: a harness wiring defect — the window it was given held no verdict from
before the change; fixed, the same run now gives 3/3 UNDETERMINED and 0 dropped]**; the
chamber spawned 2, returned `None` once, and its holdout held 0-4 episodes. At 64/month the
ring fills at M02, the chamber spawns 8 times, the discriminator drops 65 admissions (the same
wiring defect, M.15; not re-measured at 64/month), and the outcome is the same.

## M.5 Poisoning — built, fired, measured against Stage 2 alone

### The eleven spec arms (PS-S6-20260926-H6-poison-suite-0006, shipped threshold)

Poisoned promotions at x1 / x4 / x16.

| arm | class | naive-finetune | stage2-only | stage6 poisoned | stage6 clean rate | verdict |
|---|---|---|---|---|---|---|
| P1 | DATA | 1/1/1 | 0/0/**1** | 0/0/0 | 0.0 | ACCEPT_NOTHING_EQUIVALENT |
| P1b | DATA | 1/1/1 | 0/0/**1** | 0/0/0 | 0.0 | ACCEPT_NOTHING_EQUIVALENT |
| P2 | SLOW_DRIFT | 2/2/2 | **2/2/2** | 0/0/0 | 0.0 | ACCEPT_NOTHING_EQUIVALENT |
| P2b | SLOW_DRIFT | 1/1/1 | **1/1/1** | 0/0/0 | 0.0 | ACCEPT_NOTHING_EQUIVALENT |
| P3 | LABEL | 2/2/2 | **2/2/2** | None (VACUOUS) | 0.0 | UNMEASURED |
| P3b | LABEL | 4/4/4 | **4/4/4** | None (VACUOUS) | 0.0 | UNMEASURED |
| P4a | MODEL | n/a | n/a | 0/0/0 | 0.0 | ACCEPT_NOTHING_EQUIVALENT |
| P4b | MODEL | n/a | n/a | 0/0/0 | 0.0 | ACCEPT_NOTHING_EQUIVALENT |
| P4c | MODEL | 1/1/1 | 0/0/0 | 0/0/0 | 0.0 | ACCEPT_NOTHING_EQUIVALENT |
| P5 | SLOW_DRIFT | 1/1/1 | 0/0/0 | 0/0/0 | n/a | HELD_BY_STAGE2_ALONE |
| P6 | DATA | 1/1/1 | 0/0/0 | 0/0/0 | 0.0 | ACCEPT_NOTHING_EQUIVALENT |

Stage2Only's clean rate on the data/drift arms is 0.5-1.0. **The arms Stage 2 alone fails are
P1@x16, P1b@x16, P2, P2b, P3, P3b** — the only arms on which Stage 6 could have shown its
poisoning layer is worth having. On all six Stage 6 held at 0 poisoned and learned 0 clean, so
nothing shows that a Stage 6 defence, rather than the absence of learning, did the holding. At
threshold 0.6 (PS-S6-20260926-H6-poison-suite-diag-0007) every Stage 6 row and verdict is
identical.

### Slow drip over many corroborated epochs

`benchmarks/stage6/slow_drip.py --epochs 2 4 8` (PS-S6-20260926-H6-slow-drip-0004; at 0.6,
PS-S6-20260926-H6-slow-drip-diag-0005, identical Stage 6 rows). 2 poison sessions per epoch,
after a 160-session warm-up that fills the shadow window.

| drip | epochs | poison offered | naive poisoned / clean | stage2-only poisoned / clean | stage6 poisoned / clean |
|---|---|---|---|---|---|
| DRIP-DATA (P1 staging, fresh lineage each session) | 2 / 4 / 8 | 4 / 8 / 16 | 1 of 1 / 3 of 4 | **0 of 1 / 3 of 4** | 0 of 1 / 0 of 4 |
| DRIP-LABEL-1G (one analyst group says BENIGN on F2) | 2 / 4 / 8 | 4 / 8 / 16 | 2 of 2 / 0 of 2 | 2 of 2 / 0 of 2 | None (VACUOUS) / 0 of 2 |
| DRIP-LABEL-2G (two colluding groups) | 2 / 4 / 8 | 8 / 16 / 32 | 2 of 2 / 0 of 2 | 2 of 2 / 0 of 2 | None (VACUOUS) / 0 of 2 |

- **Poisoned vs clean promotion rate, Stage 6: 0/1 vs 0/4** at every epoch count — equal
  because both are zero. **Stage 2 alone: 0/1 vs 3/4** — it separates the data drip and learns.
- The label drips suppress both F2 targets for NaiveFinetune and Stage2Only (Stage 2 has no
  label path). For Stage 6 they are VACUOUS: it never detected F2, so neither the one-group
  attack nor the two-group attack on `MIN_INDEPENDENT_LABEL_GROUPS = 2` could be measured.
  **Whether the label quorum resists two colluding groups is UNMEASURED.**
- ~~The drift discriminator dropped 8 / 13 / 26 normality admissions at 2 / 4 / 8 epochs: every
  corroborated change is classed POISON_SUSPECT, so frequent legitimate epochs starve normality
  learning outright.~~ **[CORRECTED, M.15]** That measured the harness, not the mechanism: the
  window handed to `drift_signals` never held a verdict from before the change, so every key
  counted as "changed" and POISON_SUSPECT was forced. Re-measured after the fix in M.15. The
  independence check refused 22 single-source offers per run.

## M.6 Anti-forgetting — against never-update and full retrain

Stage 6 F1 retention 0.0 at M08 and M12 in every configuration; never-update 1.0 then 0.0;
full-retrain 1.0 and 1.0 (per-month recall at FPR 0.05). Value-aware rehearsal vs reservoir at
16/64/256 KiB (gate G6.13): 0.0 vs 0.0 at every budget. Stage 6 never acquired anything to
retain. **The anti-forgetting stack is NOT-JUSTIFIED.** On this corpus only the unguarded
full-retrain keeps F1 through the look-alike twin — in ranking; at its own threshold it alerts
on nothing (M.3).

## M.7 Ablation — does each component earn its existence?

Rule C firing counts on the 12-month run (gate G6.13, this session): HEL-F07 half-life 0,
HEL-F10 competition 0, HEL-F21 resurrection 0, HEL-F25 retire 0 -> **INERT**. HEL-F08
plasticity field 3, HEL-F15 value-aware rehearsal 1, HEL-F19 drift discriminator 3 (3/3 false
POISON_SUSPECT **[CORRECTED, M.15: forced by the harness's empty pre-change window; re-run
after the fix: 3/3 UNDETERMINED, 0 admissions dropped, so no outcome changed]**) -> fired,
delta 0.0. HEL-F11 UNMEASURED (no G4 switch). The joint control —
`stage6-minimal`, all six flags off — gives the identical outcome (0 items, AP 0.5000, same
poisoned count) in 4/4 configurations. **No OPTIONAL mechanism has a measured benefit.** Those
that fire do nothing ~~or harm (the discriminator's firings are all false and drop every
post-change normality admission)~~ **[CORRECTED, M.15: the "harm" was the harness defect;
with a correct window the discriminator changes no outcome on this corpus — NOT-YET-JUSTIFIED,
not harmful]**. The REQUIRED checks do fire and do their job: G3 and G8
refused 7/7 bad candidates; the independence check refused 25 offers in the §0 probe and 22
per drip run.

## M.8 Rollback, canary and shadow — reversibility under repetition

`benchmarks/stage6/rollback_stress.py --promotions 45 --regressions 30`
(PS-S6-20260926-H6-rollback-stress-0009) on the gate's rig: the real controller, fossil store
on disk and lineage DAG, with a lab chamber (this measures the one writer, not what the real
chamber would propose). Rig windows: canary 8, probation 16.

| probe | measured |
|---|---|
| promotions walked submit -> shadow -> canary -> trusted | 45 / 45 |
| spurious rollbacks on benign probation (45 x 16 = 720 sessions) | **0** |
| trusted items with `lineage_complete` after 45 promotions | 46 / 46; `verify()` problems 0 |
| regression visible in the canary window, protected-anchor session | rejected at canary, never installed: 5 / 5 |
| regression visible on probation traffic, protected-anchor session | automatic rollback 3 / 3; digest and bytes identical 3 / 3 |
| regression visible (canary or probation), **unprotected** session | **acted on 0 / 12** — counted, not rolled back |
| regression never visible on live traffic | kept 10 / 10 (the rehearsal-gap limit) |
| operator rollback to every fossil still held | 28 / 28 digest- and byte-identical (never collected lineage — see M.15 for the run that does) |
| rollback to a state whose fossil was evicted (68 states, `MAX_FOSSILS` 32) | refused 39 / 39 |
| rollback to a digest never fossilised | refused |

**A canary or probation regression rolls back only when the regressing session touches a
protected anchor** (8/8 protected, 0/12 unprotected). That is the documented `CanaryPolicy`
(no knob for unprotected regressions, `shadow/canary.py`), and a chosen parameter; it means
"a canary regression triggers rollback rather than being logged" holds only for protected
anchors.

## M.9 Provenance and lineage

On the rig 46/46 trusted items resolve their lineage, `verify()` reports 0 problems (M.8).
**[CORRECTED, M.15]** On the rig the CAPSULE and VERDICT nodes are written by the lab chamber
itself, so this figure measures DAG bookkeeping, not gateway provenance; and until the M.15
fixes a capsule the gateway *refused* (DISCARD, HOSTILE_SUSPECT) counted as admitted, a folded
non-capsule id counted as an admitted capsule, and a learned THRESHOLD kept genesis lineage. The
gate's tamper probe is detected and a lineage-less item is refused at load (G6.1/G6.2). On the
endurance, 60-, 180- and 288-month runs the check is VACUOUS: no learned item was ever trusted.

## M.10 Resource cost

`benchmarks/stage6/resources_compare.py --spm 16 --repeats 3`
(PS-S6-20260926-H6-resources-compare-0010): each learner in a fresh process, same compiled
stream, Stage 0 `ResourceSampler`; loadavg 20.4-26.2 (contended — ratios only).

| learner | CPU s (median of 3) | CPU ratio to Stage 6, per repeat | delta RSS max (B) | stored B | trusted-state B |
|---|---|---|---|---|---|
| stage6 | 3.104 | 1.0 / 1.0 / 1.0 | 1146880 | 7049317 | 63788 |
| full-retrain | 5.310 | 1.723 / 1.485 / 1.711 | 360448 | 3348005 | 16748 |
| never-update | 3.514 | 1.130 / 1.226 / 1.132 | 344064 | 3045892 | 9195 |
| naive-finetune | 4.813 | 1.556 / 1.729 / 1.551 | 348160 | 3045892 | 19032 |
| stage2-only | 4.574 | 1.467 / 1.634 / 1.491 | 364544 | 3045892 | 16446 |
| reservoir-65536 | 5.873 | 1.883 / 2.113 / 1.819 | 282624 | 3109187 | 30528 |

- Stage 6 is the cheapest in CPU **because it learned nothing** and scores with a one-item
  state; it is not a cost win (F7 moot while R is not comparable).
- **Stage 6 costs more memory than the unbounded full-retrain baseline** — the direction
  holds; ~~2.1x its stored bytes (7049317 vs 3348005; 2.7x at 64/month)~~ **[CORRECTED, M.15:
  the two sides of that ratio use different estimators (baselines: canonical capsule bytes;
  Stage 6: fixed per-step constants that are ~81% of its total), so the 2.1x is not a memory
  measurement; one method applied to every learner is in M15-2]**, ~3.2x its RSS increment,
  and a 63788-byte trusted state that holds one THRESHOLD item.
- **Correction to G6.11's 84.418:** `WorkMeter` counts item x step comparisons and motif
  evaluations only; gateway, ledger, lineage, fossil and replay work is unmetered. In CPU
  seconds full-retrain costs 1.49-1.72x Stage 6, not 84x.
- Edge envelope: every child `within_target` True, peak sampled RSS 89.6 MB, of which ~88.7 MB
  is the idle process holding the compiled corpus; the learner's own increment is 1.0-1.15 MB.
  `pocketsec-stage6 --json resources` (14:06, loadavg `7.33 14.5 15.91`): incremental RSS
  552960 B, peak 93814784 B, 1.353 CPU s for 244 events, model bytes 63788, within ceiling and
  edge target, consolidator deferred 0. The gate's own run: 512000 B. Dev host, not a 2 GB
  device.

## M.11 Bounds — flood, and a horizon almost five times the gate's

### Flood (PS-S6-20260926-H6-flood-bounds-0008)

20 000 unseen-signature capsules (one compiled attacker session re-sealed with fresh groups,
evidence and a random object-semantics pattern each), every 16th offer a legitimate labelled
pair, consolidation every 16 episodes, all through `StageSixLearner.observe`. 272.6 s wall,
loadavg `13.01 12.8 14.27` -> `21.33 16.69 15.43`.

| store | max count / cap | max bytes / cap | evictions | verdict |
|---|---|---|---|---|
| gateway (issued verdicts) | 4096 / 4096 | 2288969 / 15728640 | 38152 | at cap, evicting |
| provenance ledger | 4096 / 4096 | 7341740 / 15728640 | 15964 | at cap |
| lineage DAG | 4061 / 8192 | 3966890 / 10485760 | 40840 folded | sawtooth under cap |
| replay ring | 256 / 256 | 2211840 / — | 20994 | at cap |
| episodic, fossils, controller, chamber, contexts, trusted | 4, 2, 5, 3, 1, 1 | far under | 0 | flat |

Process RSS 48.4 MB after 500 capsules, 55.9 MB at 3000, 59.0 MB at 5500, 59.7 MB at 8000,
59.9-60.1 MB from 10 500 to 20 000 — **a plateau**. The gateway's pattern table filled at 512
and refused 146525 step-pattern offers. Post-flood probe, 64 fresh routine sessions: **165**
step patterns refused tracking after the flood vs **0** on a fresh learner (11 tracked). A
flood locks legitimate normality patterns out of tracking; whether that changes an admission
is UNMEASURED (the unflooded control admitted nothing from those 64 sessions either).
**[CORRECTED, M.15]** The lock-out was permanent (review S6-AUTH-07): tracks were never
retired. They now are (least recently seen first, uncorroborated first, counted); the flood
figures under the fix are in M.15.

### Horizon: 180 and 288 months (PS-S6-20260926-H6-horizon-0011, PS-S6-20260926-H6-horizon-long-0013)

Per-cycle maximum count; one `StageSixLearner`; the synthetic year repeated 24 times (the
15-cycle run agrees on every shared year). Run 92.6 s, loadavg 3.98-5.63.

| store | yr 1 | yr 5 | yr 10 | yr 15 | yr 17 | yr 24 | cap | verdict |
|---|---|---|---|---|---|---|---|---|
| gateway | 244 | 1220 | 2440 | 3660 | 4096 | 4096 | 4096 | **cap binds at year 17**, 6112 evictions |
| ledger | 244 | 1220 | 2440 | 3660 | 4096 | 4096 | 4096 | **cap binds at year 17**, 1760 evictions |
| fossils | 5 | 13 | 23 | 30 | 32 | 32 | 32 | **cap binds at year 16**, 28 evictions |
| lineage DAG | 507 | 2514 | 927 | 3425 | 4095 | 3817 | 8192 | sawtooth: folds at 4096 (8235 folded) |
| contexts | 3 | 15 | 16 | 16 | 16 | 16 | 16 | cap from year 5, 56 evictions |
| replay ring | 192 | 256 | 256 | 256 | 256 | 256 | 256 | cap from year 2 |
| episodic | 28 | 124 | 184 | 244 | 268 | 352 | 576 | **still growing, +12/year** |
| controller decisions | 11 | 44 | 84 | 118 | 141 | 208 | 256 | **still growing** |
| chamber issued | 4 | 19 | 37 | 53 | 60 | 80 | 256 | **still growing** |
| trusted items | 1 | 1 | 1 | 1 | 1 | 1 | 257 | flat (nothing learned) |

Every store stays under its cap for 288 months. The plateau G6.12 asks for appears only where
a cap binds, and for gateway, ledger and fossils that takes 16-17 synthetic years; episodic,
controller and chamber are still rising linearly at year 24 and would reach their caps at
roughly years 43, 30 and 70 by linear extrapolation (not measured). Boundedness is by
construction (caps with recorded eviction), not by saturation of what is learned — and on this
corpus nothing is learned.

## M.12 Tests run in this session

- `PYTHONPATH=. pytest tests/test_stage6_*.py` (system pytest; `.venv` has none), 13:12-13:24:
  **404 tests: 403 passed, 1 failed, 1 error**, 687.95 s. Both were registry-byte-identity
  assertions in `tests/test_stage6_gate.py`, caused by **this session**: `learnability.py
  --record` appended a ledger row at 13:33 while the test ran.
- Re-run with no concurrent writer, `pytest tests/test_stage6_gate.py tests/test_stage6_boundary.py`
  (14:14-14:18): **58 tests, 56 passed, 2 failed**, 238.9 s. `test_stage6_gate.py` all pass.
  The 2 failures are the Stage 7 seam of M.1:
  `test_trusted_state_has_exactly_one_writer_across_the_repository` and
  `test_minting_names_appear_only_in_the_module_that_mints`, both on
  `pocketsec/stage7/gate_boundary.py:131-132`. They passed in the 13:12 run, before that file
  existed. **[CORRECTED, M.15: stale — both pass on the current tree; see M.15 for this
  session's test run.]**
- The adversarial tests the lead named exist and passed in the 13:12 run:
  `tests/test_stage6_gateway.py::test_a_sample_injected_straight_from_telemetry_is_refused`,
  `tests/test_stage6_promotion.py::test_private_installer_refuses_an_unminted_decision`,
  `::test_raw_telemetry_hand_built_candidates_and_unknown_rollbacks_are_refused`,
  `tests/test_stage6_endurance.py::test_raw_telemetry_never_moves_the_stage_six_digest_between_consolidations`,
  and the AST single-writer test with its negative fixture
  `tests/test_stage6_boundary.py::test_the_single_writer_rule_catches_every_way_to_name_the_installer`.
- The full repository suite was not run by this wave (another wave's files are in flux).

## M.13 Recommendation

1. **Keep the boundary as the only writer.** Controller + `TrustedMind._install_trusted` +
   `FossilStore` + `KnowledgeLineageDAG` + the gateway's Stage 2 composition hold under every
   attack built here and refused 7/7 bad candidates. Supported as a construction result.
2. **Ship no learned state from this stage.** The learner produced none, and every candidate it
   produced alerts on every session.
3. **REJECT the learner as built; default-off or remove every OPTIONAL `HEL-F*`** (four INERT;
   three fired with no benefit; the drift discriminator is observed harmful to learning).
4. **Fix `labs/continual_baselines.py`'s threshold refit** before any further comparison: three
   baselines alert on nothing at their own threshold.
5. **Next experiment, UNMEASURED here:** full retrain over the bounded episodic store *as the
   chamber*, submitted through the same controller. Full retrain ranks best but promotes
   12-20 poisoned items ungated, so it is a candidate for the boundary, not a replacement for it.
6. **For the lead:** the threshold defect (`DEFAULT_THRESHOLD == UNEXPLAINED_WEIGHT`, `>=`)
   makes G3 unpassable for every detector candidate; the canary policy for unprotected
   regressions (0/12 acted on); ~~and the Stage 7 file that now fails Stage 6's single-writer
   scan~~ (**[CORRECTED, M.15]** no longer true on the current tree); and the M.15 items
   marked "for the lead".

## M.14 The rejection, recorded

Block 0050-0059 is fully assigned and this wave may use no number outside it, so the verdict is
a dated **measurement-wave addendum to ADR-0058**
(`docs/adr/0058-anti-forgetting-verdict-against-never-update-full-retrain-and-reservoir.md`).
It keeps NOT-YET-JUSTIFIED for the anti-forgetting stack, records the learner as REJECTED as
built, keeps never-update + calibration-only only as the *safe default* (never-update loses F1
at M09), and chooses "keep the boundary, rebuild the learner, measure full retrain inside the
boundary next".

## M.15 Review-fix session — what an independent review found, and what changed

Later on 2026-09-26 an independent review of this stage confirmed 15 CRITICAL/HIGH and 14
MEDIUM findings, each of which survived a refutation attempt. This section records the fix, the
regression test that pins it (each fails on the pre-fix behaviour and passes after; the test's
docstring names its finding) and every figure re-measured afterwards. Every number below was
produced by running code in the review-fix session; load average is quoted beside each run
(another wave was active; loadavg 4.2-18.9). Where this section and anything above disagree,
this section is the current statement.

### M15-1 The fixes

| finding | defect (confirmed) | fix | regression test |
|---|---|---|---|
| S6-AUTH-01 (CRITICAL) | any source except TEACHER/FOREIGN_HOST/DERIVED_INFERENCE could self-assert GROUND_TRUTH, which settles an episode alone, outvotes an analyst quorum and is exempt from the benign-label-on-protected-detector and label-shift rules | GROUND_TRUTH may be *declared* only by `SourceClass.LAB_GROUND_TRUTH` (whitelist, refused at construction); the gateway *honours* it only from an independence group in `ground_truth_groups` (empty by default: an endpoint has no lab); otherwise it is one ANALYST vote, screened like any other (`poisoning.honoured_origin`) | `test_stage6_gateway.py::test_only_a_lab_source_may_declare_ground_truth`, `::test_unauthenticated_ground_truth_does_not_settle_alone`, `::test_unauthenticated_ground_truth_benign_on_a_protected_detector_is_hostile` |
| F1 | the drift window started empty at the pivot, forcing POISON_SUSPECT | `StageSixLearner` keeps the last `DRIFT_ALIGN_WINDOW` verdicts and opens the window with them | `test_stage6_endurance.py::test_the_drift_window_holds_verdicts_from_before_its_pivot` |
| F2 | "poisoned items" counted additions only; a labelled poison session's episode id was not a poison id | poison ids hold the episode and its labels; the tracker counts detector removals, and those in the update right after a poison capsule | `::test_labelled_poison_episodes_are_poison_ids_and_removals_are_counted`, `::test_the_tracker_counts_a_threshold_change_and_a_poison_removal` |
| F3, S6-AUTH-08 | a learned THRESHOLD kept `ItemLineage('genesis', (), (), ())`; `lineage_complete` accepted any THRESHOLD claiming genesis; the tracker keyed on item id only | the chamber stamps a learned threshold's lineage (candidate, the benign episodes it was fitted against, their evidence); the controller binds the genesis weight into the DAG, so a THRESHOLD claiming genesis at another weight fails at load; the tracker compares (item id, weight) | `test_stage6_lineage.py::test_a_changed_threshold_claiming_genesis_fails_lineage_once_genesis_is_bound`, `test_stage6_evolution.py::test_a_learned_threshold_names_its_candidate_and_is_fitted_off_the_holdout` |
| F4 (correctness) | G6.3 used recall@FPR, which re-chooses the threshold, so a threshold-only blinding promotion showed 0 violations | G6.3 also measures operating recall at each state's own threshold and fails on a drop in either | `test_stage6_gate.py::test_g63_fails_a_threshold_only_promotion_that_blinds_every_family` |
| F4 (honesty) | G6.3 PASSed on a promotion that could not regress | a promotion is *informative* only if a learned item changed and the before-state detected something; zero informative promotions is VACUOUS (FAIL) | `::test_g63_calls_a_promotion_that_could_not_regress_uninformative` |
| F5 | calibration was fitted on the holdout negatives G3 then scored it on | `_calibrate` fits on rehearsal + training negatives only; G3 refuses a CALIBRATION claim whose threshold lineage cites a holdout episode | the evolution test above (disjointness and the G3 refusal) |
| S6-AUTH-02 | an explicit rollback re-installed a state probation had rolled back, with no gate and no probation, blaming and blacklisting the good installer | an explicit target that was rolled back (or is a ROLLED_BACK candidate's proposal) is refused; target selection moved to `promotion/restore.py` | `test_stage6_promotion.py::test_an_operator_cannot_re_trust_a_state_probation_rolled_back` |
| S6-R1, honesty F2 | after `collect_lineage` an operator rollback to a held, intact fossil installed a different state and recorded FOSSIL_CORRUPTION | `collect_lineage` keeps the items of every retained fossil live; an explicit target is restored exactly or refused, never substituted; an intact fossil whose lineage was folded is recorded `LINEAGE_UNVERIFIABLE`, not corruption | `::test_an_explicit_rollback_target_is_restored_exactly_after_a_lineage_fold`, `::test_an_unverifiable_explicit_target_is_refused_never_substituted`, amended `::test_a_raw_dag_collect_strands_the_target_and_rollback_names_it` |
| S6-AUTH-03 | canary and probation regressed only on labelled sessions; an all-unlabelled window completed and probation passed | a detection dropped on an unlabelled protected-anchor session is a regression; a window completes, and a probation ends, only with >= `MIN_LABELLED_BENIGN` (1, chosen) benign-labelled sessions; a canary with enough sessions but no benign label is REJECTED (`canary_unlabelled`); `CanaryReport` reports labelled counts | `::test_unlabelled_canary_traffic_cannot_promote_a_candidate_that_drops_a_detection`, `::test_an_unlabelled_canary_window_is_incomplete_and_the_candidate_is_rejected`, `::test_unlabelled_probation_neither_passes_nor_hides_a_dropped_detection` |
| S6-AUTH-05 | `apply_context_transition` accepted any hand-built `EpochTransition` | `open_new_epoch` mints each transition with a random token into a bounded, single-use registry; the controller consumes it last and checks `previous` against the trusted context | `::test_a_hand_built_context_transition_is_refused` |
| S6-AUTH-07 | independence tracks were never retired: 512 keys ended normality learning for the gateway's lifetime | a full tracker retires its least recently seen key, uncorroborated first, counted in `pattern_evictions` (moved to `homeostasis/independence.py`) | `test_stage6_gateway.py::test_a_full_pattern_tracker_retires_its_least_recent_key_and_counts_it`, `::test_one_source_filling_the_tracker_cannot_end_normality_learning` |
| S6-R2 | past the DAG cap every admit raised `LineageCapacityError` | the gateway checks room first, folds once through the controller's bound collector, then refuses with a counted, unissued `lineage_full` DISCARD | `::test_a_full_lineage_dag_refuses_and_counts_instead_of_raising_on_every_admit`, `::test_a_bound_collector_folds_so_admission_continues_past_the_cap` |
| F6, S6-R6 | stale G6.1 claim; the 2.1x memory figure compared two estimators | documents corrected (M.1, M.10, M.12, M.13, ledger); one measured quantity in M15-2 | — (documents) |
| S6-AUTH-04 (MEDIUM) | `setattr(mind, SEALED_NAMES[1], state)` wrote trusted state without spelling a sealed name | `TrustedMind.__setattr__` refuses; only the installer writes (through `object.__setattr__`, in the one file allowed to) | `::test_the_trusted_mind_refuses_attribute_writes_even_through_sealed_names` |
| F1 (MEDIUM) | G6.1 read the mind's cached digest and never compared it across `observe()` | G6.1 probe (d) recomputes the trusted digest around every `observe()` of a 12-month run | `test_stage6_gate.py::test_g61_catches_an_observe_that_writes_trusted_state_behind_the_installer` |
| F3 (MEDIUM) | no negative control for a probation that rolls back on any attack | added | `::test_an_attack_during_a_non_regressing_probation_does_not_roll_back` |
| S6-AUTH-06, F5 (MEDIUM) | a capsule the gateway refused (DISCARD, HOSTILE_SUSPECT) counted as admitted; after a fold any folded id did | `KnowledgeLineageDAG.capsule_admitted` refuses those verdicts and counts only folded CAPSULE ids that were admitted when folded; the conservation gate calls it instead of a copy | `test_stage6_lineage.py::test_an_item_citing_a_discarded_or_hostile_capsule_is_not_lineage_complete`, `::test_a_folded_non_capsule_id_is_not_an_admitted_capsule` |
| S6-AUTH-09 (MEDIUM) | a hand-built `PackageVerification` imported an unsigned package | `package_to_capsules` accepts only a verification `verify_package` issued (bounded registry) | `test_stage6_capsule.py` (the "different package" test, extended) |
| F7 (MEDIUM) | G3 fell back to the caller's whole holdout when a candidate named none | G3 uses only the episodes the candidate named | covered by the F5 test path |
| S6-R8 (MEDIUM) | after a promotion `_learn` spawned a doomed candidate; a dropped consolidation candidate was uncounted | the loop stops once probation opens; the drop is counted (`consolidation_candidate_dropped_short_ring`) | `test_stage6_endurance.py::test_dropped_consolidation_candidates_and_the_episode_book_are_reported` |
| S6-R5 (MEDIUM, partial) | the episode book (<= 256 full capsules) was never reported | reported as the `episode_book` store (bytes = canonical capsule bytes) inside the quarantine-metadata budget | same test |
| S6-R9 (MEDIUM) | gateway and ledger were each capped at the whole shared budget | `STORE_GROUPS` checks the sum | `::test_stores_sharing_one_budget_are_checked_together` |

### M15-2 The 12-month run, re-measured (seed 11, 16 sessions/month, loadavg 5.43 -> 5.28)

Scratch measurement script run once over the identical compiled stream for every learner.
"promotions" = new (item id, weight) pairs, so a threshold move counts. "deep B" = the size
of each learner's own object graph (`sys.getsizeof` over `gc.get_referents`, types, modules and
functions skipped) *excluding every object reachable from the shared compiled stream* — one
method for every learner, unlike the self-reported "stored B".

| learner | promotions | poisoned additions | detectors removed | removed right after a poison capsule | self-reported stored B | deep B (own graph) |
|---|---|---|---|---|---|---|
| never-update | 8 | 0 | 0 | 0 | 3045892 | 55980 |
| calibration-only | 10 | 0 | 0 | 0 | 3045892 | 56012 |
| naive-cap4 | 57 | 12 | 21 | 0 | 3045892 | 74105 |
| naive-cap8 | 45 | 12 | 7 | 2 | 3045892 | 76875 |
| naive-cap64 | 45 | 12 | 7 | 2 | 3045892 | 76894 |
| reservoir-65536 | 44 | 12 | 0 | 0 | 3109187 | 93212 |
| full-retrain | 43 | 12 | 2 | 1 | 3348005 | 94195 |
| prototype-centroid | 33 | 12 | 0 | 0 | 3045892 | 81311 |
| **stage2-only** | 24 | **0** | 7 | **2** | 3045892 | 152111 |
| **stage6** | **0** | 0 | 0 | 0 | 6986347 | **1122605** |

- **stage2-only's "0 poisoned" was the metric's blindness:** 0 poisoned additions, but 2 of its
  detectors left trusted state in the update right after an M10 label-flip poison capsule.
  Stage 6 removed nothing and promoted nothing, so its 0 is accept-nothing (F10), as before.
- **Memory:** by one method, Stage 6's own object graph is 1122605 B against full-retrain's
  94195 B (11.9x) and never-update's 55980 B. The self-reported "stored B" ratio (2.09x here,
  2.1x in M.10) is withdrawn as a memory figure: it divides canonical capsule bytes by fixed
  per-step constants. The direction (Stage 6 costs more) holds; the magnitude depends on the
  method, and this is the only one applied to every learner. Dev host, not a device.
- Stage 6 counters: `drift:UNDETERMINED` 3, `drift_dropped_admissions` 0 (the counter never
  moved), `rejected_offline_or_shadow` 1, `rejected_canary_unlabelled` 1, promotions 0,
  rollbacks 0, trusted items 1. Gateway: `ground_truth_demoted` 0, `lineage_full_refused` 0,
  `pattern_evictions` 0, 23 patterns tracked.

### M15-3 HEL-F19 with the window it was specified to take

Instrumented 12-month run (loadavg 4.59): the three windows held 48 / 73 / 80 verdicts, of which
32 / 64 / 64 from before the pivot; breadth 0.0 in each (no pattern first appeared after the
change); semantics stable; 0 groups on changed patterns; all three **UNDETERMINED**
(`too_few_independent_groups`); 0 admissions dropped (13 in Part M). Ablation
(`pocketsec-stage6 ablation`, loadavg 4.84 -> 4.81): HEL-F19 firing 3 (classification differs
from "corroborated => legitimate"), delta 0.0, NOT_YET_JUSTIFIED — the firings changed no
outcome. Slow drip (`benchmarks/stage6/slow_drip.py --epochs 2 4 8`, 315.6 s, loadavg 4.65 ->
17.94): `drift_dropped_admissions` 0 / 0 / 0 at 2 / 4 / 8 epochs (8 / 13 / 26 in Part M); Stage 6
still 0 of 1 poisoned and 0 of 4 clean on DRIP-DATA, VACUOUS on both label drips; stage2-only
0 of 1 / 3 of 4; the independence check refused 22 per data drip. **The "harmful" verdict is
retracted; the discriminator is inert on this corpus (NOT-YET-JUSTIFIED)** — ADR-0058 has the
dated correction.

### M15-4 The canary on unlabelled traffic — the new rule fires on the real run

On the 12-month run the rehearsal-only CONSOLIDATION candidate `cand-57e5a35a7618c649...` —
the one promotion Part M reported, whose items were identical before and after — reached the
end of its canary with 4 MALICIOUS-labelled and **0 BENIGN-labelled** sessions and was REJECTED
(`canary_unlabelled`). On this corpus no benign session is ever labelled, so as the corpus
stands no candidate can pass a canary: the boundary now says it has no false-positive evidence
instead of passing without any. In the flood below the rule rejected 28 candidates. The
minimum (`MIN_LABELLED_BENIGN` = 1) is a chosen parameter, not a measurement — for the lead.

### M15-5 Rollback with lineage collected between promotions

`benchmarks/stage6/rollback_stress.py --promotions 45 --regressions 30 --collect-lineage`
(11.7 s, loadavg 15.66 -> 15.78; 267 lineage nodes folded): 45/45 promoted, 0 spurious rollbacks,
46/46 items `lineage_complete`, 0 `verify()` problems; canary/probation rows unchanged from M.8
(5/5 rejected at canary, 3/3 automatic rollbacks byte-identical, 0/12 unprotected acted on,
10/10 invisible kept); **operator rollback to every held fossil 28/28 digest- and
byte-identical, 0 substituted**; 39/39 evicted states refused; a never-fossilised digest
refused. The pre-fix controller was not re-run under `--collect-lineage` in this session; the
reviewer's reproduction is the evidence of the defect and the regression tests pin it.

### M15-6 Flood with retiring independence tracks

`benchmarks/stage6/flood.py --capsules 20000` (122.1 s, loadavg 16.72 -> 9.32): every store under
its cap; `pattern_evictions` 18293, `pattern_overflow` 0; RSS 40.7 MB at start, 61.0 MB at end
and at the sampled maximum. Post-flood probe, 64 fresh routine sessions: the flooded learner
tracked the legitimate patterns by retiring 11 old keys and refused none (165 refused in
Part M); the fresh control tracked 11. Neither admitted anything from those 64 sessions, so
whether
retirement changes an admission is still UNMEASURED.

### M15-7 The gate on the current tree

`python -m pocketsec.stage6.cli gate` (15:35:59-15:44:58, loadavg 4.19 at start, 18.29 at
end) -> **5/13 criteria met, GATE: FAILED (8), exit 1.** PASS: G6.1 (sealed-name scans `[]`;
6/6 injections refused; 5 chamber faults, 0 digest changes; probe (d) 244 `observe()` calls, 0
unrecorded trusted-state changes), G6.6, G6.7, G6.8, G6.11. **G6.3 now FAILS as VACUOUS**
(0 promotions examined on the 12-month run; the rig firing proof still rejects the F1-removing
candidate). The other FAILs are as in M.1 (G6.2, G6.4, G6.5, G6.9, G6.10, G6.12, G6.13).

### M15-7b Tests in this session

- `PYTHONHASHSEED=0 python -m pytest -p no:cacheprovider tests/test_stage6_*.py` (after the
  controller, canary, gateway, chamber and lineage fixes): **429 passed** in 500.03 s.
- `PYTHONHASHSEED=0 python -m pytest -q` (the whole repository, 15:47:06-16:25:43, loadavg
  16.70 -> 9.97): **3805 passed, 3 failed** (counted from pytest's progress markers; the
  project's `addopts = -q` doubles the quiet flag, so no summary count line is printed). The 3
  failures are outside Stage 6: `tests/test_stage1_pipeline.py::test_stage1_acceptance_gate_passes`
  and `::test_gate_cli_exits_zero` (G1.12 peak RSS 136171520 B vs the 104857600 B edge target,
  measured in the long-lived test process) and
  `tests/test_stage5_sentinel.py::test_the_sentinel_trusted_surface_stays_inside_its_ratchet`
  (Stage 5 files total 1370 lines vs ratchet 1330). Neither file imports Stage 6; both belong to
  other waves and were not touched.

### M15-8 Not fixed — accepted known defects, with the reason

- **GROUND_TRUTH authentication is by configured group, not by signature.** `source_class` and
  `independence_group` are both self-declared capsule fields, so an attacker who can spell an
  authenticated lab group's name can still assert GROUND_TRUTH. A real fix needs signed
  provenance on capsules, which this stage's contracts do not carry (for the lead).
- **S6-R3:** every promotion Stage 6 made was a score-identical, rehearsal-only CONSOLIDATION
  that then held a 128-session probation. Now refused at canary on this corpus (M15-4); the
  design question (should score-identical promotions exist at all) is the lead's.
- **S6-R4:** each admit recomputes the trusted state's digest and the capsule digest twice; the
  review measured the share of gateway CPU this costs, this session did not (UNMEASURED here).
  A performance defect; left rather than add a digest cache to a frozen value in this session.
- **S6-R5 (rest):** the replay ring has no byte cap and `STEP_BYTES_ESTIMATE` undercounts a
  resident step (by the review's measurement; not re-measured here); G6.10 is still measured
  only on the 15-step corpus. The envelope at the 64-step capsule maximum is UNMEASURED.
- **S6-R7:** homeostasis fired 28 times and changed 0 outcomes on the endurance corpus (ablation
  row above). It is kept on: it is the only rule that screens a BENIGN label against a
  protected *trusted detector*, and the S6-AUTH-01 tests exercise it adversarially.
- **Files over 800 lines** (controller 878, quarantine 933, endurance 1078, evolution 1671,
  semantic 911) were already over; this session split `promotion/restore.py` and
  `homeostasis/independence.py` out but still grew three of them.

## What would change this conclusion

- **A candidate the boundary should accept.** If a rebuilt chamber (or full retrain inside the
  boundary) proposes detectors with near-zero benign FP on held-out eval and the gates still
  refuse them, the boundary becomes the defect and M.13 point 1 is withdrawn.
- **Stage 6 learning something clean on the arms Stage 2 fails** (P1@x16, P1b@x16, P2, P2b, P3,
  P3b) with 0 poisoned promotions. Only that shows the Stage 6 poisoning layer beats Stage 2
  (F8) and stops F10.
- **A corpus on which E3 holds** and Stage 6 then beats never-update on acquisition by >= 0.10
  with retention within 0.02.
- **The threshold ADR.** At 0.6 the blocker moved from G3 to G8 and the outcome did not change,
  so this alone is not expected to change the verdict; it must be re-measured, not assumed.
- **Repaired baseline thresholds.** With working operating points the FP comparisons of M.3
  become meaningful; the AP ranking (full-retrain 0.8692 vs Stage 6 0.5000) would not change.
- **Real telemetry.** Every figure here is synthetic.

## Honesty ledger

### MEASURED
Every row produced in the measurement session, 2026-09-26, seed 11. Scripts are in
`benchmarks/stage6/`; ids are in `experiments/registry.jsonl` (63 rows, `verify_integrity()`
problems `[]` after the session's writes).

| claim | value | how it was produced (module:function) | experiment id | synthetic? |
|---|---|---|---|---|
| gate, 13:06 run | 6/13, FAILED (7), exit 1; loadavg end 8.16 11.62 13.41 | pocketsec.stage6.cli:_gate | PS-S6-20260926-H6-helios-gate-0001 (registered from the 14:06 re-run) | yes |
| gate, 14:06 re-run | 5/13, FAILED (8): G6.1 failed on stage7/gate_boundary.py:131-132 *at 14:06*; stale since (M.15) | pocketsec.stage6.cli:_register; gate_construction:sealed_name_violations | PS-S6-20260926-H6-helios-gate-0001 | yes |
| injections refused / digest changes | 6/6, 0 | gate_construction:check_raw_telemetry_cannot_modify | PS-S6-20260926-H6-helios-gate-0001 | yes |
| E2 control APs | 0.5776 / 0.5 / 0.6069 | labs.endurance:check_preconditions | PS-S6-20260926-H6-learnability-0002 | yes |
| Stage 6 learned items, 4 configs x {full, minimal} | 0 in 8/8 | benchmarks/stage6/learnability.py:run | PS-S6-20260926-H6-learnability-0002 | yes |
| Stage 6 AP over the year | 0.5000 in 8/8 | stage0 security_metrics:average_precision | PS-S6-20260926-H6-learnability-0002 | yes |
| full-retrain / stage2-only AP (16/month) | 0.8790 / 0.7302 | same | PS-S6-20260926-H6-learnability-0002 | yes |
| learned candidates refused | 7 of 7 (G3 x5 incl. 2 with empty holdout; G8 x3 at 0.96875-1.0) | benchmarks/stage6/refusal_census.py:census | PS-S6-20260926-H6-refusal-census-0003 | yes |
| refused candidates on 576 held-out sessions | benign FP 1.0, AP 0.5, recall@FPR0.05 0.0 (7/7) | benchmarks/stage6/candidate_quality.py:_quality | PS-S6-20260926-H6-candidate-quality-0012, -v2-0014 | yes |
| baselines' own operating point | full-retrain thr 0.900001, stage2-only 0.666668: operating recall 0.0, FP 0.0; never-update F1 1.0, FP 0.361 | same | PS-S6-20260926-H6-candidate-quality-v2-0014 | yes |
| full-retrain pooled-year ranking | AP 0.8692, recall@FPR0.05 0.674 | same | PS-S6-20260926-H6-candidate-quality-v2-0014 | yes |
| data drip, Stage 6 vs Stage2Only (poisoned / clean) | 0/1, 0/4 vs 0/1, 3/4 at 2, 4, 8 epochs | labs.poison_suite:run_arm | PS-S6-20260926-H6-slow-drip-0004 | yes |
| label drips (1 and 2 groups) | naive & stage2-only suppressed 2/2; Stage 6 VACUOUS | same | PS-S6-20260926-H6-slow-drip-0004 | yes |
| drift-discriminator dropped admissions, data drip | 8 / 13 / 26 at 2 / 4 / 8 epochs — a harness artefact, RETRACTED (M.15) | StageSixLearner counters | PS-S6-20260926-H6-slow-drip-0004 | yes |
| spec arms, Stage 6 | poisoned 0, clean 0.0 on every scored arm; P3/P3b VACUOUS | labs.poison_suite:run_poison_suite | PS-S6-20260926-H6-poison-suite-0006 | yes |
| arms Stage 2 alone fails | P1@x16, P1b@x16, P2, P2b, P3, P3b | same | PS-S6-20260926-H6-poison-suite-0006 | yes |
| spec arms at threshold 0.6 | identical verdicts | same | PS-S6-20260926-H6-poison-suite-diag-0007 | yes |
| flood: caps, RSS plateau | all under cap; RSS 59.9-60.1 MB from 10 500 to 20 000 capsules | benchmarks/stage6/flood.py:main | PS-S6-20260926-H6-flood-bounds-0008 | yes |
| post-flood pattern refusals, flooded vs control | 165 vs 0 | same | PS-S6-20260926-H6-flood-bounds-0008 | yes |
| operator rollbacks byte-identical; evicted refused | 28/28; 39/39 | promotion.controller:rollback_learning | PS-S6-20260926-H6-rollback-stress-0009 | yes |
| visible regressions acted on, protected / unprotected | 8/8 / 0/12 | shadow.canary:CanaryEvaluator via the controller | PS-S6-20260926-H6-rollback-stress-0009 | yes |
| spurious probation rollbacks | 0 in 720 benign sessions | same | PS-S6-20260926-H6-rollback-stress-0009 | yes |
| CPU ratio full-retrain / Stage 6 | 1.723, 1.485, 1.711 (loadavg 20-26) | stage0 ResourceSampler | PS-S6-20260926-H6-resources-compare-0010 | yes |
| stored bytes Stage 6 / full-retrain | 7049317 / 3348005 — self-reported estimates by different methods, not a memory ratio (M.15) | Learner.cost | PS-S6-20260926-H6-resources-compare-0010 | yes |
| Stage 6 incremental RSS | 1007616-1146880 B (fresh child); 552960 B (CLI); 512000 B (gate) | stage0 ResourceSampler; resources:measure | PS-S6-20260926-H6-resources-compare-0010 | yes |
| store growth, 288 months | gateway/ledger cap binds year 17, fossils year 16; episodic, controller, chamber still rising at year 24 | benchmarks/stage6/horizon.py:main | PS-S6-20260926-H6-horizon-0011, -horizon-long-0013 | yes |
| stage6 test files, 13:12 | 404: 403 passed, 1 failed, 1 error (both from this session's concurrent ledger write) | pytest | — | n/a |
| gate + boundary tests, 14:14 | 58: 56 passed, 2 failed (the Stage 7 file) | pytest | — | n/a |
| gate, review-fix session 15:35-15:44 | 5/13, FAILED (8), exit 1; G6.1 PASS incl. probe (d) 244 observe() calls, 0 unrecorded changes; G6.3 FAIL (VACUOUS) | pocketsec.stage6.cli:_gate | — (not registered) | yes |
| HEL-F19 on the 12-month run, fixed window | 3/3 UNDETERMINED; 32/64/64 pre-pivot verdicts; 0 admissions dropped | labs.endurance:StageSixLearner._close_drift (instrumented) | — (M15-3) | yes |
| slow drip, discriminator drops after the fix | 0 / 0 / 0 at 2 / 4 / 8 epochs | benchmarks/stage6/slow_drip.py | — (M15-3) | yes |
| stage2-only detectors removed right after a poison capsule | 2 (0 poisoned additions) | labs.endurance:_Tracker | — (M15-2) | yes |
| own object-graph bytes, Stage 6 / full-retrain | 1122605 / 94195 | scratch gc traversal excluding the shared stream | — (M15-2) | yes |
| operator rollbacks with lineage collected between promotions | 28/28 byte-identical, 0 substituted, 267 nodes folded | benchmarks/stage6/rollback_stress.py --collect-lineage | — (M15-5) | yes |
| canary rejections for no benign label | 1 on the 12-month run; 28 in the flood | shadow.canary / controller.promote_trusted | — (M15-4, M15-6) | yes |

### UNMEASURED
| claim the architecture makes | why not measured | what would measure it | blocking? |
|---|---|---|---|
| Stage 6 resists label poisoning (P3, P3b, 1- and 2-group drips) | Stage 6 never detected a target (VACUOUS) | a learner that acquires F2 first | yes, G6.9 |
| the label quorum resists two colluding groups | same | same | yes |
| Stage 6's poisoning layer beats Stage 2 on the arms Stage 2 fails | Stage 6 learned nothing clean there (F10) | same | yes, F8 |
| anti-forgetting, resurrection, time-to-adapt | nothing acquired | same | yes, G6.5 |
| Stage 6 at detector capacity 4 and 8; HEL-F11 | no capacity parameter and no G4 switch (integration blocker) | a spec change | yes, G6.13 |
| full retrain *inside* the boundary | not built | a chamber that retrains over the bounded episodic store | no |
| any learner's operating-point precision | the baselines' threshold refit alerts on nothing | a repaired refit | no |
| whether the flood-locked pattern table changes an admission | the unflooded control admitted nothing in 64 sessions | a longer probe spanning epochs | no |
| plateau of episodic, controller, chamber | still rising at 288 months | a longer horizon | yes, G6.12 |
| M11 resource-pressure deferral | consolidation never falls due in M11 (0 deferrals) | a timeline with consolidation due under pressure | yes, G6.10 |
| EWC/SI, LwF, adapter isolation, dynamic expansion, ONNX/INT4 | no parameters to act on (ADR-0050) | a neural learner behind a research boundary | no |
| RSS/CPU on a 2 GB device; real upgrade drift | dev host; synthetic signals | a device and real upgrades | no |
| the full repository test suite | not run by this wave | `pytest tests/` with no other wave writing | no |

### REJECTED
| component | measured effect | verdict (REJECTED / NOT-YET-JUSTIFIED / RETRACTED / INERT / DEGENERATE) | ADR |
|---|---|---|---|
| the Stage 6 learner as built (chamber induction behind the boundary) | 0 items in 8/8 runs; 7/7 candidates benign FP 1.0, AP 0.5 on held-out eval; Stage 6 AP 0.5000 vs full-retrain 0.8692-0.8790 | REJECTED (as built) | 0058 addendum |
| anti-forgetting stack | retention 0.0 of nothing; 0.0 vs reservoir 0.0 at 3 budgets | NOT-YET-JUSTIFIED | 0058 |
| HEL-F07, HEL-F10, HEL-F21, HEL-F25 | firing 0; all-optional-off identical in 4/4 configs | INERT — remove or default-off | 0057 |
| HEL-F08 plasticity field, HEL-F15 value-aware rehearsal | fired 3 / 1, delta 0.0; all-optional-off identical | NOT-YET-JUSTIFIED — default-off | 0057, 0058 |
| HEL-F19 drift discriminator | ~~3/3 false POISON_SUSPECT; drops 8-65 legitimate admissions per run~~ harness artefact (M.15); with a correct window: 3/3 UNDETERMINED, 0 admissions dropped, delta 0.0 | NOT-YET-JUSTIFIED (no outcome changed; the "harmful" verdict is RETRACTED) | 0058 addendum + review-fix addendum |
| Stage 6 poisoning layer beyond Stage 2 | 0 poisoned only where 0 clean (F10); HELD_BY_STAGE2_ALONE on P5 | NOT-YET-JUSTIFIED | 0054, 0058 addendum |
| never-update + calibration-only as the *best* learner | never-update F1 recall@FPR 0.0 from M09; calibration-only acquires no F2/F3 | superseded as best; kept as safe default | 0058 addendum |

### RETRACTED
| retracted claim | where it was published | the defect | corrected value |
|---|---|---|---|
| "FullRetrain/Stage 6 work 84.418" as a cost ratio | G6.11 detail; Appendix A §5 and its MEASURED row | `WorkMeter` excludes gateway, ledger, lineage, fossil and replay work | CPU ratio 1.49-1.72; ~~stored bytes Stage 6 = 2.1x full-retrain~~ (itself retracted below) |
| baseline rows "FP 0.0" read as precision | gate G6.13/G6.5 comparisons; Appendix A §3 | full-retrain, stage2-only, calibration-only refit their threshold above their own detector weights and alert on nothing | operating recall 0.0 at FP 0.0 (full-retrain, stage2-only) |
| "HEL-F19 classes 3/3 corroborated changes POISON_SUSPECT; observed harmful to learning" | M.4, M.5, M.7, REJECTED table; Appendix A; ADR-0058 addendum | the harness passed a window with no verdict from before the change, which forces POISON_SUSPECT (review F1) | 3/3 UNDETERMINED, 0 admissions dropped (M.15) |
| "G6.3 PASS: 1 promotion examined, 0 violations" | M.1; Appendix A; planning/PROGRESS.md; planning/MEMORY.md | the promotion could not have regressed (identical items, 0.0 baseline) and the metric re-chose its threshold (review F4, honesty F4) | VACUOUS; a threshold-only blinding promotion is now a violation (M.15) |
| "vs Stage2Only: both 0 poisoned items" | M.3; Appendix A | the metric counted additions only; the M10 label-flip removes detectors (review F2) | stage2-only: 0 poisoned additions, 2 detectors removed right after a poison capsule (M.15) |
| "Stage 6 costs 2.1x full-retrain's stored bytes" | M.10; RETRACTED row above; Appendix A; ADR-0058 addendum | two different estimators (review S6-R6) | one method for every learner in M15-2 |
| "G6.1 fails on the current tree because of stage7/gate_boundary.py" | M.1, M.12, M.13; the 14:06 ledger row | the Stage 7 file changed after this was written (review F6) | the sealed-name scans return `()`; G6.1 status in M.15 |

### NOT A DETECTION RESULT
Every corpus is synthetic — the 12-month endurance timeline at 16 and 64 sessions/month, its
60-, 180- and 288-month repetitions, the eleven poison arms, the slow drips, the flood and the
gate rig — and every Stage 5 record the stage learns from is simulated. No figure here says
how any learner would detect anything on a real host.

### PARAMETERS
Every §4.21 constant is chosen, not measured, including `MIN_INDEPENDENT_GROUPS` 3,
`MIN_INDEPENDENT_LABEL_GROUPS` 2, `UNEXPLAINED_WEIGHT` 0.5, `DEFAULT_THRESHOLD` 0.5,
`MAX_SHADOW_DISAGREEMENT` 0.10, `MIN_UTILITY_GAIN` 0.01, `HOLDOUT_SHARE` 0.25,
`MIN_SHADOW_SESSIONS` 32, `SHADOW_SAMPLE_EVERY` 4, `CANARY_WINDOW_SESSIONS` 64,
`PROBATION_SESSIONS` 128, `MAX_PROTECTED_REGRESSIONS` 0, `MAX_PATTERNS_TRACKED` 512,
`MAX_ISSUED_VERDICTS` 4096, `MAX_TRUST_RECORDS` 4096, `MAX_EPISODES` 512, `MAX_FOSSILS` 32,
`MAX_LINEAGE_NODES` 8192, `FPR_BUDGET` 0.05, `SESSIONS_PER_MONTH` 16 and the rest of the table
— chosen, not measured. The measurement wave's own choices are parameters too: the diagnostic
genesis threshold 0.6, 64 sessions/month, 2 poison sessions per epoch, the 160-session warm-up,
the 20 000-capsule flood, 45 rig promotions and 30 regressions, 15 and 24 horizon cycles, and
the rig's 8/16 canary/probation windows.

## Appendix B — commands run in the measurement session, with their real output

All from the repository root with `PYTHONHASHSEED=0` and
`TMPDIR=<session scratchpad>`; the `### hh:mm:ss loadavg` lines are the runner's own stamps.

```
$ .venv/bin/python -m pocketsec.stage6.cli gate                       # 13:06
  loadavg at end of run: 8.16 11.62 13.41
  6/13 criteria met
  GATE: FAILED (7)
  513.11s user 1.10s system 91% cpu 9:24.91 total ; exit 1

### 13:23:57 loadavg 16.25 14.34 13.50 :: benchmarks/stage6/learnability.py --spm 16 64 --threshold default 0.6 --record PS-S6-20260926-H6-learnability-0002
  # spm 16: compiled in 47.7 s, corpus sha256:4f6062a0fdd09dd86244b0fdd64399d3f397dec8faf34ca32c2c6fbc4af2201d
  # spm 64: compiled in 111.5 s, corpus sha256:4b3df6fb8c6f3cd852ab0b6c2b50a691fe3a386683d9748a7a35521ff2a1172d
  stage6 items {'THRESHOLD': 1} ... AP 0.5000   (all four configurations; stage6-minimal identical)
  full-retrain items {'BASELINE': 13, 'DETECTOR': 3, 'THRESHOLD': 1} ... AP 0.8790 (16/month)
  recorded PS-S6-20260926-H6-learnability-0002 ; ### exit 0 13:33:44 loadavg 15.66 19.44 17.18

### 13:33:44 :: benchmarks/stage6/refusal_census.py --spm 16 64 --threshold default 0.6 --record ...-refusal-census-0003
  cand-e2260fa93fcb8700 ['SYMBOLIC'] {'DETECTOR': 4} REJECTED [('G3_CURRENT_HOLDOUT', 0.0, 'holdout used 4/4; recall_gain 0.0; fp_reduction None')]
  cand-be60aba31ae4cef9 ['SYMBOLIC'] {'DETECTOR': 4} REJECTED [('G8_SHADOW', 0.96875, 'disagreement_rate 0.96875 not <= 0.1')]
  cand-8c55dfef6406cd7c ['SYMBOLIC'] {'DETECTOR': 4} REJECTED [('G8_SHADOW', 1.0, 'disagreement_rate 1.0 not <= 0.1')]
  ### exit 0 13:35:56 loadavg 9.31 15.83 16.17

### 13:35:56 :: benchmarks/stage6/slow_drip.py --epochs 2 4 8 --record ...-slow-drip-0004
  DRIP-DATA e 8 stage6         off 16 pois 0 / 1 clean 0 / 4 {'drift_dropped_admissions': 26, ... 'single_source_refusals': 22}
  DRIP-DATA e 8 stage2-only    off 16 pois 0 / 1 clean 3 / 4
  DRIP-LABEL-2G e 8 stage2-only off 32 pois 2 / 2 clean 0 / 2
  # wall 140.7 s, loadavg [9.31, 15.83, 16.17] -> [10.62, 13.55, 15.24] ; ### exit 0

### 13:38:17 :: slow_drip.py --epochs 2 4 8 --threshold 0.6 --record ...-slow-drip-diag-0005   ; # wall 203.6 s ; exit 0
### 13:41:42 :: benchmarks/stage6/poison_diag.py --record ...-poison-suite-0006
  P1   stage2-only     x16  offered 96    poisoned 1 clean 3 (0.75)
  P2   stage2-only     x16  offered 22    poisoned 2 clean 4 (1.0)
  P2   stage6          x16  offered 22    poisoned 0 clean 0 (0.0)
  verdict P5: HELD_BY_STAGE2_ALONE: Stage 6 adds nothing on this arm (F8)
  # threshold None; wall 377.4 s; loadavg [15.75, 14.95, 15.47] -> [10.14, 13.67, 15.06] ; exit 0
### 13:48:00 :: poison_diag.py --threshold 0.6 --record ...-poison-suite-diag-0007 ; # wall 315.7 s ; exit 0
### 13:53:16 :: benchmarks/stage6/flood.py --capsules 20000 --record ...-flood-bounds-0008
  post_flood_probe: flooded pattern_overflow_delta 165, control_no_flood 0 ; exit 0
### 13:57:53 :: benchmarks/stage6/rollback_stress.py --promotions 45 --regressions 30 --record ...-rollback-stress-0009
  visible_regressions_by_protected: {'False': {'acted_on': 0, 'visible_regressions': 12}, 'True': {'acted_on': 8, 'visible_regressions': 8}}
  C: bytes_match 28, digest_match 28, evicted_rollback_refused 39, evicted_states 39, unfossilised_refused True ; exit 0
### 13:58:00 :: benchmarks/stage6/resources_compare.py --spm 16 --repeats 3 --record ...-resources-compare-0010
  stage6 3.104 [1.0, 1.0, 1.0] ... full-retrain 5.31 [1.723, 1.485, 1.711] ; ### exit 0 14:01:42 loadavg 25.98 21.70 17.78
### 14:01:42 :: benchmarks/stage6/horizon.py --cycles 15 --record ...-horizon-0011 ; exit 0
### 14:06:21 :: python -m pocketsec.stage6.cli --json resources
  "incremental_rss_bytes": 552960, "peak_rss_bytes": 93814784, "cpu_seconds": 1.3528..., "events": 244,
  "profile_within_target": true, "within_ceiling": true
### 14:06:41 :: python -m pocketsec.stage6.cli experiments --register
  registered 11 entries: ['PS-S6-20260926-H6-helios-gate-0001', 'PS-S6-20260926-H8-ablation-0001', ... '-0010']
  gate result: FAILED (8) ; ### exit 1 14:13:20
### 14:13:21 :: benchmarks/stage6/candidate_quality.py --spm 16 64 --threshold default 0.6 --record ...-candidate-quality-0012
  REJECTED 4 fp 1.0 F1 1.0 F2 1.0 F3 1.0 ['IMPERSONATE[req=0,forbid=0,raised=0]', ...]   (7 of 7 rows)
### 14:14:52 :: pytest tests/test_stage6_gate.py tests/test_stage6_boundary.py --junitxml=...
  {'tests': '58', 'failures': '2', 'errors': '0', 'skipped': '0', 'time': '238.931'} ; exit 1
### 14:18:54 :: benchmarks/stage6/horizon.py --cycles 24 --record ...-horizon-long-0013
  gateway [244, ..., 3904, 4096, 4096, ...] plateau 16 ; episodic [28, ..., 352] grew_last True ; exit 0
### 14:23:30 :: benchmarks/stage6/candidate_quality.py --spm 16 --threshold default 0.6 --record ...-candidate-quality-v2-0014
  full_retrain_final {'threshold': 0.900001, 'benign_fp': 0.0, 'ap': 0.8691896609788481, 'recall_at_fpr_0.05': 0.6736111111111112, 'F1_recall': 0.0, ...}
  stage2_only_final  {'threshold': 0.666668, 'benign_fp': 0.0, 'ap': 0.6239792712290859, 'recall_at_fpr_0.05': 0.0, 'F1_recall': 0.0, ...}
  ; exit 0

$ .venv/bin/python -c "...ExperimentRegistry('experiments/registry.jsonl').verify_integrity()"
  63 integrity problems []
```

Diagnostics run but not registered (exploratory, superseded by the registered runs above):
the first gate run's funnel, a dry run of each script, and a scratch check that the refused
candidates were `IMPERSONATE`-only motifs; their figures agree with the registered runs.

## Appendix A — the integration wave's findings, verbatim (superseded where Part M says so)

The block below is the integration wave's document exactly as it stood before Part M was
written (sha256 of the original file
`4fc958b68d1e8faa2b527442097f0cad2570b692f744e39bfe7fbc719619c497`), quoted so that its
headings do not read as this document's ledger. Part M supersedes: the G6.11 work ratio as a
cost figure; the reading of the baselines' FP 0.0 as precision; and G6.1's PASS, which no
longer holds on the current tree (M.1). **[CORRECTED, M.15]** The last clause is stale (the
Stage 7 file no longer spells the sealed names); M.15 supersedes Part M in turn on G6.1, G6.3,
the HEL-F19 verdict, the "0 poisoned" comparison with Stage2Only and the 2.1x memory figure,
all of which also appear in the quoted block below.

> # Stage 6 — HELIOS + MNEMOSYNE — findings
>
> - **Date:** 2026-09-26
> - **Status:** PARTIAL. The boundary holds on every construction check; the learner learns
>   nothing on the only corpus; the gate fails 7 of 13, including G6.13 by construction.
> - **Spec:** `docs/stage-6-spec.md`. **ADRs:** 0050-0059.
> - **Every figure below was produced by running code in the integration session.** Wall-clock
>   figures carry `/proc/loadavg`; another wave was running tests on this host.
>
> ## 1. The result in one paragraph
>
> Stage 6's deliverable is the quarantine -> validation -> promotion boundary and the ability to
> reverse it. That part is built and holds under attack: no injection path changed the trusted
> digest, the single writer is the only writer across `pocketsec/`, a probation regression rolls
> back automatically to a byte-identical fossil, a corrupted fossil is skipped and named, and no
> Shadow/Canary/Conservation/LearningRecord payload carries an authority or Stage 5 class key.
> The learner behind that boundary learns nothing on the 12-month endurance timeline: zero
> learned items in 12 months and in 60 months, benign FP rate 1.0 in every month, acquisition 0.0
> on F1, F2 and F3. Every poisoning arm is therefore held by accept-nothing equivalence (F10), not
> by a demonstrated defence, and every anti-forgetting and ablation figure is DEGENERATE or INERT.
>
> ## 2. The gate, as run
>
> `python -m pocketsec.stage6.cli gate` → **6/13 criteria met, GATE: FAILED (7), exit 1**.
> Loadavg at end of run `4.31 5.27 6.02` (run 1); a second run gave the same 6/13 at loadavg `15.41 12.04 8.45`.
>
> | id | criterion | result | why |
> |---|---|---|---|
> | G6.1 | raw telemetry cannot modify trusted cognition | PASS | 0 sealed-name violations; 6/6 injections refused, 0 digest changes; 5 faults injected inside the chamber, 0 digest changes |
> | G6.2 | complete provenance and lineage | FAIL | **vacuous**: 0 learned items in either run; tamper and load probes both work |
> | G6.3 | historical capabilities within regression bounds | PASS | 1 promotion examined, 0 violations; G2 refuses an F1-removing rig candidate |
> | G6.4 | repetition cannot become normal | FAIL | Stage 6 poisoned 0 but **clean 0** on P1 and P2 at x1/x4/x16 (F10) |
> | G6.5 | epoch changes adapt without forgetting | FAIL | **vacuous**: M01 FP rate 1.0; context A never had a baseline; F1 never acquired |
> | G6.6 | isolated evaluation before influence | PASS | skips raise; a 31-session shadow is refused; refusals leave the digest unchanged |
> | G6.7 | no Stage 5 authority from shadow/canary failure | PASS | 0 import/T5/upstream violations; forced aborts carry no authority key; emitted ≥ trusted on 14 canary observations |
> | G6.8 | rollback restores known-good state | PASS | 1 automatic probation rollback to the pre-promotion digest, bytes identical; corrupted fossil skipped as FOSSIL_CORRUPTION |
> | G6.9 | data/label/model/slow-drift poisoning | FAIL | 11 arms, all 4 classes, all fired; P3/P3b VACUOUS for Stage 6; Stage 6 clean rate 0.0 on every arm |
> | G6.10 | Stage 0 resource envelope | FAIL | RSS +552960 B / +471040 B over two runs (within ceiling), edge profile within target, all §39 rows under budget — but **M11 deferral never fired** (consolidation not due in M11) |
> | G6.11 | full retraining off-endpoint | PASS | runtime never imports labs; spawn refuses 129 verdicts; episodic cap cannot be raised |
> | G6.12 | bounded growth over month/year | FAIL | no cap exceeded, but stores still **grow** from months 25-36 to 49-60 (gateway 732 -> 1220, lineage 1503 -> 2514 nodes): the caps have not bound in 60 synthetic months |
> | G6.13 | ablation survival | FAIL | by construction (synthetic); also preconditions DEGENERATE, 4 rows INERT, 1 UNMEASURED |
>
> Where the gate uses a rig it says so: G6.3's firing proof, G6.6, G6.7(b) and G6.8 run the real
> controller, fossil store and conservation gate with a lab chamber
> (`pocketsec/stage6/gate_rig.py`) that mints real `EvolutionCandidate` values, because the real
> learner never produces a promotion to test them on. They establish controller properties, not
> anything about what the real chamber proposes. The rig's genesis threshold is 0.6 (see §3).
>
> ## 3. Why the learner learns nothing — measured
>
> `StageSixLearner` on the 12-month timeline (seed 11), counters from the same run:
>
> - The chamber was asked to spawn **twice** in 12 months. Learning was deferred 7 month-ends
>   because the replay ring held fewer than `MIN_SHADOW_SESSIONS × SHADOW_SAMPLE_EVERY` = 128
>   sessions (16 sessions a month reaches it at M08), and 3 more because a probation was active.
> - Of the two spawns: one returned `None`, one candidate was refused by the conservation gate;
>   one candidate (no learned items) reached TRUSTED.
> - The drift discriminator classified **all 3** corroborated context changes as
>   POISON_SUSPECT and dropped 13 normality admissions. Every change on this timeline is a
>   legitimate corroborated one, so these are 3 false positives out of 3.
> - `DEFAULT_THRESHOLD` (0.5) equals `UNEXPLAINED_WEIGHT` (0.5) and the alert rule is
>   `score >= threshold`, so the genesis state alerts on every session that has an unexplained
>   non-escalating step: benign FP rate 1.0 in every month, and no detector can add recall.
> - **Diagnostic, no code changed:** with the genesis threshold set to 0.6 (a scratch script
>   patching `genesis_state`), the benign FP rate is 0.0 in every month and the learner still
>   promotes **no learned item**. The threshold equality is a real defect but not the only one.
>
> Fixing any of these changes a §4.21 constant or a package's design, which the phase STOP
> conditions reserve for the project lead; this wave reports them instead.
>
> ## 4. The poisoning arms — measured (x1 / x4 / x16)
>
> | arm | class | Stage 6 poisoned | NaiveFinetune poisoned | Stage2Only poisoned | Stage 6 clean | verdict |
> |---|---|---|---|---|---|---|
> | P1 | DATA | 0/0/0 | 1/1/1 | 0/0/1 | 0 | ACCEPT_NOTHING_EQUIVALENT |
> | P2 | SLOW_DRIFT | 0/0/0 | 2/2/2 | 2/2/2 | 0 | ACCEPT_NOTHING_EQUIVALENT |
> | P5 | SLOW_DRIFT | 0/0/0 | — | 0 | — | HELD_BY_STAGE2_ALONE |
>
> All eleven arm verdicts (G6.9): P1, P1b, P2, P2b, P4a, P4b, P4c, P6 ACCEPT_NOTHING_EQUIVALENT;
> P3, P3b UNMEASURED (Stage 6 never detected a target, so none could be suppressed); P5
> HELD_BY_STAGE2_ALONE.
>
> **Source independence (ADR-0054) closes exactly the §0 hole and no wider one.** The exact §0
> probe — one lineage, 240 step offers across a corroborated change — gives 25
> `single_source_repetition` refusals and 0 admissions; with the check off, 3 admissions (the §0
> figure reproduced). But arm P1 as built mints a fresh lineage per session, which is what a
> repeated attacker job looks like: at x16, 96 poisoned capsules minted **6 CandidateAdmissions**
> with 11-16 "independent" groups. P1b (fork-spray) minted the same 6. Stage 6 promoted none of
> them — but it promoted nothing clean either.
>
> ## 5. Resources and bounds — measured
>
> Fresh-process 12-month Stage 6 loop (`pocketsec-stage6 resources`, run by G6.10): incremental
> RSS 552960 B (gate run 1; 471040 B in gate run 2), edge profile within target with the trusted state's canonical bytes (63788 B) as
> the model size, peak §39 rows: quarantine metadata 3234462 B, episodic 162354 B,
> semantic/procedural 65539 B, lineage+fossil 710960 B, consolidation workspace 2876002 B — all
> under their normal budgets. Dev host, not a 2 GB device.
>
> 60-month run: 0 cap violations; the only store whose cap bound is the replay ring (256
> sessions), which evicts. Every other store is still below its cap and still growing at month
> 60, so **the plateau G6.12 asks for is not shown**. Boundedness here is by construction (caps),
> not by observed saturation.
>
> Within-run cost ratios (G6.11): FullRetrain/Stage 6 work 84.418, stored bytes 0.475. Stage 6
> did less work because it learned nothing; this is not a cost win.
>
> ## 6. Seams reconciled by the integrator
>
> - `labs/endurance.py`: the learner called `KnowledgeLineageDAG.collect` directly, which strands
>   the pinned probation rollback target (pinned by
>   `test_a_raw_dag_collect_strands_the_target_and_rollback_names_it`); it now calls
>   `LearningPromotionController.collect_lineage()`.
> - The three owners of sealed names (`promotion/controller.py`, `capsule/quarantine.py`,
>   `chamber/evolution.py`) declare them in `SEALED_NAMES`, so the gate scans for them without
>   spelling them; a boundary test pins the declarations to the test's table.
> - Three law tests named by `LEARNING_CONSTITUTION` did not exist; they were written
>   (`test_repetition_from_one_independence_group_counts_once`,
>   `test_a_candidate_is_not_promoted_on_score_alone`,
>   `test_a_candidate_that_forgets_a_historical_detection_is_refused`) and the foundation's
>   pending lists were emptied, so every symbol and law test must now resolve.
> - `measure_stage6_resources` takes an optional `model_bytes` callable; omitted, the profile's
>   model row stays UNMEASURED.
> - Boundary rule 6 exempts exactly the integrator's harness modules (`gate*.py`, `cli.py`),
>   which must run the labs; a compensating rule forbids anything else from importing them.
> - Deviation from spec §2.1: the gate is split into `gate.py`, `gate_construction.py`,
>   `gate_measured.py` and `gate_rig.py` (Stage 5 precedent) to stay under ~800 lines per file.
>
> ## 7. Open items for the project lead
>
> 1. `DEFAULT_THRESHOLD == UNEXPLAINED_WEIGHT` with a `>=` alert rule (needs an ADR to change).
> 2. The learner cannot run at `detector_capacity` other than 64 and cannot switch G4 off, so
>    the CAPACITY_SWEEP points below 64 and HEL-F11 are UNMEASURED.
> 3. The drift discriminator's 3/3 false POISON_SUSPECT verdicts on legitimate changes.
> 4. Source independence keyed on process lineage is defeated by per-session repetition (§4).
> 5. E3 fails at M12 because NeverUpdate's F1 recall collapses at M09 when twin T3 appears.
> 6. Files over the ~800-line guideline: `chamber/evolution.py` 1635, `labs/endurance.py` 1030,
>    `capsule/experience_capsule.py` 1017, `memory/semantic.py` 893, `capsule/quarantine.py`
>    882, `promotion/controller.py` 848 (spec §2.1 forbids adding modules to split them).
>
> ## Honesty ledger
>
> ### MEASURED
> | claim | value | how it was produced (module:function) | experiment id | synthetic? |
> |---|---|---|---|---|
> | injections refused, digest changes | 6/6, 0 | gate_construction:check_raw_telemetry_cannot_modify | PS-S6-20260926-H6-helios-gate-0001 (not registered) | yes |
> | §0 single-source probe | 25 refusals, 0 admissions; control 3 admissions | gate_construction:_single_source_probe | same | yes |
> | P1 at x16 through one gateway | 96 poisoned capsules -> 6 CandidateAdmissions | gate_measured:_poisoned_admissions | same | yes |
> | automatic probation rollback | 1, byte-identical, pre-promotion digest | gate_construction:check_rollback_restores (rig) | same | yes |
> | learned items after 12 / 60 months | 0 / 0 | gate_measured:check_provenance_and_lineage | same | yes |
> | Stage 6 benign FP rate, every month | 1.0 | labs.endurance:run_endurance | same | yes |
> | incremental RSS, 12-month loop | 552960 B (gate run 1, loadavg 4.31 5.27 6.02); 471040 B (gate run 2, loadavg 15.41 12.04 8.45) | gate_measured:resource_measurement | same | yes |
> | FullRetrain / Stage 6 work, stored | 84.418, 0.475 | gate_construction:check_retraining_off_endpoint | same | yes |
> | store growth months 25-36 -> 49-60 | lineage 1503 -> 2514 nodes; gateway 732 -> 1220 | gate_measured:check_bounded_growth | same | yes |
> | endurance preconditions | DEGENERATE (E1 oracle recall 1.0/1.0/1.0; E3 naive 0.0 vs never-update 0.0 at M12) | labs.endurance:check_preconditions | same | yes |
>
> ### UNMEASURED
> | claim the architecture makes | why not measured | what would measure it | blocking? |
> |---|---|---|---|
> | EWC/SI, LwF, adapter isolation, dynamic expansion | no parameters to act on (ADR-0050) | a neural learner behind a research boundary | no |
> | ONNX export and INT8/INT4 runtime | no numpy/ONNX (ADR-0050) | same | no |
> | quantised variant acceptance | no BASELINE item in any learned state, so agreement is None (ADR-0059) | a state with baselines | no |
> | Stage 6 at detector capacity 4 and 8 | chamber/consolidator take no capacity parameter | a capacity keyword (spec change) | yes, for G6.13 |
> | HEL-F11 counterfactual rehearsal ablation | the controller runs G4 with no switch | a G4 flag | yes, for G6.13 |
> | real upgrade drift, real host RSS | synthetic signals; dev host | a device and real package upgrades | no |
>
> ### REJECTED
> | component | measured effect | verdict (REJECTED / NOT-YET-JUSTIFIED / RETRACTED / INERT / DEGENERATE) | ADR |
> |---|---|---|---|
> | HEL-F07 epistemic half-life | firing 0, delta 0.0 | INERT | 0057 |
> | HEL-F10 memory competition | firing 0, delta 0.0 | INERT | 0057 |
> | HEL-F21 resurrection | firing 0, delta 0.0 | INERT | 0057 |
> | HEL-F25 melt/retire by half-life | firing 0, delta 0.0 | INERT | 0057 |
> | HEL-F08 plasticity field | firing 3, delta 0.0 on a DEGENERATE corpus | DEGENERATE | 0057 |
> | HEL-F15 value-aware rehearsal | firing 1, delta 0.0 on a DEGENERATE corpus | DEGENERATE | 0058 |
> | HEL-F19 drift discriminator | firing 3 (3/3 false POISON_SUSPECT), delta 0.0 | NOT-YET-JUSTIFIED | 0058 |
> | anti-forgetting stack as a whole | R_new 0.0, R_old 0.0 | NOT-YET-JUSTIFIED | 0058 |
>
> ### RETRACTED
> | retracted claim | where it was published | the defect | corrected value |
> |---|---|---|---|
> | none this wave | — | — | — |
>
> ### NOT A DETECTION RESULT
> Every corpus is synthetic; every Stage 5 record is simulated. Nothing here is a detection result.
>
> ### PARAMETERS
> Every §4.21 constant is chosen, not measured: `MIN_INDEPENDENT_GROUPS` 3,
> `MIN_INDEPENDENT_LABEL_GROUPS` 2, the §39 budgets (15/15/20/10/15 MiB normal), `MAX_*` store
> caps, `UNEXPLAINED_WEIGHT` 0.5, `DEFAULT_THRESHOLD` 0.5, `HALF_LIFE_H0` 2048, `PLASTICITY_FLOOR`
> 0.05, `EPS_SECURITY` 0.02, `EPS_FP_RATE` 0.01, `MIN_SHADOW_SESSIONS` 32, `SHADOW_SAMPLE_EVERY`
> 4, `CANARY_WINDOW_SESSIONS` 64, `PROBATION_SESSIONS` 128, `FPR_BUDGET` 0.05,
> `SESSIONS_PER_MONTH` 16, `CAPACITY_SWEEP` (4, 8, 64), `REPLAY_BUDGETS_BYTES` (16384, 65536,
> 262144), `POISON_MULTIPLIERS` (1, 4, 16) and the rest of the table — chosen, not measured. The
> gate rig's threshold 0.6 and its shortened canary/probation windows (8/16) are also chosen.
