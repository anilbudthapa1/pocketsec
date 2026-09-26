# ADR-0048 — SAFE/AEGIS planning machinery is not justified against the fixed playbook

- **Status:** Accepted (measurement). The removal it recommends is **Proposed** for the
  project lead; no code was deleted by this ADR.
- **Date:** 2026-09-26
- **Stage:** 5
- **Deciders:** Stage 5 integrator
- **Supersedes / superseded by:** none

> This is a **measurement ADR** (ADR-0125's rule: a rejection branch needs a reproduced
> measurement). Every figure below was produced in the session that wrote this file by
> `python -m pocketsec.stage5.cli gate` and `python -m pocketsec.stage5.cli baselines`, all
> arms in one process on one corpus through the real SENTINEL and the real executor against
> `SimulatedHost`. It is a within-model result (§6.1): "collateral" is defined by harm tables
> authored by the same wave as the planner.

## Context

The lead: the SAFE Action Field, the Pareto/regret selector, the Counterfactual Response
Twin and the Intervention Cone must beat a static "if Φ above threshold, suspend" table on
measured collateral and effectiveness, or be reported as not justified.

**The measurement** — `build_response_corpus(count=20, seed=11)`, corpus digest
`07fe384c7ece3b28754aec1cc798277c063922bd2046f7b870fc6a38a76cf795`, 10 hostile and 10
benign-admin cases:

| arm | contained (of 10) | actions | collateral_per_1000 | work units | escalations |
|---|---|---|---|---|---|
| **AEGIS** (full planner, every flag on) | **0** | 10 | 0.0 | 2700 | 10 |
| B1 act-never | 0 | 0 | None | 360 | 0 |
| **B2 fixed playbook** | **10** | 10 | **0.0** | **380** | 0 |
| B3 if-then per mechanism | 10 | 20 | 500.0 | 400 | 0 |
| B4 act-always | 10 | 20 | 500.0 | 400 | 0 |
| B5 D3FEND lookup | 0 | 0 | None | 360 | 0 |
| B6 scalar utility | 0 | 10 | 0.0 | 2700 | 10 |
| B7 single-world | 0 | 10 | 0.0 | 740 | 10 |
| B8 no hysteresis | 0 | 10 | 0.0 | 2700 | 10 |
| B9 human only | 10 | 20 | 0.0 | 410 | 20 |

- `saturation_check`: **not degenerate** (best B2 contains 10, median AEGIS contains 0).
- Pareto frontier on (contained, collateral, work units): **{B1, B2, B5}**. AEGIS is not on it.
- `run_ablation` for all eleven OPTIONAL core ids: every delta **0.0**, verdict
  `NOT_YET_JUSTIFIED` (the planner never takes an autonomous intervention, so switching any
  mechanism off cannot change what it contains).
- G5.9, `build_ambiguous_pairs(count=30, seed=17)`: **DEGENERATE** (B4 act-always reaches
  the best containment, 30, at collateral 500.0); full planner and B7 both contain 0.

**Why AEGIS contains nothing, measured rather than guessed.** Cold, the effectiveness memory
holds no rollback samples, `rollback_reliability` is `None` below eight, and `None` blocks
every autonomous leased intervention — so the planner escalates. That could have been an
artefact of priming, so G5.14 re-runs four planner arms with memory primed by in-simulator
`LAB_SANDBOX` drills (eight forced-rollback and eight clean drills per containment operator,
per case, keyed by the case's own mechanism):

| primed arm | contained | collateral_per_1000 | work units | escalations |
|---|---|---|---|---|
| AEGIS | **0** | 0.0 | 2700 | 10 |
| B6 scalar utility | 0 | 0.0 | 2700 | 10 |
| B7 single-world (no twin, no cone, no regret) | **10** | 0.0 | 770 | 0 |
| B8 no hysteresis | 0 | 0.0 | 2700 | 10 |

Primed, every rejected intervention on the hostile cases is rejected with reason `SHADOW`
(`ACTION_SHADOW_ABOVE_CEILING`, 20 of 20 intervention candidates across the 10 hostile cases,
measured by a diagnostic run of the planner on primed rigs). The cone's terms raise the
Action Shadow above `SHADOW_AUTONOMY_CEILING = 0.35`, a **chosen, uncalibrated** parameter
(F3 could not be evaluated: no committed intervention produced a residual to calibrate
against). With the twin and the cone off (B7), the generation-time shadow stays under the
ceiling and the same containment operators act — containing all ten at zero collateral.

**An integration defect found on the way, and what it did and did not change.** The action
field proposed *restoration* operators (`RESUME_PROCESS`, `RELEASE_LOCAL_SOCKET`, …) as
incident responses at the same class-proportional security prior as the containments they
undo; the baselines filtered them and AEGIS did not. The field now refuses them
(`safe/action_field.py:_eligible_specs`). Measured in this session by reverting the fix
in-process on the same corpus: with the defect, AEGIS took 20 actions — `RELEASE_LOCAL_SOCKET`
as "containment" on all 10 hostile cases, 0 escalations, 3600 work units — and contained 0;
with the fix it takes 10 observation actions, escalates the 10 hostile cases, spends 2700
work units, and still contains 0. The defect changed what AEGIS did; it did not cause this
ADR's result.

## Decision

1. **Falsifier F1 fired.** B2 reaches `incidents_contained` 10 against the full planner's 0,
   at collateral no higher (0.0 vs 0.0) and at 380 against 2700 work units.
2. **F4 fired (vacuously):** B6's scalar utility matches the frontier selector exactly —
   neither acts.
3. **F2's ablation clause fired:** `enable_twin` delta is 0.0 — `NOT_YET_JUSTIFIED`, not
   `REJECTED`, because the planner never acts and so cannot show a difference either way.
4. The SAFE/AEGIS planning machinery (twin, cone, Pareto/regret, multi-world evaluation) is
   recorded **NOT JUSTIFIED** on this corpus inside this model. **Recommendation (Proposed,
   for the project lead):** ship the fixed playbook behind SENTINEL and the transactional
   executor as the autonomous path, keep the planner as a recommendation generator for the
   human contract, and do not make the shadow gate a veto on autonomy until F3 can be
   evaluated. No flag default was changed: no delta was negative, so spec §6's "HARMFUL ⇒
   default off" rule does not apply.

## Options considered

| Option | Security cost | Resource cost | Measured consequence | Why not chosen |
|---|---|---|---|---|
| A. Keep AEGIS as the autonomous path | none added | 2700 work units per 20 cases | contains 0/10 cold and 0/10 primed | loses to a table |
| B. Lower `SHADOW_AUTONOMY_CEILING` until AEGIS acts | tunes an uncalibrated parameter to the corpus it is scored on | — | not attempted | the authorship confound §6.1 names |
| **C. Record F1; recommend playbook-behind-SENTINEL (chosen)** | none | 380 work units | — | — |

## Consequences

**Accepted costs.** The stage's elaborate machinery has no measured benefit here. The safety
machinery — typed operators, SENTINEL, identity, leases, evidence ordering, verification —
is unaffected by this ADR and is what the gate's construction criteria settle.

**What this is not.** Not evidence about a Linux host, and not evidence that the twin cannot
help anywhere: it is evidence that on this corpus, inside this model, the fixed playbook
matches or beats it.

## Verification

`python -m pocketsec.stage5.cli gate` (G5.9, G5.14 details) and
`python -m pocketsec.stage5.cli baselines`, `python -m pocketsec.stage5.cli ablation`.

## Prior art

No novelty claim is made.

## Measurement addendum — 2026-09-26, Stage 5 measurement wave

Appended, not rewritten: the text above stands as the integrator's record. Every figure
below was produced by a script in `benchmarks/stage5/` and registered in
`experiments/registry.jsonl` under the id given; all corpora synthetic, all hosts
`SimulatedHost`. No new ADR number was used because the Stage 5 block 0040–0049 is full.

**Two corrections to the Context above.**

1. *"Cold … `None` blocks every autonomous leased intervention — so the planner
   escalates."* The recorded rejection reason, cold, is `SHADOW` on 20 of 20 containment
   candidates across C1's 10 hostile cases — the same as primed. The cone-informed Action
   Shadow is 0.4146 (`SUSPEND_PROCESS`) and 0.3627 (`RESTRICT_LOCAL_SOCKET`) on every one of
   those cases against the 0.35 ceiling. Missing reliability would also block, but it is not
   what the planner records. (PS-S5-20260926-BASE-shadow-gate-0004)
2. *"B7 single-world (no twin, no cone, no regret)"*. B7 keeps Response Identifiability,
   which evaluates the rival world: on the hostile halves of 30 hostile-leading ambiguous
   pairs, primed B7 rejects 60 of 60 containment candidates `NOT_IDENTIFIABLE`, naming the
   benign rival. B7 is not the lead's baseline (2). A literal single-world control (SW:
   leading world + policy harm table, nothing else; `benchmarks/stage5/arms.py`) was added.
   (PS-S5-20260926-BASE-b7-identifiability-0010)

**F1's evidence is weaker than it reads, in B2's favour.** On
`build_response_corpus(20, 11)` host Phi is 4.0 on all 10 benign cases and 10.0 on all 10
hostile ones, so B2's single test equals `truth` on 20 of 20 and the unambiguous split is
solved by one field (PS-S5-20260926-BASE-corpus-audit-0003). On the decoupled counter-corpus
C2 (same resolutions and truth, a quarter of each class re-hosted), `[contained, collateral]`
is B2 `[5, 5]`, SW `[10, 0]`, primed B7 `[5, 0]`, AEGIS cold and primed `[0, 0]`
(PS-S5-20260926-BASE-arms-counter-corpora-0002).

**Ablation with headroom.** Primed, leave-one-out: removing `enable_twin`, `enable_cone` or
`enable_shadow_gate` (SAFE-F04/F05/F06) each moves AEGIS from `[0, 0]` to `[10, 0]` on C1
and `[0, 0]` to `[5, 0]` on C2, with no corpus on which removal adds collateral; every other
flag has no effect, cold or primed (PS-S5-20260926-BASE-ablation-primed-0005). By spec §6 /
G5.14 wording a harmful mechanism "is defaulted off with an ADR". **Not done here**: the
gate's own (cold) ablation shows 0.0, the three flags form one safety veto, and no ADR
number is free to record the default change. For the project lead.

**Sensitivity, not tuning.** With `SHADOW_AUTONOMY_CEILING` patched to 0.37–0.70 and memory
primed, AEGIS and B6 both read `[10, 0]` on C1, `[5, 0]` on C2 and `[0, 0]` on both pair
corpora — never better than SW on any corpus (PS-S5-20260926-BASE-shadow-gate-0004).

**Revised recommendation (Proposed).** Decision 4's "ship the fixed playbook behind
SENTINEL" is not supported by these measurements either: B2's advantage on C1 is the label
leak, and on C2 it takes 5 collateral actions where SW takes 0. The measurements support no
autonomous chooser yet, and on Stage 4's real exports nothing is selectable at all
(ADR-0045 addendum). If one must ship, the simplest arm dominated on no measured corpus is
SW-shaped: the leading world and the policy harm table, behind SENTINEL and the executor.

## Fix-wave addendum — 2026-09-26, Stage 5 fix wave

Four corrections. Each cites the code that shows it.

1. **The Counterfactual Response Twin and the Intervention Cone do not depend on the
   world** (finding R3; not fixed). `ResponseTwin.predict(candidate, *, world_id)` uses
   `world_id` only as a label on the returned `TwinPrediction`. Nothing else in the method
   reads it. The cone is built from that prediction plus an adaptation model derived from
   the host snapshot. The planner still builds one cone per Stage 4 world and predicts
   several times per candidate. Every one of those predictions is identical apart from the
   `world_id` label. So the
   architecture's "predict effects across plausible worlds" is not implemented. This is
   the cause of M.3's per-operator constant Action Shadow, which the measurement wave
   attributed to host shape without naming the mechanism. It is not fixed here, because
   world-dependent consequence tables would be a new model, not a repair. It strengthens
   this ADR's rejection: the twin and the cone evaluated no counterfactual.
2. **Under PARETO_THEN_POLICY the frontier stage cannot change the pick** (finding R5).
   `policy_pick` is a lexicographic minimum over all seven harms and then both benefits,
   which is every objective `dominates` compares, with exact comparisons. The lexicographic
   winner is therefore always on the frontier.
   `tests/test_stage5_aegis.py::test_the_frontier_stage_cannot_change_the_policy_pick`
   assigned random objective vectors to a real field's candidates 500 times. The pick with
   the frontier stage differed from the pick without it 0 times, while the frontier removed
   candidates in some trials. SAFE-F08's ablation (`enable_pareto=False`) must swap in
   `SCALAR_UTILITY`, so its delta measures lexicographic against weighted-sum, not frontier
   against no frontier. Falsifier F4's B6 = AEGIS reading stands, but it says nothing about
   the frontier itself.
3. **Four of G5.14's eleven OPTIONAL deltas were 0.0 by construction** (finding R7).
   `enable_residual` (SAFE-F16) and `enable_d3fend` (SAFE-F23) have no reader. The
   `PlannerConfig` docstring said "read by other subsystems", which was false and is
   corrected. `enable_response_cells` (SAFE-F21/F22) swaps a field that
   `generate_action_field` never reads; a tripwire object passed as the cells is never
   touched on any gate case. G5.14 now reports those four as inert and unmeasured. It
   reads "7/11 OPTIONAL ids carry a measured delta", not 11/11.
4. **Work units were double-counted for executor spend** (finding F10). `_score_receipt`
   added each receipt's `work_units`, and `run_arm` then added the whole `rig.governor`
   TOTAL, which already contains that spend. Sweeper transactions were counted once, so the
   inflation varied by arm on a Pareto axis. Fixed. This wave's gate run reads AEGIS 2690,
   B2 370 and B7 730 wu, against 2700, 380 and 740 in Part II §5. The ordering of the
   cold arms and the frontier (B1, B2, B5) are unchanged. Separately, primed B7 now
   contains 0, not 10: the earlier fix batch stopped scoring a no-op undo as a successful
   rollback, so the priming drills teach a reliability of 0.0 (findings Part III, F.0). The
   primed figures in the measurement addendum above predate that change.
