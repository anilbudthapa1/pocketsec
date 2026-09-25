# ADR-0036 — Competing worlds are not yet justified against single-world MAP

- **Status:** Accepted
- **Date:** 2026-09-25
- **Stage:** 4
- **Deciders:** Stage 4 integrator
- **Supersedes / superseded by:** none

> This is a **measurement ADR**. ADR-0125's rule applies: a rejection branch needs a
> reproduced measurement, not a flag and a filename. The measurement below was produced by
> `python -m pocketsec.stage4.cli gate` in the session that wrote this file, and every
> figure is reproducible from `pocketsec/stage4/labs/baselines.py:run_baselines` on the
> stated corpus and seed.

## Context

Stage 4's central claim is that *maintaining a bounded set of competing security worlds,
with visibility-aware negative evidence and cost-aware active sensing, resolves incidents
with fewer unsupported claims and at lower total cost than committing to a single best
explanation.*

B1 `SingleWorldMAP` is the control for the entire multi-world machinery (D4.5, D4.12): the
same engine code path with `max_worlds=1` and no fission or fusion. B8 `NoStage4` is the
control for the stage existing at all. Spec §1.1 said in advance that B1 may well win on
synthetic data and that the honest outcome is to say so.

**The measurement, on `build_incident_corpus(count=60, seed=11)`, all nine rows in one
process, `/proc/loadavg` 1.86 1.48 1.55:**

| baseline | world-set recall (signal coverage) | telemetry bytes | cpu_units | work units |
|---|---|---|---|---|
| B1 SingleWorldMAP | 0.3167 | 18426 | 1.9563 | — |
| B3 AlwaysOnRichTelemetry | **1.0000** | **14880** | ~6e-05 | 240 |
| B8 NoStage4 | n/a (proposes no world) | 0 | ~1.4e-05 | 30 |
| **CBF_LUCID** | 0.9000 | 18426 | **8.5860** | 204088 |

Three results decide this ADR, and the first of them decides it on its own.

1. **`saturation_guard` reports DEGENERATE**: best 0.6667 within 0.01 of median 0.6667.
   Under the project's own rule (spec §7, rule 2) a degenerate split records **no
   comparison**. Four of the nine baselines are at or below the corpus base rate 0.3333
   (B2, B3, B5, B6) and their comparison is refused rather than reported.
2. **The Pareto frontier contains exactly one member, `B8_NoStage4`.** CBF_LUCID is
   dominated, as is every other baseline.
3. **The `LucidConfig` flag ablation returns 0 of 10 flags JUSTIFIED**, with all nine rows
   coming out `DEGENERATE` at `world_set_recall`. No OPTIONAL `CBF-F*` id carries a measured
   delta.

A fourth measurement explains the third and is the reason this ADR does not go further:
**no step of the LUCID loop writes a world's `support` back into the field.**
`WorldSupport.combine` is called from `pocketsec/stage4/counterfactual/` and from the labs,
and from nowhere under `pocketsec/stage4/engine/`. Traced over a 74-transition incident,
every world sat at log-odds `0.0` / `UNRESOLVED` at every step. The support vector the
whole comparison rests on is uniform and static, so `IdentifiabilityState` is
`UNIDENTIFIABLE` on 60/60 cases, `confidence` is `0.0` on 60/60, and every counterfactual
support shift is exactly `+0.0000`.

## Decision

**Competing-world cognition is recorded as NOT-YET-JUSTIFIED, not REJECTED, and the
machinery is retained pending one specific fix.**

Three parts, each of which the code must obey:

1. **No Stage 4 document, docstring or gate detail may claim that competing worlds beat a
   single-world control.** `G4.10` fails and says why. `docs/stage-4-findings.md` leads with
   the negative result.
2. **The distinction between NOT-YET-JUSTIFIED and REJECTED is load-bearing here.** ADR-0009
   got this right under pressure: on a corpus with no headroom, "no measured benefit" cannot
   demonstrate absence of benefit, and two of the three components flagged there later turned
   out to be *actively harmful* on a corpus that did have headroom. Removing the world
   lifecycle on a DEGENERATE split would be the same error with the sign flipped.
3. **The retention is conditional and the condition is named.** The belief-update defect
   above must be fixed, with its own ADR and its own measurement, before G4.10 is re-run. If
   the comparison is still lost with a support vector that moves, ADR-0036 is amended to
   REJECTED and the multi-world machinery is removed.

## Options considered

| Option | Security cost | Resource cost | Complexity | Why not chosen |
|---|---|---|---|---|
| **A. Record NOT-YET-JUSTIFIED, retain, name the condition** (chosen) | none: the gate fails and no claim is made | the machinery stays on disk: 61 modules, ~29.6 KB peak incident state measured | unchanged | — |
| B. REJECT and remove the world lifecycle now | would discard the four properties that *are* settled (claim separation, zero unsupported claims, bounded state, crash isolation) | saves all of Stage 4's cost | large reduction | The split is DEGENERATE. A rejection on a split that cannot tell models apart measures the split (ADR-0010's finding across four corpora, and ADR-0120's guard exists for exactly this). ADR-0125 forbids a rejection branch without a reproduced measurement that *discriminates* |
| C. Fix the support update inside this integration pass, then re-measure | none | none | moderate | The integrator would author the belief-update arithmetic that G4.2 and G4.10 then score, on the corpus it is scored on — the authorship confound spec §6.1 names as the reason those criteria cannot be settled by this wave. A mechanism written by the party grading it is not a measurement |
| D. Report the signal-coverage recall of 0.9000 as the headline | **high**: it reads as near-success | none | none | `B3_AlwaysOnRichTelemetry` reaches **1.0** on that metric by its own docstring's admission — it collects everything and reasons about nothing. A metric a do-nothing control saturates is measuring the metric. The spec's own two clauses give 0.1167 and 0.0333 |
| E. Lower `MIN_WORLD_SET_RECALL` from 0.9 to what was measured | **highest**: a criterion restated until it passes | none | none | ADR-0113, and the most useful defect class found in Stage 2: four gate numbers were structurally incapable of coming out differently. No threshold in this stage was moved to change an outcome |

## Consequences

**Accepted costs.** Stage 4 ships machinery that has not earned its keep on any corpus
available here, and the gate says so on every run. A reader who wants a working incident
resolver does not have one. The cost of *not* removing it is 61 modules of maintained code;
the cost of removing it would be the four properties that are settled, which are the only
part of this stage with independent value.

**Bounded state.** Unchanged by this decision. Measured under
`build_world_flood(count=40, seed=23)`, sampled at all 1120 update steps: worlds 3/8, graph
nodes 9/512, edges 5/1024, claims 12/256, reasoning units 2961/4096, state bytes
29651/8388608, with 5028 `Truncation` records recording every loss. The bounds hold; the
world bound was never reached, so this run does not exercise degradation *at* the bound.

**Reversibility.** Nothing is compiled or learned, so there is no demotion path to build.
Removal is deleting `worlds/lifecycle.py`, `worlds/tombstone.py`, `graph/`, and the
`max_worlds > 1` path in `engine/lucid.py`; the typed claim graph (`claims/`) and the
degradation contract (`engine/degradation.py`) are independent of the world set and would
survive it. That independence is deliberate and is why F1's stated consequence — "reduce
Stage 4 to B6 plus the typed claim graph" — is a real option rather than a rhetorical one.

**Authority.** No. Nothing here moves Stage 4 closer to execution authority. The Stage 5
seam stays plain JSON carrying `information_gaps` — questions, not instructions — and no
dataclass field in the stage names a `FORBIDDEN_AUTHORITY_FIELDS` token
(`tests/test_stage4_boundary.py`).

## Verification

A reviewer confirms this ADR by running the measurement, not by reading it:

- `python -m pocketsec.stage4.cli gate` — G4.10 reports FAIL, names the DEGENERATE verdict,
  lists the refused baselines and prints the frontier.
- `python -m pocketsec.stage4.cli baselines` — the nine-row table and the saturation guard.
- `python -m pocketsec.stage4.cli ablation` — the nine ablation rows and their verdicts.
- `tests/test_stage4_gate.py::test_g4_10_runs_the_saturation_guard_before_recording_a_comparison`
  pins that the guard runs *first* and that a degenerate split records no comparison.
- `tests/test_stage4_gate.py::test_the_coverage_reading_is_saturated_by_a_do_nothing_control`
  pins option D's refutation as a measurement: B3 reaches exactly 1.0.
- `tests/test_stage4_gate.py::test_the_gate_reports_failed_and_says_which` fails if G4.10
  ever passes without the defect above being fixed.

## Prior art

No claim of novelty is made by this ADR, so no prior-art entry is required for one. Stage 4
binds to H3 (`literature_status = NOT_REVIEWED`) and H7 (`NOT_REVIEWED`) in
`docs/prior-art/ledger.json`; no H10 was minted (spec §2.9). The negative result recorded
here is a property of this repository's corpora, not a claim about the literature.


## Amendment — 2026-09-26, review-fix wave (S4-REV-04, S4-REV-05, S4-FC-08, S4-CPLX-01)

Three corrections, each measured in the review-fix session.

1. **Detection scoring.** The engine rows scored `int(not abstained) == label`, which credited
   every abstention as a correct benign call. Scored on the verdict, with abstentions reported as
   coverage and never as hits, `CBF_LUCID`, `B1_SingleWorldMAP` and `B7_InformationGainPlanner`
   score **0.0 detection accuracy at 0.0 coverage** on `build_incident_corpus(count=60, seed=11)`;
   `B4_PhiThresholdPlaybook` and `B8_NoStage4` score **0.6667**. Competing worlds do not beat
   single-world MAP because neither commits to anything, and neither beats Stage 1's Φ path.
2. **Every engine verdict is `UNKNOWN` on 60 of 60** (it was `UNIDENTIFIABLE`): the fields hold only
   UNKNOWN-family worlds, which the identifiability test now recognises whatever their suffix.
3. **Seven of nine `LucidConfig` flags are inert by construction** — their results are discarded
   or never read — so their ablation could only ever read 0.0. They default off and are marked
   `INERT` in the ablation. With them on, the 60-incident walk spent 250905 work units against
   241266 off, and because the §20 horizon is now charged in work units, 29 of 60 incidents came
   out different (fewer worlds) purely because inert passes closed the horizon sooner.

Measured but not acted on: replacing the Sparse World Graph (D4.12) with a no-op left every
verdict, world, claim graph and Stage 5 hypothesis byte-identical on the same walk. The graph is
read by no decision. **The measurement supports removing it**; it is kept only because G4.9
measures its bounds and no ADR number is free in this stage's block to record the removal.
