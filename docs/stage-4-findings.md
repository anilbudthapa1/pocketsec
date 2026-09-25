# Stage 4 — CBF + LUCID — findings

- **Status (review-fix revision, 2026-09-26):** the gate **reports FAILED** and exits 1; the
  per-criterion result of this revision's own run is in "Review-fix revision" directly below. The
  previous revision's "FAILED (7 of 12)" is that revision's run and is kept below for lineage.
- **Date:** 2026-09-25 (integration wave) and **2026-09-25, independent measurement session**
  (this revision).
- **Gate:** `python -m pocketsec.stage4.cli gate` — exit 1
- **Spec:** `docs/stage-4-spec.md`; architecture `docs/architecture/sources/stage-04-cbf-lucid.md`
- **Host:** Python 3.14.7, Linux 7.1.5+kali-amd64. Every figure carries the `/proc/loadavg` reading
  of the run that produced it. Load on this host moved between **1.62 and 14.12** during the
  measurement session — the high end is a full test suite of another wave's making, running in the
  same tree. **No absolute microsecond or millisecond figure in this document is a device
  measurement** (spec §2.8). Only within-run ratios transfer.

## Review-fix revision (2026-09-26) — read this before anything below it

A review wave refuted-then-confirmed 21 HIGH and 25 MEDIUM findings against this stage
(`S4-REV-*`, `S4-SEC-*`, `S4-FC-*`, `S4-RES-*`, `S4-MEAS-*`, `S4-CPLX-*`). This revision fixes the
ones that could be fixed without rewriting the stage, corrects every document claim they showed to
be false, and says plainly which ones remain. **Several statements further down this document were
false; each is now marked `RETRACTED (review-fix)` where it stands, and listed in the RETRACTED
table.** Every figure in this section was produced by code run in this revision's session, with the
load average beside it; none is a device measurement.

### What the fixes changed about the headline

The headline below said Stage 4 is "correct, bounded, isolated and honest" and "does not reason".
The review showed the first half was overstated in three places, and those are now fixed:

1. **The bounds were counters, not bounds.** `BudgetController.charge` saturated after the work
   had run, nothing checked `exhausted()` first, `IncidentState.transitions` kept every transition
   and was rescanned each update, the truncation log re-recorded the same refused edges each step,
   and nothing ever charged the §20 `ResolutionHorizon` (S4-REV-01, S4-SEC-01, S4-FC-04, S4-RES-01,
   S4-RES-03, S4-REV-10). Now: the budget is checked **before** the optional and fission passes
   and a refusal is recorded once; the horizon is charged every update (transitions, work units,
   granted escalations) and once it is spent the incident stops reasoning and only extends its
   evidence lineage; the shadow keeps only the `observation_incomplete` transitions that can change
   it (the identical shadow from a set bounded by the signal vocabulary); the truncation log is
   deduplicated and capped at 256 records plus one overflow record per kind.
2. **"Isolated" was measured on a stand-in.** G4.11 faulted only the integrator's hook harness, and
   passed with every `LucidEngine` entry point replaced by a raiser (S4-FC-01). Four calls in
   `resolve`/`close_incident` ran unguarded while the docstring said "Nothing here raises"
   (S4-FC-03), and the degradation ledger was engine-lifetime, so one fault downgraded and
   mis-attributed every later incident (S4-REV-06, S4-FC-09, S4-RES-04, S4-SEC-06). Now: G4.11 has
   an engine arm that patches a fault into 11 real call sites of the real engine; every call is
   guarded; each incident owns its ledger.
3. **"Honest" had a hole in the claim graph.** The compiler emitted, for every world, an
   authoritative DER reading "N observation(s) form the causal spine of <world>" — world
   attribution under a DER type — and G4.8 could not see it because it checks only shapes
   (S4-FC-02, S4-REV-09). That DER is removed; G4.8 now also checks every authoritative OBS digest
   against the digests the incident's Stage 1 telemetry actually carried, and fails any DER whose
   rule is outside a closed, currently empty catalogue. `kind_of` now reads the exact class, so a
   subclass can no longer relabel an INF as DER (S4-SEC-02, S4-FC-13).

The second half of the headline — **Stage 4 does not reason** — is unchanged and now reads more
starkly, because two fixes removed artefacts that had made it look like a partial answer:

- **Every engine verdict is now `UNKNOWN`, on 60 of 60 incidents** (it was `UNIDENTIFIABLE`). The
  engine only ever spawns `unresolved_novel_mechanism[.<sha12>]` worlds, and the identifiability
  test recognised only the un-suffixed id as the UNKNOWN family, so a field of UNKNOWN-family
  worlds was ranked as if it held mechanisms (S4-REV-05). A field of such worlds is not a set of
  mechanisms that could be identified or told apart, so `UNIDENTIFIABLE` claimed more than the
  field held.
- **The engine rows' 0.6667 detection accuracy was an artefact.** `int(not abstained) == label`
  scored every abstention as a correct benign call (S4-REV-04). Scored on the verdict itself, with
  abstentions counted as coverage and never as hits, `CBF_LUCID`, `B1_SingleWorldMAP` and
  `B7_InformationGainPlanner` all score **0.0 detection accuracy at 0.0 coverage** — they commit to
  a verdict on no case. `B4_PhiThresholdPlaybook` and `B8_NoStage4` (Stage 1's Φ path alone) score
  **0.6667**. That is the Pareto result stated without the artefact: **the simplest baselines are
  the only rows that commit, and Stage 4 adds nothing measurable to them on this corpus.**

```
$ PYTHONPATH=. PYTHONHASHSEED=0 python final_measure.py      # loadavg 1.32 1.30 1.52 -> 2.90 1.67 1.63
engine walk cpu_s 4.783 work_units 241266
identifiability {'UNKNOWN': 60}
prediction verdict {'UNKNOWN': 60}
horizon outcome {'REQUEST_HIGHER_OBSERVATION_TIER': 5, 'ESCALATE_TO_ANALYST': 55}
incidents whose horizon closed 53 of 60
max truncations per incident 40
authoritative claims 186
resolved claim_graph json bytes (max) 3451
degradation records 0
B1_SingleWorldMAP det_acc 0.0 coverage 0.0 nonident None recall 0.31666666666666665
B2_NaiveAncestryAttribution det_acc 0.3333333333333333 coverage None nonident None recall None
B3_AlwaysOnRichTelemetry det_acc 0.3333333333333333 coverage None nonident None recall 1.0
B4_PhiThresholdPlaybook det_acc 0.6666666666666666 coverage None nonident None recall None
B5_FixedWindowCorrelation det_acc 0.3333333333333333 coverage None nonident None recall None
B6_TwoStateHMM det_acc 0.3333333333333333 coverage None nonident None recall None
B7_InformationGainPlanner det_acc 0.0 coverage 0.0 nonident None recall None
B8_NoStage4 det_acc 0.6666666666666666 coverage None nonident None recall None
CBF_LUCID det_acc 0.0 coverage 0.0 nonident None recall 0.9
```

The script drives `gate_criteria.drive_engine` over `build_incident_corpus(count=60, seed=11)` with
Stage 1's AOP, tallies the states, verdicts and horizon outcomes, and prints
`labs/baselines.run_baselines` for the same corpus; it lives in this session's scratchpad and is
reproduced by those two calls. `nonident None` means the corpus has no case labelled
UNIDENTIFIABLE, so that column is not computable on it — it is not a zero.

### The gate, this revision

`python -m pocketsec.stage4.cli gate; echo "exit=$?"` at loadavg 12.51 7.11 3.76 (another wave's
suite was running) — status lines verbatim, detail strings elided:

```
  [FAIL] G4.1  Partial-observability and visibility models empirically measured
  [FAIL] G4.2  CBF preserves the ground-truth world or an equivalent explanation
  [PASS] G4.3  Constructed non-identifiable cases are explicitly recognised
  [FAIL] G4.4  Evidence Tension and Sensor Shadow behave correctly under dropped telemetry
  [FAIL] G4.5  At least one active sensing method reduces bytes/CPU versus always-on telemetry
  [FAIL] G4.6  Counterfactual stress identifies predefined spurious causal explanations
  [FAIL] G4.7  Typed Claim Graph enforces OBS/DER/INF/CF/EXT/UNK separation
  [PASS] G4.8  Authoritative output contains zero unsupported factual claims
  [FAIL] G4.9  World count, graph size and reasoning work remain hard bounded
  [FAIL] G4.10  CBF/LUCID beats or complements simpler baselines on the measured Pareto frontier
  [PASS] G4.11  Stage 4 remains optional to core Stage 1-3 detection if it crashes
  [PASS] G4.12  All novelty claims remain provisional until formal prior-art/patent review

GATE: FAILED (8)
exit=1
```

Against the previous revision's FAILED (7): **G4.7 moved PASS -> FAIL** (its only DER was the
laundering one, S4-FC-02); every other status is unchanged, but G4.8, G4.9 and G4.11 now measure
what they claim to (digest-anchored claims; one long incident and a hit world bound; the real
engine). G4.9 still fails on its ground-truth-survival clause alone (0 of 40).

### Measured before/after, within this revision's session

| quantity | before the fix | after | how measured |
|---|---|---|---|
| One incident held open over all 1120 same-epoch flood transitions: per-update cost at the end vs the start | review: 2.83 → 18.50 ms/update at 200 → 1000 held transitions (reproduced by the reviewers; not re-run on the old code here, the old code no longer exists in the tree) | CPU-per-update ratio, last 100 ÷ first 100 updates, **1.088** at loadavg 1.89 and **0.675** at loadavg 8.78 in the final gate run (contention, not signal); the horizon closes at update **55**, after which an update costs **1** work unit | `gate_bounds.long_incident_bounds`, G4.9 |
| Same long incident: state bytes at half-way and at the end | grew ~1.4 KB per update (review) | **54781 and 54781** — flat; `engine.memory_bytes()` **4860 → 4860** | same |
| Same long incident: truncation log | 13895 records over 1397 transitions (review) | **257** of a 267 cap | same |
| Short flood `build_world_flood(40, 23)`: truncations | 5028 (previous revision) | **217**, because a re-reported identical loss is no longer a new record | `gate_probes.flood_bounds`, G4.9 |
| World bound hit at `max_worlds=2`: world-kind `Truncation` records | **0** — the refusal was discarded | **40**, one per distinct explanation refused a birth | `gate_bounds.capacity_bounds`, G4.9 |
| Inert flags on vs off, 60-incident walk (flags `enable_sequential_evidence`, `_counterfactual`, `_self_questioning`, `_stress`, `_cell_feedback`) | on: **250905** work units | off: **241266**; the output differed on **29 of 60** incidents, and only through the horizon — the inert passes spent units that closed it earlier, so e.g. `s4-inc-0011-0004` held 3 worlds with them on and 4 with them off | `drive_engine` with each `LucidConfig`, fingerprinting verdicts, world ids and claim graphs; loadavg 1.51 1.34 2.02 |
| Sparse World Graph (D4.12) replaced by a no-op | — | every verdict, world, claim graph and Stage 5 hypothesis row **byte-identical** (fingerprint `6e0d4a73db7259ce` both ways); walk CPU 4.663 s vs 4.576 s at loadavg 3.46 — a 2% difference inside the contention on this host, not a measured saving | patched `SparseWorldGraph.add`/`link` to no-ops, same walk (S4-CPLX-01) |

### Per finding: what was done

| finding | disposition | where |
|---|---|---|
| S4-REV-01, S4-SEC-01, S4-FC-04, S4-RES-01, S4-RES-03 | **fixed**: budget checked before optional/fission passes; horizon charged and obeyed; shadow evidence bounded; truncation log deduplicated and capped; `memory_bytes()` counts the incident's state | `engine/lucid.py`, `engine/lucid_bounds.py`, `engine/lucid_support.py`, `graph/sparse_world_graph.py:append_truncations`, `graph/entropy_budget.py:units_exhausted` |
| S4-REV-10 | **fixed**: horizon charged every update; ESCALATE_TO_ANALYST is reached on 55 of 60 incidents | `engine/lucid_bounds.py:charge_horizon` |
| S4-SEC-09 | **fixed**: granted escalations charge the budget and the horizon; the planner is handed `escalations_remaining()` | same, `engine/lucid_steps.py:plan_observation` |
| S4-REV-03 | **fixed**: a plan whose refusals are about wiring (no AOP, unmeasured or non-positive cost) yields INSUFFICIENT_EVIDENCE, never UNIDENTIFIABLE; every engine the labs and the flood build now has an AOP | `sensing/active_plan.py:NOT_ATTEMPTED_REASONS`, `identifiability/resolution.py`, `labs/baselines.py`, `gate_probes.py` |
| S4-REV-04 | **fixed**: verdict-based scoring; abstention is coverage, never a hit | `labs/baseline_metrics.py:predicted_label` |
| S4-REV-05, S4-FC-06 | **fixed**: the whole UNKNOWN family maps to UNKNOWN; a lone world's margin comes from its own support | `identifiability/resolution.py:is_unknown_mechanism`, `self_margin` |
| S4-REV-06, S4-FC-09, S4-RES-04, S4-SEC-06 | **fixed**: per-incident ledgers, rolled up for reporting; unusable locators fall back to a digest label instead of aborting the compile | `engine/lucid_bounds.py:incident_ledger`, `claims/compiler.py:_evidence_label` |
| S4-REV-07 | **document corrected**: G4.4's detail and the text below now give the real cause of `confidence == 0.0` (world uncertainty pinned at 1.0 by construction, plus the hole rule), not the frozen support vector. The confidence formula is **unchanged**; see "Still open" | `gate.py` G4.4 |
| S4-FC-01, S4-MEAS-06 | **fixed**: G4.11 engine arm over the real `LucidEngine`, 11 fault points, per-incident scoping checked | `gate_optionality.py` |
| S4-FC-02, S4-REV-09 | **fixed**: spine DER removed; digest anchoring and a closed DER catalogue in G4.8. **Consequence: G4.7 now FAILS**, because its behavioural half required a DER on real output and the only one was the laundering one. The requirement was not relaxed | `claims/compiler.py`, `claims/graph.py`, `gate_probes.py:claim_support_audit` |
| S4-FC-03 | **fixed**: every call in `resolve`/`close_incident` guarded; export falls back to a minimal field, then to a record built from primitives | `engine/lucid.py`, `engine/lucid_bounds.py` |
| S4-FC-05, S4-RES-02 | **fixed**: a birth refused at capacity is a world-kind `Truncation` carrying the residual's consequence; G4.9 now requires world-kind records at the bound | `engine/lucid_steps.py:_capacity_loss`, `gate_bounds.py` |
| S4-FC-07, S4-MEAS-05 | **document corrected, check made honest**: G4.5 reports its ratios as labelled proxies and the telemetry clause as UNMEASURED; it cannot pass until telemetry is modelled per collected event | `gate.py` G4.5, ADR-0037 amendment |
| S4-FC-08, S4-REV-11, S4-CPLX-02 | **fixed**: the seven inert flags are declared in `INERT_FLAGS` with the reason, default **off**, and the ablation marks them `INERT` rather than computing a structural 0.0 | `engine/lucid_support.py:INERT_FLAGS`, `labs/experiments.py` |
| S4-FC-10 | **fixed and re-measured**: the resolved field carries the compiled graph; the published `claim_graph 142` is RETRACTED; the real largest resolved graph on the corpus is **3451** JSON bytes | `engine/lucid.py:_resolve` |
| S4-MEAS-07 | **fixed**: one baseline table per gate run, shared by G4.2, G4.5 and G4.10 | `gate.py:Stage4GateContext.baselines` |
| S4-REV-02 | **fixed**: one likelihood ratio per transition over that transition's own signals | `engine/lucid_steps.py:accumulate_evidence` |
| S4-REV-12, S4-SEC-03, S4-SEC-08 | **fixed**: duplicate row ids refused; `from_dict` runs the export walk; authority-named keys refused on every construction path; the walk is memoised | `stage5_walk.py` |
| S4-SEC-05, S4-FC-14 | **fixed**: a well-typed engine outcome with an unusable value degrades the slot; a wrong return **type** still raises (an existing test pins that as a wiring error) | `slot.py` |
| S4-SEC-07 | **fixed**: stress counts distinct evidence digests, not claims | `crystal/feedback.py` |
| S4-FC-11, S4-FC-12, S4-FC-17, S4-CPLX-01, S4-CPLX-03 | **documented** in the ledger below; no code change | this document |
| S4-REV-13, S4-REV-14, S4-SEC-04 | **still open** — see below | — |

### Still open, and why

- **Confidence is structurally 0.0 (S4-REV-07).** `confidence_of` uses `1 - leader.uncertainty` and
  every engine world's uncertainty is 1.0; separately the hole rule zeroes it whenever any expected
  signal is unobservable, which the lifecycle's self-named signals are on every incident. Deriving
  uncertainty from evidence is new cognition, subject to the same authorship confound as the
  support update (spec §6.1), so it was not written here. **G4.4's F4 clause therefore still cannot
  fail, and fixing the support update alone would leave it just as vacuous.**
- **The §23 `against` section can never be filled (S4-REV-13).** OBS subjects are
  `evidence:<locator>` and `forbidden_evidence` holds signal names; the two never match. Filling it
  needs OBS claims that name the signal they evidence — a claim-schema change, not a fix.
- **Two death rules (S4-REV-14).** `EvidenceTension.is_fatal()` (exported as `fatal`) is an OR of
  three routes; the engine's `death_cause` requires sustained AND over-threshold. Three tests in
  `tests/test_stage4_visibility.py` pin the OR semantics, so unifying them is a decision about
  which rule is correct, recorded here rather than made silently.
- **The verbalizer guard is a denylist (S4-SEC-04).** Latent: the engine always passes
  `verbalizer=None`. An allowlist guard is the fix when a model is ever attached.
- **The Sparse World Graph is read by nothing (S4-CPLX-01)**, measured above: removing it changes
  no output byte. It is kept because G4.9 measures its bounds and D4.12 names it; **the measurement
  supports removing it**, and that belongs in a Stage 4 ADR when a number is free.
- **Lifecycle death, fission, fusion and dominance pruning never fire on any corpus here
  (S4-CPLX-03).** Not re-measured in this revision; the review's claim is carried, not asserted.

## How to read this revision

This revision was written by a measurement session that ran every number again from scratch. It
does three things, in order of importance:

1. It **reproduced** the integration wave's central result: the LUCID loop never writes belief back
   into the field, so every world's support is identically `0.0` and nothing resolves.
2. It found **four new defects in the measurement apparatus itself** — not in the cognition — each
   of which made a gate figure structurally incapable of coming out differently. Three of them made
   Stage 4 look *worse* than it is; one made it look *better*. All four are recorded below with the
   command that exposed them. This is `MEMORY.md` lesson 10 firing for the second time in this
   repository: *before believing a gate figure, ask what input would change it.*
3. It **filled four gaps** the integration wave left as UNMEASURED: per-component bytes,
   degradation at the world bound, CPU per unit of work, and whether Stage 4's one apparent win
   over its control survives inspection. It does not.

Every figure in the MEASURED table below was produced by running code in this session. Figures the
integration wave produced and this session did **not** reproduce are marked `CARRIED` and are not
asserted as this session's measurements.

---

## The headline, stated before anything flattering

**Stage 4's cognition machinery is correct, bounded, isolated and honest. It does not reason.**

Those are two separate results and both are measured.

The four criteria the spec said this wave could actually settle (§6.1) — claim-kind separation,
zero unsupported authoritative claims, bounded state, and crash isolation — are settled. Three pass
outright and the fourth (G4.9) fails on one clause while **every bound it was built to hold, holds**.

> **Review-fix correction.** "Correct, bounded, isolated and honest" was overstated in three places
> (bounds that were counters, isolation measured on a stand-in, and an authoritative DER that
> carried world attribution); all three are fixed and described in "Review-fix revision" at the top.
> Of the four construction criteria, **two now pass (G4.8, G4.11)**: G4.9 still fails only on the
> ground-truth-survival clause, and **G4.7 now fails** because the only DER the engine ever emitted
> was the laundering one and it has been removed.

The six criteria about whether competing-world reasoning *resolves incidents* fail, and they fail
for **one shared reason** that everything else is downstream of.

### The defect that dominates the result — reproduced independently this session

**No step of the LUCID loop ever writes a world's `support` back into the field.**

Verified two independent ways this session — by grep over the code, and by trace over the corpus.

```
$ grep -rn '\.combine(' pocketsec/stage4/ | grep -v __pycache__
pocketsec/stage4/counterfactual/intervention.py:322:        worlds.append(replace(world, support=world.support.combine(llr)))
pocketsec/stage4/counterfactual/stress.py:208:        worlds.append(replace(world, support=world.support.combine(SUPPORT_SENSITIVITY * delta)))
$ grep -rn 'combine\|support=' pocketsec/stage4/engine/*.py | grep -v __pycache__
   (no output)
```

`WorldSupport.combine` has **two** call sites in the whole of Stage 4, both under
`counterfactual/`, and **none** under `pocketsec/stage4/engine/` — which contains no `support=`
assignment either. The belief-update rule is not merely inert; it is absent.

And the consequence, measured over the whole gate corpus:

```
$ python -m pocketsec.stage4.cli gate            # loadavg 1.86 2.12 2.78
... (full output pasted in "Commands and their real output" below)

$ python - <<'PY'   # the support trace; full script pasted below
=== over all 60 incidents ===
distinct world support.value: [0.0]
distinct resolution.confidence: [0.0]
distinct verdict.support_margin: [0.0]
identifiability state tally: {'UNIDENTIFIABLE': 60}
```

Three distinct-value sets, each of size one, over 60 incidents and 4372 Stage 1 transitions. The
engine resolved `IDENTIFIED` on **0 of 60** cases.

**One refinement of how the integration wave stated this.** That wave wrote that "the support
vector is uniform and static for the whole incident". The support *values* are static at `0.0`;
`field.support_vector()` is not, because it normalises equal log-odds into an equal share and the
share changes when the world **count** changes. Measured on `s4-inc-0011-0000` (58 transitions,
3 worlds), `support_vector()` took **four** distinct states across the walk:

| state | value |
|---|---|
| `()` | before the first world is born |
| 3 worlds | `0.3333, 0.3333, 0.3333` |
| 2 worlds | `0.5, 0.5` |
| 1 world | `1.0` |

Every one of those is `1/K`. The vector moves only with `K`; it never moves with evidence. A reader
who saw the vector change could reasonably conclude belief was updating. It is not.

Everything that reads support therefore reads a tie:

| downstream quantity | measured value, all 60 corpus cases | consequence |
|---|---|---|
| world `support.value` (LOG_ODDS) | `0.0` | no world is ever favoured |
| `IdentifiabilityVerdict.support_margin` | `0.0` | never reaches `IDENTIFIABILITY_MARGIN` |
| `IdentifiabilityState` | `UNIDENTIFIABLE` on 60/60 | `IDENTIFIED` on 0/60 |
| `IncidentResolution.confidence` | `0.0` on 60/60 | G4.4's F4 inequality holds vacuously |
| counterfactual `support_shift` | `+0.0000` on every perturbation | G4.6 cannot discriminate |
| best `signal_discrimination` any action reached | `0.0922` against a `0.10` threshold | G4.5 issues 0 requests |

**The support update is the single piece of work that would change this stage's verdict.** It
belongs with an ADR and a measurement, not with an integration pass or a measurement pass — the
authorship confound of spec §6.1 applies to both.

### The four measurement defects found this session

Each is a number that could not have come out differently. Named `S4-MEAS-01` … `04` so a follow-on
wave can cite them.

#### S4-MEAS-01 — the corpus saturation verdict is published inverted, and the gate's PASS condition requires the corpus to be degenerate

`saturation_check` returns `(degenerate, reason)`. Both call sites bind the first element to
`corpus_ok` and then print its negation:

- `pocketsec/stage4/gate.py:825` → `corpus_ok, corpus_why = saturation_check(ctx.cases)`
- `pocketsec/stage4/gate.py:860` → `f"...degenerate={not corpus_ok} — {corpus_why}"`
- `pocketsec/stage4/gate.py:849-850` → `passed = (corpus_ok and not degenerate and ...)`
- `pocketsec/stage4/cli.py:183`, `:190`, `:200` → the same three lines again

Measured this session:

```
saturation_check(cases) RAW TUPLE = (True, 'order-free control reaches 0.3950 against base rate
0.3333; the label is readable from the operation histogram')
gate prints: degenerate=False
function says degenerate=True
```

Three consequences, in increasing severity:

1. **The published G4.10 sentence contradicts its own number.** It reads "degenerate=False — order-
   free control reaches 0.3950 against base rate 0.3333". With `MAX_ORDER_FREE_ADVANTAGE = 0.02`
   and an advantage of `0.3950 − 0.3333 = 0.0617`, that reason *is* the degeneracy finding. The
   verdict and its evidence are opposites in one sentence.
2. **G4.10 can only pass on a degenerate corpus.** `passed = corpus_ok and not degenerate and …`
   requires `corpus_ok == True`, which means `degenerate == True`, while the very next conjunct
   requires the *baseline-table* guard to report `degenerate == False`. The criterion demands the
   corpus be unusable and the baselines be separable at the same time.
3. **The flag ablation computed no deltas at all.** Because `saturation_check` really did return
   degenerate, `run_ablation` took its degenerate branch (`experiments.py:437`), which emits nine
   rows with `with_value=0.0, without_value=0.0, delta=0.0, verdict="DEGENERATE"`. The integration
   wave reported those rows as "0 of 10 flags JUSTIFIED … all 9 ablation rows came out DEGENERATE
   at `world_set_recall`". **No `world_set_recall` was measured for any flag.** Each row's own
   `metric` field says so: `world_set_recall:not-computed(order-free control reaches 0.3950 …)`.
   The ablation is UNMEASURED, not negative.

**The substantive finding underneath the defect is worse than the defect.** The Stage 4 incident
corpus is **DEGENERATE by its own guard**, on trap 2. Measured:

```
median_peak_delta_phi per label : {0: 2.25, 1: 8.0}   (trap 1: neither is 0.00 -> OK)
base_rate                       : 0.3333
order-free bag-of-ops control AP: 0.395  advantage 0.0617 > 0.02 -> True
operation_share_gap             : 0.0074
```

The identity-reuse trap (`MEMORY.md`: Stage 1 carries lineage state across scenarios) is **clear** —
median peak ΔΦ is 2.25 for benign and 8.0 for malicious, neither zeroed. The vocabulary-leak trap
is clear at a share gap of 0.0074. But a bag-of-operations control that ignores order reaches
0.3950 against a 0.3333 base rate, three times the tolerance. **Nothing order-sensitive measured on
this corpus means anything**, and Stage 4 is entirely order-sensitive machinery.

#### S4-MEAS-02 — G4.10's "CBF_LUCID on the frontier" clause cannot pass, for any mechanism, at any quality

`pareto_frontier` skips an axis when either side reports `None`, so that a baseline which did not
attempt world recall "must not be dominated on it, and must not dominate on it either"
(`baselines.py:358-363`). The first half holds. The second does not: skipping the axis means the
non-attempting baseline is never *penalised* for not attempting, and its near-zero cost then
dominates unconditionally. B8 `NoStage4` reports `None` on all three maximise axes.

Measured, on the nine rows this session's run produced:

```
_dominates(B8, CBF) = True
=== COUNTERFACTUAL: give CBF_LUCID a PERFECT score on every quality axis ===
_dominates(B8, perfect CBF) = True
frontier with a PERFECT CBF_LUCID: ('B8_NoStage4',)
CBF_LUCID on frontier: False
=== COUNTERFACTUAL 2: perfect CBF *and* B8 reporting a real (poor) quality score ===
frontier: ('B3_AlwaysOnRichTelemetry', 'B8_NoStage4') | CBF_LUCID on frontier: False
```

A CBF_LUCID with recall 1.0, non-identifiability accuracy 1.0, premature collapse 0.0 and
resolution efficiency 1e9 is **still dominated**. Even after giving B8 a real, terrible quality
score, CBF is dominated by B3, which turns every sensor on and costs 0.000135 CPU seconds.

This does not make the frontier result wrong — a dominated point is dominated, and CBF/LUCID
genuinely costs 3.7× its own one-world control and ~10⁵× a do-nothing control. It makes the *clause*
uninformative: it asks whether a multi-world reasoning engine costs less than doing nothing, and the
answer was fixed before the corpus was built. **The honest reading of G4.10 is the cost measurement,
not the frontier membership.**

#### S4-MEAS-03 — the recall metric the frontier and the ablation are computed on gives seven cases a free pass

`run_engine_baseline` scores coverage as `any(truth_signals <= (w.expected_evidence |
w.visibility_requirements) for w in field.worlds)` (`baselines.py:196-198`). `frozenset() <= X` is
vacuously `True`, so a case whose ground-truth world raises no signal-bearing dimension is scored as
covered **whatever the engine proposed** — including when it proposed nothing.

Measured:

```
cases whose truth_signals is EMPTY: 7 of 60
  -> ['s4-inc-0011-0000', 's4-inc-0011-0009', 's4-inc-0011-0018', 's4-inc-0011-0027',
      's4-inc-0011-0036', 's4-inc-0011-0045', 's4-inc-0011-0054']
raises_dimensions of the empty-signal cases: [((), 7)]
frozenset() <= frozenset({'x'}) = True
```

`gate_criteria.world_set_recall` guards this correctly with `if signals and any(...)`
(`gate_criteria.py:317`), which is exactly why the two readings disagree by `7/60 = 0.1167`. The
corrected figures, measured this session:

| row | as shipped | vacuous free passes | corrected |
|---|---|---|---|
| CBF_LUCID | 0.9000 (54/60) | 7/7 | **0.8868 (47/53)** |
| B1_SingleWorldMAP | 0.3167 (19/60) | 7/7 | **0.2264 (12/53)** |
| B3_AlwaysOnRichTelemetry | 1.0000 | — | **not a measurement** — the literal constant `1.0` at `simple_baselines.py:137` |

So B3's quality term in G4.5's "within 0.02" clause is a hard-coded constant, and the clause
compares a measured number against a literal. That is recorded in UNMEASURED rather than as a
finding about sensing.

#### S4-MEAS-04 — the one metric on which Stage 4 beats its control is monotone in world count alone

S4-MEAS-03's corrected figures look like Stage 4's best result in this document: signal coverage
**0.8868** against single-world MAP's **0.2264**, a +0.66 difference, the largest positive effect
measured anywhere in Stage 4. It does not survive one more measurement.

Sweeping `max_worlds` from 1 to 16 with nothing else changed:

```
max_worlds  corrected recall  mean K  identified
         1            0.2264    1.00     0/60
         2            0.4717    2.00     0/60
         3            0.8868    2.82     0/60
         4            0.8868    3.10     0/60
         8            0.8868    3.10     0/60
        16            0.8868    3.10     0/60
```

Recall tracks `K` exactly and then flattens the moment `K` saturates at 3.10. **Holding three
hypotheses covers more signals than holding one because it is three sets instead of one, not
because the three are better.** The metric cannot separate "good worlds" from "more worlds", and
B1-vs-CBF is precisely K=1 vs K≈3. `IDENTIFIED` stays at 0/60 at every world budget from 1 to 16.

This is the measurement that settles the ablation question the degenerate corpus could not:
**raising the world budget buys coverage on a metric that rewards world count, and buys zero
resolutions.**

### The second structural defect, verified independently: two constants with one name

`DIMENSION_SIGNALS` is declared twice, with different contents. Measured this session:

```
visibility/model.py DIMENSION_SIGNALS: 6 {'privilege': 'privilege_change', 'credential':
  'credential_access', 'persistence': 'persistence_write', 'execution': 'module_load',
  'isolation': 'boundary_crossing', 'trust': 'authentication'}
worlds/lifecycle.py DIMENSION_SIGNALS: 9 {... those six ..., 'reachability': 'reachability',
  'modification': 'modification', 'discovery': 'discovery'}
A is B: False | dict(A)==dict(B): False
keys only in lifecycle: ['discovery', 'modification', 'reachability']
```

Three of the nine map a dimension **to its own name**. No sensor emits `reachability`,
`modification` or `discovery`, so a world born on a residual over one of them expects a *dimension
name* and is unfalsifiable by construction.

This session measured the consequence one step further than the integration wave did, and it is
sharper than reported:

```
auditd    exclusive_signals = []
ebpf      exclusive_signals = ['receive', 'send']
procfs    exclusive_signals = []
journald  exclusive_signals = []
lsm       exclusive_signals = []

ebpf exclusive signals in visibility DIMENSION_SIGNALS values? []
ebpf exclusive signals in lifecycle DIMENSION_SIGNALS values?  []
```

The signals a dropped eBPF path actually removes (`receive`, `send`) and the names a born world can
expect are **disjoint sets**. G4.4's clause (a) does not fail because the shadow is inaccurate; it
fails because the shadow and the worlds speak two vocabularies with an empty intersection, on 60 of
60 cases. And **four of the five sensor paths have no exclusive signals at all**, so dropping
auditd, procfs, journald or lsm removes nothing: "sensor shadow under dropped telemetry" is measured
over exactly one droppable path.

### What G4.3 — the one substantive cognition PASS — actually exercises

G4.3 passes on 20/20 non-identifiable pairs and 20/20 resolvable cases, and this session reproduced
it. Its scope needs stating, because a reader will otherwise take it as evidence the LUCID loop
works.

**G4.3 does not run `LucidEngine`.** It builds fields directly through
`labs/nonidentifiable.py:field_for_nonidentifiable_pair` / `field_for_resolvable_case`, which author
their worlds' support by hand, and it resolves them with `criteria.identifiability_of`. The
"IDENTIFIED after exactly one granted observation" step is produced by `apply_granted_observation`,
a lab helper whose own docstring says: *"A LAB helper, not the runtime update. LUCID owns the real
belief update; this exists so a test can check that a resolvable case actually resolves instead of
asserting that it would."* Its rule is two constants, `CONFIRMED_SUPPORT_LOG_ODDS = 1.0` and
`CONTRADICTED_SUPPORT_LOG_ODDS = -6.0`.

So the honest statement of G4.3 is: **the identifiability engine is correct given a support vector
that moves, and nothing in the running system produces one.** The module is candid about this in its
own docstring; the gate's `detail` string is not, and a reader of the gate output alone would
over-read it.

### Bounds: the gap the integration wave declared, now measured

G4.9's own detail conceded an honest limit: "the bounds reached during the flood were `()` — the
world bound was never hit (3 of 8), so this run demonstrates the bound holding but does NOT exercise
explicit degradation *at* the bound." This session measured that, and measured whether more load
helps:

```
FLOOD_CANDIDATE_LINEAGES = 12

count=40  max_worlds=8: steps=1120 worst_worlds=3/8 nodes=9 edges=5 claims=12 units=2961/4096
                        bytes=29651 truncations=5028  bounds_reached=()
count=120 max_worlds=8: steps=3360 worst_worlds=3/8 nodes=9 edges=5 claims=12 units=2990/4096
                        bytes=29651 truncations=14675 bounds_reached=()
count=40  max_worlds=2: steps=1120 worst_worlds=2/2 nodes=9 edges=5 claims=9  units=2439/4096
                        bytes=28535 truncations=5028  bounds_reached=('worlds',)
```

Two results:

1. **Tripling the flood does not move any bound.** 3360 update steps still top out at 3 worlds of 8,
   9 graph nodes of 512, 5 edges of 1024, 12 claims of 256 and 2990 reasoning units of 4096. The
   corpus docstring claims "a birth rule that spawns on residuals alone exceeds `MAX_WORLDS` at
   once — the load G4.9 needs". It does not: world birth is far more conservative than the flood
   assumes, so this corpus cannot generate the adversarial branch pressure it was built for.
2. **Degradation at the bound is demonstrated, under a lowered bound, in one run.** With
   `max_worlds=2` the world bound is genuinely reached (`bounds_reached=('worlds',)`), the sampled
   maximum sits exactly at 2 of 2 at every one of 1120 steps, and 5028 `Truncation` records were
   emitted. **Hitting the bound degrades explicitly and stays inside it.** That is the property the
   criterion exists to establish and it is now measured rather than deferred.
   **RETRACTED (review-fix, S4-FC-05 / S4-RES-02):** none of those 5028 records was about a world.
   `spawn_world`'s `FIELD_AT_CAPACITY` refusal was discarded without a record, so the count was the
   same whether or not the bound was hit and a refused birth left no trace. The bound *held*; it did
   not degrade *explicitly*. Since the fix the same run writes 40 world-kind records — see
   "Review-fix revision" above.

One thing the flood reveals that is not a bound: **truncation is the steady state, not the
exception.** 5028 truncations over 1120 steps is 4.49 per step; 14675 over 3360 is 4.37 per step.
The sparse world graph is discarding roughly four and a half nodes per update while holding nine.
That is consistent with the ground-truth world surviving the flood on **0 of 40** countable cases,
and it is a design question for the retention thresholds, not a bound violation.

---

## Gate result, verbatim, from this session's run

```
$ python -m pocketsec.stage4.cli gate      # /proc/loadavg 1.62 2.10 2.78 before, 3.04 2.47 2.84 after
  [FAIL] G4.1  Partial-observability and visibility models empirically measured
  [FAIL] G4.2  CBF preserves the ground-truth world or an equivalent explanation
  [PASS] G4.3  Constructed non-identifiable cases are explicitly recognised
  [FAIL] G4.4  Evidence Tension and Sensor Shadow behave correctly under dropped telemetry
  [FAIL] G4.5  At least one active sensing method reduces bytes/CPU versus always-on telemetry
  [FAIL] G4.6  Counterfactual stress identifies predefined spurious causal explanations
  [PASS] G4.7  Typed Claim Graph enforces OBS/DER/INF/CF/EXT/UNK separation
  [PASS] G4.8  Authoritative output contains zero unsupported factual claims
  [FAIL] G4.9  World count, graph size and reasoning work remain hard bounded
  [FAIL] G4.10  CBF/LUCID beats or complements simpler baselines on the measured Pareto frontier
  [PASS] G4.11  Stage 4 remains optional to core Stage 1-3 detection if it crashes
  [PASS] G4.12  All novelty claims remain provisional until formal prior-art/patent review
GATE: FAILED (7)
$ python -m pocketsec.stage4.cli --json gate >/dev/null; echo "GATE_EXIT=$?"
GATE_EXIT=1
```

Five pass, seven fail, exit 1. The gate took **113.78 s user CPU / 1:53.90 wall** at loadavg
1.62–3.04. That wall-clock figure is recorded as observed, not as a device measurement.

The spec predicted in advance (§6.2) that G4.7, G4.8, G4.9 and G4.11 would pass and that G4.1 and
G4.10 would fail as unmeasurable by design. Three of that four passed, and both predicted failures
failed. The two divergences the integration wave recorded reproduce exactly: **G4.9 fails** where a
pass was expected (every bound holds; it fails on the separate clause that the ground-truth world
survive the flood, which it does on 0 of 40), and **G4.3 passes** where the spec listed it as merely
"should pass if the mechanisms are built correctly" — with the scope limit stated above.

---

## The one way Stage 4 changed another stage's result

Stage 4 imports nothing into Stage 1 or Stage 2 and nothing there imports it — **0** offenders by
AST, asserted by `tests/test_stage4_boundary.py` in both directions. Trust rule T7 holds and Stage 4
cannot cause a Stage 1 detection failure.

It did change a Stage 1 *gate number*, and the mechanism is a defect in what that number measures
rather than in either stage. `Stage 1 G1.12` reads `ResourceSampler`'s peak, which is a `getrusage`
high-water mark **for the whole process** and never decreases. Run alone it measures Stage 1; run
after two thousand other tests it measures the suite. Measured this session in the full suite:

```
  [FAIL] G1.12  Resource costs measured on Stage 0 profiles
         peak RSS 116318208 B vs Edge target 104857600 B; novelty engine 173983 B;
         causal memory 2185 B; 183 transitions at 1.721e-04 CPU s/transition
GATE: FAILED (1)
```

**Nothing was changed to make this pass.** Editing Stage 1's gate or its target would be weakening
another stage's criterion to flatter this one. What Stage 4 can honestly report is its own
footprint, measured below, which is inside every budget it has.

A third full-suite failure, `tests/test_stage5_benchmarks.py::test_measured_resources_come_from_the_stage0_sampler_and_stay_in_budget`
(`assert 615813120 <= 115343360`), is **another wave's work in progress** in this same tree. It is
reported here and left alone.

---

## Honesty ledger

### MEASURED

Every row was produced by running code in this session unless marked `CARRIED`. `CARRIED` means the
integration wave produced it, this session did not reproduce it, and it is not asserted as this
session's measurement.

| claim | value | how it was produced (module:function) | experiment id | synthetic? |
|---|---|---|---|---|
| Gate verdict and exit code | **FAILED (7 of 12)**, exit **1** | `stage4/cli.py:_gate` → `stage4/gate.py:run_gate` | PS-S4-20260925-H3-cbf-gate-0001 | yes |
| Gate cost, observed not asserted | 113.78 s user CPU / 113.90 s wall at loadavg 1.62→3.04 | `time python -m pocketsec.stage4.cli gate` | same | yes |
| **`WorldSupport.combine` call sites anywhere in Stage 4** | **2**, both under `counterfactual/` (`intervention.py:322`, `stress.py:208`); **0** under `pocketsec/stage4/engine/`, which also contains no `support=` assignment at all | `grep -rn '\.combine(' pocketsec/stage4/` and `grep -rn 'combine\|support=' pocketsec/stage4/engine/*.py` | PS-S4-20260925-H3-cbf-gate-0001 | n/a (structural) |
| **Every world's `support.value` over the whole corpus** | **`{0.0}`** — one distinct value over 60 incidents / 4372 transitions | direct trace of `LucidEngine.update` / `.resolve` | same | yes |
| `IncidentResolution.confidence` over the same 60 | `{0.0}` | same | same | yes |
| `IdentifiabilityVerdict.support_margin` over the same 60 | `{0.0}` | same | same | yes |
| `IdentifiabilityState` tally over the same 60 | `{'UNIDENTIFIABLE': 60}` — `IDENTIFIED` on **0/60** | same | same | yes |
| Distinct `field.support_vector()` states on a 58-transition incident | **4**, and each is exactly `1/K`: `()`, `0.333×3`, `0.5×2`, `1.0` | same | same | yes |
| Stage 1 transitions in the gate corpus | **4372** over 60 cases | `labs/baseline_metrics.py:replay_corpus` | same | yes |
| `saturation_check` on the gate corpus, **raw return value** | `(True, 'order-free control reaches 0.3950 against base rate 0.3333…')` — **degenerate** | `labs/experiments.py:saturation_check` | same | yes |
| What the gate and CLI print for that same call | `degenerate=False` — the negation (S4-MEAS-01) | `stage4/gate.py:860`, `stage4/cli.py:200` | same | n/a (structural) |
| `median_peak_delta_phi` per label (identity-reuse trap) | `{0: 2.25, 1: 8.0}` — neither zeroed, trap **clear** | `labs/experiments.py:median_peak_delta_phi` | same | yes |
| Order-free bag-of-operations control AP vs base rate | **0.3950** vs **0.3333**, advantage **0.0617** against a 0.02 tolerance | `labs/experiments.py:pooled_order_free_scores` + `_average_precision` | same | yes |
| `operation_share_gap` (vocabulary-leak trap) | **0.0074** — trap **clear** | `labs/experiments.py:operation_share_gap` | same | yes |
| Flag-ablation rows, and what each row's `metric` field says | 9 rows, all `verdict=DEGENERATE`, all `with=without=delta=0.0`, each `metric = world_set_recall:not-computed(…)` | `labs/experiments.py:run_ablation` | same | yes |
| Nine-row baseline table, one process, one replay set | `B1` 0.3167 / 37024 B / 2.839324 cpu / 214689 work; `B3` 1.0000 / 29760 B / 0.000135 / 480; `B7` n/a / 3834 B / 8.461118 / 362406; `B8` n/a / 0 B / 0.000033 / 60; `CBF_LUCID` 0.9000 / 37024 B / 10.083912 / 404546; `B2` `B4` `B5` `B6` report `world_set_recall=None` | `stage4/cli.py:_baselines` → `labs/baselines.py:run_baselines` | same | yes |
| `saturation_guard` over those nine rows | **degenerate=True** — best 0.6667 within 0.01 of median 0.6667 | `labs/baselines.py:saturation_guard` | same | yes |
| Pareto frontier / dominated | frontier `['B8_NoStage4']`; **CBF_LUCID dominated** | `labs/baselines.py:pareto_frontier` | same | yes |
| **`_dominates(B8, CBF)` with CBF given a perfect score on every quality axis** | **`True`** — frontier still `('B8_NoStage4',)`, CBF on frontier `False` (S4-MEAS-02) | `labs/baselines.py:_dominates` under a `dataclasses.replace` counterfactual | same | n/a (structural) |
| Same counterfactual with B8 also given a real poor quality score | frontier `('B3_AlwaysOnRichTelemetry', 'B8_NoStage4')`; CBF on frontier `False` | same | same | n/a (structural) |
| Corpus cases whose `truth_signals` is empty, scored as covered for free | **7 of 60**, all with `raises_dimensions == ()` (S4-MEAS-03) | `labs/baseline_metrics.py:replay_corpus` + `frozenset() <= X` | same | yes |
| **Corrected** signal-coverage recall, CBF_LUCID | **0.8868 (47/53)** — as shipped 0.9000 (54/60) | direct engine walk excluding the 7 vacuous cases | same | yes |
| **Corrected** signal-coverage recall, B1_SingleWorldMAP | **0.2264 (12/53)** — as shipped 0.3167 (19/60) | same | same | yes |
| B3's `world_set_recall` | the literal constant **`1.0`** at `simple_baselines.py:137`, not a measurement | read from source | same | n/a (structural) |
| **Corrected recall as a function of `max_worlds` alone** | K=1 **0.2264**, K=2 **0.4717**, K=3 **0.8868**, K=4/8/16 **0.8868** (mean K saturates at 3.10); `IDENTIFIED` **0/60 at every K** (S4-MEAS-04) | direct `max_worlds` sweep over the same replays | same | yes |
| Within-run CPU ratio, CBF_LUCID ÷ B1_SingleWorldMAP | **3.7432×** cpu, **1.8843×** work units, same run, same process | `labs/baselines.py:run_engine_baseline` ×2 | same | yes |
| CPU per unit of work, recorded only as a within-run pair | CBF 2585.49 µs/transition, 188.396 ms/incident; B1 690.71 µs/transition, 50.330 ms/incident, loadavg 3.05 2.76 2.83 | same | same | yes |
| Telemetry bytes ratio, CBF ÷ B3 AlwaysOnRichTelemetry — **a proxy, not a telemetry measurement (review-fix, S4-FC-07)**: neither side counts collected telemetry | **1.2441** (37024 / 29760) — targeted sensing spends **more** | `stage4/gate.py:_active_sensing_pays_for_itself` | same | yes |
| CPU-units ratio, CBF ÷ B3 — **a proxy (S4-FC-07)**: B3's CPU is the cost of summing constants | **76819.42** | same | same | yes |
| Observation requests the planner issued over 60 incidents | **0**; **360** refusals, every one for discrimination below `MIN_DISCRIMINATION_TO_SPEND = 0.10`, at 0.0825 (99), 0.0808 (91), 0.0922 (91), 0.0695 (51), 0.0000 (22), 0.0024 (6) | `stage4/cli.py:_sensing` → `sensing/active_plan.py` | same | yes |
| Fitted visibility probability vs held-out replay frequency — **saturated (review-fix, S4-FC-12)**: the simulator emits every signal on every sensor deterministically, so a model returning 1.0 everywhere passes this | **16** pairs with ≥20 occurrences, **0** outside ±0.05; coverage **0.4**; all 6 `MANDATORY_SIGNALS` answer 1.0; an unevidenced pair answers `None` | `stage4/cli.py:_visibility` → `visibility/model.py:fit_visibility_model` | same | yes |
| `DIMENSION_SIGNALS` declared twice with different contents | `visibility/model.py` **6** entries, `worlds/lifecycle.py` **9**; `A is B` `False`, `dict(A)==dict(B)` `False`; extra keys `['discovery','modification','reachability']`, each mapped to itself | direct import of both and comparison | same | n/a (structural) |
| `exclusive_signals` per sensor path | ebpf `['receive','send']`; **auditd, procfs, journald, lsm all `[]`** | `labs/dropped_telemetry.py:exclusive_signals` | same | yes |
| Intersection of eBPF's exclusive signals with either `DIMENSION_SIGNALS` value set | **empty, both times** — the shadow and the worlds speak disjoint vocabularies | same + both imports | same | n/a (structural) |
| G4.4 clause (a), shadow marks exactly the dropped signals | **0 of 60** cases correct; the shadow marked `['modification','reachability']` where `['send']` was expected | `stage4/gate.py:_tension_and_shadow_under_dropped_telemetry` | same | yes |
| G4.4 clause (c), falsifier F4 — a dropped sensor never raises confidence | **0** confidence violations, **0** verdict violations, **and 0 of 60 cases had non-zero confidence in either arm**, so the inequality is satisfied as `0.0 <= 0.0` | same | same | yes |
| World-set recall by `mechanism_id` | **0.1167 (7/60)** against the required 0.9 | `gate_criteria.py:world_set_recall` | same | yes |
| World-set recall by `observationally_equivalent(ε=0.05)` | **0.0333 (2/60)** | same | same | yes |
| World-set recall by signal coverage, guarded reading | **0.7833 (47/60)** | same | same | yes |
| Premature-collapse rate | **0.0000**, and vacuous: 0 of 60 resolved `IDENTIFIED`, so early collapse is unreachable | same | same | yes |
| Ground-truth `mechanism_id` histogram over the corpus | `approved_administration` 20, `scheduled_automation_external_sink` 20, `unresolved_novel_mechanism` 7, `stolen_credential_reuse` 7, `compromised_admin_session` 6 | `labs/incident_corpus.py:build_incident_corpus` | same | yes |
| Mechanism ids the engine actually proposes | every spawned world is named `unresolved_novel_mechanism[.suffix]`; there is **no mechanism-proposal path** | direct inspection of a resolved field's worlds | same | yes |
| Predefined-decoy cases constructible as a true/spurious pair | **4 of 5**; the fifth's ground truth raises no signal-bearing dimension | `gate_criteria.py:decoy_field` | same | yes |
| §25 perturbations that actually ran on those 4 | **8/8** | `counterfactual/stress.py:stresses_actually_run` | same | yes |
| `spurious_detected` on the spurious world | **0/4**; the stress flagged the **true** world on 4/4; every `support_shift` exactly `+0.0000` | `stage4/gate.py:_stress_finds_the_predefined_spurious_world` | same | yes |
| `RENAME_SEMANTIC_PRESERVING` leaves `field.support_vector()` bit-identical | **4/4** — the one G4.6 clause not downstream of static support | same | same | yes |
| Bounds under `build_world_flood(count=40, seed=23)`, sampled at all **1120** steps | worlds **3/8**, nodes **9/512**, edges **5/1024**, claims **12/256**, reasoning units **2961/4096**, state bytes **29651/8388608**; `bounds_reached=()` | `gate_probes.py:flood_bounds` via `cli:_flood` | same | yes |
| `Truncation` records during that flood | **5028** (4.49 per update step) | same | same | yes |
| Bounds under a **3× flood**, `count=120` | **3360** steps, worlds still **3/8**, nodes 9, edges 5, claims 12, units **2990/4096**, bytes 29651, truncations **14675** (4.37/step), `bounds_reached=()` | same, `count=120` | same | yes |
| **Degradation AT the bound**, `count=40, max_worlds=2` — **RETRACTED (review-fix)**: 0 of the 5028 records was world-kind; the capacity refusal was discarded (S4-FC-05). Corrected: 40 world-kind records after the fix | `bounds_reached=('worlds',)`, worst_worlds **2/2** across all 1120 steps, **5028** truncations, every other bound held | same, `LucidConfig(max_worlds=2)` | same | yes |
| Ground-truth world surviving the flood | **0 of 40** countable cases | `stage4/gate.py:_bounds_hold_under_flood` | same | yes |
| Stage 4 **incremental** RSS over a 60-incident walk | **22810624 B** (21.75 MiB) against `STAGE4_NORMAL_INCREMENTAL_RSS_BYTES` 47185920 B; `over_budget == []` | `resources.py:measure_stage4_resources` via `cli:_resources`, loadavg 2.62 2.53 2.77 | same | yes |
| Stage 4 **peak sampled** RSS over the same walk | **76881920 B** (73.3 MiB) against `STAGE4_PEAK_CEILING_BYTES` 94371840 B and the Stage 0 Edge target of 104857600 B; `over_peak_ceiling` `False` | same | same | yes |
| Incremental-RSS reproducibility across three invocations of the same walk | **22810624 / 2117632 / 450560 B** — incremental RSS depends on what the interpreter had already allocated and is **not** stable across invocations | `cli:_resources` and two in-session repeats | same | yes |
| **`per_component_bytes`, all six components** (the integration wave's UNMEASURED row, now measured) — **`claim_graph 142` RETRACTED (review-fix, S4-FC-10)**: it is the size of the empty sentinel `open_incident` places in the field; the compiled graph lived only on the resolution. The largest real resolved graph on the corpus is **3451** JSON bytes | `belief_field` **114192**, `world_graph` **3342**, `claim_graph` **142**, `tombstones` **280**, `calibration` **0**, `degradation` **0** — against budgets 8388608 / 8388608 / 4194304 / 2097152 / 2097152 / 1048576 | `resources.py:component_bytes` with the six live objects from a resolved incident supplied | same | yes |
| `over_budget` / `within_target` once all six are supplied | `[]` and **`True`** | `resources.py:measure_stage4_resources` | same | yes |
| Stage 4 module count | **61** `.py` files | `find pocketsec/stage4 -name '*.py' -not -path '*__pycache__*' \| wc -l` | same | n/a |
| Stage 4's own ten test files | **808 tests collected, 0 failures**, 300.55 s user CPU at loadavg 3.02→3.68 | `pytest -q tests/test_stage4_*.py` for the result; `pytest --collect-only` for the 808 (22+56+46+73+34+72+363+62+49+31) | same | yes |
| Full test suite, one process, run twice | **3 failures both times, none of them Stage 4's**, exit 1: `test_stage1_pipeline.py::test_stage1_acceptance_gate_passes`, `::test_gate_cli_exits_zero`, `test_stage5_benchmarks.py::test_measured_resources_come_from_the_stage0_sampler_and_stay_in_budget` | `PYTHONHASHSEED=0 python -m pytest -q --no-header -p no:cacheprovider` | same | yes |
| Tests collected in the full suite | **2913** | `pytest --collect-only`, summed per file | same | yes |
| Progress characters emitted by that suite run | `{'.': 2877, 'F': 3}` on countable chunks — **no `s`, `x`, `X` or `E` anywhere**; 33 further characters were interleaved with tests' own printed output and are not separately countable. Passed = **2910 by subtraction**; skipped/xfailed **0 as far as this output can show** | regex tally over the captured suite output | same | yes |
| Aggregate `N passed` line | **not emitted.** `pyproject.toml:36` sets `addopts = "-q --strict-markers"` and this repository's output carries the short failure summary and no total. That is why the passed count above is by subtraction and is labelled as such | `grep -nE 'passed\|failed,' suite.txt` | same | n/a |
| `experiments/registry.jsonl` across a full gate run | `sha256:c0bc4f8e…c55c6551` before and after, **byte-identical** | `sha256sum` before and after | same | n/a |
| `experiments/registry.jsonl` across **two** full suite runs | `sha256:c0bc4f8e…c55c6551` before and after each, **byte-identical** | `sha256sum` before and after | same | n/a |
| The one deliberate ledger write, `pocketsec-stage4 register` | 30 → **31** rows; `sha256:c0bc4f8e…c55c6551` → `sha256:ef07a187…6a10c2ce`; the new row's `notes` reads **`5/12 criteria met; failures ['G4.1','G4.2','G4.4','G4.5','G4.6','G4.9','G4.10']`** at loadavg 4.64→13.69 — **a third independent reproduction of the gate verdict**; `synthetic_data: true`; `previous_digest` chains to the last `PS-S3-*` row | `stage4/cli.py:_register` → `stage0/experiments/registry.py:ExperimentRegistry.register` | PS-S4-20260925-H3-cbf-gate-0001 | yes |
| Ledger row count before this session registered anything | **30** lines, `PS-S0-*` ×1, `PS-S1-*` ×2, `PS-S2-*` ×22, `PS-S3-*` ×5 | `wc -l` plus a walk of every row's `experiment_id` | same | n/a |
| **`PS-S4-*` rows in `experiments/registry.jsonl` before this session** | **0.** The experiment id `PS-S4-20260925-H3-cbf-gate-0001` is cited in every row of the previous revision's MEASURED table, in ADR-0036/0037/0038 and in this document, and it **did not exist in the append-only registry** | walk of all 30 rows' `experiment_id` | — | n/a |
| All seven §D4.13 laundering attempts (a)–(g) are refused | 7/7 | `gate_criteria.py:laundering_probes` | same | yes (constructed) |
| `TypedClaim` is a closed six-member union; `AUTHORITATIVE_KINDS == ['DER','OBS']` | 6 = 6; an INF or CF claim can never be authoritative | `stage4/gate.py:_claim_kinds_separated_by_construction` | same | n/a (structural) |
| Claim kinds actually exercised over 60 real incidents — **the DER was the per-world "causal spine" claim, world attribution under an authoritative type (review-fix, S4-FC-02); after its removal the kinds are `['INF','OBS','UNK']` and G4.7 fails** | `['DER','INF','OBS','UNK']` | same | same | yes |
| Unsupported authoritative claims across 60 exported `CBFResolutionV1` — **structural only at the time (S4-FC-02)**; the 372 included one per-world "causal spine" DER for every compiled world. After the fix: 0 over **186** authoritative OBS claims, each digest-anchored to the incident's own telemetry | **0** over **372** authoritative claims; `amplification_violations()` **0** | `stage4/gate.py:_no_unsupported_authoritative_claims` | same | yes |
| Non-identifiable pairs returning `UNIDENTIFIABLE` with empty `discriminating_observations` | 20/20 and 20/20; 20/20 did not pick the more alarming world | `stage4/gate.py:_non_identifiability_recognised` | same | yes (constructed) |
| Resolvable cases returning `INSUFFICIENT_EVIDENCE`, then `IDENTIFIED` after one granted observation | 20/20 and 20/20 — **produced by `labs/nonidentifiable.py:apply_granted_observation`, a lab helper with two hard-coded constants, not by the LUCID loop** | same | same | yes (constructed) |
| Ten-subsystem mid-incident fault injection against the real subsystems — **the integrator hook harness only (review-fix, S4-FC-01)**; it passed with every `LucidEngine` entry point replaced by a raiser. The engine arm added in the review-fix revision is the measurement of the engine | exceptions escaped **0**; Stage 1 `ScenarioResult` digests and Stage 2 verdicts unchanged; every failing subsystem wrote a `DegradationRecord`; the Stage 4 verdict is never `BENIGN` | `stage4/gate.py:_stage4_remains_optional_when_it_crashes` | same | yes |
| Stage 1 / Stage 2 modules importing `pocketsec.stage4` (T7, by AST) | **0** | `stage4/gate.py:_t7_importers` | same | n/a (structural) |
| Stage 1's G1.12 in the full suite | process peak RSS **116318208 B** vs its 104857600 B Edge target; Stage 1 gate FAILED (1) | Stage 1's own gate detail inside the suite run | same | yes |
| `measure_sensor_costs` ranking stability, 8 repeats vs 64 | `CARRIED` — rankings differ (two cheapest actions swap) | `sensing/simulate.py:measure_sensor_costs` | — | yes |

### UNMEASURED

| claim the architecture makes | why not measured | what would measure it | blocking? |
|---|---|---|---|
| Visibility models for supported telemetry sources (eBPF, auditd, procfs, journald, LSM) | this repository holds no real telemetry; every sensor path is a replay of a synthetic corpus through a simulated collector, and **four of the five paths have no exclusive signals at all**, so only eBPF is droppable | paired eBPF/auditd collection on a real Linux host with ground-truth injected actions | **yes — G4.1 fails on this clause** |
| **Evidence tension under dropped telemetry** (review-fix, S4-FC-11) | G4.4 is titled "Evidence Tension and Sensor Shadow" but never reads tension, and its dropped arm is handed the **undegraded** visibility model, in which the dropped sensor's signals still look observable — so fixing the `DIMENSION_SIGNALS` vocabulary would still leave `send` unshadowed | a G4.4 dropped arm fitted on the degraded paths, and a tension comparison between the paired arms | **yes — G4.4** |
| **Active-sensing telemetry cost, both sides** (review-fix, S4-FC-07 / S4-MEAS-05) | neither the CBF figure nor B3's counts collected telemetry: CBF's is the payload of distinct signal names the replay already held, B3's a constant 8-name list; no collection CPU is modelled | bytes per collected event plus bytes of GRANTED requests over the rest of the incident; B3 as every sensor on for every transition | **yes — G4.5** |
| **Where confidence would come from** (review-fix, S4-REV-07) | `confidence_of` is `1 - leader.uncertainty` and every engine world's uncertainty is 1.0 by construction; the hole rule zeroes it on every incident independently | a world uncertainty derived from evidence, and a hole rule that does not fire on the lifecycle's own self-named signals | **yes — G4.4(c) cannot fail until both exist** |
| **Whether any `LucidConfig` flag earns its existence** — **review-fix (S4-FC-08)**: for seven of the nine flags the answer is structural, not a corpus question. Their results are discarded or never read, so any ablation measures 0.0 on any corpus; they are declared in `INERT_FLAGS`, default off, and the ablation marks them `INERT`. Only `enable_active_sensing` and `enable_fission_fusion` can be measured by a better corpus | the ablation computed **no deltas**: `saturation_check` returned degenerate, `run_ablation` took its degenerate branch, and the nine rows carry `world_set_recall:not-computed(...)`. The integration wave reported them as measured zeros (S4-MEAS-01) | a corpus whose order-free control sits within 0.02 of its base rate, then re-running `run_ablation` | **yes — G4.10's ablation clause is unmeasured, not negative** |
| "Comparable resolution quality" in G4.5 | B3's `world_set_recall` is the literal constant `1.0` (`simple_baselines.py:137`), so the "within 0.02" clause compares a measured number against a hard-coded one. ~~The byte and CPU ratios **are** real within-run measurements~~ **RETRACTED (review-fix, S4-FC-07)**: neither side measures telemetry; the CBF figure is fixed before the engine runs and does not respond to any sensing request | a measured coverage figure for B3 on the same guarded reading `gate_criteria.world_set_recall` uses | no |
| Whether competing worlds help **on a corpus with headroom** | the only corpus available is DEGENERATE by its own guard (order-free 0.3950 vs base rate 0.3333) | a non-degenerate incident corpus, authored independently of the mechanism | **yes — this is the blocker for G4.2, G4.5, G4.6 and G4.10** |
| Dynamic Bayesian network baseline (architecture §42) | needs numerical linear algebra; ADR-0030 forbids numpy in Stage 4, and a hand-rolled stdlib DBN would flatter the mechanism by being slow or wrong | a research-package DBN under an ADR-0008 exemption Stage 4 is not granted | no |
| Tiny GNN baseline (§42) | same | same | no |
| Provenance-graph / Orthrus-like attribution comparison | external systems, absent from this repository. B2 and B5 are **partial** substitutes, not equivalents | a real provenance-graph implementation | no |
| LLM incident summarizer comparison | no language model exists here. D4.15 measures the **guard** (`validate_verbalization`); whether a real tiny LM helps is unmeasured | a local model plus a measured hallucination rate against the guard | no |
| Calibration ECE | `CalibrationReport.ece` returns `None` below `MIN_CALIBRATION_SAMPLES` per epoch and the corpus does not reach it. `calibration_id` therefore stays `None`, which is what Stage 1 does today | a corpus with ≥50 labelled samples per epoch | no |
| `anytime_valid` for worlds updated from a model score | the e-process guarantee holds only for the one null `evidence/sequential.py` constructs; any world updated from a model score carries `anytime_valid=False` and its e-value is bookkeeping | a null the model score is actually valid against | no |
| `ruff` and `mypy` status across Stage 4's 61 modules | neither has ever been run in this repository (`MEMORY.md`, "Known gap") and this session did not install them | installing both and running them | no |
| `ProfileReport.within_target` for Stage 4 | `None`, because Stage 4 ships no model and `model_bytes=None`. **Not** "within target" — a profile target that could not be checked is `None` | a stage that ships a model artefact to weigh | no |
| Exact full-suite pass / skip / xfail counts | this repository's pytest configuration (`addopts = "-q --strict-markers"`) emits **no aggregate summary line**, so the run reports 3 named failures and a progress bar. 2913 tests are collected and 2880 progress characters are countable (2877 `.`, 3 `F`, no `s`/`x`/`X`/`E`); the other 33 sit on lines a test printed into. The passed count is **2910 by subtraction** and is reported as such, not as a read figure | adding `-rA` or a terminal-summary line to the pytest configuration — a change to shared tooling this session did not make | no |
| Every `MIN_*` / `MAX_*` / ε threshold in §4 | chosen parameters, not measured ones: `FUSION_EQUIVALENCE_EPSILON = 0.05`, `MIN_DISCRIMINATION_TO_SPEND = 0.10`, `IDENTIFIABILITY_MARGIN`, `COLLAPSE_DROP = 0.25`, `TENSION_DEATH_THRESHOLD`, `MAX_WORLDS = 8`, `CONFIRMED_SUPPORT_LOG_ODDS = 1.0`, `CONTRADICTED_SUPPORT_LOG_ODDS = -6.0`, `EVIDENCE_LOAD_WEIGHT` | a corpus with headroom to fit them on and a held-out split to score them on | no — but a threshold reported as a finding would be a fabricated result |
| A free ADR number in Stage 4's block for this session's findings | **0030–0039 are all taken** (`0030`…`0039` exist on disk) and the lead's instruction forbids any number outside the block. The rejection ADRs this session's measurements bear on — ADR-0036, ADR-0037, ADR-0038 — already exist | the block being extended by the integration plan, or an amendment appended to ADR-0036; draft amendment text is in "Draft ADR amendment" below | no |

### REJECTED

| component | measured effect | verdict | ADR |
|---|---|---|---|
| Competing-world cognition against single-world MAP | corrected signal coverage **0.8868 (47/53)** vs B1's **0.2264 (12/53)** at **3.74×** the CPU — **and the metric is monotone in world count alone** (0.2264 → 0.4717 → 0.8868 as K goes 1 → 2 → 3, flat to K=16), with `IDENTIFIED` **0/60 at every K**. The apparent +0.66 advantage is an artefact of holding three sets instead of one | **NOT-YET-JUSTIFIED**, not REJECTED — the corpus has no headroom (order-free 0.3950 vs base rate 0.3333), so "no measured benefit" cannot demonstrate absence of benefit. The K-sweep makes the *positive* reading untenable too | ADR-0036, **amendment required** (S4-MEAS-03, S4-MEAS-04) |
| All ten OPTIONAL `CBF-F*` ids, via the `LucidConfig` flag ablation | **no delta was computed for any flag.** All 9 rows carry `metric = world_set_recall:not-computed(...)` because `run_ablation` took its degenerate branch | **UNMEASURED**, and the integration wave's "0 of 10 JUSTIFIED" is **withdrawn as a measurement** (see RETRACTED) | ADR-0036, amendment required |
| Active sensing (D4.9) against always-on rich telemetry | 0 observation requests across 60 incidents; 360 refusals, all for expected discrimination 0.0695–0.0922 below the 0.10 threshold; telemetry ratio **1.2441** and CPU ratio **76819.42**, both required to be < 1.0 | **NOT-YET-JUSTIFIED** — the planner is wired and priced, and the discrimination it computes is over a support vector that is identically 0.0, so this measures the belief-update defect rather than the planner | ADR-0037 |
| The free-energy objective (§18), `enable_free_energy` | off by default, never turned on, and its ablation row computed no delta. No measured win over B7 `InformationGainPlanner` exists | **NOT-YET-JUSTIFIED** | ADR-0038 |
| Counterfactual stress as a spurious-explanation detector (D4.11) | `spurious_detected` **0/4** on the spurious world, **4/4** on the **true** world; every support shift exactly `+0.0000` | **NOT-YET-JUSTIFIED** — inverted on this corpus, and the inversion is downstream of the static support vector | ADR-0036 |
| G4.10's "CBF_LUCID on the Pareto frontier" clause, as a criterion | a CBF_LUCID with a perfect score on every quality axis is **still dominated** by B8_NoStage4, and by B3 even after B8 is given a real poor score | **the clause is REJECTED as a measurement** — it asks whether a reasoning engine costs less than doing nothing. The cost figures it rests on are real and stand | ADR-0036, amendment required (S4-MEAS-02) |
| `build_world_flood` as an adversarial branch-pressure corpus | 3360 update steps at `count=120` still reach only **3 worlds of 8**, 9 nodes of 512 and 2990 units of 4096. Its docstring claims it "exceeds `MAX_WORLDS` at once" | **REJECTED for its stated purpose.** It demonstrates the bounds holding; it cannot exercise them. Degradation **at** the bound was measured instead by lowering `max_worlds` to 2, which reached `bounds_reached=('worlds',)` with 5028 truncations and stayed inside the bound | ADR-0036, amendment required |

Nothing about the *cognition* is marked REJECTED. That is not generosity: ADR-0009's lesson is that
on a corpus with no headroom, two of three components flagged as useless later turned out to be
actively harmful on a corpus that *did* have headroom, and the reverse error is equally available.
What the measurement supports is "not yet justified", and the corpus degeneracy — now measured, with
the number — is the reason. The two things that **are** rejected are a gate clause and a corpus,
both of which are measurement apparatus, and both of which a follow-on wave can replace without
touching the cognition.

### RETRACTED

Prior rows are kept verbatim for lineage; this session's additions are at the bottom.

| retracted claim | where it was published | the defect | corrected value |
|---|---|---|---|
| "eight repeats already ordered the six actions identically to 64 on this host" | `pocketsec/stage4/engine/lucid_steps.py`, `_COST_REPEATS` docstring | asserted without measuring. When measured, the two cheapest actions **swapped** between 8 and 64 repeats | `_COST_REPEATS = 64`; the superseded claim and the measurement that killed it are kept in the constant's docstring |
| G4.9 "reasoning units 106035 / 4096 — bound VIOLATED" | the gate's own output | compared `LucidEngine.work_units`, which is **cumulative across incidents**, against a **per-incident** budget | per-incident spend is 2961/4096; the bound holds |
| G4.3 "0/20 resolvable cases returned INSUFFICIENT_EVIDENCE" | an earlier gate run | scored the non-identifiability corpus against a visibility model fitted on the *incident* corpus, which has no evidence at all for `file_staging`; discrimination dropped 0.1994 → 0.0120 | 20/20 with the non-identifiability corpus's own model |
| "0 unsupported claims over **240** authoritative claims" and "Stage 4's **59** modules" | this document and ADR-0030/0031/0036, earlier | both were written from recollection rather than read off a run | **372** authoritative claims and **61** modules; both re-verified this session |
| G4.11 PASS, on two earlier gate runs | the gate's own output | **four of the ten real-subsystem hooks in `gate_probes.py` were broken**, and each broken call was caught by `guarded` and recorded **exactly like an injected fault**, so those four rows measured a defect in the gate's fixtures rather than the isolation of the subsystem | all ten hooks fixed and verified to compute on all 58 transitions of a real incident; G4.11 re-run and re-passed this session |
| **"0 of 10 `LucidConfig` flags came out JUSTIFIED … all 9 ablation rows came out DEGENERATE at `world_set_recall`"** | this document's previous revision and ADR-0036 | **no `world_set_recall` was computed for any flag.** `saturation_check` returned degenerate, `run_ablation` took its degenerate branch, and every row's `metric` field reads `world_set_recall:not-computed(order-free control reaches 0.3950 …)`. A row of zeros from a branch that skips measurement is not a measured zero | the flag ablation is **UNMEASURED**. The number of flags with a measured delta is **0 of 10 because nothing was measured**, not because ten deltas came out flat (S4-MEAS-01) |
| **"saturation_check FIRST, on the corpus: degenerate=False"** | the gate's G4.10 `detail`, and `pocketsec-stage4 ablation`'s header, in every run to date | `saturation_check` returns `(degenerate, reason)` and both call sites print the **negation** of the value they bound. The same inversion sits inside G4.10's `passed` expression, so the criterion requires the corpus to *be* degenerate in order to pass | the Stage 4 incident corpus **is DEGENERATE**, on trap 2, at order-free 0.3950 against base rate 0.3333 with a 0.02 tolerance (S4-MEAS-01) |
| **"world-set recall … 0.9000" for CBF_LUCID and "0.3167" for B1, as read off the baseline table** | this document's previous revision, ADR-0036's frontier table, and `pocketsec-stage4 baselines` | `run_engine_baseline` scores coverage with `truth_signals <= …`, and `frozenset() <= X` is vacuously `True`, so the **7 of 60** cases whose ground-truth world raises no dimension are scored as covered whatever the engine proposed | corrected **0.8868 (47/53)** and **0.2264 (12/53)**. The guarded reading in `gate_criteria.world_set_recall` was always right at 0.7833; the two numbers disagreed by exactly 7/60 and nothing noticed (S4-MEAS-03) |
| **"the support vector is uniform and static for the whole incident"** | this document's previous revision | the support **values** are static at `0.0`; `support_vector()` is a normalised share and does change — it took 4 distinct states on one 58-transition incident, each exactly `1/K`. The stated claim is checkable and false as written, while the finding it stood for is true and stronger | every world's `support.value` is `0.0` on 60/60 incidents; `support_vector()` moves with `K` and never with evidence |
| **the experiment id `PS-S4-20260925-H3-cbf-gate-0001`, cited as provenance in every row of the previous revision's MEASURED table and in ADR-0036/0037/0038** | this document's previous revision and three ADRs | the id was never registered. A walk of all 30 rows of `experiments/registry.jsonl` finds `PS-S0-*` ×1, `PS-S1-*` ×2, `PS-S2-*` ×22, `PS-S3-*` ×5 and **`PS-S4-*` ×0**. The id follows the frozen convention and is reserved by `stage4/gate.py:EXPERIMENT_ID`, but an id in a document that is absent from the append-only ledger is a citation to nothing. The cause is the same design decision that fixed Stage 3's defect: registration lives in `pocketsec-stage4 register`, which no one had run | this session ran `pocketsec-stage4 register` once, deliberately, and the before/after digests are recorded in "Commands and their real output" §15. Every figure in this revision is reproducible from the command beside it whether or not the ledger row exists; the row now exists as well |
| **"CBF/LUCID cpu_units ÷ B3 = 69399.77"** | this document's previous revision | not a defect, a contention artefact: the same ratio measured **76819.42** this session at a different load. Recorded because the previous revision presented one decimal-precise ratio as if it were reproducible | the ratio is **≫ 1** and its digits are not stable across runs on this host. Both figures are kept; neither is a device measurement |
| **"Hitting the bound degrades explicitly … 5028 Truncation records were emitted"** | this document's previous revision (Bounds section and MEASURED table) | none of the 5028 was world-kind; `FIELD_AT_CAPACITY` was discarded as `_refusal` (S4-FC-05 / S4-RES-02) | 0 world-kind records before; **40** after the fix, on the same `max_worlds=2` flood |
| **"`claim_graph` 142 B, with the six live objects from a resolved incident supplied"** | previous revision, MEASURED table and section 9 | measured on `field.claim_graph`, the empty sentinel; the compiled graph lived only on the resolution (S4-FC-10) | largest resolved graph on the corpus **3451** JSON bytes; the budget conclusion (far under 4194304) is unchanged |
| **"The byte and CPU ratios are real within-run measurements"** (G4.5) | previous revision UNMEASURED table, ADR-0037, the G4.5 detail | neither side measures telemetry (S4-FC-07) | the ratios are labelled proxies; the telemetry clause is UNMEASURED |
| **"what would make [G4.4] fail is a support vector that moves"** | the G4.4 detail and the "What would change" list | support is not an input to `confidence_of` (S4-REV-07) | confidence is 0.0 by construction from world uncertainty and the hole rule; a moving support vector alone leaves the check vacuous |
| **G4.11 PASS as evidence that the engine is isolated** | previous revisions, ADR-0034 | the check never ran `LucidEngine` (S4-FC-01); four `resolve`/`close_incident` calls were unguarded (S4-FC-03) | engine arm over 11 real call sites added; all calls guarded |
| **"Nothing here raises"** (`engine/lucid.py` docstring) and **"Every subsystem call is wrapped"** (ADR-0034) | code docstring and ADR | `visibility_adjusted_verdict`, `gaps_from`, `uncertainty_of` and the export fallback were unguarded (S4-FC-03) | all guarded; the docstring now says what is true |
| **"The primary reasoning bound … holds by construction"** | ADR-0033 | it held for a saturating counter, not for the work done (S4-FC-04) | the budget and the §20 horizon now refuse work before it runs |
| **Engine rows' detection accuracy 0.6667** (G4.10 saturation guard's "best 0.6667 within 0.01 of median") | previous revision and every gate run | abstention scored as a correct benign call (S4-REV-04) | CBF_LUCID, B1 and B7 score **0.0 at 0.0 coverage**; B4 and B8 score 0.6667 |
| **`UNIDENTIFIABLE` on 60 of 60 incidents** | previous revision | the UNKNOWN family was recognised only by its un-suffixed id (S4-REV-05) | **`UNKNOWN` on 60 of 60** |
| **"0 unsupported claims over 372 authoritative claims"** as a statement about honesty | previous revision, G4.8 | the 372 included one per-world "causal spine" DER for every compiled world — world attribution under an authoritative type — and the walk only checked shapes (S4-FC-02) | 0 over **186** authoritative OBS claims, each digest-anchored |
| **"all 9 ablation rows … NOT_YET_JUSTIFIED — get a non-degenerate corpus and re-run"** as the route for every flag | previous revision UNMEASURED table | seven flags are inert by construction; a better corpus cannot move them (S4-FC-08) | declared `INERT`, default off |

### NOT A DETECTION RESULT

Nothing in this document is a detection result, and five specific things that look like one are not.

- **Every corpus here is synthetic** (ADR-0010). Four corpora in this repository have produced only
  trivial or impossible tasks with no middle band, and the Stage 4 incident corpus is **DEGENERATE
  by its own guard**, measured this session at order-free 0.3950 against a 0.3333 base rate.
- **The corpus author and the mechanism author are the same wave.** `GroundTruthWorld` labels the
  world each case came from and `SecurityWorldV1.mechanism_id` is the vocabulary LUCID would propose
  from — except that it proposes nothing: every spawned world is named
  `unresolved_novel_mechanism[.suffix]`, so recall by `mechanism_id` (0.1167) is measuring the
  absence of a mechanism-proposal path, not a disagreement about mechanisms. This confound does
  **not** apply to G4.7, G4.8, G4.9 or G4.11.
- **The Stage 2 verdicts in G4.11 are not a second opinion.** They are a deterministic function of
  the Stage 1 transitions at an arbitrary 0.25 operating point — a stronger form of a digest check,
  not an independent detector.
- **No timing figure here is a device measurement.** Load on this host moved between 1.62 and 14.12
  during the session, and a Stage 2 gate previously saw a 7× inflation between load 8–12 and load
  23–67. Only within-run ratios transfer, and each carries its own `/proc/loadavg`.
- **Incremental RSS is not stable across invocations.** The same 60-incident walk reported
  22810624, 2117632 and 450560 bytes in three runs, because `delta_rss` depends on what the
  interpreter had already allocated. The **peak against the ceiling** is the comparable figure:
  76881920 B against 94371840 B, and against the Stage 0 Edge target of 104857600 B.

---

## What would change this conclusion

Ordered by how much each would change, and each is a measurement, not an opinion.

1. **Write the belief update.** One mechanism — `WorldSupport.combine(log_likelihood_ratio)` called
   from the LUCID loop with the likelihood ratio `accumulate_evidence` already computes and stores
   in `IncidentState.sequential`. Six failing criteria are downstream of its absence: G4.2 (recall
   and premature collapse), G4.4(c) (the F4 inequality is `0.0 <= 0.0` — **correction, review-fix
   S4-REV-07: support is not an input to `confidence_of`; confidence is 0.0 because every world's
   uncertainty is pinned at 1.0 and because the hole rule fires on every incident, so the belief
   update alone would leave G4.4(c) exactly as vacuous**), G4.5 (discrimination is
   computed over a flat vector), G4.6 (every `support_shift` is `+0.0000`), G4.9's survival clause
   and G4.10. Until it exists, **no measurement of Stage 4's cognition is informative in either
   direction**, and that is the single most important sentence in this document.
2. **Get a non-degenerate corpus.** Every "not yet justified" verdict here rests on a corpus whose
   own guard calls it degenerate at order-free 0.3950 vs base rate 0.3333. The fix is the same one
   Stage 2 needed and eventually found (`stage1/labs/ambiguous_corpus.py` dropped a saturated
   1.0000 to 0.5066): interleave more lineages, put every attack operation into benign traffic, and
   re-check `saturation_check` **reading its return value the right way round**.
3. **Fix the four measurement defects before measuring anything else.** S4-MEAS-01 (inverted
   verdict, at `gate.py:825/849/860` and `cli.py:183/190/200`), S4-MEAS-02 (a frontier clause that
   cannot pass), S4-MEAS-03 (`frozenset() <= X`), S4-MEAS-04 (a metric monotone in K). A wave that
   writes the belief update and then reads these four numbers will conclude the wrong thing twice
   over: three of them understate the mechanism and one overstates it.
4. **Collapse the two `DIMENSION_SIGNALS` maps, or state which vocabulary a world may expect.**
   While the sensor vocabulary and the world-expectation vocabulary have an empty intersection on
   the only droppable sensor path, G4.4's shadow clause cannot pass however good the shadow is.
   This is a design decision and belongs in an ADR with its own measurement.
5. **Build a flood that actually floods.** `build_world_flood` cannot reach 4 worlds in 3360 steps.
   Until a corpus can drive `K` to `MAX_WORLDS`, "the bound holds under adversarial load" is
   demonstrated only by lowering the bound — which this session did, successfully, and which is
   weaker evidence than the criterion asks for.
6. **A real-telemetry visibility measurement.** G4.1 fails on its telemetry-source clause and will
   keep failing until paired eBPF/auditd collection on a real host with ground-truth injected
   actions exists. Four of the five simulated sensor paths currently have no exclusive signals, so
   the simulator cannot even pose the question for them.

**What would *not* change the conclusion**, so that nobody spends a wave on it: tuning any threshold
in §4. `MIN_DISCRIMINATION_TO_SPEND` is 0.10 and the best discrimination measured is 0.0922, which
is close enough to tempt. Lowering it would make G4.5 issue requests over a support vector that is
identically 0.0. Every one of those requests would be noise, and the criterion would then pass on
nothing at all.

---

## Draft ADR amendment

**No ADR number is available.** Stage 4's reserved block is **0030–0039** and all ten files exist
(`docs/adr/0030-…` through `0039-…`). The lead's instruction forbids using any number outside the
block, and the integration plan's own table (§5.5) assigns Stage 4 `0023–0032`, which Stage 3
already occupies at `0020–0029`. Minting a number would either collide with another wave or break
the block rule, so this session mints none and records the constraint instead.

The rejection this document reports is already recorded in **ADR-0036**, **ADR-0037** and
**ADR-0038**. What those three need is an amendment, not a successor. Draft text for ADR-0036, for
whoever holds the pen next:

> ### Amendment, measurement session 2026-09-25
>
> Three figures this ADR rests on are withdrawn as measurements and replaced.
>
> 1. **"0 of 10 flags JUSTIFIED" is withdrawn.** The flag ablation computed no deltas.
>    `saturation_check` returned `degenerate=True`, `run_ablation` took its degenerate branch, and
>    each of the nine rows carries `metric = world_set_recall:not-computed(...)`. The ablation is
>    UNMEASURED. `pocketsec/stage4/gate.py:825` and `pocketsec/stage4/cli.py:183` bind
>    `(degenerate, reason)` to `corpus_ok` and print its negation, so every published run of this
>    gate has reported the corpus as non-degenerate while its own quoted reason said otherwise.
> 2. **The frontier table's `world_set_recall` column is corrected.** `run_engine_baseline` scores
>    coverage with `truth_signals <= …`, and an empty `truth_signals` is vacuously a subset, so the
>    7 of 60 cases whose ground-truth world raises no dimension were scored as covered regardless of
>    what the engine proposed. Corrected: CBF_LUCID **0.8868 (47/53)**, B1_SingleWorldMAP
>    **0.2264 (12/53)**. B3's `1.0` is a literal constant, not a measurement.
> 3. **The corrected advantage does not support competing worlds either.** Sweeping `max_worlds`
>    with nothing else changed gives recall 0.2264 / 0.4717 / 0.8868 at K = 1 / 2 / 3 and flat to
>    K = 16, with `IDENTIFIED` at 0/60 throughout. The metric is monotone in world count, so the
>    +0.66 difference between B1 and CBF measures K, not reasoning.
>
> The decision is unchanged and better supported: **NOT-YET-JUSTIFIED**, with the corpus degeneracy
> now quantified (order-free control 0.3950 against base rate 0.3333, tolerance 0.02) as the reason
> it cannot be stronger. Two additions to the consequences: G4.10's "on the frontier" clause is
> rejected as a criterion, because a perfectly-scoring mechanism is still dominated by a control
> that reports `None` on every quality axis; and `build_world_flood` is rejected for its stated
> purpose, because 3360 steps reach 3 worlds of 8.

---

## Provisional status of every claim in this document

No claim here is asserted as new, and no priority claim is made, because both prior-art ledger
entries Stage 4 binds to are unreviewed: H3 (`literature_status = NOT_REVIEWED`) and H7
(`NOT_REVIEWED`). Nothing above is unprecedented, nothing is a breakthrough, and no patent position
is asserted anywhere in this document — none of the three may be claimed until that review has
happened. G4.12 **passes**: the two ledger entries exist, the five honesty-ledger headings are
present, this document makes no unbacked novelty claim, and `experiments/registry.jsonl` is
byte-identical across a full gate run. The digest changed exactly once this session, on an explicit
`pocketsec-stage4 register` (§15) — which is a deliberate operator action, not a gate side effect,
and G4.12's clause is about the latter. What G4.12 does **not** assert is that the review has
happened — it asserts that no claim outrunning it has been made.

Stage 4 minted no hypothesis of its own: `pocketsec/stage0/hypotheses.py` holds H0–H8 and
`tests/test_harness_and_gate.py` asserts the prior-art ledger covers exactly that set, so appending
H10 would mean editing a Stage 0 file another wave may be inside (spec §2.9).

---

## Commands and their real output

**Review-fix note (S4-FC-17).** Several scripts below are elided as `...` — including the ones behind
the 60/60 zero-support trace, the corrected recall, the K-sweep, the flood configurations and the
perfect-CBF counterfactual — although the text around them says "full script pasted below". Those
scripts were not preserved and this revision could not recover them, so the figures they produced
are **MEASURED with the script not preserved**: they cannot be re-run from this document, and a
reader should weigh them accordingly. The review-fix revision's own figures above name the function
each one calls.

Every command below was run in this session, in `/home/anil/Documents/Research/pocketsec`, on
Python 3.14.7 / Linux 7.1.5+kali-amd64. `/proc/loadavg` is printed before and after each.

### 1. The gate

```
$ cat /proc/loadavg
1.62 2.10 2.78 3/1828 1801774
$ sha256sum experiments/registry.jsonl
c0bc4f8ea4ade092cb53877593cee836df52c5c9d88845683f21532ec55c6551  experiments/registry.jsonl
$ time python -m pocketsec.stage4.cli gate
PocketSec Stage 4 acceptance gate — CBF + LUCID

This gate is EXPECTED TO FAIL and its failures are the stage's findings (docs/stage-4-spec.md §6.2). Read docs/stage-4-findings.md beside it.

  [FAIL] G4.1  Partial-observability and visibility models empirically measured
         MEASURED (simulator): 16 held-out (signal, sensor) pairs with >=20 occurrences, 0 outside +-0.05 of the fitted probability; all 6 MANDATORY_SIGNALS answer 1.0: True; an unevidenced pair answers None not 0.0: True; coverage 0.4; evidence written to results/stage4-visibility.json and its provenance matches the split just run: True; simulator half met: True. UNMEASURED (and the reason this check FAILS): the telemetry-source clause. [...]
  [FAIL] G4.2  CBF preserves the ground-truth world or an equivalent explanation
         over 60 cases of build_incident_corpus(count=60, seed=11): world-set recall by mechanism_id 0.1167, by observational equivalence at eps=0.05 0.0333, so the criterion's own reading is 0.1167 against the required 0.9. Premature-collapse rate 0.0000 (<= 0.1) — and it is 0.0000 for the wrong reason: the engine resolved IDENTIFIED on zero of 60 cases [...] A third reading — signal coverage [...] gives 0.7833 [...] B1 single-world MAP matches recall at no greater CPU: False (B1 recall 0.31666666666666665, cpu 2.4174; CBF recall 0.9, cpu 9.4474). loadavg (1.8623046875, 2.123046875, 2.77880859375).
  [PASS] G4.3  Constructed non-identifiable cases are explicitly recognised
         build_nonidentifiable_pairs(count=20, seed=17): 20/20 returned IdentifiabilityState.UNIDENTIFIABLE, 20/20 with discriminating_observations == (), 20/20 mapped to Verdict.UNIDENTIFIABLE with abstained=True, and 20/20 did NOT pick the more alarming world. build_resolvable_after_one_observation: 20/20 returned INSUFFICIENT_EVIDENCE [...] and 20/20 reached IDENTIFIED after exactly one granted 'file_staging' observation.
  [FAIL] G4.4  Evidence Tension and Sensor Shadow behave correctly under dropped telemetry
         paired over 60 cases, full telemetry against drop_sensor_path(case, ebpf), whose exclusive signals are ['receive', 'send']. (c) falsifier F4 [...]: 0 confidence violations, 0 verdict violations. (a) the shadow marks the signals the drop made unobservable: 60 cases where it did not ["s4-inc-0011-0000: expected ['send'] in ['modification', 'reachability']", ...], 0 where it did. THE NUMBER THAT DECIDED THIS AND WHY IT IS NOT REASSURING: 0 of 60 cases had a non-zero confidence in either arm.
  [FAIL] G4.5  At least one active sensing method reduces bytes/CPU versus always-on telemetry
         same run, same process: CBF/LUCID against B3_AlwaysOnRichTelemetry. telemetry_bytes ratio 1.2441 (37024 / 29760); cpu_units ratio 76819.4243; both must be < 1.0: False. Quality within 0.02: False (B3 world-set recall 1.0, CBF 0.9). THE NUMBER THAT DECIDED THIS: the planner issued 0 ObservationRequests across 60 incidents. It refused 360 actions [...]
  [FAIL] G4.6  Counterfactual stress identifies predefined spurious causal explanations
         4 of 5 predefined-decoy cases could be constructed as a true/spurious world pair [...] spurious_detected on the SPURIOUS world 0/4, and the stress flagged the TRUE world instead on 4 cases [...] every support shift it measured was exactly +0.0000 [...] RENAME_SEMANTIC_PRESERVING leaves field.support_vector() bit-identical on 4/4
  [PASS] G4.7  Typed Claim Graph enforces OBS/DER/INF/CF/EXT/UNK separation
         structural: the TypedClaim union has 6 members against 6 ClaimKind values [...] AUTHORITATIVE_KINDS is ['DER', 'OBS'] [...] All seven spec §D4.13 laundering attempts (a)-(g) were refused: True. behavioural, over 60 real incidents: kinds actually present ['DER', 'INF', 'OBS', 'UNK']
  [PASS] G4.8  Authoritative output contains zero unsupported factual claims
         over 60 exported CBFResolutionV1 records covering 372 authoritative claims: unsupported_authoritative() returned 0 claims; amplification_violations() returned 0 [...]
  [FAIL] G4.9  World count, graph size and reasoning work remain hard bounded
         build_world_flood(count=40, seed=23), every bound sampled at each of 1120 update steps [...] worlds 3/8; graph nodes 9/512; edges 5/1024; claims 12/256; reasoning units 2961/4096; state bytes 29651/8388608. All within bound: True. 5028 Truncation records were emitted [...] The ground-truth world survived the flood on 0/40 countable cases. HONEST LIMIT ON THIS PASS: the bounds reached during the flood were () [...]
  [FAIL] G4.10  CBF/LUCID beats or complements simpler baselines on the measured Pareto frontier
         saturation_check FIRST, on the corpus: degenerate=False — order-free control reaches 0.3950 against base rate 0.3333 [...] saturation_guard on the 9 baseline outcomes: degenerate=True — SATURATED: best 0.6667 within 0.01 of median 0.6667 [...] Pareto frontier ['B8_NoStage4']; dominated [... 'CBF_LUCID']; CBF_LUCID on the frontier: False. Flag ablation over 9 rows: 0 of 10 LucidConfig flags came out JUSTIFIED [] (verdict tally {'DEGENERATE': 9}) [...]
  [PASS] G4.11  Stage 4 remains optional to core Stage 1-3 detection if it crashes
         ten subsystems x 12 incidents, each fault raised MID-incident [...] Exceptions that escaped: 0. [...] T7, by AST over every module: modules under pocketsec/stage1/ or pocketsec/stage2/ importing pocketsec.stage4: 0.
  [PASS] G4.12  All novelty claims remain provisional until formal prior-art/patent review
         [...] experiments/registry.jsonl is byte-identical before and after this gate run: True (sha256:c0bc4f8e...c55c6551 -> sha256:c0bc4f8e...c55c6551)

GATE: FAILED (7)
python -m pocketsec.stage4.cli gate  113.78s user 0.07s system 99% cpu 1:53.90 total
$ cat /proc/loadavg
3.04 2.47 2.84 2/1807 1808572
$ sha256sum experiments/registry.jsonl
c0bc4f8ea4ade092cb53877593cee836df52c5c9d88845683f21532ec55c6551  experiments/registry.jsonl

$ python -m pocketsec.stage4.cli --json gate > gate.json; echo "GATE_EXIT=$?"
GATE_EXIT=1
```

The G4.1, G4.2, G4.4, G4.5, G4.6, G4.9 and G4.10 detail strings are abridged with `[...]` above
where they repeat text quoted in full elsewhere in this document. The unabridged run is reproducible
with the command shown.

### 2. Baselines — all nine rows, one process

```
$ cat /proc/loadavg
2.89 2.63 2.85 3/1887 1816685
$ time python -m pocketsec.stage4.cli baselines
Stage 4 baselines (synthetic corpus; within-run ratios only)

  SATURATION GUARD: degenerate=True — SATURATED: best 0.6667 within 0.01 of median 0.6667
  A DEGENERATE split records no comparison. The table below measures the split.

  baseline                         recall  unsup    bytes         cpu     work
  B1_SingleWorldMAP                0.3167      0    37024    2.839324   214689
  B2_NaiveAncestryAttribution         n/a      0        0    0.001289       79
  B3_AlwaysOnRichTelemetry         1.0000      0    29760    0.000135      480
  B4_PhiThresholdPlaybook             n/a      0        0    0.000228      240
  B5_FixedWindowCorrelation           n/a      0        0    0.001978     4262
  B6_TwoStateHMM                      n/a      0        0    0.009642    17488
  B7_InformationGainPlanner           n/a      0     3834    8.461118   362406
  B8_NoStage4                         n/a      0        0    0.000033       60
  CBF_LUCID                        0.9000      0    37024   10.083912   404546

  frontier  ['B8_NoStage4']
  dominated ['B1_SingleWorldMAP', 'B2_NaiveAncestryAttribution', 'B3_AlwaysOnRichTelemetry', 'B4_PhiThresholdPlaybook', 'B5_FixedWindowCorrelation', 'B6_TwoStateHMM', 'B7_InformationGainPlanner', 'CBF_LUCID']
  loadavg   (2.97265625, 2.67333984375, 2.859375)
python -m pocketsec.stage4.cli baselines  24.75s user 0.04s system 99% cpu 24.787 total
$ cat /proc/loadavg
2.97 2.67 2.86 2/1839 1818266
```

Note for the reader: **six of the nine rows report `recall = n/a`** — `world_set_recall is None`,
which the frontier treats as an incomparable axis. That is why the frontier has one member and why
S4-MEAS-02 exists.

### 3. Ablation — and the inverted verdict

```
$ cat /proc/loadavg
2.27 2.53 2.80 2/1840 1820962
$ time python -m pocketsec.stage4.cli ablation
LucidConfig flag ablation (saturation guard first)

  corpus degenerate: False — order-free control reaches 0.3950 against base rate 0.3333; the label is readable from the operation histogram

  flag                        core           with  without    delta  verdict
  enable_free_energy                       0.0000   0.0000  +0.0000  DEGENERATE
  enable_sequential_evidence  CBF-F08      0.0000   0.0000  +0.0000  DEGENERATE
  enable_verbalizer                        0.0000   0.0000  +0.0000  DEGENERATE
  enable_active_sensing       CBF-F13      0.0000   0.0000  +0.0000  DEGENERATE
  enable_fission_fusion       CBF-F04      0.0000   0.0000  +0.0000  DEGENERATE
  enable_counterfactual       CBF-F09      0.0000   0.0000  +0.0000  DEGENERATE
  enable_self_questioning     CBF-F15      0.0000   0.0000  +0.0000  DEGENERATE
  enable_stress               CBF-F16      0.0000   0.0000  +0.0000  DEGENERATE
  enable_cell_feedback        CBF-F19      0.0000   0.0000  +0.0000  DEGENERATE

  NOT_YET_JUSTIFIED is not REJECTED: on a corpus with no headroom, 'no measured benefit' cannot demonstrate absence of benefit (ADR-0009).
  blocked experiments: ['S4X-02', 'S4X-16', 'S4X-34', 'S4X-40']
python -m pocketsec.stage4.cli ablation  3.85s user 0.01s system 99% cpu 3.867 total
```

The header says `degenerate: False` and the rows say `DEGENERATE`. Both come from the same call. The
next command settles which is which.

### 4. S4-MEAS-01 — the inversion, and the corpus's real saturation state

```
$ python - <<'PY'
from pocketsec.stage4 import gate_criteria as criteria
from pocketsec.stage4.labs.experiments import saturation_check, MAX_ORDER_FREE_ADVANTAGE, run_ablation
cases = criteria.corpus()
raw = saturation_check(cases)
print("saturation_check(cases) RAW TUPLE =", raw)
corpus_ok, corpus_why = raw
print("gate prints: degenerate=%r" % (not corpus_ok))
print("function says degenerate=%r" % corpus_ok)
rows = run_ablation(cases, seed=criteria.CORPUS_SEED)
for r in rows[:3]:
    print("  ", r.flag, r.with_value, r.without_value, r.delta, r.verdict, "| metric =", r.metric)
PY
corpus cases: 60 count/seed: 60 11
saturation_check(cases) RAW TUPLE = (True, 'order-free control reaches 0.3950 against base rate 0.3333; the label is readable from the operation histogram')
MAX_ORDER_FREE_ADVANTAGE = 0.02

=== what the gate/cli print vs what the function returned ===
gate prints: degenerate=False
function says degenerate=True
reason: order-free control reaches 0.3950 against base rate 0.3333; the label is readable from the operation histogram

ablation rows: 9
   enable_free_energy 0.0 0.0 0.0 DEGENERATE | metric = world_set_recall:not-computed(order-free control reaches 0.3950 against base rate 0.3333; the label is readable from the operation histogram)
   enable_sequential_evidence 0.0 0.0 0.0 DEGENERATE | metric = world_set_recall:not-computed(order-free control reaches 0.3950 against base rate 0.3333; the label is readable from the operation histogram)
   enable_verbalizer 0.0 0.0 0.0 DEGENERATE | metric = world_set_recall:not-computed(order-free control reaches 0.3950 against base rate 0.3333; the label is readable from the operation histogram)
```

And the three traps, each read out separately:

```
$ python - <<'PY'   # median_peak_delta_phi / order-free control / share gap
...
PY
median_peak_delta_phi per label : {0: 2.25, 1: 8.0}   (trap 1: neither is 0.00 -> OK)
base_rate                       : 0.3333
order-free bag-of-ops control AP: 0.395  advantage 0.0617 > 0.02 -> True
operation_share_gap             : 0.0074

VERDICT: the incident corpus is DEGENERATE by its own guard, on trap 2.
```

### 5. S4-MEAS-02 — the frontier clause cannot pass

```
$ python - <<'PY'   # reconstructs this run's nine rows, then perturbs CBF to perfection
...
PY
# Scope of this reconstruction, stated because it is not the live objects: the nine
# BaselineOutcome instances were rebuilt from the recall / unsup / bytes / cpu / work
# columns printed by `pocketsec-stage4 baselines` above, with detection_accuracy set
# uniformly to 0.6667. detection_accuracy is not one of pareto_frontier's seven axes
# (_MAXIMISE + _MINIMISE), so it cannot affect the domination result; the reconstruction
# reproduces the shipped frontier exactly, which is the check that it is faithful.
reconstructed frontier: ('B8_NoStage4',)
reconstructed dominated: ('B1_SingleWorldMAP', 'B2_NaiveAncestryAttribution', 'B3_AlwaysOnRichTelemetry', 'B4_PhiThresholdPlaybook', 'B5_FixedWindowCorrelation', 'B6_TwoStateHMM', 'B7_InformationGainPlanner', 'CBF_LUCID')

B8 axes: {'world_set_recall': None, 'nonidentifiability_accuracy': None, 'resolution_efficiency': None, 'premature_collapse_rate': None, 'cpu_units': 3.3e-05, 'telemetry_bytes': 0, 'work_units': 60}
_dominates(B8, CBF) = True

=== COUNTERFACTUAL: give CBF_LUCID a PERFECT score on every quality axis ===
_dominates(B8, perfect CBF) = True
frontier with a PERFECT CBF_LUCID: ('B8_NoStage4',)
CBF_LUCID on frontier: False

=== COUNTERFACTUAL 2: perfect CBF *and* B8 reporting a real (poor) quality score ===
frontier: ('B3_AlwaysOnRichTelemetry', 'B8_NoStage4') | CBF_LUCID on frontier: False
```

### 6. The support trace, and CPU per unit of work

```
$ cat /proc/loadavg
3.00 2.72 2.81 3/1856 1837445
$ python - <<'PY'   # support trace over one incident, then over all 60, then the CPU pair
...
PY
60 cases, 4372 Stage 1 transitions total; stage1 replay cpu 0.8808s

incident s4-inc-0011-0000: 58 transitions, 3 worlds
distinct support_vector() states across every update step: 4
    ()
    (('w-3aa2a6993bc725a7', 0.3333333333), ('w-988cf849410e592a', 0.3333333333), ('w-a327a812ce644e59', 0.3333333333))
    (('w-988cf849410e592a', 0.5), ('w-a327a812ce644e59', 0.5))
    (('w-a327a812ce644e59', 1.0),)
raw world support values: [('unresolved_novel_mechanism', 'LOG_ODDS', 0.0, 'UNRESOLVED'), ('unresolved_novel_mechanism.373d251c2100', 'LOG_ODDS', 0.0, 'UNRESOLVED'), ('unresolved_novel_mechanism.d6396866cea8', 'LOG_ODDS', 0.0, 'UNRESOLVED')]
resolution: state=UNIDENTIFIABLE confidence=0.0 abstained=True margin=0.0

=== over all 60 incidents ===
distinct world support.value: [0.0]
distinct resolution.confidence: [0.0]
distinct verdict.support_margin: [0.0]
identifiability state tally: {'UNIDENTIFIABLE': 60}

=== CPU per unit of work (same run, same process) ===
CBF_LUCID  cpu=11.3038s work=404546 recall=0.9 tel=37024
           cpu/transition=2585.49 us  cpu/incident=188.396 ms
B1         cpu=3.0198s work=214689 recall=0.31666666666666665 tel=37024
           cpu/transition=690.71 us  cpu/incident=50.330 ms
WITHIN-RUN RATIO CBF/B1: cpu 3.7432x  work 1.8843x
loadavg (3.04931640625, 2.76318359375, 2.82568359375)
$ cat /proc/loadavg
3.05 2.76 2.83 3/1840 1839542
```

### 7. S4-MEAS-03 and S4-MEAS-04 — the vacuous free passes and the K-sweep

```
$ python - <<'PY'
...
PY
cases whose truth_signals is EMPTY: 7 of 60
  -> ['s4-inc-0011-0000', 's4-inc-0011-0009', 's4-inc-0011-0018', 's4-inc-0011-0027', 's4-inc-0011-0036', 's4-inc-0011-0045', 's4-inc-0011-0054']
frozenset() <= frozenset({'x'}) = True
expected gap = 7/60 = 0.1167
measured this session: run_engine_baseline 0.9000, world_set_recall.by_signal_coverage 0.7833, gap 0.1167 = 7/60

truth mechanism_id histogram: [('approved_administration', 20), ('scheduled_automation_external_sink', 20), ('unresolved_novel_mechanism', 7), ('stolen_credential_reuse', 7), ('compromised_admin_session', 6)]
raises_dimensions of the empty-signal cases: [((), 7)]

$ python - <<'PY'   # corrected recall
...
PY
CBF_LUCID              as-shipped 0.9000 (54/60)  |  vacuous free passes 7/7  |  CORRECTED 47/53 = 0.8868
B1_SingleWorldMAP      as-shipped 0.3167 (19/60)  |  vacuous free passes 7/7  |  CORRECTED 12/53 = 0.2264
B3_AlwaysOnRichTelemetry world_set_recall is the literal constant 1.0 (simple_baselines.py:137), not a measurement.

$ python - <<'PY'   # is the metric monotone in K alone?
...
PY
max_worlds  corrected recall  mean K  identified
         1            0.2264    1.00     0/60
         2            0.4717    2.00     0/60
         3            0.8868    2.82     0/60
         4            0.8868    3.10     0/60
         8            0.8868    3.10     0/60
        16            0.8868    3.10     0/60
```

Load during the K-sweep was 3.92 → 14.12 (another wave's suite was running); the recall figures are
counts and unaffected, and no timing figure is taken from that run.

### 8. Bounds, including degradation at the bound

```
$ cat /proc/loadavg
2.62 2.53 2.77 3/1854 1830154
$ python -m pocketsec.stage4.cli flood
Adversarial branch flood: build_world_flood(count=40, seed=23)

  steps                    1120
  worst_worlds             3
  worst_graph_nodes        9
  worst_graph_edges        5
  worst_claims             12
  worst_state_bytes        29651
  worst_reasoning_units    2961
  truncations              5028
  bounds_reached           []
  loadavg                  (2.6533203125, 2.541015625, 2.76806640625)
  wall=4.09s maxrss=43600kB

$ python - <<'PY'   # three flood configurations
...
PY
FLOOD_CANDIDATE_LINEAGES = 12

count=40 max_worlds=8: steps=1120 worst_worlds=3/8 nodes=9 edges=5 claims=12 units=2961/4096 bytes=29651 truncations=5028 bounds_reached=()
   within_bound (all): True

count=120 max_worlds=8: steps=3360 worst_worlds=3/8 nodes=9 edges=5 claims=12 units=2990/4096 bytes=29651 truncations=14675 bounds_reached=()
   within_bound (all): True

count=40 max_worlds=2: steps=1120 worst_worlds=2/2 nodes=9 edges=5 claims=9 units=2439/4096 bytes=28535 truncations=5028 bounds_reached=('worlds',)
   within_bound (all): True

loadavg (2.71044921875, 2.73828125, 2.8095703125)
```

### 9. Resources, including the per-component breakdown

```
$ cat /proc/loadavg
2.56 2.52 2.76 3/1824 1829266
$ python -m pocketsec.stage4.cli resources
Stage 4 resource measurement (contended host; see docs/stage-4-spec.md §2.8)

  budget                             {'belief_field': 8388608, 'calibration': 2097152, 'claim_graph': 4194304, 'degradation': 1048576, 'tombstones': 2097152, 'world_graph': 8388608}
  incremental_rss_bytes              22810624
  loadavg                            [2.623046875, 2.533203125, 2.7666015625]
  measured_by                        pocketsec.stage4.cli:resources
  normal_incremental_budget_bytes    47185920
  over_budget                        []
  over_peak_ceiling                  False
  peak_ceiling_bytes                 94371840
  peak_sampled_rss_bytes             76881920
  per_component_bytes                {}
  unmeasured                         ['belief_field not supplied', 'world_graph not supplied', 'claim_graph not supplied', 'tombstones not supplied', 'calibration not supplied', 'degradation not supplied']
  within_target                      None
  wall=12.26s maxrss=74780kB
```

Filling the six `not supplied` rows by passing the live structures from a resolved incident:

```
$ python - <<'PY'
...
PY
PASS 1 (no live objects — identical to `pocketsec-stage4 resources`):
  incremental_rss_bytes 2117632 peak 53997568
  per_component_bytes {}

LIVE STRUCTURES from the last resolved incident:
  field.state_bytes()          114192
  field.graph.memory_bytes()   3342
  tombstones.memory_bytes()    280
  degradation.memory_bytes()   0
  engine.memory_bytes()        0
  claim_graph serialised bytes 142
  fresh EpochCalibration       0

PASS 2 (all six components supplied):
  per_component_bytes {"belief_field": 114192, "calibration": 0, "claim_graph": 142, "degradation": 0, "tombstones": 280, "world_graph": 3342}
  STAGE4_BUDGET       {"belief_field": 8388608, "calibration": 2097152, "claim_graph": 4194304, "degradation": 1048576, "tombstones": 2097152, "world_graph": 8388608}
  still unmeasured    []
  over_budget [] | over_peak_ceiling False | within_target True
  incremental_rss 450560 | peak 54558720
```

Every component is **two to four orders of magnitude** under its budget, `over_budget` is empty, and
`within_target` becomes `True` once nothing is missing. Falsifier **F10 does not fire**: Stage 4 does
not exceed its Edge resource targets. Note also the three different `incremental_rss_bytes` readings
for the same walk (22810624 / 2117632 / 450560) — that figure is not stable across invocations and
only the peak-against-ceiling comparison is reportable.

### 10. Sensing and visibility

```
$ python -m pocketsec.stage4.cli sensing
Discriminating-observation planner over the incident corpus

  requests issued  0 across 60 incidents
  refusals, by reason:
       99  expected discrimination 0.0825 below MIN_DISCRIMINATION_TO_SPEND 0.1
       91  expected discrimination 0.0808 below MIN_DISCRIMINATION_TO_SPEND 0.1
       91  expected discrimination 0.0922 below MIN_DISCRIMINATION_TO_SPEND 0.1
       51  expected discrimination 0.0695 below MIN_DISCRIMINATION_TO_SPEND 0.1
       22  expected discrimination 0.0000 below MIN_DISCRIMINATION_TO_SPEND 0.1
        6  expected discrimination 0.0024 below MIN_DISCRIMINATION_TO_SPEND 0.1
  wall=26.75s maxrss=117992kB

$ python -m pocketsec.stage4.cli visibility
Visibility model: fitted on half the replays, scored on the other half

  provenance        {'corpus': 'stage4-incident-corpus', 'count': 60, 'seed': 11, 'sensors': ['ebpf', 'auditd'], 'fit_scenarios': 30, 'held_out_scenarios': 30, 'synthetic_data': True}
  coverage          0.4
  compared pairs    16 (>= 20 occurrences)
  outside +-0.05     0 ()
  evidence written  results/stage4-visibility.json
  wall=1.94s maxrss=31744kB
```

### 11. The two `DIMENSION_SIGNALS` maps and the disjoint vocabularies

```
$ python - <<'PY'
...
PY
visibility/model.py DIMENSION_SIGNALS: 6 {'privilege': 'privilege_change', 'credential': 'credential_access', 'persistence': 'persistence_write', 'execution': 'module_load', 'isolation': 'boundary_crossing', 'trust': 'authentication'}
worlds/lifecycle.py DIMENSION_SIGNALS: 9 {'privilege': 'privilege_change', 'credential': 'credential_access', 'persistence': 'persistence_write', 'isolation': 'boundary_crossing', 'execution': 'module_load', 'trust': 'authentication', 'reachability': 'reachability', 'modification': 'modification', 'discovery': 'discovery'}
A is B: False | dict(A)==dict(B): False
keys only in lifecycle: ['discovery', 'modification', 'reachability']

auditd    exclusive_signals = []
ebpf      exclusive_signals = ['receive', 'send']
procfs    exclusive_signals = []
journald  exclusive_signals = []
lsm       exclusive_signals = []

ebpf exclusive signals in visibility DIMENSION_SIGNALS values? []
ebpf exclusive signals in lifecycle DIMENSION_SIGNALS values?  []
the three lifecycle-only self-mappings: ['discovery', 'modification', 'reachability']

=> the signals a dropped eBPF path actually removes and the names a born world
   can expect are DISJOINT sets. The shadow therefore cannot mark them.
```

### 12. Tests, and the ledger's immutability

```
$ cat /proc/loadavg
3.02 2.89 2.86 3/1846 1857760
$ sha256sum experiments/registry.jsonl
c0bc4f8ea4ade092cb53877593cee836df52c5c9d88845683f21532ec55c6551  experiments/registry.jsonl
$ time PYTHONHASHSEED=0 python -m pytest -q tests/test_stage4_*.py
........................................................................ [  8%]
  (... 808 tests, no F, no E ...)
................                                                         [100%]
PYTHONHASHSEED=0 python -m pytest -q tests/test_stage4_...  300.55s user 0.22s system 99% cpu 5:00.86 total
$ sha256sum experiments/registry.jsonl
c0bc4f8ea4ade092cb53877593cee836df52c5c9d88845683f21532ec55c6551  experiments/registry.jsonl
$ cat /proc/loadavg
3.68 3.33 3.07 3/1848 1873404

$ python -m pytest -q --collect-only tests/test_stage4_*.py | awk -F': ' '/^tests/ {s+=$2; print} END {print "TOTAL:", s}'
tests/test_stage4_boundary.py: 22
tests/test_stage4_claims.py: 56
tests/test_stage4_counterfactual.py: 46
tests/test_stage4_foundation.py: 73
tests/test_stage4_gate.py: 34
tests/test_stage4_lifecycle.py: 72
tests/test_stage4_optionality.py: 363
tests/test_stage4_resolution.py: 62
tests/test_stage4_runtime.py: 49
tests/test_stage4_visibility.py: 31
TOTAL STAGE4 TESTS: 808

$ PYTHONHASHSEED=0 python -m pytest -q --no-header -p no:cacheprovider   # full suite
...
  [FAIL] G1.12  Resource costs measured on Stage 0 profiles
         peak RSS 116318208 B vs Edge target 104857600 B; novelty engine 173983 B; causal memory 2185 B; 183 transitions at 1.721e-04 CPU s/transition
GATE: FAILED (1)
...
E   assert 615813120 <= 115343360
tests/test_stage5_benchmarks.py:770: AssertionError
=========================== short test summary info ============================
FAILED tests/test_stage1_pipeline.py::test_stage1_acceptance_gate_passes - As...
FAILED tests/test_stage1_pipeline.py::test_gate_cli_exits_zero - AssertionErr...
FAILED tests/test_stage5_benchmarks.py::test_measured_resources_come_from_the_stage0_sampler_and_stay_in_budget
$ sha256sum experiments/registry.jsonl
c0bc4f8ea4ade092cb53877593cee836df52c5c9d88845683f21532ec55c6551  experiments/registry.jsonl
```

**Three failures in the full suite, none of them Stage 4's.** Two are Stage 1's G1.12 reading a
process-wide `getrusage` high-water mark; one is Stage 5's equivalent and belongs to another wave
building in this tree. `experiments/registry.jsonl` is **byte-identical** before and after the gate
run, before and after the Stage 4 test files, and before and after the full suite — the Stage 3
defect (a gate appending a row every time the suite ran) does not recur here.

### 13. Module count

```
$ find pocketsec/stage4 -name '*.py' -not -path '*__pycache__*' | wc -l
61
```

### 14. A fourth gate run, at four times the load — and what it says about timing

Run after the ledger write, at loadavg **10.48 → 14.18** against the first run's 1.62 → 3.04.

```
$ python -m pocketsec.stage4.cli gate | grep -E '^  \[|^GATE'
  [FAIL] G4.1  ... [FAIL] G4.2  ... [PASS] G4.3  ... [FAIL] G4.4  ... [FAIL] G4.5
  [FAIL] G4.6  ... [PASS] G4.7  ... [PASS] G4.8  ... [FAIL] G4.9  ... [FAIL] G4.10
  [PASS] G4.11 ... [PASS] G4.12
GATE: FAILED (7)
```

Same five passes, same seven failures. **G4.12 still passes** with this document rewritten and the
ledger at 31 rows. Comparing the two runs' detail strings figure by figure:

| figure | run 1, loadavg 1.86 | run 4, loadavg ~12 | moved? |
|---|---|---|---|
| world-set recall by `mechanism_id` | 0.1167 | 0.1167 | no |
| telemetry bytes ratio CBF ÷ B3 | 1.2441 (37024 / 29760) | 1.2441 (37024 / 29760) | no |
| flood bounds | worlds 3/8, nodes 9/512 | worlds 3/8, nodes 9/512 | no |
| authoritative claims | 372 | 372 | no |
| corpus `degenerate=` as printed | `False` (S4-MEAS-01) | `False` | no — the inversion is deterministic |
| **B1 cpu** | **2.4174** | **2.8854** | **×1.19** |
| **CBF cpu** | **9.4474** | **24.1664** | **×2.56** |
| **cpu ratio CBF ÷ B1** | **3.91** | **8.37** | **×2.14** |
| cpu ratio CBF ÷ B3 | 76819.42 | 77802.41 | ×1.01 |

**Every count is reproducible and every CPU figure is not.** More pointedly: the *within-run* CPU
ratio between two engine configurations moved from 3.91 to 8.37 between runs, and this session
measured a third value, 3.74, in an isolated script at loadavg 3.05. So the rule this repository
learned from Stage 2 needs tightening for Stage 4: on this host, **not even a within-run ratio
between two code paths is stable**, because the two paths absorb contention differently — B1 took a
1.19× hit where CBF took 2.56×. The only CPU statements this document makes are therefore
order-of-magnitude ones (CBF costs single-digit multiples of its one-world control and five orders of
magnitude more than doing nothing), and the `3.7432×` figure in the MEASURED table is labelled with
the load it was taken at for exactly this reason.

### 15. The one deliberate ledger write

No `PS-S4-*` row existed before this command. The id had been cited as provenance throughout the
previous revision and in ADR-0036/0037/0038 without ever being registered, because registration
lives in a subcommand an operator invokes and nobody had. This session ran it once, deliberately.
`register` re-runs the whole gate before it writes, so its `notes` field is a **third independent
reproduction** of the gate verdict.

```
$ sha256sum experiments/registry.jsonl; wc -l experiments/registry.jsonl
c0bc4f8ea4ade092cb53877593cee836df52c5c9d88845683f21532ec55c6551  experiments/registry.jsonl
30 experiments/registry.jsonl
$ cat /proc/loadavg
4.64 4.74 4.75 4/2077 1999846
$ python -m pocketsec.stage4.cli --json register
{
  "entry": {
    "dataset_name": "stage4-incident-corpus",
    "dataset_sha256": "sha256:38f09d4292004066202b6c250dc6208147521e7a963bfd728cfdf00d878494d7",
    "dataset_version": "stage4-incident-v0.1.0+stage1-ambiguous-v0.1.0",
    "entry_digest": "sha256:7c28231e73b64147a9a444760d011d081b93a5e0d061807a33802e686f65db58",
    "experiment_id": "PS-S4-20260925-H3-cbf-gate-0001",
    "git_commit": null,
    "hypothesis": "H3",
    "notes": "5/12 criteria met; failures ['G4.1', 'G4.2', 'G4.4', 'G4.5', 'G4.6', 'G4.9', 'G4.10']",
    "previous_digest": "sha256:8f2854a85e6dd78736e8c9d43d1ab2f223a8b4db29501ec6c8de31b288a0b48a",
    "recorded_at_ns": 1790312313821172236,
    "result_path": null,
    "seeds": {"corpus": 11, "flood": 23, "nonidentifiable": 17},
    "slot_name": "stage4-cbf-lucid",
    "synthetic_data": true,
    "title": "Stage 4 CBF+LUCID acceptance gate"
  },
  "registered": "PS-S4-20260925-H3-cbf-gate-0001"
}
$ sha256sum experiments/registry.jsonl; wc -l experiments/registry.jsonl
ef07a187c9d3c5e2baf1869d94f661ee4efc290f581aa4616bf830dc6a10c2ce  experiments/registry.jsonl
31 experiments/registry.jsonl
$ cat /proc/loadavg
13.69 9.00 6.40 11/2153 2019911
```

Three things this row establishes, and one it does not:

- `synthetic_data` is **`true`**, truthfully, as the harness requires.
- `notes` reads **5/12 criteria met, failures `['G4.1','G4.2','G4.4','G4.5','G4.6','G4.9','G4.10']`** —
  the same five passes and same seven failures as the two runs earlier in this session, from a third
  independent gate invocation at a much higher load (4.64 → 13.69). **The gate verdict is
  reproducible; only its timings are not.**
- The chain is intact: `previous_digest` is the `PS-S3-…-vm-cost-split-0005` entry's digest, the file
  grew 30 → 31 rows, and nothing was rewritten.
- It does **not** change any figure in this document. Every number here is reproducible from the
  command printed beside it whether or not the ledger row exists; the row makes the run citable, not
  true.

**The digest changed exactly once, and only here.** `sha256:c0bc4f8e…c55c6551` held across a full
gate run, across Stage 4's 808 tests, and across two full suite runs; it became
`sha256:ef07a187…6a10c2ce` on this one explicit `register`. That is the property Stage 3's defect
(spec §2.7) violated and this stage's design restores.
