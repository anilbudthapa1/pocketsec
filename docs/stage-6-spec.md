# Stage 6 — HELIOS + MNEMOSYNE — implementation specification

- **Status:** the implementation contract for Wave 6. Binding on all eight work packages.
- **Date:** 2026-09-26
- **Architecture source of truth:** `docs/architecture/sources/stage-06-helios-mnemosyne.md`
- **Build contract:** `docs/architecture/stage-3-12-integration-plan.md`
- **Phase checklist and gate:** `planning/PHASE_06_CLAUDE_CODE.md`
- **ADR block:** **0050–0059 only** (the project lead's block for this wave; it overrides the
  0043–0052 row of integration plan §5.5, which Stage 5 has already consumed up to 0049).
  Verified free this session: `ls docs/adr | grep -cE '^005[0-9]-'` → `0`.
- **Gate check count:** **13**, fixed by integration plan §5.1, one per bullet of architecture §52.
- **Findings document the integrator must write:** `docs/stage-6-findings.md`.

---

## 0. Measurement status of this document

Every claim below is one of three things, and the reader may hold me to the label.

**MEASURED — produced by running code in this session.** Load average is recorded beside each
row because a Stage 2 gate measured a 7× wall-clock inflation on this contended host.

| claim | value | how it was produced | `/proc/loadavg` |
|---|---|---|---|
| Every Stage 0–5 symbol Stage 6 consumes exists | **101 OK, 0 missing**, exit 0 | the §3.0 script, `PYTHONPATH=. python3 verify_seam.py` | `0.95 1.28 2.00` |
| Upstream schema versions Stage 6 pins | `ssir_transition.v1`, `cbf_resolution.v1`, `response_record.v1`, `threat_prediction.v1`, `security_event_sequence.v1` → all `1.0.0` | `SCHEMA_REGISTRY.get(...)` after importing the modules, same script | same |
| ADR numbers 0050–0059 are unused | `0` files | `ls docs/adr \| grep -cE '^005[0-9]-'` | — |
| `pocketsec/stage6/` contains no Python | `0` files | `find pocketsec/stage6 -name '*.py' \| wc -l` | — |
| `pocketsec/stage6/` holds five **empty** directories | `helios/ learning/ memory/ mnemosyne/ quarantine/` | `find pocketsec/stage6 -mindepth 1 -type d` | — |
| No Stage 6 test or doc exists | `0` / `0` | `ls tests \| grep -c stage6`; `ls docs \| grep -c stage-6` | — |
| The numpy exemption covers Stage 2 **only** | `RESEARCH_PREFIX = "pocketsec/stage2/research/"` | `tests/test_repository_structure.py:79` | — |
| `HYPOTHESES` holds H0–H8 only | `['H0'…'H8']` | `sorted(HYPOTHESES)` | — |
| The experiment grammar accepts Stage 6 on H6 | `PS-S6-20260926-H6-helios-gate-0001` | `format_experiment_id(stage=6, hypothesis="H6", slug="helios-gate", sequence=1, date="20260926")` | — |
| Edge profile agent RSS / host RAM target | `104857600` B / `2147483648` B | `PROFILES["edge"]`, `HOST_RAM_TARGET_BYTES` | — |
| Stage 2 meaning space | 26 features = `object_semantics` 15 + `state_delta_raised` 9 + `state_delta_scalars` 2, inside a 96-wide `FEATURE_LAYOUT` | `FEATURE_LAYOUT`, `MEANING_GROUPS` | — |
| `DIMENSIONS` order | `privilege, trust, credential, reachability, persistence, execution, modification, discovery, isolation` | `list(DIMENSIONS)` | — |
| **Stage 2's gate already stops Stage 2's poison suite completely** | `build_poison_suite(count=24, seed=11)`, 768 samples: QUARANTINED **18 promotions, 0 escalating, 0 attack-lineage**; ACCEPT_EVERYTHING 768 / 244 / 64; ACCEPT_NOTHING 0 / 0 / 0 | `stage2.gate_criteria.adaptation_run(...)` under the three `AdaptationPolicy` values | `2.16 1.70 2.46` |
| **Stage 2's gate promotes one source's escalation-free repetition once it spans two corroborated epochs** | one escalation-free transition taken from the poison suite's own high-frequency attacker lineage, offered 40× in epoch 0 then 200× in epoch 1 after a corroborated `EpochDecision`: **3 promotions**; outcomes `frequency_alone 40, queued_for_delay 4, serving_delay 193, PROMOTED 3` | `scratchpad/probe_single_source.py`: Stage 2 `QuarantineBuffer` + `PromotionController` with a counting `TrustedQuantizer` | `2.53 1.85 2.49` |
| **Trivial controls saturate Stage 2's drift corpus** | `build_drift_corpus(count=60, seed=11)`, base rate 0.2833: any-escalation rule AP **0.2833**; one hand-written same-actor `CREDENTIAL → EXTERNAL_ENDPOINT` motif AP **1.0000**; max per-lineage cumulative positive ΔΦ AP **1.0000** | `scratchpad/probe_saturation.py`, `average_precision` from `stage0/benchmark/security_metrics.py:92` | `2.79 1.68 2.10` |
| A Stage 6 lab can build a `ResponseRecordV1` through the interface alone | hand-built simulated record `to_dict → from_dict` round trip, digests equal: `True` | direct construction of `ResponseRecordV1` with one `COMMITTED_VERIFIED` receipt row | — |

The last three rows are the design inputs this document is built around. They are the reason
§4.15 builds new poisoning arms instead of re-running Stage 2's, and the reason §4.20 forbids any
anti-forgetting claim on a corpus that fails the saturation preconditions.

**DESIGN — assigned by this document.** Every module path, type, field, signature and bound in
§4 is a name this contract assigns. None of it exists yet. An engineer who finds a better name may
not use it: eight packages build in parallel and the names are the interface.

**UNMEASURED — stated as such, never guessed.** Every detection figure, every retention and
forgetting number, every poisoning rate of the Stage 6 learner, every RSS figure, every shadow or
canary statistic. §9 is the complete list. An unmeasured figure is `None` in data and `UNMEASURED`
in prose. **No timing figure in this document is a device measurement**; only within-run ratios
recorded beside `/proc/loadavg` transfer off this host.

---

## 1. What Stage 6 is for, stated so no engineer mistakes it

Stage 6 is where learning is allowed to change **trusted state**. After Stage 5 it is the most
dangerous stage in the project: an attacker who controls what the endpoint learns controls what it
will ignore next month. **The deliverable is the quarantine → validation → promotion boundary and
the ability to reverse it. The cleverness of the learner is optional.**

Stated as one sentence the gate can check: *there is exactly one function in the repository that
changes the endpoint's trusted cognitive state; every argument it accepts was minted by the
quarantine gateway, the conservation gate, the shadow and the canary, in that order; every change
it makes is reversible to a byte-identical prior state identified by digest; and everything it
holds is bounded.*

### 1.1 What Stage 6 will probably turn out to be worth, and why that is fine

Every completed stage so far has rejected most of its own elaborate machinery on measurement:
Stage 2 its core (ADR-0010), Stage 3 its cell format (ADR-0021), Stage 4 its competing worlds
(ADR-0036), Stage 5 its planner (ADR-0048). The expected Stage 6 outcome, stated in advance so a
failing gate is not mistaken for a failed wave:

- **The boundary will hold and can be settled here.** Single writer, gateway-minted inputs,
  digest-identical rollback, lineage completeness, bounded stores, no authority path. These are
  construction properties testable on synthetic data.
- **Stage 6's own poisoning layer must earn its place over Stage 2's.** §0 measured that Stage 2's
  gate already stops Stage 2's poison suite outright. Whatever Stage 6 adds (source independence,
  semantic homeostasis, the drift discriminator) is justified only by arms Stage 2 fails. Where
  Stage 2 alone already scores zero poisoned promotions, Stage 6 is reported as adding nothing on
  that arm.
- **The anti-forgetting machinery will probably not beat `NEVER_UPDATE + CALIBRATION_ONLY` on a
  synthetic corpus**, because §0 measured that a zero-parameter per-lineage ΔΦ score and a single
  hand-written motif already reach AP 1.0 on the only drift corpus in the repository. If the
  endurance corpus cannot be built to pass the §4.20 preconditions, the anti-forgetting result is
  `DEGENERATE`, and that is the finding.

---

## 2. Repository rules this wave operates under

### 2.1 Layout — integration plan §1.2, amended

Integration plan §1.2 fixes the Stage 6 skeleton. This document amends it in five places, each
recorded in an ADR: **no `research/` package** (ADR-0050); **`shadow/rollback.py` is folded into
`promotion/controller.py`**, because rollback writes trusted state and there is one writer
(ADR-0052); **`promotion/controller.py` is added** as that writer; **`export/learning_record.py` is
added** for HEL-F26; and `core_ids.py`, `resources.py` and `labs/sixty_experiments.py` are added as
every earlier stage added them. Nothing else is added, and no package may create a module not
listed here.

```
pocketsec/stage6/
    __init__.py                     # integrator. EMPTY or a lazy surface (stage5/__init__.py shape)
    core_ids.py                     # HEL-F01 … HEL-F26, REQUIRED/OPTIONAL + ablation slot
    resources.py                    # §39/§40 budgets, WorkMeter, ResourceSnapshot, loadavg, RSS measurement
    gate.py                         # integrator. 13 checks
    cli.py                          # integrator. pocketsec-stage6 {gate,endurance,poison,ablation,resources,export,experiments}
    constitution/learning.py        # D6.1: laws, conservation terms, lifecycle machine, protected anchors
    capsule/experience_capsule.py   # D6.2: ExperienceCapsuleV1, EncodedStep, builders
    capsule/quarantine.py           # D6.2: QuarantineGateway — the ONLY importer of foreign stages (T3)
    provenance/ledger.py            # D6.3: ProvenanceLedger, TrustRecord
    provenance/trust.py             # D6.3: score_provenance, detect_evidence_dependence
    memory/semantic.py              # D6.4: KnowledgeItem, TrustedKnowledgeState, score_session, SemanticMemory
    memory/episodic.py              # D6.4: EpisodeSkeleton, EpisodicMemory, admit_episode
    memory/procedural.py            # D6.4: ProcedureRecord, ProceduralMemory
    memory/half_life.py             # D6.5: epistemic half-life
    memory/competition.py           # D6.7: compete_knowledge
    plasticity/field.py             # D6.6: compute_plasticity_field
    plasticity/masks.py             # D6.6: PlasticityMask, generate_plasticity_mask
    rehearsal/counterfactual.py     # D6.8: generate_counterfactual_replay
    fossils/store.py                # D6.9: KnowledgeFossil, FossilStore
    fossils/lineage.py              # D6.10: KnowledgeLineageDAG
    chamber/evolution.py            # D6.11: EvolutionChamber, induce_motifs
    consolidator/mnemosyne.py       # D6.12: MnemosyneConsolidator
    shadow/mind.py                  # D6.13: ShadowMind
    shadow/canary.py                # D6.17: CanaryPolicy, CanaryEvaluator
    conservation/gate.py            # D6.14: offline_validation, complete_with_shadow
    promotion/controller.py         # D6.17: TrustedMind + LearningPromotionController — THE ONE WRITER
    homeostasis/poisoning.py        # D6.15: suspicion vector, normalisation-attack detector
    homeostasis/drift.py            # D6.16: drift discriminator, KnowledgeContextRegistry, resurrection
    export/quantized_candidates.py  # D6.18
    export/learning_record.py       # HEL-F26: LearningRecordV1, the Stage 7 handoff
    fleet/package.py                # D6.19: KnowledgePackageV1 (import side only; off by default)
    labs/sixty_experiments.py       # D6.20: the S6X-01…60 catalogue
    labs/endurance_corpus.py        # D6.20: the §51 month timeline, built from Stage 2's drift helpers
    labs/poison_suite.py            # D6.15/D6.20: the poisoning arms of §4.15
    labs/continual_baselines.py     # §7: the six stdlib continual-learning baselines
    labs/endurance.py               # D6.20: the harness that runs every learner on identical input
```

Every subsystem `__init__.py` stays **empty**; consumers import the leaf module. **An empty
subsystem package is a defect** (ADR-0121). The five empty directories found on disk (§0) are
handled as ADR-0121 handled Stage 2's: `memory/` is filled by package `memory`; **`helios/`,
`learning/`, `mnemosyne/` and `quarantine/` are deleted by package `foundation`** (they are empty,
are not packages, and name no module in this layout), and `tests/test_stage6_boundary.py` forbids
their return.

### 2.2 Stage 6 ships **no** `research/` package and no numpy — ADR-0050

Integration plan §2.4 permits `stage6/research/`. It cannot exist in this wave: `RESEARCH_PREFIX`
is still the single literal `"pocketsec/stage2/research/"` (§0), ADR-0011 which was to widen it was
never written, and this wave may not edit `tests/test_repository_structure.py`. A numpy import
anywhere under `pocketsec/stage6/` therefore fails
`test_runtime_has_no_third_party_imports`. Consequences, all recorded in ADR-0050:

- Every learner — the Stage 6 learner and all six baselines — is stdlib and symbolic.
- The §47 neural families (EWC/SI regularisation, LwF distillation, adapter isolation, dynamic
  expansion) have **no object to act on**: there are no parameters to regularise, no teacher
  logits to distil, no base network to adapt. They are reported as `UNMEASURED — not applicable to
  a parameter-free learner`, never as passed.
- The chamber's candidate kinds are exactly those with an executor (§4.11). `classifier`,
  `adapter` and `structural` do not appear in any enum (lesson 3: never define a catalog richer
  than its consumer).
- ONNX export and ONNX Runtime quantisation are UNMEASURED. D6.18 quantises the float-bearing parts
  of the symbolic state with stdlib `array` and measures what that costs (§4.18).

### 2.3 Hard mechanical constraints

- Python ≥ 3.11, `from __future__ import annotations`, strict typing on every public API,
  `@dataclass(frozen=True, slots=True)` for every value type, explicit `__all__`, a module
  docstring that says what the module is **for**. Read `stage2/adaptation/quarantine.py` and
  `stage5/stage6_interface.py` before writing: they are the house style.
- Files under ~800 lines, functions under ~50. `print()` only in `cli.py`.
- **Every store is bounded, every truncation explicit, every eviction counted and recorded.** A
  store without a `memory_bytes()` method and a named cap constant is a defect.
- **Time is sequence, not wall clock.** Every age, window, delay and expiry is counted in offered
  capsules (`sequence`), the Stage 2 precedent (`promotion.py`'s `PROMOTION_DELAY_SEQUENCES`). The
  endpoint's clock is not the attacker's constraint; its event stream is.
- **Cost is work units, not microseconds** (ADR-0033 precedent). Every learning, scoring and
  consolidation path charges a `WorkMeter` (§4.1). Wall clock is recorded beside `/proc/loadavg`
  as an observation and never asserted.
- **The T5 trap — read this before naming a field.** No dataclass field under `pocketsec/stage6/`
  may contain, lowercased, any member of `FORBIDDEN_AUTHORITY_FIELDS`
  (`action, remediation, execute, command, shell, kill, quarantine, block, authorize,
  authorization, privilege, sudo`). It bites on words nobody reads as authority:
  **`fraction`, `transaction`, `interaction`, `compaction`, `extraction` all contain `action`**;
  `blocked`, `executed`, `quarantined_at`, `privileged` are all refused. There is **no exemption
  list** (the Stage 4 rule, `stage4/worlds/world.py:158`). This document already renamed every
  collision: the architecture's `ExperienceCapsule.action_outcome` is **`response_outcome`**;
  every "fraction" is a **`share`** or a **`rate`**. Enum *members* (unannotated class-body
  assignments such as `LifecycleState.QUARANTINED`) are not fields and are not screened.

### 2.4 Reuse, not duplication: Stage 6 generalises Stage 2's gate by composition — ADR-0051

Stage 2 built the only two learned-side components that survived measurement:
`QuarantineBuffer` (`stage2/adaptation/quarantine.py:360`) and `PromotionController`
(`stage2/adaptation/promotion.py:197`). **Stage 6 builds on them by composition and never copies
their logic.** The binding decisions:

1. **`capsule/quarantine.py` owns exactly one `QuarantineBuffer` and exactly one
   `PromotionController`.** Every normality-direction step (a step offered as "this is how the
   host normally behaves") becomes an `AdaptationSample` and passes through
   `QuarantineBuffer.quarantine_adaptation_sample` — the risk rule, the fixed-anchor consistency
   rule and the epoch rule are Stage 2's and are **not reimplemented**. The escalation rule is
   absolute and stays absolute.
2. **Stage 2's `PromotionController.promote` is the QUARANTINED → CANDIDATE transition for
   normality learning.** Its `quantizer` argument is Stage 6's `_CandidateRegister`, an adapter
   that satisfies the `TrustedQuantizer` protocol (`promotion.py:96`) by recording a pending
   BASELINE admission in the gateway's bounded candidate register. **Stage 2's "write" therefore
   lands in Stage 6's candidate register, not in trusted memory.** Its frequency refusal, evidence
   refusal, delay and expiry are inherited unchanged; a refusal's reason string is Stage 2's
   (`REFUSE_FREQUENCY_ALONE`, `REFUSE_EVIDENCE`, …).
3. **Stage 6 adds only what Stage 2 structurally cannot see.** §0 measured the gap:
   `AdaptationSample` carries no source, so Stage 2 promotes one attacker's escalation-free
   repetition once it spans two corroborated epochs (3 promotions in the probe). Stage 6's
   **source-independence check** (ADR-0054) runs *before* `PromotionController.promote` is called
   and refuses a pattern observed from fewer than `MIN_INDEPENDENT_GROUPS` independence groups.
   The remaining gates — conservation, shadow, canary — act on candidates, which Stage 2 has no
   notion of. They are in series with Stage 2's gate, never parallel to it.
4. **Threat learning (new detectors) does not pass through Stage 2's controller**, because that
   controller refuses retained evidence by design ("evidence is an input to investigation, never
   to normality", `promotion.py` docstring) and a detector is learned *from* evidence. Threat
   capsules go gateway → chamber → conservation → shadow → canary → controller; they still enter
   through `QuarantineGateway.admit` and nowhere else.
5. **There is exactly one trusted writer**: `LearningPromotionController` in
   `promotion/controller.py` (§4.17). A second function that writes trusted state, or a second
   epoch/frequency/delay gate, is a defect and a gate failure (G6.1).

### 2.5 Upstream imports — an allow-list — ADR-0053

| upstream | Stage 6 may import | never |
|---|---|---|
| Stage 0 | anything under `pocketsec.stage0` | — |
| Stage 1 | anything under `pocketsec.stage1` | — |
| Stage 2 | `encoder.ssir_encoder`, `adaptation.quarantine`, `adaptation.promotion`, `adaptation.epoch_guard`; **and only from `stage6/labs/`**: `labs.drift_corpus`, `labs.poison_suite` | `research.*`, `gate*`, everything else |
| Stage 3 | **nothing** — `KnowledgeCellV1` is not consumed (below) | everything |
| Stage 4 | `stage5_interface` (`CBFResolutionV1`) only | everything else |
| Stage 5 | `stage6_interface` (`ResponseRecordV1`, `VERIFIED_OUTCOME`, `seam_violations`, `authority_violations`) only | everything else |
| Stages 7–12 | only `capsule/quarantine.py` may ever import them (T3); today nothing does | — |

**`KnowledgeCellV1` is not consumed.** Integration plan §3.2 lists it. Stage 6 has no executor for
cell bytecode, Stage 3's own GC and melting already govern cells, and ADR-0021 measured that the
cell format loses to the rule it wraps. A capsule kind for cell outcomes with no consumer would be
the lesson-3 defect. Recorded in ADR-0053.

### 2.6 Another wave is building in this tree

- **Never** edit, revert or delete anything under `pocketsec/stage<other>/`,
  `tests/test_stage<other>_*.py` or `docs/stage-<other>-*.md`. Never run `git checkout`,
  `git stash`, `git restore`, `git clean` or `git commit`.
- **Never** edit `tests/test_repository_structure.py`. Stage 6's boundary rules live in
  `tests/test_stage6_boundary.py` (§5.1), which *imports* the shared resolver
  `pocketsec.stage2.gate_criteria.imported_modules` (`gate_criteria.py:547`) and never copies it.
- Stage 5 is being finished right now. Code against `pocketsec/stage5/stage6_interface.py` **as it
  stands** (§3.2 quotes it). If it proves inadequate, report a blocker; do not edit Stage 5.
- When the full suite runs, failures in another stage's test files are that wave's
  work-in-progress. Report them and move on. Judge Stage 6 by `tests/test_stage6_*.py` plus
  `pocketsec-stage6 gate`.
- `pyproject.toml` is shared: the integrator appends exactly
  `pocketsec-stage6 = "pocketsec.stage6.cli:main"` and one CI step. Nothing else.

### 2.7 The gate never mutates the real experiment ledger

`Stage6GateContext.build()` records ablation rows in a **temporary** registry. G6.13 asserts
`experiments/registry.jsonl` is byte-identical before and after the gate run. Rows that belong in
the ledger are written only by `pocketsec-stage6 experiments`, an explicit subcommand (Stage 4/5
precedent).

### 2.8 Hypothesis binding — no H12 is minted — ADR-0055

Integration plan §5.2 pre-assigns H12 via ADR-0012, which was never written; `HYPOTHESES` holds
H0–H8 (§0) and `tests/test_harness_and_gate.py:241` couples it to the prior-art ledger. Stage 6
binds to the existing **H6 — "Hierarchical reversible forgetting: bound memory while retaining
recognisable behaviour"**, which is literally the anti-forgetting and bounded-memory claim, and to
**H8** for ablation rows ("combine only components independently justified by ablation").

```python
# pocketsec/stage6/gate.py
STAGE6_HYPOTHESIS = "H6"
EXPERIMENT_ID = "PS-S6-20260926-H6-helios-gate-0001"
```

### 2.9 Timing on a contended host

Another wave's runs inflate wall clock on this host (7× measured by Stage 2). Every timing figure
Stage 6 reports is recorded with `/proc/loadavg`, and every comparison of two paths is a
**within-run ratio** of two passes in the same process. Work units are the primary cost measure and
are deterministic.

---

## 3. The data seam

### 3.0 The verification script

Run this before writing code; it produced the first MEASURED row of §0. It lives in the
scratchpad, not the repository.

```bash
cd /home/anil/Documents/Research/pocketsec
PYTHONPATH=. python3 - <<'PY'
import inspect, os
ROOT = os.getcwd() + "/"
TARGETS = [
  ("pocketsec.stage0.contracts.common", ["EvidenceRef","ContractError","register_schema","digest_of_bytes",
     "require_identifier","require_finite_unit_interval","SCHEMA_REGISTRY"]),
  ("pocketsec.stage0.contracts.threat_prediction_v1", ["Verdict","NON_COMMITTAL_VERDICTS","FORBIDDEN_AUTHORITY_FIELDS"]),
  ("pocketsec.stage0.gate", ["GateCheck","GateReport","REPO_ROOT"]),
  ("pocketsec.stage0.benchmark.resource_metrics", ["ResourceSampler","ResourceMetrics","read_rss_bytes"]),
  ("pocketsec.stage0.benchmark.profiles", ["check_profile","ProfileReport","PROFILES","HOST_RAM_TARGET_BYTES"]),
  ("pocketsec.stage0.benchmark.security_metrics", ["evaluate_scores","average_precision","recall_at_max_fpr",
     "confusion_at_threshold","SecurityMetrics"]),
  ("pocketsec.stage0.experiments.registry", ["ExperimentRegistry"]),
  ("pocketsec.stage0.experiments.ids", ["format_experiment_id","parse_experiment_id"]),
  ("pocketsec.stage0.hypotheses", ["HYPOTHESES"]), ("pocketsec.stage0.prior_art", ["PriorArtLedger"]),
  ("pocketsec.stage0.repro.seeds", ["SeedSet"]),
  ("pocketsec.stage1.pipeline", ["Stage1Pipeline","ScenarioResult"]),
  ("pocketsec.stage1.labs.corpus", ["Behaviour","Scenario"]),
  ("pocketsec.stage1.ssir.transition", ["SSIRTransitionV1"]),
  ("pocketsec.stage1.ssir.entities", ["SemanticProperty"]),
  ("pocketsec.stage1.state.security_state", ["SecurityStateV1","StateDelta","DIMENSIONS"]),
  ("pocketsec.stage1.state.potential", ["phi","delta_phi"]),
  ("pocketsec.stage1.epoch.model", ["Epoch","EpochDecision","EpochModel","SystemIdentity","EpochTransitionReason"]),
  ("pocketsec.stage2.encoder.ssir_encoder", ["EncodedTransition","encode_ssir_transition","FEATURE_LAYOUT",
     "FEATURE_WIDTH","GROUP_OFFSETS","feature_names"]),
  ("pocketsec.stage2.adaptation.quarantine", ["QuarantineBuffer","AdaptationSample","QuarantineVerdict",
     "QuarantineOutcome","ESCALATION_PROPERTIES","ESCALATION_MASK","MEANING_GROUPS","meaning_vector",
     "meaning_distance","pattern_key","BASELINE_EPOCH_ID","MAX_QUARANTINE","DEFAULT_CONSISTENCY_RADIUS"]),
  ("pocketsec.stage2.adaptation.promotion", ["PromotionController","PromotionRecord","TrustedQuantizer",
     "REFUSE_FREQUENCY_ALONE","REFUSE_EVIDENCE","PROMOTION_DELAY_SEQUENCES","MAX_DELAYED_PROMOTIONS"]),
  ("pocketsec.stage2.adaptation.epoch_guard", ["SystemChangeSignal","AdaptationPolicy"]),
  ("pocketsec.stage2.labs.drift_corpus", ["build_drift_corpus","make_actors","interleave","session_behaviour",
     "SessionActor","malicious_lineage","DRIFT_TECHNIQUE_CORROBORATED_CHANGE",
     "DRIFT_TECHNIQUE_UNCORROBORATED_CHANGE","BOOT_ID"]),
  ("pocketsec.stage2.labs.poison_suite", ["build_poison_suite","poison_lineage","adaptation_lineage",
     "POISON_ARMS","POISON_TECHNIQUE_HIGH_FREQUENCY","POISON_TECHNIQUE_SLOW_DRIFT",
     "POISON_TECHNIQUE_NEAR_MISS","POISON_VERSION"]),
  ("pocketsec.stage2.gate_criteria", ["imported_modules"]),
  ("pocketsec.stage4.stage5_interface", ["CBFResolutionV1","CBF_RESOLUTION_V1_ID"]),
  ("pocketsec.stage5.stage6_interface", ["ResponseRecordV1","RESPONSE_RECORD_V1_ID","VERIFIED_OUTCOME",
     "seam_violations","authority_violations","SEAM_AUTHORITY_EXEMPTIONS"]),
]
missing = []
for mod_name, names in TARGETS:
    mod = __import__(mod_name, fromlist=["*"])
    for name in names:
        obj = getattr(mod, name, None)
        if obj is None:
            missing.append(f"{mod_name}.{name}"); print("MISSING", mod_name, name); continue
        try: where = f"{inspect.getsourcefile(obj).replace(ROOT,'')}:{inspect.getsourcelines(obj)[1]}"
        except Exception: where = f"{mod.__file__.replace(ROOT,'')}:<constant>"
        print("OK", f"{mod_name}.{name}", "->", where)
print("MISSING COUNT:", len(missing))
PY
cat /proc/loadavg
```

Measured output this session: **101 OK, 0 missing**. (`inspect` reports the decorator line for a
decorated class, which is why several lines below are one less than the `class` keyword.)

### 3.1 Consumed from Stages 0–5 — every type below exists, cited `path:line`

| type / symbol | path:line | how Stage 6 uses it |
|---|---|---|
| `EvidenceRef` (`store`, `locator`, `digest`) | `stage0/contracts/common.py:124` | capsule evidence is the `digest` (`sha256:<64 hex>`), never content |
| `ContractError`, `register_schema`, `digest_of_bytes`, `require_identifier`, `require_finite_unit_interval` | `common.py:32`, `:49`, `:116`, `:72`, `:84` | validation, schema registration, content addressing |
| `Verdict`, `NON_COMMITTAL_VERDICTS`, `FORBIDDEN_AUTHORITY_FIELDS` | `stage0/contracts/threat_prediction_v1.py:66`, constants | labels and resolution states; the T5 screen |
| `GateCheck`, `GateReport`, `REPO_ROOT` | `stage0/gate.py:44`, `:55` | the gate |
| `ResourceSampler`, `ResourceMetrics`, `read_rss_bytes` | `stage0/benchmark/resource_metrics.py:103`, `:57`, `:38` | G6.10; the only RSS source |
| `check_profile`, `ProfileReport`, `PROFILES`, `HOST_RAM_TARGET_BYTES` | `stage0/benchmark/profiles.py:85`, `:61` | G6.10; `within_target is None` is UNMEASURED |
| `evaluate_scores`, `average_precision`, `recall_at_max_fpr`, `confusion_at_threshold` | `stage0/benchmark/security_metrics.py:211`, `:92`, `:122`, `:73` | every recall/AP/FP figure; no second metric implementation |
| `ExperimentRegistry`, `format_experiment_id` | `stage0/experiments/registry.py:106`, `ids.py:56` | registration via the CLI only |
| `HYPOTHESES`, `PriorArtLedger`, `SeedSet` | `stage0/hypotheses.py`, `prior_art.py:71`, `repro/seeds.py:23` | G6.13 novelty discipline; seeds |
| `Stage1Pipeline`, `ScenarioResult` | `stage1/pipeline.py:77`, `:46` | the endurance harness compiles every scenario once |
| `Behaviour`, `Scenario` | `stage1/labs/corpus.py:33`, `:44` | the only scenario types; no fifth one |
| `SSIRTransitionV1` | `stage1/ssir/transition.py:81` | source of `EncodedStep` |
| `SemanticProperty`, `DIMENSIONS`, `SecurityStateV1`, `StateDelta` | `stage1/ssir/entities.py:64`, `security_state.py`, `:121`, `:180` | protected anchors; `SecurityStateV1()` placeholder (§4.2) |
| `Epoch`, `EpochDecision`, `EpochModel`, `SystemIdentity`, `EpochTransitionReason` | `stage1/epoch/model.py:104`, `:80`, `:136`, `:54`, `:47` | "epoch" binds to Stage 1's `Epoch`; knowledge contexts key on `SystemIdentity.key()` |
| `EncodedTransition`, `encode_ssir_transition`, `FEATURE_LAYOUT`, `FEATURE_WIDTH`, `GROUP_OFFSETS`, `feature_names` | `stage2/encoder/ssir_encoder.py:142`, `:195`, constants, `:122` | the representation every learner shares |
| `QuarantineBuffer`, `AdaptationSample`, `QuarantineVerdict` (Stage 2's), `QuarantineOutcome`, `ESCALATION_PROPERTIES`, `ESCALATION_MASK`, `MEANING_GROUPS`, `meaning_vector`, `meaning_distance`, `pattern_key`, `DEFAULT_CONSISTENCY_RADIUS` | `stage2/adaptation/quarantine.py:360`, `:218`, `:279`, `:209`, `:184`, `:193`, `:198`, constants | composed by the gateway (ADR-0051) |
| `PromotionController`, `PromotionRecord`, `TrustedQuantizer`, `REFUSE_*`, `PROMOTION_DELAY_SEQUENCES` | `stage2/adaptation/promotion.py:197`, `:125`, `:96`, constants | composed by the gateway (ADR-0051) |
| `SystemChangeSignal` | `stage2/adaptation/epoch_guard.py:203` | the endurance harness's out-of-band change reports |
| `build_drift_corpus`, `make_actors`, `interleave`, `session_behaviour`, `SessionActor`, `malicious_lineage`, `BOOT_ID` | `stage2/labs/drift_corpus.py:379`, `:122`, `:320`, `:148`, `:107`, `:305` | labs only: the endurance corpus is built from these, not a second builder |
| `build_poison_suite`, `poison_lineage`, `POISON_ARMS` | `stage2/labs/poison_suite.py:264`, `:225` | labs only: the Stage-2-equivalent arms |
| `imported_modules` | `stage2/gate_criteria.py:547` | tests only: the one import resolver |
| `CBFResolutionV1` | `stage4/stage5_interface.py:399` | WORLD_RESOLUTION capsules |
| `ResponseRecordV1`, `VERIFIED_OUTCOME`, `seam_violations`, `authority_violations` | `stage5/stage6_interface.py:275`, constant, `:136`, `:157` | RESPONSE_OUTCOME capsules; Stage 6's own exports reuse both screens |

### 3.2 The upstream contracts, quoted

**Stage 2 quarantine** (`quarantine.py`): three outcomes and no fourth from
`quarantine_adaptation_sample` — `RETAINED_AS_EVIDENCE` (risk: object carries
credential/authorisation/persistence/external meaning, or raised a capability, or ΔΦ > 2.0, or
uncertainty > 0.5), `REFUSED` (meaning distance above radius 1.0 from the **fixed** anchor, or the
buffer is full — it refuses newcomers rather than evicting waiting patterns), `HELD` (eligible only
with ≥ 8 observations across ≥ 2 corroborated epochs). "Nothing is promoted here." Anchors are
released only by `record_epoch_decision` with `corroborated and changed_components`. **Residual risk
the docstring states:** the first escalation-free sample after a corroborated change defines the
new anchor. Stage 6 attacks exactly this (arm P2b, §4.15).

**Stage 2 promotion** (`promotion.py`): refuses evidence, refuses anything the buffer refused,
refuses fewer than 2 epochs (`REFUSE_FREQUENCY_ALONE`) re-checked independently of the verdict,
queues the first eligible sample for `PROMOTION_DELAY_SEQUENCES = 64` and writes only if the
behaviour recurs after the delay; the queue holds ≤ 64 and drops are counted.

**Stage 5 handoff** (`stage6_interface.py`): `ResponseRecordV1` is plain JSON with a canonical
`sha256:` digest. Four refusals at export time: no Stage 5 class name as a key (18 tokens), no
authority-named key except exactly four (`operator_id`, `operator_class`, `authority`,
`rollback_operator_id`), no `COMMITTED_VERIFIED` row with an unverifiable postcondition, and
`simulated` required on the record and on every receipt row. Receipt rows carry `tx_id`,
`operator_id`, `outcome`, `postconditions`, `rollback_attempted`, `rollback_succeeded`,
`host_kind`, `simulated`, `epoch_id`. **Every Stage 5 record today is `simulated=True`**
(ADR-0046); Stage 6 carries that flag onto every procedure it learns.

**Stage 4 handoff** (`stage5_interface.py:399`): `CBFResolutionV1` carries `resolution_id`,
`incident_id`, `epoch_id`, `verdict: Verdict`, `identifiability: str`, `hypotheses` (plain rows),
`evidence_lineage` (plain rows), `uncertainty`, and refuses authority-named fields at construction.

**Stage 1 epochs** (`epoch/model.py`): `EpochModel.evaluate` opens an epoch only when a changed
identity component is also in `corroborating_evidence`; `behavioural_novelty` is accepted and never
read. A return to an earlier identity opens a **new** `epoch_id` whose `SystemIdentity.key()`
equals the old one — which is what makes resurrection (§4.16) keyable.

### 3.3 Exposed to Stage 7 — the names this contract assigns

Integration plan §3.2 names them; every one exists at the module below after this wave.

| type | module | Stage 7 uses it for |
|---|---|---|
| `ExperienceCapsuleV1` (schema `pocketsec.experience_capsule.v1` @ `1.0.0`) | `capsule/experience_capsule.py` | the **only** form in which foreign knowledge reaches this host |
| `QuarantineGateway.admit(capsule) -> QuarantineVerdict` (integration plan §3.2's signature, unchanged) | `capsule/quarantine.py` | the single admission function for Stages 7, 8, 9 and 12 |
| `QuarantineVerdict`, `QuarantineBucket` | `capsule/quarantine.py` | ingress outcome; `IngressVerdict` success = a capsule handed to `admit` |
| `ProvenanceLedger`, `TrustRecord` | `provenance/ledger.py` | provenance of admitted knowledge |
| `EpisodicMemory`, `SemanticMemory`, `ProceduralMemory` | `memory/{episodic,semantic,procedural}.py` | read-only views |
| `EpistemicHalfLife` | `memory/half_life.py` | knowledge aging |
| `PlasticityField`, `PlasticityMask` | `plasticity/{field,masks}.py` | — |
| `KnowledgeFossil`, `KnowledgeLineageDAG` | `fossils/{store,lineage}.py` | Stage 11 inherits these as-is |
| `EvolutionChamber`, `Consolidation`, `ShadowMind`, `ConservationVerdict`, `CanaryReport`, `LearningRollback` | as §2.1 | — |
| `QuantizedCandidate` | `export/quantized_candidates.py` | — |
| `LearningRecordV1` (schema `pocketsec.learning_record.v1` @ `1.0.0`) | `export/learning_record.py` | the plain-JSON projection of trusted state Stage 7 distils from |
| `KnowledgePackageV1` | `fleet/package.py` | optional, off by default |

**Binding inherited by Stage 7 (architecture §56):** external knowledge is always a candidate,
never authority. Nothing Stage 7 produces may call anything in `promotion/controller.py`.

---

## 4. Deliverables

Each deliverable names its module, its public types (fields and types), its functions (signatures)
and its bounds. `[package]` names the owning work package (§5). Every constant cited is in the
§4.21 table.

### 4.0 The model everything else hangs on — read first

**Trusted cognition** is one immutable value, `TrustedKnowledgeState` (§4.4), holding:
`DETECTOR` items (motifs over encoded steps), `BASELINE` items (Stage 2 meaning anchors per pattern
key and knowledge context), `PROCEDURE` items (verified response records from Stage 5) and one
`THRESHOLD` item, plus the **protected rehearsal set** — the episodes the conservation gate replays.
It has a canonical byte form and a `sha256:` digest. The endpoint's current trusted state is held by
exactly one `TrustedMind`, owned by exactly one `LearningPromotionController`, whose private
`_install_trusted` is the only code that changes it (§4.17).

**The score** (`score_session`, §4.4) is what "detection capability" means in this stage — the thing
retention is measured on and the thing poisoning tries to move:

```
D = max(weight of every applicable DETECTOR whose motif matches the session), else 0.0
U = UNEXPLAINED_WEIGHT × max over actors a of (unexplained_a / nonescalating_a)
      a step is non-escalating iff touches_protected(step) == () and step.state_delta_mask == 0
      it is unexplained iff no applicable BASELINE b has b.pattern_key == pattern_key(step)
        and meaning_distance(step meaning, b.anchor) <= b.weight   (weight = radius for BASELINE)
      an actor with no non-escalating step contributes 0
score = max(D, U);   alert iff score >= THRESHOLD.weight
```

`U` is bounded at `UNEXPLAINED_WEIGHT = 0.5`: unexplained behaviour is anomaly evidence, never a
verdict. **Novelty is not maliciousness** — nothing in Stage 6 emits a `ThreatPredictionV1`, and the
score has no path to Stage 5. `U` exists so that normality learning has a consumer (lesson 3): a
BASELINE item changes an outcome only by explaining a step, and slow poisoning's harm is exactly
that it explains the attacker's own staging steps.

**Why motifs and not float prototypes.** A detector must express "this actor read a credential and
later sent to an external endpoint" — a conjunction over one lineage — or the §0 probe shows the
task cannot be expressed per step. A motif is 1–2 ordered `MotifStep`s within one `actor_slot`,
each a `(relation, require_properties, forbid_properties, require_raised)` bitmask test against the
encoder's own masks. **Lesson 2 is enforced as a precondition (E1, §4.20):** an oracle detector set
built from ground-truth motifs must reach recall ≥ 0.9 at the FPR budget on every endurance family,
or the representation cannot express the task and the anti-forgetting result is BLOCKED. Known
inexpressible, stated in advance: counts ("N repetitions"), timing, and chains longer than 2 steps.

**Units.** `sequence` = offered-capsule counter. Cost = `WorkMeter` units (1 per item×step
comparison, 1 per motif-candidate evaluation per episode). Bytes = each store's `memory_bytes()`.

### D6.1 — Learning Constitution `[foundation]`

```python
# pocketsec/stage6/constitution/learning.py
class LearningLaw(StrEnum):                       # architecture §2, verbatim meaning
    RAW_TELEMETRY_IS_NOT_TRAINING_DATA = "RAW_TELEMETRY_IS_NOT_TRAINING_DATA"
    REPETITION_IS_NOT_TRUTH = "REPETITION_IS_NOT_TRUTH"
    MODEL_SCORE_IS_NOT_KNOWLEDGE = "MODEL_SCORE_IS_NOT_KNOWLEDGE"
    NOVELTY_IS_NOT_PERMISSION_TO_ADAPT = "NOVELTY_IS_NOT_PERMISSION_TO_ADAPT"
    SUCCESS_IS_NOT_PERMISSION_TO_FORGET = "SUCCESS_IS_NOT_PERMISSION_TO_FORGET"

@dataclass(frozen=True, slots=True)
class LawBinding:
    law: LearningLaw
    enforced_by: str        # "pocketsec.stage6.capsule.quarantine:QuarantineGateway.admit" — resolvable
    tested_by: str          # "tests/test_stage6_gateway.py::test_..." — the test whose name says it
    statement: str

class ConservationTerm(StrEnum):                   # architecture §3, bound to a ConservationCheck
    NEW_UTILITY = "NEW_UTILITY"                    # -> G3_CURRENT_HOLDOUT
    HISTORICAL_SECURITY_LOSS = "HISTORICAL_SECURITY_LOSS"  # -> G2_HISTORICAL_REPLAY
    SAFETY_INVARIANT_LOSS = "SAFETY_INVARIANT_LOSS"        # -> G5_ADVERSARIAL (+ homeostasis)
    POISON_RISK = "POISON_RISK"                    # -> gateway suspicion + G5
    RESOURCE_GROWTH = "RESOURCE_GROWTH"            # -> G7_RESOURCE
    ROLLBACK_STATE_EXISTS = "ROLLBACK_STATE_EXISTS"        # -> G9_ROLLBACK

class LifecycleState(StrEnum):                     # architecture §42, exactly
    QUARANTINED, CANDIDATE, OFFLINE_VALIDATED, SHADOW, CANARY, TRUSTED,
    DORMANT, FOSSILIZED, RETIRED, REJECTED, ROLLED_BACK   # each = its own name

ALLOWED_TRANSITIONS: Mapping[LifecycleState, frozenset[LifecycleState]]
# QUARANTINED->{CANDIDATE,REJECTED}; CANDIDATE->{OFFLINE_VALIDATED,REJECTED};
# OFFLINE_VALIDATED->{SHADOW,REJECTED}; SHADOW->{CANARY,REJECTED}; CANARY->{TRUSTED,REJECTED};
# TRUSTED->{DORMANT,FOSSILIZED,RETIRED,ROLLED_BACK}; DORMANT->{TRUSTED,FOSSILIZED,RETIRED,ROLLED_BACK};
# FOSSILIZED->{RETIRED}; RETIRED, REJECTED, ROLLED_BACK -> {} (terminal)
def require_transition(current: LifecycleState, target: LifecycleState) -> None   # ContractError if absent

class Timescale(StrEnum): WORKING, HOST_BASELINE, EPISODIC, SEMANTIC, STRUCTURAL, ARCHAEOLOGY
TIMESCALES: Mapping[Timescale, str]   # timescale -> the ONE update-rule symbol path (§4, table)
# WORKING -> "stage1 (volatile, not Stage 6)"; HOST_BASELINE -> capsule.quarantine:QuarantineGateway.admit;
# EPISODIC -> memory.episodic:EpisodicMemory.admit_episode; SEMANTIC -> promotion.controller:LearningPromotionController.promote_trusted;
# STRUCTURAL -> "UNMEASURED: no structural candidate kind exists (ADR-0056)";
# ARCHAEOLOGY -> consolidator.mnemosyne:MnemosyneConsolidator.consolidate_memory

@dataclass(frozen=True, slots=True)
class ProtectedAnchor:
    anchor_id: str
    properties: frozenset[SemanticProperty]
    dimensions: frozenset[str]          # members of DIMENSIONS
    structural: bool                    # True: enforced by construction, not by masks
    rationale: str

PROTECTED_ANCHORS: tuple[ProtectedAnchor, ...]      # architecture §21, bound:
#  privilege_boundary      dims {privilege}
#  credential_material     props {CREDENTIAL, CREDENTIAL_READER}    dims {credential}
#  authorization_material  props {AUTHORIZATION_DATA}
#  executable_trust        dims {execution, trust}
#  persistence             props {PERSISTENCE, PERSISTENCE_WRITER}  dims {persistence}
#  external_egress         props {EXTERNAL_ENDPOINT}                dims {reachability}
#  evidence_integrity      structural (G1: no candidate alters a rehearsal exemplar's evidence or lineage)
#  response_authority      structural (T5 + no Stage 5 import but stage6_interface)
# Module-level assert: set(ESCALATION_PROPERTIES) <= union of anchor.properties — Stage 6
# generalises Stage 2's escalation rule and may never be narrower than it.

def property_mask(properties: Iterable[SemanticProperty]) -> int   # bit order derived from
    # feature_names() "object.<P>" labels, exactly as quarantine._mask_from_properties does
def raised_mask(dimensions: Iterable[str]) -> int                  # from "raised.<dim>" labels
def touches_protected(object_property_mask: int, state_delta_mask: int) -> tuple[str, ...]
    # anchor ids hit, sorted; () = touches none. Structural anchors never match here.

MIN_INDEPENDENT_GROUPS: int = 3          # normality: distinct independence groups per pattern
MIN_INDEPENDENT_LABEL_GROUPS: int = 2    # threat: distinct groups asserting MALICIOUS
LEARNING_CONSTITUTION: tuple[LawBinding, ...]   # five, one per law
def verify_constitution() -> tuple[str, ...]    # importlib-resolves every enforced_by; () = all resolve
```

Bounds: pure data; no state. Failure mode: `verify_constitution()` returning anything non-empty is a
G6.1 failure — a law bound to a symbol that does not exist is a docstring.

### D6.2 — ExperienceCapsule + Quarantine Gateway `[capsule]` (types) and `[gateway]` (gateway)

```python
# pocketsec/stage6/capsule/experience_capsule.py
EXPERIENCE_CAPSULE_V1_ID = "pocketsec.experience_capsule.v1"
EXPERIENCE_CAPSULE_V1_VERSION = register_schema(EXPERIENCE_CAPSULE_V1_ID, "1.0.0")

class CapsuleKind(StrEnum): TRANSITION_EPISODE, WORLD_RESOLUTION, RESPONSE_OUTCOME, LABEL_ASSERTION, FOREIGN_PACKAGE
class SourceClass(StrEnum): KERNEL_SENSOR, DERIVED_INFERENCE, ANALYST, EXTERNAL_DATASET, LAB_GROUND_TRUTH, TEACHER, FOREIGN_HOST
class LabelOrigin(StrEnum): NONE, GROUND_TRUTH, ANALYST, INFERENCE, WEAK, TEACHER
class PrivacyClass(StrEnum): PUBLIC_DERIVED, HOST_SENSITIVE, SECRET_BEARING
class ContaminationFlag(StrEnum): ATTACKER_CONTROLLED_SOURCE, OBSERVATION_INCOMPLETE, SENSOR_DISAGREEMENT,
    UNCORROBORATED_EPOCH, SIMULATED_RECORD, FOREIGN_ORIGIN, DUPLICATE_EVIDENCE, TRUNCATED

@dataclass(frozen=True, slots=True)
class EncodedStep:                     # one Stage 2 EncodedTransition, losslessly re-constructible
    features: tuple[float, ...]        # len == FEATURE_WIDTH (96); rounded to FEATURE_DECIMALS
    relation: int
    relation_family: int
    state_delta_mask: int
    time_bucket: int
    delta_phi: float
    object_property_mask: int
    epoch_id: int
    actor_slot: int                    # order of first appearance within the capsule
    uncertainty: float
    source_group: str                  # "grp-" + sha256(actor lineage identity)[:16] — accounting, never a feature
    causal_signature: str
    parent_signature: str
    evidence: tuple[str, ...]          # sha256 digests, <= MAX_EVIDENCE_PER_STEP
    def to_encoded(self) -> EncodedTransition
    def meaning(self) -> tuple[float, ...]            # == stage2 meaning_vector(self.to_encoded())
    @classmethod
    def from_transition(cls, transition: SSIRTransitionV1, *, actor_slot: int) -> EncodedStep

@dataclass(frozen=True, slots=True)
class SourceProvenance:
    source_class: SourceClass
    source_id: str
    independence_group: str            # capsules sharing it count as ONE vote
    label_origin: LabelOrigin
    transformation_lineage: tuple[str, ...]   # e.g. ("stage1.pipeline", "stage2.encoder:<layout digest>")
    host_id: str

@dataclass(frozen=True, slots=True)
class LabelAssertion:
    verdict: Verdict
    origin: LabelOrigin
    asserted_by: str                   # its independence group ("analyst:<id>", "teacher:<id>", "lab")
    target_capsule_id: str

@dataclass(frozen=True, slots=True)
class ExperienceCapsuleV1:             # architecture §5, every field bound
    capsule_id: str                    # "cap-" + digest prefix of the canonical payload without this field
    kind: CapsuleKind
    epoch_id: int
    context_id: str                    # "ctx-" + SystemIdentity.key() (see memory/semantic.context_id_for)
    evidence_refs: tuple[str, ...]     # sha256 digests; non-empty except LABEL_ASSERTION; <= MAX_EVIDENCE_REFS_PER_CAPSULE
    source_provenance: SourceProvenance
    security_worlds: tuple[str, ...]   # CBFResolutionV1 hypothesis ids, () if none
    resolution_state: Verdict          # what Stages 1–4 concluded; UNKNOWN by default
    response_outcome: str | None       # architecture "action_outcome" renamed (T5); a receipt outcome string
    visibility: float                  # [0,1]: 1 - share of steps with observation_incomplete
    confidence_components: tuple[tuple[str, float], ...]   # sorted; ("uncertainty_max", u), ("delta_phi_max", x) …
    contradiction_history: tuple[str, ...]  # capsule ids this contradicts
    privacy_class: PrivacyClass
    contamination_flags: frozenset[ContaminationFlag]
    steps: tuple[EncodedStep, ...]     # TRANSITION_EPISODE only; <= MAX_STEPS_PER_CAPSULE
    label: LabelAssertion | None
    procedure_rows: tuple[Mapping[str, Any], ...]  # RESPONSE_OUTCOME only; seam-safe receipt rows; <= MAX_PROCEDURE_ROWS
    truncated: bool
    created_sequence: int
    schema_version: str = EXPERIENCE_CAPSULE_V1_VERSION
    def canonical_bytes(self) -> bytes     # sorted keys, allow_nan=False, trailing newline
    def digest(self) -> str
    def to_dict(self) -> dict[str, Any];  @classmethod def from_dict(cls, payload) -> ExperienceCapsuleV1

def capsule_from_scenario(result: ScenarioResult, *, epoch: Epoch, provenance: SourceProvenance,
                          sequence: int, label: LabelAssertion | None = None) -> ExperienceCapsuleV1
def capsule_from_resolution(resolution: CBFResolutionV1, *, target_capsule_id: str, epoch: Epoch,
                            provenance: SourceProvenance, sequence: int) -> ExperienceCapsuleV1
def capsule_from_response(record: ResponseRecordV1, *, epoch: Epoch, provenance: SourceProvenance,
                          sequence: int) -> ExperienceCapsuleV1
def capsule_from_label(label: LabelAssertion, *, epoch: Epoch, provenance: SourceProvenance,
                       sequence: int) -> ExperienceCapsuleV1
def build_experience_capsule(source: ScenarioResult | CBFResolutionV1 | ResponseRecordV1 | LabelAssertion, *,
                             epoch: Epoch, provenance: SourceProvenance, sequence: int,
                             label: LabelAssertion | None = None,
                             target_capsule_id: str = "") -> ExperienceCapsuleV1      # HEL-F01, dispatch only
def privacy_audit(capsules: Iterable[ExperienceCapsuleV1]) -> PrivacyAuditReport     # S6X-57
@dataclass(frozen=True, slots=True)
class PrivacyAuditReport: capsules: int; free_text_values: int; secret_pattern_hits: int; offenders: tuple[str, ...]
```

Rules the capsule module enforces (each has a test named for it):

- **`capsule_from_scenario` never reads `scenario.label`.** Ground truth reaches a capsule only as an
  explicit `LabelAssertion`. Test: two `ScenarioResult`s identical except `scenario.label` produce
  byte-identical capsules.
- Evidence is digests only; no path, command line, user name or raw field value is stored. The
  encoder already excludes `display_name` (ADR-0007); `source_group` is a hash.
- `RESPONSE_OUTCOME` capsules keep only rows that pass `seam_violations(...) == ()` and
  `authority_violations(...) == ()` (Stage 5's own screens, reused). A `simulated=True` record sets
  `ContaminationFlag.SIMULATED_RECORD`; the flag can never be cleared downstream.
- `SECRET_BEARING` is assigned when any string value matches the secret screen
  (`(?i)(password|passwd|secret|token|api[_-]?key|BEGIN [A-Z ]*PRIVATE KEY)`); the gateway discards
  such capsules outright.
- Over-length inputs truncate to the cap with `truncated=True` and `ContaminationFlag.TRUNCATED` —
  never silently.

```python
# pocketsec/stage6/capsule/quarantine.py                           [gateway]
class QuarantineBucket(StrEnum): TRUSTED_CANDIDATE, UNCERTAIN, HOSTILE_SUSPECT, DISCARD   # architecture §6

@dataclass(frozen=True, slots=True)
class CandidateAdmission:              # a normality pattern that cleared Stage 2's controller
    pattern_key: str                   # stage2 pattern_key
    anchor: tuple[float, ...]          # stage2 meaning vector at admission
    context_id: str
    capsule_ids: tuple[str, ...]       # <= MAX_ITEM_CAPSULE_REFS
    evidence_digests: tuple[str, ...]
    independent_groups: int
    stage2_reason: str                 # PromotionRecord.reason, verbatim
    sequence: int

@dataclass(frozen=True, slots=True)
class QuarantineVerdict:               # Stage 6's; distinct from stage2.adaptation.quarantine.QuarantineVerdict
    verdict_id: str                    # digest over capsule_id + bucket + reasons + sequence
    capsule_id: str
    kind: CapsuleKind
    bucket: QuarantineBucket
    reasons: tuple[str, ...]
    trust: TrustRecord
    dependence: DependenceReport
    suspicion: PoisonSuspicion
    normalization: NormalizationFinding | None
    stage2_outcomes: tuple[tuple[str, int], ...]   # Stage 2 outcome value -> count for this capsule
    admissions: tuple[CandidateAdmission, ...]     # patterns Stage 2's controller admitted during this call
    sequence: int

class QuarantineGateway:
    def __init__(self, *, ledger: ProvenanceLedger, lineage: KnowledgeLineageDAG,
                 buffer: QuarantineBuffer | None = None, controller: PromotionController | None = None,
                 min_independent_groups: int = MIN_INDEPENDENT_GROUPS,
                 independence_check: bool = True, homeostasis: bool = True) -> None
        # min_independent_groups < 2 raises ValueError (one group corroborating itself is frequency)
    def bind_trusted_view(self, view: Callable[[], TrustedKnowledgeState]) -> None
        # called ONCE by LearningPromotionController.__init__ with mind.current; a second bind raises. The gateway
        # READS trusted state (label contradiction, near-miss mimicry) and can never write it.
    def admit(self, capsule: ExperienceCapsuleV1) -> QuarantineVerdict   # HEL-F02 — integration plan §3.2's exact signature
        # ContractError if no trusted view is bound
    def record_epoch_decision(self, decision: EpochDecision) -> bool   # forwards to BOTH Stage 2 objects
    def issued(self, verdict: QuarantineVerdict) -> bool               # verdict_id in the bounded issued set
    def take_admissions(self) -> tuple[CandidateAdmission, ...]        # drains the candidate register
    def pending_label_episodes(self) -> tuple[str, ...]
    def stats(self) -> GatewayStats
    def memory_bytes(self) -> int
```

`admit`'s pipeline, in this exact order (architecture §6), each stage recorded in `reasons`:

1. **Type and schema.** Anything that is not an `ExperienceCapsuleV1` raises `ContractError`.
   `SECRET_BEARING` → `DISCARD`.
2. **Deduplicate.** A `capsule_id` already issued → `DISCARD` with `ContaminationFlag`-style reason
   `duplicate`; the issued set is bounded (`MAX_ISSUED_VERDICTS`, oldest forgotten, counted).
3. **Provenance.** `score_provenance` → `ledger.record` (§D6.3). Below `MIN_PROVENANCE_SCORE` →
   `UNCERTAIN`.
4. **Dependence.** `detect_evidence_dependence` over the ledger records sharing this capsule's
   pattern keys (normality) or target episode (labels).
5. **Suspicion + homeostasis.** `estimate_poison_suspicion` and
   `detect_semantic_normalization_attack` (§D6.15). `PoisonSuspicion.is_hostile()` or a non-`None`
   finding → `HOSTILE_SUSPECT`. Hostile capsules are **kept as evidence** (episodic memory's
   hostile tier), never learned from and never silently dropped.
6. **Normality path** (`TRANSITION_EPISODE` whose label is `None` or `BENIGN`): for each step build
   `AdaptationSample(encoded=step.to_encoded(), state=SecurityStateV1(), epoch_id=step.epoch_id,
   delta_phi=step.delta_phi, uncertainty=step.uncertainty, evidence=step.evidence,
   received_at_sequence=<gateway step counter>, causal_signature=…, parent_signature=…)` and call
   `buffer.quarantine_adaptation_sample`. `state=SecurityStateV1()` is a **documented placeholder**:
   neither Stage 2's buffer nor `_CandidateRegister` reads it, and a test proves the register's
   output is identical for two different states. On an eligible (`HELD`, no failed checks) verdict,
   record the step's `source_group` against its pattern key (bounded: `MAX_PATTERNS_TRACKED`
   patterns × `MAX_GROUPS_TRACKED_PER_PATTERN` groups); if fewer than `min_independent_groups`
   distinct groups have been seen, record reason `single_source_repetition` and **do not call
   Stage 2's controller**; otherwise call `controller.promote(verdict, sample,
   quantizer=self._register, lattice=None)`. A `PROMOTED` record becomes a `CandidateAdmission`.
7. **Threat path** (`TRANSITION_EPISODE` with a MALICIOUS label, `LABEL_ASSERTION`,
   `WORLD_RESOLUTION`): label assertions accumulate per target episode (bounded
   `MAX_PENDING_LABEL_EPISODES`); the episode becomes `TRUSTED_CANDIDATE` only when MALICIOUS is
   asserted by ≥ `MIN_INDEPENDENT_LABEL_GROUPS` distinct groups **or** once by `GROUND_TRUTH`.
   `TEACHER` and `WEAK` assertions never count toward the quorum on their own (§26: teacher output
   is weak evidence until validated).
8. **Response path** (`RESPONSE_OUTCOME`): `TRUSTED_CANDIDATE` when every retained row passed the
   Stage 5 screens; otherwise `UNCERTAIN`.
9. **Foreign path** (`FOREIGN_PACKAGE`): at most `UNCERTAIN` unless a local independent group
   corroborates the same pattern or motif. A remote majority never overrides a local invariant.
10. **Lineage.** Record `CAPSULE` and `VERDICT` nodes in the DAG (§D6.10); only then is the verdict
    added to the issued set and returned.

Failure modes: overflow of any bounded map refuses the newcomer and counts it (Stage 2's "refuse,
don't evict waiting patterns" rule); **overflow never promotes**.

### D6.3 — Provenance / Trust Ledger `[capsule]`

```python
# pocketsec/stage6/provenance/ledger.py
@dataclass(frozen=True, slots=True)
class TrustRecord:                     # architecture §7, every row bound
    capsule_id: str
    source_class: SourceClass
    source_id: str
    independence_group: str
    epoch_id: int
    visibility: float
    label_origin: LabelOrigin
    transformation_lineage: tuple[str, ...]
    content_digest: str                # capsule.digest()
    contamination_risk: float          # [0,1]
    provenance_score: float            # [0,1]
    step_groups: tuple[str, ...]       # distinct EncodedStep.source_group values, sorted, <= 16
    recorded_sequence: int

class ProvenanceLedger:
    def __init__(self, *, capacity: int = MAX_TRUST_RECORDS) -> None
    def record(self, capsule: ExperienceCapsuleV1, *, score: ProvenanceScore) -> TrustRecord
    def get(self, capsule_id: str) -> TrustRecord | None     # None after eviction: promotion then FAILS (§41)
    def records_for(self, capsule_ids: Iterable[str]) -> tuple[TrustRecord, ...]
    def evicted(self) -> int
    def memory_bytes(self) -> int
    def stats(self) -> LedgerStats      # records, evicted, memory_bytes

# pocketsec/stage6/provenance/trust.py
SOURCE_CLASS_PRIOR: Mapping[SourceClass, float]
# LAB_GROUND_TRUTH 1.0, KERNEL_SENSOR 0.9, ANALYST 0.8, DERIVED_INFERENCE 0.5, EXTERNAL_DATASET 0.5,
# TEACHER 0.3, FOREIGN_HOST 0.2   — chosen parameters (§4.21), not measurements
LABEL_ORIGIN_WEIGHT: Mapping[LabelOrigin, float]
# GROUND_TRUTH 1.0, ANALYST 0.8, INFERENCE 0.5, WEAK 0.3, TEACHER 0.3, NONE 0.0

@dataclass(frozen=True, slots=True)
class ProvenanceScore: score: float; contamination_risk: float; reasons: tuple[str, ...]
def score_provenance(capsule: ExperienceCapsuleV1) -> ProvenanceScore                  # HEL-F03
    # score = prior(source_class) × visibility × (1 - contamination_risk)
    # contamination_risk = max over flags of FLAG_RISK (ATTACKER_CONTROLLED_SOURCE 1.0, FOREIGN_ORIGIN 0.6,
    #   UNCORROBORATED_EPOCH 0.5, SENSOR_DISAGREEMENT 0.4, OBSERVATION_INCOMPLETE 0.3, SIMULATED_RECORD 0.2,
    #   TRUNCATED 0.2, DUPLICATE_EVIDENCE 0.5), 0 if none

@dataclass(frozen=True, slots=True)
class DependenceReport:
    observations: int
    independent_groups: int
    largest_group_share: float         # NOT "fraction" (T5)
    groups: tuple[tuple[str, int], ...]   # sorted, <= 16
    dependent: bool                    # independent_groups < min_groups
def detect_evidence_dependence(records: Sequence[TrustRecord], *, min_groups: int) -> DependenceReport   # HEL-F04
    # groups are TrustRecord.step_groups for normality, independence_group for labels; a group is
    # one vote however many capsules it contributed (architecture §7's last sentence)
```

**Independence group, bound.** For telemetry it is the hashed Stage 1 actor lineage identity
(`proc:<boot>:<pid>:<start>`). This is a provenance decision, not a model feature, so ADR-0007 is not
touched. **Known weakness, attacked rather than hidden:** an attacker who forks many short-lived
lineages mints many groups. Arm P1b ("fork-spray", §4.15) measures whether that defeats the check.

### D6.4 — Bounded Episodic / Semantic / Procedural Memory `[memory]`

```python
# pocketsec/stage6/memory/semantic.py
ALL_CONTEXTS = "*"
def context_id_for(identity: SystemIdentity) -> str          # "ctx-" + identity.key()

class ItemKind(StrEnum): DETECTOR, BASELINE, PROCEDURE, THRESHOLD
class ItemStatus(StrEnum): ACTIVE, DORMANT                    # RETIRED/FOSSILIZED items leave the state

@dataclass(frozen=True, slots=True)
class MotifStep: relation: int; require_properties: int; forbid_properties: int; require_raised: int

@dataclass(frozen=True, slots=True)
class ItemLineage:
    candidate_id: str                  # the EvolutionCandidate (or "genesis")
    capsule_ids: tuple[str, ...]       # non-empty except genesis; <= MAX_ITEM_CAPSULE_REFS
    evidence_digests: tuple[str, ...]  # non-empty except genesis
    parent_item_ids: tuple[str, ...]   # items this one replaced/merged/refined

@dataclass(frozen=True, slots=True)
class ItemValidation:
    validations: int; recurrence: int; contradictions: int
    first_sequence: int; last_matched_sequence: int; epochs_seen: frozenset[int]

@dataclass(frozen=True, slots=True)
class KnowledgeItem:
    item_id: str                       # "k-" + digest prefix of (kind, motif, anchor, pattern_key, context_ids)
    kind: ItemKind
    status: ItemStatus
    context_ids: frozenset[str]        # {ALL_CONTEXTS} for DETECTOR/THRESHOLD by default
    motif: tuple[MotifStep, ...]       # DETECTOR only; 1..MAX_MOTIF_LENGTH
    anchor: tuple[float, ...]          # BASELINE only; stage2 meaning vector (26 floats)
    pattern_key: str                   # BASELINE: stage2 pattern_key; DETECTOR: "motif:<digest>"; PROCEDURE: "<operator_id>|<context_id>"
    weight: float                      # DETECTOR: precision estimate; BASELINE: radius; THRESHOLD: alert threshold
    origin_verdict: Verdict            # MALICIOUS for detectors, BENIGN for baselines; never a family name
    protected: bool                    # touches a protected anchor -> frozen_core in every mask
    lineage: ItemLineage
    validation: ItemValidation
    procedure: ProcedureRecord | None  # PROCEDURE only

@dataclass(frozen=True, slots=True)
class TrustedKnowledgeState:
    version: int
    parent_digest: str | None
    active_context: str
    items: tuple[KnowledgeItem, ...]           # sorted by item_id
    rehearsal: tuple[EpisodeSkeleton, ...]     # the protected replay set, sorted by episode_id
    def canonical_bytes(self) -> bytes         # floats rounded to 6 dp; deterministic; byte-identical round trip
    def digest(self) -> str
    @classmethod
    def from_canonical_bytes(cls, data: bytes, *, lineage: KnowledgeLineageDAG | None = None) -> TrustedKnowledgeState
        # ALWAYS refuses (LineageError) an item with empty capsule_ids/evidence_digests unless candidate_id == "genesis";
        # with a DAG, also refuses an item for which lineage.lineage_complete(item) is False
    def with_changes(self, *, add: Sequence[KnowledgeItem] = (), remove: Sequence[str] = (),
                     replace: Sequence[tuple[str, KnowledgeItem]] = (), threshold: float | None = None,
                     rehearsal: Sequence[EpisodeSkeleton] | None = None,
                     active_context: str | None = None) -> TrustedKnowledgeState
        # new value, version+1, parent_digest=self.digest(); CapacityError past any cap — never silently drops
    def detectors(self) -> tuple[KnowledgeItem, ...]; def baselines(self) -> tuple[KnowledgeItem, ...]
    def procedures(self) -> tuple[KnowledgeItem, ...]; def threshold(self) -> float
    def byte_size(self) -> int                 # len(canonical_bytes())

def genesis_state(*, identity: SystemIdentity, threshold: float = DEFAULT_THRESHOLD) -> TrustedKnowledgeState
@dataclass(frozen=True, slots=True)
class SessionScore: score: float; detector_hits: tuple[str, ...]; unexplained: float; work_units: int
def match_motif(motif: Sequence[MotifStep], steps: Sequence[EncodedStep]) -> bool
def score_session(state: TrustedKnowledgeState, steps: Sequence[EncodedStep], *, context_id: str,
                  meter: WorkMeter | None = None) -> SessionScore
class SemanticMemory:                          # read-only view; the plan's exposed name
    def __init__(self, state: TrustedKnowledgeState) -> None
    def lookup(self, pattern_key: str) -> tuple[KnowledgeItem, ...]
    def detectors(self) -> tuple[KnowledgeItem, ...]; def baselines(self, context_id: str) -> tuple[KnowledgeItem, ...]
```

An item applies when `status is ACTIVE` and (`ALL_CONTEXTS in context_ids` or the scoring
`context_id in context_ids`). Items of any other context are **dormant by construction**: a
corroborated epoch change to a new identity makes the old context's baselines inapplicable without
deleting them (architecture §23 "preserve old baseline, avoid immediate overwrite").

```python
# pocketsec/stage6/memory/episodic.py
@dataclass(frozen=True, slots=True)
class EpisodeSkeleton:                 # architecture §14's "compact sufficient episode representation"
    episode_id: str                    # the source capsule_id
    steps: tuple[EncodedStep, ...]     # <= MAX_SKELETON_STEPS: every escalating step + the first step of each
                                       #   distinct (actor_slot, pattern_key); truncated flag if cut
    verdict: Verdict                   # replay label (from the label quorum or resolution)
    label_origin: LabelOrigin
    epoch_id: int
    context_id: str
    visibility_mask: int               # bit i set = step i observed
    anchors_touched: tuple[str, ...]   # touches_protected over the steps
    truncated: bool
    def byte_size(self) -> int

class EpisodeTier(StrEnum): LEARNING, HOSTILE      # HOSTILE = kept as evidence, never learned from
@dataclass(frozen=True, slots=True)
class EpisodeValue:                    # architecture §9, every factor bound
    security_information: float        # 1 if anchors_touched else share of escalating steps
    novelty: float                     # 1 - (# resident episodes with identical motif signature)/(1 + resident)
    future_replay_value: float         # 1 if it covers a DETECTOR with < 2 exemplars, else 0.5
    label_quality: float               # LABEL_ORIGIN_WEIGHT[label_origin]
    provenance_trust: float            # TrustRecord.provenance_score
    storage_cost: float                # byte_size / MAX_SKELETON_BYTES
    redundancy: float                  # share of steps already covered by resident episodes
    poison_risk: float                 # PoisonSuspicion scalar summary
    value: float                       # product / (storage_cost + redundancy + poison_risk + EPS)
def episode_value(skeleton: EpisodeSkeleton, *, trust: TrustRecord, suspicion_summary: float,
                  resident: Sequence[EpisodeSkeleton], trusted: TrustedKnowledgeState) -> EpisodeValue
def skeleton_from_capsule(capsule: ExperienceCapsuleV1, *, verdict: Verdict, label_origin: LabelOrigin) -> EpisodeSkeleton

class EpisodicMemory:
    def __init__(self, *, capacity: int = MAX_EPISODES, byte_budget: int = MAX_EPISODIC_BYTES,
                 hostile_capacity: int = MAX_HOSTILE_EPISODES) -> None
    def admit_episode(self, skeleton: EpisodeSkeleton, *, value: EpisodeValue, verdict_id: str,
                      tier: EpisodeTier = EpisodeTier.LEARNING) -> AdmissionRecord        # HEL-F06
        # full -> evict the MIN-value LEARNING episode iff the newcomer's value is higher, else refuse;
        # every eviction appends an EvictionRecord (bounded log, counters never reset)
    def episodes(self, *, tier: EpisodeTier = EpisodeTier.LEARNING) -> tuple[EpisodeSkeleton, ...]
    def verdict_of(self, episode_id: str) -> str | None       # the gateway verdict_id it came in under
    def evictions(self) -> int; def memory_bytes(self) -> int; def stats(self) -> EpisodicStats
```

Episodic memory is **quarantine-side and untrusted**: writing to it changes no trusted state. Its
content reaches trusted state only when a candidate adds an exemplar to the rehearsal set, which goes
through the controller like every other change, and the controller verifies every exemplar's
`episode_id` resolves to a gateway-issued capsule in the DAG.

```python
# pocketsec/stage6/memory/procedural.py
@dataclass(frozen=True, slots=True)
class ProcedureRecord:
    operator_id: str; operator_class: int; context_id: str
    verified: int; unverified: int; rolled_back: int; failed: int
    simulated: bool                    # True if ANY contributing row was simulated — sticky
    evidence_digests: tuple[str, ...]  # <= MAX_ITEM_CAPSULE_REFS
def procedure_observations(capsule: ExperienceCapsuleV1) -> tuple[ProcedureRecord, ...]
    # only rows with outcome == VERIFIED_OUTCOME count as verified; refusal outcomes are ignored
class ProceduralMemory:
    def __init__(self, state: TrustedKnowledgeState) -> None
    def lookup(self, operator_id: str, *, context_id: str) -> ProcedureRecord | None
```

**Procedural memory changes no detection outcome** and nothing in Stages 1–5 reads it. It is a
bounded typed record store whose consumers are the Stage 7 export and G6.2's lineage check. The gate
reports it as **not a detection mechanism** and reports its lookup count; it is never counted as
evidence that learning helped.

Bounds: `MAX_DETECTOR_ITEMS`, `MAX_BASELINE_ITEMS`, `MAX_PROCEDURE_ITEMS`,
`MAX_REHEARSAL_EXEMPLARS`, `MAX_TRUSTED_STATE_BYTES`, `MAX_EPISODES`, `MAX_EPISODIC_BYTES`,
`MAX_HOSTILE_EPISODES`, `MAX_SKELETON_STEPS`.

### D6.5 — Epistemic Half-Life engine `[memory]`

```python
# pocketsec/stage6/memory/half_life.py
@dataclass(frozen=True, slots=True)
class HalfLifeInputs:
    validation_strength: float   # validations / (validations + 1)
    recurrence: float            # recurrence / (recurrence + 1)
    contradiction: float         # contradictions / (contradictions + 1)
    epoch_distance: float        # distinct corroborated epochs since last match, / (that + 1)
    drift_sensitivity: float     # 1 for BASELINE (context-bound), 0 for DETECTOR
def half_life(inputs: HalfLifeInputs, *, h0: float = HALF_LIFE_H0) -> float
    # H = h0 * (1 + validation_strength + recurrence) / (1 + contradiction + epoch_distance + drift_sensitivity)
@dataclass(frozen=True, slots=True)
class EpistemicHalfLife: item_id: str; half_life: float; age: int; trust: float; inputs: HalfLifeInputs
def update_epistemic_half_life(item: KnowledgeItem, *, now_sequence: int, epochs_since_match: int) -> EpistemicHalfLife   # HEL-F07
    # age = now_sequence - item.validation.last_matched_sequence; trust = 2 ** (-age / H) (trust0 = 1)
def trust_ranking(items: Sequence[KnowledgeItem], *, now_sequence: int,
                  epochs_since_match: Mapping[str, int]) -> tuple[EpistemicHalfLife, ...]   # ascending trust
```

Consumer: MNEMOSYNE's eviction/retire order and the plasticity field's stability term. **Simple
control: least-recently-matched (LRU) order.** Firing count: the number of eviction decisions whose
victim differs from the LRU victim. Zero ⇒ `INERT`. The architecture calls the formula "a research
starting point"; its constants are parameters, not calibrated values.

### D6.6 — Adaptive Plasticity Field + masks `[evolution]`

```python
# pocketsec/stage6/plasticity/field.py
@dataclass(frozen=True, slots=True)
class PlasticityTerms:                 # architecture §11, every symbol bound
    component_id: str                  # item_id | "threshold" | "new:<pattern_key>"
    novelty: float                     # N: 1 - max overlap with resident items of the same kind
    validation: float                  # V: independent_groups / MIN_INDEPENDENT_GROUPS, capped 1
    stability: float                   # S: EpistemicHalfLife.trust (1.0 for new components)
    utility: float                     # U: holdout recall gain (detectors) / FP reduction (baselines), >= 0
    forgetting_risk: float             # R: share of rehearsal positives this component covers alone
    contradiction: float               # C: share of contradicting labels on its episodes
    poison: float                      # Q: PoisonSuspicion scalar summary
    budget_pressure: float             # B: occupied / capacity of its store
@dataclass(frozen=True, slots=True)
class PlasticityField: entries: tuple[tuple[str, float], ...]; terms: tuple[PlasticityTerms, ...]
    def value(self, component_id: str) -> float
def plasticity(terms: PlasticityTerms) -> float   # (N*V*S*U) / (1 + R + C + Q + B)
def compute_plasticity_field(terms: Sequence[PlasticityTerms]) -> PlasticityField       # HEL-F08

# pocketsec/stage6/plasticity/masks.py
@dataclass(frozen=True, slots=True)
class PlasticityMask:                  # architecture §12
    frozen_core: frozenset[str]        # every protected item + every component with P < PLASTICITY_FLOOR
    adaptable: frozenset[str]
    max_item_mutations: int            # <= MAX_ITEM_MUTATIONS
    max_threshold_delta: float         # <= MAX_THRESHOLD_DELTA
    expires_at_sequence: int           # created + MASK_EXPIRY_SEQUENCES; an expired mask permits nothing
    def permits(self, component_id: str, *, now_sequence: int) -> bool
def generate_plasticity_mask(field: PlasticityField, *, protected: frozenset[str], now_sequence: int) -> PlasticityMask   # HEL-F09
def uniform_mask(component_ids: Iterable[str], *, protected: frozenset[str], now_sequence: int) -> PlasticityMask
    # the SIMPLE CONTROL: same mutation and threshold budgets, no field — isolates the field from the budget knob
```

HEL-F09 is REQUIRED (frozen core and budgets are safety bounds); HEL-F08 is OPTIONAL and must beat
`uniform_mask` **at identical `max_item_mutations`** (lesson 4: the budget is the knob; the control
holds it fixed). Firing count: changes the field froze that the uniform mask would have allowed.

### D6.7 — Memory Competition engine `[evolution]`

```python
# pocketsec/stage6/memory/competition.py
class CompetitionOutcome(StrEnum): REPLACE, COEXIST, REJECT_NEW
@dataclass(frozen=True, slots=True)
class CompetitionScores:               # architecture §13, every axis bound
    coverage: float                    # share of replay positives matched
    recall: float                      # at the trusted threshold
    fp_burden: float                   # share of replay negatives alerted
    calibration: float                 # Brier over replay
    applicability: frozenset[str]      # context ids
    resource_bytes: int
    robustness: float                  # recall over semantics-preserving counterfactual variants
@dataclass(frozen=True, slots=True)
class CompetitionResult: outcome: CompetitionOutcome; new_item_id: str; old_item_id: str
                         new: CompetitionScores; old: CompetitionScores; reason: str
def compete_knowledge(new: KnowledgeItem, old: KnowledgeItem, *, replay: Sequence[EpisodeSkeleton],
                      variants: Sequence[ReplayVariant], threshold: float, meter: WorkMeter) -> CompetitionResult   # HEL-F10
    # REPLACE iff new Pareto-dominates old on (recall↑, fp_burden↓, calibration↓, resource_bytes↓, robustness↑)
    #   with >= 1 strict improvement AND new.applicability ⊇ old.applicability;
    # COEXIST iff both are within EPS_SECURITY of their best on disjoint applicability;
    # else REJECT_NEW. A protected old item is never REPLACEd by an item with lower recall on any variant.
def overlaps(a: KnowledgeItem, b: KnowledgeItem) -> bool   # same kind and (same pattern_key or motif match-sets intersect on replay)
```

**Simple controls: `NEWEST_WINS` (always replace) and `OLDEST_WINS` (never replace).** Firing count:
conflicts resolved to COEXIST or REJECT_NEW that newest-wins would have replaced.

### D6.8 — Counterfactual Rehearsal engine `[lineage]`

```python
# pocketsec/stage6/rehearsal/counterfactual.py
class VariantKind(StrEnum): RENAME_ACTORS, ALTER_TIMING, DROP_TELEMETRY, SUBSTITUTE_PROCESS_CLASS, INJECT_DECOYS
@dataclass(frozen=True, slots=True)
class ReplayVariant:
    variant_id: str; kind: VariantKind; source_episode_id: str
    steps: tuple[EncodedStep, ...]
    expected_verdict: Verdict          # the source's verdict when semantics are preserved, else UNKNOWN
    semantics_preserved: bool
def generate_counterfactual_replay(skeleton: EpisodeSkeleton, *, kinds: Sequence[VariantKind] = tuple(VariantKind),
                                   seed: int, decoys: Sequence[EpisodeSkeleton] = (),
                                   max_variants: int = MAX_VARIANTS_PER_EPISODE) -> tuple[ReplayVariant, ...]   # HEL-F11
```

Per kind: RENAME permutes `actor_slot` values; ALTER_TIMING changes `time_bucket` and the temporal
feature group; DROP_TELEMETRY removes one step and clears its `visibility_mask` bit — if the removed
step is part of every matching motif the variant is `semantics_preserved=False`; SUBSTITUTE swaps the
`actor_semantics` feature group with another actor's in the same episode (never touching
`object_semantics` or `state_delta_raised`); INJECT_DECOYS inserts benign decoy steps under fresh
`actor_slot`s. Deterministic from `seed`.

**Stated in advance (lesson 2):** the motif matcher ignores `actor_slot` identity and time, so
RENAME and ALTER_TIMING **cannot change any score by construction**. They are kept as regression
tests that identity or timing has not leaked into the representation, and are reported INERT, not as
a mechanism result. Only DROP, SUBSTITUTE and DECOY can fire. **Simple control: plain replay of the
stored skeletons (G2 alone).** Firing count: candidates G4 refused that G2 accepted.

### D6.9 — Knowledge Fossil store `[lineage]`

```python
# pocketsec/stage6/fossils/store.py
class FossilReason(StrEnum): GENESIS, PRE_PROMOTION, PROMOTION, CONTEXT_DORMANCY, CONSOLIDATION, RETIREMENT
@dataclass(frozen=True, slots=True)
class KnowledgeFossil:                 # architecture §15, every field bound
    artifact_hash: str                 # sha256 of the UNcompressed payload == TrustedKnowledgeState.digest()
    parent_hashes: tuple[str, ...]
    versions: tuple[tuple[str, str], ...]   # ("state", str(version)), ("capsule_schema", …), ("encoder", layout digest)
    benchmark_fingerprint: str         # digest of the rehearsal replay result at fossilisation
    epoch_range: tuple[int, int]
    capabilities_preserved: tuple[str, ...]  # DETECTOR item ids
    creation_reason: FossilReason
    created_sequence: int
    pinned: bool
    compressed_bytes: int
@dataclass(frozen=True, slots=True)
class FossilTombstone: artifact_hash: str; reason: str; evicted_sequence: int; parent_hashes: tuple[str, ...]
class FossilStore:
    def __init__(self, *, max_fossils: int = MAX_FOSSILS, max_bytes: int = MAX_FOSSIL_BYTES,
                 directory: Path | None = None) -> None     # directory: zlib-compressed <hash>.fossil files
    def create_fossil(self, state: TrustedKnowledgeState, *, reason: FossilReason, fingerprint: str,
                      epoch_range: tuple[int, int], sequence: int, pin: bool = False) -> KnowledgeFossil   # HEL-F12
    def load(self, artifact_hash: str) -> TrustedKnowledgeState
        # decompress, re-hash, FossilIntegrityError on mismatch; the corrupted fossil is never returned
    def payload(self, artifact_hash: str) -> bytes     # verified canonical bytes
    def latest_known_good(self, *, excluding: frozenset[str] = frozenset()) -> KnowledgeFossil | None
    def pin(self, artifact_hash: str) -> None; def unpin(self, artifact_hash: str) -> None   # <= MAX_PINNED_FOSSILS
    def fossils(self) -> tuple[KnowledgeFossil, ...]; def tombstones(self) -> tuple[FossilTombstone, ...]
    def evictions(self) -> int; def memory_bytes(self) -> int
```

Eviction: oldest **unpinned** fossil first; a tombstone is appended (bounded `MAX_TOMBSTONES`,
counted). The current trusted state's fossil and the probation rollback target are always pinned.
**This makes rollback depth bounded — a real, stated consequence of the 2 GB constraint:** a state
older than the retained fossils cannot be restored, and the tombstone says so rather than pretending
otherwise (ADR-0052).

### D6.10 — Knowledge Lineage DAG `[lineage]`

```python
# pocketsec/stage6/fossils/lineage.py
class NodeKind(StrEnum): GENESIS, CAPSULE, VERDICT, CANDIDATE, CONSERVATION, SHADOW, CANARY,
                         PROMOTION, ROLLBACK, FOSSIL, REJECTION, TOMBSTONE
@dataclass(frozen=True, slots=True)
class LineageNode: node_id: str; kind: NodeKind; digest: str; created_sequence: int; detail: str
@dataclass(frozen=True, slots=True)
class LineageEdge:                     # architecture §16: every edge stores all six
    parent: str; child: str
    reason: str
    evidence: tuple[str, ...]          # digests
    tests: tuple[str, ...]             # conservation/shadow/canary report digests
    parent_versions: tuple[str, ...]   # state digests
    transformation: str
    gate_result: str                   # "PASS" | "FAIL:<check ids>"
    edge_digest: str                   # sha256 over parent node digest + child node digest + the six fields
class KnowledgeLineageDAG:
    def __init__(self, *, max_nodes: int = MAX_LINEAGE_NODES, max_edges: int = MAX_LINEAGE_EDGES) -> None
    def update_lineage_dag(self, *, node: LineageNode, parents: Sequence[str], reason: str,
                           evidence: Sequence[str] = (), tests: Sequence[str] = (),
                           parent_versions: Sequence[str] = (), transformation: str = "",
                           gate_result: str = "PASS") -> LineageNode       # HEL-F13
        # unknown parent -> LineageError (only GENESIS has none); a cycle -> LineageError; duplicate node_id -> LineageError
    def has(self, node_id: str) -> bool
    def parents(self, node_id: str) -> tuple[str, ...]; def ancestors(self, node_id: str, *, max_depth: int = 64) -> tuple[str, ...]
    def lineage_complete(self, item: KnowledgeItem) -> bool
        # CANDIDATE node item.lineage.candidate_id exists AND has a PROMOTION descendant AND every capsule id is a
        # CAPSULE node (or inside a TOMBSTONE's id set) with a VERDICT child — or candidate_id == "genesis"
    def verify(self) -> tuple[str, ...]     # recompute every edge_digest; () = intact; any tamper is reported
    def collect(self, *, live_items: Sequence[KnowledgeItem], pinned_fossils: Sequence[str]) -> int
        # reachability GC: nodes not reachable backwards from live items/pinned fossils are folded into ONE
        # TOMBSTONE node (id set <= MAX_TOMBSTONE_IDS, digest of the removed digests); returns nodes folded
    def memory_bytes(self) -> int; def stats(self) -> LineageStats
```

Live lineage is always complete because collection never folds a node a live item reaches; bounded
because live items are capped and each carries ≤ `MAX_ITEM_CAPSULE_REFS` capsules. Tampering (S6X-42)
is detected by `verify()`.

### D6.11 — HELIOS Evolution Chamber `[evolution]`

```python
# pocketsec/stage6/chamber/evolution.py
class CandidateKind(StrEnum):          # ADR-0056: exactly the kinds with an executor
    STATISTICAL = "STATISTICAL"        # BASELINE add/update from CandidateAdmissions
    SYMBOLIC = "SYMBOLIC"              # DETECTOR add/refine/remove
    CALIBRATION = "CALIBRATION"        # THRESHOLD change within mask.max_threshold_delta
    PROCEDURAL = "PROCEDURAL"          # PROCEDURE add/merge
    CONSOLIDATION = "CONSOLIDATION"    # produced by MNEMOSYNE
    RESURRECTION = "RESURRECTION"      # produced by homeostasis.drift
@dataclass(frozen=True, slots=True)
class KnowledgeDelta:
    added: tuple[KnowledgeItem, ...]; removed: tuple[str, ...]; replaced: tuple[tuple[str, KnowledgeItem], ...]
    threshold: float | None; rehearsal_added: tuple[EpisodeSkeleton, ...]; rehearsal_removed: tuple[str, ...]
    active_context: str | None
@dataclass(frozen=True, slots=True)
class MotifCandidate: motif: tuple[MotifStep, ...]; precision: float; coverage: float; support: tuple[str, ...]
@dataclass(frozen=True, slots=True)
class EvolutionCandidate:
    candidate_id: str                  # "cand-" + digest(base_digest, delta)
    kinds: frozenset[CandidateKind]
    base_digest: str
    proposed: TrustedKnowledgeState
    delta: KnowledgeDelta
    verdict_ids: tuple[str, ...]       # gateway verdicts it was built from
    capsule_ids: tuple[str, ...]
    mask: PlasticityMask
    competition: tuple[CompetitionResult, ...]
    holdout_episode_ids: tuple[str, ...]
    mask_refusals: int                 # changes the mask forbade (plasticity firing count)
    work_units: int
    created_sequence: int
class UnquarantinedInputError(ContractError): ...

def induce_motifs(malicious: Sequence[EpisodeSkeleton], benign: Sequence[EpisodeSkeleton], *,
                  max_per_episode: int = MAX_MOTIF_CANDIDATES_PER_EPISODE,
                  min_precision: float = MIN_DETECTOR_PRECISION, meter: WorkMeter) -> tuple[MotifCandidate, ...]
    # SHARED by the chamber AND every baseline learner (§7), so learners differ only in the mechanism under test.
    # Per malicious episode, per actor_slot, over escalating steps in order: every single step and every ordered
    # pair (i<j), first max_per_episode by position. Start each MotifStep specific (require = the step's full
    # object mask and state_delta_mask, forbid = 0); greedily drop required bits one at a time while precision on
    # (malicious ∪ benign) stays >= min_precision; then, if a benign twin still matches, add the forbid bit that
    # separates it. weight = (tp + 1) / (tp + fp + 2). Dedupe identical motifs; stable order.

class EvolutionChamber:
    def __init__(self, *, gateway: QuarantineGateway, episodic: EpisodicMemory,
                 consolidator: MnemosyneConsolidator, max_capsules: int = MAX_CHAMBER_CAPSULES,
                 work_budget: int = MAX_CHAMBER_WORK_UNITS, plasticity_field: bool = True,
                 competition: bool = True) -> None
    def spawn_evolution_candidate(self, *, trusted: TrustedKnowledgeState, verdicts: Sequence[QuarantineVerdict],
                                  admissions: Sequence[CandidateAdmission], half_lives: Sequence[EpistemicHalfLife],
                                  sequence: int) -> EvolutionCandidate | None      # HEL-F14
    def issued(self, candidate: EvolutionCandidate) -> bool    # candidate_id in the bounded issued set
```

Algorithm, in order: (1) **any** verdict with `not gateway.issued(v)` or bucket other than
`TRUSTED_CANDIDATE` raises `UnquarantinedInputError` for the whole call — no partial candidate;
(2) more than `max_capsules` verdicts raises `ContractError` (the chamber never sees full history);
(3) split episodes by `sha256(episode_id)` into training and holdout (`HOLDOUT_SHARE`); (4) SYMBOLIC:
`induce_motifs` on training malicious vs training benign plus resident benign episodes; each motif
that overlaps a resident detector goes through `compete_knowledge` (or `NEWEST_WINS` when
`competition=False`); (5) STATISTICAL: admissions → BASELINE items with `weight =
DEFAULT_CONSISTENCY_RADIUS` and the admission's context; (6) PROCEDURAL: merge counts; (7)
CALIBRATION: threshold at the FPR budget over rehearsal ∪ holdout negatives, clipped to
`max_threshold_delta`; (8) plasticity field → mask (or `uniform_mask` when `plasticity_field=False`);
drop forbidden changes, count them; (9) if a cap would be exceeded, ask
`consolidator.plan_room(trusted, needed)` for evictions (fossilised first) — never drop silently;
(10) `proposed = trusted.with_changes(...)`; items carry `ItemLineage(candidate_id, capsule_ids,
evidence_digests, parent_item_ids)`; (11) record a `CANDIDATE` node whose parents are the `VERDICT`
nodes. The chamber works only on immutable values: it holds no reference to `TrustedMind` and
**cannot** write trusted state; an exception inside it leaves the trusted digest unchanged (§41).

### D6.12 — MNEMOSYNE Consolidator `[evolution]`

```python
# pocketsec/stage6/consolidator/mnemosyne.py
@dataclass(frozen=True, slots=True)
class Consolidation:                   # architecture §18, every bullet a field
    candidate: EvolutionCandidate | None          # the trusted-state change it proposes (goes through the controller)
    deduplicated: int                  # episodic episodes merged as semantically equivalent (untrusted side)
    merged: tuple[tuple[str, str], ...]           # detector pairs merged (in the candidate)
    split: tuple[str, ...]                        # items split by context divergence (in the candidate)
    aged: tuple[EpistemicHalfLife, ...]
    dormant_evicted: tuple[str, ...]              # dormant-context items fossilised then removed (in the candidate)
    retired: tuple[str, ...]
    rehearsal_selected: tuple[str, ...]
    fossil_due: bool
    deferred: bool
    deferred_reasons: tuple[str, ...]
    work_units: int
class MnemosyneConsolidator:
    def __init__(self, *, fossils: FossilStore, lineage: KnowledgeLineageDAG,
                 value_aware_rehearsal: bool = True, half_life: bool = True, period: int = CONSOLIDATION_PERIOD) -> None
    def consolidate_memory(self, *, trusted: TrustedKnowledgeState, episodic: EpisodicMemory,
                           snapshot: ResourceSnapshot, now_sequence: int,
                           epochs_since_match: Mapping[str, int]) -> Consolidation          # HEL-F15
    def melt_or_retire_knowledge(self, trusted: TrustedKnowledgeState, *, rankings: Sequence[EpistemicHalfLife],
                                 now_sequence: int) -> KnowledgeDelta                        # HEL-F25
        # melt = ACTIVE -> DORMANT (reversible); retire = remove, ONLY after a RETIREMENT fossil holds it, ONLY if
        # trust < RETIRE_TRUST_FLOOR and dormant > MAX_DORMANT_SEQUENCES and not protected. Protected items are never retired.
    def select_rehearsal_exemplars(self, episodic: EpisodicMemory, *, trusted: TrustedKnowledgeState,
                                   budget_bytes: int) -> tuple[EpisodeSkeleton, ...]
        # value-aware: >= 1 positive exemplar per DETECTOR, then benign exemplars covering each context, then by value
        # control (value_aware_rehearsal=False): reservoir sampling at the SAME byte budget (ADR-0128 precedent)
    def plan_room(self, trusted: TrustedKnowledgeState, needed: Mapping[ItemKind, int]) -> KnowledgeDelta
        # evict dormant-context items first (fossilised), then lowest-trust (half_life=True) or LRU (False)
def consolidation_allowed(snapshot: ResourceSnapshot) -> tuple[bool, tuple[str, ...]]   # architecture §40
```

When `consolidation_allowed` is false, consolidation is **deferred**: bounded metadata is queued,
nothing expensive runs, and detection is never blocked (scoring never waits on consolidation).

### D6.13 — Shadow Mind runtime `[promotion]`

```python
# pocketsec/stage6/shadow/mind.py
@dataclass(frozen=True, slots=True)
class ShadowSession: session_id: str; steps: tuple[EncodedStep, ...]; context_id: str; label: Verdict | None
@dataclass(frozen=True, slots=True)
class ShadowReport:                    # architecture §19, every comparison a field; counts only
    candidate_digest: str; trusted_digest: str
    sessions_seen: int; sessions_sampled: int
    misses_caught: int                 # labelled MALICIOUS: candidate alerts, trusted does not
    regressions: int                   # labelled MALICIOUS: trusted alerts, candidate does not
    protected_regressions: int         # regressions on sessions touching a protected anchor
    fp_change: int                     # labelled BENIGN: candidate alerts - trusted alerts
    disagreement_rate: float | None    # None when nothing was sampled
    calibration_delta: float | None    # Brier(candidate) - Brier(trusted) over labelled sampled sessions
    poisoning_sensitivity: float | None  # disagreement on hostile-tier episodes
    work_units: int; bytes_estimate: int
    aborted: bool; abort_reason: str
    def digest(self) -> str; def to_dict(self) -> dict[str, Any]
class ShadowMind:
    def __init__(self, *, sample_every: int = SHADOW_SAMPLE_EVERY, work_budget: int = MAX_SHADOW_WORK_UNITS,
                 byte_budget: int = MAX_SHADOW_BYTES) -> None
    def run_shadow_mind(self, candidate: TrustedKnowledgeState, trusted: TrustedKnowledgeState,
                        sessions: Iterable[ShadowSession]) -> ShadowReport      # HEL-F16
```

Zero authority by construction: the shadow holds no reference to Stage 5, the controller, or any
writer; its output is counts. Sampling is deterministic (`every sample_every-th session`). **OOM
safety (architecture §41):** when the `WorkMeter` or byte estimate would exceed its budget the shadow
stops, returns `aborted=True`, and the trusted scoring of that session has already happened — the
shadow runs *after* production scoring, never before it. An aborted report fails G8.

### D6.14 — Knowledge Conservation Gate `[promotion]`

```python
# pocketsec/stage6/conservation/gate.py
class ConservationCheck(StrEnum): G1_INTEGRITY, G2_HISTORICAL_REPLAY, G3_CURRENT_HOLDOUT, G4_COUNTERFACTUAL,
                                  G5_ADVERSARIAL, G6_CALIBRATION, G7_RESOURCE, G8_SHADOW, G9_ROLLBACK
@dataclass(frozen=True, slots=True)
class ConservationResult: check: ConservationCheck; passed: bool; measured: float | None; bound: float | None; detail: str
@dataclass(frozen=True, slots=True)
class ConservationVerdict:
    candidate_id: str; base_digest: str; proposed_digest: str
    results: tuple[ConservationResult, ...]    # exactly nine, in enum order
    complete: bool                     # False until G8 has a ShadowReport
    passed: bool                       # complete and all nine passed
    verdict_digest: str; work_units: int
def offline_validation(candidate: EvolutionCandidate, *, trusted: TrustedKnowledgeState,
                       lineage: KnowledgeLineageDAG, fossils: FossilStore, holdout: Sequence[EpisodeSkeleton],
                       hostile: Sequence[EpisodeSkeleton], variant_seed: int, meter: WorkMeter) -> ConservationVerdict   # HEL-F17
def complete_with_shadow(verdict: ConservationVerdict, report: ShadowReport) -> ConservationVerdict
```

The nine checks, each measured against a named bound:

| check | measured | passes iff |
|---|---|---|
| G1 integrity | recomputed `proposed.digest()`; every item `lineage_complete`; no rehearsal exemplar's evidence or lineage altered relative to base | digests match, 100% complete, 0 altered |
| G2 historical replay | per-verdict-class recall of `proposed` vs `trusted` on the **trusted** rehearsal set at each state's own threshold | no drop > `EPS_SECURITY`, and 0 protected exemplars newly missed |
| G3 current holdout | recall gain on holdout MALICIOUS (SYMBOLIC) or FP-rate reduction on holdout BENIGN (STATISTICAL, CALIBRATION) | gain ≥ `MIN_UTILITY_GAIN` for any kind that claims utility; PROCEDURAL/CONSOLIDATION/RESURRECTION claim none and pass on non-regression |
| G4 counterfactual | recall over `semantics_preserved` variants of the rehearsal positives | drop vs trusted ≤ `EPS_COUNTERFACTUAL` |
| G5 adversarial | hostile-tier episodes whose score falls below threshold under `proposed` while ≥ threshold under `trusted`; plus any BASELINE that explains a step touching a protected anchor | 0 and 0 |
| G6 calibration | Brier over rehearsal ∪ holdout | increase ≤ `EPS_BRIER` |
| G7 resource | `proposed.byte_size()`, per-kind counts, `candidate.work_units`, byte growth | all within caps; growth ≤ `MAX_STATE_GROWTH_BYTES` |
| G8 shadow | `ShadowReport` | not aborted, `sessions_sampled ≥ MIN_SHADOW_SESSIONS`, `disagreement_rate ≤ MAX_SHADOW_DISAGREEMENT`, `protected_regressions == 0` |
| G9 rollback | `fossils.load(trusted.digest())` | loads and verifies |

A failing candidate returns to quarantine as a `REJECTION` node and "does not affect production"
(architecture §20): the trusted digest is unchanged, asserted in the promotion tests.

### D6.15 — Semantic Homeostasis + poisoning defenses `[gateway]`

```python
# pocketsec/stage6/homeostasis/poisoning.py
@dataclass(frozen=True, slots=True)
class PoisonSuspicion:                 # architecture §34 — a structured vector, not one scalar
    source_control: float              # contamination_risk of the source
    dependence: float                  # 1 - independent_groups / max(1, observations)
    protected_conflict: bool           # the capsule moves protected meaning toward normal
    label_shift: float                 # share of prior assertions on the same motif with the opposite verdict
    trigger_concentration: float       # share of steps one object-property bit away from a trusted DETECTOR's
                                       #   required mask on the same relation (near-miss mimicry)
    cross_epoch_inconsistency: float   # share of epochs in which this motif got the opposite verdict
    historical_regression: float | None      # filled only by the conservation gate (G2), else None
    counterfactual_instability: float | None # filled only by the conservation gate (G4), else None
    def summary(self) -> float         # max of the numeric components, 1.0 if protected_conflict
    def is_hostile(self) -> bool       # protected_conflict or dependence >= HOSTILE_DEPENDENCE with >= MIN obs,
                                       #   or trigger_concentration >= HOSTILE_TRIGGER_CONCENTRATION,
                                       #   or label_shift >= HOSTILE_LABEL_SHIFT
class LabelHistory:                    # bounded: MAX_LABEL_HISTORY motif keys, oldest forgotten, counted
    def observe(self, motif_key: str, verdict: Verdict, *, group: str, epoch_id: int) -> None
    def opposite_share(self, motif_key: str, verdict: Verdict) -> float
    def epoch_inconsistency(self, motif_key: str) -> float
@dataclass(frozen=True, slots=True)
class NormalizationFinding: anchors: tuple[str, ...]; detector_ids: tuple[str, ...]; rule: str; detail: str
def estimate_poison_suspicion(capsule: ExperienceCapsuleV1, *, trust: TrustRecord, dependence: DependenceReport,
                              trusted: TrustedKnowledgeState, history: LabelHistory) -> PoisonSuspicion   # HEL-F05
def detect_semantic_normalization_attack(capsule: ExperienceCapsuleV1, *,
                                         trusted: TrustedKnowledgeState) -> NormalizationFinding | None   # HEL-F18
    # rule "benign_label_on_protected_detector": a BENIGN assertion (any origin but GROUND_TRUTH) on an episode
    #   whose steps match a trusted DETECTOR touching a protected anchor;
    # rule "normality_on_protected_meaning": a normality-direction step touching a protected anchor
    #   (Stage 2's risk rule already refuses these — counted separately as stage2_equivalent);
    # rule "remove_protected_detector": a LABEL/FOREIGN capsule proposing to retire a protected detector
```

**Protected meaning does not adapt from frequency** (architecture §21): no count, rate or repetition
enters any rule above. Baseline frequency may adapt; the anchors may not.

### D6.16 — Drift / Epoch / Recurrence engine `[gateway]`

```python
# pocketsec/stage6/homeostasis/drift.py
class DriftClass(StrEnum): LEGITIMATE_DRIFT, POISON_SUSPECT, UNDETERMINED
@dataclass(frozen=True, slots=True)
class DriftSignals:                    # architecture §22, one field per row
    provenance_trusted_change: bool    # a corroborated EpochDecision (decision.transitioned) inside the window
    breadth: float                     # distinct pattern keys changed / pattern keys observed in the window
    timing_aligned: bool               # first changed sample within DRIFT_ALIGN_WINDOW of the transition
    independent_corroboration: int     # distinct groups exhibiting the change
    semantics_stable: bool             # no changed pattern touches a protected anchor
    rollback_test_passed: bool | None  # from the conservation gate when available, else None
@dataclass(frozen=True, slots=True)
class DriftVerdict: drift_class: DriftClass; signals: DriftSignals; reasons: tuple[str, ...]
def drift_signals(window: Sequence[QuarantineVerdict], *, decision: EpochDecision | None,
                  decision_sequence: int | None) -> DriftSignals
def classify_drift_vs_poisoning(signals: DriftSignals) -> DriftVerdict               # HEL-F19
    # LEGITIMATE_DRIFT iff provenance_trusted_change AND semantics_stable AND
    #   independent_corroboration >= MIN_INDEPENDENT_GROUPS AND rollback_test_passed is not False;
    # POISON_SUSPECT iff not semantics_stable OR (not provenance_trusted_change AND independent_corroboration < MIN)
    #   OR rollback_test_passed is False; else UNDETERMINED. No single signal decides either way.

class ContextStatus(StrEnum): ACTIVE, PROVISIONAL, DORMANT
@dataclass(frozen=True, slots=True)
class KnowledgeContext:                # a group of Stage 1 epochs sharing one SystemIdentity.key(); NOT a second Epoch
    context_id: str; identity: SystemIdentity; epoch_ids: tuple[int, ...]; status: ContextStatus
    opened_sequence: int; last_active_sequence: int; dormancy_fossil: str | None
@dataclass(frozen=True, slots=True)
class EpochTransition: previous: str; current: str; resurrect: ResurrectionProposal | None; proposal: KnowledgeDelta
@dataclass(frozen=True, slots=True)
class ResurrectionProposal: context_id: str; fossil_hash: str; items: tuple[KnowledgeItem, ...]
class KnowledgeContextRegistry:        # bounded MAX_KNOWLEDGE_CONTEXTS, oldest DORMANT dropped (its fossil stays)
    def open_new_epoch(self, decision: EpochDecision, *, identity: SystemIdentity, sequence: int,
                       trusted: TrustedKnowledgeState, fossils: FossilStore) -> EpochTransition | None   # HEL-F20
        # None unless decision.transitioned. Old ACTIVE -> DORMANT; new context PROVISIONAL, or the matched
        # DORMANT context -> resurrection. The trusted change (active_context) is a PROPOSAL the controller installs.
    def resurrect_dormant_knowledge(self, identity: SystemIdentity, *, trusted: TrustedKnowledgeState,
                                    fossils: FossilStore) -> ResurrectionProposal | None     # HEL-F21
        # a context whose items are no longer resident is reloaded from its dormancy fossil (integrity-verified);
        # the result is a RESURRECTION candidate: shadow + conservation + controller, never a direct write
    def contexts(self) -> tuple[KnowledgeContext, ...]; def memory_bytes(self) -> int
```

An uncorroborated `EpochDecision` changes nothing here (Stage 1 already refused it); epoch
manipulation (arm P5) is measured as "contexts opened and items retired by uncorroborated changes",
which must be 0. **Resurrection's simple control: relearn from scratch** (no registry lookup).
Resurrection fires only when a returning context's items were evicted; if capacity never forced an
eviction, resurrection is reported `INERT` on that run, not "working".

### D6.17 — Canary + Learning Rollback controller `[promotion]`

```python
# pocketsec/stage6/shadow/canary.py
@dataclass(frozen=True, slots=True)
class CanaryPolicy:
    share: float = CANARY_SHARE                  # NOT "fraction" (T5)
    window_sessions: int = CANARY_WINDOW_SESSIONS
    max_protected_regressions: int = MAX_PROTECTED_REGRESSIONS
    max_fp_increase: float = CANARY_MAX_FP_INCREASE
    probation_sessions: int = PROBATION_SESSIONS
def canary_sampled(session_id: str, *, share: float) -> bool      # int(sha256(session_id)[:8], 16) / 2**32 < share
def emitted_score(trusted: float, candidate: float, *, sampled: bool) -> float
    # max(trusted, candidate) if sampled else trusted: a canary may ADD evidence, never suppress it (§43)
@dataclass(frozen=True, slots=True)
class CanaryObservation: session_id: str; trusted_score: float; candidate_score: float; emitted: float
                         sampled: bool; label: Verdict | None
@dataclass(frozen=True, slots=True)
class CanaryReport: candidate_digest: str; observations: int; sampled: int; disagreements: int
                    regressions: int; protected_regressions: int; fp_increase: float | None
                    window_complete: bool; regressed: bool; reasons: tuple[str, ...]
                    def digest(self) -> str; def to_dict(self) -> dict[str, Any]
class CanaryEvaluator:
    def __init__(self, *, candidate: TrustedKnowledgeState, trusted: TrustedKnowledgeState, policy: CanaryPolicy) -> None
    def observe(self, session: ShadowSession) -> CanaryObservation
    def report(self) -> CanaryReport

# pocketsec/stage6/promotion/controller.py        — THE ONE WRITER
@dataclass(frozen=True, slots=True)
class PromotionDecision:
    decision_id: str; candidate_id: str; from_state: LifecycleState; to_state: LifecycleState
    conservation_digest: str | None; shadow_digest: str | None; canary_digest: str | None
    trusted_before: str; trusted_after: str; reason: str; sequence: int
class RollbackTrigger(StrEnum): CANARY_REGRESSION, PROBATION_REGRESSION, FOSSIL_CORRUPTION, INTEGRITY_FAILURE, OPERATOR_REQUEST
@dataclass(frozen=True, slots=True)
class LearningRollback:                # architecture §44
    rollback_id: str; trigger: RollbackTrigger; candidate_id: str | None
    from_digest: str; to_digest: str
    restored_bytes_identical: bool     # canonical_bytes() == the fossil's verified payload
    skipped_fossils: tuple[str, ...]   # corrupted fossils passed over
    evidence: tuple[str, ...]          # the report digests that triggered it
    sequence: int
class TrustedMind:
    def current(self) -> TrustedKnowledgeState
    def digest(self) -> str
    def score(self, steps: Sequence[EncodedStep], *, context_id: str, meter: WorkMeter | None = None) -> SessionScore
    # private: self._trusted_state; self._install_trusted(state, *, decision) — the ONLY mutation in the repository
class LearningPromotionController:
    def __init__(self, *, genesis: TrustedKnowledgeState, fossils: FossilStore, lineage: KnowledgeLineageDAG,
                 gateway: QuarantineGateway, chamber: EvolutionChamber, shadow: ShadowMind,
                 policy: CanaryPolicy = CanaryPolicy()) -> None
        # constructs the TrustedMind; fossilises + pins genesis; records GENESIS and "promotion-genesis" nodes;
        # calls gateway.bind_trusted_view(self.mind.current)
    @property
    def mind(self) -> TrustedMind
    def submit(self, candidate: EvolutionCandidate, *, holdout: Sequence[EpisodeSkeleton],
               hostile: Sequence[EpisodeSkeleton], variant_seed: int) -> PromotionDecision
        # refuses a candidate not chamber.issued(); refuses base_digest != mind.digest(); runs offline_validation ITSELF
        # (no externally supplied verdict is ever accepted) -> OFFLINE_VALIDATED | REJECTED
    def run_shadow(self, candidate_id: str, sessions: Iterable[ShadowSession]) -> PromotionDecision   # -> SHADOW | REJECTED
    def promote_canary(self, candidate_id: str) -> PromotionDecision                                  # HEL-F22 -> CANARY
    def observe_canary(self, session: ShadowSession) -> CanaryObservation | PromotionDecision
        # returns a REJECTED decision the moment the report regresses; the trusted digest never changed
    def promote_trusted(self, candidate_id: str) -> PromotionDecision                                 # HEL-F23
        # requires: complete & passed ConservationVerdict, CanaryReport window_complete and not regressed;
        # pins a PRE_PROMOTION fossil of the current state, installs, fossilises + pins the new state,
        # records PROMOTION with parents CANDIDATE, CONSERVATION, SHADOW, CANARY; enters PROBATION
    def observe_probation(self, session: ShadowSession) -> LearningRollback | None
        # compares against the pinned pre-promotion state; a regression triggers rollback_learning AUTOMATICALLY
    def rollback_learning(self, *, trigger: RollbackTrigger, to_digest: str | None = None) -> LearningRollback   # HEL-F24
        # target = to_digest or the pinned pre-promotion fossil or latest_known_good; FossilIntegrityError -> skip to the
        # next known-good and record it; install; assert restored_bytes_identical; ROLLBACK node + REJECTION of the
        # candidate recorded; nothing about the failed candidate is deleted
    def apply_context_transition(self, transition: EpochTransition) -> PromotionDecision
        # active_context changes still pass G1, G2, G7, G9 (no shadow/canary: no detector or baseline changes)
    def decisions(self) -> tuple[PromotionDecision, ...]; def rollbacks(self) -> tuple[LearningRollback, ...]
    def stats(self) -> ControllerStats
```

`require_transition` guards every state change; skipping a state raises. Bounded logs
(`MAX_DECISION_LOG`, `MAX_ROLLBACK_LOG`) drop oldest with counters; the full history is in the DAG.
`_install_trusted` refuses any `decision` whose `decision_id` this controller did not mint in the
same call chain (a module-private issued set), so even a caller holding the object and naming the
private method is refused — and the AST rule (§5.1 rule 4) forbids naming it outside this file.

### D6.18 — Quantized candidate export pipeline `[lineage]`

```python
# pocketsec/stage6/export/quantized_candidates.py
@dataclass(frozen=True, slots=True)
class QuantizedState: base_digest: str; bits: int; scale: float; zero_point: int; payload: bytes; float_count: int
@dataclass(frozen=True, slots=True)
class QuantizedCandidate:
    base_digest: str; bits: int
    fp_bytes: int; quantized_bytes: int
    recall_fp: float | None; recall_q: float | None
    fp_rate_fp: float | None; fp_rate_q: float | None
    consistency_agreement: float | None   # share of Stage 2 radius decisions (baseline anchors) unchanged
    accepted: bool; reason: str
def quantize_state(state: TrustedKnowledgeState, *, bits: int) -> QuantizedState     # bits in QUANT_BITS; symmetric per-tensor
def dequantize_state(quantized: QuantizedState, *, template: TrustedKnowledgeState) -> TrustedKnowledgeState
def evaluate_quantized(state: TrustedKnowledgeState, *, bits: int, replay: Sequence[EpisodeSkeleton],
                       context_id: str) -> QuantizedCandidate
    # accepted iff recall drop <= QUANT_MAX_RECALL_DROP and FP-rate increase <= EPS_FP_RATE and agreement >= QUANT_MIN_AGREEMENT
```

What is quantised: BASELINE anchors (26 floats each), DETECTOR weights, the threshold. Motifs are
integer bitmasks and are not quantised. **Stated in advance:** most meaning features are {0, 1}, so
INT8 is expected to be lossless and the only effect a small size change; the measurement confirms or
refutes it. ONNX FP32/INT8/INT4 and RSS/PSS of an inference workspace are UNMEASURED (ADR-0050).

### HEL-F26 — `export_learning_record` `[lineage]`

```python
# pocketsec/stage6/export/learning_record.py
LEARNING_RECORD_V1_ID = "pocketsec.learning_record.v1"
LEARNING_RECORD_V1_VERSION = register_schema(LEARNING_RECORD_V1_ID, "1.0.0")
@dataclass(frozen=True, slots=True)
class LearningRecordV1:                # plain JSON, the Stage 5 handoff's shape and refusals
    record_id: str; trusted_digest: str; state_version: int; active_context: str
    items: tuple[Mapping[str, Any], ...]      # kind, pattern_key, motif bitmasks, weight, context_ids, status,
                                              #   candidate_id, evidence digest COUNT (not the digests), simulated flag
    fossil_hashes: tuple[str, ...]; tombstoned_fossils: int
    rollback_rows: tuple[Mapping[str, Any], ...]   # trigger, from_digest, to_digest, restored_bytes_identical
    lineage_intact: bool                      # lineage.verify() == ()
    privacy_class: str                        # always "PUBLIC_DERIVED": no signatures, no source groups, no ids of capsules
    simulated: bool                           # True if any contributing record or corpus was synthetic/simulated
    interface_version: str = LEARNING_RECORD_V1_VERSION
    def to_dict(self) -> dict[str, Any]       # refuses seam_violations(...) and authority_violations(...) != ()
    def digest(self) -> str
def export_learning_record(state: TrustedKnowledgeState, *, lineage: KnowledgeLineageDAG, fossils: FossilStore,
                           rollback_rows: Sequence[Mapping[str, Any]], simulated: bool) -> LearningRecordV1   # HEL-F26
```

`rollback_rows` are plain mappings (the controller passes `LearningRollback.to_dict()`), so this module
does not import `promotion/`. Stage 5's two screens are reused, not re-implemented.

### D6.19 — Optional fleet knowledge package protocol `[capsule]`

```python
# pocketsec/stage6/fleet/package.py
FLEET_EXCHANGE_ENABLED: bool = False            # architecture §36: no fleet export by default
KNOWLEDGE_PACKAGE_V1_ID = "pocketsec.knowledge_package.v1"
@dataclass(frozen=True, slots=True)
class KnowledgePackageV1:
    package_id: str; source_host: str; key_id: str; created_sequence: int
    items: tuple[Mapping[str, Any], ...]        # PUBLIC_DERIVED projections only; <= MAX_PACKAGE_ITEMS
    lineage_digests: tuple[str, ...]
    signature: str                               # hex HMAC-SHA256 over canonical bytes without signature
    schema_version: str
@dataclass(frozen=True, slots=True)
class PackageVerification: valid: bool; reasons: tuple[str, ...]; fleet_group: str
def sign_package(package: KnowledgePackageV1, *, key: bytes) -> KnowledgePackageV1
def verify_package(package: KnowledgePackageV1, *, keyring: Mapping[str, bytes]) -> PackageVerification
    # refuses: unsigned, unknown key_id, bad signature, unversioned, oversize (MAX_PACKAGE_BYTES), non-PUBLIC items
def package_to_capsules(package: KnowledgePackageV1, *, verification: PackageVerification, epoch: Epoch,
                        sequence: int, enabled: bool = FLEET_EXCHANGE_ENABLED) -> tuple[ExperienceCapsuleV1, ...]
    # FleetDisabledError unless enabled; kind FOREIGN_PACKAGE, source FOREIGN_HOST, label origin WEAK,
    # contamination FOREIGN_ORIGIN, independence_group = "fleet:" + key_id (duplicate hosts sharing a key are ONE vote)
```

Import side only: a package becomes capsules, and capsules go to `QuarantineGateway.admit` — they are
candidates, never authority. **HMAC is not host identity** (a shared symmetric key proves membership,
not which host signed); asymmetric signatures need a third-party library and are UNMEASURED. Stage 7
owns the real collective protocol.

### D6.20 — 60-experiment + month/year endurance benchmark `[foundation]` (catalogue) + `[endurance]` (harness)

```python
# pocketsec/stage6/labs/sixty_experiments.py                        [foundation]
class ExperimentStatus(StrEnum): EXECUTABLE, UNMEASURED
@dataclass(frozen=True, slots=True)
class Stage6Experiment: experiment_id: str      # "S6X-01" … "S6X-60", architecture §50 titles verbatim
                        title: str; deliverable: str; status: ExperimentStatus
                        runner: str | None       # dotted path "module:function", resolved lazily by importlib
                        limitation: str          # required non-empty for UNMEASURED; may be "" otherwise
SIXTY_EXPERIMENTS: tuple[Stage6Experiment, ...]  # exactly 60
def resolve_runners() -> tuple[str, ...]          # dotted paths that fail to resolve; () = all resolve
```

UNMEASURED rows, fixed now: S6X-13 (EWC/SI), S6X-14 (distillation), S6X-15 (adapter isolation) —
not applicable to a parameter-free learner (ADR-0050); S6X-39 neural backdoor half (the symbolic
trigger half is EXECUTABLE as arm P4c); S6X-52/53 ONNX half (the stdlib INT8/INT4 half is
EXECUTABLE). S6X-60 is EXECUTABLE with the limitation that Stages 3–5 participate only through
synthetic records built via their handoff types, not live.

```python
# pocketsec/stage6/labs/endurance_corpus.py                        [endurance]
ENDURANCE_VERSION = "stage6-endurance-v0.1.0"
class Month(IntEnum): M01 … M12        # architecture §51, one member per bullet
@dataclass(frozen=True, slots=True)
class EnduranceSession: session_id: str; month: int; scenario: Scenario; family: str | None; role: str
                        # role in {"routine","attack","twin","poison","eval"}; family/role are ACCOUNTING ONLY
@dataclass(frozen=True, slots=True)
class MonthPlan: month: int; identity: SystemIdentity; signal: SystemChangeSignal | None
                 sessions: tuple[EnduranceSession, ...]; eval_sessions: tuple[EnduranceSession, ...]
def build_endurance_timeline(*, months: int = 12, sessions_per_month: int = SESSIONS_PER_MONTH,
                             eval_per_family: int = EVAL_SESSIONS_PER_FAMILY, seed: int) -> tuple[MonthPlan, ...]
def build_year_timeline(*, cycles: int = YEAR_CYCLES, sessions_per_month: int, seed: int) -> tuple[MonthPlan, ...]
    # 60 months: the 12-month plan repeated with fresh session seeds and fresh identities per cycle
```

The §51 timeline, bound (families and twins are built with `make_actors`/`interleave`/
`session_behaviour` from `stage2/labs/drift_corpus.py`, session-unique identities, matched operation
composition across classes — integration plan §5.4):

| month | architecture §51 | what the corpus does |
|---|---|---|
| M01 | stable host | context A; routines; family **F1** (credential egress: `setuid → read CREDENTIAL → connect/send EXTERNAL`, one lineage) and twin **T1** (a backup agent: read CREDENTIAL → send loopback, one lineage) |
| M02 | software update | corroborated change (package+service) → context B; routines swap to pool B |
| M03 | benign workload expansion | new benign services (new objects/relations) — the FP load normality learning must absorb |
| M04 | slow poisoning attempt | arms P1, P1b, P2, P2b (§4.15) |
| M05 | new attack family | **F2** (privileged persistence: `setuid → write PERSISTENCE`, one lineage) and twin **T2** (package-manager transaction writing a unit file) |
| M06 | rollback to old stack | corroborated change back to context A's identity (new `epoch_id`, same key) |
| M07 | sensor change | a share of steps dropped / `observation_incomplete`; family **F3** (staging exfil: `write TEMP_LOCATION → connect EXTERNAL`) |
| M08 | recurring old attack | F1 again |
| M09 | benign rare admin | twin **T3** (admin `setuid → read CREDENTIAL`, no egress) with clean ANALYST BENIGN labels |
| M10 | targeted label poison | arm P3/P3b: BENIGN labels on F2 sessions |
| M11 | resource pressure | `ResourceSnapshot` above every §40 threshold for the month |
| M12 | mixed recurrence | F1 + F2 + F3 + T1–T3 |

```python
# pocketsec/stage6/labs/continual_baselines.py                     [endurance]
class Learner(Protocol):
    name: str
    def observe(self, capsule: ExperienceCapsuleV1, *, sequence: int) -> None
    def on_epoch(self, decision: EpochDecision, identity: SystemIdentity, *, sequence: int) -> None
    def consolidate(self, snapshot: ResourceSnapshot, *, sequence: int) -> None
    def score(self, steps: Sequence[EncodedStep], *, context_id: str) -> float
    def cost(self) -> LearnerCost                  # work_units, stored_bytes, trusted_bytes
    def trusted_digest(self) -> str
@dataclass(frozen=True, slots=True)
class LearnerCost: work_units: int; stored_bytes: int; trusted_bytes: int
class NeverUpdate, NaiveFinetune, ReservoirReplay, FullRetrain, PrototypeCentroid, CalibrationOnly   # §7
class Stage2Only                       # normality via Stage 2 buffer+controller straight into its state; detectors as NaiveFinetune
def oracle_detectors(timeline: Sequence[MonthPlan]) -> TrustedKnowledgeState   # E1 only: ground-truth motifs, unbounded

# pocketsec/stage6/labs/poison_suite.py                            [endurance]
POISON6_VERSION = "stage6-poison-v0.1.0"
class PoisonClass(StrEnum): DATA, LABEL, MODEL, SLOW_DRIFT
@dataclass(frozen=True, slots=True)
class PoisonArm: arm_id: str; poison_class: PoisonClass; title: str; attacks_mechanism: str
def build_poison_arm(arm_id: str, *, multiplier: int, seed: int) -> PoisonScenario
@dataclass(frozen=True, slots=True)
class PoisonScenario: arm: PoisonArm; clean: tuple[ExperienceCapsuleV1, ...]; poisoned: tuple[ExperienceCapsuleV1, ...]
                      signals: tuple[tuple[int, SystemChangeSignal], ...]   # (position, change)
POISON_ARMS6: tuple[PoisonArm, ...]    # §4.15 table
def simulated_teacher_labels(sessions: Sequence[EnduranceSession], *, error_share: float, seed: int) -> tuple[LabelAssertion, ...]

# pocketsec/stage6/labs/endurance.py                               [endurance]
@dataclass(frozen=True, slots=True)
class StageSixConfig: independence_check: bool = True; homeostasis: bool = True; plasticity_field: bool = True
                      half_life: bool = True; competition: bool = True; counterfactual_variants: bool = True
                      value_aware_rehearsal: bool = True; drift_discriminator: bool = True
                      resurrection: bool = True; detector_capacity: int = MAX_DETECTOR_ITEMS
class StageSixLearner                  # wires gateway→chamber→consolidator→controller with a StageSixConfig
@dataclass(frozen=True, slots=True)
class MonthCheckpoint: month: int; learner: str; acquisition: Mapping[str, float | None]
                       retention: Mapping[str, float | None]; fp_rate: float | None; store_bytes: Mapping[str, int]
                       store_counts: Mapping[str, int]; evictions: Mapping[str, int]; promotions: int; rollbacks: int
                       poisoned_promotions: int; clean_promotions: int; cost: LearnerCost
@dataclass(frozen=True, slots=True)
class EnduranceReport: timeline_version: str; seed: int; checkpoints: tuple[MonthCheckpoint, ...]
                       preconditions: PreconditionReport; synthetic: bool = True
@dataclass(frozen=True, slots=True)
class PreconditionReport: expressible: bool | None; saturated: bool | None; forgetting_pressure: bool | None
                          acquisition_need: bool | None; vocabulary_leak: bool | None; details: tuple[str, ...]
def compile_timeline(timeline: Sequence[MonthPlan]) -> CompiledTimeline   # Stage1Pipeline ONCE; capsules shared by all learners
def run_endurance(compiled: CompiledTimeline, learners: Sequence[Learner]) -> EnduranceReport
def check_preconditions(compiled: CompiledTimeline) -> PreconditionReport   # E1–E5
def run_poison_suite(*, multipliers: Sequence[int] = POISON_MULTIPLIERS, seed: int) -> PoisonReport
def run_ablation(compiled: CompiledTimeline) -> tuple[AblationRow, ...]
@dataclass(frozen=True, slots=True)
class AblationRow: core_id: str; flag: str; control: str; metric: str; full: float | None; ablated: float | None
                   delta: float | None; firing_count: int; verdict: str   # JUSTIFIED|NOT_YET_JUSTIFIED|HARMFUL|INERT|DEGENERATE|UNMEASURED
```

**Every learner receives identical input.** `compile_timeline` runs `Stage1Pipeline` once per
scenario (session-unique identities, own pipeline per timeline) and produces the capsule stream and
labelled eval sessions; learners never touch Stage 1. All learners use `induce_motifs` and
`score_session`, so a difference between two learners is the mechanism under test, never the
representation.

### 4.15 The poisoning arms `[endurance]` builds and `[gateway]` defends

"A defence that has never been attacked in a test is a docstring." Every arm runs against the
Stage 6 learner **and** three controls — `NaiveFinetune` (no gate), `Stage2Only` (Stage 2's gate
alone) and accept-nothing — at every multiplier in `POISON_MULTIPLIERS`.

| arm | class | the attack | mechanism it targets | Stage 2 expected |
|---|---|---|---|---|
| P1 | DATA | one attacker lineage repeats an escalation-free staging step across ≥ 2 corroborated epochs (the §0 probe, scaled) | source independence | **promotes** (measured, §0) |
| P1b | DATA | fork-spray: the same step from `MIN_INDEPENDENT_GROUPS + 1` short-lived child lineages | source independence — attacked | promotes |
| P2 | SLOW_DRIFT | Stage 2's slow-drift walk spread over epochs, then continued after the change | fixed anchor + homeostasis | refuses (anchor) |
| P2b | SLOW_DRIFT | timed anchor capture: the attacker's first escalation-free sample lands immediately after a genuine corroborated upgrade (Stage 2's stated residual risk) | Stage 6 independence + G5 | promotes the captured anchor |
| P3 | LABEL | ANALYST-origin BENIGN assertions on F2 sessions, one analyst group, many episodes | label quorum + homeostasis | n/a (Stage 2 has no label path) |
| P3b | LABEL | `simulated_teacher_labels` with a systematic error share on F1/F2 | teacher-is-weak rule | n/a |
| P4a | MODEL | a candidate whose proposed-state bytes are altered after the chamber issued it | G1 integrity | n/a |
| P4b | MODEL | a fossil file corrupted on disk before a rollback | fossil integrity + fallback | n/a |
| P4c | MODEL | symbolic trigger: a BASELINE whose radius/anchor is crafted to explain exactly an attack's staging step (near-miss mimicry) | G5 + trigger concentration | n/a |
| P5 | SLOW_DRIFT | epoch manipulation: repeated **uncorroborated** identity changes to force retirement | Stage 1 corroboration + registry | refuses |
| P6 | DATA | quarantine flooding: > capacity novel signatures to evict legitimate candidates and bias exemplar selection | bounded, refuse-not-evict, value-aware episodic eviction | refuses newcomers |

Per arm the report carries: poisoned capsules offered (**must be > 0 — the arm fired**), poisoned
promotions and rate, clean promotions and rate, and the same for each control. **An arm on which
`NaiveFinetune` promotes nothing is `DEGENERATE`** — the attack was not real, and it fails G6.9.
An arm on which `Stage2Only` already promotes nothing attributes its defence to Stage 2, and Stage 6
is reported as adding nothing on it (§8, F8).

### 4.20 The endurance preconditions — checked before any retention number is believed

Synthetic corpora in this repository saturate (ADR-0010), and §0 measured that the only drift corpus
is solved by a zero-learning ΔΦ score and by one hand-written motif. `check_preconditions` therefore
gates every anti-forgetting and ablation figure:

| id | precondition | measured by | if it fails |
|---|---|---|---|
| E1 | **expressibility**: `oracle_detectors` reaches recall ≥ `EXPRESSIBLE_RECALL` at the FPR budget on every family | `score_session` + `confusion_at_threshold` | **BLOCKED** — the representation cannot express the task; no learner result is reported |
| E2 | **non-saturation**: per-lineage cumulative-ΔΦ control, any-escalation rule and `NeverUpdate` each have AP ≤ `SATURATION_AP` over the full eval set | `average_precision` | `DEGENERATE` — learning is not needed on this corpus |
| E3 | **forgetting pressure**: `NaiveFinetune` retention on F1 at M12 ≤ `NeverUpdate`'s − `FORGETTING_MIN_DROP` at the tight capacity | endurance checkpoints | anti-forgetting `DEGENERATE` |
| E4 | **acquisition need**: `NeverUpdate` acquisition on F2 and F3 ≤ `ACQUISITION_NEED_MAX` | endurance checkpoints | anti-forgetting `DEGENERATE` (never-update already wins) |
| E5 | **no vocabulary leak**: a bag-of-operations (order-free, per-session relation counts) control's AP within `VOCABULARY_LEAK_MAX` of the base rate | `average_precision` | corpus defect: fix the corpus, report nothing |

The endurance engineer builds the twins so E2 can hold (a twin must look like its family to ΔΦ and to
the generic motif, and differ only in a bit a refined motif can require or forbid). **If E2 cannot be
made to hold, that is the finding** and is reported, never worked around by weakening the control.

### 4.21 The constant table, and three rules that bind every package

Every bound in one place. **A literal at a use site is a defect**; import the constant. **Every value
below is a chosen parameter, not a measurement**, and the findings list them under `PARAMETERS`.

| constant | value | module |
|---|---|---|
| `MIN_INDEPENDENT_GROUPS` / `MIN_INDEPENDENT_LABEL_GROUPS` | 3 / 2 | `constitution/learning.py` |
| `STAGE6_NORMAL_INCREMENTAL_RSS_BYTES` / `STAGE6_INCREMENTAL_CEILING_BYTES` | 57671680 / 104857600 (§39: 55 MiB / 100 MiB) | `resources.py` |
| `QUARANTINE_META_BUDGET_BYTES` / `EPISODIC_BUDGET_BYTES` / `SEMANTIC_PROCEDURAL_BUDGET_BYTES` / `LINEAGE_FOSSIL_META_BUDGET_BYTES` / `CONSOLIDATION_WORKSPACE_BUDGET_BYTES` | 15 / 15 / 20 / 10 / 15 MiB (normal); peaks 25 / 25 / 30 / 15 / 35 MiB | `resources.py` |
| `STAGE6_DISK_BUDGET_BYTES` | 500 MiB | `resources.py` |
| `CONSOLIDATION_MAX_MEMORY_PRESSURE` / `_MAX_CPU_LOAD` / `_MAX_URGENCY` / `_MIN_DISK_FREE_BYTES` | 0.8 / 0.8 / 0.5 / 64 MiB | `resources.py` |
| `MAX_STEPS_PER_CAPSULE` / `MAX_EVIDENCE_REFS_PER_CAPSULE` / `MAX_EVIDENCE_PER_STEP` / `MAX_PROCEDURE_ROWS` / `MAX_CAPSULE_BYTES` / `FEATURE_DECIMALS` | 64 / 32 / 4 / 16 / 65536 / 6 | `capsule/experience_capsule.py` |
| `MAX_TRUST_RECORDS` | 4096 | `provenance/ledger.py` |
| `MIN_PROVENANCE_SCORE` | 0.5 | `provenance/trust.py` |
| `MAX_ISSUED_VERDICTS` / `MAX_CANDIDATE_REGISTER` / `MAX_PATTERNS_TRACKED` / `MAX_GROUPS_TRACKED_PER_PATTERN` / `MAX_PENDING_LABEL_EPISODES` | 4096 / 64 / 512 / 16 / 256 | `capsule/quarantine.py` |
| `HOSTILE_DEPENDENCE` / `HOSTILE_TRIGGER_CONCENTRATION` / `HOSTILE_LABEL_SHIFT` / `MAX_LABEL_HISTORY` | 0.8 / 0.5 / 0.5 / 512 | `homeostasis/poisoning.py` |
| `MAX_KNOWLEDGE_CONTEXTS` / `DRIFT_ALIGN_WINDOW` | 16 / 64 | `homeostasis/drift.py` |
| `MAX_DETECTOR_ITEMS` / `MAX_BASELINE_ITEMS` / `MAX_PROCEDURE_ITEMS` / `MAX_REHEARSAL_EXEMPLARS` / `MAX_TRUSTED_STATE_BYTES` | 64 / 128 / 64 / 128 / 1048576 | `memory/semantic.py` |
| `MAX_MOTIF_LENGTH` / `MAX_ITEM_CAPSULE_REFS` / `UNEXPLAINED_WEIGHT` / `DEFAULT_THRESHOLD` | 2 / 16 / 0.5 / 0.5 | `memory/semantic.py` |
| `MAX_EPISODES` / `MAX_HOSTILE_EPISODES` / `MAX_EPISODIC_BYTES` / `MAX_SKELETON_STEPS` / `MAX_SKELETON_BYTES` / `MAX_EVICTION_LOG` | 512 / 64 / 4194304 / 32 / 8192 / 128 | `memory/episodic.py` |
| `HALF_LIFE_H0` / `RETIRE_TRUST_FLOOR` | 2048 / 0.05 | `memory/half_life.py` |
| `PLASTICITY_FLOOR` | 0.05 | `plasticity/field.py` |
| `MAX_ITEM_MUTATIONS` / `MAX_THRESHOLD_DELTA` / `MASK_EXPIRY_SEQUENCES` | 4 / 0.10 / 512 | `plasticity/masks.py` |
| `MAX_VARIANTS_PER_EPISODE` | 5 | `rehearsal/counterfactual.py` |
| `MAX_FOSSILS` / `MAX_PINNED_FOSSILS` / `MAX_FOSSIL_BYTES` / `MAX_TOMBSTONES` | 32 / 4 / 16777216 / 256 | `fossils/store.py` |
| `MAX_LINEAGE_NODES` / `MAX_LINEAGE_EDGES` / `MAX_TOMBSTONE_IDS` | 8192 / 16384 / 1024 | `fossils/lineage.py` |
| `MAX_CHAMBER_CAPSULES` / `MAX_CHAMBER_WORK_UNITS` / `MAX_MOTIF_CANDIDATES_PER_EPISODE` / `MIN_DETECTOR_PRECISION` / `HOLDOUT_SHARE` | 128 / 500000 / 16 / 0.9 / 0.25 | `chamber/evolution.py` |
| `CONSOLIDATION_PERIOD` / `MAX_DORMANT_SEQUENCES` | 64 / 8192 | `consolidator/mnemosyne.py` |
| `EPS_SECURITY` / `MIN_UTILITY_GAIN` / `EPS_FP_RATE` / `EPS_BRIER` / `EPS_COUNTERFACTUAL` / `MAX_STATE_GROWTH_BYTES` | 0.02 / 0.01 / 0.01 / 0.02 / 0.05 / 65536 | `conservation/gate.py` |
| `SHADOW_SAMPLE_EVERY` / `MIN_SHADOW_SESSIONS` / `MAX_SHADOW_WORK_UNITS` / `MAX_SHADOW_BYTES` / `MAX_SHADOW_DISAGREEMENT` | 4 / 32 / 200000 / 8388608 / 0.10 | `shadow/mind.py` |
| `CANARY_SHARE` / `CANARY_WINDOW_SESSIONS` / `CANARY_MAX_FP_INCREASE` / `PROBATION_SESSIONS` / `MAX_PROTECTED_REGRESSIONS` | 0.10 / 64 / 0.02 / 128 / 0 | `shadow/canary.py` |
| `MAX_DECISION_LOG` / `MAX_ROLLBACK_LOG` | 256 / 64 | `promotion/controller.py` |
| `QUANT_BITS` / `QUANT_MAX_RECALL_DROP` / `QUANT_MIN_AGREEMENT` | (8, 4) / 0.01 / 0.99 | `export/quantized_candidates.py` |
| `FLEET_EXCHANGE_ENABLED` / `MAX_PACKAGE_BYTES` / `MAX_PACKAGE_ITEMS` | False / 65536 / 64 | `fleet/package.py` |
| `FPR_BUDGET` | 0.05 | `labs/endurance.py` (every recall figure is at this FPR) |
| `SESSIONS_PER_MONTH` / `EVAL_SESSIONS_PER_FAMILY` / `YEAR_CYCLES` / `ENDURANCE_SEED` | 16 / 8 / 5 / 11 | `labs/endurance_corpus.py` |
| `CAPACITY_SWEEP` / `REPLAY_BUDGETS_BYTES` / `POISON_MULTIPLIERS` | (4, 8, 64) / (16384, 65536, 262144) / (1, 4, 16) | `labs/endurance.py` |
| `EXPRESSIBLE_RECALL` / `SATURATION_AP` / `FORGETTING_MIN_DROP` / `ACQUISITION_NEED_MAX` / `VOCABULARY_LEAK_MAX` | 0.9 / 0.9 / 0.10 / 0.5 / 0.05 | `labs/endurance.py` |

**Rule A — key-space identity (the S2-FC-01 class, twice shipped).** Every keyed join ships a test
asserting its two key spaces are structurally identical:

| key | producer | consumer | test |
|---|---|---|---|
| Stage 2 `pattern_key` | `QuarantineGateway` normality path, `CandidateAdmission.pattern_key` | `KnowledgeItem.pattern_key` (BASELINE), `score_session` baseline lookup | `test_baseline_key_is_stage2_pattern_key` |
| `context_id_for(identity)` | `capsule.context_id`, `KnowledgeContext.context_id` | `KnowledgeItem.context_ids`, `score_session(context_id=…)` | `test_context_key_is_one_function` |
| `capsule_id` | `ExperienceCapsuleV1` | `TrustRecord.capsule_id`, `ItemLineage.capsule_ids`, DAG `CAPSULE` node ids, `EpisodeSkeleton.episode_id` | `test_capsule_id_is_the_same_string_everywhere` |
| `TrustedKnowledgeState.digest()` | `TrustedMind.digest()` | `KnowledgeFossil.artifact_hash`, `EvolutionCandidate.base_digest`, `LearningRollback.to_digest` | `test_state_digest_is_the_fossil_hash` |

**Rule B — a check must exercise the mechanism it names.** Every `_check_*` in `gate.py` calls at least
one function that performs work, and `tests/test_stage6_gate.py::test_every_gate_check_can_fail`
constructs, per check, one non-compliant fixture that makes it report FAILED.

**Rule C — prove each mechanism fires before measuring it (the Stage 4 lesson).** Every OPTIONAL
`HEL-F*` reports a **firing count** — how many times it changed an outcome relative to its simple
control on the real run. A mechanism with firing count 0 is reported `INERT`, never "measured", and
its ablation delta is not quoted as evidence. Each firing count's definition is fixed in §4 above.

### 4.22 `core_ids.py` and `resources.py` `[foundation]`

```python
# pocketsec/stage6/core_ids.py — copies stage2/core_ids.py's shape
class FunctionClass(StrEnum): REQUIRED, OPTIONAL
@dataclass(frozen=True, slots=True)
class Stage6Function: core_id: str; architecture_id: str; name: str; symbol: str   # "module:qualname", resolvable
                      function_class: FunctionClass; ablation_flag: str | None; simple_control: str | None
STAGE6_FUNCTIONS: tuple[Stage6Function, ...]   # exactly 26, HEL-F01..HEL-F26 <-> S6-F01..S6-F26
PINNED_SCHEMAS: Mapping[str, str]              # the five upstream ids of §0 -> "1.0.0"
def resolve_symbols() -> tuple[str, ...]       # unresolvable symbols; () = all resolve
def optional_functions() -> tuple[Stage6Function, ...]
```

| core id | S6 id | function | symbol | class | ablation flag → control |
|---|---|---|---|---|---|
| HEL-F01 | S6-F01 | build_experience_capsule | `capsule.experience_capsule:build_experience_capsule` | REQUIRED | — |
| HEL-F02 | S6-F02 | quarantine_experience | `capsule.quarantine:QuarantineGateway.admit` | REQUIRED | — |
| HEL-F03 | S6-F03 | score_provenance | `provenance.trust:score_provenance` | REQUIRED | — |
| HEL-F04 | S6-F04 | detect_evidence_dependence | `provenance.trust:detect_evidence_dependence` | REQUIRED | `independence_check` → off (ablated anyway, §7) |
| HEL-F05 | S6-F05 | estimate_poison_suspicion | `homeostasis.poisoning:estimate_poison_suspicion` | REQUIRED | — |
| HEL-F06 | S6-F06 | admit_episode | `memory.episodic:EpisodicMemory.admit_episode` | REQUIRED | — |
| HEL-F07 | S6-F07 | update_epistemic_half_life | `memory.half_life:update_epistemic_half_life` | OPTIONAL | `half_life` → LRU |
| HEL-F08 | S6-F08 | compute_plasticity_field | `plasticity.field:compute_plasticity_field` | OPTIONAL | `plasticity_field` → `uniform_mask` |
| HEL-F09 | S6-F09 | generate_plasticity_mask | `plasticity.masks:generate_plasticity_mask` | REQUIRED | — |
| HEL-F10 | S6-F10 | compete_knowledge | `memory.competition:compete_knowledge` | OPTIONAL | `competition` → NEWEST_WINS |
| HEL-F11 | S6-F11 | generate_counterfactual_replay | `rehearsal.counterfactual:generate_counterfactual_replay` | OPTIONAL | `counterfactual_variants` → plain replay |
| HEL-F12 | S6-F12 | create_fossil | `fossils.store:FossilStore.create_fossil` | REQUIRED | — |
| HEL-F13 | S6-F13 | update_lineage_dag | `fossils.lineage:KnowledgeLineageDAG.update_lineage_dag` | REQUIRED | — |
| HEL-F14 | S6-F14 | spawn_evolution_candidate | `chamber.evolution:EvolutionChamber.spawn_evolution_candidate` | REQUIRED | — |
| HEL-F15 | S6-F15 | consolidate_memory | `consolidator.mnemosyne:MnemosyneConsolidator.consolidate_memory` | OPTIONAL | `value_aware_rehearsal` → reservoir |
| HEL-F16 | S6-F16 | run_shadow_mind | `shadow.mind:ShadowMind.run_shadow_mind` | REQUIRED | — |
| HEL-F17 | S6-F17 | run_conservation_gate | `conservation.gate:offline_validation` | REQUIRED | — |
| HEL-F18 | S6-F18 | detect_semantic_normalization_attack | `homeostasis.poisoning:detect_semantic_normalization_attack` | REQUIRED | `homeostasis` → Stage 2 anchors only (ablated anyway) |
| HEL-F19 | S6-F19 | classify_drift_vs_poisoning | `homeostasis.drift:classify_drift_vs_poisoning` | OPTIONAL | `drift_discriminator` → "corroborated ⇒ legitimate" |
| HEL-F20 | S6-F20 | open_new_epoch | `homeostasis.drift:KnowledgeContextRegistry.open_new_epoch` | REQUIRED | — |
| HEL-F21 | S6-F21 | resurrect_dormant_knowledge | `homeostasis.drift:KnowledgeContextRegistry.resurrect_dormant_knowledge` | OPTIONAL | `resurrection` → relearn |
| HEL-F22 | S6-F22 | promote_canary | `promotion.controller:LearningPromotionController.promote_canary` | REQUIRED | — |
| HEL-F23 | S6-F23 | promote_trusted | `promotion.controller:LearningPromotionController.promote_trusted` | REQUIRED | — |
| HEL-F24 | S6-F24 | rollback_learning | `promotion.controller:LearningPromotionController.rollback_learning` | REQUIRED | — |
| HEL-F25 | S6-F25 | melt_or_retire_knowledge | `consolidator.mnemosyne:MnemosyneConsolidator.melt_or_retire_knowledge` | OPTIONAL | `half_life` → LRU retire |
| HEL-F26 | S6-F26 | export_learning_record | `export.learning_record:export_learning_record` | REQUIRED | — |

```python
# pocketsec/stage6/resources.py
class WorkBudgetExceeded(RuntimeError): ...
class WorkMeter:                       # deterministic cost; the primary cost measure (ADR-0033 precedent)
    def __init__(self, *, budget: int | None = None) -> None
    def charge(self, units: int = 1) -> None            # raises WorkBudgetExceeded past budget
    @property
    def spent(self) -> int
@dataclass(frozen=True, slots=True)
class ResourceSnapshot:                # architecture §40, each condition a field
    memory_pressure: float; cpu_load: float; incident_urgency: float; disk_free_bytes: int; thermal_ok: bool
    @classmethod
    def capture(cls, *, incident_urgency: float = 0.0) -> ResourceSnapshot   # /proc/meminfo, loadavg/cpu_count, statvfs
@dataclass(frozen=True, slots=True)
class StoreBudget: name: str; normal_bytes: int; peak_bytes: int
STORE_BUDGETS: tuple[StoreBudget, ...] # the five §39 rows
def loadavg() -> tuple[float, float, float]            # /proc/loadavg; Stage 6's own (it may not import stage5.resources)
@dataclass(frozen=True, slots=True)
class Stage6ResourceReport: metrics: ResourceMetrics; profile: ProfileReport; incremental_rss_bytes: int | None
                            within_ceiling: bool | None; store_bytes: Mapping[str, int]; loadavg: tuple[float, float, float]
def measure_stage6_resources(work: Callable[[], Mapping[str, int]], *, events: int) -> Stage6ResourceReport
    # runs work() inside ResourceSampler; work returns per-store memory_bytes; within_ceiling is None when RSS is unavailable
```

### 4.23 Integrator-owned: `gate.py`, `cli.py`, `__init__.py`

`gate.py` follows `stage5/gate.py`: a module docstring stating the gate is expected to fail G6.13 and
why; `STAGE6_HYPOTHESIS = "H6"`; `EXPERIMENT_ID`; `Stage6GateContext.build()` (one compile, one
endurance run per learner, one 60-month run, one poison-suite run, a temporary registry);
`run_gate() -> GateReport` with thirteen `_check_*` in §6 order. `cli.py`:
`main(argv: Sequence[str] | None = None) -> int`, `--json`, a required subparser with `gate`,
`endurance`, `poison`, `ablation`, `resources`, `export` and `experiments` (the only command that
appends to `experiments/registry.jsonl`, ids `PS-S6-<date>-H6-<slug>-NNNN` / `-H8-` for ablation
rows). `tests/test_stage6_gate.py` asserts 13 checks, `test_every_gate_check_can_fail`, and that the
registry is byte-identical across a gate run.

---

## 5. Work packages

Eight packages. **No two share a file.** `pocketsec/stage6/{__init__.py, gate.py, cli.py}`,
`tests/test_stage6_gate.py`, `docs/stage-6-findings.md`, the ADR files 0050–0059, `pyproject.toml`
and `.github/workflows/ci.yml` are **integrator-owned** and in no package. Each package owns the
empty `__init__.py` of every subsystem directory it is first to populate (listed).

| # | key | delivers | owns (under `pocketsec/stage6/` unless shown) | depends on | ≈ lines incl. tests |
|---|---|---|---|---|---|
| 1 | `foundation` | D6.1, D6.20 catalogue, §39/§40 governor (§4.22) | `core_ids.py`, `resources.py`, `constitution/__init__.py`, `constitution/learning.py`, `labs/__init__.py`, `labs/sixty_experiments.py`, `tests/test_stage6_foundation.py`, `tests/test_stage6_boundary.py`; deletes `helios/`, `learning/`, `mnemosyne/`, `quarantine/` | — | 1300 |
| 2 | `capsule` | D6.2 (types), D6.3, D6.19 | `capsule/__init__.py`, `capsule/experience_capsule.py`, `provenance/__init__.py`, `provenance/ledger.py`, `provenance/trust.py`, `fleet/__init__.py`, `fleet/package.py`, `tests/test_stage6_capsule.py` | foundation | 1300 |
| 3 | `memory` | D6.4, D6.5 | `memory/__init__.py`, `memory/semantic.py`, `memory/episodic.py`, `memory/procedural.py`, `memory/half_life.py`, `tests/test_stage6_memory.py` | foundation, capsule | 1300 |
| 4 | `lineage` | D6.8, D6.9, D6.10, D6.18, HEL-F26 | `rehearsal/__init__.py`, `rehearsal/counterfactual.py`, `fossils/__init__.py`, `fossils/store.py`, `fossils/lineage.py`, `export/__init__.py`, `export/quantized_candidates.py`, `export/learning_record.py`, `tests/test_stage6_lineage.py` | foundation, capsule, memory | 1400 |
| 5 | `gateway` | D6.2 (gateway), D6.15, D6.16 | `capsule/quarantine.py`, `homeostasis/__init__.py`, `homeostasis/poisoning.py`, `homeostasis/drift.py`, `tests/test_stage6_gateway.py` | foundation, capsule, memory, lineage | 1300 |
| 6 | `evolution` | D6.6, D6.7, D6.11, D6.12 | `plasticity/__init__.py`, `plasticity/field.py`, `plasticity/masks.py`, `memory/competition.py`, `chamber/__init__.py`, `chamber/evolution.py`, `consolidator/__init__.py`, `consolidator/mnemosyne.py`, `tests/test_stage6_evolution.py` | foundation, capsule, memory, lineage, gateway | 1450 |
| 7 | `promotion` | D6.13, D6.14, D6.17 | `conservation/__init__.py`, `conservation/gate.py`, `shadow/__init__.py`, `shadow/mind.py`, `shadow/canary.py`, `promotion/__init__.py`, `promotion/controller.py`, `tests/test_stage6_promotion.py` | all of 1–6 | 1450 |
| 8 | `endurance` | D6.20 harness, §4.15 attacks, §7 baselines | `labs/endurance_corpus.py`, `labs/poison_suite.py`, `labs/continual_baselines.py`, `labs/endurance.py`, `tests/test_stage6_endurance.py` | all of 1–7 | 1600 |

**Build order is package order.** Packages 1–5 plus 7 carry the security boundary; package 8 does not
start until `tests/test_stage6_{foundation,boundary,capsule,memory,lineage,gateway,promotion}.py`
pass. Packages build in parallel against the signatures in §4; a package that finds a signature it
depends on unworkable reports it to the integrator rather than changing another package's file. Line
figures are budgets; a package that overruns splits functions, not features.

### 5.1 `tests/test_stage6_boundary.py` — owned by `foundation`

The AST rules, for Stage 6 only, using `pocketsec.stage2.gate_criteria.imported_modules`
(`gate_criteria.py:547`) as the one resolver. `tests/test_repository_structure.py` is read for the
technique and never edited.

1. **R1 / ADR-0001.** Every module under `pocketsec/stage6/` imports only roots in
   `sys.stdlib_module_names` or `pocketsec`.
2. **R2 / ADR-0008 + ADR-0050.** No module under `pocketsec/stage6/` imports any
   `pocketsec.stage*.research*`, and `pocketsec/stage6/research/` does not exist.
3. **Upstream allow-list (§2.5, ADR-0053).** Stage 2 imports limited to the four runtime modules (and
   the two lab modules, from `stage6/labs/` only); Stage 3 none; Stage 4 only `stage5_interface`;
   Stage 5 only `stage6_interface`; Stages 7–12 only from `capsule/quarantine.py` (T3).
4. **Single writer (ADR-0052).** Across **all of `pocketsec/`**: an `ast.Attribute` or `ast.Name` or
   `def` named `_install_trusted` or `_trusted_state` appears only in `promotion/controller.py`; a
   call constructing `TrustedMind(...)` appears only there.
5. **Gateway seal.** Names `_issue_verdict` / `_issued_verdicts` appear only in
   `capsule/quarantine.py`; `_issue_candidate` / `_issued_candidates` only in `chamber/evolution.py`;
   `_issue_decision` / `_issued_decisions` only in `promotion/controller.py`.
6. **Runtime never imports labs.** No module under `pocketsec/stage6/` outside `labs/` imports
   `pocketsec.stage6.labs`.
7. **T5.** No `@dataclass` class under `pocketsec/stage6/` has an annotated field whose lowercased name
   contains a `FORBIDDEN_AUTHORITY_FIELDS` member (enum members are not fields). No exemption list.
8. **No earlier stage depends on Stage 6.** No module under `pocketsec/stage0/`…`stage5/` imports
   `pocketsec.stage6`.
9. **No second harness, ledger, contracts or corpus type.** No directory under `pocketsec/stage6/`
   named `contracts`, `benchmark`, `experiments` or `research`; no `def run_benchmark`,
   `class ExperimentRegistry`, `class Scenario` or `class Behaviour`.
10. **No empty package (ADR-0121)** and `helios/`, `learning/`, `mnemosyne/`, `quarantine/` do not
    exist.
11. **No second Stage 2 gate.** No module under `pocketsec/stage6/` defines a function containing the
    identifiers `min_epochs` or `delay_sequences` as parameters — those belong to Stage 2's objects,
    which Stage 6 composes (ADR-0051).

A committed negative fixture accompanies rules 1–3 and 6: the checker must catch
`from ..stage2.research import x`, `from . import research`, `from ...stage3.cells import schema`
and `from ..labs import endurance`, because relative imports were invisible to two checkers at once in
Stage 2 (S2-AUTH-01).

---

## 6. Acceptance gate, as executable checks

Thirteen checks, one per bullet of architecture §52, in its order. Integration plan §5.1 fixes the
count. `Stage6GateContext.build()` compiles the 12-month timeline once, runs every learner on it once,
runs the 60-month plateau run and the poison suite once, so thirteen checks do not replay them
(`stage1/gate.py:55` shape). Every check runs the real subsystem.

| id | §52 criterion | executable check | met on synthetic data? |
|---|---|---|---|
| **G6.1** | Raw telemetry cannot directly modify trusted cognition | (a) Boundary rules 4, 5 and 11 evaluated in-gate; `verify_constitution() == ()`. (b) Six injections, each refused **and** `mind.digest()` unchanged across all six: an `EncodedTransition` passed to `controller.submit` (`ContractError`/`TypeError`); a hand-built `QuarantineVerdict(bucket=TRUSTED_CANDIDATE)` to `chamber.spawn_evolution_candidate` (`UnquarantinedInputError`); a hand-built `EvolutionCandidate` to `submit` (not chamber-issued); the §0 single-source probe driven through `QuarantineGateway.admit` (reason `single_source_repetition`, 0 admissions); `TrustedKnowledgeState.from_canonical_bytes` of a state holding a lineage-less item (`LineageError`); `controller.rollback_learning(trigger=OPERATOR_REQUEST, to_digest=<digest of a state this controller never fossilised>)` (refused: a rollback may only restore a fossil this store verifies). The forged-decision call to the private installer is **not** made from `gate.py` — boundary rule 4 forbids naming it anywhere under `pocketsec/` — and lives in `tests/test_stage6_promotion.py::test_private_installer_refuses_an_unminted_decision`. (c) An exception injected inside the chamber leaves the digest unchanged. **PASS: 6/6 refused, 0 digest changes, (a) and (c) clean** | yes |
| **G6.2** | Every promoted knowledge object has complete provenance and lineage | After the 12-month Stage 6 run: every item in `mind.current()` satisfies `lineage.lineage_complete(item)` (**100%**, count reported); every `PROMOTION` node has `CANDIDATE`, `CONSERVATION`, `SHADOW`, `CANARY` parents; every capsule id an item cites is a live `CAPSULE` node with a `VERDICT` child (reachability collection never folds live lineage, even after the provenance ledger has evicted the `TrustRecord`); `lineage.verify() == ()`. Tamper probe: alter one edge's `reason` in a copy → `verify()` non-empty. Load probe: a state with one item lacking lineage → `LineageError` | yes |
| **G6.3** | Critical historical security capabilities remain within predefined regression bounds | Across every promotion of the 12-month run: per-family rehearsal recall after ≥ before − `EPS_SECURITY` for F1, F2, F3 (families are accounting labels read from the corpus, never from state); violations **0**. Firing proof: the gate submits a candidate that removes the F1 detector and asserts G2 refuses it. Reports G2 refusals over the run | yes (synthetic families only, §6.1) |
| **G6.4** | Slow malicious repetition cannot simply become normal through frequency | Arms P1 and P2 at every multiplier in `POISON_MULTIPLIERS`: Stage 6 poisoned promotions **0** at every multiplier; `NaiveFinetune` poisoned promotions > 0 and non-decreasing in the multiplier (the attack is real and the knob moves it); Stage 6 clean promotions > 0 (not accept-nothing). `Stage2Only`'s counts reported beside them | yes |
| **G6.5** | Legitimate epoch changes can adapt without destroying old recurring knowledge | From the 12-month run: (a) after M02, benign FP rate returns within `EPS_FP_RATE` of M01's inside `PROBATION_SESSIONS`+`CANARY_WINDOW_SESSIONS` sessions — time-to-adapt is an `int`, `None` fails; (b) context A's baselines are resident as dormant items or held in a verified `CONTEXT_DORMANCY` fossil; (c) at M06, context A applies again — resurrection fired ≥ 1 at `detector_capacity = CAPACITY_SWEEP[0]`, or A's items were still resident (reported `INERT` for resurrection, not a failure of (c)); (d) F1 retention at M08 ≥ F1 acquisition at M01 − `EPS_SECURITY`; (e) arm P5: contexts opened and items retired by uncorroborated changes **0** | yes (mechanism; real upgrade drift UNMEASURED, §6.1) |
| **G6.6** | Candidate models/cells are evaluated in isolation before influence | Every `PROMOTION` in the run is preceded, in the decision log, by `OFFLINE_VALIDATED`, `SHADOW` with `sessions_sampled ≥ MIN_SHADOW_SESSIONS`, and `CANARY` with `window_complete`; `require_transition(CANDIDATE, TRUSTED)` raises; a candidate's `proposed` state is a distinct value from the trusted one and mutating the chamber's inputs cannot change `mind.digest()`; a REJECTED candidate leaves the digest unchanged | yes |
| **G6.7** | Shadow/canary failure cannot grant Stage 5 authority | (a) Boundary rules 3, 7, 8. (b) Force a shadow over-budget (`work_budget=1`) and a canary regression: the reports are `aborted` / `regressed`, `authority_violations(report.to_dict()) == ()` and `seam_violations(...) == ()` for every Shadow/Canary/Conservation/LearningRecord payload. (c) Over every canary observation of the run, `emitted ≥ trusted_score` — a canary adds evidence, never suppresses. (d) No Stage 6 module is imported by any Stage 5 module | yes — construction |
| **G6.8** | Learning rollback restores a known-good cognitive state | Promote a candidate that passes offline gates but regresses live: the rehearsal set lacks F3 and the candidate drops the F3 detector (this also demonstrates G2's rehearsal-gap limit); probation traffic contains F3. PASS requires: **1 automatic rollback** (via `observe_probation`, never an explicit call), `mind.digest() == pre-promotion digest`, `restored_bytes_identical is True`, the candidate's REJECTION and ROLLBACK nodes present. Then corrupt the newest fossil on disk and roll back: `FOSSIL_CORRUPTION` recorded, the corrupted hash in `skipped_fossils`, the restored state the next known-good, byte-identical to its fossil | yes |
| **G6.9** | Poisoning tests include data, label, model and slow-drift attacks | `run_poison_suite` over all eleven arms of §4.15: each `PoisonClass` has ≥ 1 arm; every arm offered > 0 poisoned capsules (fired); `NaiveFinetune` promotes > 0 on every DATA/LABEL/SLOW_DRIFT arm (else `DEGENERATE`); every MODEL arm refused by construction; Stage 6 poisoned promotions **0 on every arm**; Stage 6 clean promotion rate > 0. Reports the full arm × learner × multiplier table. **P1b (fork-spray) is included and may fail this check; if it does, that is the finding** | yes |
| **G6.10** | Endpoint adaptation stays within the Stage 0 resource envelope | `measure_stage6_resources()` runs the 12-month Stage 6 loop inside `ResourceSampler`: incremental RSS ≤ `STAGE6_INCREMENTAL_CEILING_BYTES`, reported against the 55 MiB normal target; `check_profile(..., "edge")`; every store's `memory_bytes()` ≤ its §39 budget at every checkpoint; M11 deferred consolidation ≥ 1 and no session went unscored. RSS unavailable ⇒ `within_target is None` ⇒ **UNMEASURED ⇒ FAIL**, never PASS. Wall clock recorded with `/proc/loadavg`, not asserted | yes (in-process on the dev host; device figures UNMEASURED) |
| **G6.11** | Full retraining/distillation remains off-endpoint unless measurement proves otherwise | (a) Construction: no runtime module imports `labs`; `spawn_evolution_candidate` refuses > `MAX_CHAMBER_CAPSULES`; no runtime function takes an unbounded history (episodic memory is capped). (b) Measured and reported, not asserted: `FullRetrain`'s `stored_bytes` and `work_units` over the 12-month run against Stage 6's, as within-run ratios. If `FullRetrain` fits every §39 budget, the detail says the architecture's "unless measurement proves otherwise" clause was triggered and the findings must discuss it. **PASS iff (a)** | yes |
| **G6.12** | Knowledge growth is bounded over month/year simulation | 60-month run: every store's count and bytes ≤ its cap at every checkpoint; for each store whose cap bound, eviction counter > 0 and every eviction has a record or tombstone; plateau: max over months 49–60 ≤ max over months 25–36 for every store; lineage live nodes ≤ `MAX_LINEAGE_NODES` | yes (§6.1: the plateau is caps binding on a repeating synthetic cycle) |
| **G6.13** | Every advanced Stage 6 mechanism survives ablation against simpler continual-learning baselines | E1–E5 first (`BLOCKED`/`DEGENERATE` ⇒ FAIL with the reason, nothing recorded as justified). Then `run_ablation`: every OPTIONAL `HEL-F*` has an `AblationRow` with a measured non-`None` delta against its named simple control, a firing count > 0 and a verdict; the anti-forgetting comparison of §7 at every `REPLAY_BUDGETS_BYTES` and `CAPACITY_SWEEP` point; `experiments/registry.jsonl` byte-identical before/after; `docs/stage-6-findings.md` exists with all five honesty-ledger headings; `set(HYPOTHESES) == {H0…H8}`; no novelty word within 3 lines of an architecture construct name (§54) without `no novelty claim` in the paragraph. **FAILS by construction on synthetic data** (§6.1): PASS additionally requires `EnduranceReport.synthetic is False` | **NO** |

### 6.1 The criteria that cannot be met on synthetic data, declared

**G6.13 — "every advanced mechanism survives ablation": NOT MET, and the check is written to fail
rather than pass.** ADR-0010 established that the synthetic corpora in this repository produce only
trivial or impossible tasks, and §0 re-measured it for the drift corpus (ΔΦ control AP 1.0). A
mechanism that is JUSTIFIED on a synthetic timeline has shown its *mechanism* works, not that it
*survives* on real long-horizon telemetry. A mechanism that is NOT-YET-JUSTIFIED or HARMFUL on
synthetic data has, however, no evidence for it, and the findings recommend removing it. The four
neural §47 families are UNMEASURED (ADR-0050), which the check reports and does not count as passed.

**Partially bounded by synthetic data — met here as mechanism, UNMEASURED as value:**

- **G6.3** — "critical historical capabilities" are the three synthetic families F1–F3. No claim is
  made about any real technique.
- **G6.5** — the epoch changes are `SystemChangeSignal`s the harness asserts. Real package-upgrade
  drift (what actually changes in behaviour after `apt upgrade`) is UNMEASURED.
- **G6.9** — the adversary is this wave's own. An adaptive adversary who reads this document can
  target the parameters in §4.21; nothing here measures that.
- **G6.10** — RSS is the pytest-free in-process measurement on a contended dev host, not a 2 GB
  device (tests-and-tooling Trap 16).
- **G6.12** — the 60-month run repeats one synthetic year; the plateau shows the caps and eviction
  work, not that real knowledge would saturate there.

---

## 7. The baselines Stage 6 must beat

Every learner shares `induce_motifs`, `score_session`, the capsule stream and the capacity; they differ
only in the mechanism under test (lesson 4). All figures are at `FPR_BUDGET` via
`confusion_at_threshold`/`recall_at_max_fpr`; costs are `LearnerCost`.

| baseline (the dumbest thing that could work) | what it does | Stage 6 must beat it on | if it does not |
|---|---|---|---|
| `NeverUpdate` | trusted state frozen at M01 | **acquisition** (R_new on F2, F3) by ≥ 0.10, while **retention** (R_old on F1 at M08/M12) ≥ `NeverUpdate`'s − `EPS_SECURITY` | learning adds nothing → ADR-0058 recommends never-update + calibration-only |
| `NaiveFinetune` | every labelled capsule updates detectors immediately, FIFO eviction at capacity, threshold refit on the last window | retention (it is the forgetting lower bound; E3 requires it to forget) and poisoned promotions | the anti-forgetting stack is decorative |
| `ReservoirReplay` | reservoir-sampled replay buffer at the **same byte budget**; accept an update iff replay recall does not drop | retention at each `REPLAY_BUDGETS_BYTES` point (value-aware rehearsal must beat reservoir at equal bytes — ADR-0128 found the "clever" eviction was reservoir sampling) | value-aware rehearsal NOT-YET-JUSTIFIED |
| `FullRetrain` | rebuilds detectors from **all** retained history each consolidation (unbounded store) | **cost** (`stored_bytes`, `work_units`) at retention and acquisition within `EPS_SECURITY` of it | the machinery is not justified on cost; see G6.11 |
| `PrototypeCentroid` | one motif per MALICIOUS label cluster, no competition, no gates | acquisition and FP rate | competition/refinement NOT-YET-JUSTIFIED |
| `CalibrationOnly` | never adds items; refits the threshold only | acquisition (tests whether any structural learning is needed) | structural learning unnecessary on this corpus |
| `Stage2Only` | Stage 2's buffer + controller straight into state; detectors as `NaiveFinetune` | poisoned promotions per arm (§4.15) | Stage 6's poisoning layer adds nothing on that arm (F8) |

Per OPTIONAL mechanism, the simple control that isolates it (ablation = full Stage 6 with that one
flag replaced by its control):

| core id | mechanism | simple control | metric | firing count |
|---|---|---|---|---|
| HEL-F07 | epistemic half-life | LRU order | F1 retention at tight capacity | victims differing from LRU |
| HEL-F08 | plasticity field | `uniform_mask`, same budgets | R_old and R_new at fixed `MAX_ITEM_MUTATIONS` | changes frozen that uniform allowed |
| HEL-F10 | memory competition | `NEWEST_WINS` | FP rate on T1–T3 and F-retention | conflicts not resolved as replace |
| HEL-F11 | counterfactual rehearsal (G4) | plain replay (G2 only) | poisoned + regressing candidates admitted | G4 refusals G2 accepted |
| HEL-F15 | value-aware consolidation | reservoir at equal bytes | retention per byte budget | exemplars differing from reservoir |
| HEL-F19 | drift-vs-poison discriminator | "corroborated change ⇒ legitimate" | P2b promotions and time-to-adapt at M02 | verdicts differing from the rule |
| HEL-F21 | resurrection | relearn from scratch | time-to-adapt at M06 | resurrections performed |
| HEL-F25 | melt/retire by half-life | LRU retire | retention at tight capacity | retirements differing from LRU |
| (gateway) | source independence (ADR-0054) | off | P1/P1b poisoned promotions | `single_source_repetition` refusals |
| (gateway) | homeostasis anchors beyond Stage 2's four | Stage 2's `ESCALATION_PROPERTIES` only | P3/P4c poisoned promotions | refusals Stage 2's rule would not make |

Source independence and homeostasis are REQUIRED security mechanisms, but they are ablated anyway: a
required mechanism that never fires is still a finding.

---

## 8. What would falsify this stage's central claim

**Central claim:** learning changes trusted state only through quarantine → validation → promotion;
this gated learner acquires new detections without forgetting critical old ones, resists poisoning
that the simpler gate does not, stays bounded, and is reversible to a byte-identical prior state — at
lower cost than full retraining.

| # | falsifier | where it is measured | consequence |
|---|---|---|---|
| F1 | any path, AST or behavioural, by which input not minted by the gateway changes `mind.digest()` | G6.1 | the boundary is void; BLOCK the stage |
| F2 | rollback restores a digest ≠ the pre-promotion digest, or a canary/probation regression is logged but not rolled back | G6.8 | reversibility void |
| F3 | a trusted item without resolvable lineage after a run | G6.2 | provenance void |
| F4 | any store exceeds its cap, or grows between months 25–36 and 49–60 | G6.12 | bounded-memory claim void |
| F5 | a poisoning arm promotes under Stage 6 while `NaiveFinetune` shows the attack is real | G6.9 | the defence fails that attack class |
| F6 | Stage 6 R_old < `NeverUpdate` R_old − `EPS_SECURITY`, or Stage 6 R_new ≤ `NeverUpdate` R_new | §7, G6.13 | gated learning harms retention or learns nothing → recommend never-update + calibration-only |
| F7 | Stage 6 cost ≥ `FullRetrain` cost at comparable R | §7, G6.11 | the machinery is not justified on cost |
| F8 | `Stage2Only` achieves Stage 6's poisoned-promotion count on every arm | §4.15 | Stage 6's poisoning layer is decorative; reduce Stage 6 to Stage 2's gate + lineage/rollback |
| F9 | every OPTIONAL mechanism reports firing count 0 | Rule C | all INERT; remove them |
| F10 | Stage 6's clean promotion rate is 0 | G6.4, G6.9 | the defence works by learning nothing (accept-nothing equivalence) |

---

## 9. Honest limits — what this wave cannot prove

### 9.1 The one that matters most

Every corpus is synthetic, every Stage 5 record is `simulated=True`, and the only drift corpus in the
repository is solved at AP 1.0 by a zero-learning control (§0). Whether long-horizon learning **helps**
a real endpoint is not measurable in this repository. What this wave can settle is whether learning
is *safe to allow*: single writer, gated inputs, reversibility, lineage, bounds, and resistance to the
attacks it builds.

### 9.2 The rest

- No neural candidate exists; EWC/SI, LwF, adapter isolation, dynamic expansion, backdoor-trigger
  tests on neural models, ONNX export and ONNX Runtime INT8/INT4 are UNMEASURED (ADR-0050).
- The motif representation cannot express counts, timing or chains longer than two steps (§4.0).
- Independence groups are hashed lineages; fork-spraying is attacked (P1b) but a stronger grouping
  (causal-root lineage) is not built.
- Rollback depth is bounded by `MAX_FOSSILS`; older states are unrecoverable by design.
- HMAC package signing proves key membership, not host identity.
- Analyst and teacher labels are simulated; no real analyst workflow or teacher model exists. The
  optional tiny language model of architecture §32 does not exist in the repository, so its
  restrictions hold vacuously.
- Stages 3, 4 and 5 participate only through their handoff types built synthetically, not live.
- Wall clock is contended (7× Stage 2 precedent); RSS is an in-process dev-host figure.
- Every threshold in §4.21 is a chosen parameter; none is calibrated.
- Encryption at rest of episodic/fossil stores (architecture §36) is not implemented (no stdlib
  authenticated cipher); stores are integrity-protected by hash only.

---

## 10. ADRs — block 0050–0059, all ten assigned

The integrator writes all ten using `docs/adr/0000-adr-template.md`, each with an **Options considered**
table carrying a measured-consequence column (integration plan §5.5).

| ADR | title | status at spec time |
|---|---|---|
| 0050 | Stage 6 ships no research package and no numpy; the neural continual-learning families and ONNX are unmeasured | decided (§2.2) |
| 0051 | Stage 6 promotes through Stage 2's quarantine buffer and promotion controller by composition | decided (§2.4) |
| 0052 | Trusted cognition is one content-addressed state with one writer; rollback is by fossil digest and bounded in depth | decided (§4.0, D6.9, D6.17) |
| 0053 | Stage 6 consumes Stages 4 and 5 only through their JSON handoffs and does not consume Knowledge Cells; `action_outcome` is `response_outcome` | decided (§2.5) |
| 0054 | Source independence is a promotion requirement because Stage 2's gate promotes single-source repetition across epochs (measured 3/240) | decided (§0, §2.4) |
| 0055 | Stage 6 mints no hypothesis and binds to H6 (and H8 for ablation) | decided (§2.8) |
| 0056 | Candidate kinds are exactly those with an executor; no classifier, adapter or structural kind | decided (D6.11) |
| 0057 | Plasticity field, half-life and competition verdicts | **written from measurement** by the integrator |
| 0058 | Anti-forgetting verdict against never-update, full-retrain and reservoir replay | **written from measurement** |
| 0059 | Quantisation verdict, and fleet exchange stays off by default | **written from measurement** |

---

## 11. The honesty ledger `docs/stage-6-findings.md` must end with

Verbatim structure from integration plan §7, plus a PARAMETERS section:

```markdown
## Honesty ledger

### MEASURED
| claim | value | how it was produced (module:function) | experiment id | synthetic? |
|---|---|---|---|---|

### UNMEASURED
| claim the architecture makes | why not measured | what would measure it | blocking? |
|---|---|---|---|

### REJECTED
| component | measured effect | verdict (REJECTED / NOT-YET-JUSTIFIED / RETRACTED / INERT / DEGENERATE) | ADR |
|---|---|---|---|

### RETRACTED
| retracted claim | where it was published | the defect | corrected value |
|---|---|---|---|

### NOT A DETECTION RESULT
Every corpus is synthetic; every Stage 5 record is simulated. Nothing here is a detection result.

### PARAMETERS
Every §4.21 constant, with the sentence "chosen, not measured".
```

Every MEASURED row quotes its number inline (`results/*.json` is git-ignored) and records
`/proc/loadavg` beside any timing.

---

## 12. Completion output

The integrator ends the wave with the phase file's nine-item block: `PHASE 6 STATUS: COMPLETE |
PARTIAL | BLOCKED`; implemented checklist IDs 01–20; files changed; tests run with exact counts
(counted with `--junitxml`, because `-q` on top of `addopts = "-q"` suppresses the summary line —
MEMORY Stage 5 trap 5); the measured benchmark and resource results with load averages; unresolved
defects; ADRs 0050–0059; the exact MEMORY.md and PROGRESS.md edits; and the recommended next phase,
without starting it. **Expected status: PARTIAL**, because G6.13 fails by construction on synthetic
data (§6.1).
