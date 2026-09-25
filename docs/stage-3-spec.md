# Stage 3 — AICT + CRYSTAL — implementation specification

- **Status:** Implementation contract for Wave 3. Binding on all eight Stage 3 work packages.
- **Date:** 2026-09-25
- **Architecture source:** `docs/architecture/sources/stage-03-aict-crystal.md`
- **Build contract:** `docs/architecture/stage-3-12-integration-plan.md` (§1.2, §2, §3.2, §5, §6)
- **Phase checklist:** `planning/PHASE_03_CLAUDE_CODE.md`
- **ADR block:** 0020–0029. Verified free this session:
  `ls docs/adr/` returns `0000 0001 … 0010 0113 … 0122`. No number in 0020–0029 is taken.

## 0. Measurement status of this document

**Nothing in this document was measured in this session.** The only command output I produced
here that carries a number is `cat /proc/loadavg` → `13.76 12.40 13.95`, recorded so the next
wave knows this host was contended while this spec was written.

Every figure quoted below is **cited, not produced**: `planning/MEMORY.md`,
`planning/PROGRESS.md`, `docs/adr/0010-…`, `docs/adr/0118-…`. Each is marked with its source.
A Stage 3 implementer may **not** carry any of them into a findings document as their own
measurement.

---

## 1. What Stage 3 is actually compiling — and what it is not

The architecture document (§1, §3, §20, §42) assumes Stage 3 crystallises a **DTL**. **There is
no DTL.** ADR-0010 rejected it on measured grounds. The accepted Stage 2 core is a TCN with
detached heads, and the strongest measured artefact in the whole project is a *zero-parameter
rule*.

Recorded in `planning/MEMORY.md` and `docs/adr/0010-…`, not measured here:

| model | PR-AUC | µs/event | params |
|---|---|---|---|
| tcn | 1.0000 | 6.6 | 6,961 |
| dtl-conv | 1.0000 | 22.3 | 19,851 |
| mlp-pooled | 0.9415 | 3.2 | 4,657 |
| **phi-oracle** | **0.7484** | **~0.0** | **0** |

Three consequences bind every package in this wave.

**1.1 The first crystallisation target is Stage 1's Φ-oracle, not a neural region.**
Stage 2 already hands it over as a first-class `CandidateKind.DETERMINISTIC_SCORER`
(`pocketsec/stage2/compile_candidates/candidate.py`, ADR-0118). Crystallising a thing that is
already free is not the trivial case — it is the **honest** one. It asks whether the Knowledge
Cell machinery adds anything at all over the rule it wraps. If a `KnowledgeCellV1` reproducing
the Φ-oracle costs more µs/event or more bytes than the Φ-oracle, that is a **measured rejection
of the cell format**, and the wave must report it and write ADR-0021 accordingly.

**1.2 The dual oracle is rebound (D3.8).**
- **Oracle A** is *data*, never a live forward pass: a frozen `TeacherSnapshotV1` — a pinned-seed,
  offline-produced map from a canonical frame digest to a teacher score. For the Φ-oracle cell
  the teacher source is `"phi-oracle"`; the `"tcn"` source is loadable but **this wave does not
  produce it** (see §2.3), so it is `UNMEASURED`, never silently absent.
- **Oracle B** is Stage 1's explicit invariants, which already exist in code: `phi`/`delta_phi`
  (`stage1/state/potential.py:170`, `:195`), the `INTERACTIONS` table (`potential.py:65`),
  `SecurityStateV1.join` monotonicity (`security_state.py:165`) and `StateDelta`
  (`security_state.py:181`).

Oracle B does the catching. A single oracle that is just the teacher catches nothing, and the
teacher here *is* the thing being compiled.

**1.3 The compression criterion is restated (G3.9).**
"End-to-end average CPU/event is materially lower than pure DTL" is now meaningless: DTL is
rejected and costs 22.3 µs/event; the thing Stage 3 must beat costs about 0.1 µs/event with zero
parameters. Stage 3's value, if it has any, is **not speed over a teacher it no longer has**.
It is:

- **(a)** bounded executable knowledge with an explicit **validity boundary** and **reversible,
  localised melting** when reality changes; and
- **(b)** a representation whose cost is **auditable** — every µs and every byte attributable to
  a named cell.

Measure *that*. If the machinery cannot beat "run the Φ-oracle plus a drift detector", say so
plainly and write ADR-0024. See §6 for the executable form.

**1.4 Melting is the load-bearing feature, not crystallisation.** Anyone can compile a model into
a table. The claim that distinguishes AICT is that **localised drift reopens a subregion without
discarding unrelated crystallised knowledge**. The falsification experiment for this is built
**first**, not last (package `lifecycle`, §5.7; gate criterion G3.7; falsifier F2 in §8).

---

## 2. Repository rules this wave operates under

### 2.1 Layout — fixed by integration plan §1.2

```
pocketsec/stage3/
    __init__.py            EMPTY at creation; the integrator fills it last
    core_ids.py            AICT-F01 … AICT-F20, REQUIRED/OPTIONAL
    theory.py              D3.1 measurable definitions
    gate.py                INTEGRATOR-OWNED. 13 checks, one per acceptance criterion
    cli.py                 INTEGRATOR-OWNED. pocketsec-stage3 {gate,runtime,resources,crystallize,handoff}
    cells/      {invariant.py, operator.py, schema.py, field.py, fission.py, fusion.py}
    bytecode/   {isa.py, verifier.py, vm.py}
    invariants/ {anti_unification.py, motifs.py, discovery.py}
    boundary/   {index.py, pressure.py}
    synthesis/  {operators.py, selector.py}
    crystal/    {pipeline.py}
    oracles/    {security_specs.py, teacher.py, dual_oracle.py, counterexamples.py}
    promotion/  {shadow.py, assurance.py, decay.py, audit.py}
    melting/    {stress.py, partial.py, full.py}
    gc/         {controller.py}
    resources.py, slot.py, stage4_interface.py
    labs/       {crystal_corpus.py, baselines.py, boundary_evasion.py, ablation.py}
```

- Every `__init__.py` stays **empty**. Consumers import the leaf module.
- **An empty subpackage is a defect** (ADR-0121). Create a package in the commit that fills it.
  The four directories that exist today — `pocketsec/stage3/{bytecode,cells,compiler,crystal}` —
  are empty and are exactly the anti-pattern. `compiler/` is **not** in the layout above:
  the package `synthesis` owns compilation. **The integrator deletes `pocketsec/stage3/compiler/`.**

### 2.2 Hard mechanical constraints

- Python ≥ 3.11 (running 3.14.7). `from __future__ import annotations` in every module.
- Files < ~800 lines, functions < ~50 lines, `__all__` explicit, public APIs type-annotated.
- Module docstring states what the module is **for**. Comments explain **why**, not what.
- `print()` only in `cli.py` (`tests/test_repository_structure.py:152`).
- No edits to `contracts/*.schema.json`, `pocketsec/stage0/contracts/`, or Stage 1/2 contract
  types. New schema ids register through
  `pocketsec.stage0.contracts.common.register_schema` (`common.py:49`).
- **No package may edit `tests/test_repository_structure.py`.** Stage 3's dependency-boundary
  check is a new file, `tests/test_stage3_boundary.py`, implementing the same AST rules for
  Stage 3 only. Owned by the `foundation` package.
- `[tool.mypy] strict = true` over `pocketsec` and `tests`; `ruff` at 100 columns with
  `select = ["E","F","I","B","UP","SIM","RUF"]`. Both have **never been run in this repository**
  (`MEMORY.md`, Known gap). Wave 3 runs both and reports the count, or records `UNMEASURED`
  and says why.

### 2.3 Stage 3 ships **no** `research/` package and **no** numpy — ADR-0020

This is a decision, not an omission, and it is decisive.

`tests/test_repository_structure.py:73` hard-codes `RESEARCH_PREFIX = "pocketsec/stage2/research/"`
and `:86` hard-codes the same path again. Under those two lines, **`pocketsec/stage3/research/`
is a *runtime* directory**: a numpy import inside it fails
`test_runtime_has_no_third_party_imports`, and an import of `pocketsec.stage2.research.*` from it
fails `test_runtime_never_imports_research_code`. The integration plan pre-assigns **ADR-0011** to
widening that literal into a `RESEARCH_PREFIXES` tuple — but that is an edit to the one test file
this wave is forbidden to touch while another wave may be editing it.

**Decision.** Stage 3 creates no `pocketsec/stage3/research/` directory and imports no
third-party module anywhere. This costs nothing real, because:

- the four mandated baselines (§7) — a lookup table, a depth-limited decision tree, the
  unchanged Φ-oracle, and an LRU over a frozen-teacher snapshot — are all comfortably stdlib;
- Oracle A is **data** (integration plan §2.5: "Teacher consultation happens offline … and its
  result is a signed artifact"), so the runtime never needs a teacher object;
- the Stage 2 frozen benchmark that G3.1 requires already exists behind an existing numpy entry
  point, `python -m pocketsec.stage2.research.cli frontier`, which writes
  `results/stage2-frontier.json`. The Stage 3 gate **reads** that artifact and refuses evidence
  whose `(corpus, count, seed)` differs from the split the gate itself ran — exactly the pattern
  `pocketsec/stage2/gate.py` already uses.

Consequence, stated for the record: **the TCN-sourced `TeacherSnapshotV1` is not produced by this
wave.** `TeacherOracle` reports `TEACHER_UNAVAILABLE` for it and the affected divergence term is
`None` (UNMEASURED), never zero. ADR-0011 remains pre-assigned and unspent; a later wave that
genuinely needs gradient descent inside Stage 3 writes it then.

### 2.4 Another wave is building in this working tree

- Never edit `pocketsec/stage<other>/`, `tests/test_stage<other>_*.py`, `docs/stage-<other>-*.md`.
- Never run `git checkout`, `git stash`, `git restore`, `git clean`, `git commit`.
- Full-suite failures in another stage's test files are that wave's work in progress. Report and
  move on. Judge Stage 3 by `tests/test_stage3_*.py` plus `pocketsec-stage3 gate`.
- **Timing is contended.** A Stage 2 gate run measured a 7× inflation at load 23–67 versus load
  8–12 (`planning/PROGRESS.md`). Record `/proc/loadavg` beside every timing figure, prefer
  **within-run ratios** between two paths measured in the same run, and never present an absolute
  microsecond figure as a device measurement.

---

## 3. The data seam

### 3.1 Consumed from Stages 0–2 — every type below exists, cited `path:line`

Quoted from `docs/architecture/stage-3-12-integration-plan.md` §3.1/§3.2. Stage 3 *consumes*:

| Type | Path:line | Stage 3 use |
|---|---|---|
| `SSIRTransitionV1`, `RepresentationLevel`, `TemporalContext` | `stage1/ssir/transition.py:82`, `:39`, `:49` | the only event substrate invariant discovery reads |
| `Entity`, `SemanticBelief`, `SemanticProperty`, `EntityKind` | `stage1/ssir/entities.py:238`, `:118`, `:64`, `:34` | anti-unification generalises over `SemanticProperty`, **never** `Entity.display_name` (ADR-0006/0007) |
| `Relation`, `RelationFamily`, `family_of` | `stage1/ssir/relations.py:19`, `:56`, `:95` | boundary index key component |
| `SecurityStateV1`, `StateDelta`, `DIMENSIONS` | `stage1/state/security_state.py:122`, `:181`, `:108` | cell output type; `StateDelta.bitmask` (`:206`) is a boundary index key component |
| `phi`, `delta_phi`, `PhiBreakdown`, `INTERACTIONS`, `calibrate` | `stage1/state/potential.py:170`, `:195`, `:147`, `:65`, `:237` | **Oracle B** |
| `AdaptiveObservationPolicy`, `EscalationDecision`, `ObservationLevel`, `MANDATORY_SIGNALS` | `stage1/observation/policy.py:151`, `:93`, `:39`, `:47` | escalation is an `EscalationDecision`, **not a new type** |
| `Epoch`, `EpochModel`, `EpochDecision`, `SystemIdentity` | `stage1/epoch/model.py:105`, `:136`, `:81`, `:55` | `X` (epoch validity); Stage 3 does not define a second epoch |
| `CausalMemory`, `CausalNode`, `causal_signature` | `stage1/causal/memory.py:155`, `:83`, `:47` | causal attribution preservation (G3.8) |
| `Stage1Pipeline`, `ScenarioResult` | `stage1/pipeline.py:78`, `:47` | the **only** corpus walk; no second pipeline |
| `Behaviour`, `Scenario`, `build_corpus` | `stage1/labs/corpus.py:34`, `:45`, `:220` | Stage 3 defines **no fifth Scenario type** |
| `EncodedTransition`, `encode_ssir_transition`, `FEATURE_LAYOUT`, `FEATURE_WIDTH`, `NEED_SIGNAL_INDICES`, `ENCODER_VERSION` | `stage2/encoder/ssir_encoder.py:143`, `:195`, `:94`, `:95`, `:113`, `:45` | feature frame for tree/table baselines |
| `Stage2Sample`, `Stage2Dataset`, `build_dataset` | `stage2/dataset.py:38`, `:72`, `:147` | baseline evaluation |
| `LineageWindow` | `stage2/state/window.py:136` | `DeterministicScorerSpec.evaluate` input |
| `ExecutionPath`, `PATH_COST_UNITS` | `stage2/core_ids.py:43`, `:62` | path accounting; **`PATH_COST_UNITS` is uncalibrated** (ADR-0114) |
| `CompileCandidateV1`, `CandidateKind`, `ValidityBoundary`, `MeasuredCost`, `CandidateStability`, `UNSEEN_INPUT_ABSTAIN` | `stage2/compile_candidates/candidate.py` | the compile input |
| `DeterministicScorerSpec` | `stage2/compile_candidates/phi_oracle_candidate.py:90` | the Φ-oracle as plain data |
| `Stage3Handoff`, `build_handoff`, `write_handoff`, `seam_violations`, `EvidenceBoundPrediction` | `stage2/compile_candidates/stage3_interface.py` | the wire Stage 3 reads |
| `build_drift_corpus`, `malicious_lineage`, `DRIFT_VERSION` | `stage2/labs/drift_corpus.py:379`, `:305`, `:82` | the **multi-epoch** corpus (see §3.3) |
| `SystemChangeSignal` | `stage2/adaptation/epoch_guard.py:204` | drives epoch transitions with corroboration |
| `TransitionCache`, `transition_cache_key`, `lru_control` | `stage2/cache/transition_cache.py:227`, `:78`, `utility.py:117` | baseline B4's LRU; **do not reimplement an LRU** |
| `ModelSlot`, `validate_slot` | `stage0/contracts/model_slot.py:41`, `:57` | `CrystalSlot` implements this |
| `ThreatPredictionV1`, `Verdict`, `ComputePath`, `EvidenceRelevance`, `FORBIDDEN_AUTHORITY_FIELDS` | `stage0/contracts/threat_prediction_v1.py:143`, `:66`, `:84`, `:98`, `:48` | cell output envelope |
| `EvidenceRef`, `ContractError`, `register_schema`, `digest_of_bytes`, `require_identifier` | `stage0/contracts/common.py:125`, `:32`, `:49` | evidence lineage |
| `run_benchmark`, `BenchmarkCase`, `BenchmarkResult`, `SequenceDataset` | `stage0/benchmark/harness.py:133`, `:43`, `:92`, `dataset.py:53` | the **only** measurement path |
| `ResourceSampler`, `ResourceMetrics`, `check_profile`, `ProfileReport` | `stage0/benchmark/resource_metrics.py:103`, `:58`, `profiles.py:85`, `:62` | the **only** resource path |
| `SecurityMetrics`, `evaluate_scores` | `stage0/benchmark/security_metrics.py:178`, `:211` | the **only** PR-AUC path |
| `GateCheck`, `GateReport` | `stage0/gate.py:45`, `:56` | gate shape |
| `ExperimentRegistry.register`, `format_experiment_id`, `SeedSet` | `stage0/experiments/registry.py:138`, `ids.py:56`, `repro/seeds.py:24` | append-only ledger; Stage 3 counter starts at `0001` |

**Forbidden consumption.** Per integration plan §6.5, Stage 3 does **not** consume Behaviour
Atoms, the transition lattice, Future Cones or the counterfactual twin. D2.6–D2.15 are not
prerequisites and must not be built to unblock Stage 3.

### 3.2 Exposed to Stage 4 (and to Stages 9, 10) — names assigned by the build contract

The integration plan §3.2 names these; Stage 3 must create them at exactly these paths:

| Name | Module | Consumed by |
|---|---|---|
| `KnowledgeCellV1` (schema id `pocketsec.knowledge_cell.v1`) | `stage3/cells/schema.py` | 4, 5, 6, 7, 10 |
| `KnowledgeField` | `stage3/cells/field.py` | 4 |
| `BoundaryIndex` | `stage3/boundary/index.py` | 4 |
| `BoundaryPressureReport` | `stage3/boundary/pressure.py` | 10 |
| `Invariant` | `stage3/cells/invariant.py` | 4, 8 |
| `CellISA` (`Op`, `Instruction`), `CellBytecode` (= `OperatorProgram`), `CellVerifier`, `CellVM` | `stage3/bytecode/{isa,verifier,vm}.py` | 9, 12 |
| `DualOracleVerdict` | `stage3/oracles/dual_oracle.py` | 10 |
| `CounterexampleStore` | `stage3/oracles/counterexamples.py` | 8, 10 |
| `AssuranceState` | `stage3/promotion/assurance.py` | **10 extends it, never forks it** |
| `MeltReport` | `stage3/melting/full.py` | 6, 11 |
| `CrystalSlot(ModelSlot)` | `stage3/slot.py` | hub; `ComputePath.CHEAP_TRANSITION` on a cell hit |

**Binding, verbatim from the plan:** "`BoundaryIndex.lookup()` returns `KnowledgeCellV1 | None`;
`CellVM.run()` returns a `StateDelta` plus `tuple[EvidenceRef, ...]`; escalation is an
`EscalationDecision` (`stage1/observation/policy.py:93`), not a new type."

### 3.3 The G2.13 blocker, and how Stage 3 resolves it honestly

Stage 2's export gate fails G2.13 with `distinct_epochs 1 < 2`: `CandidateStability.stable`
(`candidate.py`) requires two distinct epochs and the **detection** corpus has one. The exporter
therefore refuses the Φ-oracle candidate.

**Do not lower the stability requirement.** "Frequency is not corroboration" is the anti-poisoning
invariant (ADR-0007, `instability_reason()`). Weakening it to unblock Stage 3 would be the exact
failure this repository exists to refuse.

**The corpus with genuinely distinct epochs already exists.** `pocketsec/stage2/labs/drift_corpus.py`
builds three routine phases with **two corroborated epoch transitions** (0→1 policy at 25%,
1→2 package at 50%) and one uncorroborated change at 70% that must *not* open an epoch
(`build_drift_corpus` docstring, `drift_corpus.py:379`). `gate_measures.DRIFT_EPOCH_SIGNALS`
(`:118`) supplies the out-of-band `SystemChangeSignal` for each phase, so behaviour alone never
opens an epoch.

**Decision (ADR-0028).** Stage 3's corpus is `build_drift_corpus` replayed through
`Stage1Pipeline` with `DRIFT_EPOCH_SIGNALS` driving `EpochModel.evaluate`. `labs/crystal_corpus.py`
is a **thin composition** of existing parts — it does not build a fifth `Scenario` type and does
not define a second corpus builder. It exports `CRYSTAL_CORPUS_VERSION` and ships the two
mandatory corpus tests from integration plan §5.4:

- `test_crystal_corpus_uses_session_unique_identities` — `Stage1Pipeline` carries lineage state
  across scenarios; a corpus reusing process identities erases its own signal (the retracted
  +0.042 result).
- `test_crystal_corpus_has_non_zero_median_delta_phi_for_both_classes` — asserted **before** any
  model is fitted.
- `test_crystal_corpus_carries_no_vocabulary_signal` — per-operation count distributions match
  across classes within noise, and a pooled order-free control scores within 0.05 of the base rate.

**If, after this, a stable candidate still cannot legitimately exist**, the wave reports
`PHASE 3 STATUS: PARTIAL` with the exact reason — not a lowered threshold, not a workaround —
and G3.1/G3.3 record the end-to-end demonstration as blocked.

---

## 4. Deliverables D3.1 – D3.16

Each deliverable below names its exact module path, its public types with fields and types, its
public functions with signatures, and its bounds. Nothing here is TBD.

### D3.1 — AICT theory specification and measurable definitions
**Module:** `pocketsec/stage3/theory.py` · **Package:** `foundation`

```python
class SecurityConsequence(IntEnum):          # §7 Theta_c(SecurityConsequence(R))
    ROUTINE = 0; ELEVATED = 1; HIGH = 2; CRITICAL = 3

def consequence_of(delta: StateDelta, state: SecurityStateV1) -> SecurityConsequence
    # CRITICAL when any INTERACTIONS predicate (potential.py:136 _PREDICATES) fires;
    # HIGH when delta raises privilege/credential/persistence/isolation;
    # ELEVATED when delta is non-empty; ROUTINE otherwise.

@dataclass(frozen=True, slots=True)
class ResolutionState:                        # §6 Resolution(R) = (P, U, V, C, E, D)
    predictive_stability: float               # P in [0,1]
    calibrated_uncertainty: float             # U in [0,1]; LOWER is better
    validated_breadth: int                    # V: distinct BoundaryKeys covered
    counterfactual_consistency: float         # C in [0,1]; the fraction of
                                              # ACTOR_SUBSTITUTION probes that did not
                                              # diverge, over the probes that moved THAT
                                              # axis. UNMEASURED when none did, and the
                                              # crystallisation round then REFUSES rather
                                              # than writing a number: §9's
                                              # identity-versus-property check cannot be
                                              # reported as satisfied by a run that never
                                              # perturbed the actor.
    evidence_agreement: float                 # E in [0,1]
    drift_stability: int                      # D: distinct CORROBORATED epochs
    measured_by: str                          # "module:function"; raises if not that shape
    def unmet(self, threshold: ResolutionThreshold) -> tuple[str, ...]

@dataclass(frozen=True, slots=True)
class ResolutionThreshold:
    min_predictive_stability: float; max_calibrated_uncertainty: float
    min_validated_breadth: int; min_counterfactual_consistency: float
    min_evidence_agreement: float; min_drift_stability: int

THRESHOLDS: Mapping[SecurityConsequence, ResolutionThreshold]   # Theta_c, rising with consequence
def crystallization_allowed(r: ResolutionState, c: SecurityConsequence) -> tuple[bool, tuple[str, ...]]

@dataclass(frozen=True, slots=True)
class IntelligenceDensity:                    # §5 ID(R)
    utility: float | None                     # None == UNMEASURED, never 0.0
    microseconds_per_event: float | None
    resident_bytes: int | None
    audit_cost_per_event: float | None
    measured_by: str
    @property
    def density(self) -> float | None         # None if ANY term is None

@dataclass(frozen=True, slots=True)
class KnowledgePressure:                      # §17 — deliberately NOT one product
    frequency: int; measured_teacher_cost_us: float | None
    predictability: float; security_utility: float
    @property compute_pressure(self) -> float | None
    @property security_pressure(self) -> float
    # There is no `.score`. §17: "maintain separate compute-pressure and security-pressure
    # components rather than blindly multiplying arbitrary scores."
```

**Bounds.** `THRESHOLDS` is a closed mapping over all four consequence levels. Every `float | None`
field is `None` when unmeasured; a `None` anywhere makes the derived quantity `None`. There is no
default that turns UNMEASURED into a number.

### D3.2 — CRYSTAL algorithm prototype
**Module:** `pocketsec/stage3/crystal/pipeline.py` · **Package:** `synthesis`

Implements §33 exactly, in that order.

```python
@dataclass(frozen=True, slots=True)
class CrystalConfig:
    pressure_budget: int = 256            # BoundaryPressure probes per candidate
    max_refinements: int = 8              # RefineOrFission iterations
    epsilon_by_consequence: Mapping[SecurityConsequence, float]
    shadow_min_coverage: Mapping[SecurityConsequence, int]
    seed: int

@dataclass(frozen=True, slots=True)
class CrystalRun:
    region_key: BoundaryKey
    invariant: Invariant | None
    boundary: CellBoundary | None
    candidates_tried: tuple[OperatorForm, ...]
    selected: OperatorCandidate | None
    pressure: BoundaryPressureReport | None
    dual_oracle: DualOracleVerdict | None
    shadow: ShadowRun | None
    outcome: CrystalOutcome            # PROMOTED | REFUSED_RESOLUTION | REFUSED_HARD_CONSTRAINT
                                       # | REFUSED_DIVERGENCE | RETURNED_TO_LEARNING | BUDGET_EXHAUSTED
    counterexamples: tuple[Counterexample, ...]
    reason: str

def crystallize(region: RegionSample, *, config: CrystalConfig, teacher: TeacherOracle,
                field: KnowledgeField, store: CounterexampleStore) -> CrystalRun
```

**Bounds.** `pressure_budget ≤ 4096`; `max_refinements ≤ 8`; a run that exhausts budget returns
`BUDGET_EXHAUSTED` and `region_to_DTL` semantics — i.e. the region stays on the learned/fluid path.
`crystallize` **never** promotes; it returns a run and the caller promotes.

### D3.3 — Behavioural Invariant discovery engine
**Modules:** `invariants/anti_unification.py`, `invariants/motifs.py`, `invariants/discovery.py`
· **Package:** `invariants` · **Types live in** `cells/invariant.py` (package `foundation`)

```python
# cells/invariant.py  (foundation — placed here so discovery has no circular dep on schema)
class PredicateRole(StrEnum): ACTOR = "ACTOR"; OBJECT = "OBJECT"

@dataclass(frozen=True, slots=True)
class SemanticPredicate:
    role: PredicateRole
    required_properties: frozenset[SemanticProperty]
    forbidden_properties: frozenset[SemanticProperty]
    relation_family: RelationFamily | None
    entity_kind: EntityKind | None
    # __post_init__ raises ContractError if required & forbidden intersect, and asserts over
    # its own __dataclass_fields__ that no field name contains "name", "identity" or "path"
    # (ADR-0006/0007: names are evidence, never semantics).
    def matches(self, entity: Entity, relation: Relation) -> bool
    def generality(self) -> int      # |SemanticProperty| - |required| - |forbidden|

@dataclass(frozen=True, slots=True)
class ConsequentSpec:
    required_dimensions: frozenset[str]        # subset of DIMENSIONS
    min_delta_phi: float
    required_evidence_kinds: frozenset[str]
    consequence: SecurityConsequence

@dataclass(frozen=True, slots=True)
class Invariant:
    invariant_id: str
    antecedent: tuple[SemanticPredicate, ...]  # 1..MAX_ANTECEDENT_TERMS
    consequent: ConsequentSpec
    support: int                               # distinct lineages, not events
    contradictions: int
    identities_collapsed: int                  # what anti-unification generalised over
    epochs: frozenset[int]
    falsifier: str                             # the observation that would refute it; non-empty
    evidence: tuple[EvidenceRef, ...]          # non-empty
    def to_dict(self) -> dict[str, Any]; @classmethod from_dict(...)
```

```python
# invariants/anti_unification.py                                     §9 semantic anti-unification
PROPERTY_ORDER: tuple[SemanticProperty, ...]        # pinned; index order is a wire commitment
def property_mask(props: Iterable[SemanticProperty]) -> int
def anti_unify(entities: Sequence[Entity], role: PredicateRole,
               relation_family: RelationFamily | None) -> SemanticPredicate | None
    # Most specific shared asserted properties. Returns None when the generalisation floor
    # (>= 1 required property) is not met: a predicate with no required property is universal
    # and would silently extrapolate over the whole host.

# invariants/motifs.py                                               §9 transition motif extraction
MAX_MOTIF_LENGTH = 4; MAX_MOTIFS = 4096
@dataclass(frozen=True, slots=True)
class TransitionMotif:
    steps: tuple[tuple[RelationFamily, int, int], ...]   # (family, delta bitmask, phi band)
    support: int; lineages: int
def extract_motifs(sessions, *, k: int, min_support: int) -> tuple[TransitionMotif, ...]

# invariants/discovery.py
MAX_INVARIANTS = 256; MIN_LINEAGE_SUPPORT = 4
def discover_invariants(sessions, *, min_support=MIN_LINEAGE_SUPPORT,
                        max_invariants=MAX_INVARIANTS) -> tuple[Invariant, ...]
def minimal_conditions(inv, sessions) -> Invariant           # §9 minimal-feature search
def predictive_equivalence_clusters(sessions, *, max_clusters: int) -> tuple[frozenset[str], ...]
def counterfactual_substitution(inv, sessions, *, seed: int) -> tuple[bool, tuple[str, ...]]
    # §9: rename/swap semantically equivalent actors; the required outcome must be stable.
def cross_epoch_validate(inv, sessions) -> frozenset[int]
    # §9: reject a relationship that exists only inside one accidental configuration,
    # UNLESS it is explicitly epoch-bound — in which case the returned set is the binding.
```

**Bounds.** `MAX_INVARIANTS = 256`, `MAX_MOTIFS = 4096`, `MAX_ANTECEDENT_TERMS = 4`,
`MAX_MOTIF_LENGTH = 4`. `support` counts **distinct causal lineages**, never events — a pattern
seen a thousand times in one lineage has one witness.

### D3.4 — Knowledge Boundary and Boundary Pressure engine
**Modules:** `boundary/index.py`, `boundary/pressure.py` · **Package:** `knowledge_boundary`

```python
# boundary/index.py
BoundaryKey = tuple[int, int, int]      # (RelationFamily.value, actor property mask, StateDelta.bitmask)
MAX_INDEX_KEYS = 8192
MAX_INDEX_BYTES = 8 * 1024 * 1024       # §38 "Boundary index < 2-8 MB"

@dataclass(frozen=True, slots=True)
class CellBoundary:                     # §10 B(K)
    predicates: tuple[SemanticPredicate, ...]
    state_dimensions: frozenset[str]    # subset of DIMENSIONS
    phi_range: tuple[float, float]
    max_uncertainty: float
    epochs: frozenset[int]              # non-empty; an empty boundary contains NOTHING
    forbidden_combinations: tuple[frozenset[SemanticProperty], ...]
    unseen_input_behaviour: str = "ABSTAIN"    # the ONLY accepted value (mirrors ValidityBoundary)
    @property is_empty(self) -> bool
    def contains(self, frame: CellFrame) -> bool
    def distance(self, frame: CellFrame) -> int   # 0 inside; >0 = number of violated clauses
    def keys(self) -> tuple[BoundaryKey, ...]     # bounded expansion, <= MAX_KEYS_PER_CELL (64)
    @classmethod from_validity_boundary(cls, b: ValidityBoundary, ...) -> CellBoundary

class BoundaryIndex:
    def __init__(self, *, max_keys=MAX_INDEX_KEYS, max_bytes=MAX_INDEX_BYTES) -> None
    def insert(self, cell: KnowledgeCellV1) -> None        # raises when full; never silently evicts
    def remove(self, cell_id: str) -> int
    def lookup(self, frame: CellFrame) -> KnowledgeCellV1 | None      # CONTRACT NAME — plan §3.2
    def lookup_all(self, frame: CellFrame) -> tuple[KnowledgeCellV1, ...]
    def near_boundary(self, frame: CellFrame, *, within: int = 1) -> tuple[KnowledgeCellV1, ...]
    def memory_bytes(self) -> int
```

```python
# boundary/pressure.py
class Perturbation(StrEnum):            # §11, one member per listed axis
    SEMANTIC_DIMENSION; TIMING; CAUSAL_PREDECESSOR; EPOCH; PRIVILEGE
    ACTOR_SUBSTITUTION; EVIDENCE_ABLATION

class PressureStrategy(StrEnum):
    GUIDED = "GUIDED"                   # walk the divergence gradient, one axis at a time
    RANDOM_REPLAY = "RANDOM_REPLAY"     # the mandated control for G3.4

@dataclass(frozen=True, slots=True)
class BoundaryProbe:
    frame: CellFrame; perturbation: Perturbation; steps_from_seed: int; seed_digest: str

@dataclass(frozen=True, slots=True)
class BoundaryPressureReport:
    strategy: PressureStrategy; seed: int; probes_run: int; budget: int
    budget_exhausted: bool
    divergences: tuple[BoundaryProbe, ...]
    counterexample_classes: frozenset[str]      # the comparison unit for G3.4
    false_inside: int; false_outside: int       # §37 boundary quality
    near_boundary_errors: int
    probes_by_axis: tuple[tuple[str, int], ...]         # axes ACTUALLY MOVED, per probe
    divergences_by_axis: tuple[tuple[str, int], ...]
    unmeasured_probes: int                              # the oracle had NO OPINION
    def to_dict(self) -> dict[str, Any]
    def probes_on(self, axis: Perturbation) -> int      # 0 means the axis never moved
    def divergences_on(self, axis: Perturbation) -> int
    # CORRECTIONS (defect-repair wave), both of which changed reported numbers:
    #   * The three §37 counters advance only when the oracle had an opinion — a hard
    #     violation fired, or the teacher answered. Oracle A is an exact-digest snapshot of
    #     corpus frames and every perturbed frame misses it, so `false_inside` was counting
    #     snapshot key misses as missed detections and feeding them, at weight 0.25, into the
    #     melt decision. Those probes are `unmeasured_probes` now.
    #   * The per-axis counts exist because a per-axis metric needs a per-axis denominator:
    #     `counterfactual_consistency` divided ACTOR_SUBSTITUTION divergences by `probes_run`,
    #     the total over all seven axes.

def apply_boundary_pressure(cell, *, oracle: DualOracleEvaluator, budget: int, seed: int,
                            strategy: PressureStrategy = PressureStrategy.GUIDED
                            ) -> BoundaryPressureReport
def random_replay_control(cell, *, oracle, budget: int, seed: int) -> BoundaryPressureReport
    # SAME budget CAP, SAME seed family. G3.4 compares counterexample_classes between the two.
    # The cap is shared; the SPEND is not — guided stops when it exhausts
    # AXIS_ORDER x MAX_STEPS_PER_AXIS, random spends every probe — so a comparison must read
    # both `probes_run` values rather than calling the pair "equal-budget".
    #
    # A probe is credited with a counterexample class for every axis it ACTUALLY MOVED. An
    # axis that was drawn and skipped (perturbed_frame returned None) gets nothing: crediting
    # it invents a finding about a frame the axis never touched, and doing so produced G3.4's
    # withdrawn "strict superset" result (ADR-0026's correction).
```

**Bounds.** `budget ≤ 4096` probes. `MAX_KEYS_PER_CELL = 64` — a cell whose boundary expands to
more keys is refused, which is the mechanical cap on the "knowledge explosion" threat (§39).

### D3.5 — Knowledge Cell schema and Knowledge Field index
**Modules:** `cells/operator.py`, `cells/schema.py`, `cells/field.py` · **Package:** `foundation`

```python
# cells/operator.py                                    §13 operator forms
class OperatorForm(StrEnum):
    CONSTANT; LOOKUP_TABLE; BITSET_PREDICATE; DECISION_DAG
    FSM_FRAGMENT; WEIGHTED_TRANSITION; LINEAR_EXPRESSION; BYTECODE
    # RESIDUAL_MICRO_MODEL is DELIBERATELY ABSENT this wave. §13 lists it as the fallback
    # "only when symbolic/executable compression fails"; it would require a weights blob and a
    # numpy producer, and §2.3 forbids both. ADR-0021 records the omission as a decision.

@dataclass(frozen=True, slots=True)
class OperatorProgram:                  # = CellBytecode in plan §3.2 naming
    form: OperatorForm
    words: tuple[int, ...]              # PCB encoding; () for non-BYTECODE forms
    table: Mapping[str, float]          # plain JSON; () -> {} for non-table forms
    max_steps: int                      # declared, statically checked
    max_state_bytes: int                # declared, statically checked
    digest: str                         # "sha256:" of canonical JSON of (form, words, table)
    def to_dict(self); @classmethod from_dict(...)
    def size_bytes(self) -> int
```

```python
# cells/schema.py
KNOWLEDGE_CELL_V1_ID = "pocketsec.knowledge_cell.v1"
KNOWLEDGE_CELL_V1_VERSION = register_schema(KNOWLEDGE_CELL_V1_ID, "1.0.0")

class AssuranceLevel(StrEnum):          # §25 — A5 is reachable only with a named prover module
    A0; A1; A2; A3; A4; A5
class CellPhase(StrEnum):               # §3
    FLUID; STRUCTURED; CRYSTALLIZED; STRESSED; MELTED
class ConstraintKind(StrEnum):          # §19 "hard constraints Q_i"
    NEVER_SUPPRESS_MANDATORY_EVIDENCE; NEVER_DOWNGRADE_CONSEQUENCE
    NEVER_LOWER_PHI; NEVER_NORMALISE_HIGH_CONSEQUENCE; STATE_MONOTONE

@dataclass(frozen=True, slots=True)
class HardConstraint:
    constraint_id: str; kind: ConstraintKind; detail: str

@dataclass(frozen=True, slots=True)
class AuditPolicy:                      # §27 A_i
    base_rate: float; min_rate: float; max_rate: float; jitter_salt: str

@dataclass(frozen=True, slots=True)
class KnowledgeCellV1:                  # §12 K_i = (I, B, Omega, Gamma, E, Q, X, A, V)
    cell_id: str
    invariant: Invariant                             # I
    boundary: CellBoundary                           # B
    operator: OperatorProgram                        # Omega
    resolution: ResolutionState                      # Gamma (structure)
    confidence: float                                # Gamma_t scalar in [0,1]
    assurance: AssuranceLevel
    phase: CellPhase
    evidence_lineage: tuple[EvidenceRef, ...]        # E — non-empty
    constraints: tuple[HardConstraint, ...]          # Q — non-empty
    epochs: frozenset[int]                           # X — non-empty
    audit_policy: AuditPolicy                        # A
    version: int                                     # V
    parent_cell_id: str | None                       # rollback identity
    source_candidate_id: str | None                  # the CompileCandidateV1 it came from
    schema_version: str = KNOWLEDGE_CELL_V1_VERSION
    # __post_init__ raises ContractError on: empty evidence_lineage; empty constraints;
    # empty epochs; boundary.is_empty; operator.max_steps > MAX_CELL_STEPS;
    # confidence outside [0,1]; any field name containing a FORBIDDEN_AUTHORITY_FIELDS token.
    def to_dict(self); @classmethod from_dict(...)
    def size_bytes(self) -> int
```

```python
# cells/field.py                                       §15 Knowledge Field, §16 composition algebra
MAX_CELLS = 512
MAX_FIELD_BYTES = 20 * 1024 * 1024      # §38 "Knowledge Cells + metadata < 5-20 MB bounded"
MAX_COMPOSITION_DEPTH = 4

@dataclass(frozen=True, slots=True)
class CellActivation:
    cell_id: str; delta: StateDelta; risk: float
    evidence_required: tuple[EvidenceRef, ...]
    escalation: EscalationDecision | None
    consequence: SecurityConsequence
    confidence: float; epochs: frozenset[int]

class CompositionOutcome(StrEnum):
    RESOLVED; ABSTAINED_CONTRADICTION; ABSTAINED_EPOCH_INCOMPATIBLE
    ABSTAINED_DEPTH; ABSTAINED_NO_CELL

@dataclass(frozen=True, slots=True)
class CompositionVerdict:
    outcome: CompositionOutcome
    delta: StateDelta; risk: float
    evidence: tuple[EvidenceRef, ...]        # UNION, never a subset of any input (§16 rule 1)
    escalation: EscalationDecision | None    # MAX requested level within resource policy
    contributing: tuple[str, ...]; reason: str

class KnowledgeField:
    def __init__(self, *, max_cells=MAX_CELLS, max_bytes=MAX_FIELD_BYTES) -> None
    def insert(self, cell) -> None          # raises FieldFull; NEVER silently evicts
    def remove(self, cell_id: str) -> bool
    def get(self, cell_id: str) -> KnowledgeCellV1 | None
    def cells(self) -> tuple[KnowledgeCellV1, ...]
    def memory_bytes(self) -> int
    def compose(self, activations: Sequence[CellActivation]) -> CompositionVerdict
```

**Composition rules, each a named test (§16):**
1. evidence union is monotone — `len(verdict.evidence) >= max(len(a.evidence_required))`;
2. a lower-confidence cell can never downgrade a higher-consequence validated result;
3. escalation composes by maximum requested level within `AOPBudget`;
4. the composed `StateDelta` must satisfy `SecurityStateV1.join` monotonicity or the verdict
   abstains;
5. contradictory cells → `ABSTAINED_CONTRADICTION`, never arbitrary winner selection;
6. epoch-incompatible cells cannot compose;
7. depth > `MAX_COMPOSITION_DEPTH` → `ABSTAINED_DEPTH`.

### D3.6 — PocketSec Cell Bytecode + verifier + VM
**Modules:** `bytecode/isa.py`, `bytecode/verifier.py`, `bytecode/vm.py` · **Package:** `bytecode`

```python
# isa.py
PCB_VERSION = "pocketsec-cell-bytecode.1.0.0"
MAX_INSTRUCTIONS = 64; MAX_STACK = 16; MAX_CONSTANTS = 32; MAX_SET_MEMBERS = 32

class Op(IntEnum):                       # §14, exactly the candidate list
    LOAD_STATE; LOAD_SEM; LOAD_REL; LOAD_DELTA; LOAD_CONST
    EQ; NE; LT; GT; IN_SET
    AND; OR; NOT
    COUNT_WINDOW; SEEN_WITHIN
    TRANSITION; UPDATE_PHI
    RAISE_OBSERVATION; PRESERVE_EVIDENCE
    RETURN_STATE; RETURN_RISK; ABSTAIN
    # There is NO jump, branch, call, loop, alloc, load-indirect or syscall opcode.
    # That absence is the termination argument; see PROVEN_PROPERTIES below.

class ValueType(StrEnum): BOOL; INT; FLOAT; SET; EVIDENCE
OPERAND_ARITY: Mapping[Op, int]
STACK_EFFECT: Mapping[Op, tuple[tuple[ValueType, ...], tuple[ValueType, ...]]]

@dataclass(frozen=True, slots=True)
class Instruction: op: Op; operand: int
def encode(instructions: Sequence[Instruction]) -> tuple[int, ...]
def decode(words: Sequence[int]) -> tuple[Instruction, ...]
CellISA = Op                             # plan §3.2 contract alias
```

```python
# verifier.py
@dataclass(frozen=True, slots=True)
class VerificationReport:
    ok: bool
    proven: tuple[str, ...]              # PROVEN BY CONSTRUCTION
    tested_only: tuple[str, ...]         # EMPIRICAL — must be worded as such everywhere
    failures: tuple[tuple[str, str], ...]
    instruction_count: int; max_stack_depth: int; max_state_bytes: int

PROVEN_PROPERTIES: tuple[str, ...] = (
    "termination: the program is straight-line; the ISA defines no jump, branch or call "
      "opcode, and instruction_count <= MAX_INSTRUCTIONS is checked statically",
    "no unbounded loop: by the same absence — there is no opcode that can move the program "
      "counter backwards",
    "no dynamic allocation: max_stack_depth is computed exactly by abstract interpretation "
      "over a straight-line program and checked against MAX_STACK",
    "operand-type safety: abstract stack typing over a straight-line program is exact, not "
      "an approximation, so a type error is a decision rather than a heuristic",
    "bounded state access: every LOAD_* operand indexes a fixed-size CellFrame and is "
      "range-checked at verification time; there is no indirect load",
)
TESTED_ONLY_PROPERTIES: tuple[str, ...] = (
    "the VM does not corrupt interpreter or host state — no test has observed it; empirical",
    "decode(encode(p)) == p for the generated program corpus — empirical over that corpus",
    "no verified program has exceeded its declared max_steps in any run — empirical",
    "resistance to adversarially-crafted operand values beyond the range check — empirical, "
      "exercised by labs/boundary_evasion.py",
)

def verify(program: OperatorProgram) -> VerificationReport
CellVerifier = verify                    # plan §3.2 contract alias
```

**This is where formal-verification language will be tempted, and this is the answer.**
The verifier **proves** the five properties above *by construction*, and the proof of each is one
sentence about the ISA, not about a test suite. Everything in `TESTED_ONLY_PROPERTIES` is an
**empirical claim** and must be worded as one everywhere it appears — spec, ADR, findings,
docstring. `AssuranceLevel.A5` ("formally verified property set, **if actually proven**") may be
assigned **only** for a property in `PROVEN_PROPERTIES`, and `promote_cell` enforces that. A
bytecode VM that is "safe" because no test broke it is at A4 at best.

```python
# vm.py
MAX_CELL_STEPS = MAX_INSTRUCTIONS

@dataclass(frozen=True, slots=True)
class CellFrame:                          # the ONLY thing a cell may read — §30 "normalized Stage 1 data"
    state: SecurityStateV1; delta: StateDelta
    actor_properties: int; object_properties: int     # property_mask ints
    relation_family: RelationFamily
    phi: float; delta_phi: float; uncertainty: float
    epoch_id: int; window_counts: Mapping[int, int]
    evidence: tuple[EvidenceRef, ...]
    encoder_version: str

@dataclass(frozen=True, slots=True)
class CellResult:
    abstained: bool
    delta: StateDelta                      # plan §3.2 binding: run() returns a StateDelta ...
    evidence: tuple[EvidenceRef, ...]      # ... plus tuple[EvidenceRef, ...]
    risk: float
    escalation: EscalationDecision | None
    steps_executed: int
    reason: str

class CellVM:
    def __init__(self, *, max_steps: int = MAX_CELL_STEPS) -> None
    def run(self, program: OperatorProgram, frame: CellFrame) -> CellResult
        # Calls verify() first. An unverified or failing program ABSTAINS; it never executes.
        # No file, socket, subprocess, import, eval or attribute-lookup path exists in this module.
```

**Bounds.** 64 instructions, stack depth 16, 32 constants, 32 set members, zero allocation after
frame construction. `CellVM` imports only `pocketsec.stage0/1/3` and the stdlib; asserted by
`tests/test_stage3_boundary.py`.

### D3.7 — Multi-operator synthesis and selector
**Modules:** `synthesis/operators.py`, `synthesis/selector.py` · **Package:** `synthesis`

```python
# operators.py — one bounded synthesiser per form. Each returns None when it cannot fit.
def synthesize_constant(samples) -> OperatorProgram | None
def synthesize_lookup_table(samples, *, max_entries: int = 1024) -> OperatorProgram | None
def synthesize_bitset_predicate(samples) -> OperatorProgram | None
def synthesize_decision_dag(samples, *, max_depth: int = 4, max_nodes: int = 31) -> OperatorProgram | None
def synthesize_fsm_fragment(samples, *, max_states: int = 8) -> OperatorProgram | None
def synthesize_weighted_transition(samples, *, max_states: int = 8) -> OperatorProgram | None
def synthesize_linear_expression(samples, *, max_terms: int = 6) -> OperatorProgram | None
def synthesize_bytecode(samples, *, max_instructions: int = 24, node_budget: int = 20000
                        ) -> OperatorProgram | None     # bounded enumerative over PCB
SYNTHESISERS: tuple[tuple[OperatorForm, Callable[..., OperatorProgram | None]], ...]

# selector.py                                                    §13 "cheapest candidate satisfying"
@dataclass(frozen=True, slots=True)
class OperatorCandidate:
    program: OperatorProgram
    microseconds_per_event: float | None    # within-run measurement; None == UNMEASURED
    bytes_resident: int
    equivalence: DualOracleVerdict
    loadavg_at_measurement: float           # contended host; recorded with every timing
def measure_candidate(program, frames, *, repetitions: int = 7) -> OperatorCandidate
    # min-of-repetitions, and the report carries /proc/loadavg. Absolute microseconds are NEVER
    # presented as a device figure; only within-run ratios transfer.
def select_operator_form(candidates: Sequence[OperatorCandidate], *,
                         constraints: Sequence[HardConstraint]) -> OperatorCandidate | None
def pareto_frontier(candidates) -> tuple[OperatorCandidate, ...]
```

**Bound and rule.** A candidate with `microseconds_per_event is None` is **never** selected —
UNMEASURED is not cheap. The selector refuses a candidate whose `equivalence.hard_violations` is
non-empty *before* considering cost.

### D3.8 — Dual-oracle security-equivalence engine
**Modules:** `oracles/security_specs.py`, `oracles/teacher.py`, `oracles/dual_oracle.py`
· **Package:** `oracles`

```python
# security_specs.py — ORACLE B. Stage 1 invariants that already exist in code.
@dataclass(frozen=True, slots=True)
class Violation: constraint_id: str; kind: ConstraintKind; detail: str; frame_digest: str

def check_hard_security_constraints(cell, frame: CellFrame, result: CellResult
                                    ) -> tuple[Violation, ...]
    # NEVER_SUPPRESS_MANDATORY_EVIDENCE: result.evidence must cover MANDATORY_SIGNALS coverage
    #   of frame.evidence (stage1/observation/policy.py:47).
    # NEVER_LOWER_PHI:        phi(apply(frame.state, result.delta)) >= phi(frame.state).total
    # STATE_MONOTONE:         SecurityStateV1.join(before, after) == after   (security_state.py:165)
    # NEVER_DOWNGRADE_CONSEQUENCE / NEVER_NORMALISE_HIGH_CONSEQUENCE: a frame whose
    #   consequence_of(...) is HIGH or CRITICAL may not receive a benign result, whatever the
    #   teacher says. This is the clause that catches teacher error.

# teacher.py — ORACLE A, as DATA (integration plan §2.5). Never a live forward pass.
TEACHER_SNAPSHOT_V1_ID = "pocketsec.teacher_snapshot.v1"
@dataclass(frozen=True, slots=True)
class TeacherSnapshotV1:
    teacher_id: str
    source: str                  # "phi-oracle" | "tcn"   ("tcn" NOT produced by this wave)
    encoder_version: str; corpus_version: str; seed: int
    responses: Mapping[str, float]        # canonical frame digest -> score
    measured_by: str; experiment_id: str
    digest: str
def frame_digest(frame: CellFrame) -> str        # canonical sha256; the snapshot join key
def write_snapshot(s, path: Path) -> str ; def load_snapshot(path: Path) -> TeacherSnapshotV1
class TeacherOracle:
    def __init__(self, snapshot: TeacherSnapshotV1 | None) -> None
    @property available(self) -> bool
    def consult(self, frame: CellFrame) -> float | None   # None == not in snapshot == UNKNOWN

# dual_oracle.py — §19 D_sec, §20 dual oracle
@dataclass(frozen=True, slots=True)
class SecurityDivergence:
    d_state_delta: float
    d_security_potential: float
    d_future_hazard: None            # PERMANENTLY None: hazard REJECTED by ADR-0116
    d_uncertainty: float
    d_evidence_requirement: float
    d_causal_attribution: float
    weights: Mapping[str, float]
    @property total(self) -> float | None      # None if any weighted term is None

@dataclass(frozen=True, slots=True)
class DualOracleVerdict:
    passed: bool
    teacher_available: bool
    teacher_divergence: float | None           # None == UNMEASURED, never 0.0
    envelope: float
    divergence: SecurityDivergence
    hard_violations: tuple[Violation, ...]
    consequence: SecurityConsequence
    reason: str

class DualOracleEvaluator:
    def __init__(self, *, teacher: TeacherOracle, vm: CellVM) -> None
    def evaluate(self, cell, frames: Sequence[CellFrame]) -> DualOracleVerdict
        # PASSES only if: teacher_divergence <= envelope(consequence) AND hard_violations == ().
        # If teacher_available is False the verdict FAILS with reason "TEACHER_UNAVAILABLE".
        # It never passes on Oracle B alone, and never passes on Oracle A alone.
```

**Bound.** `envelope` is a closed mapping over `SecurityConsequence`, monotonically tighter with
consequence. `d_future_hazard` is typed `None` so a future contributor cannot quietly restore a
mechanism ADR-0116 rejected on measured calibration.

### D3.9 — Counterexample memory and regression corpus
**Module:** `oracles/counterexamples.py` · **Package:** `oracles`

```python
MAX_HOT_COUNTEREXAMPLES = 2048
MAX_HOT_BYTES = 15 * 1024 * 1024        # §38 "Counterexample hot store < 5-15 MB"

@dataclass(frozen=True, slots=True)
class Counterexample:                    # §21, field-for-field
    counterexample_id: str
    cell_candidate_id: str
    transitions: tuple[SSIRTransitionV1, ...]
    state: SecurityStateV1
    epoch_id: int
    expected: CellResult
    observed: CellResult
    divergence_type: str
    evidence: tuple[EvidenceRef, ...]
    incident_linked: bool                # immune to GC and to melting (§29, §40)
    superseded_by: str | None

class CounterexampleStore:
    def __init__(self, *, cold_archive: Path | None, max_hot=MAX_HOT_COUNTEREXAMPLES,
                 max_bytes=MAX_HOT_BYTES) -> None
    def record(self, cx: Counterexample) -> None
        # At capacity: the OLDEST non-incident-linked entry is written to the cold archive and
        # dropped from hot. An incident-linked entry is NEVER dropped; if all entries are
        # incident-linked the store raises rather than deleting one.
    def replay_all(self, cell, *, vm: CellVM) -> tuple[Counterexample, ...]   # regression corpus
    def supersede(self, old_id: str, new_id: str) -> None    # never delete; supersede + keep lineage
    def for_candidate(self, candidate_id: str) -> tuple[Counterexample, ...]
    def memory_bytes(self) -> int
```

**Bound and rule.** No delete API. `supersede` marks; the archive is append-only. "Never delete
prior research artefacts, counterexamples, provenance or rollback information" is enforced by the
absence of a method, not by review.

### D3.10 — Cell fission / fusion
**Modules:** `cells/fission.py`, `cells/fusion.py` · **Package:** `synthesis`

```python
MAX_FISSION_DEPTH = 3
class FissionDomain(StrEnum): STABLE; AMBIGUOUS; INVALID
@dataclass(frozen=True, slots=True)
class FissionResult:
    stable: KnowledgeCellV1 | None          # K_A remains crystallized
    ambiguous: CellBoundary | None          # K_B: returned to the learned path
    invalid: CellBoundary | None            # rejected outright
    depth: int; reason: str
def fission_cell(cell, counterexamples: Sequence[Counterexample], *, depth: int) -> FissionResult
    # Splits ONLY the heterogeneous region (§22). Refuses at MAX_FISSION_DEPTH, and refuses when
    # the split would push the field past MAX_CELLS — the "knowledge explosion" cap (§39).

def fuse_cells(a: KnowledgeCellV1, b: KnowledgeCellV1) -> KnowledgeCellV1 | None
    # §23: only if SecurityFuture(a) ~= SecurityFuture(b) AND the boundary UNION stays validated.
    # A fused cell re-enters shadow at A0; fusion is reversible via parent_cell_id.
```

### D3.11 — Shadow promotion and assurance-state pipeline
**Modules:** `promotion/shadow.py`, `promotion/assurance.py` · **Package:** `lifecycle`

```python
# shadow.py                                                      §26
@dataclass(frozen=True, slots=True)
class ShadowRun:
    frames_seen: int; distinct_boundary_keys: int; distinct_transitions: int
    agreements: int; divergences: tuple[BoundaryProbe, ...]
    consequence: SecurityConsequence
    coverage_met: bool; reason: str
SHADOW_MIN_COVERAGE: Mapping[SecurityConsequence, tuple[int, int]]   # (frames, boundary keys)
def shadow_execute(cell, frames, *, oracle: DualOracleEvaluator, vm: CellVM) -> ShadowRun
    # Coverage is consequence-dependent and measured in BOUNDARY COVERAGE and DIVERSITY OF
    # TRANSITIONS, not in a fixed event count (§26).

# assurance.py
@dataclass(frozen=True, slots=True)
class AssuranceState:                    # Stage 10 EXTENDS this; it must not fork it
    level: AssuranceLevel
    replay: ShadowRun | None              # A1
    pressure: BoundaryPressureReport | None   # A2
    shadow: ShadowRun | None              # A3
    exhaustive_domain: str | None         # A4 — the bounded domain actually enumerated
    proven_properties: tuple[str, ...]    # A5 — must be a subset of PROVEN_PROPERTIES
    prover: str | None                    # "module:function"; None forbids A5
    counterexamples_open: int
    def to_dict(self)

class PromotionOutcome(StrEnum):
    PROMOTED; REFUSED_ASSURANCE; REFUSED_COVERAGE; REFUSED_HARD_CONSTRAINT
    REFUSED_FIELD_FULL; REFUSED_OPEN_COUNTEREXAMPLE
@dataclass(frozen=True, slots=True)
class PromotionVerdict: outcome: PromotionOutcome; cell: KnowledgeCellV1 | None; reason: str
def promote_cell(cell, state: AssuranceState, *, field: KnowledgeField,
                 index: BoundaryIndex) -> PromotionVerdict
    # Raises if state.level is A5 and (state.prover is None or a claimed property is not in
    # PROVEN_PROPERTIES). This is the mechanical guard against formal-verification language.
    #
    # Refuses REFUSED_ASSURANCE below MIN_PROMOTABLE_ASSURANCE = A1. ASSURANCE_EVIDENCE[A0]
    # is the empty tuple, so `missing_evidence()` is empty at A0 and the assurance check was
    # vacuous exactly where §25 calls a cell "candidate only": a cell never replayed,
    # pressured or shadowed reached the answering path and emitted committal verdicts on
    # CHEAP_TRANSITION. A0 is also the only level this repository's cell producers emit —
    # `crystallize` builds at A0 and `fuse_cells` demotes to A0 "so it re-enters shadow",
    # which is a rule with no mechanism behind it unless promotion refuses the rung.
```

### D3.12 — Adaptive auditing and certificate decay
**Modules:** `promotion/audit.py`, `promotion/decay.py` · **Package:** `lifecycle`

```python
# audit.py                                                       §27, §40 anti-gaming
MIN_AUDIT_RATE = 0.001; MAX_AUDIT_RATE = 1.0
def audit_probability(cell, *, stress: CellStress, epoch_age: int,
                      boundary_distance: int, recent_agreement: float) -> float
class AuditSampler:
    def __init__(self, *, boot_salt: str) -> None
    def should_audit(self, cell, frame: CellFrame, *, probability: float) -> bool
        # Unpredictable WITHIN policy: the decision is a keyed hash of
        # (boot_salt, cell_id, cell.audit_policy.jitter_salt, frame_digest), not a counter
        # and not a seeded PRNG stream an attacker can phase against (§39 "audit gaming").
        # The rate stays inside [min, max].
        #
        # CORRECTION (defect-repair wave): this line named only
        # (boot_salt, cell_id, frame_digest) and the implementation matched it — which meant
        # `AuditPolicy.jitter_salt` was validated, serialised and carried across the Stage 4
        # seam while nothing read it, and the documented mitigation (rotate a compromised
        # cell's salt) was provably a no-op. The salt is now in the message. The secrecy is
        # still the BOOT salt's alone: every jitter_salt this repository produces is derived
        # from a public region key, so it buys separation between cells and rotation, not
        # unpredictability.
@dataclass(frozen=True, slots=True)
class AuditReport:
    audits: int; disagreements: int; rate_observed: float
    teacher_available: bool; teacher_cost_us: float | None
    teacher_silent: int = 0
        # Audited frames on which the oracle had NO OPINION: the snapshot held no answer and
        # no hard constraint fired. Counted apart from `disagreements` because `_decide`
        # returns not-passed for both, and reading a snapshot key miss as disagreement made
        # `CellStress.teacher_disagreement` read 1.0 — the maximum, at the heaviest weight —
        # for a cell nothing had been measured wrong about. `disagreement_rate` is None when
        # no audit produced an opinion, and `compute_cell_stress` refuses rather than scoring.

# decay.py                                                       §28 Gamma_(t+1)
DECAY_TERMS: Mapping[str, float]   # successful_audit_credit, disagreement_penalty,
                                   # epoch_shift_penalty, boundary_violation_penalty,
                                   # unobserved_change_penalty
MIN_ASSURANCE_CONFIDENCE = 0.35
def decay_confidence(confidence: float, *, successful_audits: int, disagreements: int,
                     epoch_shifts: int, boundary_violations: int,
                     unobserved_changes: int) -> float          # clamped to [0, 1]
def below_minimum(confidence: float) -> bool
    # Crossing MIN_ASSURANCE_CONFIDENCE raises the audit rate OR melts — never silently continues.
```

**Rule.** Age alone never decays confidence. §28: "age alone does not automatically make knowledge
wrong, but untested change reduces trust." There is no time term in `decay_confidence`.

### D3.13 — Partial / full melting and recrystallization
**Modules:** `melting/stress.py`, `melting/partial.py`, `melting/full.py` · **Package:** `lifecycle`

```python
# stress.py                                                      §24
@dataclass(frozen=True, slots=True)
class CellStress:
    teacher_disagreement: float; boundary_violations: int; epoch_drift: int
    uncertainty_rise: float; counterexamples: int; calibration_decay: float
    @property total(self) -> float
PARTIAL_MELT_THRESHOLD: float; FULL_MELT_THRESHOLD: float
def compute_cell_stress(cell, *, audit: AuditReport, pressure: BoundaryPressureReport | None,
                        store: CounterexampleStore) -> CellStress

# partial.py / full.py
class MeltKind(StrEnum): PARTIAL; FULL
@dataclass(frozen=True, slots=True)
class MeltReport:
    cell_id: str; kind: MeltKind
    melted_region: CellBoundary | None
    surviving_cell: KnowledgeCellV1 | None
    reopened_keys: tuple[BoundaryKey, ...]
    unrelated_cells_before: int
    unrelated_cells_retained: int        # a bystander sanity check, NOT the number
                                         # G3.7 turns on — see the correction below
    rollback_version: int; reason: str
    @property repair_locality(self) -> float | None   # retained / before; None if before == 0

def partial_melt(cell, region: CellBoundary, *, field: KnowledgeField,
                 index: BoundaryIndex) -> MeltReport

# CORRECTION (Stage 3 defect-repair wave). `repair_locality` cannot falsify F2.
# `partial_melt` touches only `cell.cell_id` and `successor_cell_id(cell)`, and
# `KnowledgeField.insert` refuses rather than evicting, so no statement in its
# success path can remove a bystander: the ratio is 1.0 or None on every report
# that exists, and a `partial_melt` with its narrowing logic deleted reports the
# same 1.0. What can fail, and what G3.7 now asserts, is that the survivor is live
# in both containers, that its key set is a PROPER SUBSET of the original's, that
# its boundary shares no satisfiable frame with the drifted region, and that a
# frame the index answered before the melt routes to abstention after it.
#
# Two further corrections to the melting algebra, both measured:
#   * `narrow_boundary`'s accept condition must be FRAME-level, not key-level.
#     `keys()` is a product over declared requirements while `contains` is a
#     conjunction matched by superset, so dropping an ACTOR predicate shrinks the
#     key set and ENLARGES the accepted frame set. Use
#     `CellBoundary.accepts_no_more_than`.
#   * Region overlap must be frame-level too: `keys()` folds `state_dimensions`
#     into one union delta mask while `contains` matches it by subset, so a
#     dimension-scoped drift is key-disjoint from a cell it fully reaches. Use
#     `CellBoundary.intersects`.
#
# `narrow_boundary` therefore takes the drifted region as a `CellBoundary`, not as
# a key set.
def full_melt(cell, *, field: KnowledgeField, index: BoundaryIndex) -> MeltReport
def recrystallize(report: MeltReport, *, config: CrystalConfig, teacher: TeacherOracle,
                  field: KnowledgeField, store: CounterexampleStore) -> CrystalRun | None
```

**This is the load-bearing claim.** `repair_locality` is the falsification number. Build this
experiment **first**: drive drift into one behavioural region of the drift corpus, and measure
whether unrelated cells survive and whether the melted region genuinely returns to the learned
path. See §8 F2.

### D3.14 — Intelligence GC and resource controller
**Modules:** `gc/controller.py`, `resources.py` · **Package:** `runtime`

```python
# gc/controller.py                                               §29 Utility(K)
@dataclass(frozen=True, slots=True)
class CellUtility:
    saved_compute_us: float | None; usage: int; assurance: float
    security_utility: float; memory_bytes: int
    audit_cost_us: float | None; maintenance_cost_us: float | None
    @property utility(self) -> float | None        # None if any measured term is None
@dataclass(frozen=True, slots=True)
class GCReport:
    evaluated: int; compacted: int; retained: int
    incident_protected: int; bytes_reclaimed: int; unmeasured_skipped: int
def garbage_collect_knowledge(field, *, index: BoundaryIndex, store: CounterexampleStore,
                              budget_bytes: int) -> GCReport
    # A cell whose utility is None (UNMEASURED) is RETAINED and counted in unmeasured_skipped.
    # Incident-linked evidence is preserved independently of cell GC and melting (§29, §40).

# resources.py                                                   §38
STAGE3_BUDGET: Mapping[str, int] = {
    "boundary_index":     8 * 1024 * 1024,
    "knowledge_cells":   20 * 1024 * 1024,
    "cell_vm":            8 * 1024 * 1024,
    "audit_state":        5 * 1024 * 1024,
    "counterexample_hot":15 * 1024 * 1024,
}
STAGE3_NORMAL_INCREMENTAL_RSS_BYTES = 25 * 1024 * 1024
STAGE3_PEAK_INCREMENTAL_RSS_BYTES   = 60 * 1024 * 1024
@dataclass(frozen=True, slots=True)
class Stage3ResourceReport:
    peak_sampled_rss_bytes: int | None; incremental_rss_bytes: int | None
    per_component_bytes: Mapping[str, int]; within_budget: bool | None   # None if UNMEASURED
    loadavg: tuple[float, float, float]
def measure_stage3_resources(...) -> Stage3ResourceReport    # uses ResourceSampler ONLY
```

### D3.15 — Baseline comparison, ablation, threat-model and falsification report
**Modules:** `labs/baselines.py`, `labs/boundary_evasion.py`, `labs/ablation.py`
· **Package:** `runtime` · **Document:** `docs/stage-3-findings.md` (**integrator-owned**)

See §7 for the baselines and §8 for the falsifiers. `labs/ablation.py` enumerates every
`FunctionClass.OPTIONAL` id in `core_ids.py` and requires each to name a recorded experiment id
with a measured delta — an OPTIONAL function with no experiment id is **FAILED**, not PENDING.
It runs the **saturation guard first** (integration plan §8 risk 2): if best and median models are
within 0.01 PR-AUC, or a pooled order-free control is within 0.02 of the best, the result is
`DEGENERATE` and **no ablation result is recorded**.

`labs/boundary_evasion.py` implements the §39 threat model as an executable suite: boundary
evasion, crystallization poisoning, audit gaming, cell-conflict DoS, certificate rollback,
malformed bytecode, knowledge explosion via forced fission, epoch manipulation, counterexample
poisoning. Nine cases, each asserting the §40 control that stops it.

### D3.16 — Frozen Stage 3 interface for Stage 4
**Modules:** `slot.py`, `stage4_interface.py` · **Package:** `runtime`

```python
# slot.py
class CrystalSlot:                        # satisfies stage0 ModelSlot protocol
    slot_name = "stage3-crystal"
    model_state_version: str; input_schema: str; output_schema: str
    def __init__(self, *, field: KnowledgeField, index: BoundaryIndex, vm: CellVM,
                 sampler: AuditSampler, teacher: TeacherOracle) -> None
    def predict(self, sequence: SecurityEventSequenceV1) -> ThreatPredictionV1
        # Cell hit  -> compute_path = ComputePath.CHEAP_TRANSITION (plan §3.2 binding)
        # No cell / conflict / off-boundary -> Verdict.UNKNOWN, abstention. NEVER a guess and
        #   NEVER a neural forward pass: Stage 3's runtime holds no model.
        # Carries evidence and causal attribution through; carries NO authority field.

# stage4_interface.py
CRYSTAL_HANDOFF_V1_ID = "pocketsec.crystal_handoff.v1"
@dataclass(frozen=True, slots=True)
class CrystalHandoffV1:
    handoff_id: str
    cells: tuple[Mapping[str, Any], ...]          # plain JSON — Stage 4 imports no Stage 3 class
    assurance: tuple[Mapping[str, Any], ...]
    boundary_keys: tuple[Mapping[str, Any], ...]
    melt_history: tuple[Mapping[str, Any], ...]
    encoder_version: str; interface_version: str
    def to_dict(self); @classmethod from_dict(...)
def build_crystal_handoff(field, index, *, handoff_id: str) -> CrystalHandoffV1
def write_crystal_handoff(h, path: Path) -> str   # canonical JSON, returns "sha256:" digest
```

The seam mirrors `Stage3Handoff` exactly: plain data only, canonical bytes, content digest, and a
`seam_violations`-style refusal so a Stage 3 class name can never cross into Stage 4.

---

## 5. Work packages

Eight packages. **No two share a file.** `pocketsec/stage3/{gate.py, cli.py, __init__.py}`,
`docs/stage-3-findings.md` and the ADR files are **integrator-owned** and appear in no package.
`tests/test_stage3_boundary.py` (the AST dependency-boundary check named by the wave brief) is
owned by `foundation`; the Knowledge-Boundary package's tests are
`tests/test_stage3_knowledge_boundary.py` so the two never collide.

| # | key | delivers | depends on |
|---|---|---|---|
| 1 | `foundation` | D3.1, D3.5 (+ `Invariant`, `core_ids`, boundary test) | — |
| 2 | `bytecode` | D3.6 | foundation |
| 3 | `invariants` | D3.3 | foundation |
| 4 | `knowledge_boundary` | D3.4 | foundation, bytecode, invariants |
| 5 | `oracles` | D3.8, D3.9 | foundation, bytecode, knowledge_boundary |
| 6 | `synthesis` | D3.2, D3.7, D3.10 | foundation, bytecode, invariants, knowledge_boundary, oracles |
| 7 | `lifecycle` | D3.11, D3.12, D3.13 | foundation, bytecode, knowledge_boundary, oracles |
| 8 | `runtime` | D3.14, D3.15, D3.16 | all of the above |

Each package is roughly 600–1200 lines of new code *including* its test file. Each ships
`tests/test_stage3_<key>.py`.

---

## 6. Acceptance gate, as executable checks

Thirteen checks, one per criterion in `planning/PHASE_03_CLAUDE_CODE.md` §42. Integration plan
§5.1 fixes the count at **13**. Every `_check_*` runs the real subsystem; none reads a document,
with the single unavoidable exception of G3.12/G3.13, which are *about* documents and are
described precisely below.

| id | criterion | executable check | met on synthetic data? |
|---|---|---|---|
| **G3.1** | Stage 2 baseline frozen and reproducibly benchmarked before Stage 3 comparisons | Read `results/stage2-frontier.json` (written by `python -m pocketsec.stage2.research.cli frontier`). **Refuse** evidence whose `(corpus, count, seed)` differs from the split the gate itself ran. Assert the frozen `TeacherSnapshotV1` digest matches the pinned seed. Missing or mismatched evidence ⇒ **FAIL as UNMEASURED**, never PASS. | yes |
| **G3.2** | ≥4 alternative compilation/distillation baselines implemented | Run all five baselines in `labs/baselines.py` on one split in one run; assert each beats `Stage2Dataset.base_rate` by more than `AT_CHANCE_PR_AUC_BAND` (0.01); emit the PR-AUC × µs/event × bytes table. A baseline measurably **below** chance is a **bug** and the whole comparison is refused, not reported. A baseline **within** the band is reported `AT_CHANCE` — it is not a working control, and the sign of a margin that small is not a result. B4 sits there on the drift corpus at +0.0086, which is why this criterion FAILS. | yes |
| **G3.3** | Cells have versioned schema, bounded operator form, explicit validity boundary | Build a `KnowledgeCellV1` from the exported Φ-oracle candidate; assert `schema_version` registered; assert `verify(cell.operator).ok`; assert `not cell.boundary.is_empty`; assert `ContractError` on each of empty evidence / empty epochs / empty boundary / oversized operator / an authority-named field. | yes |
| **G3.4** | Boundary Pressure finds counterexamples missed by naive random replay, **or it is removed** | `apply_boundary_pressure(strategy=GUIDED)` vs `random_replay_control`, **same budget, same seed family, same run**. PASS iff `guided.counterexample_classes - random.counterexample_classes` is non-empty on ≥1 controlled test class. Empty ⇒ FAIL, and ADR-0026 **removes** D3.4's guided search. | yes |
| **G3.5** | Dual-oracle prevents predefined teacher-error crystallization cases | Three constructed cases in `labs/baselines.py`: (a) a teacher snapshot that scores a `CRITICAL`-consequence frame benign; (b) one that suppresses a `MANDATORY_SIGNALS` evidence requirement; (c) one that lowers Φ. Assert `DualOracleEvaluator.evaluate(...).passed is False` with a `hard_violations` entry for each, and assert a teacher-only control **would** have passed all three. | yes |
| **G3.6** | Promotion, sampled auditing, partial melting and full melting work end-to-end | One scripted sequence over the drift corpus: crystallize → promote → audit at a sampled rate → drift → `partial_melt` → `full_melt` → `recrystallize`. Assert each step's report is non-degenerate and the field's cell count and bytes stay under `MAX_CELLS` / `MAX_FIELD_BYTES` at every step. | yes |
| **G3.7** | Localized drift reopens a subregion without discarding unrelated crystallised knowledge | Crystallize ≥4 cells across ≥2 boundary regions of the drift corpus; drive the corpus's epoch-1→2 package change into **one** region; assert `reopened_keys` is **non-empty** and ⊆ the drifted region's keys; that the survivor is live in both the field and the index with a **proper subset** of the original's keys and no satisfiable frame in common with the drifted region; and that a frame the index answered before the melt routes to abstention (the learned path) afterwards. `MeltReport.repair_locality` is reported as a bystander sanity check — it is 1.0 by construction and is **not** the assertion (see §D3.13). | yes |
| **G3.8** | Crystallized execution preserves required evidence and causal attribution | For every frame resolved by a cell, assert `CellResult.evidence` covers the frame's `MANDATORY_SIGNALS` evidence and the `ThreatPredictionV1` from `CrystalSlot` resolves to a non-empty `EvidenceRef` chain; assert the `causal_signature` of the resolving transition survives into the prediction. | yes |
| **G3.9** | End-to-end average CPU/event materially lower than pure DTL at comparable security quality — **RESTATED, see below** | Measure, in **one run** with `/proc/loadavg` recorded: the within-run ratio of µs/event for (i) `CrystalSlot` over the field, (ii) baseline B3 (Φ-oracle unchanged), (iii) B1 lookup table, (iv) B4 frozen-teacher LRU; plus bytes for each. PASS requires (i) ≤ (ii) on **both** µs ratio and bytes. The **security-quality clause is reported as `UNMEASURED`** with the reason. | **NO** |
| **G3.10** | Stage 3 incremental memory within the declared Edge budget | `measure_stage3_resources()` via `ResourceSampler` only; assert per-component bytes under `STAGE3_BUDGET` and incremental RSS under `STAGE3_NORMAL_INCREMENTAL_RSS_BYTES`. `within_budget is None` (UNMEASURED) ⇒ FAIL. | yes |
| **G3.11** | No surviving component lacks ablation-supported value | `labs/ablation.py` enumerates `FunctionClass.OPTIONAL` ids in `core_ids.py`; each must name a registered experiment id with a measured delta. Run the **saturation guard first**; `DEGENERATE` ⇒ FAIL with that reason and no recorded ablation. | partly — see §9 |
| **G3.12** | All claims of formal verification limited to properties actually proven | Two parts, both executable: (a) assert `set(AssuranceState.proven_properties) ⊆ set(PROVEN_PROPERTIES)` for every promoted cell and that `prover` is non-`None` for any A5; (b) grep `docs/stage-3-*.md` and `pocketsec/stage3/**/*.py` for `proven`, `verified`, `formally`, `sound`, `guarantee` and assert each occurrence is within 3 lines of a `module:function` path or of the literal string `empirical`. | yes |
| **G3.13** | Prior-art review completed before any external novelty claim | Assert `docs/prior-art/ledger.json` holds an entry for Stage 3's hypothesis (H9) and that `docs/stage-3-findings.md` contains no novelty-claiming phrase (`novel`, `first`, `unprecedented`, `patent`) unless the matching ledger entry's `literature_status != "NOT_REVIEWED"`. | yes |

### 6.1 G3.9, restated honestly — ADR-0024

The architecture's wording ("materially lower than pure DTL") is void: DTL is rejected, costs
22.3 µs/event (cited, not measured here), and beating it proves nothing. Substituting "lower than
the TCN's 6.6 µs/event" is only marginally better, because the thing Stage 3 actually wraps is a
zero-parameter oracle at ≈0.1 µs/event.

**The bar this wave must clear, and the only one worth reporting:**

> In a single run, on one host, with the load average recorded, a `KnowledgeCellV1` reproducing
> the Φ-oracle must cost **no more** µs/event and **no more** bytes than running the Φ-oracle
> directly (baseline B3), while producing identical scores on every frame in the split.

If it costs more, the **cell format is rejected for this class of knowledge** and the wave says so
plainly in ADR-0021 and `docs/stage-3-findings.md`. That is a real result, not a failure to
deliver.

**The security-quality half of the criterion cannot be met and is not claimed.** "Comparable
security quality" requires a corpus where security quality is discriminable. Four synthetic
corpora produced only trivial or impossible tasks, never a middle band (ADR-0010); the Stage 2
gate's own G2.2 reports `ORDER_FREE_BASELINE_TIES_BEST`. Reporting a PR-AUC on such a split as
evidence of equivalence would be the exact lie this project rejected its own Stage 2 core to
avoid. G3.9 therefore reports the cost ratio as MEASURED and the quality clause as UNMEASURED,
and the check **fails** rather than passing on half the criterion.

---

## 7. Baselines Stage 3 must beat

The gate demands at least four alternative compilation/distillation baselines. These are the
**dumbest things that could work**, and they are the comparison, not a formality. Stage 2 already
found that an atom/epoch-keyed cache **loses** to a plain LRU keyed on
`(relation_family, state_delta_mask)` (`PROGRESS.md`, G2.10: 0.9966 vs 0.9977). Expect the same
family of result here and do not flinch from it.

| id | baseline | what it is | the metric it must lose on, for the advanced component to survive |
|---|---|---|---|
| **B1** | `PlainLookupTable` | `dict[BoundaryKey, float]` keyed on the quantised representation — no invariant, no boundary, no VM | **Knowledge Field + BoundaryIndex** must match B1's coverage at ≤ B1's bytes *and* provide a melt path B1 cannot. Equal coverage at more bytes ⇒ the field machinery is rejected. |
| **B2** | `DepthLimitedTree` | depth ≤ 4 Gini tree on `EncodedTransition` features, pure stdlib | **Multi-operator synthesis + selector (D3.7)** must produce an operator at ≤ B2's µs/event and ≤ B2's bytes at equal equivalence. If `DECISION_DAG` is always selected, the other seven synthesisers are NOT_YET_JUSTIFIED and must say so. |
| **B3** | `PhiOracleUnchanged` | `DeterministicScorerSpec` at `PHI_SQUASHED_FEATURE_INDEX = 73`, invoked directly — **no cell machinery at all** | **The whole of Stage 3.** A Φ-oracle `KnowledgeCellV1` must cost ≤ B3 on µs/event **and** bytes at identical scores. This is G3.9 and falsifier F1. |
| **B4** | `FrozenTeacherLRU` | `TransitionCache` (existing, `stage2/cache/transition_cache.py:227`) with `lru_control` eviction, keyed on `(relation_family, state_delta_mask)`, serving a frozen `TeacherSnapshotV1` | **Cell promotion + audit (D3.11/D3.12)** must achieve a lower *total* cost than B4 once audit traffic is counted. If audit cost ≥ the cell's saving, falsifier F5 fires. |
| **B5** | `NoStage3` | Stage 1 Φ path only, plus a drift detector (`epoch_guard.detect_epoch_mismatch` semantics) — the §35 "No Stage 3" row | **Melting (D3.13).** Stage 3's only defensible advantage is *localised* repair. B5 invalidates everything on drift. If `repair_locality` does not exceed B5's (which is 0.0 by construction) on a *measured* run, the stage reduces to distillation plus cache invalidation. |

Every baseline runs in the **same run** as the mechanism it controls, and every comparison is a
**within-run ratio**. Absolute microsecond figures are recorded with `/proc/loadavg` and are never
presented as device measurements.

---

## 8. What would falsify this stage's central claim

**The central claim.** *Security-relevant knowledge, once resolved, can be represented as a
validity-bounded executable Knowledge Cell whose cost is auditable, and localised drift can melt
one subregion of that knowledge without discarding unrelated crystallised knowledge.*

| id | falsifier | measurement that decides it | if it fires |
|---|---|---|---|
| **F1** | A `KnowledgeCellV1` reproducing the Φ-oracle costs more µs/event **or** more bytes than B3 at identical scores | G3.9 within-run ratio | The cell **format** adds nothing over the rule it wraps. Report in ADR-0021; Stage 3 does not crystallise deterministic scorers. |
| **F2** | Partial melt reopens cells outside the drifted region, or the melted region keeps answering from a stale cell. **Restated by the defect-repair wave:** the first clause was written as `MeltReport.repair_locality < 1.0`, which cannot happen — see the correction under §D3.13. The testable form is: the survivor's key set is not a proper subset of the original's, or its boundary still intersects the drifted region, or a frame inside the drifted region still resolves through the index | G3.7 | **The stage reduces to ordinary distillation plus cache invalidation.** Say that plainly; ADR-0025. This is the one that matters most. |
| **F3** | Guided Boundary Pressure finds no counterexample class that random replay misses at the same budget cap | G3.4 | Remove D3.4's guided search (the architecture gate says "or it is removed"). ADR-0026. |
| **F4** | The dual oracle passes any of the three constructed teacher-error cases | G3.5 | Oracle B is decorative; the dual-oracle design does not prevent teacher-error crystallization. Report as a failure of §20. |
| **F5** | Audit traffic needed to hold confidence above `MIN_ASSURANCE_CONFIDENCE` costs ≥ the cell's measured saving | G3.6 + B4 | §41: "Knowledge Cells require so much audit traffic that DTL rarely sleeps." The promotion path is not worth its keep. |
| **F6** | Any property in `PROVEN_PROPERTIES` turns out to need a runtime check rather than a static argument | G3.12(a) + the verifier's own tests | Move it to `TESTED_ONLY_PROPERTIES` and reword every mention. No A5 cell may exist. |
| **F7** | B1 (plain lookup table) achieves equal compilation coverage at fewer total bytes | G3.2 + G3.9 | §41: "A static cache achieves comparable wake-rate reduction with materially lower complexity." The Knowledge Field is rejected. |
| **F8** | Field cell count or bytes grow without bound under `labs/boundary_evasion.py`'s forced-fission case | G3.6 + the threat suite | §39 "knowledge explosion" is unmitigated; `MAX_FISSION_DEPTH`/`MAX_CELLS` caps are insufficient. |
| **F9** | Invariant discovery over-generalises and boundary search cannot control false negatives — `BoundaryPressureReport.false_inside` stays high after refinement | G3.4 | §41 clause 3. Anti-unification's generalisation floor is wrong or the boundary language is too weak. |

---

## 9. Honest limits — what this stage will **not** be able to prove on synthetic data

Stated here so it cannot be forgotten, and required verbatim in the findings document's
**NOT A DETECTION RESULT** section (integration plan §7).

1. **No detection result generalises.** Every corpus in this repository is synthetic. ADR-0010:
   four synthetic corpora produced only trivial or impossible tasks, never a middle band; real
   telemetry is required before a predictive core can be judged. Stage 3 may validate its
   **mechanism** — verifier soundness, boundary semantics, melt/rollback, bytecode bounds,
   composition algebra — and may **not** claim a compression or detection result that transfers.
2. **"Comparable security quality" (G3.9) is unmeasurable here** and is reported as UNMEASURED.
   See §6.1.
3. **The TCN-sourced teacher snapshot does not exist this wave** (§2.3). Every dual-oracle result
   is against the `"phi-oracle"` source. Teacher-error *resistance* is demonstrated against
   **constructed** corrupted snapshots, which is a valid mechanism test and is not evidence about
   a real TCN's error modes.
4. **Absolute timings are not device measurements.** The host is contended (`/proc/loadavg`
   `13.76 12.40 13.95` while this spec was written; a Stage 2 gate run measured a 7× inflation at
   load 23–67 vs 8–12). Only within-run ratios transfer.
5. **Ablation (G3.11) may be refused as `DEGENERATE`** rather than passed. The Stage 2 gate's G2.2
   already reports `ORDER_FREE_BASELINE_TIES_BEST` on the ambiguous corpus. A saturated split
   cannot show that any component helps; `NOT_YET_JUSTIFIED` is the honest verdict and is **not**
   the same as `REJECTED`.
6. **`PATH_COST_UNITS` is uncalibrated** (ADR-0114), so any "compute units per event" figure is a
   policy unit, not a cost. Report `path_cost_units_calibrated: false`.
7. **Repair locality is measured against a corpus whose drift we authored.** A drift the corpus
   designer planted is easier to localise than a drift reality plants. The result is a mechanism
   demonstration, not a field claim.
8. **`ruff` and `mypy` have never been run in this repository.** If they cannot be run this wave,
   lint and type status stays `UNVERIFIED` — not "clean".

---

## 10. ADRs this wave must write — block 0020–0029

Verified free: `ls docs/adr/` returns `0000 … 0010` and `0113 … 0122`. All of 0020–0029 are
unused. Every ADR uses `docs/adr/0000-adr-template.md` and keeps its **Options considered** table
with a **measured consequence** column; an options table with no measured column is a design note,
not an ADR.

| ADR | decision |
|---|---|
| **0020** | Stage 3 ships no `research/` package and no third-party import; Oracle A is data. Records why `tests/test_repository_structure.py` is not edited and why ADR-0011 stays unspent. |
| **0021** | `KnowledgeCellV1` schema, the eight operator forms, and the deliberate omission of `RESIDUAL_MICRO_MODEL`. **Carries the F1 verdict** — whether the cell format beats the rule it wraps. |
| **0022** | PCB ISA v1: the five properties the verifier **proves by construction** and the four it only **tests**, with the argument for each. |
| **0023** | Oracle A rebound to a frozen `TeacherSnapshotV1`; Oracle B bound to Stage 1's existing invariants. Records that the architecture document's DTL assumption is void. |
| **0024** | G3.9 restated: speed-over-DTL is meaningless; the bar is the Φ-oracle on cost and bytes, and the quality clause is UNMEASURED. |
| **0025** | **Melting locality** — the F2 verdict. Whether localised repair is real or the stage reduces to distillation plus cache invalidation. |
| **0026** | Boundary Pressure kept or removed, on the measured guided-vs-random-replay comparison (F3). |
| **0027** | Operator-selector default form, on the measured Pareto frontier; which synthesisers are `NOT_YET_JUSTIFIED`. |
| **0028** | Stage 3's corpus is the Stage 2 drift corpus replayed with `DRIFT_EPOCH_SIGNALS`. **G2.13's `distinct_epochs >= 2` is not lowered.** |
| **0029** | Field bounds, GC retention policy and the §38 resource budget as enforced constants; what is protected from GC and melting. |

Two ADRs are pre-assigned by the build contract and are **not** in Stage 3's block:
**ADR-0011** (widen `RESEARCH_PREFIXES`) is deferred unspent by ADR-0020; **ADR-0012** (add
hypotheses H9–H18 and their prior-art ledger entries) is required before any Stage 3 experiment id
can name `H9`, because `tests/test_harness_and_gate.py:241` asserts
`set(ledger.entries) == set(HYPOTHESES)`. The integrator writes ADR-0012 or Stage 3 uses `H4`
("Neural-to-symbolic JIT compilation"), which is the honest existing binding for D3.2/D3.7.

---

## 11. Honesty ledger — required section format

`docs/stage-3-findings.md` (integrator-owned) must end with the five headings from integration
plan §7, verbatim in structure: **MEASURED**, **UNMEASURED**, **REJECTED**, **RETRACTED**,
**NOT A DETECTION RESULT**. The Stage 3 gate includes a check that the file exists and contains
all five.

Three distinctions the format exists to keep, restated because this wave will be tempted by all
three:

- **NOT-YET-JUSTIFIED is not REJECTED.** A component that showed no benefit on a *saturated*
  corpus has not been disproven; it has not been tested.
- **RETRACTED is not deleted.** Supersede and keep the lineage, with the defect that produced the
  original.
- **`None` never means zero.** A cost that could not be measured is `None`; a profile that could
  not be checked is `None`, never "within target".
