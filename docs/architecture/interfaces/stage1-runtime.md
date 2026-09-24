# Stage 1 runtime interface reference — pipeline, slot, observation, aggregation, gate, CLI, labs, guillotine

> **Scope.** This document is an EXACT API reference for the Stage 1 *driver* layer:
> `pocketsec/stage1/pipeline.py`, `slot.py`, `observation/policy.py`,
> `aggregation/policy.py`, `gate.py`, `cli.py`, `labs/*.py`, `guillotine/*.py`.
> It does **not** document the SSIR core (`ssir/`, `compiler/`, `state/`, `novelty/`,
> `causal/`, `epoch/`, `telemetry/`) except where a signature in this layer requires it;
> those are separate reference documents.
>
> **Honesty contract.** Every number in this document was produced by running code in the
> authoring session (2026-09-24, from the repo root with `PYTHONPATH=.`). Numbers I did not
> measure are written `UNMEASURED`. Every symbol below was read out of the named `.py` file;
> nothing is inferred from other documentation. Line numbers are as of the file state read
> in that session — if a file has been edited since, re-grep the symbol rather than trusting
> the offset.

---

## 1. Purpose

This layer is the only sanctioned way to turn a labelled behaviour corpus into compiled SSIR
and then into a measurement. `Stage1Pipeline` wires the Stage 1 subsystems in fixed order —
raw records → `EventAssembler` → `SemanticCompiler` → (`CausalMemory`, `EpochModel`,
`AdaptiveObservationPolicy`, `AggregationPolicy`) — and replays one `Scenario` per call,
returning a `ScenarioResult` that every downstream consumer reads. `slot.py` exposes that
result through Stage 0's frozen `ModelSlot` boundary as two deliberately different model
families (symbolic Φ-reader, statistical novelty-reader) so the representation is never tuned
to one consumer. `observation/policy.py` and `aggregation/policy.py` are the two
budget-bounded policies the pipeline drives per transition: selective telemetry escalation
under hard caps, and conservation-rule-gated coalescing of repetitive low-value transitions.
`labs/` supplies four synthetic corpora with synchronised ground truth and the dual-sensor
emitter that makes cross-sensor equivalence testable; `guillotine/` measures what each SSIR
information family is worth by refitting a probe per ablation and reporting a Pareto frontier
with leave-one-out and multi-draw stability; `gate.py` and `cli.py` make the thirteen Stage 1
acceptance criteria executable. Because everything downstream — the gate, the guillotine,
the adversarial harness and the Stage 2 fixtures — runs through `Stage1Pipeline.run_scenario`,
they are all guaranteed to be measuring the same system.

---

## 2. Public symbols

Signatures are quoted verbatim. `file:line` is the definition line. Where `__all__` omits a
symbol that is nonetheless imported elsewhere in the repo, that is flagged — it is public in
practice.

### 2.1 `pocketsec/stage1/pipeline.py`

`__all__ = ["DEFAULT_SCENARIO_SPACING_NS", "DEFAULT_STEP_GAP_NS", "ScenarioResult", "Stage1Pipeline"]` (pipeline.py:33)

| Symbol | Signature / type | file:line | Purpose |
|---|---|---|---|
| `DEFAULT_STEP_GAP_NS` | `int = 1_000_000` | pipeline.py:41 | Gap applied between consecutive behaviours when a `Behaviour` does not declare `_gap_ns`. 1 ms. |
| `DEFAULT_SCENARIO_SPACING_NS` | `int = 60_000_000_000` | pipeline.py:43 | Timeline distance between scenarios: scenario `offset` is multiplied by this to place the scenario on the host timeline. 60 s. |
| `ScenarioResult` | `@dataclass(frozen=True, slots=True)` | pipeline.py:47 | Everything one scenario produced. Immutable. |
| `ScenarioResult.scenario` | `Scenario` | pipeline.py:50 | The input scenario, label included. |
| `ScenarioResult.transitions` | `tuple[SSIRTransitionV1, ...]` | pipeline.py:51 | **All** compiled transitions, in compile order. |
| `ScenarioResult.emitted` | `tuple[SSIRTransitionV1, ...]` | pipeline.py:52 | The subset the `AggregationPolicy` chose to emit (absorbed ones are absent). |
| `ScenarioResult.final_state` | `SecurityStateV1` | pipeline.py:53 | State of the **single hard-coded lineage** `f"proc:boot-0001:{pid}:7"` (pipeline.py:144), not of the host and not of all actors. See Trap T2. |
| `ScenarioResult.peak_phi` | `float` | pipeline.py:54 | `phi(final_state).total` (pipeline.py:151). Despite the name this is the *final-state* Φ, not a max over steps. See Trap T3. |
| `ScenarioResult.peak_novelty` | `float` | pipeline.py:55 | `max(t.novelty.peak for t in transitions)`, default `0.0` (pipeline.py:152). A true maximum. |
| `ScenarioResult.peak_uncertainty` | `float` | pipeline.py:56 | `max(t.uncertainty for t in transitions)`, default `0.0` (pipeline.py:153). A true maximum. |
| `ScenarioResult.unresolved` | `int` | pipeline.py:57 | Count of fused events for which `SemanticCompiler.compile` returned `None` (no recognisable machine relation). |
| `ScenarioResult.semantic_keys` | `@property -> tuple[Any, ...]` | pipeline.py:60 | `tuple(t.semantic_key() for t in self.transitions)`. Sensor-independent; this is the equality used for cross-sensor equivalence. Built from `transitions`, **not** `emitted`. |
| `ScenarioResult.to_dict` | `def to_dict(self) -> dict[str, Any]` | pipeline.py:64 | Keys: `scenario`, `transitions` (a **count**, not the objects), `emitted` (count), `final_state`, `peak_phi`, `peak_novelty`, `peak_uncertainty`, `unresolved`. Floats rounded to 4 dp. |
| `Stage1Pipeline` | `@dataclass` (mutable, not frozen, not slots) | pipeline.py:78 | One host's Stage 1 substrate. |
| `Stage1Pipeline.host_id` | `str = "lab-host-01"` | pipeline.py:81 | Field 1 (positional order matters). |
| `Stage1Pipeline.identity` | `SystemIdentity = field(default_factory=lambda: SystemIdentity(kernel_id="6.1.0", package_digest="pkg-a", service_digest="svc-a"))` | pipeline.py:82 | Field 2. Seeds the `EpochModel`. |
| `Stage1Pipeline.novelty` | `NoveltyEngine = field(default_factory=NoveltyEngine)` | pipeline.py:87 | Field 3. Handed to the `SemanticCompiler`; the pipeline and compiler share one instance. |
| `Stage1Pipeline.causal` | `CausalMemory = field(default_factory=CausalMemory)` | pipeline.py:88 | Field 4. |
| `Stage1Pipeline.aggregation` | `AggregationPolicy = field(default_factory=AggregationPolicy)` | pipeline.py:89 | Field 5. |
| `Stage1Pipeline.observation` | `AdaptiveObservationPolicy = field(default_factory=AdaptiveObservationPolicy)` | pipeline.py:90 | Field 6. |
| `Stage1Pipeline.epoch` | `EpochModel` — **created in `__post_init__`, not a dataclass field** | pipeline.py:95 | `EpochModel(identity=self.identity)`. Cannot be injected via the constructor. |
| `Stage1Pipeline.compiler` | `SemanticCompiler` — **created in `__post_init__`, not a dataclass field** | pipeline.py:96 | `SemanticCompiler(host_id=self.host_id, novelty=self.novelty)`. Cannot be injected; to supply a custom `EntityRegistry` you must assign `pipeline.compiler` after construction. |
| `Stage1Pipeline.run_scenario` | `def run_scenario(self, scenario: Scenario, *, sensor: SensorPath = SensorPath.EBPF, offset: int = 0) -> ScenarioResult` | pipeline.py:99 | The single entry point. `sensor` and `offset` are keyword-only. |
| `Stage1Pipeline.report` | `def report(self) -> dict[str, Any]` | pipeline.py:196 | Cumulative report over **every** scenario run on this instance. Keys (verified by running it): `host_id`, `compiler`, `novelty_memory_bytes`, `causal`, `aggregation`, `observation`, `epoch`, `registry`. |

`Stage1Pipeline._record_causal` (pipeline.py:157) and `Stage1Pipeline._consider_observation`
(pipeline.py:169) are private but determine observable behaviour; the mechanics you must know:

* `_record_causal` passes only the **first two** evidence locators to `CausalMemory.record`
  (`transition.evidence[:2]`, pipeline.py:166).
* `_consider_observation` computes causal relevance as the **cumulative** positive ΔΦ of the
  *lineage*, not of this transition: `cumulative += max(0.0, transition.delta_phi)` then
  `relevance = cumulative / (1.0 + cumulative)` (pipeline.py:174-178). The accumulator
  `self._lineage_responsibility` (pipeline.py:97) is **never reset between scenarios**.
* The AOP clock is derived, not real: `now_ns=transition.sequence * 1_000_000`
  (pipeline.py:185), where `sequence` is the compiler's global monotonic counter.
* On escalation the pipeline immediately reports a **hard-coded** payoff:
  `record_observation(..., extra_events=4, uncertainty_now=max(0.05, transition.uncertainty * 0.5))`
  (pipeline.py:190-194). That is where `AOPReport.mean_uncertainty_reduction` comes from in
  every pipeline-driven run.

`run_scenario` internals a later stage must know (all in pipeline.py:108-155):

| Behaviour | Line | Consequence |
|---|---|---|
| `assembler = EventAssembler()` — fresh per call | 108 | Assembly state never leaks between scenarios. |
| `pid = str(1000 + offset)` | 112 | Two scenarios run with the same `offset` on the same pipeline share one lineage. |
| `elapsed = offset * DEFAULT_SCENARIO_SPACING_NS` | 115 | `offset` is both the pid seed **and** the timeline placement. |
| `elapsed += int(behaviour.fields.get("_gap_ns", DEFAULT_STEP_GAP_NS))` | 120 | `_gap_ns` is a reserved `Behaviour.fields` key consumed here. It is **not** stripped and travels into `RawEventV1.fields` (verified). |
| `emit(..., index=offset * 100 + index, ...)` | 121-128 | Record ids collide once a scenario exceeds 100 behaviours and offsets are adjacent. Ids are cosmetic, but do not key anything on them. |
| `self.epoch.record_transition()` only for non-`None` transitions | 137 | Unresolved operations do not count toward epoch observation. |
| `if self.aggregation.offer(transition) is not None: emitted.append(...)` | 141-142 | Emission is decided by the policy, which is **shared across scenarios**. |
| `lineage = f"proc:boot-0001:{pid}:7"` | 144 | Hard-codes `boot_id="boot-0001"` and `start_time="7"`. See Trap T2. |

### 2.2 `pocketsec/stage1/slot.py`

`__all__ = ["NoveltyStatisticalSlot", "SSIRSlotBase", "StateCalculusSlot"]` (slot.py:38)

| Symbol | Signature / type | file:line | Purpose |
|---|---|---|---|
| `DEFAULT_PHI_THRESHOLD` | `float = 4.0` | slot.py:41 | Not in `__all__`; importable. Φ at or above which the state-calculus slot commits to `SUSPICIOUS`. |
| `_squash` | `def _squash(value: float, scale: float) -> float` | slot.py:45 | Private. `value / (value + scale) if value > 0 else 0.0`. |
| `SSIRSlotBase` | `@dataclass` | slot.py:50 | Shared plumbing. **Not a valid `ModelSlot` on its own** — it declares no `slot_name` or `model_state_version`; `_abstain` reads them via `# type: ignore[attr-defined]` (slot.py:91, 98). |
| `SSIRSlotBase.results` | `dict[str, ScenarioResult]` | slot.py:58 | Required, field 1. Keyed by `SecurityEventSequenceV1.sequence_id`. |
| `SSIRSlotBase.input_schema` | `str = ACCEPTED_INPUT_SCHEMA` | slot.py:59 | Field 2. Resolves to `"pocketsec.security_event_sequence.v1"` (measured). |
| `SSIRSlotBase.output_schema` | `str = PRODUCED_OUTPUT_SCHEMA` | slot.py:60 | Field 3. Resolves to `"pocketsec.threat_prediction.v1"` (measured). |
| `SSIRSlotBase._result_for` | `def _result_for(self, sequence: SecurityEventSequenceV1) -> ScenarioResult \| None` | slot.py:62 | `self.results.get(sequence.sequence_id)`. |
| `SSIRSlotBase._relevance` | `@staticmethod def _relevance(result: ScenarioResult) -> tuple[EvidenceRelevance, ...]` | slot.py:66 | Weights each transition's **first** evidence ref (`transition.evidence[:1]`) by `max(0, responsibility) / total`. When `total == 0` weights are uniform `1/len`. Returns `()` when no transition carried evidence. |
| `SSIRSlotBase._abstain` | `def _abstain(self, sequence: SecurityEventSequenceV1, reason_uncertainty: float = 1.0) -> ThreatPredictionV1` | slot.py:87 | Emits `Verdict.INSUFFICIENT_EVIDENCE`, `confidence=0.0`, `novelty_score=0.0`, `abstained=True`, `compute_path=ComputePath.CHEAP_TRANSITION`. |
| `StateCalculusSlot` | `@dataclass class StateCalculusSlot(SSIRSlotBase)` | slot.py:104 | Symbolic family. Reads ΔS and Φ; deliberately blind to the novelty tensor. |
| `StateCalculusSlot.slot_name` | `str = "s1-state-calculus"` | slot.py:112 | Field 4 (after the three base fields). |
| `StateCalculusSlot.model_state_version` | `str = "s1-calculus.1.0.0"` | slot.py:113 | Field 5. |
| `StateCalculusSlot.phi_threshold` | `float = DEFAULT_PHI_THRESHOLD` | slot.py:114 | Field 6. |
| `StateCalculusSlot.predict` | `def predict(self, sequence: SecurityEventSequenceV1) -> ThreatPredictionV1` | slot.py:116 | Abstains when the result is missing **or** `not result.transitions` (slot.py:118). Abstains when `result.peak_uncertainty >= 0.8` (slot.py:130), carrying that value as `uncertainty`. Otherwise `SUSPICIOUS` iff `result.peak_phi >= self.phi_threshold`. `confidence = _squash(peak_phi, phi_threshold)` when committed, else `1 - _squash(...)`, clamped with `min(1.0, ...)`. `state_identifier=None`, `calibration_id=None` (uncalibrated, deliberately), `next_event=None`. `compute_path = CHEAP_TRANSITION` when **no** transition has a truthy `state_delta`, else `STATISTICAL` (slot.py:144-148). `compute_budget_units = float(len(result.transitions))`. `prediction_id = f"{slot_name}-{sequence_id}"`. |
| `NoveltyStatisticalSlot` | `@dataclass class NoveltyStatisticalSlot(SSIRSlotBase)` | slot.py:155 | Statistical family. The deliberate control: expected to fire on novel benign work. |
| `NoveltyStatisticalSlot.slot_name` | `str = "s1-novelty-statistical"` | slot.py:163 | Field 4. |
| `NoveltyStatisticalSlot.model_state_version` | `str = "s1-novelty.1.0.0"` | slot.py:164 | Field 5. |
| `NoveltyStatisticalSlot.novelty_threshold` | `float = 0.7` | slot.py:165 | Field 6. |
| `NoveltyStatisticalSlot.predict` | `def predict(self, sequence: SecurityEventSequenceV1) -> ThreatPredictionV1` | slot.py:167 | Abstains only on missing result or zero transitions. `SUSPICIOUS` iff `peak_novelty >= novelty_threshold`. `confidence = peak_novelty` when committed else `1 - peak_novelty`. **No uncertainty-based abstention** — asymmetric with `StateCalculusSlot` by design. Emits `next_event=NextEventExpectation(surprise_bits=mean_surprise * 8.0)` where `mean_surprise` is the mean of `t.novelty.mean`. `compute_path=ComputePath.STATISTICAL` always. |

Both slots pass `pocketsec.stage0.contracts.model_slot.validate_slot` (measured in this
session). Construct them with **keyword arguments**: the inherited field order is
`(results, input_schema, output_schema, slot_name, model_state_version, <threshold>)`, so
positional construction silently binds a dict-of-results to `results` and then a string to
`input_schema`.

### 2.3 `pocketsec/stage1/observation/policy.py` — the Adaptive Observation Policy (D1.9)

`__all__ = ["AOPBudget", "AdaptiveObservationPolicy", "EscalationDecision", "MANDATORY_SIGNALS", "ObservationLevel"]` (policy.py:30).
**`AOPReport` is missing from `__all__`** but is the return type of `report()` and is public in practice.

| Symbol | Signature / type | file:line | Purpose |
|---|---|---|---|
| `ObservationLevel` | `class ObservationLevel(StrEnum)` | observation/policy.py:39 | Members `BASELINE`, `ELEVATED`, `HIGH_RESOLUTION`, each with `.value` equal to its name. |
| `MANDATORY_SIGNALS` | `frozenset[str]` | observation/policy.py:47 | Measured contents: `{"authentication", "boundary_crossing", "credential_access", "module_load", "persistence_write", "privilege_change"}`. AOP may add observation; it may never remove these. |
| `AOPBudget` | `@dataclass(frozen=True, slots=True)` | observation/policy.py:60 | Hard caps. Exceeding one **stops** escalation. |
| `AOPBudget.max_concurrent` | `int = 8` | observation/policy.py:64 | Maximum concurrently escalated targets. |
| `AOPBudget.max_duration_ns` | `int = 30_000_000_000` | observation/policy.py:66 | An escalation expires this long after its last renewal. 30 s. |
| `AOPBudget.max_escalations_per_window` | `int = 32` | observation/policy.py:68 | Amplification bound per window. |
| `AOPBudget.window_ns` | `int = 60_000_000_000` | observation/policy.py:69 | 60 s. |
| `AOPBudget.max_extra_events_per_second` | `int = 500` | observation/policy.py:71 | Per-call cap applied in `record_observation`. |
| `AOPBudget.max_memory_bytes` | `int = 256 * 1024` | observation/policy.py:73 | Bookkeeping ceiling (262144). |
| `AOPBudget.escalation_threshold` | `float = 0.5` | observation/policy.py:78 | Geometric-mean score at or above which escalation is considered. |
| `AOPBudget.to_dict` | `def to_dict(self) -> dict[str, Any]` | observation/policy.py:80 | All seven fields verbatim. |
| `EscalationDecision` | `@dataclass(frozen=True, slots=True)` | observation/policy.py:93 | One decision plus its reason. Positional order: `(target, level, budget_score, escalated, refused_reason)`. |
| `EscalationDecision.target` | `str` | observation/policy.py:96 | |
| `EscalationDecision.level` | `ObservationLevel` | observation/policy.py:97 | `BASELINE` on every refusal. |
| `EscalationDecision.budget_score` | `float` | observation/policy.py:98 | Reported even when refused. |
| `EscalationDecision.escalated` | `bool` | observation/policy.py:99 | |
| `EscalationDecision.refused_reason` | `str = ""` | observation/policy.py:100 | Empty string on success. |
| `EscalationDecision.to_dict` | `def to_dict(self) -> dict[str, Any]` | observation/policy.py:102 | `budget_score` rounded to 4 dp. |
| `AOPReport` | `@dataclass(frozen=True, slots=True)` | observation/policy.py:122 | Fields in order: `escalations_opened: int`, `escalations_refused: int`, `expired: int`, `currently_active: int`, `extra_events_collected: int`, `mean_uncertainty_reduction: float \| None`, `peak_concurrent: int`, `memory_bytes: int`, `caps_hit: tuple[str, ...]` (observation/policy.py:123-131). `mean_uncertainty_reduction` is `None` — never `0.0` — when nothing was recorded. |
| `AOPReport.to_dict` | `def to_dict(self) -> dict[str, Any]` | observation/policy.py:133 | `caps_hit` becomes a `list`; the mean is rounded to 4 dp or stays `None`. |
| `AdaptiveObservationPolicy` | `class` (plain, not a dataclass) | observation/policy.py:151 | |
| `AdaptiveObservationPolicy.__init__` | `def __init__(self, budget: AOPBudget \| None = None) -> None` | observation/policy.py:154 | `budget` is **positional-or-keyword**. `None` → `AOPBudget()`. Exposes `self.budget`. |
| `AdaptiveObservationPolicy.budget_score` | `@staticmethod def budget_score(*, uncertainty: float, security_potential: float, causal_relevance: float) -> float` | observation/policy.py:170 | Keyword-only. Returns the **cube root** of `clamp01(uncertainty) * (Φ/(1+Φ)) * clamp01(causal_relevance)` — a geometric mean, a monotone rescaling of the spec's product. Measured: `(0.5, 1.0, 0.5) -> 0.5`; any zero factor → `0.0`. |
| `AdaptiveObservationPolicy.memory_bytes` | `@property -> int` | observation/policy.py:192 | `sum(len(target.encode("utf-8")) + 48 for active escalations)`. Zero when nothing is active. |
| `AdaptiveObservationPolicy.level_for` | `def level_for(self, target: str) -> ObservationLevel` | observation/policy.py:195 | `BASELINE` for unknown targets. |
| `AdaptiveObservationPolicy.is_mandatory` | `def is_mandatory(self, signal: str) -> bool` | observation/policy.py:199 | Membership in `MANDATORY_SIGNALS`. |
| `AdaptiveObservationPolicy.collects` | `def collects(self, signal: str, target: str) -> bool` | observation/policy.py:202 | Positional. `True` unconditionally for mandatory signals; otherwise `True` only when the target is escalated above `BASELINE`. This method is what makes "AOP never disables mandatory signals" structural. |
| `AdaptiveObservationPolicy.consider` | `def consider(self, *, target: str, uncertainty: float, security_potential: float, causal_relevance: float, now_ns: int) -> EscalationDecision` | observation/policy.py:215 | All keyword-only. Order of operations: `_expire(now_ns)` → `_roll_window(now_ns)` → score → **already-active fast path (renew and return `escalated=True`)** → threshold check → cap check → open. Level is `HIGH_RESOLUTION` when `score >= (1 + escalation_threshold) / 2` (0.75 at defaults), else `ELEVATED` (observation/policy.py:248-252). |
| `AdaptiveObservationPolicy.record_observation` | `def record_observation(self, target: str, *, extra_events: int, uncertainty_now: float) -> None` | observation/policy.py:278 | `target` positional, the rest keyword-only. **Silent no-op when `target` is not currently escalated** (observation/policy.py:287-289; measured). `extra_events` is clamped to `max_extra_events_per_second` and the clamp adds `"max_extra_events_per_second"` to `caps_hit`. Appends `uncertainty_at_open - uncertainty_now` to the reduction samples — a *negative* value is recorded happily. |
| `AdaptiveObservationPolicy.report` | `def report(self) -> AOPReport` | observation/policy.py:307 | Snapshot; cheap; safe to call repeatedly. |

Private but behaviour-defining: `_cap_refusal` (observation/policy.py:265) checks caps in a
fixed order and returns the **first** violated one — `max_concurrent`, then
`max_escalations_per_window`, then `max_memory_bytes`. `max_duration_ns` is not a refusal; it
is enforced by `_expire` (observation/policy.py:296). `_roll_window`
(observation/policy.py:302) resets the per-window counter once `now_ns - window_start >= window_ns`;
because `_window_start_ns` initialises to `0` (observation/policy.py:157), the first
`consider` call with `now_ns >= window_ns` rolls the window immediately.

### 2.4 `pocketsec/stage1/aggregation/policy.py` — semantic aggregation (D1.10)

`__all__ = ["AggregatedTransition", "AggregationPolicy", "AggregationThresholds", "can_aggregate"]` (aggregation/policy.py:33).
**`AggregationReport` is missing from `__all__`** but is the return type of `report()`.

| Symbol | Signature / type | file:line | Purpose |
|---|---|---|---|
| `AggregationThresholds` | `@dataclass(frozen=True, slots=True)` | aggregation/policy.py:42 | What counts as "low" per conjunct. |
| `AggregationThresholds.max_novelty` | `float = 0.25` | aggregation/policy.py:45 | Refuse when `transition.novelty.peak >` this. |
| `AggregationThresholds.max_delta_phi` | `float = 0.0` | aggregation/policy.py:46 | Refuse when `transition.delta_phi >` this. At the default, **any** positive ΔΦ refuses aggregation. |
| `AggregationThresholds.max_uncertainty` | `float = 0.3` | aggregation/policy.py:47 | Refuse when `transition.uncertainty >` this. |
| `AggregationThresholds.evidence_sample` | `int = 3` | aggregation/policy.py:49 | Evidence refs kept per aggregate: first N then a rolling last N. |
| `AggregationThresholds.max_groups` | `int = 512` | aggregation/policy.py:50 | Bound on live groups; oldest is evicted (FIFO/LRU on `move_to_end`). |
| `AggregationThresholds.to_dict` | `def to_dict(self) -> dict[str, Any]` | aggregation/policy.py:52 | Measured output: `{'max_novelty': 0.25, 'max_delta_phi': 0.0, 'max_uncertainty': 0.3, 'evidence_sample': 3, 'max_groups': 512}`. |
| `can_aggregate` | `def can_aggregate(transition: SSIRTransitionV1, thresholds: AggregationThresholds) -> tuple[bool, str]` | aggregation/policy.py:62 | Both parameters positional. Returns `(allowed, reason)`; the reason is returned **even on success**. Check order (this order is the conservation rule): `is_high_consequence` → `delta_phi` → `novelty.peak` → `uncertainty` → `observation_incomplete`. |
| `AggregatedTransition` | `@dataclass` (mutable) | aggregation/policy.py:86 | A coalesced run. |
| `AggregatedTransition.key` | `tuple[Any, ...]` | aggregation/policy.py:89 | `transition.semantic_key()`. |
| `AggregatedTransition.exemplar` | `SSIRTransitionV1` | aggregation/policy.py:90 | The first transition of the run. |
| `AggregatedTransition.count` | `int = 1` | aggregation/policy.py:91 | Incremented by `absorb`; the first member is counted at construction. |
| `AggregatedTransition.first_ns` | `int = 0` | aggregation/policy.py:92 | **Misleading name.** Holds `transition.sequence`, a counter, not nanoseconds (aggregation/policy.py:193, 195, 115). Measured: 4 and 5 for a 2-member run. |
| `AggregatedTransition.last_ns` | `int = 0` | aggregation/policy.py:93 | Same: a sequence number. |
| `AggregatedTransition.min_novelty` | `float = 1.0` | aggregation/policy.py:94 | |
| `AggregatedTransition.max_novelty` | `float = 0.0` | aggregation/policy.py:95 | |
| `AggregatedTransition.max_uncertainty` | `float = 0.0` | aggregation/policy.py:96 | |
| `AggregatedTransition.evidence_head` | `list[EvidenceRef] = field(default_factory=list)` | aggregation/policy.py:97 | |
| `AggregatedTransition.evidence_tail` | `list[EvidenceRef] = field(default_factory=list)` | aggregation/policy.py:98 | |
| `AggregatedTransition.interval_ns` | `@property -> int` | aggregation/policy.py:101 | `last_ns - first_ns` — therefore a **sequence-number delta**, not a duration. |
| `AggregatedTransition.evidence` | `@property -> tuple[EvidenceRef, ...]` | aggregation/policy.py:105 | `tuple(head + tail)`. |
| `AggregatedTransition.absorb` | `def absorb(self, transition: SSIRTransitionV1, thresholds: AggregationThresholds) -> None` | aggregation/policy.py:113 | Mutates in place. Takes only `transition.evidence[:1]` per member. |
| `AggregatedTransition.to_dict` | `def to_dict(self) -> dict[str, Any]` | aggregation/policy.py:126 | Keys: `relation` (exemplar's `relation.name`), `count`, `first_sequence`, `last_sequence`, `interval`, `novelty_extrema` (`[min, max]`), `max_uncertainty`, `retained_evidence`. |
| `AggregationReport` | `@dataclass(frozen=True, slots=True)` | aggregation/policy.py:140 | Fields in order: `emitted: int`, `aggregated_away: int`, `groups: int`, `high_consequence_preserved: int`, `refusal_reasons: dict[str, int]` (aggregation/policy.py:141-145). |
| `AggregationReport.compression_ratio` | `@property -> float` | aggregation/policy.py:148 | `aggregated_away / (emitted + aggregated_away)`, `0.0` when both are zero. |
| `AggregationReport.to_dict` | `def to_dict(self) -> dict[str, Any]` | aggregation/policy.py:152 | Adds `compression_ratio` rounded to 4 dp. |
| `AggregationPolicy` | `class` (plain, not a dataclass) | aggregation/policy.py:163 | Bounded coalescing. |
| `AggregationPolicy.__init__` | `def __init__(self, thresholds: AggregationThresholds \| None = None) -> None` | aggregation/policy.py:166 | Exposes `self.thresholds`. |
| `AggregationPolicy.offer` | `def offer(self, transition: SSIRTransitionV1) -> SSIRTransitionV1 \| None` | aggregation/policy.py:174 | Returns the transition to emit, or `None` when absorbed. **The first member of every run is always emitted** (aggregation/policy.py:201) and counted in `emitted`. |
| `AggregationPolicy.groups` | `@property -> tuple[AggregatedTransition, ...]` | aggregation/policy.py:213 | Live groups in LRU order (oldest first). |
| `AggregationPolicy.report` | `def report(self) -> AggregationReport` | aggregation/policy.py:216 | Cumulative over the policy's whole lifetime. |

`refusal_reasons` keys are `reason.split(":")[0]` (aggregation/policy.py:180-182). Only two
reasons contain a colon (`"high-consequence: …"` and `"observation incomplete: …"`), so the
other three keys retain their **formatted float values**. Measured keys from one run:
`{'high-consequence': 3, 'novelty peak 1.000 above threshold': 1}` and, from another,
`{'novelty peak 1.000 above threshold': 1, 'novelty peak 0.500 above threshold': 1, 'novelty peak 0.333 above threshold': 1}`.
Treat `refusal_reasons` as unbounded-cardinality diagnostic text, never as a stable enum.

### 2.5 `pocketsec/stage1/gate.py` — the executable acceptance gate

`__all__ = ["Stage1GateContext", "run_gate"]` (gate.py:25). The module-level constants and
`SSIRTransitionFields` are not in `__all__` but carry no underscore and are imported elsewhere.

| Symbol | Signature / type | file:line | Purpose |
|---|---|---|---|
| `EVAL_COUNT` | `int = 60` | gate.py:27 | Replay-corpus size for the shared context. |
| `SEED` | `int = 20_260_924` | gate.py:28 | Corpus seed for the shared context and for G1.1. |
| `GUILLOTINE_SIZE` | `int = 160` | gate.py:33 | Hard-corpus size for each guillotine split. |
| `GUILLOTINE_FIT_SEED` | `int = 3` | gate.py:34 | Probe fit split seed. |
| `GUILLOTINE_SCORE_SEED` | `int = 11` | gate.py:35 | Scoring split seed. Disjoint from the fit seed — Stage 0 fair-comparison rule 6. |
| `STABILITY_DRAWS` | `int = 3` | gate.py:38 | Draws used by G1.11 (the CLI `stability` command uses 5). |
| `STABILITY_SIZE` | `int = 160` | gate.py:39 | Corpus size per stability draw (CLI uses 200). |
| `Stage1GateContext` | `@dataclass` | gate.py:55 | One shared pipeline run so thirteen checks do not replay the corpus thirteen times. |
| `Stage1GateContext.results` | `list[ScenarioResult]` | gate.py:58 | `EVAL_COUNT` replay-corpus results from **one** pipeline, offsets `0..n-1`. |
| `Stage1GateContext.pipeline` | `Stage1Pipeline` | gate.py:59 | The instance those results came from; still holds cumulative policy state. |
| `Stage1GateContext.peak_rss_bytes` | `int \| None` | gate.py:60 | `metrics.peak_sampled_rss_bytes or metrics.peak_rss_bytes` — `None` when unmeasurable. |
| `Stage1GateContext.cpu_seconds` | `float` | gate.py:61 | From `ResourceSampler(interval_seconds=0.005)`. |
| `Stage1GateContext.transitions` | `int` | gate.py:62 | Sum of `len(r.transitions)`. |
| `Stage1GateContext.guillotine_fit` | `list[ScenarioResult]` | gate.py:65 | Hard corpus, `GUILLOTINE_FIT_SEED`, its **own fresh pipeline**. |
| `Stage1GateContext.guillotine_score` | `list[ScenarioResult]` | gate.py:66 | Hard corpus, `GUILLOTINE_SCORE_SEED`, its own fresh pipeline. |
| `Stage1GateContext.build` | `@classmethod def build(cls) -> Stage1GateContext` | gate.py:69 | Takes no arguments — the sizes and seeds are the module constants, not parameters. |
| `run_gate` | `def run_gate() -> GateReport` | gate.py:89 | Takes no arguments. Builds a context and returns a Stage 0 `GateReport` of exactly thirteen `GateCheck`s, ids `G1.1`…`G1.13`, in the fixed order at gate.py:93-107. |
| `SSIRTransitionFields` | `def SSIRTransitionFields() -> tuple[str, ...]` | gate.py:153 | Helper: `dataclasses.fields(SSIRTransitionV1)` names. Named like a constant deliberately (`# noqa: N802`). |

Check-by-check: what each criterion actually measures, and what it constructs for itself.

| Id | Function | file:line | Passes when |
|---|---|---|---|
| G1.1 | `_cross_sensor_equivalence` | gate.py:111 | 20 replay scenarios (`seed=SEED`, `split="eval"`) compile to identical `semantic_keys` through `SensorPath.EBPF` and `SensorPath.AUDITD`, on **two separate pipelines**. Requires `agree == len(scenarios)` exactly. |
| G1.2 | `_separate_versioned_interfaces` | gate.py:130 | Both `RAW_EVENT_V1_ID` and `SSIR_TRANSITION_V1_ID` are in `SCHEMA_REGISTRY`, and `"state_delta"` is an `SSIRTransitionV1` field while `SecurityStateV1()` has no `novelty` attribute. |
| G1.3 | `_explicit_uncertainty` | gate.py:161 | Every transition in `ctx.results` has `uncertainty > 0.0`, and a one-behaviour unknown-object scenario yields `peak_uncertainty > 0.0`. Note the `partial` scenario it builds (gate.py:166) is computed for the detail string only; it is not in the pass condition. |
| G1.4 | `_novelty_separate_from_potential` | gate.py:183 | At least one window has `novelty >= 0.7 and phi < 2.0`, and the Pearson correlation over `(peak_novelty, peak_phi)` is `None` or `< 0.9`. `_pearson` (gate.py:202) returns `None` for fewer than 2 points or zero variance. |
| G1.5 | `_epoch_regime_change` | gate.py:212 | A corroborated `package_digest` change transitions the epoch, the prior epoch's `observed_transitions` survives in `retained_history`, and `before > 0`. |
| G1.6 | `_causal_spine_retained` | gate.py:240 | `len(spine) >= 3`, `report.compressed > 0`, and every spine node has `resolution == 0`. Builds two 60-step benign branches with **different operation mixes** plus one `ATTACK_EXFIL`, on one pipeline at offsets 0/1/2. |
| G1.7 | `_adaptive_observation` | gate.py:282 | Both directions: the selected scenario (unknown binary → ptrace → external connect) opens ≥1 escalation with `mean_uncertainty_reduction > 0`, the routine 40-read control opens **0**, peak concurrency and memory are within budget, `max_extra_events_per_second` is not in `caps_hit`, and `collects("credential_access", "never-escalated")` is `True`. |
| G1.8 | `_aggregation_preserves_high_consequence` | gate.py:350 | Every high-consequence transition in `ATTACK_EXFIL * 5` is present in `emitted`, there is at least one, and a separate 200-read flood compresses `> 0.5`. |
| G1.9 | `_guillotine_pareto` | gate.py:378 | `is_measured_frontier and knee is not None and held_out and not degenerate`. |
| G1.10 | `_renaming_generalisation` | gate.py:402 | The `renaming`, `unseen_binary` and `obfuscation` outcomes of `run_adversarial_suite()` all pass. |
| G1.11 | `_field_justification` | gate.py:415 | `measure_stability(draws=STABILITY_DRAWS, corpus_size=STABILITY_SIZE)`: every family is either justified (`redundancy_rate < 1.0`) or a freeze candidate, i.e. `set(justified) \| set(freeze_candidates) == set(redundancy_rate)`, **and** `justified` is non-empty. |
| G1.12 | `_resource_costs_measured` | gate.py:460 | `ctx.peak_rss_bytes is not None` and `<= PROFILES["edge"].agent_rss_target_bytes`. |
| G1.13 | `_multiple_model_families` | gate.py:485 | Feeding both slots identical SSIR (keys `f"s1-{i:04d}"`) yields `disagreements > 0 and agreements > 0`. Uses `_stub_sequence` (gate.py:516) — a `SecurityEventSequenceV1` carrying only the id the slots key on. |

`assert phi` at gate.py:540 exists to keep the `phi` import alive for detail strings; do not
remove it without also removing the import.

**Measured this session** (`python -m pocketsec.stage1.cli gate`, repo root, `PYTHONPATH=.`):
all thirteen checks PASS, exit code 0, wall clock **14.0 s**. Selected measured details from
that run: G1.1 20/20; G1.3 183 transitions all with `uncertainty > 0`, unknown-object
uncertainty 0.300; G1.4 42 high-novelty/low-potential windows, `r=None`; G1.6 spine 4 of 124
nodes at full fidelity, 60 compressed, 0 dropped; G1.7 1 escalation, mean uncertainty
reduction 0.2, routine control 0 escalations, peak concurrent 1/8, memory 69/262144 B;
G1.8 3/3 high-consequence emitted, flood compressed 98.0%; G1.9 10 points spanning 2–37
bytes/transition, knee `-actor_semantics` at 21 B with PR-AUC 0.9916405433646813;
G1.11 3 draws, 7 families justified, freeze candidates `['evidence_link', 'exact_identity']`,
UNSTABLE `['actor_semantics']`, baseline PR-AUC 0.9868 [0.9830–0.9923], Φ composition gain
4.750; G1.12 peak RSS 25915392 B vs Edge target 104857600 B, novelty engine 173983 B, causal
memory 2185 B, 1.632e-04 CPU s/transition; G1.13 18 agreements / 42 disagreements.

### 2.6 `pocketsec/stage1/cli.py`

`__all__ = ["main"]` (cli.py:22). Console script `pocketsec-stage1` → `pocketsec.stage1.cli:main` (`pyproject.toml`).

| Symbol | Signature | file:line | Purpose |
|---|---|---|---|
| `main` | `def main(argv: Sequence[str] \| None = None) -> int` | cli.py:41 | Parses `argv` (defaults to `sys.argv[1:]`) and dispatches. Returns a process exit code. |

Subcommands (`sub.add_parser` loop, cli.py:29-37) — a subcommand is **required**
(`required=True`, cli.py:28); `--json` is a **global** flag that must precede the subcommand
in argv order as far as `argparse` layout goes, and is passed to every handler as
`as_json`:

| Command | Handler | file:line | Exit code | Notes |
|---|---|---|---|---|
| `gate` | `_gate` | cli.py:54 | `0` if `report.passed` else `1` | JSON mode prints `report.to_dict()` with `indent=2, sort_keys=True`. |
| `adversarial` | `_adversarial` | cli.py:68 | `0` if `report.passed` else `1` | Runs `run_adversarial_suite()`. |
| `guillotine` | `_guillotine` | cli.py:83 | always `0` | Builds a full `Stage1GateContext` first, then `run_guillotine(ctx.guillotine_score, train=ctx.guillotine_fit)`. |
| `calibrate` | `_calibrate` | cli.py:109 | always `0` | `calibrate([(r.final_state, r.scenario.label) for r in ctx.results if r.transitions])`. |
| `replay` | `_replay` | cli.py:121 | always `0` | Prints `transitions`, `scenarios`, `peak_rss_bytes`, `cpu_seconds`, `pipeline.report()`. |
| `stability` | `_stability` | cli.py:145 | always `0` | `measure_stability(draws=5, corpus_size=200)` — **different parameters from the gate's G1.11**. |

`guillotine`, `calibrate` and `replay` each call `Stage1GateContext.build()`, which recompiles
the replay corpus *and* both 160-scenario hard splits. They are not cheap; there is no way to
pass a pre-built context through the CLI.

### 2.7 `pocketsec/stage1/labs/corpus.py` — the replay corpus and the dual-sensor emitter

`__all__ = ["Behaviour", "CORPUS_VERSION", "Scenario", "build_corpus", "emit"]` (corpus.py:26).
The behaviour-chain constants below are public but absent from `__all__`.

| Symbol | Signature / type | file:line | Purpose |
|---|---|---|---|
| `CORPUS_VERSION` | `str = "stage1-replay-corpus-v0.1.0"` | corpus.py:28 | |
| `Behaviour` | `@dataclass(frozen=True, slots=True)` | corpus.py:34 | One logical machine operation with its ground truth. |
| `Behaviour.operation` | `str` | corpus.py:37 | e.g. `"execve"`, `"read"`, `"connect"`, `"setuid"`, `"ptrace"`, `"mount"`, `"install"`, `"fork"`, `"accept"`, `"send"`, `"recv"`, `"write"`. An unrecognised operation compiles to `None` and increments `unresolved`. |
| `Behaviour.fields` | `dict[str, str] = field(default_factory=dict)` | corpus.py:38 | **A mutable dict inside a frozen dataclass** — `Behaviour` is therefore not hashable-safe to mutate; treat `fields` as read-only. Reserved keys: `_gap_ns` (consumed by the pipeline), `pid`, `start_time`, `uid` (override the emitter's defaults). |
| `Behaviour.with_fields` | `def with_fields(self, **extra: str) -> Behaviour` | corpus.py:40 | Returns a new `Behaviour` with `{**self.fields, **extra}`. The immutable way to rewrite a chain. |
| `Scenario` | `@dataclass(frozen=True, slots=True)` | corpus.py:45 | |
| `Scenario.name` | `str` | corpus.py:48 | Positional field 1. |
| `Scenario.behaviours` | `tuple[Behaviour, ...]` | corpus.py:49 | Positional field 2. |
| `Scenario.label` | `int` | corpus.py:50 | Positional field 3. `0` benign, `1` malicious. This is the supervision signal the guillotine probe reads. |
| `Scenario.technique` | `str \| None = None` | corpus.py:51 | Field 4. |
| `Scenario.unseen_technique` | `bool = False` | corpus.py:52 | Field 5. Marks techniques absent from the training split. |
| `Scenario.to_dict` | `def to_dict(self) -> dict[str, Any]` | corpus.py:54 | Keys: `name`, `label`, `technique`, `unseen_technique`, `length`. |
| `BENIGN_PATTERNS` | `tuple[tuple[Behaviour, ...], ...]` — 5 patterns | corpus.py:66 | Build, web request, backup, package query, local service chatter. |
| `BENIGN_PRIVILEGED` | `tuple[Behaviour, ...]` — 3 steps | corpus.py:101 | Legitimate admin: high Φ, label 0. The case that stops Φ being read as a threat score. |
| `ATTACK_EXFIL` | `tuple[Behaviour, ...]` — 4 steps | corpus.py:110 | `setuid(0)` → `read /etc/shadow` → `connect 203.0.113.42:443` → `send`. The spec's worked example. |
| `ATTACK_PERSISTENCE` | `tuple[Behaviour, ...]` — 3 steps | corpus.py:118 | Privileged systemd unit write. |
| `ATTACK_UNSEEN_MEMORY` | `tuple[Behaviour, ...]` — 3 steps | corpus.py:127 | ptrace credential theft; held out of training. |
| `ATTACK_UNSEEN_ESCAPE` | `tuple[Behaviour, ...]` — 3 steps | corpus.py:134 | Container escape; held out. |
| `emit` | `def emit(behaviour: Behaviour, *, sensor: SensorPath, index: int, host_id: str, boot_id: str = "boot-0001", pid: str = "1000", elapsed_ns: int \| None = None) -> list[RawEventV1]` | corpus.py:144 | `behaviour` positional, everything else keyword-only. `SensorPath.EBPF` → **one** record, `record_type=behaviour.operation`, `assembly_key=None`, `fields={"operation": f"sys_{operation}", pid, start_time="7", uid="1000", **behaviour.fields}`. `SensorPath.AUDITD` → **two** records sharing `assembly_key=f"audit-{index:05d}"` with `_expected_records="2"`: a `SYSCALL` record carrying `syscall=operation.upper()` plus pid/start_time/uid **but not** `behaviour.fields`, and a detail record typed `SOCKADDR` when `"raddr" in behaviour.fields` else `PATH`, carrying `behaviour.fields`, at `observed_at_ns + 1000`. `monotonic_ns = elapsed_ns if elapsed_ns is not None else index * 1_000_000`; `observed_at_ns = 1_760_000_000_000_000_000 + monotonic` (`_BASE_NS`, corpus.py:30). |
| `build_corpus` | `def build_corpus(*, count: int, seed: int, split: str, include_unseen: bool = True) -> tuple[Scenario, ...]` | corpus.py:220 | All keyword-only. Returns exactly `count` scenarios. `split="train"` → benign-only (measured: labels `[0]`). Any other value of `split` (including `"eval"`) takes the mixed branch — **`split` is not validated**, so a typo silently produces the eval mix. Mix by `index % 10`: bucket 3 → `ATTACK_EXFIL`; 6 → `ATTACK_PERSISTENCE`; 8 (when `include_unseen`) → `ATTACK_UNSEEN_MEMORY` if `index % 20 == 8` else `ATTACK_UNSEEN_ESCAPE`, `unseen_technique=True`; 5 → `BENIGN_PRIVILEGED` label 0; otherwise a random `BENIGN_PATTERNS` draw. |

### 2.8 `pocketsec/stage1/labs/hard_corpus.py` — the discriminating corpus

`__all__ = ["HARD_CORPUS_VERSION", "build_hard_corpus", "DISCRIMINATOR_PAIRS"]` (hard_corpus.py:38).
All chain constants below are public but absent from `__all__`.

| Symbol | Signature / type | file:line | Purpose |
|---|---|---|---|
| `HARD_CORPUS_VERSION` | `str = "stage1-hard-corpus-v0.1.0"` | hard_corpus.py:40 | |
| `BACKUP_LOCAL` | `tuple[Behaviour, ...]` — 4 | hard_corpus.py:44 | Benign half of the `capability_delta` pair. |
| `BACKUP_EXFIL` | 5 | hard_corpus.py:51 | Malicious half: same credential read **plus** egress. |
| `ADMIN_CONFIG_WRITE` | 3 | hard_corpus.py:61 | Benign half of `object_semantics`. |
| `PRELOAD_HIJACK` | 3 | hard_corpus.py:67 | Malicious half: identical privileged write to `/etc/ld.so.preload`. |
| `READER_ONLY` | 4 | hard_corpus.py:75 | Benign half of `actor_semantics`. |
| `SPAWNER_NETWORKER` | 5 | hard_corpus.py:82 | Malicious half: same binary, demonstrated spawn + network. |
| `KNOWN_BINARY_WORK` | 3 | hard_corpus.py:92 | Benign half of `uncertainty`. |
| `UNKNOWN_BINARY_WORK` | 3 | hard_corpus.py:98 | Malicious half: `/tmp/.cache/sys-helper-8812`. |
| `CONCENTRATED_ESCALATION` | 4 | hard_corpus.py:107 | Malicious half of `causal_memory`. |
| `GRADUAL_MAINTENANCE` | 6 | hard_corpus.py:116 | Benign half: same capabilities reached through interleaved routine work. |
| `MONITORING_EXTERNAL` | 4 | hard_corpus.py:127 | Benign, shares external egress with attacks. |
| `PACKAGE_INSTALL` | 4 | hard_corpus.py:134 | Benign, shares privileged persistence. |
| `CI_BUILD` | 5 | hard_corpus.py:141 | Benign, shares fork + external connect. |
| `LOTL_SERVICE_BACKDOOR` | 5 | hard_corpus.py:151 | Living-off-the-land attack. |
| `LOTL_CRON_PERSIST` | 4 | hard_corpus.py:159 | Living-off-the-land attack. |
| `DISCRIMINATOR_PAIRS` | `tuple[tuple[str, tuple[Behaviour, ...], tuple[Behaviour, ...]], ...]` — 5 entries `(family, benign, malicious)` | hard_corpus.py:169 | Families covered: `capability_delta`, `object_semantics`, `actor_semantics`, `uncertainty`, `causal_memory`. **`novelty` and `timing` are NOT in this tuple** — they are generated per index by `_novelty_pair` (hard_corpus.py:205) and `_timing_pair` (hard_corpus.py:228) inside `build_hard_corpus`. |
| `build_hard_corpus` | `def build_hard_corpus(*, count: int, seed: int, split: str) -> tuple[Scenario, ...]` | hard_corpus.py:249 | All keyword-only; **no default for `split`**. `split="train"` → exactly `count` benign scenarios (measured labels `[0]`). Otherwise: 10 pair scenarios from `DISCRIMINATOR_PAIRS`, then 8 novelty-pair scenarios (`range(4)` × 2), then 8 timing-pair scenarios (`range(4)` × 2) = **26 guaranteed**, then padding to `count` with `index % 3 == 0` → an `_ATTACK_POOL` draw else a `_BENIGN_POOL` draw. The final line (hard_corpus.py:301) returns all 26 when `count < 26`. **Measured: `build_hard_corpus(count=5, seed=3, split="eval")` returns 26 scenarios, not 5.** `count` is a floor on the eval split, not a length. |
| `_SLOW_GAP_NS` | `int = 3_600_000_000_000` | hard_corpus.py:200 | 1 hour; the `timing` pair's benign side. Private but load-bearing. |
| `_BURST_GAP_NS` | `int = 200_000` | hard_corpus.py:202 | 200 µs; the malicious side. |

### 2.9 `pocketsec/stage1/labs/ambiguous_corpus.py` — the non-saturated multi-actor corpus

`__all__ = ["AMBIGUOUS_VERSION", "ActorRole", "build_ambiguous_corpus"]` (ambiguous_corpus.py:43).
Consumed by `pocketsec/stage2/dataset.py:24` and `:160` — **not** by the Stage 1 gate or CLI.

| Symbol | Signature / type | file:line | Purpose |
|---|---|---|---|
| `AMBIGUOUS_VERSION` | `str = "stage1-ambiguous-v0.1.0"` | ambiguous_corpus.py:45 | |
| `ActorRole` | `@dataclass(frozen=True, slots=True)` | ambiguous_corpus.py:52 | One concurrent process. Fields: `name: str` (:55), `pid: str` (:56), `start_time: str` (:57), `routine: tuple[tuple[str, dict[str, str]], ...]` (:58). |
| `build_ambiguous_corpus` | `def build_ambiguous_corpus(*, count: int, seed: int, split: str = "eval") -> tuple[Scenario, ...]` | ambiguous_corpus.py:268 | Keyword-only; `split` defaults to `"eval"`. Returns exactly `count` scenarios. Each session draws `rng.randrange(7, 9)` roles and `rng.randrange(50, 90)` background steps. `malicious = split != "train" and index % 3 == 0`; `subtle = malicious and index % 9 == 0` truncates the chain to `chain[: max(2, len(chain) - 2)]` and sets `unseen_technique=True`. **Both classes draw from the same `_CHAIN_POOL`** (4 chains after ambiguous_corpus.py:164): the only label-bearing difference is whether one lineage performed every stage (`single_lineage=True`) or the stages were spread across distinct actors. Measured: `count=9, seed=5` → 9 scenarios, labels `{0, 1}`, session lengths 62/63/77 behaviours; `split="train"` → labels `[0]`. |

Behaviour that a later stage must not re-derive by guessing:

* Every behaviour carries an explicit `pid` and `start_time` from its `ActorRole`
  (`_behaviour`, ambiguous_corpus.py:189), plus `_gap_ns`. These **override** the emitter's
  defaults, which is how the corpus gets 7–8 distinct lineages per scenario (measured: 8
  distinct `actor.identity` values in one session) — and which is also the direct cause of
  Trap T2.
* Role routines are deliberately **capability-neutral**: loopback networking only, no
  credential or persistence objects, no privilege change (comment at ambiguous_corpus.py:61-72).
  Because the capability lattices are monotone, a role that already held external reachability
  would produce zero ΔΦ when a chain stage granted it again. Do not "make the roles more
  realistic" without re-measuring — that is the exact defect the comment records.
* `_make_roles` (ambiguous_corpus.py:167) derives session-unique identities
  (`pid = 100_000 + session * 100 + index`, `start_time = 1_000 + session * 10 + index`)
  specifically so lineage state cannot accumulate between sessions on a shared pipeline.
* `_interleave` (ambiguous_corpus.py:201) **raises `RuntimeError`** when a benign spread has
  fewer distinct actors than chain stages (ambiguous_corpus.py:251-256). That is a guard, not
  a bug: sampling with replacement previously mislabelled benign sessions.

### 2.10 `pocketsec/stage1/labs/longhorizon_corpus.py` — long multi-stage sessions

`__all__ = ["LONG_HORIZON_VERSION", "build_long_horizon_corpus"]` (longhorizon_corpus.py:33).
Consumed by `pocketsec/stage2/dataset.py:25` — not by the Stage 1 gate or CLI.

| Symbol | Signature / type | file:line | Purpose |
|---|---|---|---|
| `LONG_HORIZON_VERSION` | `str = "stage1-longhorizon-v0.1.0"` | longhorizon_corpus.py:35 | |
| `build_long_horizon_corpus` | `def build_long_horizon_corpus(*, count: int, seed: int, split: str = "eval") -> tuple[Scenario, ...]` | longhorizon_corpus.py:170 | Keyword-only; returns exactly `count`. Session length `rng.randrange(40, 120)`. Benign when `split == "train" or index % 3 != 0`. Attacks: `slow = index % 6 == 0` → `_SLOW_ATTACK_STAGES` spread across the session with a 20–90 minute gap and `unseen_technique=True`, `technique="slow-interleaved-chain"`; otherwise `_ATTACK_STAGES` as a contiguous sub-millisecond burst, `technique="burst-chain"`. Measured: `count=6, seed=5` → 6 scenarios, labels `{0, 1}`. |

Unlike the ambiguous corpus, these behaviours set **only** `_gap_ns` (`_step`,
longhorizon_corpus.py:111) — no `pid`, no `start_time`. A whole session therefore compiles
into the pipeline's single default lineage, so `ScenarioResult.final_state` and `peak_phi`
are meaningful here.

### 2.11 `pocketsec/stage1/labs/adversarial.py` — the eight representation attacks (D1.12)

`__all__ = ["AdversarialReport", "run_adversarial_suite"]` (adversarial.py:38).
**`TestOutcome` is missing from `__all__`** but is the element type of `AdversarialReport.outcomes`.

| Symbol | Signature / type | file:line | Purpose |
|---|---|---|---|
| `TestOutcome` | `@dataclass(frozen=True, slots=True)` | adversarial.py:42 | Fields: `name: str` (:43), `passed: bool` (:44), `measurement: str` (:45), `detail: str` (:46). `to_dict` at :48. |
| `AdversarialReport` | `@dataclass(frozen=True, slots=True)` | adversarial.py:58 | `outcomes: tuple[TestOutcome, ...]` (:59); `passed` property (:62) = all outcomes passed; `failures` property (:66); `to_dict` (:69). |
| `run_adversarial_suite` | `def run_adversarial_suite() -> AdversarialReport` | adversarial.py:322 | No arguments. Returns the eight outcomes in the fixed order at adversarial.py:325-333: `renaming`, `unseen_binary`, `obfuscation`, `timing_shift`, `high_novelty_benign`, `epoch_poisoning`, `flood`, `sensor_disagreement`. Each test builds its **own fresh `Stage1Pipeline`**. |

The pass conditions, since G1.10 depends on three of them:

| `name` | file:line | Passes when |
|---|---|---|
| `renaming` | adversarial.py:83 | `ATTACK_EXFIL` and the same chain with every `execve` path rewritten to `/tmp/.x91` produce identical `final_state.to_levels()` **and** `abs(Δpeak_phi) < 0.01`. |
| `unseen_binary` | adversarial.py:104 | `"exfiltration_triad" in phi(result.final_state).active_interactions` for an unseen `execve` path. |
| `obfuscation` | adversarial.py:130 | Adding `cmdline` and `comm` junk fields leaves `final_state.to_levels()` unchanged. |
| `timing_shift` | adversarial.py:151 | Offsets 0 and 50 on **separate** pipelines reach identical state levels. |
| `high_novelty_benign` | adversarial.py:175 | A 12-step novel build reaches `peak_novelty >= 0.9` **and** `peak_phi < 2.0`. |
| `epoch_poisoning` | adversarial.py:198 | An uncorroborated identity change at `behavioural_novelty=1.0` does **not** transition, and the same change with `corroborating_evidence={"package_digest"}` does. |
| `flood` | adversarial.py:231 | 400 log reads leave `novelty.memory_bytes <= 2_000_000`, `len(causal) <= causal.capacity`, and `aggregation.aggregated_away > 0`. |
| `sensor_disagreement` | adversarial.py:261 | Hand-built conflicting `AUDITD` + `EBPF` records sharing one `assembly_key` compile to at least one transition whose `uncertainty` **exceeds** a clean scenario's `peak_uncertainty`. |

**Measured this session:** 8/8 pass in 0.12 s. `renaming` 13.75 vs 13.75; `unseen_binary`
Φ 13.75 with interactions `['exfiltration_triad', 'privileged_credential_access', 'credential_egress']`;
`high_novelty_benign` novelty 1.00 / Φ 0.75; `flood` novelty 163993 B, 400 causal nodes, 396
aggregated (ratio 0.99); `sensor_disagreement` conflicted uncertainty 0.550 vs clean 0.300.

### 2.12 `pocketsec/stage1/guillotine/features.py`

`__all__ = ["FEATURE_FAMILIES", "LogisticProbe", "extract_features", "feature_names"]` (features.py:29)

| Symbol | Signature / type | file:line | Purpose |
|---|---|---|---|
| `FEATURE_FAMILIES` | `dict[str, str]` — 22 entries, feature name → SSIR field family | features.py:34 | Measured: 22 features over 12 distinct families — `actor_id`, `actor_sem`, `causal_sig`, `evidence_id`, `invariant_delta`, `novelty_actor`, `novelty_host`, `object_sem`, `relation`, `state_delta`, `time_bucket`, `uncertainty`. **`object_id`, `novelty_relation`, `novelty_object`, `epoch_id_low` and `flags` exist in the codec's `LAYOUTS` but carry no feature**, so ablating them changes byte cost without changing the probe's inputs. |
| `feature_names` | `def feature_names(retained: frozenset[str]) -> tuple[str, ...]` | features.py:67 | Positional. Names whose carrying family is in `retained`, in `FEATURE_FAMILIES` insertion order. Measured: `feature_names(frozenset({"state_delta"})) == ('delta_total', 'delta_max', 'delta_dimensions')`. |
| `extract_features` | `def extract_features(result: ScenarioResult, names: Sequence[str]) -> list[float]` | features.py:74 | Both positional. Returns `[0.0] * len(names)` when the scenario compiled no transitions (measured). Order follows `names`, so `feature_names` and `extract_features` must be given the same `names` object. |
| `LogisticProbe` | `@dataclass` | features.py:129 | Stdlib-only L2 logistic regression by full-batch gradient descent. |
| `LogisticProbe.learning_rate` | `float = 0.1` | features.py:136 | |
| `LogisticProbe.iterations` | `int = 400` | features.py:137 | Fixed count — no convergence check, no early stop. |
| `LogisticProbe.l2` | `float = 0.01` | features.py:138 | |
| `LogisticProbe.fit` | `def fit(self, rows: list[list[float]], labels: list[int]) -> LogisticProbe` | features.py:146 | Returns `self` for chaining. **Raises `ValueError` when `set(labels)` has fewer than two members** (features.py:159-163; measured). Returns `self` unchanged (unfitted) when `rows` is empty. Standardisation (`_standardise_from`, features.py:194) is learned on the fit rows only; zero-variance columns get `scale = 1.0`. Weights start at zero and iteration count is fixed, so the fit is deterministic. |
| `LogisticProbe.predict` | `def predict(self, rows: list[list[float]]) -> list[float]` | features.py:187 | Returns `[0.0] * len(rows)` when never fitted. `zip(..., strict=True)` in `_apply_scaling` and `_raw` means a width mismatch **raises** rather than silently truncating. |

The 22 feature definitions, quoted from `extract_features` (features.py:88-124), because a
later stage reusing them must not re-derive them:
`delta_total` = Σ`state_delta.magnitude`; `delta_max` = max of the same; `delta_dimensions` =
size of the union of `state_delta.dimensions`; `phi_total` = Σ`max(0, delta_phi)`;
`phi_peak_step` = max of the same; `object_props_max` / `actor_props_max` = max count of
asserted semantic properties; `object_props_total` / `actor_props_total` = size of the union;
`novelty_peak` / `novelty_mean` from `t.novelty.peak`; `novelty_actor_peak` = max
`t.novelty["actor"]`; `uncertainty_peak` / `uncertainty_mean`; `time_bucket_min` /
`time_bucket_mean` from `t.temporal.since_actor_bucket`; `causal_depth` = number of distinct
`causal_signature`s; `causal_concentration` = `max(phis) / phi_total` (0.0 when `phi_total == 0`);
`responsibility_peak` = max `t.responsibility`; and three controls expected to be
uninformative — `distinct_actors` (distinct `actor.identity`), `evidence_count` (Σ evidence
refs), `transition_count`.

### 2.13 `pocketsec/stage1/guillotine/ablation.py` — the Information Guillotine (D1.11)

`__all__ = ["ABLATIONS", "AblationResult", "InformationFamily", "ParetoReport", "run_guillotine"]` (ablation.py:43)

| Symbol | Signature / type | file:line | Purpose |
|---|---|---|---|
| `InformationFamily` | `@dataclass(frozen=True, slots=True)` | ablation.py:47 | Fields: `name: str` (:50), `fields: frozenset[str]` (:51), `rationale: str` (:52). |
| `ABLATIONS` | `tuple[InformationFamily, ...]` — 9 families in the spec's removal order | ablation.py:57 | Measured order and field sets: `exact_identity` `{actor_id, object_id}`; `evidence_link` `{evidence_id}`; `object_semantics` `{object_sem}`; `actor_semantics` `{actor_sem}`; `capability_delta` `{state_delta, invariant_delta}`; `uncertainty` `{uncertainty}`; `novelty` `{novelty_host, novelty_actor, novelty_relation, novelty_object}`; `timing` `{time_bucket}`; `causal_memory` `{causal_sig, epoch_id_low}`. `relation` and `flags` are **never ablated**, so `transition_count` survives every cut. |
| `AblationResult` | `@dataclass(frozen=True, slots=True)` | ablation.py:107 | One frontier point. Fields in order: `label: str` (:110), `removed: tuple[str, ...]` (:111), `retained_fields: tuple[str, ...]` (:112), `bytes_per_transition: float` (:113), `pr_auc: float \| None` (:114), `recall_at_fpr_budget: float \| None` (:115), `precision: float \| None` (:116), `recall: float \| None` (:117), `false_positives: int` (:118), `transitions_scored: int` (:119). |
| `AblationResult.security_retention` | `@property -> float \| None` | ablation.py:122 | An alias for `pr_auc`. |
| `AblationResult.to_dict` | `def to_dict(self) -> dict[str, Any]` | ablation.py:125 | Emits `retained_field_count`, not the field names. Floats rounded (bytes 2 dp, metrics 4 dp); `None` preserved as `None`. |
| `ParetoReport` | `@dataclass(frozen=True, slots=True)` | ablation.py:145 | Fields in order: `leave_one_out: dict[str, float]` (:154), `points: tuple[AblationResult, ...]` (:155), `knee: AblationResult \| None` (:156), `baseline: AblationResult` (:157), `held_out: bool = False` (:161). Note `leave_one_out` comes **first** positionally. |
| `ParetoReport.is_measured_frontier` | `@property -> bool` | ablation.py:164 | At least two distinct `bytes_per_transition` values among the points. |
| `ParetoReport.informative_cuts` | `@property -> int` | ablation.py:169 | Number of cumulative cuts where PR-AUC strictly fell relative to the previous point. |
| `ParetoReport.degenerate` | `@property -> bool` | ablation.py:180 | `informative_cuts <= 1`. A degenerate frontier is a statement about the corpus; its knee must not justify a freeze. |
| `ParetoReport.redundant_families` | `@property -> frozenset[str]` | ablation.py:192 | Intersection of cumulatively free (`pr_auc >= previous - 1e-9`) and leave-one-out free (`cost <= 1e-9`). The only honest removal candidates. |
| `ParetoReport.caveat` | `@property -> str` | ablation.py:214 | Three outcomes: `"OPTIMISTIC: …"` when `not held_out`; `"DEGENERATE: …"` when degenerate; else `"frontier discriminates between field families"`. Always surface this string alongside any frontier number. |
| `ParetoReport.to_dict` | `def to_dict(self) -> dict[str, Any]` | ablation.py:230 | Keys: `baseline`, `knee`, `points`, `leave_one_out`, `redundant_families`, `is_measured_frontier`, `held_out`, `informative_cuts`, `degenerate`, `caveat`. |
| `run_guillotine` | `def run_guillotine(results: list[ScenarioResult], *, train: list[ScenarioResult] \| None = None, fpr_budget: float = 0.05, threshold: float = 0.5, knee_tolerance: float = 0.02) -> ParetoReport` | ablation.py:299 | `results` positional (the **scoring** split); the rest keyword-only. `train=None` fits and scores on `results` and sets `held_out=False`. Produces `1 + 9 = 10` cumulative points plus 9 leave-one-out evaluations — 19 probe fits per call. Baseline retains `frozenset(LAYOUTS)` (all 17 codec fields, 37 bytes). Byte cost comes from `SSIRCodec(retained=…).record_bytes(RepresentationLevel.L2)`, so it is per-record, independent of the corpus. |

`_find_knee` (ablation.py:372) returns the **cheapest** point whose PR-AUC is
`>= baseline.pr_auc - knee_tolerance`, or `None` when the baseline PR-AUC is `None`. The
baseline itself is always a candidate.

**Measured this session.** `run_guillotine(score, train=fit)` with two disjoint
`build_hard_corpus(count=160, split="eval")` draws (seeds 3 and 11, one fresh pipeline per
split): baseline PR-AUC **0.9955506117908788** at **37.0** bytes/transition; knee
`-actor_semantics` at **21.0** bytes. With `count=60` on the same seeds: baseline PR-AUC
**0.9761904761904762**, knee `-actor_semantics` at 21.0 bytes with PR-AUC
**0.9712643678160919**, `informative_cuts=5`, `degenerate=False`, `held_out=True`,
`redundant_families = ['evidence_link', 'exact_identity', 'object_semantics', 'uncertainty']`,
wall clock 0.98 s. Passing a benign-only `train` split raises `ValueError` from
`LogisticProbe.fit` (measured).

### 2.14 `pocketsec/stage1/guillotine/stability.py` — multi-draw freeze stability

`__all__ = ["FREEZE_UNANIMITY_REQUIRED", "StabilityReport", "measure_stability"]` (stability.py:26)

| Symbol | Signature / type | file:line | Purpose |
|---|---|---|---|
| `FREEZE_UNANIMITY_REQUIRED` | `bool = True` | stability.py:30 | Module-level switch read by `freeze_candidates`. `True` → threshold 1.0; `False` → 0.8. |
| `DEFAULT_CORPUS_SIZE` | `int = 240` | stability.py:32 | Not in `__all__`. |
| `StabilityReport` | `@dataclass(frozen=True, slots=True)` | stability.py:36 | Fields in order: `draws: int` (:37), `corpus_size: int` (:38), `redundancy_rate: dict[str, float]` (:40), `loo_spread: dict[str, tuple[float, float, float]]` (:42) as `(min, mean, max)`, `baseline_pr_auc: tuple[float, float, float]` (:43) as `(min, mean, max)`, `knee_bytes: tuple[float, float, float]` (:44), `full_bytes: float` (:45). |
| `StabilityReport.freeze_candidates` | `@property -> frozenset[str]` | stability.py:48 | Families with `redundancy_rate >= threshold`. Safe to drop. |
| `StabilityReport.unstable` | `@property -> frozenset[str]` | stability.py:56 | `0.0 < rate < 1.0` — the dangerous ones a single draw would have recommended dropping. |
| `StabilityReport.freeze_ready` | `@property -> bool` | stability.py:67 | `bool(freeze_candidates) and draws >= 3`. |
| `StabilityReport.to_dict` | `def to_dict(self) -> dict[str, Any]` | stability.py:70 | Adds `freeze_candidates`, `unstable` (both sorted lists) and `freeze_ready`. |
| `measure_stability` | `def measure_stability(*, draws: int = 4, corpus_size: int = DEFAULT_CORPUS_SIZE, base_seed: int = 1000) -> StabilityReport` | stability.py:97 | All keyword-only. Draw `d` uses `fit_seed = base_seed + d*2` and `score_seed = base_seed + d*2 + 1`, each compiled on its **own** fresh pipeline, so no draw scores data its probe was fitted on. Cost: `2 × draws` corpus compiles and `19 × draws` probe fits. `full_bytes` is overwritten each draw, so it reports the **last** draw's baseline byte count. |

**Measured this session** via gate G1.11 (`draws=3, corpus_size=160`): baseline PR-AUC
0.9868 [0.9830–0.9923]; freeze candidates `['evidence_link', 'exact_identity']`;
UNSTABLE `['actor_semantics']`; 7 families justified.

---

## 3. How to construct and drive the subsystem

This snippet was executed in the authoring session and ran to completion against the
signatures above. Run it from the repo root with `PYTHONPATH=.` (or with the package
installed).

```python
"""Minimal, correct drive of the Stage 1 runtime."""
from pocketsec.stage0.contracts.model_slot import validate_slot
from pocketsec.stage0.contracts.security_event_v1 import (
    SecurityEventSequenceV1,
    SecurityEventV1,
)
from pocketsec.stage1.guillotine.ablation import run_guillotine
from pocketsec.stage1.labs.hard_corpus import build_hard_corpus
from pocketsec.stage1.pipeline import ScenarioResult, Stage1Pipeline
from pocketsec.stage1.slot import NoveltyStatisticalSlot, StateCalculusSlot
from pocketsec.stage1.telemetry.raw_event_v1 import SensorPath


def compile_split(*, count: int, seed: int) -> list[ScenarioResult]:
    """One pipeline per split; one DISTINCT offset per scenario.

    Reusing an offset on the same pipeline shares a lineage and manufactures
    capability accumulation the corpus never described (see Trap T1).
    """
    pipeline = Stage1Pipeline(host_id="lab-host-01")
    return [
        pipeline.run_scenario(scenario, sensor=SensorPath.EBPF, offset=index)
        for index, scenario in enumerate(
            build_hard_corpus(count=count, seed=seed, split="eval")
        )
    ]


# Two DISJOINT labelled splits: the probe must never score what it was fitted on.
fit = compile_split(count=160, seed=3)
score = compile_split(count=160, seed=11)

report = run_guillotine(score, train=fit)
assert report.held_out, "an optimistic frontier must not drive a freeze decision"
print(report.baseline.pr_auc, report.baseline.bytes_per_transition)
print(report.knee.label, report.knee.bytes_per_transition)
print(report.caveat)  # ALWAYS report this next to any frontier number

# Drive the Stage 0 model-slot boundary with the same compiled SSIR.
keyed = {f"seq-{i:04d}": result for i, result in enumerate(score)}
calculus = StateCalculusSlot(results=keyed)          # keyword args, not positional
statistical = NoveltyStatisticalSlot(results=keyed)
validate_slot(calculus)
validate_slot(statistical)

sequence = SecurityEventSequenceV1(
    sequence_id="seq-0000",          # must match a key in `keyed`, or the slot abstains
    host_id="lab-host-01",
    events=(
        SecurityEventV1(
            event_id="seq-0000-e0",
            host_id="lab-host-01",
            boot_id="boot-0001",
            observed_at_ns=1,
            monotonic_ns=1,
            source="stage1.ssir",
            kind="ssir.transition",
        ),
    ),
)
print(calculus.predict(sequence).verdict, statistical.predict(sequence).verdict)
```

Measured output of the above in this session: baseline PR-AUC `0.9955506117908788` at `37.0`
bytes, knee `-actor_semantics` at `21.0` bytes, caveat
`frontier discriminates between field families`, and both slots returning `SUSPICIOUS`.

Cumulative policy state is read from the pipeline, never from a `ScenarioResult`:

```python
pipeline = Stage1Pipeline()
for index, scenario in enumerate(build_hard_corpus(count=40, seed=3, split="eval")):
    pipeline.run_scenario(scenario, offset=index)

snapshot = pipeline.report()          # cumulative over EVERY scenario run on this instance
snapshot["aggregation"]["compression_ratio"]
snapshot["observation"]["escalations_opened"]
pipeline.aggregation.report()         # AggregationReport
pipeline.observation.report()         # AOPReport; mean_uncertainty_reduction may be None
```

Driving the two policies directly, without the pipeline:

```python
from pocketsec.stage1.aggregation.policy import AggregationPolicy, AggregationThresholds, can_aggregate
from pocketsec.stage1.observation.policy import AOPBudget, AdaptiveObservationPolicy

aop = AdaptiveObservationPolicy(AOPBudget(max_concurrent=4))
decision = aop.consider(                      # every argument is keyword-only
    target="proc:boot-0001:1000:7",
    uncertainty=0.9,
    security_potential=8.0,                   # raw Φ; squashed internally, not clipped
    causal_relevance=0.6,                     # LINEAGE cumulative responsibility, not this ΔΦ
    now_ns=1_000_000,
)
if decision.escalated:
    aop.record_observation(decision.target, extra_events=4, uncertainty_now=0.4)
assert aop.collects("credential_access", "any-target-at-all")   # mandatory: unconditional

policy = AggregationPolicy(AggregationThresholds(max_novelty=0.25))
allowed, reason = can_aggregate(transition, policy.thresholds)   # reason returned even when allowed
emit_me = policy.offer(transition)            # None means absorbed into a run
```

Running the gate programmatically:

```python
from pocketsec.stage1.cli import main
from pocketsec.stage1.gate import run_gate

report = run_gate()                    # no arguments; builds its own context
report.passed, [c.id for c in report.failures]
raise SystemExit(main(["gate"]))       # or ["--json", "gate"]
```

---

## 4. Invariants enforced in code

Each row names the line that enforces it, and the test or gate check that would fail if it
were broken. Tests are in `tests/`; gate checks are ids from `run_gate`.

| Invariant | Enforced at | Verified by |
|---|---|---|
| AOP never disables a mandatory signal: `collects` returns `True` for any signal in `MANDATORY_SIGNALS` regardless of escalation state or budget. | observation/policy.py:209-210 | `tests/test_stage1_bounded.py:432 test_mandatory_signals_are_collected_without_escalation`; gate G1.7 (`mandatory_intact`, gate.py:328) |
| Escalation budget is a **product**, so any zero factor suppresses it entirely. | observation/policy.py:186-189 | `tests/test_stage1_bounded.py:440 test_budget_is_a_product_so_any_zero_factor_suppresses`; measured: `budget_score(1.0, 0.0, 1.0) == 0.0` |
| High uncertainty with no security consequence does not escalate. | observation/policy.py:186-189, 238-241 | `tests/test_stage1_bounded.py:447 test_high_uncertainty_without_consequence_does_not_escalate` |
| Concurrency, rate and memory caps refuse new escalations rather than degrading. | observation/policy.py:265-276 | `tests/test_stage1_bounded.py:455 test_concurrency_cap_refuses_further_escalation` |
| Escalations expire without renewal. | observation/policy.py:296-300 | `tests/test_stage1_bounded.py:472 test_escalations_expire` |
| The extra-event rate is capped and the cap is recorded in `caps_hit`. | observation/policy.py:290-293 | `tests/test_stage1_bounded.py:489 test_extra_event_rate_is_capped` |
| `mean_uncertainty_reduction` is `None`, never `0.0`, when nothing was measured. | observation/policy.py:315-317 | Measured in this session; consistent with the Stage 0 "unmeasured is not measured" rule |
| High-consequence transitions are refused aggregation **unconditionally, before** the four conjuncts. | aggregation/policy.py:72-73 | `tests/test_stage1_bounded.py:512 test_high_consequence_transitions_are_never_aggregated`; gate G1.8 (gate.py:363-367) |
| An incomplete observation cannot be aggregated (low information loss is uncertifiable). | aggregation/policy.py:80-81 | `tests/test_stage1_bounded.py:534 test_incomplete_observation_blocks_aggregation` |
| Aggregation is fidelity reduction, never erasure: count, interval, novelty extrema, max uncertainty and head/tail evidence are retained. | aggregation/policy.py:113-124, 126-136 | `tests/test_stage1_bounded.py:522 test_aggregation_retains_count_extrema_and_evidence` |
| Repetitive low-value transitions do coalesce (the policy is not inert). | aggregation/policy.py:203-206 | `tests/test_stage1_bounded.py:507 test_repetitive_low_value_events_aggregate`; gate G1.8 flood `compression_ratio > 0.5` |
| Group count is bounded. | aggregation/policy.py:208-210 | UNMEASURED by a dedicated test; `max_groups=512` default at aggregation/policy.py:50 |
| A supervised probe refuses a single-class fit split, loudly. | features.py:157-163 | `tests/test_stage1_guillotine.py:46 test_probe_refuses_a_single_class_fit`; measured `ValueError` |
| The probe is deterministic (zero init, fixed iterations). | features.py:168-170, 137 | `tests/test_stage1_guillotine.py:63 test_probe_is_deterministic` |
| Features are standardised on the fit split only, so scale does not decide. | features.py:194-214 | `tests/test_stage1_guillotine.py:71 test_probe_standardises_so_scale_does_not_decide` |
| Every feature maps to a real SSIR field family. | features.py:34-64 | `tests/test_stage1_guillotine.py:86 test_every_feature_maps_to_a_real_ssir_field` |
| Removing a family removes its features from the fit entirely. | features.py:67-72, ablation.py:256-263 | `tests/test_stage1_guillotine.py:90 test_removing_a_family_removes_its_features` |
| An empty scenario yields all-zero features rather than raising. | features.py:77-78 | `tests/test_stage1_guillotine.py:97 test_features_of_an_empty_scenario_are_zero`; measured |
| A frontier fitted and scored on one split declares itself OPTIMISTIC and must not drive a freeze. | ablation.py:161, 215-219, 368 | `tests/test_stage1_guillotine.py:168 test_frontier_flags_an_optimistic_fit`; gate G1.9 requires `held_out` |
| A corpus too separable to discriminate declares itself DEGENERATE. | ablation.py:180-189, 220-227 | `tests/test_stage1_pipeline.py:258 test_guillotine_reports_its_own_degeneracy`, `:282 test_guillotine_detects_an_informative_frontier`; gate G1.9 requires `not degenerate` |
| A family is a removal candidate only when it is free **both** cumulatively and leave-one-out. | ablation.py:192-211 | `tests/test_stage1_guillotine.py:192 test_leave_one_out_covers_every_family` |
| A freeze candidate must be redundant on **every** draw. | stability.py:48-53, 30 | `tests/test_stage1_guillotine.py:209 test_stability_requires_unanimity_for_a_freeze_candidate`, `:215 test_unstable_families_are_not_freeze_candidates` |
| Stability reports a spread, not a point estimate. | stability.py:132-137 | `tests/test_stage1_guillotine.py:228 test_stability_reports_a_spread_not_a_point_estimate` |
| The knee is cheaper than the full representation, and chosen by measurement. | ablation.py:372-385 | `tests/test_stage1_pipeline.py:133 test_guillotine_knee_is_cheaper_than_the_full_representation` |
| Cumulative ablation actually sheds bytes. | ablation.py:279-281, 333-346 | `tests/test_stage1_guillotine.py:185 test_cumulative_ablation_sheds_bytes` |
| Removing everything collapses to near chance (the frontier is not measuring an artefact). | ablation.py:333-346 | `tests/test_stage1_guillotine.py:198 test_removing_everything_collapses_to_near_chance` |
| The hard corpus has overlapping class distributions and contains both classes. | hard_corpus.py:249-301 | `tests/test_stage1_guillotine.py:109 test_hard_corpus_has_overlapping_distributions`, `:117 test_hard_corpus_contains_both_classes` |
| The timing pair genuinely differs in timing (an earlier draft made it pure label noise). | hard_corpus.py:228-246 | `tests/test_stage1_guillotine.py:123 test_timing_pair_actually_differs_in_timing` |
| The novelty pair is not confounded with capability. | hard_corpus.py:205-225 | `tests/test_stage1_guillotine.py:141 test_novelty_pair_is_not_confounded_with_capability` |
| Every discriminator pair's halves actually differ. | hard_corpus.py:169-175 | `tests/test_stage1_guillotine.py:152 test_discriminator_pairs_differ` |
| A benign spread across fewer actors than chain stages is refused rather than silently mislabelled. | ambiguous_corpus.py:251-256 (`RuntimeError`) | UNMEASURED by a dedicated test; the guard is unconditional |
| Train splits are benign-only. | corpus.py:234-236, hard_corpus.py:259-264, ambiguous_corpus.py:285, longhorizon_corpus.py:183 | `tests/test_stage1_pipeline.py:106 test_train_split_is_benign_only`; measured labels `[0]` for all four corpora |
| Unseen techniques are absent from training. | corpus.py:256-270 | `tests/test_stage1_pipeline.py:110 test_unseen_techniques_are_absent_from_training` |
| Corpora are deterministic given a seed. | corpus.py:229, hard_corpus.py:256, ambiguous_corpus.py:278, longhorizon_corpus.py:179 | `tests/test_stage1_pipeline.py:100 test_corpus_is_deterministic` |
| The two sensor paths have genuinely different record shapes, yet identical semantics. | corpus.py:169-217 | `tests/test_stage1_pipeline.py:85 test_sensor_paths_have_genuinely_different_record_shapes`, `:75 test_two_sensor_paths_produce_identical_semantics`; gate G1.1 20/20 |
| An unrecognised operation is counted, never invented. | pipeline.py:134-136 | `tests/test_stage1_pipeline.py:48 test_unrecognised_operation_is_not_invented`; measured `unresolved == 1` |
| Each scenario gets a fresh assembler, so assembly state cannot leak between scenarios. | pipeline.py:108 | UNMEASURED by a dedicated test; the construction is unconditional |
| Both slots satisfy the frozen Stage 0 `ModelSlot` boundary and carry no response authority. | slot.py:59-60, 112-113, 163-164 | `tests/test_stage1_pipeline.py:159 test_both_slots_satisfy_the_stage0_boundary`, `:171 test_slot_carries_no_authority`; measured `validate_slot` passes |
| Slot confidence is honestly uncalibrated (`calibration_id=None`). | slot.py:139, 182 | `tests/test_stage1_pipeline.py:165 test_slots_report_uncalibrated_confidence` |
| An unknown sequence id makes a slot abstain rather than default to benign. | slot.py:118-119, 168-169, 87-100 | `tests/test_stage1_pipeline.py:181 test_unknown_sequence_makes_a_slot_abstain`; measured `INSUFFICIENT_EVIDENCE`, `abstained=True`, `uncertainty=1.0` |
| A window the calculus cannot interpret abstains instead of defaulting to benign. | slot.py:130-131 | Gate G1.13 indirectly; threshold `0.8` is a literal at slot.py:130 |
| Two model families can disagree on identical SSIR without the representation changing. | slot.py:104-190 | `tests/test_stage1_pipeline.py:189 test_two_model_families_disagree_on_the_same_representation`; gate G1.13 measured 18 agreements / 42 disagreements |
| The novelty slot is expected to fire on novel benign work (novelty is not maliciousness). | slot.py:155-190 | `tests/test_stage1_pipeline.py:203 test_novelty_slot_fires_on_novel_benign_work` |
| The whole gate passes and the CLI exits zero. | gate.py:89-108, cli.py:54-65 | `tests/test_stage1_pipeline.py:221 test_stage1_acceptance_gate_passes`, `:228 test_gate_cli_exits_zero`; measured exit 0 in 14.0 s |
| The adversarial suite passes 8/8. | adversarial.py:322-335 | `tests/test_stage1_pipeline.py:143 test_adversarial_suite_passes`; measured 8/8 in 0.12 s |
| Behavioural novelty alone never opens an epoch. | adversarial.py:198-228 (test) enforcing `epoch/model.py:170` | `tests/test_stage1_bounded.py:253 test_novelty_alone_never_opens_an_epoch`; gate G1.5, adversarial `epoch_poisoning` |
| Conflicting sensors raise uncertainty rather than picking a winner. | adversarial.py:261-319 | `tests/test_stage1_bounded.py:217 test_sensor_conflicts_are_surfaced_not_resolved`; measured 0.550 vs 0.300 |

---

## 5. Extension points

### Sanctioned — plug in here

1. **`Stage1Pipeline` constructor fields.** `host_id`, `identity`, `novelty`, `causal`,
   `aggregation`, `observation` (pipeline.py:81-92) are the intended injection points. Supply
   a tuned `AggregationPolicy(AggregationThresholds(...))` or
   `AdaptiveObservationPolicy(AOPBudget(...))` here rather than mutating the defaults.
2. **`AOPBudget` (observation/policy.py:60).** Every cap is a field. Tighten or loosen budgets
   through a new `AOPBudget` instance; the caps are read from `self.budget` on every decision.
3. **`AggregationThresholds` (aggregation/policy.py:42).** The four conjunct thresholds plus
   `evidence_sample` and `max_groups`. Changing these changes fidelity, never the
   high-consequence refusal, which is not threshold-driven.
4. **A new `ModelSlot` over `ScenarioResult`.** Subclass `SSIRSlotBase` (slot.py:50) and
   declare `slot_name`, `model_state_version` and a `predict`. The base class's `_relevance`
   and `_abstain` give you evidence weighting and honest abstention for free. This is the
   sanctioned path for a Stage 2 model to consume Stage 1 without renegotiating anything:
   `StateCalculusSlot` and `NoveltyStatisticalSlot` exist to prove the representation is not
   tuned to one consumer.
5. **A new corpus.** Write a `build_*_corpus(*, count, seed, split) -> tuple[Scenario, ...]`
   beside the four in `labs/`. Compose `Behaviour` and `Scenario` from `labs/corpus.py`; do
   not invent a parallel behaviour type. `Behaviour.with_fields` (corpus.py:40) is the
   immutable way to derive a variant chain, as `labs/adversarial.py:76 _rename` demonstrates.
6. **A new information family.** Append an `InformationFamily` to `ABLATIONS` (ablation.py:57)
   and add the features it carries to `FEATURE_FAMILIES` (features.py:34). Both are needed:
   a family with no features changes byte cost only, and a feature whose family is not in
   `LAYOUTS` is never retained.
7. **A different probe.** `run_guillotine` calls `LogisticProbe()` directly at ablation.py:259,
   so swapping the probe currently means editing `_fit_and_score`. The honest note in
   `planning/MEMORY.md` — "the frontier reflects one probe family (linear)" — is the reason this
   is worth doing, and the reason a non-linear result must be reported as a different frontier
   rather than an improvement to this one.
8. **`pocketsec-stage1` subcommands.** Add a `(name, help)` pair to the loop at cli.py:29-37
   and a handler to the dict at cli.py:43-50. Handlers take `*, as_json: bool` and return an
   exit code.

### Forbidden — do not plug in here

1. **Do not merge `SecurityStateV1` into `SSIRTransitionV1`.** SSIR answers "what changed";
   the state answers "what is now true". Gate G1.2 (gate.py:130) fails if they merge.
2. **Do not collapse novelty, Φ and uncertainty into one score.** Gate G1.4 (gate.py:183)
   requires measured high-novelty/low-potential windows and a correlation below 0.9. The two
   slots exist precisely to keep the signals separately consumable.
3. **Do not make `can_aggregate` skip the high-consequence check, and do not relax it to a
   fifth conjunct.** It is checked first and unconditionally (aggregation/policy.py:72-73).
4. **Do not let AOP remove a signal.** `collects` (observation/policy.py:202) is the only
   sanctioned read of collection state, and it short-circuits for mandatory signals. Do not add
   a de-escalation path that bypasses it.
5. **Do not route behavioural novelty into the epoch decision.** `EpochModel.evaluate` accepts
   `behavioural_novelty` and deliberately ignores it, so that callers cannot smuggle novelty in
   through another door. Adversarial `epoch_poisoning` (adversarial.py:198) fails if this changes.
6. **Do not use a `degenerate` or `not held_out` frontier to justify dropping an SSIR field.**
   `ParetoReport.caveat` (ablation.py:214) says which state you are in; gate G1.9 refuses both.
   Per `planning/MEMORY.md`, the D1.13 freeze stands narrowly on `exact_identity` only, and
   `evidence_link` is retained despite measuring free because the evidence trail is a Stage 0
   invariant that measurement does not overrule.
7. **Do not fit and score a probe on the same split.** `run_guillotine(results)` without
   `train=` is allowed only for exploration, and it self-reports `held_out=False`.
8. **Do not treat any Stage 1 number as a detection result.** Every corpus in `labs/` is
   synthetic, and every scenario carries a constructed label. `run_guillotine`'s own docstring
   and the CLI's banner (cli.py:90) say so.
9. **Do not add third-party imports anywhere in this layer.** ADR-0001: zero runtime
   dependencies, enforced by an AST import test. `LogisticProbe` is hand-written for exactly
   this reason.

---

## 6. Traps

Concrete ways a later-stage implementer gets silently wrong results from this subsystem. Each
one was reproduced in the authoring session.

**T1 — Reusing an `offset` on a shared pipeline fuses two scenarios into one lineage.**
`pid = str(1000 + offset)` (pipeline.py:112) and the lineage key is
`f"proc:boot-0001:{pid}:7"` (pipeline.py:144). Capability lattices are monotone and lineage
state is carried forward, so the second scenario inherits everything the first accumulated.
**Measured:** on one pipeline, `ATTACK_EXFIL` at `offset=0` followed by a single benign
`read /var/log/syslog` at `offset=0` gives the benign scenario `peak_phi = 13.75`; the same
benign scenario on a fresh pipeline gives `0.0`, and at `offset=1` on the same pipeline gives
`0.0`. The `_lineage_responsibility` accumulator (pipeline.py:97) is likewise never reset:
measured `{'proc:boot-0001:1000:7': 13.75}` persisting into the next scenario, which inflates
AOP causal relevance. **Always** enumerate scenarios and pass a distinct `offset`, as
`gate.py:47-50`, `gate.py:74-75` and `stability.py:89-93` all do.

**T2 — A corpus that sets its own `pid` or `start_time` silently zeroes
`final_state` and `peak_phi`.** `run_scenario` reads exactly one lineage,
`f"proc:boot-0001:{pid}:7"` (pipeline.py:144), but `emit` lets `behaviour.fields` override
`pid`, `start_time` and `uid` (corpus.py:167). The ambiguous corpus does exactly that
(`_behaviour`, ambiguous_corpus.py:189). **Measured:** for
`build_ambiguous_corpus(count=3, seed=5)`, every session reports
`ScenarioResult.peak_phi == 0.0` and an all-zero `final_state`, while the per-transition
`max(delta_phi)` reaches 4.000 on the malicious session and 2.250 on the benign ones, across
7–8 distinct `actor.identity` values. Any feature built on `final_state` or `peak_phi` — which
includes `StateCalculusSlot.predict` and the Φ-oracle — reads a constant zero on that corpus
and looks like "the representation carries nothing". Read `result.transitions` and group by
`t.actor.identity` for multi-actor corpora. The long-horizon corpus sets only `_gap_ns`
(longhorizon_corpus.py:111) and is therefore safe.

**T3 — `peak_phi` is not a peak.** It is `phi(final_state).total` (pipeline.py:151).
**Measured** on `ATTACK_EXFIL`: `peak_phi = 13.75` while the largest single-step `delta_phi`
is 8.75. Within one lineage the monotone lattices make the final state the maximum, so the
name is defensible there — but it is not a per-step maximum, and under T2 it is not even the
scenario's state. `peak_novelty` and `peak_uncertainty` (pipeline.py:152-153) *are* true
maxima over transitions; the naming is inconsistent on purpose-free grounds.

**T4 — `build_hard_corpus(count=N, split="eval")` returns more than `N` when `N < 26`.**
The pair guarantee adds 10 + 8 + 8 = 26 scenarios before the padding loop, and
hard_corpus.py:301 returns them all when `count` is smaller. **Measured:** `count=5` → 26
scenarios, `count=20` → 26, `count=26` → 26, `count=40` → 40. Never compute a base rate or a
per-scenario budget from the `count` you asked for; measure `len(...)` of what you got.

**T5 — `split` is not validated in any corpus builder.** `build_corpus` (corpus.py:234),
`build_hard_corpus` (hard_corpus.py:259), `build_ambiguous_corpus` (ambiguous_corpus.py:285)
and `build_long_horizon_corpus` (longhorizon_corpus.py:183) all test `split == "train"` (or
`!= "train"`) and fall through to the mixed branch otherwise. A typo such as `split="Train"`
or `split="training"` silently yields the labelled eval mix, which then leaks attack labels
into what you believe is a benign-only anomaly-detection split.

**T6 — A benign-only fit split does not degrade the frontier; it raises.**
`run_guillotine(score, train=benign_only)` propagates `ValueError` from
`LogisticProbe.fit` (features.py:159; measured). That is the intended behaviour — the
alternative was an inverted ranking and a baseline PR-AUC below the base rate — but an
implementer who wraps the call in a bare `except` will silently lose every frontier point.

**T7 — An already-escalated target is renewed regardless of score, threshold or cap.**
`consider` checks `if target in self._active` **before** the threshold and cap checks
(observation/policy.py:234-236). **Measured:** after opening on a score of 0.926, a second
`consider` for the same target with `uncertainty=0, security_potential=0, causal_relevance=0`
returns `escalated=True, budget_score=0.0` and keeps the target at `HIGH_RESOLUTION`. A
long-lived target therefore never has to re-earn its escalation, and its level never falls
until `max_duration_ns` expires it. Do not read `EscalationDecision.escalated` as "the budget
justifies this right now".

**T8 — `record_observation` on a non-escalated target is a silent no-op.**
observation/policy.py:287-289 returns early when the target is not in `_active`.
**Measured:** `extra_events_collected` stays 0 and `mean_uncertainty_reduction` stays `None`.
If you drive AOP yourself, call `record_observation` only when
`decision.escalated` is true, and only before the escalation expires — otherwise the
acceptance-criterion-7 payoff metric silently reports nothing.

**T9 — Negative uncertainty reductions are recorded without complaint.**
`self._uncertainty_reductions.append(escalation.uncertainty_at_open - uncertainty_now)`
(observation/policy.py:294). A worsening observation pulls the reported mean down and can
cross zero, which is exactly the quantity gate G1.7 tests (`reduced`, gate.py:321). The
pipeline sidesteps this by hard-coding `uncertainty_now = max(0.05, uncertainty * 0.5)`
(pipeline.py:193) — a *constructed* halving, not a measured resolution. Do not cite
`mean_uncertainty_reduction` from a pipeline-driven run as evidence that escalation resolves
real uncertainty.

**T10 — `AggregatedTransition.first_ns` / `last_ns` / `interval_ns` are sequence numbers, not
nanoseconds.** They are populated from `transition.sequence` (aggregation/policy.py:115, 193,
195). **Measured:** a 2-member run reported `first_ns=4, last_ns=5, interval_ns=1` for
transitions whose sequence numbers were 4 and 5. Never convert `interval_ns` to a duration.

**T11 — `AggregationReport.refusal_reasons` keys are unbounded free text.** The key is
`reason.split(":")[0]` (aggregation/policy.py:180), and only two of the five refusal reasons
contain a colon. **Measured keys:** `'high-consequence'`, but also
`'novelty peak 1.000 above threshold'`, `'novelty peak 0.500 above threshold'`,
`'novelty peak 0.333 above threshold'`. Aggregating by this key produces one bucket per
distinct formatted float, so a dashboard keyed on it grows without bound and never groups.
Match on a prefix, or count refusals yourself from `can_aggregate`.

**T12 — The first member of every aggregation run is emitted and counted as `emitted`.**
aggregation/policy.py:201. `compression_ratio` is therefore always below 1.0 and a run of two
identical transitions compresses only 50%. **Measured:** five identical reads produced
`emitted=4, aggregated_away=1, compression_ratio=0.2`, because novelty falls through the
threshold only after several sightings. Do not read a low ratio on a short scenario as "the
policy is not working".

**T13 — Every policy report on a pipeline is cumulative across scenarios, but every
`ScenarioResult` is per-scenario.** `aggregation` and `observation` are pipeline fields
(pipeline.py:89-92) and are never reset by `run_scenario`. **Measured:**
`aggregation.report().emitted` went 4 → 8 across two `ATTACK_EXFIL` scenarios. Mixing a
cumulative `pipeline.report()` figure with a per-scenario `ScenarioResult` figure in the same
ratio is a category error.

**T14 — `emitted` is a policy artefact, not a fidelity claim, and `semantic_keys` ignores it.**
`ScenarioResult.semantic_keys` (pipeline.py:60) is built from `transitions`, so cross-sensor
equivalence is a statement about compilation, not about what survived aggregation. Anything
that consumes `emitted` is consuming a compressed stream whose omissions are recoverable only
through `pipeline.aggregation.groups`.

**T15 — The AOP clock is derived from a global counter, not from the corpus timeline.**
`now_ns = transition.sequence * 1_000_000` (pipeline.py:185) while the corpus's own timeline
comes from `_gap_ns` and `offset * DEFAULT_SCENARIO_SPACING_NS` (pipeline.py:115, 120). The
two are unrelated: a corpus that spreads events over hours still advances the AOP clock by
1 ms per transition. Consequently escalation expiry (`max_duration_ns = 30 s`) triggers after
30,000 transitions rather than after 30 seconds of simulated time, and `_roll_window` rolls
every 60,000 transitions. Do not reason about AOP expiry using the corpus's `_gap_ns` values.

**T16 — Ablating a family changes byte cost and feature set by *different* amounts.**
`LAYOUTS` has 17 fields but `FEATURE_FAMILIES` references only 12 (measured).
`object_id`, `novelty_relation`, `novelty_object`, `epoch_id_low` and `flags` cost bytes and
carry no feature, so removing `exact_identity` (`{actor_id, object_id}`) costs 8 bytes while
deleting exactly one feature (`distinct_actors`). `relation` and `flags` are never ablated, so
the "everything removed" point still retains `transition_count`. A PR-AUC that does not move
across a cut may mean the cut removed no features at all — check `feature_names(retained)`
before concluding a family is free.

**T17 — `run_guillotine` fits 19 probes per call, and the CLI rebuilds the whole gate context
first.** `_guillotine`, `_calibrate` and `_replay` each call `Stage1GateContext.build()`
(cli.py:84, 110, 122), which compiles the 60-scenario replay corpus plus two 160-scenario hard
splits. `measure_stability(draws=d)` multiplies that by `d`. **Measured:** the full gate,
which does all of this once plus 3 stability draws, takes 14.0 s; one
`run_guillotine` over 2 × 60 scenarios takes 0.98 s. Budget accordingly; there is no caching.

**T18 — `StabilityReport.full_bytes` reports the last draw only.** `full_bytes` is reassigned
inside the draw loop (stability.py:118) rather than aggregated, unlike
`baseline_pr_auc` and `knee_bytes`, which are `(min, mean, max)` triples. It happens to be
constant in practice because the baseline retains all of `LAYOUTS` — but it is not a measured
spread and must not be presented as one.

**T19 — `SSIRSlotBase` is not a usable slot, and positional construction of the subclasses
mis-binds fields.** The base declares no `slot_name` or `model_state_version`; `_abstain`
reaches for them behind `# type: ignore[attr-defined]` (slot.py:91, 98), so instantiating
`SSIRSlotBase` and calling `_abstain` raises `AttributeError`. For the subclasses the
inherited field order is `(results, input_schema, output_schema, slot_name,
model_state_version, <threshold>)`, so `StateCalculusSlot(results, 4.0)` binds `4.0` to
`input_schema` and then fails `validate_slot`. Always construct with keywords.
**Measured:** `SSIRSlotBase(results={})._abstain(...)` raises
`AttributeError: 'SSIRSlotBase' object has no attribute 'slot_name'`, and
`StateCalculusSlot({}, 4.0)` yields `input_schema == 4.0` and a `ContractError` from
`validate_slot` reading `slot 's1-state-calculus' accepts 4.0, hub emits
'pocketsec.security_event_sequence.v1'`.

**T20 — `StateCalculusSlot` abstains on high uncertainty; `NoveltyStatisticalSlot` does not.**
Only the calculus slot has the `peak_uncertainty >= 0.8` guard (slot.py:130). Comparing
abstention rates between the two families therefore compares two different policies, not two
different representations' worth. The asymmetry is deliberate — the novelty slot is the
control for "rare is not malicious" — but it invalidates a naive head-to-head abstention
metric.

**T21 — `_gap_ns` is consumed but not stripped, so it reaches the raw records.**
`run_scenario` reads it (pipeline.py:120) and then passes the whole `behaviour.fields` dict to
`emit`. **Measured** eBPF record fields:
`{'operation': 'sys_read', 'pid': '1000', 'start_time': '7', 'uid': '1000', 'path': '/etc/shadow', '_gap_ns': '500'}`.
On the auditd path it lands on the detail record only. Anything that hashes or enumerates
`RawEventV1.fields` sees this synthetic key; anything that treats unknown fields as evidence
of a novel sensor shape will be wrong.

**T22 — `Behaviour.fields` is a mutable dict inside a frozen dataclass.** corpus.py:38.
`frozen=True` protects the attribute binding, not the dict. Mutating
`behaviour.fields["path"]` in place changes every scenario that shares that `Behaviour`
object — and the corpus constants (`ATTACK_EXFIL`, `_BENIGN_POOL`, …) are module-level shared
tuples. Use `Behaviour.with_fields` (corpus.py:40), which copies.

**T23 — The gate's own corpus sizes and seeds are module constants, not parameters.**
`Stage1GateContext.build()` (gate.py:69) takes no arguments; `EVAL_COUNT`, `SEED`,
`GUILLOTINE_SIZE`, `GUILLOTINE_FIT_SEED`, `GUILLOTINE_SCORE_SEED`, `STABILITY_DRAWS` and
`STABILITY_SIZE` (gate.py:27-39) are the only knobs, and `cli.py:148` uses *different* values
(`draws=5, corpus_size=200`) for the standalone `stability` command. Two "stability" numbers
in this repo are therefore not directly comparable unless you check which path produced them.

**T24 — Several checks build their own scenarios and ignore `ctx`.** `_cross_sensor_equivalence`,
`_epoch_regime_change`, `_causal_spine_retained`, `_renaming_generalisation` and the
scenario-building halves of `_explicit_uncertainty`, `_adaptive_observation` and
`_aggregation_preserves_high_consequence` construct fresh pipelines and corpora inside the
check (gate.py:113, 214-215, 252, 404, 166-171, 293-316, 352-360). `_adaptive_observation` and
`_aggregation_preserves_high_consequence` accept a `ctx` argument they never read. Changing
`EVAL_COUNT` or `SEED` therefore does not change what those criteria measure.

**T25 — README and the gate disagree about frontier degeneracy, because they describe
different corpora.** `README.md` records a degenerate frontier and an 11-byte knee; that
refers to the original easy corpus. The gate runs the *hard* corpus, and **measured in this
session** G1.9 reports a non-degenerate frontier with a 21-byte knee at `-actor_semantics`
(`informative_cuts=5` on a 2 × 60 replication). Neither number is wrong; citing one while
running the other is. Always print `ParetoReport.caveat` and the corpus builder you used
alongside any frontier figure.
