# Stage 0 contracts and the authority boundary — exact API reference

> **Scope.** `pocketsec/stage0/contracts/{common,model_slot,security_event_v1,threat_prediction_v1}.py`,
> `pocketsec/stage0/contracts/__init__.py`, `contracts/security_event_sequence_v1.schema.json`,
> `contracts/threat_prediction_v1.schema.json`, `pocketsec/stage0/hypotheses.py`,
> `pocketsec/stage0/prior_art.py`.
>
> **Honesty note.** Every signature, line number and behavioural claim below was read out of the
> `.py`/`.json` files listed above, or produced by executing the code in this session on
> Python 3.14.7. Behaviours I confirmed by running code are marked **[measured]**. Nothing here is
> inferred from other documentation. Where the code does *not* enforce something a reader might
> assume it enforces, that is stated as a gap rather than glossed.

---

## 1. Purpose

Stage 0's contract subsystem freezes the **boundary** between the stable PocketSec hub (telemetry
normalisation, deterministic rules, evidence, storage, presentation) and replaceable learned
intelligence — and it freezes only the boundary, deliberately not the security ontology, which is
Stage 1's subject and lives in the opaque `SecurityEventV1.attributes` map. It consists of exactly
two versioned, immutable record types (`SecurityEventSequenceV1` hub → slot,
`ThreatPredictionV1` slot → hub), a one-method `ModelSlot` protocol that any model family must
satisfy, a schema-id/version registry that refuses in-place breaking changes, and shared validation
helpers that make contract violations raise `ContractError` at construction time instead of
producing a plausible-looking wrong answer downstream. The same files carry the **authority
boundary**: a `ThreatPredictionV1` has no action, command, shell or privilege field, the JSON Schema
is closed (`additionalProperties: false`), and `FORBIDDEN_AUTHORITY_FIELDS` plus
`tests/test_authority_boundary.py` make adding one a test failure — so model confidence
structurally cannot become execution permission (that is Stage 5's, under SENTINEL). Alongside them,
`hypotheses.py` and `prior_art.py` hold the research-honesty ledgers (H0–H8 and their literature /
patent review state) that the Stage 0 gate checks so a hypothesis cannot silently become a claimed
result.

---

## 2. Public symbols

### 2.1 Import surface — read this before the tables

`pocketsec/stage0/contracts/__init__.py` re-exports **only** these 18 names
(`__all__`, `pocketsec/stage0/contracts/__init__.py:21-39`):

`ComputePath`, `ContractError`, `EvidenceRef`, `EvidenceRelevance`, `ModelSlot`,
`NextEventExpectation`, `NullModelSlot`, `SCHEMA_REGISTRY`, `SECURITY_EVENT_SEQUENCE_V1_ID`,
`SECURITY_EVENT_SEQUENCE_V1_VERSION`, `SecurityEventSequenceV1`, `SecurityEventV1`,
`THREAT_PREDICTION_V1_ID`, `THREAT_PREDICTION_V1_VERSION`, `ThreatPredictionV1`, `Verdict`,
`validate_slot`.

**[measured]** The following are **not** reachable as `pocketsec.stage0.contracts.<name>` and must be
imported from their defining module: `ACCEPTED_INPUT_SCHEMA`, `PRODUCED_OUTPUT_SCHEMA`,
`FORBIDDEN_AUTHORITY_FIELDS`, `NON_COMMITTAL_VERDICTS`, `MAX_SEQUENCE_CAPACITY`, `digest_of_bytes`,
`register_schema`, `require_identifier`, `require_non_negative_int`,
`require_finite_unit_interval`, `freeze_mapping`.

**[measured]** `pocketsec.stage0` (`pocketsec/stage0/__init__.py`, docstring only) exports nothing;
`hypotheses` and `prior_art` are not attributes of the package until explicitly imported
(`from pocketsec.stage0.hypotheses import ...`).

### 2.2 `contracts/common.py` — shared primitives

| Symbol | Full signature / definition | file:line | Purpose |
|---|---|---|---|
| `ContractError` | `class ContractError(ValueError)` | `pocketsec/stage0/contracts/common.py:32` | Raised on every contract violation in this subsystem. Subclasses `ValueError`, so `except ValueError` also catches it. |
| `_IDENTIFIER_RE` (private) | `re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:\-]{0,127}$")` | `common.py:28` | The identifier grammar every id field must match: 1–128 chars, first char alphanumeric, then alphanumerics/`.`/`_`/`:`/`-`. |
| `_DIGEST_RE` (private) | `re.compile(r"^sha256:[0-9a-f]{64}$")` | `common.py:29` | Evidence digest grammar. Lowercase hex only. |
| `SCHEMA_REGISTRY` | `SCHEMA_REGISTRY: Mapping[str, str] = MappingProxyType(_SCHEMA_REGISTRY)` | `common.py:46` | Read-only live view of schema id → semver. **[measured]** After importing the two contract modules it is exactly `{'pocketsec.security_event_sequence.v1': '1.0.0', 'pocketsec.threat_prediction.v1': '1.0.0'}`. |
| `register_schema` | `register_schema(schema_id: str, version: str) -> str` | `common.py:49` | Registers `schema_id` at `version` and returns `version`. Idempotent for an identical pair; raises `ContractError` for a *different* version on an existing id, and for a non-`\d+\.\d+\.\d+` version. Called at **module import time** by both contract modules. |
| `require_identifier` | `require_identifier(value: object, field: str) -> str` | `common.py:72` | Returns `value` if it matches `_IDENTIFIER_RE`, else raises `ContractError(f"{field} must be a 1-128 char identifier, got {value!r}")`. |
| `require_non_negative_int` | `require_non_negative_int(value: object, field: str) -> int` | `common.py:78` | Rejects non-`int`, `bool` (explicitly), and negatives. |
| `require_finite_unit_interval` | `require_finite_unit_interval(value: object, field: str) -> float` | `common.py:84` | Accepts `int`/`float` (not `bool`), rejects NaN/±inf, rejects outside `[0.0, 1.0]`; returns `float(value)`. |
| `freeze_mapping` | `freeze_mapping(value: Mapping[str, str] \| None, field: str) -> Mapping[str, str]` | `common.py:95` | Copies then wraps in `MappingProxyType`. `None` → empty proxy. Rejects non-`Mapping`, empty/non-str keys, non-str values. The copy is deliberate: the contract object must not alias caller state. |
| `digest_of_bytes` | `digest_of_bytes(payload: bytes) -> str` | `common.py:116` | Returns `f"sha256:{hashlib.sha256(payload).hexdigest()}"`. The only sanctioned way to produce an `EvidenceRef.digest`. |
| `EvidenceRef` | `@dataclass(frozen=True, slots=True)` | `common.py:124` | Pointer to raw evidence held outside the model. Evidence is referenced, never inlined. |
| `EvidenceRef.store` | `store: str` | `common.py:134` | Validated by `require_identifier`. |
| `EvidenceRef.locator` | `locator: str` | `common.py:135` | Any **non-empty** string — *not* identifier-constrained. **[measured]** `/var/log/audit/audit.log:9931 x` is accepted. |
| `EvidenceRef.digest` | `digest: str` | `common.py:136` | Must match `^sha256:[0-9a-f]{64}$`. **[measured]** uppercase hex is rejected. |
| `EvidenceRef.__post_init__` | `__post_init__(self) -> None` | `common.py:138` | Enforces the three rules above. |
| `EvidenceRef.to_dict` | `to_dict(self) -> dict[str, str]` | `common.py:147` | `{"store", "locator", "digest"}`. |
| `EvidenceRef.from_dict` | `@classmethod from_dict(cls, payload: Mapping[str, object]) -> EvidenceRef` | `common.py:150-151` | Coerces each field with `str(...)`; a missing key raises `ContractError(f"EvidenceRef missing field ...")`. |

`EvidenceRef` is **[measured]** hashable (all three fields are `str`), so it is safe in sets and as a
dict key.

### 2.3 `contracts/security_event_v1.py` — hub → slot input

| Symbol | Full signature / definition | file:line | Purpose |
|---|---|---|---|
| `SECURITY_EVENT_SEQUENCE_V1_ID` | `= "pocketsec.security_event_sequence.v1"` | `security_event_v1.py:34` | Frozen schema id. A breaking change takes `...v2`, never a version bump. |
| `SECURITY_EVENT_SEQUENCE_V1_VERSION` | `= register_schema(SECURITY_EVENT_SEQUENCE_V1_ID, "1.0.0")` → `"1.0.0"` | `security_event_v1.py:35` | Import-time registration; the value is the version string. |
| `MAX_SEQUENCE_CAPACITY` | `= 4096` | `security_event_v1.py:40` | Hard global upper bound on one window (bounded-state invariant). |
| `SecurityEventV1` | `@dataclass(frozen=True, slots=True)` | `security_event_v1.py:43-44` | One normalised Linux security-relevant observation. `kind` is a **source-level** label, never a threat class. |
| `SecurityEventV1.event_id` | `event_id: str` | `:52` | `require_identifier`. |
| `SecurityEventV1.host_id` | `host_id: str` | `:53` | `require_identifier`. |
| `SecurityEventV1.boot_id` | `boot_id: str` | `:54` | `require_identifier`. Monotonic times are only comparable within one boot. |
| `SecurityEventV1.observed_at_ns` | `observed_at_ns: int` | `:55` | `require_non_negative_int` (wall clock, ns). |
| `SecurityEventV1.monotonic_ns` | `monotonic_ns: int` | `:56` | `require_non_negative_int` (monotonic clock, ns). |
| `SecurityEventV1.source` | `source: str` | `:57` | `require_identifier`, e.g. `"ebpf.execve"`. |
| `SecurityEventV1.kind` | `kind: str` | `:58` | `require_identifier`, e.g. `"process.exec"`. |
| `SecurityEventV1.attributes` | `attributes: Mapping[str, str] = field(default_factory=dict)` | `:59` | **The ontology extension point.** Replaced in `__post_init__` by a `MappingProxyType` copy. |
| `SecurityEventV1.evidence` | `evidence: tuple[EvidenceRef, ...] = ()` | `:60` | Per-event evidence references; each element must be an `EvidenceRef`. |
| `SecurityEventV1.__post_init__` | `__post_init__(self) -> None` | `:62` | Runs all validators, then `object.__setattr__` for `attributes` (frozen copy) and `evidence` (tuple + element type check). |
| `SecurityEventV1.to_dict` | `to_dict(self) -> dict[str, Any]` | `:75` | Keys: `event_id, host_id, boot_id, observed_at_ns, monotonic_ns, source, kind, attributes` (a plain `dict` copy), `evidence` (list of dicts). |
| `SecurityEventV1.from_dict` | `@classmethod from_dict(cls, payload: Mapping[str, Any]) -> SecurityEventV1` | `:88-89` | Requires `_EVENT_REQUIRED_KEYS`; coerces with `str()`/`int()`; `attributes` defaults to `{}` via `payload.get("attributes") or {}`; `evidence` built with `EvidenceRef.from_dict`. |
| `SecurityEventSequenceV1` | `@dataclass(frozen=True, slots=True)` | `:106-107` | A bounded, host-local window handed to a slot. |
| `SecurityEventSequenceV1.sequence_id` | `sequence_id: str` | `:116` | `require_identifier`. |
| `SecurityEventSequenceV1.host_id` | `host_id: str` | `:117` | `require_identifier`; every event's `host_id` must equal it. |
| `SecurityEventSequenceV1.events` | `events: tuple[SecurityEventV1, ...]` | `:118` | Required, coerced with `tuple(...)`, **must be non-empty**. |
| `SecurityEventSequenceV1.window_capacity` | `window_capacity: int = MAX_SEQUENCE_CAPACITY` | `:119` | Must be in `[1, 4096]`, and `len(events) <= window_capacity`. |
| `SecurityEventSequenceV1.truncated` | `truncated: bool = False` | `:120` | Must be a real `bool`. True means earlier events were dropped. |
| `SecurityEventSequenceV1.schema_version` | `schema_version: str = SECURITY_EVENT_SEQUENCE_V1_VERSION` | `:121` | **Not validated** (see Traps 8). |
| `SecurityEventSequenceV1.__post_init__` | `__post_init__(self) -> None` | `:123` | ids → capacity → events. |
| `SecurityEventSequenceV1._validate_capacity` | `_validate_capacity(self) -> None` | `:134` | Range check and overflow check. |
| `SecurityEventSequenceV1._validate_events` | `_validate_events(self) -> None` | `:147` | Element type, host match, and monotonic non-regression *between adjacent events of the same `boot_id`*. |
| `SecurityEventSequenceV1.evidence` | `@property evidence(self) -> tuple[EvidenceRef, ...]` | `:168-169` | Flattened, in observation order: `tuple(ref for event in self.events for ref in event.evidence)`. A **property**, not a field. |
| `SecurityEventSequenceV1.to_dict` | `to_dict(self) -> dict[str, Any]` | `:173` | Keys: `schema, schema_version, sequence_id, host_id, window_capacity, truncated, events`. **[measured]** exactly the JSON Schema's property set. |
| `SecurityEventSequenceV1.from_dict` | `@classmethod from_dict(cls, payload: Mapping[str, Any]) -> SecurityEventSequenceV1` | `:184-185` | Requires `sequence_id, host_id, events`. If `schema` is present it must equal `SECURITY_EVENT_SEQUENCE_V1_ID`, else `ContractError("expected schema …")`. `window_capacity`/`truncated`/`schema_version` default. |
| `_EVENT_REQUIRED_KEYS` (private) | `= ("event_id","host_id","boot_id","observed_at_ns","monotonic_ns","source","kind")` | `:202` | Note: `attributes` and `evidence` are optional on the wire. |
| `_SEQUENCE_REQUIRED_KEYS` (private) | `= ("sequence_id","host_id","events")` | `:211` | Note: `schema` and `schema_version` are **not** required by Python (they are by JSON Schema). |
| `_require_keys` (private) | `_require_keys(payload: Mapping[str, Any], keys: Sequence[str], label: str) -> None` | `:214` | Raises listing every missing field. |
| `_freeze_evidence` (private) | `_freeze_evidence(value: Iterable[EvidenceRef]) -> tuple[EvidenceRef, ...]` | `:220` | Tuple + per-element type check. |

### 2.4 `contracts/threat_prediction_v1.py` — slot → hub output

| Symbol | Full signature / definition | file:line | Purpose |
|---|---|---|---|
| `THREAT_PREDICTION_V1_ID` | `= "pocketsec.threat_prediction.v1"` | `threat_prediction_v1.py:43` | Frozen schema id. |
| `THREAT_PREDICTION_V1_VERSION` | `= register_schema(THREAT_PREDICTION_V1_ID, "1.0.0")` → `"1.0.0"` | `:44` | Import-time registration. |
| `FORBIDDEN_AUTHORITY_FIELDS` | `frozenset({"action","remediation","execute","command","shell","kill","quarantine","block","authorize","authorization","privilege","sudo"})` | `:48-63` | Field-name **fragments**. A field whose lowercased name *contains* any of these fails `tests/test_authority_boundary.py`. |
| `Verdict` | `class Verdict(StrEnum)` with `BENIGN`, `SUSPICIOUS`, `MALICIOUS`, `UNKNOWN`, `UNIDENTIFIABLE`, `INSUFFICIENT_EVIDENCE` (values identical to names) | `:66-74` | The last three are answers, not failures. |
| `NON_COMMITTAL_VERDICTS` | `frozenset({Verdict.UNKNOWN, Verdict.UNIDENTIFIABLE, Verdict.INSUFFICIENT_EVIDENCE})` | `:79-81` | Verdicts asserting nothing about maliciousness. Must never be scored as positives. |
| `ComputePath` | `class ComputePath(StrEnum)` with `CHEAP_TRANSITION`, `STATISTICAL`, `LEARNED_SOLVER` | `:84-94` | Which tier of the novelty-energy ladder produced the prediction. |
| `EvidenceRelevance` | `@dataclass(frozen=True, slots=True)` | `:97-98` | Weighted pointer back to raw evidence. |
| `EvidenceRelevance.ref` | `ref: EvidenceRef` | `:101` | Must be an `EvidenceRef` instance. |
| `EvidenceRelevance.weight` | `weight: float` | `:102` | `require_finite_unit_interval`. |
| `EvidenceRelevance.__post_init__` | `__post_init__(self) -> None` | `:104` | — |
| `EvidenceRelevance.to_dict` | `to_dict(self) -> dict[str, Any]` | `:109` | `{"ref": {...}, "weight": float}`. No `from_dict` exists. |
| `NextEventExpectation` | `@dataclass(frozen=True, slots=True)` | `:113-114` | Optional predictive output feeding the novelty budget `I(e\|s)`. |
| `NextEventExpectation.surprise_bits` | `surprise_bits: float \| None = None` | `:117` | If not `None`: must be `>= 0.0` and not NaN. **±inf is accepted** (Trap 3). |
| `NextEventExpectation.distribution` | `distribution: Mapping[str, float] \| None = None` | `:118` | If not `None`: every key must pass `require_identifier`; every value must be in `[0, 1]`; the total must not exceed `1.0 + 1e-6`. Not normalised, not stored frozen. |
| `NextEventExpectation.__post_init__` | `__post_init__(self) -> None` | `:120` | — |
| `NextEventExpectation.to_dict` | `to_dict(self) -> dict[str, Any]` | `:135` | `{"surprise_bits": …, "distribution": dict(...) or None}`. |
| `ThreatPredictionV1` | `@dataclass(frozen=True, slots=True)` | `:142-143` | The complete, authority-free output of a model slot. |
| `ThreatPredictionV1.prediction_id` | `prediction_id: str` | `:146` | `require_identifier`. |
| `ThreatPredictionV1.sequence_id` | `sequence_id: str` | `:147` | `require_identifier`. Must match the scored window (enforced by the harness, not here). |
| `ThreatPredictionV1.verdict` | `verdict: Verdict` | `:148` | Coerced with `Verdict(self.verdict)`, so an exact-value `str` works. |
| `ThreatPredictionV1.confidence` | `confidence: float` | `:149` | `[0, 1]`. Confidence **in the stated verdict**, not a detection score. |
| `ThreatPredictionV1.novelty_score` | `novelty_score: float` | `:150` | `[0, 1]`. |
| `ThreatPredictionV1.uncertainty` | `uncertainty: float` | `:151` | `[0, 1]`. |
| `ThreatPredictionV1.model_state_version` | `model_state_version: str` | `:152` | `require_identifier`. Version of the **learned state**, distinct from the code version. |
| `ThreatPredictionV1.compute_path` | `compute_path: ComputePath` | `:153` | Coerced with `ComputePath(self.compute_path)`. |
| `ThreatPredictionV1.compute_budget_units` | `compute_budget_units: float = 0.0` | `:154` | Must be non-NaN and `>= 0`. **+inf is accepted** (Trap 3). |
| `ThreatPredictionV1.state_identifier` | `state_identifier: str \| None = None` | `:155` | If not `None`, `require_identifier`. |
| `ThreatPredictionV1.calibration_id` | `calibration_id: str \| None = None` | `:159` | `None` means the confidence is **uncalibrated**. Never invent one. |
| `ThreatPredictionV1.abstained` | `abstained: bool = False` | `:160` | Must be a real `bool`. |
| `ThreatPredictionV1.evidence_relevance` | `evidence_relevance: tuple[EvidenceRelevance, ...] = ()` | `:161` | Frozen to a tuple with per-element type check. |
| `ThreatPredictionV1.next_event` | `next_event: NextEventExpectation \| None = None` | `:162` | **Not type-checked** (Trap 11). |
| `ThreatPredictionV1.schema_version` | `schema_version: str = THREAT_PREDICTION_V1_VERSION` | `:163` | Not validated. |
| `ThreatPredictionV1.__post_init__` | `__post_init__(self) -> None` | `:165` | ids → unit intervals → enum coercion → evidence freeze → budget → abstention → optional ids. |
| `ThreatPredictionV1._validate_budget` | `_validate_budget(self) -> None` | `:182` | `value != value or value < 0.0` → `ContractError`. |
| `ThreatPredictionV1._validate_abstention` | `_validate_abstention(self) -> None` | `:187` | (a) `abstained` must be `bool`; (b) `abstained=True` requires a non-committal verdict; (c) `INSUFFICIENT_EVIDENCE` requires `abstained=True`. |
| `ThreatPredictionV1.is_committal` | `@property is_committal(self) -> bool` | `:198-199` | `self.verdict not in NON_COMMITTAL_VERDICTS`. Driven by **verdict only**, not by `abstained`. |
| `ThreatPredictionV1.is_calibrated` | `@property is_calibrated(self) -> bool` | `:203-204` | `self.calibration_id is not None`. |
| `ThreatPredictionV1.to_dict` | `to_dict(self) -> dict[str, Any]` | `:207` | 16 keys: `schema, schema_version, prediction_id, sequence_id, verdict, state_identifier, confidence, calibration_id, novelty_score, uncertainty, abstained, evidence_relevance, next_event, compute_path, compute_budget_units, model_state_version`. **[measured]** exactly equal to the JSON Schema property set. |
| `_freeze` (private) | `_freeze(value: Iterable[EvidenceRelevance]) -> tuple[EvidenceRelevance, ...]` | `:228` | Tuple + per-element type check. |

**There is no `ThreatPredictionV1.from_dict`.** **[measured]** `hasattr(ThreatPredictionV1, "from_dict")`
is `False`, and so is it for `EvidenceRelevance` and `NextEventExpectation`. Serialisation is
one-way; a consumer that must read predictions back from disk writes its own parser (Trap 6).

### 2.5 `contracts/model_slot.py` — the frozen hub/model boundary

| Symbol | Full signature / definition | file:line | Purpose |
|---|---|---|---|
| `ACCEPTED_INPUT_SCHEMA` | `= SECURITY_EVENT_SEQUENCE_V1_ID` (`"pocketsec.security_event_sequence.v1"`) | `model_slot.py:36` | What the hub emits; what a slot must declare as `input_schema`. |
| `PRODUCED_OUTPUT_SCHEMA` | `= THREAT_PREDICTION_V1_ID` (`"pocketsec.threat_prediction.v1"`) | `model_slot.py:37` | What the hub consumes; what a slot must declare as `output_schema`. |
| `ModelSlot` | `@runtime_checkable class ModelSlot(Protocol)` | `:40-41` | Everything PocketSec requires of an intelligence implementation. |
| `ModelSlot.slot_name` | `slot_name: str` | `:45` | Stable name for results and provenance, e.g. `"h0-frequency-baseline"`. |
| `ModelSlot.model_state_version` | `model_state_version: str` | `:47` | Version of the learned state, distinct from the code version. |
| `ModelSlot.input_schema` | `input_schema: str` | `:49` | Schema id the slot was built against. |
| `ModelSlot.output_schema` | `output_schema: str` | `:50` | Schema id the slot emits. |
| `ModelSlot.predict` | `predict(self, sequence: SecurityEventSequenceV1) -> ThreatPredictionV1` | `:52` | Score one bounded window. **Must not mutate `sequence`.** |
| `validate_slot` | `validate_slot(slot: ModelSlot) -> None` | `:57` | Raises `ContractError` if `not isinstance(slot, ModelSlot)`, if `slot.input_schema != ACCEPTED_INPUT_SCHEMA`, or if `slot.output_schema != PRODUCED_OUTPUT_SCHEMA`. Returns `None` on success. |
| `NullModelSlot` | `class NullModelSlot` | `:79` | A slot that always abstains — the benchmark lower bound and the proof the hub degrades gracefully. |
| `NullModelSlot.slot_name` | `= "null-abstain"` (class attribute) | `:86` | — |
| `NullModelSlot.model_state_version` | `= "null.1.0.0"` | `:87` | — |
| `NullModelSlot.input_schema` | `= ACCEPTED_INPUT_SCHEMA` | `:88` | — |
| `NullModelSlot.output_schema` | `= PRODUCED_OUTPUT_SCHEMA` | `:89` | — |
| `NullModelSlot.predict` | `predict(self, sequence: SecurityEventSequenceV1) -> ThreatPredictionV1` | `:91` | Returns `prediction_id=f"null-{sequence.sequence_id}"`, `verdict=INSUFFICIENT_EVIDENCE`, `confidence=0.0`, `novelty_score=0.0`, `uncertainty=1.0`, `abstained=True`, `compute_path=CHEAP_TRANSITION`, `compute_budget_units=0.0`. Takes no constructor arguments. |

### 2.6 `hypotheses.py` — H0–H8 as hypotheses, never results

| Symbol | Full signature / definition | file:line | Purpose |
|---|---|---|---|
| `HypothesisStatus` | `class HypothesisStatus(StrEnum)`: `PROPOSED`, `UNDER_TEST`, `SUPPORTED`, `REFUTED` | `hypotheses.py:20-24` | Lifecycle of a hypothesis. |
| `RESULT_CLAIMING_STATUSES` | `frozenset({HypothesisStatus.SUPPORTED, HypothesisStatus.REFUTED})` | `:28` | Statuses that assert a measured outcome and therefore require evidence. Not in `__all__`, but importable. |
| `Hypothesis` | `@dataclass(frozen=True, slots=True)` | `:31-32` | One competing hypothesis. |
| `Hypothesis.id` | `id: str` | `:33` | e.g. `"H3"`. No validation. |
| `Hypothesis.title` | `title: str` | `:34` | — |
| `Hypothesis.reason_to_test` | `reason_to_test: str` | `:35` | Why it is worth an experiment. |
| `Hypothesis.status` | `status: HypothesisStatus = HypothesisStatus.PROPOSED` | `:36` | Every entry starts `PROPOSED`. |
| `Hypothesis.evidence` | `evidence: tuple[str, ...] = ()` | `:38` | Experiment ids bearing on it. Empty at Stage 0. |
| `Hypothesis.to_dict` | `to_dict(self) -> dict[str, Any]` | `:40` | `{id, title, reason_to_test, status (value), evidence (list)}`. No `from_dict`. |
| `HYPOTHESES` | `HYPOTHESES = MappingProxyType({item.id: item for item in _HYPOTHESES})` — `Mapping[str, Hypothesis]` | `:88` | **[measured]** 9 entries, `H0`…`H8`, read-only proxy. |
| `unsupported_status_claims` | `unsupported_status_claims() -> list[str]` | `:91` | One message per hypothesis whose status is in `RESULT_CLAIMING_STATUSES` while `evidence` is empty. **[measured]** currently `[]`. Consumed by gate check `G0.7` (`pocketsec/stage0/gate.py:217`). |

The nine hypotheses, verbatim from `_HYPOTHESES` (`hypotheses.py:50-86`): H0 "Conventional compact
classifier / GRU"; H1 "State-space / recurrent baseline"; H2 "Learned behavioural automaton"; H3
"Novelty-budgeted conditional compute"; H4 "Neural-to-symbolic JIT compilation"; H5 "Adaptive state
growth + minimisation"; H6 "Hierarchical reversible forgetting"; H7 "Relational latent state"; H8
"Combined NERA architecture". All at `status=PROPOSED`, all with `evidence=()`.

### 2.7 `prior_art.py` — the literature / patent ledger

| Symbol | Full signature / definition | file:line | Purpose |
|---|---|---|---|
| `LEDGER_PATH` | `Path(__file__).resolve().parents[2] / "docs" / "prior-art" / "ledger.json"` | `prior_art.py:22` | Default ledger location. Resolves to `<repo>/docs/prior-art/ledger.json`. |
| `ReviewStatus` | `class ReviewStatus(StrEnum)`: `NOT_REVIEWED`, `IN_PROGRESS`, `REVIEWED` | `:25-28` | Review state for both literature and patent review. |
| `PriorArtEntry` | `@dataclass(frozen=True, slots=True)` | `:31-32` | One hypothesis's prior-art record. |
| `PriorArtEntry.hypothesis_id` | `hypothesis_id: str` | `:33` | Must be a key of `HYPOTHESES` or `inconsistencies()` flags it. |
| `PriorArtEntry.claim` | `claim: str` | `:34` | The claim whose novelty is at issue. |
| `PriorArtEntry.literature_status` | `literature_status: ReviewStatus` | `:35` | Required (no default). |
| `PriorArtEntry.patent_status` | `patent_status: ReviewStatus` | `:36` | Required (no default). |
| `PriorArtEntry.related_work` | `related_work: tuple[str, ...]` | `:37` | Required (no default). Citations. |
| `PriorArtEntry.notes` | `notes: str = ""` | `:38` | — |
| `PriorArtEntry.novelty_claim_permitted` | `@property novelty_claim_permitted(self) -> bool` | `:40-41` | `literature_status is REVIEWED and patent_status is REVIEWED and bool(related_work)`. **[measured]** `False` for every current entry. |
| `PriorArtEntry.to_dict` | `to_dict(self) -> dict[str, Any]` | `:49` | Enum fields serialised as `.value`; `related_work` as a list. |
| `PriorArtEntry.from_dict` | `@classmethod from_dict(cls, payload: Mapping[str, Any]) -> PriorArtEntry` | `:59-60` | `hypothesis_id`/`claim` via `str()`; statuses via `ReviewStatus(...)` (raises `ValueError` on an unknown value); `related_work` defaults `()`; `notes` defaults `""`. A missing `hypothesis_id`, `claim`, `literature_status` or `patent_status` raises `KeyError`. |
| `PriorArtLedger` | `@dataclass(frozen=True, slots=True)` | `:71-72` | The whole ledger. |
| `PriorArtLedger.entries` | `entries: Mapping[str, PriorArtEntry]` | `:73` | Keyed by `hypothesis_id`. **[measured]** `load()` puts a plain mutable `dict` here (Trap 14). |
| `PriorArtLedger.load` | `@classmethod load(cls, path: Path \| None = None) -> PriorArtLedger` | `:75-76` | Reads UTF-8 JSON from `path or LEDGER_PATH`. Raises `FileNotFoundError` if absent; `json.JSONDecodeError` on bad JSON; `KeyError` if an entry lacks `hypothesis_id`. Reads `payload.get("entries", ())`. |
| `PriorArtLedger.missing_hypotheses` | `missing_hypotheses(self) -> list[str]` | `:87` | `sorted(set(HYPOTHESES) - set(self.entries))`. **[measured]** currently `[]`. |
| `PriorArtLedger.inconsistencies` | `inconsistencies(self) -> list[str]` | `:91` | Missing hypotheses, entries for unknown hypotheses, and `literature_status == REVIEWED` with empty `related_work`. **[measured]** currently `[]`. Consumed by gate check `G0.8` (`gate.py:234`). |

**[measured]** `PriorArtLedger.load()` against the committed `docs/prior-art/ledger.json` yields 9
entries, `missing_hypotheses() == []`, `inconsistencies() == []`. The ledger file's own top-level
keys are `ledger_version`, `policy`, `status_values`, `entries`; only `entries` is read by the code.

### 2.8 The JSON Schemas

| Property | `contracts/security_event_sequence_v1.schema.json` | `contracts/threat_prediction_v1.schema.json` |
|---|---|---|
| `$id` | `pocketsec.security_event_sequence.v1` (line 3) | `pocketsec.threat_prediction.v1` (line 3) |
| `version` | `1.0.0` (line 4) | `1.0.0` (line 4) |
| `additionalProperties` | `false` (line 9) | `false` (line 21) — asserted by `tests/test_authority_boundary.py::test_prediction_schema_forbids_additional_properties` |
| `required` | `["schema","schema_version","sequence_id","host_id","events"]` | `["schema","schema_version","prediction_id","sequence_id","verdict","confidence","novelty_score","uncertainty","abstained","compute_path","model_state_version"]` |
| `$defs.identifier` | `^[A-Za-z0-9][A-Za-z0-9._:\-]{0,127}$` | same |
| `$defs.evidence_ref` | closed object `{store, locator (minLength 1), digest ^sha256:[0-9a-f]{64}$}` | same |
| Bounds | `window_capacity` 1–4096; `events` `minItems: 1`, `maxItems: 4096`; `event.attributes` `additionalProperties: {type: string}`, `event` object closed | `confidence`/`novelty_score`/`uncertainty` 0–1; `evidence_relevance[].weight` 0–1; `next_event.surprise_bits` `minimum: 0` or null; `compute_budget_units` `minimum: 0` |

Gate check `G0.3` (`pocketsec/stage0/gate.py:126-160`) compares, for both schemas, the JSON `$id`
against the Python id constant, the JSON `version` against the Python version constant, and
`SCHEMA_REGISTRY[schema_id]` against that version. Any drift fails the Stage 0 gate.

---

## 3. How to construct and drive the subsystem

The snippet below was **executed in this session and ran clean** on Python 3.14.7: `validate_slot`
accepted the slot, `predict` returned `SUSPICIOUS`, `is_committal` was `True`, `is_calibrated` was
`False`, and `SecurityEventSequenceV1.from_dict(sequence.to_dict()) == sequence` was `True`.

```python
from pocketsec.stage0.contracts.common import EvidenceRef, digest_of_bytes
from pocketsec.stage0.contracts.model_slot import (
    ACCEPTED_INPUT_SCHEMA,
    PRODUCED_OUTPUT_SCHEMA,
    validate_slot,
)
from pocketsec.stage0.contracts.security_event_v1 import (
    SecurityEventSequenceV1,
    SecurityEventV1,
)
from pocketsec.stage0.contracts.threat_prediction_v1 import (
    ComputePath,
    EvidenceRelevance,
    NextEventExpectation,
    ThreatPredictionV1,
    Verdict,
)

# 1. Evidence is REFERENCED, never inlined. The digest binds the reference to bytes.
raw = b"execve /usr/bin/curl"
ref = EvidenceRef(
    store="journald",                       # identifier grammar
    locator="cursor:s=abc;i=42",            # any non-empty string
    digest=digest_of_bytes(raw),            # the only sanctioned digest producer
)

# 2. Events: ordering within a boot_id is part of the contract.
events = (
    SecurityEventV1(
        event_id="ev-000",
        host_id="host-a",
        boot_id="boot-1",
        observed_at_ns=1_726_000_000_000_000_000,
        monotonic_ns=1_000,
        source="ebpf.execve",
        kind="process.exec",                # SOURCE-level label, never a threat class
        attributes={"comm": "curl", "uid": "0"},   # str -> str only; copied and frozen
        evidence=(ref,),
    ),
    SecurityEventV1(
        event_id="ev-001",
        host_id="host-a",
        boot_id="boot-1",
        observed_at_ns=1_726_000_000_000_500_000,
        monotonic_ns=2_000,                 # must not go backwards within boot-1
        source="ebpf.connect",
        kind="net.connect",
    ),
)

# 3. The window is bounded, and truncation is declared, not inferred.
sequence = SecurityEventSequenceV1(
    sequence_id="seq-0001",
    host_id="host-a",                       # every event.host_id must equal this
    events=events,
    window_capacity=64,                     # 1..MAX_SEQUENCE_CAPACITY (4096)
    truncated=True,                         # YOU must set this; it is never derived
)

# 4. A model slot is any object with these four attributes and this one method.
class MySlot:
    slot_name = "h9-example"
    model_state_version = "h9.1.0.0-fit0"   # identifier grammar; learned-state version
    input_schema = ACCEPTED_INPUT_SCHEMA
    output_schema = PRODUCED_OUTPUT_SCHEMA

    def predict(self, sequence: SecurityEventSequenceV1) -> ThreatPredictionV1:
        refs = sequence.evidence                     # property: flattened, in order
        weight = 1.0 / len(refs) if refs else 0.0
        return ThreatPredictionV1(
            prediction_id=f"{self.slot_name}-{sequence.sequence_id}",
            sequence_id=sequence.sequence_id,        # MUST echo the scored window
            verdict=Verdict.SUSPICIOUS,
            confidence=0.72,                         # confidence IN THE VERDICT
            novelty_score=0.31,
            uncertainty=0.28,
            model_state_version=self.model_state_version,
            compute_path=ComputePath.STATISTICAL,
            compute_budget_units=float(len(sequence.events)),
            calibration_id=None,                     # None == honestly uncalibrated
            abstained=False,
            evidence_relevance=tuple(
                EvidenceRelevance(ref=r, weight=weight) for r in refs
            ),
            next_event=NextEventExpectation(surprise_bits=3.5),
        )

slot = MySlot()
validate_slot(slot)                  # raises ContractError on any boundary mismatch
prediction = slot.predict(sequence)  # must not mutate `sequence`

assert prediction.is_committal is True
assert prediction.is_calibrated is False
payload = prediction.to_dict()       # 16 keys, exactly the closed JSON Schema's set
```

To abstain instead, return `Verdict.INSUFFICIENT_EVIDENCE` with `abstained=True` (and
`confidence=0.0`, `uncertainty=1.0` by convention — see `NullModelSlot.predict`,
`model_slot.py:91-103`). Abstaining is an answer, not a failure path.

To run a slot through Stage 0's measurement rules rather than calling it directly, hand it to
`pocketsec.stage0.benchmark.harness.run_benchmark`, which calls `validate_slot` itself
(`harness.py:29`). Working end-to-end examples of slots that satisfy this boundary:
`pocketsec/stage0/baselines/frequency_baseline.py:62` (`FrequencyBaselineSlot`) and
`pocketsec/stage1/slot.py:49` (`SSIRSlotBase` and its two subclasses).

---

## 4. Invariants enforced in code

| # | Invariant | Enforced at | Test |
|---|---|---|---|
| 1 | A model output carries **no response authority** — no action/command/shell/privilege field exists. | `FORBIDDEN_AUTHORITY_FIELDS` `threat_prediction_v1.py:48`; closed JSON Schema `threat_prediction_v1.schema.json:21` | `tests/test_authority_boundary.py::test_prediction_dataclass_has_no_authority_bearing_field`, `::test_prediction_schema_has_no_authority_bearing_property`, `::test_prediction_schema_forbids_additional_properties`, `::test_confidence_alone_never_marks_a_prediction_as_actionable` |
| 2 | Serialised output cannot contain a key the closed schema does not know. | `ThreatPredictionV1.to_dict` `threat_prediction_v1.py:207` | `::test_serialised_prediction_exposes_only_known_keys` |
| 3 | Abstention cannot coexist with a committal verdict. | `_validate_abstention` `threat_prediction_v1.py:190-194` | `tests/test_contracts.py::test_abstention_cannot_coexist_with_a_committal_verdict` |
| 4 | `INSUFFICIENT_EVIDENCE` requires `abstained=True`. | `_validate_abstention` `threat_prediction_v1.py:195-196` | `tests/test_contracts.py::test_insufficient_evidence_requires_abstention` |
| 5 | `UNKNOWN` / `UNIDENTIFIABLE` / `INSUFFICIENT_EVIDENCE` are valid answers. | `Verdict` `:66-74`, `NON_COMMITTAL_VERDICTS` `:79`, `is_committal` `:198` | `tests/test_contracts.py::test_non_committal_verdicts_are_valid_answers` |
| 6 | Novelty is not maliciousness: a non-committal prediction contributes a detection score of 0.0. | `pocketsec/stage0/benchmark/harness.py:207-224` (`_detection_score`) | — (documented in harness docstring `harness.py:208-219`) |
| 7 | An uncalibrated confidence reports itself uncalibrated; calibration is never faked. | `calibration_id` `:159`, `is_calibrated` `:203-205` | `tests/test_contracts.py::test_uncalibrated_confidence_is_reported_as_uncalibrated` |
| 8 | Confidence/novelty/uncertainty are finite and inside `[0, 1]`. | `require_finite_unit_interval` `common.py:84`, called `threat_prediction_v1.py:169-171` | `tests/test_contracts.py::test_prediction_rejects_out_of_range_scores` (parametrised over `-0.01`, `1.01`, NaN, inf) |
| 9 | `EvidenceRelevance.weight` is a unit interval. | `threat_prediction_v1.py:107` | `tests/test_contracts.py::test_evidence_relevance_weight_must_be_a_unit_interval` |
| 10 | A next-event distribution cannot exceed total probability 1.0. | `threat_prediction_v1.py:132-133` | `tests/test_contracts.py::test_next_event_distribution_cannot_exceed_total_probability_one` |
| 11 | Surprise is non-negative. | `threat_prediction_v1.py:123-124` | `tests/test_contracts.py::test_negative_surprise_is_rejected` |
| 12 | Evidence is referenced by `sha256:` digest, never inlined. | `EvidenceRef.__post_init__` `common.py:142-145` | `tests/test_contracts.py::test_evidence_ref_requires_a_content_digest`, `::test_evidence_ref_accepts_a_real_digest` |
| 13 | A contract object never aliases mutable caller state. | `freeze_mapping` `common.py:95` (copy + `MappingProxyType`), applied `security_event_v1.py:70-72` | `tests/test_contracts.py::test_event_attributes_are_copied_not_aliased`, `::test_event_attributes_are_not_mutable_through_the_contract`, `::test_event_is_frozen` |
| 14 | A window is non-empty and bounded at `MAX_SEQUENCE_CAPACITY` (4096), and cannot exceed its own declared capacity. | `_validate_capacity` `security_event_v1.py:134-145`, empty check `:127-128` | `tests/test_contracts.py::test_sequence_rejects_empty_window`, `::test_sequence_enforces_its_declared_window_capacity`, `::test_sequence_capacity_cannot_exceed_the_global_bound` |
| 15 | Truncation is explicit, so a bounded buffer cannot silently become a false negative. | `truncated` field `security_event_v1.py:120`, bool check `:129-130`, carried in `to_dict` `:180` | `tests/test_contracts.py::test_truncation_is_explicit_so_a_bounded_buffer_is_not_a_silent_false_negative` |
| 16 | A window is host-local: every event's `host_id` matches the sequence. | `_validate_events` `security_event_v1.py:152-156` | `tests/test_contracts.py::test_sequence_rejects_mixed_hosts` |
| 17 | Monotonic ordering within a boot is part of the contract. | `_validate_events` `security_event_v1.py:157-165` | `tests/test_contracts.py::test_sequence_rejects_backwards_monotonic_time_within_a_boot` |
| 18 | A sequence round-trips through `to_dict`/`from_dict`, and a foreign `schema` is refused. | `to_dict` `:173`, `from_dict` `:184-199` | `tests/test_contracts.py::test_sequence_round_trips_through_dict`, `::test_sequence_from_dict_rejects_a_foreign_schema` |
| 19 | Evidence is exposed in observation order. | `evidence` property `security_event_v1.py:168-171` | `tests/test_contracts.py::test_sequence_exposes_evidence_in_observation_order` |
| 20 | A breaking schema change takes a **new schema id**, never an in-place version bump. | `register_schema` `common.py:59-64` | `tests/test_contracts.py::test_reregistering_a_schema_at_a_new_version_is_refused` |
| 21 | A slot built against a foreign schema is refused at wiring time. | `validate_slot` `model_slot.py:57-76` | `tests/test_authority_boundary.py::test_a_slot_built_against_a_foreign_schema_is_refused` |
| 22 | The hub degrades to "no learned intelligence" and still emits well-formed, honestly-abstaining output. | `NullModelSlot` `model_slot.py:79-103` | `tests/test_authority_boundary.py::test_null_slot_satisfies_the_boundary_and_always_abstains` |
| 23 | `predict` does not mutate the input window. | Frozen dataclasses + frozen `attributes` | `tests/test_authority_boundary.py::test_predicting_does_not_mutate_the_input_window` |
| 24 | JSON Schema and Python contracts do not drift (`$id`, `version`, registry). | `gate.py:126-160` (`G0.3`) | `tests/test_harness_and_gate.py` (gate), `tests/test_authority_boundary.py::test_schema_path_exists` |
| 25 | A hypothesis cannot claim a measured result without a registered experiment id. | `unsupported_status_claims` `hypotheses.py:91-97`; gate `G0.7` `gate.py:215-225` | `tests/test_harness_and_gate.py:234` (`assert unsupported_status_claims() == []`) |
| 26 | Every hypothesis has a prior-art entry, and `REVIEWED` literature status requires a citation. | `PriorArtLedger.inconsistencies` `prior_art.py:91-101`; gate `G0.8` `gate.py:228-239` | `tests/test_harness_and_gate.py:247` (`assert not any(entry.novelty_claim_permitted ...)`) |
| 27 | A prediction cannot be scored against the wrong window. | `_require_matching_sequence` `pocketsec/stage0/benchmark/harness.py:226-232` (raises `ValueError`, not `ContractError`) | — |

**[measured]** `PYTHONHASHSEED=0 python3 -m pytest tests/test_contracts.py tests/test_authority_boundary.py`
→ **50 passed in 0.05s** (this session, Python 3.14.7).

---

## 5. Extension points

### Sanctioned

1. **`SecurityEventV1.attributes`** (`security_event_v1.py:59`) is *the* ontology extension point.
   Stage 1 formalises the security ontology by fixing key names and value encodings inside this
   opaque `str → str` map. The envelope fields, bounded-window semantics and measurement rules are
   frozen against it. The JSON Schema says the same thing at
   `security_event_sequence_v1.schema.json:76-80`.
2. **Implement `ModelSlot`** (`model_slot.py:41`) — four attributes and one method — for any new
   model family. Set `input_schema = ACCEPTED_INPUT_SCHEMA` and
   `output_schema = PRODUCED_OUTPUT_SCHEMA` and call `validate_slot` before wiring. Two independent
   precedents: `pocketsec/stage0/baselines/frequency_baseline.py:62` and
   `pocketsec/stage1/slot.py:49`.
3. **`ThreatPredictionV1.state_identifier`** (`:155`) is the sanctioned place for a behaviour-machine
   / threat-state id, when a slot has one.
4. **`ThreatPredictionV1.next_event`** (`:162`) is the sanctioned place for predictive output feeding
   the novelty budget `I(e|s)`.
5. **`ThreatPredictionV1.calibration_id`** (`:159`) is where a later stage records a *measured*
   calibration map. `None` is the honest default.
6. **`ComputePath`** (`:84`) is how a stage makes "resolved without neural inference" a measured
   number: report the tier that actually produced the prediction.
7. **`register_schema`** (`common.py:49`) is the sanctioned way for a later stage to add its **own,
   new** schema id to the registry. Precedent: `pocketsec/stage2/core_ids.py` imports and calls it.
8. **`PriorArtEntry` / the ledger JSON** is where a stage records its literature and patent review
   before making any novelty claim; `Hypothesis.evidence` is where experiment ids attach.
9. **`EvidenceRef.store` / `locator`** are intentionally free-form enough (subject to the identifier
   grammar on `store`) for a later stage to introduce new evidence stores without a schema change.

### Explicitly not extension points

1. **Do not add a field to `ThreatPredictionV1`, or a property to its JSON Schema, that conveys
   response authority** — no action, remediation, command, shell, kill, quarantine, block,
   authorize, privilege or sudo (name fragments listed at `threat_prediction_v1.py:48-63`). Response
   authority is Stage 5's, gated by SENTINEL. Both the dataclass and the closed schema are tested.
2. **Do not bump `version` on an existing schema `$id` to make a breaking change.** `register_schema`
   raises (`common.py:59-64`) and `G0.3` fails. A breaking change takes `...v2`.
3. **Do not widen `MAX_SEQUENCE_CAPACITY`** (`security_event_v1.py:40`) to fit a model's context
   window; the 4096 bound is the bounded-state invariant, and it is duplicated in both JSON Schemas.
4. **Do not encode a verdict, threat class, score or label in `SecurityEventV1.kind`, `source`, or
   any input-contract field.** Classification belongs in `ThreatPredictionV1`
   (`security_event_v1.py:46-49`, schema line 74).
5. **Do not add a new verdict to `Verdict` or a new tier to `ComputePath`** without an ADR: both
   enums are mirrored as closed `enum`s in the JSON Schema (lines 27-37 and 92-95), so an addition
   silently splits the two representations and `G0.3` will not catch it (it only compares `$id` and
   `version`).
6. **Do not weaken a validator to make a caller or a test pass** (`ContractError` docstring,
   `common.py:32-37`; repo rule 4 in `README.md`).
7. **Do not mutate `SCHEMA_REGISTRY`** — it is a `MappingProxyType` view; go through
   `register_schema`.
8. **Do not treat `pocketsec/stage0/contracts/` as a place to put stage-specific logic.** The Stage 1
   precedent keeps its own contracts in `pocketsec/stage1/...` and only *imports* Stage 0's.

---

## 6. Traps — how a later-stage implementer silently gets this wrong

Each trap below was confirmed by running code in this session unless marked otherwise.

1. **Reading `confidence` as a detection score inverts your ranking.** `confidence` is confidence
   *in the stated verdict*. A `BENIGN` verdict with `confidence=0.99` is a very *weak* detection.
   The correct mapping is verdict-aware and already exists: `_detection_score`
   (`harness.py:207-224`) returns `0.0` for non-committal, `1.0 - confidence` for `BENIGN`, and
   `confidence` otherwise. Rolling your own naive mapping corrupts PR-AUC and every FP figure
   without raising anything.

2. **`UNKNOWN` / `UNIDENTIFIABLE` with `abstained=False` is accepted.** **[measured]** A prediction
   with `verdict=UNKNOWN, confidence=0.99, abstained=False` constructs fine. Only
   `INSUFFICIENT_EVIDENCE` forces `abstained=True` (`threat_prediction_v1.py:195-196`). Consequence:
   `is_committal` is `False` (so the harness scores it 0.0) while the harness's abstention counter
   (`harness.py:181`, `sum(... if prediction.abstained)`) does **not** count it. If you measure
   abstention rate from the `abstained` flag, these predictions vanish from the statistics. Set
   `abstained=True` whenever you return a non-committal verdict.

3. **`+inf` passes `compute_budget_units` and `surprise_bits`.** **[measured]** Both validators test
   only `value != value` (NaN) and `value < 0`, at `threat_prediction_v1.py:184` and `:124`. An
   overflowing `-log2(p)` with `p == 0.0` yields `inf`, constructs successfully, and then poisons
   `mean_compute_budget_units` / `mean_surprise_bits` in `NoveltyEconomics` to `inf`. Clamp before
   you construct. (Note the JSON Schema's `minimum: 0` also does not exclude infinity, and JSON has
   no infinity literal, so a serialised `Infinity` is not even valid JSON.)

4. **`truncated` is never derived for you.** **[measured]** A window holding exactly
   `window_capacity` events still reports `truncated=False` unless you pass `truncated=True`. The
   whole point of the field (`security_event_v1.py:108-114`) is that a slot can tell "nothing
   happened before" from "we stopped looking". A hub that forgets to set it turns a bounded buffer
   into a silent false negative — the exact failure the field exists to prevent.

5. **Ordering is only checked between *adjacent* events sharing a `boot_id`.** **[measured]** The
   window `[(b1, mono=100), (b2, mono=5), (b1, mono=50)]` is **accepted**: the check at
   `security_event_v1.py:157-165` compares each event only with its immediate predecessor, and the
   predecessor of the third event has a different `boot_id`. Equal `monotonic_ns` is also accepted,
   and **`observed_at_ns` ordering is never checked at all**. If your model depends on global
   temporal order, sort and verify yourself; do not infer order from "the contract validated".

6. **There is no `ThreatPredictionV1.from_dict`** (nor for `EvidenceRelevance` or
   `NextEventExpectation`). **[measured]** Serialisation is one-way. If a later stage persists
   predictions and reads them back, it writes its own parser — and that parser is then *outside* the
   contract's validation, so it can reconstruct objects the dataclass would have rejected. Parse by
   constructing the real dataclasses, not by handing raw dicts onward.

7. **`from_dict` coerces silently rather than rejecting.** **[measured]**
   `SecurityEventV1.from_dict` with `observed_at_ns=3.99` yields `observed_at_ns == 3` — `int()`
   truncates, no error. Likewise `str()` is applied to `event_id`, `host_id`, `boot_id`, `source`,
   `kind`, and to all three `EvidenceRef` fields, so `digest=None` becomes the string `"None"`
   before the digest regex rejects it (a confusing error) and a numeric `kind` becomes `"5"`
   (accepted). The validators run on the *coerced* value, so type confusion upstream becomes silent
   data change, not a failure.

8. **`schema_version` is not validated anywhere in Python.** **[measured]** Both the
   `SecurityEventSequenceV1` constructor and `from_dict` accept `schema_version="not-semver"` and
   `"99.99.99"`. Only the `schema` *id* is checked on `from_dict` (`:187-191`). Do not use
   `schema_version` from an untrusted payload as a compatibility signal.

9. **Python's required keys are a subset of the JSON Schema's.** **[measured]**
   `SecurityEventSequenceV1.from_dict({"sequence_id", "host_id", "events"})` succeeds and fills
   `schema_version="1.0.0"`, but that same payload is **invalid** against
   `security_event_sequence_v1.schema.json`, whose `required` includes `schema` and
   `schema_version`. A cross-language producer that validates only with the Python contract emits
   payloads a JSON-Schema consumer rejects. Always serialise via `to_dict()`, which emits the full
   key set.

10. **`validate_slot` checks far less than it looks like it does.** **[measured]** It accepted a
    class with `def predict(self, a, b, c)` (no signature check) and accepted the **class object
    itself** rather than an instance. `runtime_checkable` Protocol `isinstance` only tests for the
    presence of the four attributes and `predict`; it checks no types and no return value. A slot
    that returns a `dict` instead of a `ThreatPredictionV1` passes `validate_slot` and fails later,
    deep inside the harness. (It does correctly reject a class missing `slot_name` — **[measured]**.)

11. **`ThreatPredictionV1.next_event` is not type-checked.** Unlike `evidence_relevance` (frozen
    with a per-element check at `:174`/`:228`) and `EvidenceRelevance.ref` (checked at `:105-106`),
    `next_event` is stored as given. Passing a bare dict constructs fine and then raises
    `AttributeError` inside `to_dict()` (`:221`) much later.

12. **`SecurityEventV1` and `SecurityEventSequenceV1` are unhashable.** **[measured]** `hash(event)`
    raises `TypeError: unhashable type: 'dict'` because `attributes` is a `mappingproxy` over a
    dict; the sequence inherits this through its `events` tuple. They compare with `==` fine, but
    you cannot put them in a `set`, use them as dict keys, or `functools.lru_cache` a function of
    them. `EvidenceRef` *is* hashable. Key caches by `event_id` / `sequence_id` instead.

13. **`to_dict()` hands out a mutable copy of `attributes`.** **[measured]** Mutating
    `event.to_dict()["attributes"]` does not affect the event (good), but it means the dict you pass
    on is not frozen — do not treat a `to_dict()` result as an immutable record.

14. **`PriorArtLedger.entries` is mutable despite the frozen dataclass.** **[measured]**
    `PriorArtLedger.load()` assigns a plain `dict` (`prior_art.py:81-85`), and
    `ledger.entries["H9"] = "injected"` succeeds. The type annotation says `Mapping`, which is a
    read-only *interface*, not a guarantee. Also: entries are keyed by `hypothesis_id`, so **two
    ledger records for the same hypothesis silently collapse** to the last one, and
    `inconsistencies()` will not notice.

15. **`inconsistencies()` does not check `patent_status`.** Read `prior_art.py:97-100`: only
    `literature_status is REVIEWED and not related_work` is flagged. An entry with
    `patent_status=REVIEWED` and `related_work=[]` passes `inconsistencies()` (and therefore gate
    check `G0.8`) while `novelty_claim_permitted` correctly stays `False`. Gate G0.8 passing is
    **not** evidence that a novelty claim is permitted — call `novelty_claim_permitted` for that.
    Nothing in `pocketsec/` calls it; only `tests/test_harness_and_gate.py:247` does.

16. **Advancing a `Hypothesis.status` is not blocked — only unevidenced advancement is.**
    `HYPOTHESES` is a read-only proxy of frozen dataclasses, so a stage cannot edit it in place; it
    must edit `hypotheses.py`. `unsupported_status_claims()` (`:91-97`) fires only for
    `SUPPORTED`/`REFUTED` with empty `evidence`, and it never validates that the listed experiment
    ids **exist** in the experiment registry. A fabricated id satisfies the gate. Register the
    experiment first (`pocketsec/stage0/experiments/`).

17. **`register_schema` runs at import time, so a collision is an `ImportError`-shaped failure.**
    **[measured]** `register_schema("pocketsec.security_event_sequence.v1", "1.1.0")` raises
    `ContractError`. Since both contract modules register at module level
    (`security_event_v1.py:35`, `threat_prediction_v1.py:44`), a later stage that re-registers an
    existing id at a different version fails during `import`, with a traceback pointing at the
    importing module rather than at the offending constant.

18. **The identifier grammar is stricter than it reads.** **[measured]** Rejected: `_leading`,
    `.x`, `a/b`, `a b`, `a+b`, and any value longer than 128 characters. Allowed after the first
    character: alphanumerics, `.`, `_`, `:`, `-`. Consequences for real data: a
    `model_state_version` containing a path, a space or a `+` (e.g. `"1.0.0+dirty"`) is rejected; a
    `kind` derived verbatim from a syscall path is rejected. `EvidenceRef.locator` is **exempt** —
    it accepts any non-empty string, which is why file paths belong there and not in `store`.

19. **Digest case matters.** **[measured]** `sha256:` + uppercase hex is rejected
    (`_DIGEST_RE` is `[0-9a-f]`). Always produce digests with `digest_of_bytes`
    (`common.py:116`), which lowercases by construction.

20. **`distribution` is only bounded above, never normalised.** **[measured]**
    `NextEventExpectation(distribution={"process.exec": 0.1})` is accepted with a total of 0.1.
    The check at `:132-133` rejects only totals above `1.0 + 1e-6`. Do not assume a returned
    distribution sums to 1; also note its keys must satisfy the identifier grammar, so an arbitrary
    event descriptor cannot be used as a key.

21. **Duplicate events are accepted.** **[measured]** A sequence built from the same event object
    three times validates: there is no `event_id` uniqueness check in `_validate_events`
    (`:147-166`). Deduplicate at the hub if your model's counts assume distinct events.
    Correspondingly, `SecurityEventSequenceV1.evidence` can yield the same `EvidenceRef` more than
    once.

22. **The contracts package does not re-export the constants you need most.** **[measured]**
    `ACCEPTED_INPUT_SCHEMA`, `PRODUCED_OUTPUT_SCHEMA`, `FORBIDDEN_AUTHORITY_FIELDS`,
    `NON_COMMITTAL_VERDICTS`, `MAX_SEQUENCE_CAPACITY` and every helper in `common.py` other than
    `ContractError`, `EvidenceRef` and `SCHEMA_REGISTRY` are absent from
    `pocketsec.stage0.contracts`. Import them from their defining module, and do not conclude from an
    `AttributeError` that they do not exist.

23. **`ContractError` is a `ValueError`.** A broad `except ValueError` swallows contract violations
    and turns "this window is malformed" into "skip this window", which is exactly how a contract
    failure becomes a silent false negative. Catch `ContractError` explicitly.

24. **Adding a verdict or compute path requires editing two files.** The enums in
    `threat_prediction_v1.py:66`/`:84` and the closed `enum` lists in
    `threat_prediction_v1.schema.json:28-35`/`:93` are independent. `G0.3` compares only `$id` and
    `version`, so a Python-only addition passes the gate and then fails JSON-Schema validation
    downstream.

25. **`SecurityEventSequenceV1.evidence` is a property, not a field.** It is recomputed on every
    access (`:168-171`) and is absent from `to_dict()`. Do not look for a top-level `evidence` key on
    the wire, and do not call it in a hot loop expecting a cached tuple.
