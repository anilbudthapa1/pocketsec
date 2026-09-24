# Stage 1 interface reference — SSIR, telemetry, semantic compiler, entity registry

> **Scope.** `pocketsec/stage1/ssir/*.py`, `pocketsec/stage1/telemetry/*.py`,
> `pocketsec/stage1/compiler/*.py`. Every signature and line number below was read
> out of the `.py` files in this session. Every number in the "Measured" notes was
> produced by running code in this session; anything not measured is marked
> `UNMEASURED`. Documentation elsewhere in the repo is not treated as evidence.
>
> **Verification performed this session:** `PYTHONHASHSEED=0 PYTHONPATH=. python -m pytest
> tests/test_stage1_semantics.py tests/test_stage1_bounded.py tests/test_stage1_pipeline.py`
> → **103 passed in 49.26s**. The snippet in section 3 and every trap in section 6
> was executed, and the outputs quoted are real program output.

---

## 1. Purpose

This subsystem is the **compatibility boundary** between raw Linux telemetry and
everything Stage 2+ learns from. Source-shaped records (`RawEventV1`) land
losslessly, are fused into one logical operation per action (`EventAssembler` →
`EvidenceEvent`), and are then compiled (`SemanticCompiler`) into the SSIR
transition `τ = (A, R, O, ΔS, U, N, P, T, E)` (`SSIRTransitionV1`), whose actor
and object are `Entity` values carrying probabilistic `SemanticBelief`. The
load-bearing design rule is that **capability semantics are earned by observed
behaviour, never granted by a name** (ADR-0006): a process becomes
`NETWORK_CLIENT` because it called `connect`, while object properties such as
`CREDENTIAL` come from host filesystem metadata. `display_name` is retained for
investigation and deliberately excluded from the model-facing binary encoding
(`SSIRCodec`). Two different sensors describing the same action must produce
equal `SSIRTransitionV1.semantic_key()` — that is Stage 1 acceptance criterion 1,
and it is the property later stages depend on when they assume their input is
sensor-independent.

**Pipeline shape (as wired in `pocketsec/stage1/pipeline.py:99`):**

```
RawEventV1 ──▶ EventAssembler.feed ──▶ EvidenceEvent ──▶ SemanticCompiler.compile ──▶ SSIRTransitionV1
                    (bounded)            (fused, lossless)      (stateful)               │
                                                                                          ▼
                                                                                   SSIRCodec.encode
```

---

## 2. Public symbols

### 2.0 Package `__init__.py` files are EMPTY

`pocketsec/stage1/ssir/__init__.py`, `pocketsec/stage1/telemetry/__init__.py` and
`pocketsec/stage1/compiler/__init__.py` are all **0 bytes**. There are no
package-level re-exports. Import from the leaf module or the import fails.

---

### 2.1 `pocketsec/stage1/ssir/entities.py`

`__all__ = ["Entity", "EntityKind", "SemanticBelief", "SemanticProperty", "UNKNOWN_ENTITY_KIND"]`
(entities.py:25). Note `BEHAVIOURAL_PROPERTIES`, `NEUTRAL_BELIEF` and
`ASSERT_THRESHOLD` are **public names that are not in `__all__`**; they are
importable and are part of the contract below.

| Symbol | Full signature / definition | file:line |
|---|---|---|
| `EntityKind` | `class EntityKind(IntEnum)` — `UNKNOWN=0, PROCESS=1, THREAD=2, USER=3, SESSION=4, FILE=5, DIRECTORY=6, SOCKET=7, ENDPOINT=8, SERVICE=9, PACKAGE=10, DEVICE=11, CONTAINER=12, NAMESPACE=13, CREDENTIAL=14, KERNEL_OBJECT=15` | entities.py:34 |
| `UNKNOWN_ENTITY_KIND` | `UNKNOWN_ENTITY_KIND = EntityKind.UNKNOWN` | entities.py:61 |
| `SemanticProperty` | `class SemanticProperty(StrEnum)` — **exactly 16 members**, value == name. Behavioural (8): `INTERPRETER, NETWORK_CAPABLE, NETWORK_CLIENT, NETWORK_SERVER, PROCESS_SPAWNER, CREDENTIAL_READER, PRIVILEGE_CHANGER, PERSISTENCE_WRITER`. Object/metadata (8): `CREDENTIAL, AUTHORIZATION_DATA, PERSISTENCE, ROOT_OWNED, USER_WRITABLE, SYSTEM_BINARY, TEMP_LOCATION, EXTERNAL_ENDPOINT` | entities.py:64 |
| `BEHAVIOURAL_PROPERTIES` | `frozenset[SemanticProperty]` — the 8 behavioural members listed above | entities.py:96 |
| `NEUTRAL_BELIEF` | `NEUTRAL_BELIEF = 0.5` | entities.py:111 |
| `ASSERT_THRESHOLD` | `ASSERT_THRESHOLD = 0.75` | entities.py:114 |
| `SemanticBelief` | `@dataclass(frozen=True, slots=True)` | entities.py:118 |
| `SemanticBelief.kind` | `kind: EntityKind = EntityKind.UNKNOWN` | entities.py:126 |
| `SemanticBelief.properties` | `properties: dict[SemanticProperty, float] = field(default_factory=dict)` — **the annotation lies**: `__post_init__` replaces it with a `MappingProxyType` (entities.py:137) | entities.py:127 |
| `SemanticBelief.observations` | `observations: int = 0` | entities.py:129 |
| `SemanticBelief.__post_init__` | `def __post_init__(self) -> None` — raises `ContractError` on a non-`SemanticProperty` key or a value outside `[0, 1]`; freezes `properties` | entities.py:131 |
| `SemanticBelief.belief` | `def belief(self, prop: SemanticProperty) -> float` — returns `NEUTRAL_BELIEF` (0.5) when absent | entities.py:139 |
| `SemanticBelief.holds` | `def holds(self, prop: SemanticProperty) -> bool` — `belief(prop) >= 0.75` | entities.py:142 |
| `SemanticBelief.asserted` | `@property def asserted(self) -> frozenset[SemanticProperty]` | entities.py:146 |
| `SemanticBelief.uncertainty` | `@property def uncertainty(self) -> float` — `kind_penalty=0.5` if kind is UNKNOWN; `indecision = mean(1 - 2*abs(v - 0.5))`, or `1.0` when `properties` is empty; `evidence_relief = 1/(1+observations)`; result clamped to `[0.05, 1.0]` | entities.py:150 |
| `SemanticBelief.observe` | `def observe(self, prop: SemanticProperty, *, support: float) -> SemanticBelief` — **keyword-only `support`**; raises `ContractError` unless `0.0 <= support <= 1.0`; `updated = min(0.99, current + support*(1-current))`; `observations += 1` | entities.py:170 |
| `SemanticBelief.classify` | `def classify(self, *, present: frozenset[SemanticProperty], evaluated: frozenset[SemanticProperty]) -> SemanticBelief` — **both keyword-only**; present → `0.95` (overwrite); evaluated-and-absent → `setdefault(prop, 0.05)`; `observations += 1` | entities.py:187 |
| `SemanticBelief.note_observation` | `def note_observation(self) -> SemanticBelief` — `observations += 1`, no property change | entities.py:214 |
| `SemanticBelief.with_kind` | `def with_kind(self, kind: EntityKind) -> SemanticBelief` | entities.py:224 |
| `SemanticBelief.to_dict` | `def to_dict(self) -> dict[str, Any]` — keys `kind` (name), `properties` (value→rounded 4), `asserted` (sorted values), `observations`, `uncertainty` (rounded 4) | entities.py:227 |
| `Entity` | `@dataclass(frozen=True, slots=True)` | entities.py:238 |
| `Entity.identity` | `identity: str` — **required**, no default | entities.py:244 |
| `Entity.semantics` | `semantics: SemanticBelief = field(default_factory=SemanticBelief)` | entities.py:246 |
| `Entity.evidence` | `evidence: tuple[EvidenceRef, ...] = ()` — coerced via `tuple()` in `__post_init__` | entities.py:248 |
| `Entity.display_name` | `display_name: str = ""` | entities.py:252 |
| `Entity.__post_init__` | raises `ContractError` for an empty/non-str `identity` or a non-`SemanticBelief` `semantics` | entities.py:254 |
| `Entity.kind` | `@property def kind(self) -> EntityKind` — delegates to `semantics.kind` | entities.py:262 |
| `Entity.uncertainty` | `@property def uncertainty(self) -> float` | entities.py:266 |
| `Entity.observe` | `def observe(self, prop: SemanticProperty, *, support: float) -> Entity` | entities.py:269 |
| `Entity.with_semantics` | `def with_semantics(self, semantics: SemanticBelief) -> Entity` | entities.py:272 |
| `Entity.to_dict` | `def to_dict(self) -> dict[str, Any]` — keys `identity`, `display_name`, `semantics`, `evidence` | entities.py:275 |

**Measured belief arithmetic (this session):** one `observe(prop, support=0.6)` from
the neutral prior yields belief `0.8`, and `holds()` is immediately `True` (0.8 ≥
0.75). A fresh `SemanticBelief(kind=EntityKind.PROCESS)` has `uncertainty == 1.0`;
so does `SemanticBelief()`.

---

### 2.2 `pocketsec/stage1/ssir/relations.py`

`__all__ = ["Relation", "RELATION_FAMILIES", "RelationFamily", "family_of"]` (relations.py:16).

| Symbol | Full signature / definition | file:line |
|---|---|---|
| `Relation` | `class Relation(IntEnum)` — `SPAWN=0, EXECUTE=1, READ=2, WRITE=3, CREATE=4, DELETE=5, RENAME=6, CONNECT=7, ACCEPT=8, LISTEN=9, SEND=10, RECEIVE=11, AUTHENTICATE=12, IMPERSONATE=13, GRANT=14, REVOKE=15, LOAD=16, MAP=17, MOUNT=18, SIGNAL=19, CONTROL=20, INSTALL=21, REMOVE=22, CHANGE=23` (24 members) | relations.py:19 |
| `RelationFamily` | `class RelationFamily(IntEnum)` — `EXECUTION=0, FILESYSTEM=1, NETWORK=2, IDENTITY=3, AUTHORIZATION=4, LOADING=5, CONTROL=6, PACKAGING=7` | relations.py:56 |
| `RELATION_FAMILIES` | `RELATION_FAMILIES: dict[Relation, RelationFamily]` — total, one entry per `Relation` | relations.py:67 |
| `family_of` | `def family_of(relation: Relation) -> RelationFamily` — plain `dict` lookup; raises `KeyError` on a non-`Relation` | relations.py:95 |

Two module-level `assert` statements run at import: `len(RELATION_FAMILIES) == len(Relation)`
(relations.py:99) and `max(Relation) < 256` (relations.py:100).

---

### 2.3 `pocketsec/stage1/ssir/transition.py`

`__all__ = ["RepresentationLevel", "SSIR_TRANSITION_V1_ID", "SSIR_TRANSITION_V1_VERSION", "SSIRTransitionV1", "TemporalContext"]` (transition.py:27).

| Symbol | Full signature / definition | file:line |
|---|---|---|
| `SSIR_TRANSITION_V1_ID` | `= "pocketsec.ssir_transition.v1"` | transition.py:35 |
| `SSIR_TRANSITION_V1_VERSION` | `= register_schema(SSIR_TRANSITION_V1_ID, "1.0.0")` → `"1.0.0"`. **Side effect at import time.** | transition.py:36 |
| `RepresentationLevel` | `class RepresentationLevel(IntEnum)` — `L0=0, L1=1, L2=2, L3=3` | transition.py:39 |
| `TemporalContext` | `@dataclass(frozen=True, slots=True)` | transition.py:49 |
| `TemporalContext.since_actor_bucket` | `since_actor_bucket: int = 0` | transition.py:58 |
| `TemporalContext.since_host_bucket` | `since_host_bucket: int = 0` | transition.py:60 |
| `TemporalContext.bucket` | `@staticmethod def bucket(delta_ns: int) -> int` — returns `0` for `delta_ns <= 0`; otherwise counts up from a 1 ms threshold multiplying by 4, capped at `15` | transition.py:63 |
| `TemporalContext.to_dict` | `def to_dict(self) -> dict[str, Any]` | transition.py:74 |
| `SSIRTransitionV1` | `@dataclass(frozen=True, slots=True)` | transition.py:82 |
| `.actor` | `actor: Entity` (required) | transition.py:86 |
| `.relation` | `relation: Relation` (required; coerced `Relation(...)` in `__post_init__`) | transition.py:87 |
| `.object` | `object: Entity` (required; **shadows the builtin name** `object`) | transition.py:88 |
| `.state_delta` | `state_delta: StateDelta` (required) | transition.py:90 |
| `.uncertainty` | `uncertainty: float` (required) | transition.py:92 |
| `.novelty` | `novelty: NoveltyTensor` (required) | transition.py:94 |
| `.causal_signature` | `causal_signature: str` (required) | transition.py:96 |
| `.parent_signature` | `parent_signature: str` (required) | transition.py:97 |
| `.responsibility` | `responsibility: float` (required) | transition.py:98 |
| `.temporal` | `temporal: TemporalContext` (required) | transition.py:100 |
| `.evidence` | `evidence: tuple[EvidenceRef, ...]` (required; coerced `tuple()`) | transition.py:102 |
| `.epoch_id` | `epoch_id: int` (required) | transition.py:104 |
| `.sequence` | `sequence: int` (required) | transition.py:105 |
| `.level` | `level: RepresentationLevel = RepresentationLevel.L1` (coerced) | transition.py:106 |
| `.delta_phi` | `delta_phi: float = 0.0` | transition.py:109 |
| `.observation_incomplete` | `observation_incomplete: bool = False` | transition.py:111 |
| `.schema_version` | `schema_version: str = SSIR_TRANSITION_V1_VERSION` | transition.py:112 |
| `.__post_init__` | raises `ContractError` if `uncertainty` outside `[0,1]`, if `novelty` is not a `NoveltyTensor`, or if `state_delta` is not a `StateDelta` | transition.py:114 |
| `.is_high_consequence` | `@property def is_high_consequence(self) -> bool` — `bool(self.state_delta)`, i.e. any dimension raised | transition.py:126 |
| `.at_level` | `def at_level(self, level: RepresentationLevel) -> SSIRTransitionV1` — see trap T13 | transition.py:134 |
| `.to_dict` | `def to_dict(self) -> dict[str, Any]` — 19 keys incl. `schema`, `schema_version`, `is_high_consequence` | transition.py:159 |
| `.semantic_key` | `def semantic_key(self) -> tuple[Any, ...]` — `(actor.kind, frozenset(actor.semantics.asserted), relation, object.kind, frozenset(object.semantics.asserted), state_delta.bitmask())`. Excludes evidence, timing, pids, display names. | transition.py:182 |

Twelve of the sixteen fields are **positional-or-keyword with no default**. Construct
with keywords; a positional call is unreadable and breaks on any reordering.

---

### 2.4 `pocketsec/stage1/ssir/codec.py`

`__all__ = ["SSIR_MAGIC", "SSIR_WIRE_VERSION", "SSIRCodec", "SSIRHeader", "LAYOUTS"]` (codec.py:32).

| Symbol | Full signature / definition | file:line |
|---|---|---|
| `SSIR_MAGIC` | `= 0x5353` ("SS") | codec.py:40 |
| `SSIR_WIRE_VERSION` | `= 1` | codec.py:41 |
| `LAYOUTS` | `LAYOUTS: dict[str, int]` — field → byte width, in wire order: `causal_sig 8, actor_id 4, object_id 4, evidence_id 4, actor_sem 2, object_sem 2, state_delta 2, invariant_delta 2, relation 1, novelty_host 1, novelty_actor 1, novelty_relation 1, novelty_object 1, uncertainty 1, time_bucket 1, epoch_id_low 1, flags 1` | codec.py:45 |
| `FULL_RECORD_BYTES` | `= sum(LAYOUTS.values())` — **measured: 37** (public, not in `__all__`) | codec.py:66 |
| `LEVEL_FIELDS` | `LEVEL_FIELDS: dict[RepresentationLevel, tuple[str, ...]]` — L0: `(actor_id, object_id, relation, flags)`; L1: `(actor_id, object_id, actor_sem, object_sem, state_delta, relation, novelty_host, novelty_actor, time_bucket, epoch_id_low, flags)`; L2 and L3: `tuple(LAYOUTS)` (all 17). **L2 and L3 are byte-identical field sets.** | codec.py:70 |
| `_HEADER` | `struct.Struct("<HBB")` — magic `uint16`, wire version `uint8`, level `uint8`; `_HEADER.size == 4` | codec.py:90 |
| flag bits | `_FLAG_HIGH_CONSEQUENCE = 1<<0`, `_FLAG_OBSERVATION_INCOMPLETE = 1<<1`, `_FLAG_AGGREGATED = 1<<2`, `_FLAG_EVIDENCE_LINKED = 1<<3` — all private | codec.py:92-95 |
| `SSIRHeader` | `@dataclass(frozen=True, slots=True)` with `magic: int`, `wire_version: int`, `level: RepresentationLevel` | codec.py:99-102 |
| `SSIRCodec.__init__` | `def __init__(self, *, retained: frozenset[str] | None = None) -> None` — **keyword-only**; raises `ContractError(f"unknown SSIR fields: ...")` for any name not in `LAYOUTS`; stores `self.retained` | codec.py:112 |
| `SSIRCodec.fields_for` | `def fields_for(self, level: RepresentationLevel) -> tuple[str, ...]` — `LEVEL_FIELDS[level]` filtered by `retained` when `retained is not None` | codec.py:118 |
| `SSIRCodec.record_bytes` | `def record_bytes(self, level: RepresentationLevel) -> int` — **payload only, EXCLUDES the 4-byte header** | codec.py:124 |
| `SSIRCodec.encode` | `def encode(self, transition: SSIRTransitionV1) -> bytes` — level is taken from `transition.level`, **not** from an argument; little-endian, unsigned | codec.py:128 |
| `SSIRCodec.decode_header` | `def decode_header(self, blob: bytes) -> SSIRHeader` — raises `ContractError` on a short blob, wrong magic, or wrong wire version | codec.py:137 |
| `SSIRCodec.decode_fields` | `def decode_fields(self, blob: bytes) -> dict[str, int]` — uses the level from the blob's header and **this codec's** `retained` set; raises `ContractError` on truncation | codec.py:155 |
| `SSIRCodec._field_values` | `@staticmethod def _field_values(transition) -> dict[str, int]` — private; the authoritative quantisation table (see below) | codec.py:171 |
| `SSIRCodec.describe` | `def describe(self) -> dict[str, Any]` — keys `wire_version`, `full_record_bytes`, `header_bytes`, `retained`, `bytes_by_level` (**`bytes_by_level` DOES include the header**) | codec.py:203 |
| `_identity_id` | `def _identity_id(identity: str) -> int` — private. `int.from_bytes(identity.encode()[:4].ljust(4, b"\0"), "little") ^ (len(identity) & 0xFF)` | codec.py:216 |
| `_semantic_mask` | `def _semantic_mask(entity: Any) -> int` — private; bit `i` set when `list(SemanticProperty)[i]` is in `entity.semantics.asserted`, for `i < 16` | codec.py:230 |

**Quantisation, from `_field_values` (codec.py:181-201):**

| Wire field | Source expression |
|---|---|
| `causal_sig` | `int(transition.causal_signature[:16] or "0", 16) & 0xFFFFFFFFFFFFFFFF` |
| `actor_id` / `object_id` | `_identity_id(entity.identity)` |
| `evidence_id` | `_identity_id(transition.evidence[0].locator)` else `0` |
| `actor_sem` / `object_sem` | `_semantic_mask(entity)` |
| `state_delta` | `transition.state_delta.bitmask() & 0xFFFF` |
| `invariant_delta` | `min(0xFFFF, int(max(0.0, transition.delta_phi) * 100))` — **ΔΦ × 100, clamped at 0 below; negative ΔΦ is not representable** |
| `relation` | `int(transition.relation) & 0xFF` |
| `novelty_{host,actor,relation,object}` | `novelty.quantised(context)` = `min(255, round(v*255))`. **`user`, `parent_child`, `time`, `causal` are NOT on the wire.** |
| `uncertainty` | `min(255, int(transition.uncertainty * 255))` — truncating, not rounding |
| `time_bucket` | `transition.temporal.since_actor_bucket & 0xFF` — **`since_host_bucket` is NOT on the wire** |
| `epoch_id_low` | `transition.epoch_id & 0xFF` |
| `flags` | bit0 `is_high_consequence`, bit1 `observation_incomplete`, bit3 `bool(evidence)`. **bit2 (`_FLAG_AGGREGATED`) is never set by this module.** |

**Measured `SSIRCodec().describe()` (this session):**
`{"wire_version": 1, "full_record_bytes": 37, "header_bytes": 4, "retained": "all",
"bytes_by_level": {"L0": 14, "L1": 24, "L2": 41, "L3": 41}}`.

---

### 2.5 `pocketsec/stage1/telemetry/raw_event_v1.py`

`__all__ = ["EvidenceEvent", "RAW_EVENT_V1_ID", "RAW_EVENT_V1_VERSION", "RawEventV1", "SensorPath"]` (raw_event_v1.py:29).

| Symbol | Full signature / definition | file:line |
|---|---|---|
| `RAW_EVENT_V1_ID` | `= "pocketsec.raw_event.v1"` | raw_event_v1.py:37 |
| `RAW_EVENT_V1_VERSION` | `= register_schema(RAW_EVENT_V1_ID, "1.0.0")` → `"1.0.0"` | raw_event_v1.py:38 |
| `SensorPath` | `class SensorPath(StrEnum)` — `AUDITD="auditd", EBPF="ebpf", PROCFS="procfs", JOURNALD="journald", LSM="lsm"` | raw_event_v1.py:41 |
| `RawEventV1` | `@dataclass(frozen=True, slots=True)` | raw_event_v1.py:56 |
| `.record_id` | `record_id: str` — must match `^[A-Za-z0-9][A-Za-z0-9._:\-]{0,127}$` | raw_event_v1.py:64 |
| `.host_id` | `host_id: str` — same identifier regex | raw_event_v1.py:65 |
| `.boot_id` | `boot_id: str` — same identifier regex | raw_event_v1.py:66 |
| `.sensor` | `sensor: SensorPath` — coerced `SensorPath(...)`; a bad value raises `ValueError`, **not `ContractError`** | raw_event_v1.py:67 |
| `.observed_at_ns` | `observed_at_ns: int` — non-negative int (bools rejected) | raw_event_v1.py:68 |
| `.monotonic_ns` | `monotonic_ns: int` — non-negative int. **This is the assembler's only clock.** | raw_event_v1.py:69 |
| `.record_type` | `record_type: str` — same identifier regex (so `"openat/read"`, `""`, `"read event"`, `"_leading"` are all rejected — verified) | raw_event_v1.py:70 |
| `.assembly_key` | `assembly_key: str \| None = None` — `None` means "one record per operation"; `""` raises `ContractError` | raw_event_v1.py:73 |
| `.fields` | `fields: dict[str, str] = field(default_factory=dict)` — must be a `dict` of `str→str`; frozen to `MappingProxyType` in `__post_init__` | raw_event_v1.py:74 |
| `.incomplete` | `incomplete: bool = False` | raw_event_v1.py:77 |
| `.__post_init__` | `def __post_init__(self) -> None` | raw_event_v1.py:79 |
| `.group_key` | `@property def group_key(self) -> str` — `self.assembly_key or self.record_id` | raw_event_v1.py:97 |
| `.evidence_ref` | `def evidence_ref(self) -> EvidenceRef` — `store=f"raw.{sensor.value}"`, `locator=record_id`, `digest=sha256` over `record_id\|host_id\|boot_id\|sensor\|record_type\|observed_at_ns\|k=v...` with field keys **sorted** | raw_event_v1.py:101 |
| `.to_dict` | `def to_dict(self) -> dict[str, Any]` — 12 keys | raw_event_v1.py:124 |
| `EvidenceEvent` | `@dataclass(frozen=True, slots=True)` | raw_event_v1.py:142 |
| `.evidence_id` | `evidence_id: str` — identifier regex | raw_event_v1.py:151 |
| `.host_id` | `host_id: str` — identifier regex | raw_event_v1.py:152 |
| `.boot_id` | `boot_id: str` — **NOT validated, NOT cross-checked against the records** | raw_event_v1.py:153 |
| `.observed_at_ns` | `observed_at_ns: int` — **NOT validated** | raw_event_v1.py:154 |
| `.monotonic_ns` | `monotonic_ns: int` — **NOT validated** | raw_event_v1.py:155 |
| `.records` | `records: tuple[RawEventV1, ...]` — required; coerced `tuple()`; empty raises `ContractError`; every record's `host_id` must equal `self.host_id` | raw_event_v1.py:156 |
| `.partial` | `partial: bool = False` — **forced to `True`** if any record has `incomplete=True` (raw_event_v1.py:170) | raw_event_v1.py:159 |
| `.sensors` | `@property def sensors(self) -> frozenset[SensorPath]` | raw_event_v1.py:174 |
| `.evidence_refs` | `@property def evidence_refs(self) -> tuple[EvidenceRef, ...]` — one per contributing record, in record order | raw_event_v1.py:178 |
| `.merged_fields` | `def merged_fields(self) -> dict[str, str]` — later records win; **recomputed on every call**, returns a fresh mutable dict | raw_event_v1.py:181 |
| `.conflicting_fields` | `def conflicting_fields(self) -> frozenset[str]` — names where contributing records disagree; **recomputed on every call** | raw_event_v1.py:193 |
| `.field` | `def field(self, name: str, default: str = "") -> str` — convenience; **currently has zero callers in the repo** | raw_event_v1.py:208 |
| `.to_dict` | `def to_dict(self) -> dict[str, Any]` | raw_event_v1.py:211 |

---

### 2.6 `pocketsec/stage1/telemetry/assembler.py`

`__all__ = ["AssemblerStats", "EventAssembler"]` (assembler.py:22).

| Symbol | Full signature / definition | file:line |
|---|---|---|
| `DEFAULT_WINDOW_NS` | `= 50_000_000` (50 ms) — public, not in `__all__` | assembler.py:26 |
| `DEFAULT_MAX_PENDING` | `= 4096` — public, not in `__all__` | assembler.py:29 |
| `_Pending` | `@dataclass class _Pending` — private: `key: str`, `records: list[RawEventV1] = field(default_factory=list)`, `opened_at_ns: int = 0`, `expected: int \| None = None`. **Mutable, not frozen.** | assembler.py:33 |
| `AssemblerStats` | `@dataclass(frozen=True, slots=True)` — `fused: int = 0`, `expired_partial: int = 0`, `evicted_under_pressure: int = 0`, `singleton: int = 0`, `max_pending_seen: int = 0` | assembler.py:41 |
| `AssemblerStats.to_dict` | `def to_dict(self) -> dict[str, Any]` — six keys; `"lost"` **aliases `evicted_under_pressure` only** and excludes `expired_partial` | assembler.py:50 |
| `EventAssembler.__init__` | `def __init__(self, *, window_ns: int = DEFAULT_WINDOW_NS, max_pending: int = DEFAULT_MAX_PENDING) -> None` — **both keyword-only**; `max_pending < 1` raises `ValueError` (**not** `ContractError`) | assembler.py:70 |
| `.pending_count` | `@property def pending_count(self) -> int` | assembler.py:88 |
| `.stats` | `def stats(self) -> AssemblerStats` | assembler.py:91 |
| `.feed` | `def feed(self, record: RawEventV1) -> list[EvidenceEvent]` — returns operations that completed **on this call** (expiries first, then possibly this record's own group) | assembler.py:100 |
| `.flush` | `def flush(self) -> list[EvidenceEvent]` — drains every pending assembly with `partial=True`, clears state, adds to `expired_partial` | assembler.py:128 |
| `._expire` | `def _expire(self, *, now_ns: int) -> list[EvidenceEvent]` — private; `break`s at the first slot still inside its window | assembler.py:137 |
| `._evict_if_over_capacity` | `def _evict_if_over_capacity(self) -> None` — private; `popitem(last=False)` while `len > max_pending`; **evicted records are discarded, never emitted** | assembler.py:151 |
| `._build` | `@staticmethod def _build(slot: _Pending, *, partial: bool = False) -> EvidenceEvent` — private; `evidence_id = f"ev-{first.host_id}-{slot.key}"`; `host_id/boot_id/observed_at_ns/monotonic_ns` all taken from `records[0]` | assembler.py:162 |

Closing rule for a keyed group: a group closes **only** when
`fields["_expected_records"]` is present, all-digits, and `len(records) >= expected`
(assembler.py:116-123). Otherwise it waits for window expiry or `flush()`.

---

### 2.7 `pocketsec/stage1/compiler/rules.py`

`__all__ = ["OPERATION_RULES", "OperationRule", "classify_operation"]` (rules.py:33).
`normalise_token` is public but **not in `__all__`**.

| Symbol | Full signature / definition | file:line |
|---|---|---|
| `OperationRule` | `@dataclass(frozen=True, slots=True)` | rules.py:37 |
| `.relation` | `relation: Relation` (required) | rules.py:40 |
| `.tokens` | `tokens: frozenset[str]` (required) — canonical, post-normalisation | rules.py:44 |
| `.object_kind` | `object_kind: EntityKind = EntityKind.UNKNOWN` | rules.py:45 |
| `.actor_properties` | `actor_properties: tuple[SemanticProperty, ...] = ()` | rules.py:47 |
| `.raises` | `raises: tuple[tuple[str, IntEnum], ...] = ()` — `(dimension_name, level)` | rules.py:49 |
| `.conditional_raises` | `conditional_raises: tuple[tuple[SemanticProperty, str, IntEnum], ...] = ()` — `(required_object_property, dimension_name, level)` | rules.py:51 |
| `.property_support` | `property_support: float = 0.6` | rules.py:52 |
| `OPERATION_RULES` | `OPERATION_RULES: tuple[OperationRule, ...]` — **measured: 24 rules, 82 distinct tokens**; exactly one rule per `Relation` | rules.py:55 |
| `_TOKEN_INDEX` | `dict[str, OperationRule]` built at import; a duplicate token raises `RuntimeError` **at import time** | rules.py:249 |
| `_DISCOVERY_PATH_MARKERS` | `("/etc/passwd", "/etc/shadow", "/proc/self/environ")` — **defined and never read anywhere in the repo** | rules.py:258 |
| `normalise_token` | `def normalise_token(raw: str) -> str` — `strip().lower()`, then strips any of `"sys_"`, `"syscall_"`, `"do_"`, `"__x64_sys_"` found as a prefix | rules.py:261 |
| `classify_operation` | `def classify_operation(event: EvidenceEvent) -> OperationRule \| None` — tries merged fields `"operation"`, `"syscall"`, `"probe"`, `"record_op"` in that order, then each record's `record_type`; returns `None` when nothing matches | rules.py:275 |

**Measured normalisation (this session):** `sys_connect`, `SYSCALL_connect`,
`syscall_connect`, `__x64_sys_connect`, `do_connect`, `CONNECT` all normalise to
`connect` and all match a rule.

**Full rule table** (relation → tokens; object kind; actor properties; unconditional
raises; conditional raises):

| Relation | tokens | object_kind | actor_properties | raises | conditional_raises |
|---|---|---|---|---|---|
| `SPAWN` | fork, clone, vfork, spawn | PROCESS | PROCESS_SPAWNER | — | — |
| `EXECUTE` | execve, execveat, exec | FILE | PROCESS_SPAWNER | — | INTERPRETER→execution=INTERPRETER; USER_WRITABLE→trust=**`1` (raw int, see T1)** |
| `READ` | read, openat_read, pread64, readv, open_rdonly | FILE | — | — | CREDENTIAL→credential=READABLE; AUTHORIZATION_DATA→credential=METADATA |
| `WRITE` | write, pwrite64, writev, open_wronly | FILE | — | modification=USER_FILES | PERSISTENCE→persistence=SERVICE; ROOT_OWNED→modification=SYSTEM; AUTHORIZATION_DATA→modification=CONFIG |
| `CREATE` | creat, mkdir, mknod, create | FILE | — | — | PERSISTENCE→persistence=USER |
| `DELETE` | unlink, unlinkat, rmdir, delete | FILE | — | — | ROOT_OWNED→modification=SYSTEM |
| `RENAME` | rename, renameat, renameat2 | FILE | — | — | — |
| `CONNECT` | connect, sys_connect, tcp_connect | ENDPOINT | NETWORK_CAPABLE, NETWORK_CLIENT | reachability=LOCAL | EXTERNAL_ENDPOINT→reachability=EXTERNAL |
| `ACCEPT` | accept, accept4 | ENDPOINT | NETWORK_CAPABLE, NETWORK_SERVER | reachability=LOCAL | — |
| `LISTEN` | listen, bind | SOCKET | NETWORK_CAPABLE, NETWORK_SERVER | reachability=LOCAL | — |
| `SEND` | send, sendto, sendmsg, write_socket | ENDPOINT | NETWORK_CAPABLE | — | EXTERNAL_ENDPOINT→reachability=EXTERNAL |
| `RECEIVE` | recv, recvfrom, recvmsg | ENDPOINT | NETWORK_CAPABLE | — | — |
| `AUTHENTICATE` | pam_authenticate, authenticate, login | USER | — | — | — |
| `IMPERSONATE` | setuid, setgid, setresuid, seteuid, sudo | USER | PRIVILEGE_CHANGER | privilege=ELEVATED | — |
| `GRANT` | chmod, fchmod, setcap, chown, grant | FILE | — | modification=CONFIG | ROOT_OWNED→privilege=ROOT |
| `REVOKE` | revoke, removexattr | FILE | — | — | — |
| `LOAD` | init_module, finit_module, load_module, dlopen | KERNEL_OBJECT | — | persistence=BOOT_KERNEL, execution=PRIVILEGED | — |
| `MAP` | mmap, mprotect | KERNEL_OBJECT | — | — | — |
| `MOUNT` | mount, umount, pivot_root, setns, unshare | NAMESPACE | — | isolation=BOUNDARY_CROSSED | — |
| `SIGNAL` | kill, tgkill, signal | PROCESS | — | — | — |
| `CONTROL` | ptrace, process_vm_readv, prctl | PROCESS | CREDENTIAL_READER | discovery=CREDENTIAL_SYSTEM, credential=READABLE | — |
| `INSTALL` | install, dpkg_install, rpm_install | PACKAGE | — | persistence=SERVICE | — |
| `REMOVE` | uninstall, dpkg_remove, rpm_erase | PACKAGE | — | — | — |
| `CHANGE` | systemctl, service_change, config_change | SERVICE | — | persistence=SERVICE | — |

Note `CONNECT`'s token set contains the literal `"sys_connect"` and `"tcp_connect"`;
`"sys_connect"` is dead because `normalise_token` strips `sys_` before lookup.

---

### 2.8 `pocketsec/stage1/compiler/entity_registry.py`

`__all__ = ["CREDENTIAL_PATHS", "EntityRegistry", "PERSISTENCE_PATHS"]` (entity_registry.py:35).
`AUTHORIZATION_PATHS` and `INTERPRETER_NAMES` are public but not in `__all__`.

| Symbol | Full signature / definition | file:line |
|---|---|---|
| `CREDENTIAL_PATHS` | `("/etc/shadow", "/etc/gshadow", "/etc/sudoers", ".ssh/id_", ".aws/credentials", ".kube/config", "/proc/self/environ")` — matched with **`in` (substring)** | entity_registry.py:39 |
| `PERSISTENCE_PATHS` | `("/etc/systemd/", "/lib/systemd/", "/etc/cron", "/etc/init.d/", "/etc/rc.local", ".bashrc", ".profile", "/etc/ld.so.preload")` — substring | entity_registry.py:50 |
| `AUTHORIZATION_PATHS` | `("/etc/passwd", "/etc/group", "authorized_keys", "/etc/pam.d/")` — substring | entity_registry.py:62 |
| `INTERPRETER_NAMES` | `frozenset({"sh","bash","dash","zsh","python","python3","perl","ruby","node","php"})` — matched against the **basename only** | entity_registry.py:66 |
| `_SYSTEM_PREFIXES` | `("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/")` — `startswith` | entity_registry.py:70 |
| `_TEMP_PREFIXES` | `("/tmp/", "/var/tmp/", "/dev/shm/")` — `startswith` | entity_registry.py:71 |
| `_LOCAL_ADDRESS_PREFIXES` | `("127.", "::1", "localhost", "unix:")` | entity_registry.py:74 |
| `_LAN_ADDRESS_PREFIXES` | `("10.", "192.168.", "172.16.", "172.17.", "169.254.", "fe80:")` | entity_registry.py:75 |
| `EntityRegistry.__init__` | `def __init__(self, *, capacity: int = 2048) -> None` — **keyword-only**; `capacity < 1` raises `ValueError` | entity_registry.py:81 |
| `.evictions` | `@property def evictions(self) -> int` | entity_registry.py:89 |
| `.__len__` | `def __len__(self) -> int` | entity_registry.py:92 |
| `.get` | `def get(self, identity: str) -> Entity \| None` — **mutates LRU order** (`move_to_end`) | entity_registry.py:95 |
| `.update` | `def update(self, entity: Entity) -> Entity` — inserts/replaces, moves to end, evicts oldest past `capacity`, returns the entity | entity_registry.py:101 |
| `.resolve_actor` | `def resolve_actor(self, event: EvidenceEvent, fields: dict[str, str]) -> Entity` — **positional**; returns the cached entity unchanged when the identity is known; otherwise creates `Entity(identity, SemanticBelief(kind=PROCESS), evidence=event.evidence_refs[:1], display_name=fields.get("exe", fields.get("comm", "")))` | entity_registry.py:111 |
| `.resolve_object` | `def resolve_object(self, event: EvidenceEvent, rule: OperationRule, fields: dict[str, str]) -> Entity` — **positional**; returns the cached entity unchanged when known; otherwise classifies from host metadata | entity_registry.py:126 |
| `._process_identity` | `@staticmethod` — `f"proc:{event.boot_id}:{fields.get('pid','0')}:{fields.get('start_time', fields.get('proc_start','0'))}"` | entity_registry.py:151 |
| `._object_identity` | `@staticmethod def _object_identity(rule, fields) -> tuple[str, str]` — returns `(identity, display)`; see table below | entity_registry.py:158 |
| `._evaluable_properties` | `@staticmethod` — ENDPOINT → `{EXTERNAL_ENDPOINT}`; FILE/DIRECTORY → the 8 properties `{CREDENTIAL, PERSISTENCE, AUTHORIZATION_DATA, SYSTEM_BINARY, ROOT_OWNED, TEMP_LOCATION, USER_WRITABLE, INTERPRETER}`; **every other kind → `frozenset()`** | entity_registry.py:180 |
| `._metadata_properties` | `@staticmethod def _metadata_properties(rule, display) -> tuple[SemanticProperty, ...]` | entity_registry.py:205 |
| `.to_dict` | `def to_dict(self) -> dict[str, Any]` — `capacity`, `live_entities`, `evictions` | entity_registry.py:239 |

**Object identity derivation (`_object_identity`, entity_registry.py:158-177):**

| `rule.object_kind` | identity | display |
|---|---|---|
| `ENDPOINT` | `endpoint:{raddr\|addr\|"unknown"}:{rport\|port\|"0"}` | `{addr}:{port}` |
| `FILE` or `DIRECTORY` | `file:{inode}` when `inode` non-empty, else `file:{path\|name\|"unknown"}` | `path\|name\|"unknown"` |
| `PROCESS` | `proc:{target_pid\|cpid\|"0"}` — **no boot/start-time, unlike the actor key** | `target_comm` or `""` |
| `USER` | `user:{target_uid\|uid\|"0"}` | `uid={uid}` |
| anything else | `{kind.name.lower()}:{path\|name\|"unknown"}` | same label |

**Metadata property assignment (`_metadata_properties`):** ENDPOINT gets
`EXTERNAL_ENDPOINT` unless the lowered display starts with a local or LAN prefix,
and never when display is `""` or `"unknown:0"`. FILE/DIRECTORY gets `CREDENTIAL`,
`PERSISTENCE`, `AUTHORIZATION_DATA` by substring; `SYSTEM_BINARY` **and**
`ROOT_OWNED` together for a `_SYSTEM_PREFIXES` path; `TEMP_LOCATION` **and**
`USER_WRITABLE` together for a `_TEMP_PREFIXES` path; `INTERPRETER` when the
basename is in `INTERPRETER_NAMES`. Every other `EntityKind` gets **no properties
and no evaluated set**, so its belief stays at the neutral prior.

---

### 2.9 `pocketsec/stage1/compiler/semantic_compiler.py`

`__all__ = ["CompilerStats", "SemanticCompiler"]` (semantic_compiler.py:44).

| Symbol | Full signature / definition | file:line |
|---|---|---|
| `PARTIAL_OBSERVATION_UNCERTAINTY` | `= 0.35` | semantic_compiler.py:49 |
| `CONFLICT_UNCERTAINTY` | `= 0.25` | semantic_compiler.py:50 |
| `CompilerStats` | `@dataclass(frozen=True, slots=True)` — `compiled: int = 0`, `unresolved_relation: int = 0`, `partial_observations: int = 0`, `sensor_conflicts: int = 0`; `.to_dict()` at :60 | semantic_compiler.py:54 |
| `SemanticCompiler.__init__` | `def __init__(self, *, host_id: str, novelty: NoveltyEngine \| None = None, registry: EntityRegistry \| None = None, max_lineages: int = 256) -> None` — **all keyword-only; `host_id` is required**. Defaults construct a fresh `NoveltyEngine()` and `EntityRegistry()`. | semantic_compiler.py:77 |
| `.host_id` | public attribute `str` | semantic_compiler.py:85 |
| `.novelty` | public attribute `NoveltyEngine` | semantic_compiler.py:86 |
| `.registry` | public attribute `EntityRegistry` | semantic_compiler.py:87 |
| `.stats` | `def stats(self) -> CompilerStats` | semantic_compiler.py:101 |
| `.host_state` | `def host_state(self) -> SecurityStateV1` — lattice join over all **live** lineages, recomputed per call | semantic_compiler.py:109 |
| `.lineage_state` | `def lineage_state(self, lineage: str) -> SecurityStateV1` — lineage key is the actor's `Entity.identity`; unknown key returns a default `SecurityStateV1()` | semantic_compiler.py:116 |
| `.compile` | `def compile(self, event: EvidenceEvent, *, epoch_id: int = 0) -> SSIRTransitionV1 \| None` — **`event` positional, `epoch_id` keyword-only**; returns `None` when no rule matches | semantic_compiler.py:119 |
| `._resolve_entities` | private | semantic_compiler.py:168 |
| `._apply_behavioural_semantics` | private — `observe(prop, support=rule.property_support)` per `rule.actor_properties`; if no property was granted, applies `note_observation()`; then `registry.update(...)` | semantic_compiler.py:175 |
| `._apply_state_operators` | `@staticmethod` private — unconditional `raises` first, then `conditional_raises` gated on `obj.semantics.holds(prop)` | semantic_compiler.py:193 |
| `._lineage_key` | private — returns `actor.identity` | semantic_compiler.py:205 |
| `._store_lineage_state` | private — evicts the **lowest-Φ** lineage past `max_lineages` (not the oldest) | semantic_compiler.py:208 |
| `._novelty_keys` | `@staticmethod` private — builds all 8 `NOVELTY_CONTEXTS` keys; reads `fields["uid"]`, `fields["ppid"]`, `fields["pid"]`, `fields["hour"]`, defaulting each to `"?"` | semantic_compiler.py:221 |
| `._uncertainty` | private — `min(1.0, max(actor.uncertainty, obj.uncertainty)*0.5 + observational + 0.05)`; **increments `_partial` / `_conflicts` as a side effect** | semantic_compiler.py:243 |
| `._temporal` | private — buckets `now - last_seen[actor]` and `now - last_host`; bounds the timing table at `max_lineages * 2` | semantic_compiler.py:260 |
| `._build` | private — computes the causal signature, chains `parent_signature` per lineage, sets `responsibility = max(0.0, ΔΦ)`, attaches **all** `event.evidence_refs`, picks the level | semantic_compiler.py:274 |
| `_choose_level` | `def _choose_level(delta: StateDelta, novelty_peak: float, uncertainty: float) -> RepresentationLevel` — module-level, **private by convention, not in `__all__`** | semantic_compiler.py:323 |

**Level policy, literally (`_choose_level`, semantic_compiler.py:332-340):**
`delta and delta.magnitude >= 2` → **L3**; `delta` (magnitude 1) → **L2**;
`novelty_peak >= 0.8 or uncertainty >= 0.6` → **L2**; `novelty_peak >= 0.4` → **L1**;
otherwise **L0**.

**Novelty keys built per transition (`_novelty_keys`):**
`host = "{RELATION}:{actor_asserted_csv}:{object_asserted_csv}"`,
`user = "{uid}:{RELATION}"`, `actor = "{actor.identity}:{RELATION}"`,
`parent_child = "{ppid}->{pid}"`, `object = "{OBJECT_KIND}:{object_asserted_csv}"`,
`relation = "{RELATION}"`, `time = "{RELATION}:{hour}"`,
`causal = "{actor_asserted_csv}|{RELATION}|{object_asserted_csv}"`.
Empty asserted sets render as the literal string `"none"`.

Two module-level `assert` statements run at import (semantic_compiler.py:343-344).

---

## 3. How to construct and drive the subsystem

The snippet below was executed this session; the output that follows it is real.

```python
from pocketsec.stage1.compiler.semantic_compiler import SemanticCompiler
from pocketsec.stage1.ssir.codec import SSIRCodec
from pocketsec.stage1.telemetry.assembler import EventAssembler
from pocketsec.stage1.telemetry.raw_event_v1 import RawEventV1, SensorPath

assembler = EventAssembler()                          # window_ns/max_pending are keyword-only
compiler = SemanticCompiler(host_id="lab-host-01")    # host_id is REQUIRED and keyword-only
codec = SSIRCodec()                                   # retained=None means "all fields"

# auditd-shaped compound operation: SYSCALL + PATH sharing an assembly key.
# _expected_records is what closes the group; without it nothing fuses until flush().
records = [
    RawEventV1(
        record_id="audit-00001-0",
        host_id="lab-host-01",
        boot_id="boot-0001",
        sensor=SensorPath.AUDITD,
        observed_at_ns=1_700_000_000_000_000_000,
        monotonic_ns=1_000_000,
        record_type="SYSCALL",
        assembly_key="audit-00001",
        fields={
            "syscall": "openat_read",       # normalises to the READ rule
            "_expected_records": "2",
            "pid": "1041",                  # pid + start_time -> the lineage key
            "start_time": "7",
            "uid": "0",
        },
    ),
    RawEventV1(
        record_id="audit-00001-1",
        host_id="lab-host-01",
        boot_id="boot-0001",
        sensor=SensorPath.AUDITD,
        observed_at_ns=1_700_000_000_000_001_000,
        monotonic_ns=1_001_000,
        record_type="PATH",
        assembly_key="audit-00001",
        fields={"path": "/etc/shadow", "inode": "918273"},
    ),
]

events = []
for record in records:
    events.extend(assembler.feed(record))   # feed returns whatever COMPLETED on this call
events.extend(assembler.flush())            # ALWAYS flush at end of stream

for event in events:
    transition = compiler.compile(event, epoch_id=0)
    if transition is None:                  # unrecognised operation: nothing is invented
        continue
    blob = codec.encode(transition)         # level comes from transition.level
    fields = codec.decode_fields(blob)      # same codec instance (same `retained`) or you misread
```

Measured output:

```
fused events: 1 assembler stats: {'fused': 1, 'expired_partial': 0,
  'evicted_under_pressure': 0, 'singleton': 0, 'max_pending_seen': 1, 'lost': 0}
relation           : READ
level              : L3
object asserted    : ['CREDENTIAL']
actor asserted     : []
state_delta        : {'raised': {'credential': {'from': 0, 'to': 2}}, 'magnitude': 2, 'bitmask': 4}
delta_phi          : 2.0
uncertainty        : 0.3
evidence refs      : 2
wire bytes         : 41
L0 projection bytes: 14
semantic_key       : (EntityKind.PROCESS, frozenset(), Relation.READ, EntityKind.FILE,
                      frozenset({SemanticProperty.CREDENTIAL}), 4)
compiler stats: {'compiled': 1, 'unresolved_relation': 0, 'partial_observations': 0,
  'sensor_conflicts': 0}
registry     : {'capacity': 2048, 'live_entities': 2, 'evictions': 0}
```

For an **eBPF-shaped** single record, set `assembly_key=None` and put the operation
in `fields["operation"]` (e.g. `"sys_read"`); it is emitted by `feed` immediately and
counted under `singleton`, not `fused`.

**Cross-sensor equivalence, verified this session.** Driving the same logical READ of
`/etc/shadow` through `SensorPath.EBPF` (1 record) and `SensorPath.AUDITD`
(2 records) produced identical `semantic_key()` values and identical `uncertainty`
(0.3 both), differing only in `len(evidence)` (1 vs 2). That equality is the contract
later stages may rely on; byte-level equality of the encoded record is **not**
implied, because `evidence_id` and the identity handles differ.

For a full worked wiring including epochs, causal memory, aggregation and the
adaptive observation policy, `pocketsec/stage1/pipeline.py:99` (`Stage1Pipeline.run_scenario`)
is the reference driver. Do not reimplement it; call it.

---

## 4. Invariants enforced in code

| # | Invariant | Enforced at |
|---|---|---|
| I1 | An unrecognised operation yields `None`; no relation is fabricated. | `semantic_compiler.py:129-132`; `tests/test_stage1_pipeline.py:48` `test_unrecognised_operation_is_not_invented` |
| I2 | `EntityKind.UNKNOWN == 0` is a first-class value, not an error. | `entities.py:43`; `tests/test_stage1_semantics.py:37` `test_unknown_entity_is_first_class` |
| I3 | A property with no evidence sits at `NEUTRAL_BELIEF == 0.5`, never 0.0. | `entities.py:140`; `tests/test_stage1_semantics.py:44` `test_unseen_property_sits_at_the_neutral_prior` |
| I4 | Belief can never reach certainty: `min(0.99, ...)`. | `entities.py:181`; `tests/test_stage1_semantics.py:49` `test_belief_rises_with_evidence_but_never_reaches_certainty` |
| I5 | `uncertainty` is clamped to `[0.05, 1.0]` — never zero. | `entities.py:168`; `tests/test_stage1_semantics.py:59` `test_uncertainty_falls_as_observations_accumulate` |
| I6 | `ASSERT_THRESHOLD (0.75) > NEUTRAL_BELIEF (0.5)`, so the prior alone never asserts. | `entities.py:111,114`; `tests/test_stage1_semantics.py:101` `test_assert_threshold_is_above_the_neutral_prior` |
| I7 | A negative classification result is recorded (belief 0.05), not omitted. | `entities.py:204-209`; `tests/test_stage1_semantics.py:67` `test_classification_records_negative_results` |
| I8 | Semantic properties are orthogonal — one entity may hold several. | `entities.py:64`; `tests/test_stage1_semantics.py:79` `test_properties_are_orthogonal` |
| I9 | `support` outside `[0, 1]` raises `ContractError`. | `entities.py:178-179`; `tests/test_stage1_semantics.py:91` `test_belief_rejects_out_of_range_support` |
| I10 | `Entity.identity` must be a non-empty string. | `entities.py:255-256`; `tests/test_stage1_semantics.py:96` `test_entity_requires_an_identity` |
| I11 | Every `Relation` has a `RelationFamily`; relations fit a `uint8`. | `relations.py:99-100` (import-time asserts); `tests/test_stage1_semantics.py:108,112` |
| I12 | `uncertainty` outside `[0,1]`, a non-`NoveltyTensor` novelty, or a non-`StateDelta` delta raises `ContractError`. | `transition.py:114-123` |
| I13 | Every compiled transition carries at least one `EvidenceRef`; evidence is referenced by `sha256:` digest, never inlined. | `semantic_compiler.py:314`, `raw_event_v1.py:101-122`; `tests/test_stage1_pipeline.py:57` `test_every_transition_carries_evidence_lineage` |
| I14 | Representation level rises with consequence. | `semantic_compiler.py:323-340`; `tests/test_stage1_pipeline.py:65` `test_representation_level_escalates_with_consequence` |
| I15 | Two sensor paths with genuinely different record shapes produce identical SSIR semantics. | `tests/test_stage1_pipeline.py:75` `test_two_sensor_paths_produce_identical_semantics`, with the shape difference itself asserted at `tests/test_stage1_pipeline.py:85` |
| I16 | An `EvidenceEvent` needs ≥1 record and all records must share `host_id`. | `raw_event_v1.py:165-169` |
| I17 | Any `incomplete` record forces `EvidenceEvent.partial = True`, overriding the constructor argument. | `raw_event_v1.py:170-171` (verified: passing `partial=False` still yields `partial=True`) |
| I18 | Sensor disagreement is surfaced, not silently resolved, and raises uncertainty. | `raw_event_v1.py:193-206`, `semantic_compiler.py:255-257`; `tests/test_stage1_bounded.py:217` `test_sensor_conflicts_are_surfaced_not_resolved` |
| I19 | Compiled uncertainty is never 0 (a `+0.05` floor) and compounds semantic with observational sources. | `semantic_compiler.py:258` |
| I20 | Compound records fuse into exactly one operation; singletons emit immediately; incomplete assemblies flush as `partial`. | `assembler.py:100-133`; `tests/test_stage1_bounded.py:186,195,200` |
| I21 | Pending assemblies are hard-bounded and overflow is **counted**, never grown into. | `assembler.py:151-159`; `tests/test_stage1_bounded.py:209` `test_assembler_evicts_under_pressure_rather_than_growing` |
| I22 | The entity registry is hard-bounded and counts evictions. | `entity_registry.py:104-107` |
| I23 | Lineage state storage is hard-bounded; the lowest-Φ lineage is evicted so an active chain survives churn. | `semantic_compiler.py:215-218` |
| I24 | The per-actor timing table is bounded at `max_lineages * 2`. | `semantic_compiler.py:267-268` |
| I25 | A foreign or version-mismatched blob is refused, never partially decoded. | `codec.py:143-152`; `tests/test_stage1_bounded.py:564` `test_decoder_refuses_a_foreign_blob` |
| I26 | Levels cost strictly progressively more bytes, and encode/decode round-trips. | `codec.py:118-166`; `tests/test_stage1_bounded.py:548,554` |
| I27 | An ablated codec really costs fewer bytes (measurement is not estimated). | `codec.py:118-126`; `tests/test_stage1_bounded.py:572` `test_ablated_codec_actually_costs_fewer_bytes` |
| I28 | Projecting to L0 genuinely drops evidence and ΔS. | `transition.py:145-156`; `tests/test_stage1_bounded.py:580` `test_projection_to_l0_drops_evidence_and_delta` |
| I29 | Temporal buckets are monotone and bounded to `[0, 15]`. | `transition.py:63-72`; `tests/test_stage1_bounded.py:588` |
| I30 | A duplicate operation token anywhere in `OPERATION_RULES` fails at **import**, not at classification time. | `rules.py:250-254` |
| I31 | Exactly one rule per relation. | `rules.py:297-299` (import-time assert) |
| I32 | `len(DIMENSIONS) <= 16` so `state_delta` fits its `uint16`. | `state/security_state.py:243` (dependency, enforced at import) |
| I33 | An unknown `retained` field name raises `ContractError` at codec construction. | `codec.py:113-115` (verified) |
| I34 | Re-registering `pocketsec.raw_event.v1` or `pocketsec.ssir_transition.v1` at a different version raises `ContractError`. | `stage0/contracts/common.py:59-64`; `tests/test_contracts.py:225` |

---

## 5. Extension points

### Sanctioned

| Where | How | Constraint |
|---|---|---|
| **New telemetry source** | Add a member to `SensorPath` (`raw_event_v1.py:41`) and emit `RawEventV1` with an `operation`/`syscall`/`probe`/`record_op` field that `normalise_token` maps onto an existing token. | Nothing downstream changes. This is the intended way to add auditd/eBPF/LSM variants. |
| **New machine operation** | Append a `Relation` member (`relations.py:19`), add its `RelationFamily` entry (`relations.py:67`), and add exactly one `OperationRule` (`rules.py:55`). | Both import-time asserts (I30, I31) must still hold. Relations must stay ≤ 255. Do **not** encode ATT&CK techniques here — the module docstring (`relations.py:4-6`) forbids it. |
| **New sensor token for an existing operation** | Add the canonical (post-normalisation) token to that rule's `tokens`. | A duplicate token across rules is an import-time `RuntimeError`. |
| **New host-metadata path class** | Extend `CREDENTIAL_PATHS`, `PERSISTENCE_PATHS`, `AUTHORIZATION_PATHS` or `INTERPRETER_NAMES` (`entity_registry.py:39-68`) **and** add the property to `_evaluable_properties` (`entity_registry.py:180`) so a negative result is still recorded. | Extending the path tuple without extending `_evaluable_properties` makes the property invisible to `classify`, so absence reads as ignorance instead of evidence. |
| **Ablation / cost measurement** | `SSIRCodec(retained=frozenset({...}))` and `record_bytes(level)`. | This is exactly what the Information Guillotine consumes. |
| **Reading a transition** | `SSIRTransitionV1.to_dict()`, `.semantic_key()`, `.at_level()`, and `family_of(transition.relation)`. `pocketsec/stage2/encoder/ssir_encoder.py:30,205` is the existing precedent — a Stage 2 consumer that imports `Relation`, `RelationFamily`, `family_of`, `SemanticProperty`, `SSIRTransitionV1` and `DIMENSIONS` and derives a feature vector without touching Stage 1 internals. | Read-only. Derive; do not mutate. |
| **Swapping the bounded substrate** | `SemanticCompiler(host_id=..., novelty=..., registry=...)` accepts injected `NoveltyEngine` and `EntityRegistry` instances. | Both must remain bounded. |

### Explicitly NOT extension points

- **Do not add a field to `SSIRTransitionV1` or change `LAYOUTS` widths/order in place.** A
  breaking layout change takes a **new schema id** (`pocketsec.ssir_transition.v2`), never a
  version bump (`codec.py:16-20`, `stage0/contracts/common.py:49-66`). `StateDelta.bitmask()`
  bit order follows `DIMENSIONS` insertion order: appending a dimension is
  backward-compatible, reordering is not (`state/security_state.py:206-217`).
- **Do not add a 17th `SemanticProperty` and expect it on the wire.** There are
  exactly 16 today and `_semantic_mask` packs `list(SemanticProperty)[:16]`
  (`codec.py:234-236`). A 17th member is silently absent from `actor_sem`/`object_sem`.
  It is also position-sensitive: **inserting** a member anywhere but the end
  renumbers every existing bit.
- **Do not grant capability properties from a name, path or command line.** Actor
  properties come only from `rule.actor_properties` after the operation was observed
  (`semantic_compiler.py:175-190`, ADR-0006). `display_name` exists for investigators
  and is excluded from the encoding (`entities.py:249-252`).
- **Do not merge `SecurityStateV1` into the transition.** SSIR answers "what changed";
  the state answers "what is now true". They are separate types by decision.
- **Do not collapse novelty, Φ and uncertainty into one score.** They are three
  independent signals; novelty is not maliciousness.
- **Do not write to `compiler._lineage_state`, `_lineage_signature`, `_last_seen_ns`,
  `registry._entities` or `assembler._pending`.** All private, all load-bearing for
  the bounded-memory invariants.
- **Do not put a verdict, severity, action or authority field anywhere in this
  subsystem.** Response authority belongs to Stage 5 under SENTINEL (ADR-0003).

---

## 6. Traps

Every trap below was reproduced by running code in this session. The quoted values
are real output.

### T1 — `EXECUTE` of a user-writable file puts a **raw `int`** into `SecurityStateV1.trust`, and `to_dict()` then crashes

`rules.py:69` writes `(SemanticProperty.USER_WRITABLE, "trust", 1)  # Trust.UNCERTAIN`
— a bare `1`, not `Trust.UNCERTAIN`. `raised_to` does
`replace(self, **{dimension: level})` (`state/security_state.py:153`), so the field
holds a plain `int`.

Reproduced end-to-end (execve of `/tmp/x91`):

```
compiled: EXECUTE delta: {'trust': (0, 1)}
lineage trust: 1 int
lineage_state().to_dict() RAISED: AttributeError 'int' object has no attribute 'name'
host_state().to_dict() -> UNCERTAIN            (join repairs the type)
```

`phi()` and `level()` keep working because they call `int(...)`. `host_state()` is
safe because `join` re-wraps via `enum_type(max(...))`
(`state/security_state.py:174`). **Only `lineage_state(...).to_dict()` is poisoned.**
A later stage that serialises per-lineage state will crash on exactly the executions
it most wants to log. Treat any state you serialise as needing
`DIMENSIONS[name](state.level(name))` re-wrapping, or fix the rule.

### T2 — `_identity_id` collides catastrophically: `actor_id` and `object_id` on the wire barely discriminate

`codec.py:225-227` hashes only the **first 4 UTF-8 bytes** XOR the length. Measured:

```
proc:boot-0001:1041:7  -> 1668248165
proc:boot-0001:1042:7  -> 1668248165     EQUAL: True
file:/etc/shadow       -> 1701603702
file:/etc/passwd       -> 1701603702     EQUAL: True
```

Every `proc:` identity of equal length collides; so does every `file:` identity of
equal length. Do **not** use the decoded `actor_id`/`object_id` to correlate,
group or count distinct entities. Use `transition.actor.identity` (the real string)
before encoding, or the evidence store. Note this partly serves the design goal
(identity is deliberately opaque to the model), but it is documented nowhere in the
module and reads like a working hash.

### T3 — A missing `pid` field silently merges every actor into one lineage

`_process_identity` (`entity_registry.py:151-155`) defaults `pid` to `"0"` and
`start_time`/`proc_start` to `"0"`. With neither present:

```
actor identities: ['proc:boot-1:0:0', 'proc:boot-1:0:0']  IDENTICAL: True
```

Because lineage state is monotone and keyed on that identity, **one fabricated
lineage accumulates every capability on the host**, ΔΦ becomes meaningless, and
`responsibility` is attributed to nothing. There is no warning and no counter. Any
new sensor must emit `pid` **and** `start_time` (or `proc_start`) or its telemetry is
worse than useless.

### T4 — Lineage state persists across everything you thought was independent

One `SemanticCompiler` carries `_lineage_state` forever, keyed by
`boot_id:pid:start_time`. Reuse that triple and prior capability leaks in. Measured
(a CONNECT to an external endpoint, then a READ of `/etc/shadow` under the same
pid/start_time):

```
after connect: EXTERNAL
after read:   {..., 'credential': 'READABLE', 'reachability': 'EXTERNAL', ...}
delta_phi of the read: 4.5   level: L3
```

The read's ΔΦ is 4.5 rather than 2.0 purely because of the earlier connect — correct
behaviour, catastrophic if your corpus or replay reuses pids between "independent"
sessions. `MEMORY.md` records this as a defect that already produced a **retracted
Stage 2 result**. Use a fresh `SemanticCompiler` per independent actor, or vary
`pid`/`start_time`/`boot_id`.

### T5 — The registry returns cached entities **unmodified**, so first sighting wins forever

`resolve_actor` (`entity_registry.py:115-116`) and `resolve_object`
(`entity_registry.py:132-133`) both `return existing` before any re-classification.
Combined with inode-keyed file identity (`file:{inode}` when `inode` is present,
ignoring `path`), the result is:

```
('/etc/shadow',        'file:555', display='/etc/shadow', ['CREDENTIAL'])
('/home/u/notes.txt',  'file:555', display='/etc/shadow', ['CREDENTIAL'])
```

A benign read of `notes.txt` is reported as a `CREDENTIAL` read of `/etc/shadow`,
raising `credential` to READABLE. Any sensor that emits a **reused, recycled or
fabricated** inode will manufacture false credential exposure. A sensor that emits
no inode falls back to `file:{path}`, which is safer here. The same cache means an
actor's `display_name` is whatever the **first** record called it.

### T6 — Without `_expected_records`, a keyed group never fuses; it lands as `partial` with inflated uncertainty

A group closes only on `len(records) >= int(fields["_expected_records"])`
(`assembler.py:116-123`). Feed two records sharing an `assembly_key` and omit it:

```
emitted before flush: 0   pending: 1
drained: 1   partial: [True]
stats: {'fused': 0, 'expired_partial': 1, ..., 'singleton': 0}
uncertainty of a partial fusion: 0.65   observation_incomplete: True
compiler stats: {'compiled': 1, 'unresolved_relation': 0, 'partial_observations': 1, ...}
```

Uncertainty jumps from 0.3 to **0.65** and `observation_incomplete` is set, which in
turn blocks aggregation downstream. A new multi-record sensor that forgets
`_expected_records` degrades the whole host's observability while every test still
passes.

### T7 — `feed()` returning `[]` does not mean nothing happened; forgetting `flush()` loses data

`feed` returns only what completed on that call. Pending groups are closed **only**
by (a) reaching `_expected_records`, (b) a later record whose `monotonic_ns` is past
the window, or (c) `flush()`. There is **no wall clock** — `_expire(now_ns=record.monotonic_ns)`
(`assembler.py:102`) advances time only when a record arrives. A quiet host holds
partial assemblies indefinitely. Always `flush()` at end of stream.

### T8 — Expiry is driven by *any* incoming record, so an unrelated event closes your group

`_expire` is called at the top of every `feed`, using that record's `monotonic_ns`:

```
pending after first record: 1
an UNRELATED later record flushed the stale group: 2 [True, False]
```

An unrelated eBPF singleton at `monotonic_ns=60_000_000` forced a stale auditd group
out as `partial=True`, and the returned list mixes the expired partial with the new
singleton. Do not assume `feed(record)` returns events derived from `record`.
Additionally, `_expire` `break`s at the first slot still inside its window
(`assembler.py:142-145`), which assumes insertion order tracks `opened_at_ns`; records
arriving out of monotonic order can leave older slots un-expired.

### T9 — Evicted assemblies are **destroyed**, not emitted

`_evict_if_over_capacity` calls `popitem(last=False)` and only increments a counter
(`assembler.py:157-159`). With `max_pending=2` and six distinct keys:

```
emitted: 0   stats: {'fused': 0, 'expired_partial': 0, 'evicted_under_pressure': 4,
                     'singleton': 0, 'max_pending_seen': 2, 'lost': 4}
flush recovers: 2
```

Four operations vanished with their evidence. This is the designed bounded-degradation
behaviour, but it is **evidence loss**: you must read
`stats().evicted_under_pressure` to know it happened, and note that
`to_dict()["lost"]` counts *only* evictions, excluding `expired_partial`.

### T10 — `dataclasses.replace()` on `RawEventV1` always raises

`__post_init__` converts `fields` to a `MappingProxyType` (`raw_event_v1.py:94`),
and the very next construction rejects it because `isinstance(MappingProxyType, dict)`
is `False` (`raw_event_v1.py:89-90`):

```
ContractError: RawEventV1.fields must be a dict
```

Verified that `replace()` on `SemanticBelief` **does** work (its `__post_init__` calls
`dict(...)` without an isinstance check), so the failure mode is inconsistent across
the subsystem. To vary a raw record, construct a new one and pass
`fields=dict(original.fields)`.

### T11 — Decoding with a different `retained` set misreads silently, with no exception

`decode_fields` uses the *decoder's* `retained` set, not the encoder's
(`codec.py:155-166`). Encoding with a full codec and decoding with a narrower one:

```
encoder fields L3: 17   decoder fields L3: 11
true relation: 2
mis-decoded relation: 108   <- wrong, no exception raised
```

`READ` (2) was read back as 108. Only the 4-byte header is validated; field
composition is not. **The `retained` set is part of the wire contract and must be
transported out of band.** Ablation experiments must decode with the same codec
instance that encoded.

### T12 — `SSIRCodec(retained=frozenset())` encodes nothing but reports `"all"`

Empty `frozenset()` passes the unknown-field check, is not `None`, and filters every
field away, while `describe()` uses a truthiness test:

```
fields_for L2: ()   record_bytes L2: 0
describe retained: all
```

You get a 4-byte header with no payload, self-described as a complete record. Pass
`retained=None` for "all"; never `frozenset()`.

### T13 — `at_level()` upward is a **relabel**, not a restore

`transition.py:142-143`: `if level >= self.level: return replace(self, level=level)`.
Projecting down then back up keeps the fields dropped but advertises the higher level:

```
L0: evidence=0  delta=False  uncertainty=0.0
back-to-L3: label=L3  evidence still 0  uncertainty still 0.0  wire bytes 41
```

A 41-byte "L3" record with zero evidence, zero uncertainty and an empty ΔS. Anything
that trusts `transition.level` to imply field presence, or that treats `uncertainty
== 0.0` as high confidence rather than "not carried at this level", draws the wrong
conclusion. Note L0/L1 projection sets `uncertainty=0.0` (`transition.py:149`), which
collides with the real invariant that compiled uncertainty is never zero (I19).

### T14 — `record_bytes()` excludes the header; `describe()["bytes_by_level"]` includes it

`record_bytes(L0)` is 10 while `len(encode(...))` is 14 (`codec.py:124-126` vs
`codec.py:135`). Measured `bytes_by_level` is `{L0: 14, L1: 24, L2: 41, L3: 41}` — the
header-inclusive figures. Mixing the two understates every cost by exactly 4 bytes per
record, which is a ~10% error at L0.

### T15 — L2 and L3 are byte-identical; `evidence_id` is only a 32-bit handle

`LEVEL_FIELDS[L2] == LEVEL_FIELDS[L3] == tuple(LAYOUTS)` (`codec.py:85-86`). The L2/L3
distinction lives **only** in the Python object's `evidence` tuple, not on the wire —
and the wire's `evidence_id` is `_identity_id(evidence[0].locator)`, i.e. the first ref
only, through the colliding hash of T2. **The evidence trail is not reconstructable
from an encoded record.** Keep the `SSIRTransitionV1` objects, or the digests, if you
need lineage.

### T16 — Four novelty contexts and `since_host_bucket` never reach the wire

The codec carries only `novelty_host`, `novelty_actor`, `novelty_relation`,
`novelty_object`. `user`, `parent_child`, `time` and `causal` are computed, used by
`_choose_level` via `novelty.peak`, and then dropped. `time_bucket` carries only
`since_actor_bucket`. A consumer reading encoded records sees a strictly poorer
novelty tensor than one reading `SSIRTransitionV1` objects.

### T17 — `invariant_delta` cannot represent a negative ΔΦ, and `epoch_id` aliases every 256 epochs

`invariant_delta = min(0xFFFF, int(max(0.0, delta_phi) * 100))` (`codec.py:191`) clamps
negatives to 0 and saturates at ΔΦ = 655.35. `epoch_id_low = epoch_id & 0xFF`
(`codec.py:199`) makes epoch 256 indistinguishable from epoch 0. Do not correlate
encoded records across more than 256 epochs.

### T18 — A non-hex `causal_signature` raises a bare `ValueError`, not `ContractError`

`codec.py:182` calls `int(sig[:16], 16)`:

```
RAISED: ValueError | invalid literal for int() with base 16: 'not-a-hex-sig'
        | is ContractError: False
```

`causal_signature` is produced as 16 hex chars by `causal_signature()`
(`causal/memory.py:47-70`), so this only bites a later stage that synthesises its own
signatures. Code that catches `ContractError` around `encode` will not catch it.

### T19 — `EvidenceEvent` validates `host_id` but not `boot_id`, and `boot_id` decides process identity

```
boots fused: ['b1', 'b2']   partial: False   -> process identity will use b1
```

Records from two different boots fused without complaint, `partial` stayed `False`,
and `_process_identity` used `event.boot_id` — so post-reboot pid reuse can merge two
unrelated processes into one lineage. `host_id` mismatch and empty `records` **are**
refused (`ContractError`). `evidence_id`, `boot_id`, `observed_at_ns` and
`monotonic_ns` on `EvidenceEvent` are otherwise unvalidated. Also note `_build`
(`assembler.py:162-173`) takes `host_id`/`boot_id`/timestamps from `records[0]` only.

### T20 — One `observe(support=0.6)` is enough to assert a capability

`0.5 + 0.6 * 0.5 = 0.8 >= ASSERT_THRESHOLD`. A **single** `connect` makes an actor
`NETWORK_CLIENT` with no corroboration, which feeds `semantic_key()`, the novelty
keys and the causal signature. A single spurious record permanently changes an
actor's semantics for as long as it stays in the registry — capability beliefs only
ever rise (`entities.py:181`).

### T21 — `classify()` never lowers an already-asserted property

`present` overwrites to 0.95 but absent uses `setdefault(prop, 0.05)`
(`entities.py:206-209`):

```
after 1st classify:                  {'CREDENTIAL': 0.95, 'PERSISTENCE': 0.05}
after CREDENTIAL evaluated ABSENT:   {'CREDENTIAL': 0.95, 'PERSISTENCE': 0.05}
                                     -> still asserted: True
```

Re-classification cannot retract a mistake. Combined with T5, a wrong first
classification is permanent for that identity's registry lifetime.

### T22 — Path matching is substring-based and unanchored

`CREDENTIAL_PATHS`, `PERSISTENCE_PATHS` and `AUTHORIZATION_PATHS` are matched with
`marker in display` (`entity_registry.py:223-228`). `/home/user/notes-about-/etc/shadow`
and `/tmp/etc/passwd-backup` both match. `SYSTEM_BINARY`/`TEMP_LOCATION` use
`startswith` and are therefore anchored, but they are checked against the raw
`display` string with no normalisation, so `/usr/./bin/x` or `/tmp/../usr/bin/x`
defeats them. No path canonicalisation happens anywhere in this subsystem.

### T23 — Non-FILE, non-ENDPOINT objects get no evaluated set, so they stay maximally uncertain

`_evaluable_properties` (`entity_registry.py:180-202`) returns `frozenset()` for
PROCESS, USER, SOCKET, NAMESPACE, KERNEL_OBJECT, PACKAGE and SERVICE. Those objects
have empty `properties`, so `indecision == 1.0` and their `uncertainty` stays high,
which propagates into `_uncertainty` via `max(actor.uncertainty, obj.uncertainty)`.
`SPAWN`, `SIGNAL`, `CONTROL`, `MOUNT`, `LOAD`, `INSTALL` and `CHANGE` transitions
therefore carry systematically higher uncertainty than file/network ones for a
structural reason, not an observational one. Do not read that as genuine ambiguity.

### T24 — `_uncertainty` mutates counters; `conflicting_fields()` and `merged_fields()` are recomputed every call

`_uncertainty` (`semantic_compiler.py:243-258`) increments `self._partial` and
`self._conflicts` as a side effect, so it is not a pure query — calling it twice
double-counts the stats. Meanwhile `merged_fields()` rebuilds its dict on every call
and `EvidenceEvent.field()` calls it each time; `compile` invokes
`conflicting_fields()` twice per event (`:255` and `:319`). Correct, but O(records ×
fields) per call — do not call them in a hot loop, and do not call `_uncertainty`
yourself.

### T25 — `stats()` accounting is not a partition

`fused` counts only groups closed by `_expected_records` (`assembler.py:122`);
singletons increment `singleton` (`assembler.py:105`) and are **never** counted as
`fused`; `flush()` and `_expire` both feed `expired_partial`. Measured for the
worked example: `{'fused': 1, ..., 'singleton': 0}`; for a single eBPF record:
`{'fused': 0, ..., 'singleton': 1}`. `fused + singleton + expired_partial +
evicted_under_pressure` is the number of *operations accounted for*, and `fused`
alone is **not** the throughput figure.

### T26 — Dead and never-set names that look live

- `BEHAVIOURAL_PROPERTIES` (`entities.py:96`) — **zero callers** in the repo. If you
  need "is this property earned by behaviour", this set is the intended answer but
  nothing enforces it; `rules.py` grants properties from `actor_properties` without
  consulting it.
- `UNKNOWN_ENTITY_KIND` (`entities.py:61`) — zero callers.
- `SemanticBelief.with_kind` (`entities.py:224`) — zero callers. An entity's `kind` is
  set at construction and never revised, so a PROCESS first seen as an object stays
  whatever `rule.object_kind` said.
- `EvidenceEvent.field` (`raw_event_v1.py:208`) — zero callers.
- `_DISCOVERY_PATH_MARKERS` (`rules.py:258`) — defined, never read. Despite its
  comment, `Discovery` is raised **only** by the `CONTROL` rule; reading `/etc/passwd`
  raises `credential=METADATA`, not `discovery`.
- `_FLAG_AGGREGATED` (`codec.py:94`) — bit 2 is defined and **never set** by
  `_field_values`. Do not read it as "this record was aggregated".
- `"sys_connect"` in the `CONNECT` token set (`rules.py:121`) — unreachable, because
  `normalise_token` strips `sys_` first.

### T27 — `SSIRTransitionV1.object` shadows the builtin

The field is literally named `object` (`transition.py:88`). Inside methods and
comprehensions that touch it, `object` no longer refers to the builtin type. Harmless
today, a real hazard in any code that does `isinstance(x, object)` nearby.

### T28 — Import order has side effects

Importing `transition.py` or `raw_event_v1.py` calls `register_schema` at module
level (`transition.py:36`, `raw_event_v1.py:38`), and `rules.py` / `relations.py` /
`semantic_compiler.py` / `security_state.py` all run module-level `assert`s at import.
Running under `python -O` disables those asserts, silently removing I11, I31 and I32.
Do not ship `-O`.

---

## 7. Honest status notes

- **Measured this session:** the 103 passing tests; all byte counts in section 2.4
  and 3; every trap output quoted in section 6; rule/token counts (24 rules, 82
  tokens); `SemanticProperty` count (16); the belief arithmetic (0.8 after one
  `support=0.6`); cross-sensor `semantic_key` equality for one READ scenario.
- **UNMEASURED here:** throughput, memory footprint, and any detection quality
  number for this subsystem. `planning/MEMORY.md` records earlier figures (peak RSS
  24.6 MB, 1.8e-04 CPU s/transition, cross-sensor equivalence 20/20) that were **not**
  reproduced in this session and are not restated as current.
- **Provisional by decision (ADR-0007):** SSIR field *widths*. Only presence/absence is
  settled; the D1.13 freeze is narrow. `codec.py:12-15` says so explicitly.
- **Not verified anywhere:** `ruff` and `mypy` have never been run on this code
  (`planning/MEMORY.md`), so the type annotations in every signature above are
  unchecked. `SemanticBelief.properties` and `RawEventV1.fields` are annotated `dict`
  and are `MappingProxyType` at runtime (T10).
