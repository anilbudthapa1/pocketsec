# Stage 1 interface reference — security state, Φ, causal memory, epoch, novelty

> **Scope.** The exact public API of `pocketsec/stage1/state/`, `pocketsec/stage1/causal/`,
> `pocketsec/stage1/epoch/` and `pocketsec/stage1/novelty/`, as read from the source on
> 2026-09-24. Every signature below is quoted from the file at the cited line. Every number
> labelled MEASURED was produced by running that code in the session that wrote this document;
> anything not measured here says UNMEASURED. Documentation is not evidence that code exists —
> the file:line citations are.
>
> **Files documented:** `state/security_state.py` (243 lines), `state/potential.py` (278),
> `causal/memory.py` (286), `epoch/model.py` (268), `novelty/engine.py` (194),
> `novelty/sketches.py` (265). The four `__init__.py` files are **all 0 bytes** — there are no
> package-level re-exports. Import from the full module path or the import fails.

---

## 1. Purpose

This subsystem is Stage 1's answer to "what is now true about this host, how dangerous is that
combination, how it got there, whether it is unusual, and whether normality itself has legitimately
moved". `state/security_state.py` models capability as nine **ordered lattices** (`SecurityStateV1`)
so an event becomes a monotone operator on state rather than another categorical event id, with
`StateDelta` carrying only the dimensions a transition *raised*. `state/potential.py` computes
**Φ(S)** — a composition-aware potential where named interaction terms (e.g. credential access +
external reachability + elevated privilege) are worth more than the sum of base severities — always
returned with its reasoning attached (`PhiBreakdown`). `causal/memory.py` keeps a **bounded**
causal record: identity-free chained signatures `P_t = H(P_parent, actor_semantics, relation,
object_semantics, state_delta_bitmask)` plus responsibility-ordered retention that demotes the
least-responsible nodes instead of the oldest. `epoch/model.py` scopes normality to a
**behavioural epoch** keyed on *system identity*, and refuses to open one without corroborating
system-change evidence — the entire anti-poisoning mechanism. `novelty/engine.py` +
`novelty/sketches.py` estimate novelty as an **8-context tensor**, not a scalar, over three bounded
tiers (exact LRU → Count-Min Sketch → stable Bloom filter). Φ, novelty and uncertainty are three
**separate** signals and this subsystem never collapses them or emits a verdict.

---

## 2. Public symbols

### 2.1 `pocketsec/stage1/state/security_state.py`

`__all__` (line 23): `CredentialExposure`, `DIMENSIONS`, `Discovery`, `ExecutionControl`,
`Isolation`, `ModificationCapability`, `Persistence`, `Privilege`, `Reachability`,
`SecurityStateV1`, `StateDelta`, `Trust`.

#### The nine lattices (all `IntEnum`; higher = more capability, or for `Trust`, less confidence)

| Symbol | Members (name = value) | file:line |
|---|---|---|
| `Privilege` | `USER=0`, `ELEVATED=1`, `ROOT=2` | `state/security_state.py:45` |
| `Trust` | `TRUSTED=0`, `UNCERTAIN=1`, `UNTRUSTED=2` | `state/security_state.py:51` |
| `CredentialExposure` | `NONE=0`, `METADATA=1`, `READABLE=2`, `EXTRACTED=3` | `state/security_state.py:57` |
| `Reachability` | `NONE=0`, `LOCAL=1`, `LAN=2`, `EXTERNAL=3` | `state/security_state.py:64` |
| `Persistence` | `NONE=0`, `USER=1`, `SERVICE=2`, `BOOT_KERNEL=3` | `state/security_state.py:71` |
| `ExecutionControl` | `LIMITED=0`, `INTERPRETER=1`, `PRIVILEGED=2` | `state/security_state.py:78` |
| `ModificationCapability` | `NONE=0`, `USER_FILES=1`, `CONFIG=2`, `SYSTEM=3` | `state/security_state.py:84` |
| `Discovery` | `NONE=0`, `LOCAL_INVENTORY=1`, `CREDENTIAL_SYSTEM=2` | `state/security_state.py:91` |
| `Isolation` | `CONFINED=0`, `NAMESPACE_AWARE=1`, `BOUNDARY_CROSSED=2` | `state/security_state.py:97` |

#### Module constant

| Symbol | Signature / value | file:line |
|---|---|---|
| `DIMENSIONS` | `dict[str, type[IntEnum]]` — **frozen insertion order**: `privilege, trust, credential, reachability, persistence, execution, modification, discovery, isolation` (9 entries, MEASURED) | `state/security_state.py:108` |
| module assert | `assert len(DIMENSIONS) <= 16, "state_delta bitmask is a uint16 in the SSIR layout"` | `state/security_state.py:243` |

#### `SecurityStateV1` — `@dataclass(frozen=True, slots=True)`, `state/security_state.py:122`

Fields, in declaration order (this order is also the positional-constructor order):

| Field | Type | Default | file:line |
|---|---|---|---|
| `privilege` | `Privilege` | `Privilege.USER` | `:125` |
| `trust` | `Trust` | `Trust.TRUSTED` | `:126` |
| `credential` | `CredentialExposure` | `CredentialExposure.NONE` | `:127` |
| `reachability` | `Reachability` | `Reachability.NONE` | `:128` |
| `persistence` | `Persistence` | `Persistence.NONE` | `:129` |
| `execution` | `ExecutionControl` | `ExecutionControl.LIMITED` | `:130` |
| `modification` | `ModificationCapability` | `ModificationCapability.NONE` | `:131` |
| `discovery` | `Discovery` | `Discovery.NONE` | `:132` |
| `isolation` | `Isolation` | `Isolation.CONFINED` | `:133` |

| Method | Full signature | Behaviour | file:line |
|---|---|---|---|
| `level` | `level(self, dimension: str) -> int` | `int(getattr(self, dimension))`; raises `ContractError(f"unknown state dimension {dimension!r}")` on `AttributeError` | `:135` |
| `raised_to` | `raised_to(self, dimension: str, level: IntEnum) -> SecurityStateV1` | Monotone raise. `ContractError` if `dimension not in DIMENSIONS`. Returns `self` **unchanged (identical object)** if `int(level) <= self.level(dimension)`; otherwise `dataclasses.replace` | `:141` |
| `delta_from` | `delta_from(self, previous: SecurityStateV1) -> StateDelta` | `StateDelta.between(previous, self)` — receiver is the *current* state | `:155` |
| `to_dict` | `to_dict(self) -> dict[str, Any]` | `{name: <enum>.name}` for every `DIMENSIONS` key, e.g. `{"privilege": "USER", ...}` | `:158` |
| `to_levels` | `to_levels(self) -> dict[str, int]` | `{name: int}` for every `DIMENSIONS` key | `:161` |
| `join` | `@classmethod join(cls, left: SecurityStateV1, right: SecurityStateV1) -> SecurityStateV1` | Per-dimension `max`, rebuilt through each `DIMENSIONS` enum type (MEASURED: returns proper enum instances for all 9 dimensions). Monotone, order-independent | `:165` |

Hashable: **yes** (MEASURED — `hash(SecurityStateV1())` works; all fields are ints).

#### `StateDelta` — `@dataclass(frozen=True, slots=True)`, `state/security_state.py:181`

| Member | Full signature | Behaviour | file:line |
|---|---|---|---|
| `raised` | `raised: dict[str, tuple[int, int]]` | Only **raised** dimensions; value is `(before_level, after_level)`. Sole field, so `StateDelta({"credential": (0, 2)})` is valid positionally | `:189` |
| `__post_init__` | `__post_init__(self) -> None` | `object.__setattr__(self, "raised", dict(self.raised))` — shallow-copies the caller's dict at construction (MEASURED) | `:191` |
| `__bool__` | `__bool__(self) -> bool` | `bool(self.raised)` — an empty delta is falsy | `:194` |
| `dimensions` | `@property dimensions(self) -> frozenset[str]` | `frozenset(self.raised)` | `:198` |
| `magnitude` | `@property magnitude(self) -> int` | `sum(after - before ...)` — total lattice steps climbed | `:202` |
| `bitmask` | `bitmask(self) -> int` | `1 << index` per raised dimension, index from `DIMENSIONS` insertion order. MEASURED bit values: `privilege=1, trust=2, credential=4, reachability=8, persistence=16, execution=32, modification=64, discovery=128, isolation=256`; all-nine mask = `511` | `:206` |
| `to_dict` | `to_dict(self) -> dict[str, Any]` | `{"raised": {name: {"from": int, "to": int}}, "magnitude": int, "bitmask": int}` | `:219` |
| `between` | `@classmethod between(cls, previous: SecurityStateV1, current: SecurityStateV1) -> StateDelta` | Raised-only diff | `:230` |
| `empty` | `@classmethod empty(cls) -> StateDelta` | `cls(raised={})` | `:239` |

Hashable: **no** (MEASURED — `hash(StateDelta.empty())` → `TypeError: unhashable type: 'dict'`,
despite `frozen=True`).

### 2.2 `pocketsec/stage1/state/potential.py`

`__all__` (line 34): `BASE_WEIGHTS`, `INTERACTIONS`, `PhiBreakdown`, `calibrate`, `delta_phi`,
`phi`. Note `Interaction` and `CalibrationReport` are **not** in `__all__` but are unavoidable —
`INTERACTIONS` is a tuple of the former and `calibrate` returns the latter.

| Symbol | Signature / value | file:line |
|---|---|---|
| `BASE_WEIGHTS` | `dict[str, float]` = `{"privilege": 1.0, "trust": 0.5, "credential": 1.0, "reachability": 0.75, "persistence": 1.0, "execution": 0.5, "modification": 0.75, "discovery": 0.5, "isolation": 1.0}` — contribution **per lattice step** | `state/potential.py:41` |
| `Interaction` | `@dataclass(frozen=True, slots=True)` with `name: str`, `weight: float`, `rationale: str` | `state/potential.py:55` (fields `:58`–`:60`) |
| `INTERACTIONS` | `tuple[Interaction, ...]`, 6 entries, evaluation order fixed: `exfiltration_triad` (4.0), `privileged_credential_access` (2.0), `credential_egress` (2.5), `privileged_persistence` (2.0), `boundary_escape` (2.0), `discovery_to_credential` (1.0) | `state/potential.py:65` |

#### The six interaction predicates (private, but this is the whole semantics of Φ)

| Interaction | Exact predicate | file:line |
|---|---|---|
| `exfiltration_triad` | `credential >= READABLE and reachability >= EXTERNAL and privilege >= ELEVATED` | `:102` |
| `privileged_credential_access` | `privilege >= ELEVATED and credential >= READABLE` | `:110` |
| `credential_egress` | `credential >= READABLE and reachability >= EXTERNAL` (no privilege requirement) | `:117` |
| `privileged_persistence` | `privilege >= ELEVATED and persistence >= SERVICE` | `:124` |
| `boundary_escape` | `isolation >= 2 and privilege >= ELEVATED` (raw `2`, i.e. `BOUNDARY_CROSSED`) | `:128` |
| `discovery_to_credential` | `discovery >= 2 and credential >= READABLE` (raw `2`, i.e. `CREDENTIAL_SYSTEM`) | `:132` |
| `_PREDICATES` | `dict[str, Callable[[SecurityStateV1], bool]]` — keyed by `Interaction.name`; `phi` looks each interaction up here by name | `:136` |

#### `PhiBreakdown` — `@dataclass(frozen=True, slots=True)`, `state/potential.py:147`

| Field | Type | file:line |
|---|---|---|
| `total` | `float` (`= base + interaction_total`) | `:154` |
| `base` | `float` | `:155` |
| `base_terms` | `dict[str, float]` — **only dimensions whose level > 0** (MEASURED: `{}` for the initial state) | `:156` |
| `active_interactions` | `tuple[str, ...]` — names, in `INTERACTIONS` order | `:157` |
| `interaction_total` | `float` | `:158` |
| `to_dict` | `to_dict(self) -> dict[str, Any]` — every float `round(..., 4)` | `:160` |

Hashable: **no** (MEASURED — `dict` field).

| Function | Full signature | file:line |
|---|---|---|
| `phi` | `phi(state: SecurityStateV1) -> PhiBreakdown` | `state/potential.py:170` |
| `delta_phi` | `delta_phi(previous: SecurityStateV1, current: SecurityStateV1) -> float` — returns `phi(current).total - phi(previous).total` | `state/potential.py:195` |
| `_additive_only` | `_additive_only(state: SecurityStateV1) -> float` — the compositionless control (base weights, no interactions) | `state/potential.py:232` |
| `calibrate` | `calibrate(labelled: list[tuple[SecurityStateV1, int]]) -> CalibrationReport` — label `0` = benign, `1` = malicious; **any other label value is silently ignored by both cohorts** | `state/potential.py:237` |

#### `CalibrationReport` — `@dataclass(frozen=True, slots=True)`, `state/potential.py:204`

| Field | Type | file:line |
|---|---|---|
| `sample_count` | `int` (length of the input list, including ignored labels) | `:212` |
| `benign_mean_phi` | `float` | `:213` |
| `malicious_mean_phi` | `float` | `:214` |
| `separation` | `float` (`malicious_mean_phi - benign_mean_phi`) | `:215` |
| `additive_separation` | `float` (same gap under `_additive_only`) | `:216` |
| `composition_gain` | `float` (`separation - additive_separation`) | `:217` |
| `notes` | `str` — set to `"insufficient labels: need both benign and malicious states"` when either cohort is empty, in which case **every number is 0.0** | `:218` |
| `to_dict` | `to_dict(self) -> dict[str, Any]` | `:220` |

MEASURED reference values (this session, `SecurityStateV1()` vs `privilege=ELEVATED,
credential=READABLE, reachability=EXTERNAL`):

- `phi(SecurityStateV1()).total == 0.0`
- Φ of that triad state = `13.75` = base `5.25` (`privilege 1.0 + credential 2.0 + reachability 2.25`)
  + interactions `8.5` (`exfiltration_triad`, `privileged_credential_access`, `credential_egress`)
- `phi(privilege=ROOT only).total == 2.0`, `active_interactions == ()`
- Every lattice at maximum: Φ `31.0`, all 6 interactions active
- `calibrate([(initial, 0), (triad, 1)])` → `separation 13.75`, `additive_separation 5.25`,
  `composition_gain 8.5`

These are properties of these weights on these states, **not** a detection result.

### 2.3 `pocketsec/stage1/causal/memory.py`

`__all__` (line 36): `CausalMemory`, `CausalNode`, `CausalResolution`, `ResponsibilityReport`,
`causal_signature`. `GENESIS_SIGNATURE` is public-by-convention but **not** in `__all__`.

| Symbol | Signature / value | file:line |
|---|---|---|
| `GENESIS_SIGNATURE` | `= "0" * 16` — the root parent signature | `causal/memory.py:44` |
| `causal_signature` | `causal_signature(*, parent_signature: str, actor_semantics: frozenset[str], relation: int, object_semantics: frozenset[str], state_delta: StateDelta) -> str` — **all keyword-only**. Material = `"|".join([parent_signature, ",".join(sorted(actor_semantics)), str(relation), ",".join(sorted(object_semantics)), str(state_delta.bitmask())])`, then `sha256(...).hexdigest()[:16]` (16 hex chars, 64 bits) | `causal/memory.py:47` |
| `CausalResolution` | Plain class, four `int` constants: `L0_EXACT = 0`, `L1_SUMMARY = 1`, `L2_FINGERPRINT = 2`, `L3_SIGNATURE = 3` (not an `Enum`) | `causal/memory.py:73` |

#### `CausalNode` — `@dataclass(frozen=True, slots=True)`, `causal/memory.py:83`

| Field | Type | Default | file:line |
|---|---|---|---|
| `signature` | `str` | — | `:86` |
| `parent_signature` | `str` | — | `:87` |
| `sequence` | `int` | — | `:88` |
| `relation` | `int` | — | `:89` |
| `state_delta_mask` | `int` | — | `:90` |
| `delta_phi` | `float` | — | `:94` |
| `resolution` | `int` | `CausalResolution.L0_EXACT` | `:95` |
| `actor_identity` | `str` | `""` | `:96` |
| `evidence_locators` | `tuple[str, ...]` | `()` | `:97` |

| Method | Full signature | Behaviour | file:line |
|---|---|---|---|
| `demote` | `demote(self, resolution: int) -> CausalNode` | One-way. Returns `self` if `resolution <= self.resolution`. Keeps `actor_identity`/`evidence_locators` only while `resolution < CausalResolution.L2_FINGERPRINT`; L2 and L3 blank both. `signature`, `parent_signature`, `sequence`, `relation`, `state_delta_mask`, `delta_phi` survive every tier (MEASURED) | `:99` |
| `to_dict` | `to_dict(self) -> dict[str, Any]` | `delta_phi` is `round(..., 4)`; `evidence_locators` becomes a `list` | `:121` |

Hashable: **yes** (MEASURED).

#### `ResponsibilityReport` — `@dataclass(frozen=True, slots=True)`, `causal/memory.py:136`

| Field | Type | Meaning | file:line |
|---|---|---|---|
| `spine` | `tuple[str, ...]` | Signatures, ordered by `sequence` | `:139` |
| `scores` | `dict[str, float]` | Responsibility of **every retained node**, not just the spine | `:140` |
| `total_phi_gain` | `float` | Sum of responsibility over retained nodes only — dropped nodes' gain is gone | `:141` |
| `retained_at_l0` | `int` | Count with `resolution == L0_EXACT` | `:143` |
| `compressed` | `int` | Count with `resolution != L0_EXACT` | `:143` (field), `:274` (computation) |
| `to_dict` | `to_dict(self) -> dict[str, Any]` | scores rounded to 4dp | `:145` |

#### `CausalMemory` — plain class, `causal/memory.py:155`

| Member | Full signature | Behaviour | file:line |
|---|---|---|---|
| `__init__` | `__init__(self, *, capacity: int = 512, l0_budget: int = 64) -> None` | `ValueError("capacity and l0_budget must be >= 1")` if either `< 1`. **No check that `l0_budget <= capacity`** (MEASURED: `CausalMemory(capacity=2, l0_budget=100)` constructs fine) | `:163` |
| `dropped` | `@property dropped(self) -> int` | Nodes evicted for capacity, cumulative | `:173` |
| `__len__` | `__len__(self) -> int` | Live node count | `:176` |
| `memory_bytes` | `@property memory_bytes(self) -> int` | Estimate: `sum(64 + len(actor_identity) + sum(len(loc) for loc in evidence_locators))`. **An estimate, not `sys.getsizeof`** | `:180` |
| `record` | `record(self, *, parent_signature: str, actor_semantics: frozenset[str], relation: int, object_semantics: frozenset[str], state_delta: StateDelta, delta_phi: float, actor_identity: str = "", evidence_locators: tuple[str, ...] = ()) -> CausalNode` | **All keyword-only.** Computes the signature, increments the internal sequence, stores keyed **by signature** in an `OrderedDict`, `move_to_end`, then `_rebalance()`. Returns the new node | `:187` |
| `_rebalance` | `_rebalance(self) -> None` | If `len > l0_budget`: sort all nodes ascending by `(responsibility, sequence)` and demote the first `len - l0_budget` — to `L1_SUMMARY` if responsibility `> 0.0`, else `L2_FINGERPRINT`. Then while `len > capacity`: pop the `min` by `(responsibility, -sequence)` and increment `dropped` | `:223` |
| `responsibility` | `@staticmethod responsibility(node: CausalNode) -> float` | `max(0.0, node.delta_phi)`. Negative ΔΦ is clamped to 0 | `:246` |
| `spine` | `spine(self, *, min_responsibility: float = 0.01) -> tuple[CausalNode, ...]` | Retained nodes with `responsibility >= min_responsibility`, sorted by `sequence` | `:256` |
| `report` | `report(self) -> ResponsibilityReport` | Recomputed on every call | `:265` |
| `to_dict` | `to_dict(self) -> dict[str, Any]` | `{"nodes", "capacity", "dropped", "memory_bytes", "report"}` — note it does **not** expose `l0_budget` | `:279` |

### 2.4 `pocketsec/stage1/epoch/model.py`

`__all__` (line 27): `EPOCH_KEY_COMPONENTS`, `EpochDecision`, `EpochModel`,
`EpochTransitionReason`, `SystemIdentity`. `Epoch` is **not** in `__all__` yet is the return type of
`EpochModel.current`; `_EpochSummary` is private.

| Symbol | Signature / value | file:line |
|---|---|---|
| `EPOCH_KEY_COMPONENTS` | `tuple[str, ...]` = `("kernel_id", "package_digest", "service_digest", "container_id", "policy_digest", "user_role_digest")` | `epoch/model.py:37` |
| `EpochTransitionReason` | `StrEnum`: `INITIAL = "INITIAL"`, `SYSTEM_CHANGE_CORROBORATED`, `REJECTED_NO_CORROBORATION`, `UNCHANGED` | `epoch/model.py:47` |

#### `SystemIdentity` — `@dataclass(frozen=True, slots=True)`, `epoch/model.py:55`

| Field | Type | Default | file:line |
|---|---|---|---|
| `kernel_id` | `str` | `""` | `:58` |
| `package_digest` | `str` | `""` | `:59` |
| `service_digest` | `str` | `""` | `:60` |
| `container_id` | `str` | `""` | `:61` |
| `policy_digest` | `str` | `""` | `:62` |
| `user_role_digest` | `str` | `""` | `:63` |

| Method | Full signature | Behaviour | file:line |
|---|---|---|---|
| `key` | `key(self) -> str` | `sha256("|".join(components)).hexdigest()[:16]`. An all-default identity yields the legal key `1867f76f89b18a0f` (MEASURED) | `:65` |
| `changed_components` | `changed_components(self, other: SystemIdentity) -> frozenset[str]` | Names differing between `self` and `other` | `:69` |
| `to_dict` | `to_dict(self) -> dict[str, Any]` | All six components | `:76` |

#### `EpochDecision` — `@dataclass(frozen=True, slots=True)`, `epoch/model.py:81`

| Member | Type / signature | Note | file:line |
|---|---|---|---|
| `epoch_id` | `int` | The epoch **in force after** the decision | `:84` |
| `reason` | `EpochTransitionReason` | — | `:85` |
| `changed_components` | `frozenset[str]` | Everything that differed, corroborated or not | `:86` |
| `corroborated` | `bool` | — | `:87` |
| `detail` | `str` | Human-readable reasoning | `:88` |
| `transitioned` | `@property transitioned(self) -> bool` | **Exactly** `reason is EpochTransitionReason.SYSTEM_CHANGE_CORROBORATED` | `:91` |
| `to_dict` | `to_dict(self) -> dict[str, Any]` | `changed_components` becomes a **sorted list**; `reason` becomes `reason.value` | `:94` |

#### `Epoch` — `@dataclass(frozen=True, slots=True)`, `epoch/model.py:105`

| Field | Type | Default | file:line |
|---|---|---|---|
| `epoch_id` | `int` | — | `:108` |
| `identity` | `SystemIdentity` | — | `:109` |
| `key` | `str` | — | `:110` |
| `opened_at_ns` | `int` | — | `:111` |
| `observed_transitions` | `int` | `0` | `:114` |
| `to_dict` | `to_dict(self) -> dict[str, Any]` | — | `:116` |

#### `EpochModel` — plain class, `epoch/model.py:136`

| Member | Full signature | Behaviour | file:line |
|---|---|---|---|
| `__init__` | `__init__(self, *, identity: SystemIdentity, now_ns: int = 0, max_history: int = 16)` | `identity` is keyword-only and required. The first epoch is **id `0`**; `_next_id` starts at `1` | `:139` |
| `current` | `@property current(self) -> Epoch` | — | `:149` |
| `epoch_id` | `@property epoch_id(self) -> int` | — | `:153` |
| `rejected_transitions` | `@property rejected_transitions(self) -> int` | Count of `REJECTED_NO_CORROBORATION` outcomes | `:157` |
| `record_transition` | `record_transition(self) -> None` | Replaces `_current` with a copy whose `observed_transitions` is +1. **Caller-driven; `evaluate` never calls it** (MEASURED) | `:161` |
| `evaluate` | `evaluate(self, *, observed_identity: SystemIdentity, corroborating_evidence: frozenset[str] \| set[str], now_ns: int, behavioural_novelty: float = 0.0) -> EpochDecision` | **All keyword-only.** `behavioural_novelty` is accepted and then never read — it exists so the signature documents the rule. Logic: no change → `UNCHANGED`; `changed & corroborating_evidence` empty → `REJECTED_NO_CORROBORATION` (+1 to the counter, epoch unchanged); otherwise `_open` | `:170` |
| `_open` | `_open(self, identity, changed, corroborated, now_ns) -> EpochDecision` | Archives the closing epoch into `_history`, trims with `while len(_history) > max_history: popitem(last=False)`, allocates `_next_id`, resets `observed_transitions` to `0` | `:218` |
| `retained_history` | `@property retained_history(self) -> tuple[dict[str, Any], ...]` | Dicts of `{"epoch_id", "key", "observed_transitions", "closed_at_ns"}`, oldest first | `:251` |
| `to_dict` | `to_dict(self) -> dict[str, Any]` | `{"current", "retained_history", "rejected_transitions"}` | `:263` |

MEASURED transcript: initial `epoch_id 0`; a `package_digest` change with empty corroboration →
`reason "REJECTED_NO_CORROBORATION"`, `epoch_id` stays `0`, `rejected_transitions == 1`; the same
change with `corroborating_evidence={"package_digest"}` → `reason "SYSTEM_CHANGE_CORROBORATED"`,
`epoch_id == 1`, `retained_history == ({"epoch_id": 0, "key": "e34a7a2052aa6bca",
"observed_transitions": 1, "closed_at_ns": 20},)`.

### 2.5 `pocketsec/stage1/novelty/engine.py`

`__all__` (line 29): `NOVELTY_CONTEXTS`, `NoveltyEngine`, `NoveltyTensor`. `NoveltyBudget` is
**not** in `__all__` but is the only way to configure the engine.

| Symbol | Signature / value | file:line |
|---|---|---|
| `NOVELTY_CONTEXTS` | `tuple[str, ...]` = `("host", "user", "actor", "parent_child", "object", "relation", "time", "causal")` — **order frozen**, the SSIR binary layout and `stage2/encoder/ssir_encoder.py:224` index into it | `novelty/engine.py:33` |

#### `NoveltyTensor` — `@dataclass(frozen=True, slots=True)`, `novelty/engine.py:46`

| Member | Signature | Behaviour | file:line |
|---|---|---|---|
| `values` | `values: dict[str, float]` | Sole field, so `NoveltyTensor({...})` works positionally | `:49` |
| `__post_init__` | `__post_init__(self) -> None` | Raises `ValueError(f"novelty tensor missing contexts: {sorted(missing)}")` if any of the 8 contexts is absent, and `ValueError(f"novelty[{context}] must be in [0, 1], got {value!r}")` if any value falls outside `[0, 1]`. Then shallow-copies the dict (both MEASURED) | `:51` |
| `__getitem__` | `__getitem__(self, context: str) -> float` | Plain `dict` lookup → `KeyError` for an unknown context | `:60` |
| `peak` | `@property peak(self) -> float` | `max` — deliberately not the mean | `:64` |
| `mean` | `@property mean(self) -> float` | — | `:74` |
| `quantised` | `quantised(self, context: str) -> int` | `min(255, int(round(value * 255)))` — the uint8 the SSIR layout carries | `:77` |
| `to_dict` | `to_dict(self) -> dict[str, Any]` | `{"values": {...4dp}, "peak": float, "mean": float}` | `:81` |

Hashable: **no** (MEASURED — `dict` field).

#### `NoveltyBudget` — `@dataclass(frozen=True, slots=True)`, `novelty/engine.py:90`

| Field | Type | Default | file:line |
|---|---|---|---|
| `lru_capacity` | `int` | `512` | `:97` |
| `sketch_width` | `int` | `512` | `:98` |
| `sketch_depth` | `int` | `4` | `:99` |
| `bloom_cells` | `int` | `4096` | `:100` |

#### `NoveltyEngine` — plain class, `novelty/engine.py:103`

| Member | Full signature | Behaviour | file:line |
|---|---|---|---|
| `__init__` | `__init__(self, budget: NoveltyBudget \| None = None) -> None` | `budget` is **positional-or-keyword** (unlike most of this subsystem). Builds one `BoundedLRUCounter`, `CountMinSketch` and `StableBloomFilter` per context — 24 structures | `:112` |
| `observations` | `@property observations(self) -> int` | Number of `observe` calls, **not** number of keys learned | `:126` |
| `memory_bytes` | `@property memory_bytes(self) -> int` | Sum of the three tiers across all 8 contexts. MEASURED for a default-budget engine with nothing observed: `163840` (160 KiB) | `:130` |
| `score` | `score(self, keys: dict[str, str]) -> NoveltyTensor` | Query; missing contexts default to `""`. Does not change counts or `observations` — but see Trap 12 | `:139` |
| `observe` | `observe(self, keys: dict[str, str]) -> NoveltyTensor` | **Scores first, then learns.** Skips any context whose key is falsy (`if not key: continue`), so an empty key is never learned. Always increments `observations` | `:145` |
| `_novelty_of` | `_novelty_of(self, context: str, key: str) -> float` | `""` → `1.0`; LRU count `> 0` → `1.0 / (1.0 + exact)`; Bloom says unseen → `1.0`; else sketch estimate → `1.0 / (1.0 + estimate)` if `> 0` else `1.0`. **Never returns 0.0** | `:162` |
| `stats` | `stats(self) -> dict[str, Any]` | `{"observations", "memory_bytes", "contexts": {ctx: {"exact", "sketch", "seen"}}}` | `:182` |

MEASURED novelty decay for one repeated key: first `observe` → `1.0`, second → `0.5`, subsequent
`score` → `0.3333…`; `quantised("host")` of `0.3333` → `85`. `score({})` → all eight contexts
`1.0`.

### 2.6 `pocketsec/stage1/novelty/sketches.py`

`__all__` (line 20): `BoundedLRUCounter`, `CountMinSketch`, `EWMA`, `StableBloomFilter`.
`_hashes(key: str, count: int, modulus: int) -> list[int]` at `:23` is private: one SHA-256 digest
sliced into 4-byte big-endian words, re-hashed for more material when needed.

#### `CountMinSketch` — `novelty/sketches.py:39`

| Member | Full signature | Behaviour | file:line |
|---|---|---|---|
| `__init__` | `__init__(self, *, width: int = 512, depth: int = 4) -> None` | `ValueError("width and depth must be >= 1")` (MEASURED) | `:49` |
| `total` | `@property total(self) -> int` | Sum of all added counts | `:58` |
| `memory_bytes` | `@property memory_bytes(self) -> int` | `width * depth * 8` — a declared bound, constant under load | `:62` |
| `add` | `add(self, key: str, count: int = 1) -> None` | — | `:66` |
| `estimate` | `estimate(self, key: str) -> int` | Row minimum. **Over-estimates, never under-estimates**; MEASURED: a never-added key returned `18` on a `width=8, depth=2` sketch after 200 distinct keys | `:71` |
| `relative_frequency` | `relative_frequency(self, key: str) -> float` | `estimate / total`, `0.0` when `total == 0` | `:78` |
| `error_bound` | `error_bound(self) -> float` | `math.e / width * total` | `:83` |
| `to_dict` | `to_dict(self) -> dict[str, Any]` | `{"width", "depth", "total", "memory_bytes", "error_bound"}` | `:87` |

#### `StableBloomFilter` — `novelty/sketches.py:97`

| Member | Full signature | Behaviour | file:line |
|---|---|---|---|
| `__init__` | `__init__(self, *, cells: int = 4096, hashes: int = 4, max_value: int = 3, decay: int \| None = None)` | `ValueError("cells and hashes must be >= 1")`. `decay` defaults to `hashes * max_value` (MEASURED: `12` at defaults) | `:107` |
| `memory_bytes` | `@property memory_bytes(self) -> int` | `cells` (a `bytearray`) | `:130` |
| `_decay_cells` | `_decay_cells(self) -> None` | Decrements `decay` cells along a **deterministic rotating cursor** — no randomness, for reproducibility | `:133` |
| `add` | `add(self, key: str) -> None` | Decays **first**, then sets `hashes` cells to `max_value`, so a just-added key always reads `seen` (MEASURED) | `:144` |
| `seen` | `seen(self, key: str) -> bool` | `all(cell > 0)` over the key's cells | `:150` |
| `add_and_check` | `add_and_check(self, key: str) -> bool` | Returns whether it **was** present, then records | `:153` |
| `fill_rate` | `@property fill_rate(self) -> float` | Fraction of non-zero cells | `:160` |
| `false_positive_rate` | `@property false_positive_rate(self) -> float` | `fill_rate ** hashes` | `:164` |
| `to_dict` | `to_dict(self) -> dict[str, Any]` | `{"cells", "hashes", "decay", "inserts", "fill_rate", "false_positive_rate", "memory_bytes"}` | `:174` |

#### `BoundedLRUCounter` — `novelty/sketches.py:186`

| Member | Full signature | Behaviour | file:line |
|---|---|---|---|
| `__init__` | `__init__(self, *, capacity: int = 1024) -> None` | `ValueError("capacity must be >= 1")`. Note the class default is `1024` while `NoveltyBudget.lru_capacity` is `512`, and the engine always passes the budget | `:195` |
| `evictions` | `@property evictions(self) -> int` | Cumulative | `:203` |
| `memory_bytes` | `@property memory_bytes(self) -> int` | `sum(len(key.encode("utf-8")) + 8)` — grows with key length | `:207` |
| `__len__` | `__len__(self) -> int` | Live entries | `:211` |
| `__contains__` | `__contains__(self, key: str) -> bool` | Does **not** touch recency | `:214` |
| `add` | `add(self, key: str, count: int = 1) -> None` | Existing key: `+= count` and `move_to_end`. New key: insert, then evict from the front while over capacity | `:217` |
| `get` | `get(self, key: str) -> int` | `0` for an absent/evicted key; **otherwise calls `move_to_end(key)`** — a read that mutates recency | `:227` |
| `to_dict` | `to_dict(self) -> dict[str, Any]` | `{"capacity", "live_entries", "evictions", "memory_bytes"}` | `:234` |

#### `EWMA` — `@dataclass` (**mutable**, not frozen, not slotted), `novelty/sketches.py:244`

| Member | Type / signature | Default | file:line |
|---|---|---|---|
| `alpha` | `float` | `0.1` | `:251` |
| `value` | `float` | `0.0` | `:252` |
| `initialised` | `bool` | `False` | `:253` |
| `update` | `update(self, sample: float) -> float` | First sample is taken verbatim; then `alpha * sample + (1 - alpha) * value` | `:255` |
| `memory_bytes` | `@property memory_bytes(self) -> int` | Hardcoded `24` | `:264` |

`EWMA` has **zero consumers anywhere in the repository** (verified by grep across all `*.py`). It is
available, unused, and untested by name.

---

## 3. How to construct and drive the subsystem

The snippet below was executed verbatim in the session that wrote this document; every printed
value in the comments is MEASURED, not predicted. There is no facade class here — you drive the
four parts yourself, or you use `pocketsec/stage1/pipeline.py` (`Stage1Pipeline`), which wires them
together for you and is what the gate, the guillotine and the Stage 2 fixtures all run through.

```python
from pocketsec.stage1.causal.memory import GENESIS_SIGNATURE, CausalMemory
from pocketsec.stage1.epoch.model import EpochModel, SystemIdentity
from pocketsec.stage1.novelty.engine import NOVELTY_CONTEXTS, NoveltyBudget, NoveltyEngine
from pocketsec.stage1.state.potential import calibrate, delta_phi, phi
from pocketsec.stage1.state.security_state import (
    CredentialExposure, Privilege, Reachability, SecurityStateV1, StateDelta,
)

# --- 1. one epoch, keyed on system identity (NOT on behaviour) ---------------
epoch = EpochModel(
    identity=SystemIdentity(kernel_id="6.1.0", package_digest="pkg-a"),
    now_ns=0,
)
assert epoch.epoch_id == 0                      # the initial epoch is id 0

# --- 2. per-LINEAGE state. Keep one SecurityStateV1 per causal lineage, never
#        one per host: a host aggregate saturates (ADR-0005). -----------------
before = SecurityStateV1()                      # phi(before).total == 0.0
after = before.raised_to("privilege", Privilege.ELEVATED)
delta = StateDelta.between(before, after)       # or: after.delta_from(before)
d_phi = delta_phi(before, after)                # 1.0
assert delta.dimensions == {"privilege"} and delta.bitmask() == 1

# --- 3. novelty: score-then-learn happens inside observe() -------------------
novelty = NoveltyEngine(NoveltyBudget())        # positional arg, 163840 bytes empty
tensor = novelty.observe({
    "host": "lab-host-01",
    "user": "uid:1000",
    "actor": "NETWORK_CLIENT",                  # semantics, not a binary name
    "parent_child": "1->1000",
    "object": "CREDENTIAL",
    "relation": "7",
    "time": "bucket:3",
    "causal": GENESIS_SIGNATURE,
})
assert set(tensor.values) == set(NOVELTY_CONTEXTS)
assert tensor.peak == 1.0                       # first sighting

# --- 4. causal memory: the signature is computed FOR you by record() ---------
memory = CausalMemory(capacity=512, l0_budget=64)
node = memory.record(
    parent_signature=GENESIS_SIGNATURE,         # chain root for a new lineage
    actor_semantics=frozenset({"NETWORK_CLIENT"}),
    relation=7,
    object_semantics=frozenset({"CREDENTIAL"}),
    state_delta=delta,
    delta_phi=d_phi,
    actor_identity="proc:boot-1:1000:7",
    evidence_locators=("sha256:aa",),
)
# node.signature == '67f04f2d447a2f73', node.sequence == 1, node.resolution == 0

# --- 5. next transition in the SAME lineage chains off the previous signature
after2 = (after
          .raised_to("credential", CredentialExposure.READABLE)
          .raised_to("reachability", Reachability.EXTERNAL))
node2 = memory.record(
    parent_signature=node.signature,            # <-- chain, do not reuse GENESIS
    actor_semantics=frozenset({"NETWORK_CLIENT"}),
    relation=12,
    object_semantics=frozenset({"CREDENTIAL"}),
    state_delta=StateDelta.between(after, after2),
    delta_phi=delta_phi(after, after2),         # 12.75
)
breakdown = phi(after2)
# breakdown.total == 13.75, base == 5.25, interaction_total == 8.5,
# active_interactions == ('exfiltration_triad', 'privileged_credential_access',
#                         'credential_egress')

# --- 6. count transitions into the epoch yourself; evaluate() never does -----
epoch.record_transition()
epoch.record_transition()

# --- 7. the host view is the lattice join over lineages, computed on demand --
host_state = SecurityStateV1.join(after2, SecurityStateV1())

# --- 8. an epoch change needs corroborating SYSTEM-CHANGE evidence -----------
rejected = epoch.evaluate(
    observed_identity=SystemIdentity(kernel_id="6.1.0", package_digest="ATTACKER"),
    corroborating_evidence=frozenset(),         # nothing confirms it
    now_ns=10,
    behavioural_novelty=1.0,                    # accepted and deliberately IGNORED
)
assert not rejected.transitioned and epoch.epoch_id == 0

opened = epoch.evaluate(
    observed_identity=SystemIdentity(kernel_id="6.1.0", package_digest="pkg-b"),
    corroborating_evidence={"package_digest"},  # must intersect what changed
    now_ns=20,
)
assert opened.transitioned and epoch.epoch_id == 1
assert epoch.retained_history[-1]["observed_transitions"] == 2   # compressed, not erased

# --- 9. reporting ------------------------------------------------------------
report = memory.report()          # spine, scores, total_phi_gain, retained_at_l0, compressed
cal = calibrate([(before, 0), (after2, 1)])
# cal.separation == 13.75, cal.additive_separation == 5.25, cal.composition_gain == 8.5
```

For the wired-together version, read `pipeline.py:94-206`: `Stage1Pipeline.__post_init__`
constructs the `EpochModel` and hands the `NoveltyEngine` to the `SemanticCompiler`
(`pipeline.py:95-96`), `_record_causal` (`pipeline.py:157`) converts an `SSIRTransitionV1` into a
`CausalMemory.record` call, and the compiler owns the per-lineage `SecurityStateV1` dict
(`compiler/semantic_compiler.py:89`, `:116`, `:208`) and the host join (`:109`).

---

## 4. Invariants enforced in code

| # | Invariant | Enforced at | Pinned by |
|---|---|---|---|
| 1 | Capability never decays within a lineage: a lower `raised_to` is a no-op | `state/security_state.py:151-153` | `tests/test_stage1_semantics.py::test_state_raises_are_monotone_within_a_lineage` |
| 2 | Raising to the level you already hold returns the identical object | `state/security_state.py:152` (`return self`) | `tests/test_stage1_semantics.py::test_raising_to_the_same_level_is_identity` |
| 3 | An unknown dimension **name** is refused with `ContractError` | `state/security_state.py:149-150` and `:138-139` | `tests/test_stage1_semantics.py::test_unknown_dimension_is_refused` |
| 4 | The host join is order-independent and monotone (per-dimension max) | `state/security_state.py:172-177` | `tests/test_stage1_semantics.py::test_join_is_order_independent` |
| 5 | A delta reports only *raised* dimensions; no change yields a falsy delta | `state/security_state.py:231-236`, `:194` | `tests/test_stage1_semantics.py::test_delta_reports_only_raised_dimensions`, `::test_no_change_yields_an_empty_delta` |
| 6 | The `state_delta` bitmask fits a uint16 | `state/security_state.py:243` (module-level `assert len(DIMENSIONS) <= 16`) | `tests/test_stage1_semantics.py::test_delta_bitmask_fits_a_uint16` (MEASURED: all-nine mask `511`) |
| 7 | Every dimension has a base weight — a new dimension cannot be half-added | `state/potential.py:41` vs `security_state.py:108` | `tests/test_stage1_semantics.py::test_every_dimension_has_a_base_weight` |
| 8 | Φ of the initial state is exactly 0.0 | `state/potential.py:172-177` (zero levels contribute nothing and are omitted from `base_terms`) | `tests/test_stage1_semantics.py::test_phi_of_the_initial_state_is_zero` |
| 9 | Composition exceeds the sum of its parts | `state/potential.py:181-184` | `tests/test_stage1_semantics.py::test_composition_exceeds_the_sum_of_parts` |
| 10 | Φ is not a privilege detector: root alone stays below 4.0 with no interactions | `state/potential.py:41` (`privilege: 1.0`) + every predicate needing a second dimension | `tests/test_stage1_semantics.py::test_privilege_alone_is_not_dangerous` (MEASURED: `2.0`, `()`) |
| 11 | The exfiltration triad fires only when all three conditions hold | `state/potential.py:102-107` | `tests/test_stage1_semantics.py::test_exfiltration_triad_fires_only_when_complete` |
| 12 | Φ is never a bare number — every score carries its breakdown | `state/potential.py:146-192` (`phi` returns `PhiBreakdown`, there is no scalar-only entry point) | `tests/test_stage1_semantics.py::test_phi_breakdown_explains_itself` |
| 13 | Every interaction weight has a written rationale and is positive | `state/potential.py:55-99` | `tests/test_stage1_semantics.py::test_every_interaction_has_a_documented_rationale` |
| 14 | `calibrate` refuses to report a separation without both classes | `state/potential.py:246-255` | MEASURED here: single-class input returns all-zero numbers and `notes == "insufficient labels: …"`. No dedicated test found by name. |
| 15 | Causal signatures are built from semantics only — no pid, path, inode or command line participates | `causal/memory.py:61-70` | `tests/test_stage1_bounded.py::test_causal_signature_ignores_identity` |
| 16 | Changing what an actor does changes the signature | `causal/memory.py:61-70` (relation and object semantics are in the material) | `tests/test_stage1_bounded.py::test_causal_signature_changes_with_behaviour` |
| 17 | Signatures chain through the parent, so the same step with a different history differs | `causal/memory.py:62` | `tests/test_stage1_bounded.py::test_causal_signature_chains_through_its_parent` |
| 18 | Causal memory is hard-bounded by node count | `causal/memory.py:238-243` | `tests/test_stage1_bounded.py::test_causal_memory_stays_within_capacity` |
| 19 | High-responsibility nodes survive compression; the spine stays at L0 | `causal/memory.py:226-236` (ranks by responsibility, not age) | `tests/test_stage1_bounded.py::test_high_responsibility_survives_compression` |
| 20 | Demotion to L2+ sheds identity and evidence locators but ΔΦ survives every tier | `causal/memory.py:108-119` | `tests/test_stage1_bounded.py::test_demotion_sheds_identity_at_l2` |
| 21 | `capacity` and `l0_budget` must be ≥ 1 | `causal/memory.py:164-165` | MEASURED: `ValueError("capacity and l0_budget must be >= 1")` |
| 22 | **Behavioural novelty alone can never open an epoch** | `epoch/model.py:170-216` — `behavioural_novelty` is a parameter that is never read; only `changed & corroborating_evidence` gates `_open` | `tests/test_stage1_bounded.py::test_novelty_alone_never_opens_an_epoch` |
| 23 | Corroboration must name a component that actually changed | `epoch/model.py:201` (`changed & frozenset(corroborating_evidence)`) | `tests/test_stage1_bounded.py::test_corroboration_must_match_what_changed` |
| 24 | An unchanged identity is a no-op regardless of evidence offered | `epoch/model.py:192-199` | `tests/test_stage1_bounded.py::test_unchanged_identity_is_a_no_op` |
| 25 | Epoch rotation compresses history; it never erases it | `epoch/model.py:225-230`, `:251-261` | `tests/test_stage1_bounded.py::test_epoch_rotation_compresses_history_rather_than_erasing_it` |
| 26 | Epoch history is bounded by `max_history` | `epoch/model.py:231-232` | `tests/test_stage1_bounded.py::test_epoch_history_is_bounded` |
| 27 | A novelty tensor must carry all 8 contexts, each within `[0, 1]` | `novelty/engine.py:51-58` | `tests/test_stage1_bounded.py::test_novelty_tensor_covers_every_context` |
| 28 | Scoring does not learn — `score` is a pure query with respect to counts | `novelty/engine.py:139-143` (no mutation) vs `:145-160` | `tests/test_stage1_bounded.py::test_scoring_does_not_learn` (but see Trap 12) |
| 29 | A missing context key is treated as novel (`1.0`), never as familiar | `novelty/engine.py:164-167` | `tests/test_stage1_bounded.py::test_missing_context_key_is_novel_not_familiar` |
| 30 | `peak` is max, not mean | `novelty/engine.py:71` | `tests/test_stage1_bounded.py::test_novelty_peak_is_max_not_mean` |
| 31 | Novelty memory stays bounded under a flood | `novelty/sketches.py:62-64`, `:130-131`, `:222-225` (all three tiers have declared caps) | `tests/test_stage1_bounded.py::test_novelty_memory_stays_bounded_under_flood` (asserts `< 2_000_000` bytes after 30 000 floods) |
| 32 | Count-Min never under-estimates | `novelty/sketches.py:73-76` (row minimum) | `tests/test_stage1_bounded.py::test_count_min_never_underestimates` |
| 33 | Count-Min memory is fixed under load | `novelty/sketches.py:62-64` | `tests/test_stage1_bounded.py::test_count_min_memory_is_fixed_under_load` |
| 34 | The Bloom filter does not saturate, so novelty cannot silently read zero | `novelty/sketches.py:133-148` (decay before insert) | `tests/test_stage1_bounded.py::test_stable_bloom_does_not_saturate`, `::test_stable_bloom_retains_recent_insertions` |
| 35 | The Bloom false-positive rate is measured, not assumed | `novelty/sketches.py:164-172` | `tests/test_stage1_bounded.py::test_stable_bloom_false_positive_rate_is_measured_not_assumed` (checks the estimator against an empirical count within 0.05) |
| 36 | LRU eviction is counted and evicted keys report `0`, never stale data | `novelty/sketches.py:223-232` | `tests/test_stage1_bounded.py::test_bounded_lru_evicts_and_counts`, `::test_bounded_lru_keeps_hot_keys` |
| 37 | Nothing in this subsystem produces a verdict or a fused score | Absence: no verdict/threat/action symbol exists in any of the six files (`grep`-verified) | ADR-0003 plus `tests/test_authority_boundary.py` at the contract boundary |

---

## 5. Extension points

**Sanctioned.**

1. **Read Φ, novelty and ΔΦ as three separate inputs.** `phi(state) -> PhiBreakdown`
   (`state/potential.py:170`), `delta_phi` (`:195`), `NoveltyTensor` (`novelty/engine.py:46`).
   Stage 2 already does exactly this: `stage2/encoder/ssir_encoder.py:224` iterates
   `NOVELTY_CONTEXTS` and `:68` derives its feature names from `DIMENSIONS`. Keep them separate
   signals; fusing them into one score is forbidden (README, MEMORY.md, invariant 37).
2. **Append a new dimension** by adding an `IntEnum`, an entry at the **end** of `DIMENSIONS`
   (`state/security_state.py:108`) and a matching `BASE_WEIGHTS` entry (`state/potential.py:41`).
   Appending keeps existing `state_delta` bitmasks valid; reordering breaks every stored mask and
   every Stage 2 feature vector. The `assert` at `:243` caps you at 16 dimensions.
3. **Add an interaction term** as an `Interaction` in `INTERACTIONS` (`state/potential.py:65`) plus
   a predicate registered in `_PREDICATES` (`:136`) under the identical name — `phi` looks the
   predicate up by `interaction.name` (`:182`), so a missing entry is a `KeyError` at scoring time,
   not at import. Give it a real `rationale`; a test asserts one exists.
4. **Re-measure Φ's value** with `calibrate(labelled)` (`state/potential.py:237`) rather than
   asserting it. `composition_gain <= 0` is a real result to report.
5. **Consume the causal spine** via `CausalMemory.spine(min_responsibility=...)`
   (`causal/memory.py:256`) and `report()` (`:265`). These are read-only views.
6. **Supply corroborating evidence** to `EpochModel.evaluate` (`epoch/model.py:170`) from an
   independent source — a package-manager transaction, a kernel boot, a config-management run.
   This is the one intended write path into epoch rotation.
7. **Re-budget the bounded structures** through `NoveltyBudget` (`novelty/engine.py:90`) and
   `CausalMemory(capacity=..., l0_budget=...)` (`causal/memory.py:163`), and *measure* the result
   with `NoveltyEngine.memory_bytes` (`:130`) and `CausalMemory.memory_bytes` (`:180`).
8. **`EWMA`** (`novelty/sketches.py:244`) is an unused, available primitive for bounded temporal
   statistics. It has no consumers today, so nothing depends on its current shape.

**Not an extension point.**

1. **Do not add a decay, timeout or downgrade path to `raised_to`.** Monotonicity within a lineage
   is invariant 1. Decay belongs to epoch rotation and lineage expiry, which are explicit and
   evidence-backed (`state/security_state.py:143-148`).
2. **Do not route behavioural novelty into epoch transitions.** `behavioural_novelty`
   (`epoch/model.py:176`) exists to be ignored; making it load-bearing destroys the whole
   anti-poisoning mechanism (invariant 22, ADR reference in README).
3. **Do not replace lineage-scoped state with a host-wide state.** ADR-0005. The host view is the
   on-demand join (`state/security_state.py:165`, `compiler/semantic_compiler.py:109`). A host-only
   state saturates and makes ΔΦ, and therefore responsibility scoring, meaningless.
4. **Do not reorder `DIMENSIONS` or `NOVELTY_CONTEXTS`.** Both orders are frozen by the SSIR v1
   binary layout (`state/security_state.py:105-107`, `novelty/engine.py:31-32`).
5. **Do not put identity into `causal_signature`.** No pid, path, inode, command line or
   `display_name` (ADR-0006, ADR-0007). The renamed-tool property depends on it.
6. **Do not mutate `CausalMemory._nodes`, `SemanticCompiler._lineage_state` or `EpochModel._current`
   from outside.** There is no public setter for any of them by design; `record_transition`
   (`epoch/model.py:161`) and `record` (`causal/memory.py:187`) are the only write paths.
7. **Do not make `phi` return a bare float** or add a `threat_score`. Invariant 12 and ADR-0003.
8. **Do not treat `memory_bytes` as an authority for a resource claim.** Both implementations
   (`causal/memory.py:180`, `novelty/sketches.py:207`) are declared estimates. Resource claims go
   through `pocketsec.stage0.benchmark.harness.run_benchmark`.

---

## 6. Traps — concrete ways to get silently wrong results

Each trap below was reproduced by running code in this session; the reproduction is stated.

**Trap 1 — `raised_to` does not validate that the level belongs to the dimension's lattice.**
`state/security_state.py:141` checks only the dimension *name* and then compares `int(level)`.
MEASURED: `SecurityStateV1().raised_to("privilege", CredentialExposure.EXTRACTED)` produces a state
whose `privilege` is `<CredentialExposure.EXTRACTED: 3>`, `level("privilege") == 3` (off the end of
a 3-member lattice), `to_dict()["privilege"] == "EXTRACTED"`, and `phi(...)` happily returns `3.0`.
A raw int is worse: `raised_to("privilege", 99)` is accepted, `level()` returns `99`, and the state
only explodes later — `to_dict()` raises `AttributeError: 'int' object has no attribute 'name'`,
possibly in a serializer far from the bug. Always pass the enum member for that dimension. If you
build raises from a table, cross-check against `DIMENSIONS[name]`.

**Trap 2 — `StateDelta`, `NoveltyTensor` and `PhiBreakdown` are `frozen=True` but unhashable.**
MEASURED: `hash(StateDelta.empty())` → `TypeError: unhashable type: 'dict'`; likewise
`NoveltyTensor` and `PhiBreakdown`. `SecurityStateV1` and `CausalNode` *are* hashable. So a cache
keyed on a state works and the same cache keyed on a delta or a tensor raises at runtime, not at
import.

**Trap 3 — `StateDelta.raised` is a live mutable dict behind a frozen facade.**
`__post_init__` (`:191`) copies the caller's dict once, so later mutating *your* source dict is
safe (MEASURED). But `delta.raised["anything"] = (0, 3)` after construction succeeds and is
observed by `magnitude`, `dimensions` and `to_dict`. Worse, the accessors disagree about unknown
keys: MEASURED for `StateDelta({"privilege": (0, 1), "telepathy": (0, 3)})` → `magnitude == 4`
(counts the bogus dimension), `bitmask() == 1` (silently drops it), `dimensions` reports both. A
typo'd dimension name therefore inflates magnitude, vanishes from the bitmask, and changes the
causal signature only through the bitmask — no exception anywhere.

**Trap 4 — `delta_from` reads backwards from how it looks.**
`current.delta_from(previous)` (`:155`). MEASURED: `b.delta_from(a)` where `b` is the *later* state
yields the raise; `a.delta_from(b)` yields an empty delta. Reversing the receiver gives you a
silently empty delta, which the aggregation policy reads as "safely coalescible".

**Trap 5 — ΔΦ is not derivable from `StateDelta`, and `StateDelta` is not derivable from ΔΦ.**
`CausalNode` stores `delta_phi` and `state_delta_mask` but no absolute Φ (`causal/memory.py:90-94`).
You cannot reconstruct Φ before or after from a node. If you need absolute Φ downstream, carry it
yourself; recomputing `phi()` from a *current* state and subtracting a node's `delta_phi` does not
reconstruct history because other lineages moved in between.

**Trap 6 — the causal signature sees only the delta's *bitmask*, not its magnitude.**
`causal/memory.py:61-70` hashes `str(state_delta.bitmask())`. MEASURED: with everything else equal,
`StateDelta({"credential": (0, 2)})` (read) and `StateDelta({"credential": (0, 3)})` (extracted)
produce the **identical** signature `196dc57a6a9c4e15`. Reading a credential and exfiltrating one
are the same route as far as the signature is concerned. Do not use signature equality as evidence
that two transitions were equally severe.

**Trap 7 — a duplicate signature silently overwrites a node, and its ΔΦ with it.**
`record` stores into `self._nodes[signature]` (`causal/memory.py:218`). MEASURED: two records with
identical `(parent_signature, actor_semantics, relation, object_semantics, bitmask)` but
`delta_phi=5.0` then `delta_phi=0.0` leave `len(memory) == 1`, the stored score `0.0`,
`total_phi_gain 0.0` and an **empty spine** — the responsible transition is gone, `dropped` stays
`0`, and nothing reports a loss. Because the signature deliberately excludes identity and
magnitude, this collides in exactly the common case: an actor repeating the same operation on the
same object class within a lineage. The internal sequence counter does advance (MEASURED `(1, 2)`),
so `len(memory)` and the sequence numbers disagree; that discrepancy is your only clue.

**Trap 8 — among equally irresponsible nodes, capacity eviction drops the NEWEST, not the oldest.**
The victim is `min(..., key=lambda n: (self.responsibility(n), -n.sequence))`
(`causal/memory.py:239-241`); minimising `-sequence` maximises `sequence`. MEASURED with
`capacity=4, l0_budget=2` and 12 zero-ΔΦ records: the survivors are sequences `[1, 2, 3, 4]` and
`dropped == 8`. So a flood of zero-responsibility events keeps the first four forever and discards
everything recent. (With varying ΔΦ the intended behaviour holds: MEASURED survivors `[8.0, 9.0,
10.0, 11.0]` for ΔΦ `= i`.) If you rely on "recent zero-ΔΦ context is still there", it is not.
Note the demotion pass on line 227 sorts by `(responsibility, n.sequence)` — oldest-first — so the
two passes tie-break in *opposite* directions.

**Trap 9 — `_rebalance` runs on every `record` and dominates its cost.**
`causal/memory.py:220` calls `_rebalance` unconditionally; `_rebalance` sorts every live node and
then runs a `min` over every live node per eviction. MEASURED in this session, 2000 records,
same machine, same process: `capacity=1_000_000, l0_budget=1_000_000` (no rebalance work)
**4.59 µs/record**; `capacity=512, l0_budget=512` **120.45 µs/record**; `capacity=512,
l0_budget=64` (close to the defaults) **197.38 µs/record**; `capacity=64, l0_budget=64`
**25.62 µs/record**. That is a ~43× difference driven purely by retention settings, on a hot path
that runs once per transition. Budget for it; do not assume `record` is cheap. (Absolute numbers are
machine- and interpreter-specific — Python 3.14 here — and are not a published benchmark result.)

**Trap 10 — `memory_bytes` is an estimate that ignores the Python object graph.**
`causal/memory.py:180-185` charges a flat 64 bytes per node plus string lengths; MEASURED: an empty
`CausalMemory` reports `0`, and 512 nodes reported `32768`. `BoundedLRUCounter.memory_bytes`
(`sketches.py:207`) counts key bytes + 8, ignoring the `OrderedDict`. Real RSS is larger. Never
present these as measured memory usage.

**Trap 11 — novelty never reaches 0.0, and a forgotten key jumps back to 1.0.**
`_novelty_of` (`novelty/engine.py:162-180`) returns `1/(1+count)`. MEASURED: after 1000
observations of one key, novelty is `0.000999…`, never `0.0` — so a threshold written as
`novelty == 0` never fires and `novelty > 0` is always true. Worse, after the LRU evicted that key
and the stable Bloom decayed it (MEASURED with `lru_capacity=4, bloom_cells=64` plus 500 flood
keys), the same key scores **`1.0` again**: "never seen" and "forgotten under pressure" are
**indistinguishable in the return value**. The only way to tell them apart is out-of-band —
`BoundedLRUCounter.evictions` (MEASURED `497`) and `StableBloomFilter.fill_rate` /
`false_positive_rate` (MEASURED `0.609` / `0.138`). A flood is therefore a novelty-inflation
primitive, and nothing in the tensor says so.

**Trap 12 — `score()` is documented as a pure query but mutates LRU recency.**
`NoveltyEngine._novelty_of` calls `BoundedLRUCounter.get` (`novelty/engine.py:169`), and `get`
calls `self._counts.move_to_end(key)` (`novelty/sketches.py:231`). Counts and `observations` are
untouched — `tests/test_stage1_bounded.py::test_scoring_does_not_learn` checks only those — but the
eviction order changes. MEASURED with `lru_capacity=2`, after `observe(A)`, `observe(B)`,
`observe(C)`: with an intervening `score({"host": "A"})`, `A` stays live and `B` is evicted; without
it, `A` is evicted and `B` stays live. In that probe both keys still scored `0.5` afterwards
(the Count-Min estimate happened to equal the exact count), so the effect was silent. Speculative
scoring is therefore not free: it reshapes which keys hold the exact tier, and combined with Trap 11
it can move a key onto the approximate path where Bloom decay makes it read `1.0`.

**Trap 13 — `observe` silently skips empty-string keys while still counting the observation.**
`novelty/engine.py:154-155` (`if not key: continue`) with `:159` incrementing unconditionally.
MEASURED: five `observe({"host": "", "user": "u"})` calls leave `observations == 5`, `user` novelty
at `0.1667`, and `host` novelty for `""` still `1.0` forever. A context you fail to populate looks
permanently maximally novel and inflates `peak` on every transition. `score({})` returns all eight
contexts at `1.0` (MEASURED), which is the by-design "missing information is not familiarity" rule —
but it means a caller with a typo'd key name gets a maximal novelty signal instead of an error.

**Trap 14 — `NoveltyTensor` validates only at construction, and `values` is a copied-but-mutable dict.**
MEASURED: `NoveltyTensor({"host": 0.5})` raises
`ValueError: novelty tensor missing contexts: ['actor', 'causal', 'object', 'parent_child',
'relation', 'time', 'user']`, and an out-of-range value raises
`ValueError: novelty[host] must be in [0, 1], got 1.5`. Post-construction mutation of `.values` is
not re-validated, and `__getitem__` (`:60`) raises a bare `KeyError` for an unknown context rather
than a `ContractError`.

**Trap 15 — `EpochModel.evaluate` never counts transitions, and never adopts a rejected identity.**
MEASURED: three `evaluate` calls leave `current.observed_transitions == 0`; you must call
`record_transition()` yourself (`epoch/model.py:161`, as `pipeline.py:137` does). Separately, after a
`REJECTED_NO_CORROBORATION`, the model still holds the **old** identity (MEASURED
`package_digest == "p1"` after observing `"p2"`), so the very next `evaluate` with the same observed
identity re-reports the same change — and if corroboration arrives later, it is accepted then
(MEASURED `transitioned == True`). Do not treat a rejection as a decision that has been settled;
it repeats on every subsequent evaluation and re-increments `rejected_transitions`.

**Trap 16 — `EpochTransitionReason.INITIAL` is never emitted by `evaluate`.**
MEASURED: a first `evaluate` against the construction identity returns `UNCHANGED`, not `INITIAL`.
`INITIAL` exists in the enum (`epoch/model.py:48`) and is unused in the module. A state machine that
waits for `INITIAL` waits forever. Use `transitioned` (`:91`) or compare `reason`, never assume the
four values are all reachable.

**Trap 17 — `SystemIdentity()` with everything unknown is a valid, shared epoch key.**
MEASURED: `SystemIdentity().key() == "1867f76f89b18a0f"`. There is no "identity unknown" state, so
a sensor that fails to populate identity silently groups every such host into one epoch, and no
component ever becomes `changed`, so no rotation can ever occur. Populate the components or track
the gap yourself.

**Trap 18 — `CausalResolution` values are plain ints and `demote` is one-way.**
`causal/memory.py:73-79` is not an `Enum`, so `demote(2)` type-checks and `node.resolution == 2`
compares equal to `CausalResolution.L2_FINGERPRINT` — the existing tests use bare `0`/`2` literals.
MEASURED: `node.demote(2).demote(0).resolution == 2` — demoting back toward L0 is a silent no-op
returning the coarse node, so a "restore fidelity" call looks like it worked. L3 also strips
identity and locators (MEASURED `actor_identity == ""`), same as L2.

**Trap 19 — responsibility clamps negative ΔΦ to zero, and Φ can only ever rise within a lineage.**
`CausalMemory.responsibility` is `max(0.0, node.delta_phi)` (`:246-254`). Within a single lineage,
monotone raises mean ΔΦ ≥ 0 anyway; but if you ever feed `record` a ΔΦ computed across *different*
lineages or across an epoch rotation, a negative value is silently flattened to `0.0`, which makes
the node the first candidate for demotion and then for eviction. Compute ΔΦ from the before/after
state of **one** lineage, as `compiler/semantic_compiler.py:302` does.

**Trap 20 — lineage state persists across scenarios on a shared pipeline.**
Not a bug in these four modules, but the failure they are most often blamed for. The compiler keys
state on a lineage string (`compiler/semantic_compiler.py:89`, `:116`) and the `NoveltyEngine` and
`CausalMemory` are pipeline-level (`pipeline.py:87-88`). MEMORY.md records this as a corpus trap
that already produced a retracted Stage 2 result: reusing process identities between sessions makes
carried-forward lineage state saturate, and median ΔΦ collapses to 0.00 for *both* classes. Give
each scenario distinct process identities, or a fresh pipeline.

**Trap 21 — `GENESIS_SIGNATURE` is duplicated as a literal in the compiler.**
`causal/memory.py:44` defines `"0" * 16`; `compiler/semantic_compiler.py:292` hardcodes `"0" * 16`
independently instead of importing it. They agree today. Changing the constant in one place
silently unroots every chain built by the other.

**Trap 22 — the sketch tier over-estimates, which always errs toward "familiar".**
MEASURED on a deliberately tiny `CountMinSketch(width=8, depth=2)` after 200 distinct keys: a
never-added key estimates `18` and `error_bound()` is `67.96`. Through `_novelty_of`
(`novelty/engine.py:179-180`) that becomes novelty `1/19 ≈ 0.053` for something never seen — but
only for keys the Bloom filter also false-positives on, since the Bloom check runs first (`:175`).
The documented failure direction is a *missed* novelty signal, never a fabricated one; it is only
safe while `false_positive_rate` stays small, which you must read and report
(`novelty/sketches.py:164`), not assume.

**Trap 23 — `CausalMemory` accepts `l0_budget > capacity` without complaint.**
MEASURED: `CausalMemory(capacity=2, l0_budget=100)` constructs with exactly those values. The L0
demotion pass then never triggers (`len` can never exceed `l0_budget`), so every retained node stays
at L0 and the only bounding mechanism is capacity eviction — you lose the compression tier entirely
while `retained_at_l0` looks healthy.

**Trap 24 — the `__init__.py` files are empty, and several needed symbols are absent from `__all__`.**
All four package `__init__.py` files are 0 bytes (MEASURED: `dir(pocketsec.stage1.state)` exposes
only the submodule names `potential` and `security_state`). Import from the full module path. Also
`NoveltyBudget`, `CalibrationReport`, `Interaction`, `Epoch` and `GENESIS_SIGNATURE` are public in
practice but missing from their modules' `__all__`, so a `from … import *` style or a re-export
audit will drop exactly the symbols you need to configure and interpret the subsystem.

**Trap 25 — `NoveltyEngine.__init__` takes its budget positionally; most other constructors here are keyword-only.**
`NoveltyEngine(budget)` works (`novelty/engine.py:112`), while `CausalMemory`, `EpochModel`,
`CountMinSketch`, `StableBloomFilter`, `BoundedLRUCounter`, `causal_signature`,
`CausalMemory.record`, `CausalMemory.spine` and `EpochModel.evaluate` are all keyword-only. And
`BoundedLRUCounter`'s own default capacity is `1024` while `NoveltyBudget.lru_capacity` is `512`, so
the tier's effective size depends on who constructed it.

---

## 7. What this document does not claim

- No detection quality, PR-AUC or resource-envelope claim is made here. The Φ values, novelty
  values, signature hex strings and timings above were produced by executing these modules in one
  session on one machine with Python 3.14 and are reproducible properties of the code, not
  benchmark results. Anything a benchmark would have to establish goes through
  `pocketsec.stage0.benchmark.harness.run_benchmark`.
- Whether Φ's weights are *good* is UNMEASURED by this document; `calibrate`
  (`state/potential.py:237`) is the instrument, and MEMORY.md records the corpus-level result
  separately.
- `ruff` and `mypy` have never been run on this repository (MEMORY.md, "Known gap"), so the type
  annotations quoted above are unverified by a type checker; they are quoted as written.
