# ADR-0118 — `CompileCandidateV1`, and the Φ-oracle as a first-class zero-parameter candidate

- **Status:** Accepted
- **Date:** 2026-09-24
- **Stage:** 2
- **Deciders:** Stage 2 completion wave, `export` work package
- **Extends:** ADR-0001 (stdlib-only runtime), ADR-0003 (predictions carry no
  authority), ADR-0008 (research boundary), ADR-0114 (honest path accounting).
  **Informed by:** ADR-0009, ADR-0010, `docs/stage-2-dtl-findings.md`.

## Context

Stage 3 crystallises what Stage 2 exports, so the export format decides what
Stage 3 can ever be. Two facts already in this repository constrain it, and
neither was produced in this session:

1. **The learned core is dominated.** ADR-0010: at equal detection (1.0000) the
   TCN costs 6.6 µs/event against DTL-C's 22.3 at 2.8× the parameters. Best
   DTL-C 0.8137 vs best baseline (mlp-pooled) 0.8060 at 4× the parameters →
   `COMPARABLE_BUT_COSTLIER`.
2. **A zero-parameter scorer solves most of the task.** Stage 1's Φ-oracle
   reaches **0.7484 PR-AUC with 0 parameters and ~0 µs/event**
   (`planning/MEMORY.md`). Integration plan §6.3 therefore names the Φ-oracle as
   Stage 3's **first** crystallisation target.

A compile format designed around frozen neural weights would make the *cheapest
and best-measured* artefact in the project a special case — a "neural region"
with zero weights, an empty validity boundary and no honest place to put an
expression. It would also make the compilation thesis untestable: if the format
cannot carry a rule that is already a rule, there is nothing to crystallise that
beats what Stage 1 computes for free.

Separately, ADR-0010 recorded the router reporting 100 % cheap-path resolution
while computing every branch. D2.13's cache sits one stage closer to the hub than
that router did, so it needs the same discipline: a saving must be provable.

## Decision

**1. `CandidateKind.DETERMINISTIC_SCORER` is a first-class kind**, listed first,
with its own payload shape (`DeterministicScorerSpec`: feature index,
aggregation, optional threshold, human-readable expression). It is the only kind
for which `MeasuredCost.microseconds_per_event is None` is constructible, because
~0 µs is a real answer for a zero-parameter rule — and the **exporter refuses it
anyway**, so an untimed oracle still never reaches Stage 3.

**2. A candidate with no recorded measurement is rejectable by construction.**
`CompileCandidateV1.__post_init__` raises `ContractError` when
`evidence_lineage` is empty, when `experiment_id` does not parse through
`stage0.experiments.ids`, when `microseconds_per_event is None` for anything but
a deterministic scorer, when any payload key (recursively, lowercased) matches
`FORBIDDEN_AUTHORITY_FIELDS`, or when the payload is not strict JSON
(`allow_nan=False`). `MeasuredCost` raises on a `measured_by` that is not
`module:function`.

**3. `ValidityBoundary.unseen_input_behaviour` may only be `"ABSTAIN"`.** Not a
default — the only accepted value. An empty boundary contains nothing and is
refused by the exporter rather than treated as permissive.

**4. The Φ feature index is pinned, not re-derived.** `PHI_SQUASHED_FEATURE_INDEX
= 73` is the **squashed absolute** ΔΦ, `abs(phi)/(abs(phi)+8.0)`
(`encoder/ssir_encoder.py:221`); the sign bit at index 74 is deliberately not
read. The module raises at import if the encoder layout no longer agrees, so a
layout change breaks loudly instead of silently reproducing 0.7484 against a
different feature.

**5. Nothing but plain data crosses the seam.** `Stage3Handoff` members are
`Mapping[str, Any]` of JSON values; `to_dict()` refuses to emit a payload whose
keys name a Stage 2 class (`FORBIDDEN_SEAM_TOKENS`); `write_handoff` returns a
`sha256:` digest of canonical bytes. An AST test asserts no module under
`cache/` or `compile_candidates/` imports anything matching `research`.

**6. The cache claims no saving it cannot prove.** `TransitionCache` records
`CACHE_LOOKUP performed=True` and, **only on a hit**, `CORE_INFERENCE
performed=False` on a `WorkLedger`. With no ledger it reports
`proven_skipped_units == 0.0` however many hits it served. A stale
`model_version` or `encoder_version` is a miss counted as a `version_rejection`,
and the stale entry is dropped.

**7. LRU remains the recommended eviction default.** See the measured split
below. `forget_low_utility_memory` ships, next to its two controls, as a
mechanism that is **NOT_YET_JUSTIFIED** — not as a default.

## Options considered

| Option | Security cost | Resource cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|---|
| **A. Weights-only format (neural regions only)** | High: the best-measured artefact in the project cannot be expressed, so Stage 3 compiles only the dominated mechanism | Every compiled artefact carries parameters | low | **Measured (existing, ADR-0010/MEMORY.md):** the only candidates it can carry are DTL-C at 22.3 µs/event and 4× params for 0.8137, versus a 0-parameter 0.7484. Strictly worse Pareto | Rejected. It would compile the thing that lost |
| **B. Deterministic scorer as a degenerate neural region** | Medium: the boundary and cost fields stop meaning what they say (0 parameters, no weights file, no epochs) | same as C | lower than C by one enum member | **Measured this session:** a `NEURAL_REGION` with `microseconds_per_event=None` raises; forcing the oracle into that kind would have required either a fabricated timing or weakening the UNMEASURED rule for every neural candidate | Rejected. It buys one enum member by making the measurement rule weaker for everything |
| **C. Deterministic scorer as a first-class kind (chosen)** | None added. Carries no authority field; payload authority names refused recursively | **Measured this session:** exported Φ-oracle candidate file 2 575 B, handoff 3 676 B; full 1024-entry cache 287 744 B (281.0 KB) | moderate: 4 modules, 1 365 lines across `candidate/exporter/phi_oracle_candidate/stage3_interface` | **Measured this session:** the Φ-oracle round-trips `to_dict`/`from_dict` exactly, exports with **zero refusals**, and Stage 3 rebuilds the scorer from plain JSON and reproduces its score — `test_stage3_can_compile_a_rule_that_is_already_a_rule` | Chosen |
| **D. Trust the caller; validate at Stage 3** | High: an unattributable or unmeasured candidate would be discovered one stage later, after compilation | 0 | lowest | **Measured this session:** 31 `pytest.raises` refusal assertions fire in `tests/test_stage2_export.py` (empty lineage, unparseable id, `None` µs, malformed `measured_by`, 12 authority tokens, non-JSON payload, `GUESS`, foreign encoder, empty boundary, unstable, duplicate, overflow). Every one of those would have become a Stage 3 defect | Rejected |
| **E. Utility-based forgetting as the cache default** | Medium: on a recency-driven workload it forgets what is about to be asked for | **Measured this session (4 000 accesses, 256 keys, keep=64, seeds fixed): hit rate 0.27350 vs LRU 0.74425 — −0.471** | moderate | On a consequence-correlated workload it wins: **0.41325 vs LRU 0.31525, +0.098**. The sign of the effect is a property of the workload, not of the mechanism | Rejected as a default; retained as an explicitly NOT_YET_JUSTIFIED option |
| **F. `assert_no_phantom_savings()` on every cache hit** | None — strictly safer | **Measured this session: 3.9 ms per call at 2 000 retained accounts, 20.9 ms at 4 096** — the P0 path would be quadratic in retained accounts | low | Would have made the cheapest path in the system the most expensive | Rejected. The phantom check is a per-run assertion (G2.3/G2.10), and the derived `ExecutionPath` already refuses to look cheap over performed inference |

The simplest option (D) was rejected because it moves every failure one stage
downstream, where the artefact has already been compiled.

## Measurements produced in this session

Host: Python 3.14.7, Linux 7.1.5+kali-amd64. **Load average during timing:
37.87** (seven other work packages building concurrently), so every wall-clock
figure below is an **upper bound** and is reported as min-of-repetitions.

| Figure | Value | How |
|---|---|---|
| Φ-oracle candidate file, on disk | **2 575 B** | `ExportReport.total_bytes`, 3 evidence refs |
| Stage 3 handoff, on disk | **3 676 B** | `write_handoff` then `stat().st_size` |
| Full 1024-entry cache, memory | **287 744 B (281.0 KB)** | `CacheStats.memory_bytes`, computed per entry, asserted by test |
| P0 cache lookup, no ledger | **9.867 µs/event** | min of 7 × 5 000 lookups on a full cache |
| P0 cache lookup, ledger-proven | **19.706 µs/event** | same, with `begin`/`record`×2/`close` per event |
| `assert_no_phantom_savings()` | **3.9 ms** at 2 000 accounts, **20.9 ms** at 4 096 | `perf_counter` around the call |
| Forgetting, consequence-correlated reuse | utility **0.41325**, LRU **0.31525**, random **0.31650** | `test_utility_forgetting_measured_against_lru_and_random` |
| Forgetting, recency-driven reuse | utility **0.27350**, LRU **0.74425**, random **0.72075** | same test |

**Not measured, and therefore not claimed:** whether the P0 cache is cheaper than
the `CORE_INFERENCE` it avoids. The TCN's 6.6 µs/event comes from an earlier
session under unknown load and `CORE_INFERENCE` itself lives in `predictors`, so
comparing 9.867 against 6.6 would be comparing two different machines' moods. The
Pareto comparison belongs to the `report` package, measured in one run.
`PATH_COST_UNITS` also remains uncalibrated (ADR-0114), so
`proven_skipped_units` is a policy-unit figure and `CacheStats.to_dict()` emits
`"path_cost_units_calibrated": false`.

## Consequences

**Accepted costs.** Every candidate producer must carry an experiment id and a
`module:function` that measured its cost. That is intrusive, and it is the point:
the alternative is a candidate that cannot be traced to a number.

The payload is normalised through JSON at construction, so a caller's tuple
becomes a list. That is what makes `from_dict(to_dict(c)) == c` exact on both
sides of the seam, and it means a payload is JSON-shaped from the moment it
exists rather than at write time.

`CompileCandidateV1` is not hashable (its payload is a mapping). It is compared
by value and identified by `candidate_id`.

**Bounded state.** `MAX_CACHE_ENTRIES = 1024`, enforced through Stage 1's
`BoundedLRUCounter` rather than a second LRU implementation; every removal —
capacity, epoch invalidation, utility forgetting — is counted in
`CacheStats.evictions`. `export_candidates` caps at 256 and **refuses** the
overflow with a reason instead of truncating silently.

**Reversibility.** Both schemas are additive and newly registered at 1.0.0.
Removing the deterministic-scorer kind would refute the compilation path rather
than simplify it; removing `forget_low_utility_memory` costs nothing measured, and
this ADR recommends LRU until real telemetry shows consequence-correlated reuse.

**Authority.** None. A candidate is data Stage 3 may compile; a
`Stage3Handoff` is JSON. `EvidenceBoundPrediction` carries a `Verdict` (including
`UNKNOWN` and `UNIDENTIFIABLE`), a score, an uncertainty estimate, evidence and a
compute path — and no action, remediation or privilege field. Its constructor
audits its own field names, so adding one later breaks construction.

## Verification

`tests/test_stage2_export.py`, **64 tests, all passing this session**
(`PYTHONHASHSEED=0 python -m pytest tests/test_stage2_export.py -q`).

The load-bearing test is
`test_stage3_can_compile_a_rule_that_is_already_a_rule`: it builds the Φ-oracle
candidate, exports it with zero refusals, builds and writes the handoff, reloads
it from disk, rebuilds `DeterministicScorerSpec` from plain JSON and re-scores a
lineage window. If the format cannot carry a zero-parameter rule, that test
fails and the compilation path is refuted before any neural region is attempted.

Anti-weakening tests, each of which fails if an invariant here is loosened:

- `test_every_forbidden_authority_field_is_actually_refused` — all twelve tokens,
  nested one level down.
- `test_a_prediction_carries_no_authority_field` — asserts over
  `__dataclass_fields__`, so a new `action` field breaks it.
- `test_hits_without_a_ledger_claim_no_saving_at_all` — five hits, zero claimed
  savings.
- `test_a_fabricated_skip_fails_assert_no_phantom_savings` — the ADR-0010 defect
  through this cache's own call path.
- `test_a_stale_version_is_a_miss_counted_as_a_version_rejection` — for both
  version fields.
- `test_an_untimed_scorer_is_still_refused_by_the_exporter` — UNMEASURED never
  reaches Stage 3, not even for the favoured candidate.
- `test_a_cache_hit_returns_a_new_entry_and_never_mutates_the_stored_one` —
  guards the validation-skipping fast copy against becoming a mutation.

Stage 2 gate check **G2.13** is the intended consumer, and it is met.

## Prior art

No novelty claimed. Validity-bounded compiled artefacts are the standard shape of
a JIT's guard/deopt pair, and content-addressed handoffs are ordinary build
provenance. The one opinionated choice is treating a zero-parameter rule as the
*primary* compile candidate rather than a degenerate case, which follows the
lesson this repository already measured and the spec already cites (Bilot et al.,
"Sometimes Simpler is Better", USENIX Security 2025): the simple mechanism won, so
the format should be built for the simple mechanism. No
`docs/prior-art/ledger.json` entry is required because no novelty is claimed.
