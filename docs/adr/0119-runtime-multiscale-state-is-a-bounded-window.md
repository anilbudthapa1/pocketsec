# ADR-0119 — Runtime multiscale state is a bounded per-lineage window, not recurrent state

- **Status:** Accepted
- **Date:** 2026-09-24
- **Stage:** 2
- **Deciders:** Stage 2 completion wave, `routing` work package
- **Supersedes:** nothing. **Extends:** ADR-0005 (state is per causal lineage),
  ADR-0006 (semantics are earned by behaviour), ADR-0007 (SSIR field freeze),
  ADR-0009 and ADR-0010 (the recurrent core is rejected; the core is a TCN).

## Context

DTL-F03 is named `update_multiscale_state` and the Stage 2 architecture document
describes it as a factorised latent state with gated timescale blocks. Two
measurements already in this repository make that reading unbuildable:

* ADR-0009: on long-horizon sessions the recurrent core scores **0.4736 PR-AUC**
  against the TCN's **1.0000**, at twice the parameters. Every recurrent model
  tried (GRU 0.334, SSM 0.341, LSTM 0.353) sits within 0.02 of the 0.333 base
  rate.
* ADR-0010: the convolutional rebuild reached parity and was then *dominated* —
  same 1.0000 detection at **22.3 µs/event vs 6.6** and 2.8× the parameters — so
  the accepted Stage 2 core is a plain TCN: causal dilated convolution
  (dilations 1, 2, 4, 8, 16, 32, kernel 3) with max-over-time pooling.

A convolution does not carry state forward. It reads a **window**. So the runtime
half of DTL-F03 was missing entirely: `pocketsec/stage2/state/` was a 0-byte
`__init__.py`, and there was no way for an endpoint to assemble the causal taps
the accepted core consumes. Filling that package with a recurrent cell would
resurrect a design this repository has already measured and rejected twice.

The second constraint is identity. Stage 1's `causal_signature` is built from
semantics alone — `stage1/causal/memory.py:55-70`: "no pid, path, inode or
command line participates" — and ADR-0007 froze `exact_identity` out of the
model-facing encoding. A window store keyed on a pid would reintroduce identity
through the grouping key, which is exactly the door ADR-0006 closed.

## Decision

`pocketsec/stage2/state/window.py` implements DTL-F03 as a **bounded per-lineage
window of encoded transitions**, and contains no hidden vector, no timescale gate
and no carried activation.

* `MAX_LINEAGES = 64`, `MAX_WINDOW = 64`. A `WindowStore` asked for more raises
  `ContractError` rather than quietly allocating it.
* `LineageWindow.lineage_key` is the **root of the `causal_signature` /
  `parent_signature` chain** — never a pid, a path, a `display_name` or an
  `identity`. An AST test asserts `window.py` never reads `.identity`,
  `.display_name`, `.actor` or `.object`, mirroring the encoder's own guard.
* `LineageWindow.dilated_context(dilation, kernel=3)` returns the causal
  left-padded kernel window, widest tap first, matching
  `research/dtl_conv.py::_dilated_windows` so runtime and research read one
  layout. Step *t* sees only steps ≤ *t*, asserted at dilations 1, 2, 4, 8, 16, 32.
* Truncation and eviction are explicit and counted: `LineageWindow.truncated` is
  sticky, `WindowStats` carries `evicted_lineages` and `truncated_steps`, and
  eviction is LRU by `last_sequence` with a deterministic tie-break on the key
  (dict iteration order must not decide an eviction, per the Stage 0
  reproducibility policy).
* `memory_bytes` is **summed from real lengths**, not estimated, and is split
  into `fixed_bytes()` (bounded by `memory_bound_bytes()`) and
  `evidence_bytes()` (variable-length locator strings this store does not choose
  and therefore does not claim to bound).
* The signature→root map is itself bounded at `max_lineages × max_window` with
  `root_evictions()` and `unresolved_parents()` counted, because a per-signature
  map over an unbounded stream is the classic leak.

**A consequence stated rather than hidden:** because the key is semantic, two
behaviourally identical lineages share one window. That is ADR-0006's intent, not
a collision bug, and nothing here may separate them by process identity.

## Options considered

| Option | Security cost | Resource cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|---|
| **A. Multi-timescale recurrent state, as the architecture document describes** | None directly | Highest: carried activations per lineage | highest | **Measured (ADR-0009): 0.4736 PR-AUC vs the TCN's 1.0000 on long-horizon sessions, at 2× the parameters. ADR-0010: 22.3 µs/event vs 6.6 at equal detection** | Rejected, twice, on measurement. Rebuilding it is the most expensive failure available to this wave |
| **B. Window = 1 (the most recent transition only)** | Cannot express "short escalating chain inside a long benign session", the shape ADR-0009 says convolution is the right bias for | Cheapest | lowest | **Measured this session** on hard/count=60/seed=11 (246 transitions, `synthetic_data=True`), majority-family next-event accuracy: **window=2 → 0.2305 at 10 844 B** vs **window=64 → 0.3621 at 266 488 B**. On ambiguous/count=60/seed=11 (4 404 transitions): **window=2 → 0.3843 at 24 728 B** vs **window=8 → 0.4604** vs **window=64 → 0.5355 at 572 830 B** | Rejected as the default. The wide window is measurably better on next-family accuracy at ~23× the memory. **This is a next-event-prediction result, not a detection result, and it says nothing about PR-AUC** |
| **C. Bounded window, 64 lineages × 64 steps (chosen)** | None. Semantic key only; truncation and eviction explicit | **Measured this session at full occupancy: `memory_bytes` 6 719 488 B (6.41 MiB), exactly equal to `memory_bound_bytes()`; sampled peak RSS 29 868 032 B, ΔRSS 5 431 296 B, 5.63e-05 CPU s/event over 4 096 updates.** Per-event: **37.21 µs/event** for `update_multiscale_state` on hard/60, of which **30.97 µs** is `encode_ssir_transition` itself → **6.23 µs/event window overhead** | moderate — 400 lines, one store, two dataclasses | Chosen. 6.41 MiB against the Stage 2 80 MB ceiling and the 100 MB Edge target | — |
| **D. Unbounded window with age-based trimming** | Silent truncation is forbidden by the Stage 0 bounded-window invariant | Unbounded by construction | low | **Not measured; refused before measurement.** A 2 GB host target cannot carry an unbounded per-lineage history | Rejected on invariant, not on measurement |

The simplest option (B) was rejected because it measurably loses next-family
accuracy — 0.3843 → 0.5355 on the ambiguous corpus — while being the only option
cheaper than the chosen one. It is retained as the named control in
`tests/test_stage2_routing.py::test_the_single_step_control_is_measured_not_assumed`,
which prints both figures and deliberately asserts **no** directional claim.

## Consequences

**Accepted costs.** 6.41 MiB at full occupancy, and a window overhead of 6.23
µs/event on top of the encoder's own 30.97 µs. The encoder dominates, which means
optimising this store would not move the per-event cost much; that is a fact about
where Stage 2's runtime cost actually lives and it is worth recording.

**Honest limits.** Every figure above is on synthetic corpora on this development
host (Python 3.14.7, Linux 7.1.5+kali-amd64). The accuracy figures are
**next-relation-family accuracy from a majority vote over the window**, not a
detection result and not a model: they compare window widths under a trivial
predictor, and nothing here shows that a wider window improves PR-AUC. On
hard/60 and ambiguous/60 the store saw only **3 and 6 distinct lineage keys**
respectively, because the corpora contain behaviourally identical chains; the
64-lineage ceiling was therefore never approached by real corpus data and its
eviction behaviour is verified by hand-built transitions only.

**Bounded state.** Yes, and measured: ≤ 64 lineages × ≤ 64 steps × 96 float
slots, `fixed_bytes()` equal to `memory_bound_bytes()` at saturation, and a store
that has saturated stops growing (`test_a_full_store_stops_growing` feeds 500
further events and asserts `memory_bytes` is unchanged). The signature→root map
is bounded separately and its evictions are counted, because evicting a chain
head can split a lineage and that cost must be visible.

**Reversibility.** The module is additive, stdlib-only, and imported by nothing
yet. Deleting it removes DTL-F03's runtime half and nothing else. It does **not**
delete or weaken `research/dtl.py` or `research/dtl_conv.py`, which stay as the
research vehicles and as the record of the rejected design.

**Authority.** None. A window is retained representation; it produces no verdict
and no score.

## Verification

`tests/test_stage2_routing.py` — all 49 tests pass this session
(`PYTHONHASHSEED=0 python -m pytest tests/test_stage2_routing.py -q`). The tests
that pin this decision:

- `test_dilated_context_is_causal_at_every_dilation_the_core_uses` (parametrised
  1, 2, 4, 8, 16, 32) — step *t* never sees *t+1*.
- `test_window_never_exceeds_max_window_and_says_when_it_truncated`,
  `test_truncation_flag_is_sticky_once_a_step_was_dropped`,
  `test_a_window_that_dropped_nothing_does_not_claim_truncation`.
- `test_lineage_count_never_exceeds_max_lineages_and_evictions_are_counted`,
  `test_eviction_is_lru_by_last_sequence_and_deterministic`,
  `test_a_replayed_stale_sequence_cannot_evict_a_fresher_lineage`.
- `test_lineage_key_never_carries_a_pid_a_display_name_or_an_identity` and
  `test_window_module_never_reads_identity_fields` (AST) — the ADR-0006/0007 guard.
- `test_memory_bytes_is_computed_and_stays_inside_its_own_bound`,
  `test_a_full_store_stops_growing`,
  `test_root_map_is_bounded_and_its_evictions_are_counted`.

`tests/test_repository_structure.py` (38 tests) still passes, so the new module
imports no third-party code and no `research/` code.

## Prior art

No novelty claimed. A bounded causal receptive field is what a temporal
convolutional network reads by definition (Bai, Kolter & Koltun, "An Empirical
Evaluation of Generic Convolutional and Recurrent Networks for Sequence
Modeling", 2018), and the decision to prefer it over recurrence here is the
measured result already recorded in ADR-0009 and ADR-0010, not a new claim. No
`docs/prior-art/ledger.json` entry is required because no novelty is claimed.
