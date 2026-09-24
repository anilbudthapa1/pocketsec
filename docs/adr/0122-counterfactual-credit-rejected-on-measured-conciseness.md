# ADR-0122 — The model-based counterfactual twin is rejected; the Φ-only path is kept

- **Status:** Accepted
- **Date:** 2026-09-24
- **Stage:** 2
- **Deliverables:** D2.10 (DTL-F10, DTL-F11), D2.11 (DTL-F12)
- **Deciders:** Stage 2 `credit` work package
- **Related:** ADR-0009, ADR-0010, ADR-0005 (lineage-scoped state)

## Context

Architecture spec section 16 defines responsibility as the divergence between
predicted security futures when a transition is masked, and section 17 keeps a
bounded ledger of the transitions that *materially* changed that future. Section
36 lists the falsifier: *"counterfactual analysis adds latency but not
attribution quality"*. Gate criterion G2.7 makes it executable — the credit
spine must inspect fewer nodes than naive ancestry at recall at least as good.

Stage 2 spec section 5 names three controls for this deliverable:
`CausalMemory.spine(min_responsibility=0.0)` (full ancestry), top-k by raw ΔΦ,
and `phi_only_probe` — replay with the transition removed, scored with Stage 1's
ΔΦ alone, **zero parameters**. All three are implemented, and all three were
measured against the model-based twin in the same run.

## Measurement

Produced by running `tests/test_stage2_credit.py::test_g27_attribution_comparison_is_measured_and_reported`
on Python 3.14.7 / Linux 7.1.5+kali-amd64, `PYTHONHASHSEED=0`.

Fixture `fixture-escalation-chain`, 12 single-lineage sessions,
`seeds=(11, 17, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61)`, `synthetic_data=True`.
Each session is background host activity plus legitimate privileged
administration plus a 2–5 stage escalation chain in the same lineage; ground
truth is the causal signature of each chain transition. Structure varies per
seed (chain length, admin-burst position, spacing), not only timing — a fixture
that varies only timing produced a spread of exactly 0.0000 across all 12 seeds,
which is degenerate by this wave's own guard.

| mechanism | nodes_inspected | chain_recall | conciseness_gain | sessions at naive recall |
|---|---|---|---|---|
| credit_spine (model-based twin) | 7.00 | 0.7361 | 4.7429 | 5/12 |
| naive_full_ancestry | 39.75 | 1.0000 | — | — |
| top_k_by_delta_phi | 7.00 | 0.8236 | 4.7429 | 5/12 |
| **phi_only_probe (0 parameters)** | **6.42** | **0.8236** | **5.5333** | 5/12 |

`conciseness_gain` is averaged over only the sessions where recall matched the
naive path; the denominator travels with it because a gain quoted at lower recall
is just a smaller number.

The sibling packages landed while this was being measured, so the same comparison
was re-run against the **real** D2.6 `BehaviourQuantizer`, the real
`TransitionLattice` and the real D2.8 `predict_future_cone`
(`test_g27_attribution_comparison_on_the_real_lattice_and_cone`), same 12 seeds:

| mechanism | nodes_inspected | chain_recall |
|---|---|---|
| credit_spine on the real D2.6/D2.8 stack | 6.17 | 0.7153 |
| naive_full_ancestry | 39.75 | 1.0000 |

The verdict does not change on the real stack: still more concise than naive, still
at lower recall, and still below the zero-parameter `phi_only_probe`'s 0.8236.

Per-session outcomes:

- G2.7 met by the credit spine on the aggregate: **False**.
- G2.7 met per session: **5/12**.
- Credit spine beats `phi_only_probe` on chain recall: **0/12 sessions**.

Latency, `timeit` best-of-7 over 50 probes each, 45-step window, 12 prototypes:

| path | µs/probe |
|---|---|
| `counterfactual_probe` (**real** D2.6 quantizer, 31 atoms, + real D2.8 cone) | **1211.9** |
| `counterfactual_probe` (bucket quantizer + bigram lattice stand-ins, 12 atoms) | 496.1 |
| `counterfactual_probe` with an O(1) prototype distance (twin machinery only) | 77.2 |
| **`phi_only_probe` (zero parameters)** | **25.3** |

The twin's own machinery is 77 µs; the rest is prototype distance and cone
expansion, which scale with the atom count. On the real stack the model-based
probe costs **48× the Φ-only control** for strictly worse attribution.

Ledger footprint at capacity: 256 entries, 144 evictions after 400 assignments,
`memory_bytes = 27392`.

## Decision

**Reject the model-based counterfactual twin as the default attribution path.
Keep the Φ-only path.**

`counterfactual_probe` remains implemented and tested, default-off, for the same
reason `DTLConvModel` was retained under ADR-0010: a task where prediction
demonstrably helps would revive it, and deleting the mechanism would delete the
measurement. `phi_only_probe` is the path that earns its place, and
`top_k_by_delta_phi` — which spends **no probes at all** — matches it exactly on
recall at the same node count on every session measured.

`CausalCreditLedger` is retained regardless of which probe feeds it: the bounded
ledger, the materiality filter and the refusal of unmeasured probes are what make
any attribution claim checkable, and they are mechanism, not model.

## Why the model-based twin loses, structurally

This is not a tuning failure. The twin's divergence signal is derived from the
*reconstructed security state* of the replayed window, and that state is built
from each transition's `state_delta_mask` — the same Stage 1 quantity ΔΦ
summarises. A transition that raised no capability, or that re-raised a
dimension an earlier transition already raised, changes nothing in the
reconstruction and therefore earns exactly zero divergence. The twin can only
attribute what ΔΦ already reports, so it cannot in principle beat a ΔΦ ranking
on this representation — and measured, it does not: it loses 0.0875 mean recall
at 1.09× the node count and ~20× the cost.

This is the same finding as ADR-0010 arriving from a different direction. Stage
1's lineage-scoped state calculus (ADR-0005) already performs attribution; Stage
2 re-deriving it through a learned lattice adds latency, not quality.

## Consequences

- **G2.7 must report FAILED on the aggregate.** The credit spine is more concise
  than naive ancestry (7.00 vs 39.75 nodes) but at *lower* recall (0.7361 vs
  1.0000), and the criterion requires recall at least as good. It is met on 5 of
  12 sessions, which is not the criterion. The gate must not be softened to
  "more concise at some recall".
- **No mechanism here reaches naive recall.** Every bounded mechanism misses
  chain transitions whose capability was already granted by legitimate
  privileged work earlier in the same lineage. Those transitions are invisible
  to ΔΦ *and* to the twin. That is an open attribution gap, not a solved one, and
  it is a property of the single-lineage corpora this repository has.
- **Measured on both stacks, and the answer is the same.** The comparison was
  authored against the spec's own simple controls (hash-bucket quantizer, bigram
  lattice) because D2.6/D2.8 did not exist yet, and then re-run against the real
  D2.6/D2.8 once they landed. Both are reported above. The real stack is more
  expensive (1211.9 vs 496.1 µs/probe) and slightly more concise (6.17 vs 7.00
  nodes) at slightly lower recall (0.7153 vs 0.7361). Neither version reaches
  naive recall and neither beats the Φ-only control.
- **D2.11 (VoI) is implemented but its value is UNMEASURED.** The
  value-of-information weighting is a stated policy heuristic. Whether it beats
  `uncertainty_only_requests` — Stage 1's existing threshold on uncertainty
  alone — needs an escalation-versus-detection measurement that this fixture
  cannot supply, because it has no observation feedback loop. `measured_reduction`
  is therefore `None` in every report this wave produced, and that is the honest
  value, not zero.

## What would reopen this

A corpus — ideally real telemetry — where a transition's contribution to the
predicted future is *not* recoverable from its own ΔΦ: multi-lineage sessions
where responsibility depends on interaction between lineages, or chains whose
consequence appears only several transitions later. On such a corpus the twin
has headroom the Φ-only control cannot reach. On the corpora this repository
has, it does not.

## Verification

- `tests/test_stage2_credit.py` — 42 tests, including the isolation invariant
  (a probe may not mutate the live quantizer or lattice, asserted against both
  the stand-ins and the real D2.6 objects), the refusal invariant (a
  budget-refused probe can never earn credit), the D2.4 seam (the real
  `WorkKind.COUNTERFACTUAL` is recorded and `assert_no_phantom_savings()`
  passes), and both G2.7 measurements above.
- `pocketsec/stage2/counterfactual/twin.py`,
  `pocketsec/stage2/counterfactual/value_of_information.py`,
  `pocketsec/stage2/credit/ledger.py`.

No experiment id was registered for this measurement: it runs inside the test
suite rather than through `stage0.benchmark.harness.run_benchmark`, because
`nodes_inspected` is an attribution metric the Stage 0 harness does not model.
The integrator should decide whether G2.7 evidence belongs in
`experiments/registry.jsonl`; until it does, this ADR and the test output are the
only provenance, and the figures above must be re-derived by running the test.

## Prior art

No novelty claimed. The `nodes_inspected`-at-equal-recall framing follows the
provenance-IDS Quality-of-Attribution literature the architecture document cites
(ORTHRUS-style attribution evaluation), which argues that practical systems must
optimise attribution quality and scalability rather than headline detection
accuracy. The negative result here is consistent with the spec's own cited
warning that simpler mechanisms frequently match far more complex designs.
