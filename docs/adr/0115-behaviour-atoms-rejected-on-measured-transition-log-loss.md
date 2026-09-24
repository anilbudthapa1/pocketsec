# ADR-0115 — Behaviour Atoms are rejected: the learned quantizer loses to a hash bucket

- **Status:** Accepted
- **Date:** 2026-09-24
- **Stage:** 2
- **Deciders:** Stage 2 completion wave, `lattice` work package
- **Supersedes / superseded by:** none. Extends ADR-0010 to the discrete layer it
  said "should not be built as specified".

## Context

D2.6 proposes a discrete layer between the 96-slot encoder and Stage 3's
executable Knowledge Cells: quantize each transition to a **Behaviour Atom**, then
learn a bounded transition lattice over atom ids. Stage 2's acceptance criterion 4
explicitly allows two outcomes — "Behaviour Atoms are demonstrably stable enough
to reuse, **or** the discrete layer is rejected" — and gate check G2.4 names the
deciding metric: the learned atoms must beat `HashBucketQuantizer` on transition
log-loss **at equal `memory_bytes`**.

Both quantizers were implemented in full and measured on the fixed split the spec
requires (`corpus=ambiguous, count=240, seed=11`), Python 3.14.7,
Linux 7.1.5+kali-amd64, 240 scenarios / 17,898 transitions, 192 fit / 48 held-out
scenarios, 3,556 held-out transition pairs. Labels are assigned online; the
lattice is fitted on the fit split only and scored on the held-out pairs.

**Measured transition log-loss (lower is better):**

| quantizer | atoms | `memory_bytes` | transition log-loss |
|---|---|---|---|
| `HashBucketQuantizer` (the control) | 14 | **3,136** | **1.889260** |
| `BehaviourQuantizer`, matched memory (`max_atoms=3`) | 3 | 2,928 | 2.148290 |
| `BehaviourQuantizer`, unmatched (`max_atoms=256`) | 256 | 249,856 | 3.613527 |

The learned quantizer loses **at matched memory (+0.259 nats)** and loses *worse*
when handed **79.7× the bytes (+1.724 nats)**. There is no budget at which it
wins. Held to the control's 3,136 bytes it also thrashes: 16,926 creations and
16,923 evictions over 17,898 transitions, i.e. it re-creates a prototype for
almost every event.

**Atom reuse across orderings.** Quantizing the same corpus forward and reversed
(count=240, seed=11) produced 256 atoms each way with **13 atom ids in common —
0.0508 overlap**. `LatticeRestructurer.stability()` nonetheless returned
**1.0000**, which would satisfy G2.4's `>= 0.90` threshold. It is a *vacuous*
1.0000: both partitions are all-singletons because **zero merges occurred**, so a
pairwise agreement index has nothing to disagree about. This is the same failure
shape ADR-0010 found in the Need router's path accounting — a true number that
measures nothing — and it is pinned by a test so it cannot be quoted as evidence
of reuse again.

The same probe at `count=60, seed=11` gives 241 forward atoms, 255 reverse atoms,
**0.5560 id overlap**, 0 merges either way, and again `stability() = 1.0000`.
Overlap therefore degrades with corpus size (0.5560 at 60 → 0.0508 at 240) while
the stability index stays pinned at 1.0000. Two corpus sizes, two very different
reuse rates, one unchanging "stability" number.

**Merge behaviour on real data (count=240, seed=11), forward order:** 0 merges,
32,640 refusals — `INSUFFICIENT_EVIDENCE` 18,275, `STATE_INCOMPATIBLE` 8,326,
`PREDICTIVE_DISTANCE` 3,548, `UNCERTAINTY_INCOMPATIBLE` 2,491. The reverse order
is within 1% on every reason. The equivalence evaluator is working; there is
simply nothing in this corpus that is predictively equivalent under a conjunction
that also requires a shared epoch and an identical nine-dimension state summary.

**Bound observed.** With learned labels the lattice saturated at
`MAX_TRANSITIONS=4096` edges with 1,664 evictions and 631,072 bytes. With hash
labels it needed 135 edges and 20,968 bytes for the same corpus. The learned
labels cost 30× the lattice as well as 80× the quantizer.

**Not measured.** The atom layer emits no detection score, so its contribution to
PR-AUC — against the Φ-oracle's free 0.7484, or against anything else — is
**UNMEASURED**, not zero. `PATH_COST_UNITS` calibration and any wake-rate effect
of atom-keyed caching belong to the `router`/`export` packages and are likewise
UNMEASURED here.

## Decision

**Reject the learned discrete layer.** `HashBucketQuantizer` is the default:
`pocketsec.stage2.lattice.quantizer.BEHAVIOUR_QUANTIZER_ENABLED = False` and
`DEFAULT_QUANTIZER = HashBucketQuantizer`.

`BehaviourQuantizer`, `TransitionLattice`, `predictive_equivalence` and
`LatticeRestructurer` are **retained as implemented code**, because:

1. The lattice, the equivalence evaluator and the restructurer are quantizer-
   agnostic — they operate on atom ids, and the hash bucket supplies those. Only
   the *prototype* layer is rejected.
2. G2.4's rejection branch requires the control to exist and the rejection to be
   measured; deleting the loser would delete the measurement.
3. Repository rule: prior counterexamples and provenance are not deleted.

**Recommended removal.** If no downstream package (D2.8 cones, D2.13 cache,
D2.15 export) finds a use for prototype geometry that the bucket key cannot
supply, `BehaviourQuantizer.fission_atom`, `BehaviourAtom.prototype` and
`LatticeRestructurer.split_heterogeneous_atom` should be deleted in a follow-up
ADR. Fission is the weakest part of the design and should go first: it splits a
prototype using only the parent's own deviation direction, because the quantizer
keeps no samples, so a split can never be validated against the points that
motivated it.

## Options considered

| Option | Security cost | Resource cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|---|
| **A. Hash bucket only (chosen)** | none identified; the bucket key is `(relation_family, state_delta_mask, object_property_mask)`, all Stage 1 semantics, no identity | 14 atoms, **3,136 B**; lattice 135 edges / 20,968 B | lowest — zero training, zero drift, zero tuning | **log-loss 1.889260**, 0 evictions | — |
| B. Learned prototypes at matched memory | same inputs; adds an unvalidatable split path | 3 atoms, 2,928 B | online clusterer + radius + learning rate to tune | **log-loss 2.148290**; 16,923 evictions on 17,898 transitions | Worse than A while thrashing its own bound |
| C. Learned prototypes, unbounded budget | as B | 256 atoms, **249,856 B** (79.7× A); lattice 4,096 edges / 631,072 B, 1,664 evictions | as B | **log-loss 3.613527** | Worst log-loss *and* worst cost — dominated, like DTL-C in ADR-0010 |
| D. Learned prototypes + merge/fission restructuring | a wrong merge is invisible and averages two futures into one alert | as B or C, plus ≤64 macro states | highest | **0 merges** on 240×seed-11; 32,640 refusals | Adds no grouping to reject; cannot be justified by ablation (criterion 12) |
| E. Drop the discrete layer entirely | loses the only Stage 2 artefact Stage 3 can crystallise cheaply | 0 B | none | UNMEASURED — no substitute candidate source was built this wave | Premature: D2.13/D2.15 need *some* stable node id, and A supplies one for 3 KB |

Stage 0 principle honoured: the simplest option won. It was not chosen on
elegance — it was measured, twice, at two budgets.

## Consequences

**Accepted costs.** Atom ids become coarse: 14 buckets for 17,898 transitions, so
a bucket averages 1,278 observations and cannot distinguish two behaviours that
share a relation family, a state-delta mask and an object-property mask. That is
a real loss of resolution, and it is worth 1.72 nats and 247 KB. Anything
downstream that needs finer granularity must say so with a measurement.

**Bounded state.** Reduced. Quantizer 249,856 → 3,136 bytes measured; lattice
631,072 → 20,968 bytes measured; lattice evictions 1,664 → 0 on the same corpus.
Both quantizers remain hard-bounded (`MAX_ATOMS=256`, `MAX_TRANSITIONS=4096`,
`MAX_EPOCHS_PER_ATOM=8`, `MAX_MACRO_STATES=64`) with every eviction counted.

**Reversibility.** Flip `BEHAVIOUR_QUANTIZER_ENABLED` to `True`. The learned code
path is intact and tested, so reopening this costs a config change plus a
re-measurement, not a rewrite. Merges are reversible independently via
`LatticeRestructurer.unmerge` (spec §13), which dissolves a macro state back to
the singleton partition it came from.

**Authority.** No change. Neither quantizer produces a verdict, a score or a
status beyond `CompileStatus.NEURAL`; nothing here can reach `EXECUTABLE`, which
only Stage 3 may assign (ADR-0003).

## What would reopen this

A corpus — ideally real telemetry — on which two transitions sharing
`(relation_family, state_delta_mask, object_property_mask)` have measurably
different continuations. On `ambiguous` they do not, which is why the bucket wins.
Note the standing caveat from ADR-0010: all four corpora are synthetic, and the
Φ-oracle's PR-AUC on this same generator moves 0.4025 with corpus size alone, so
this result is a fact about `ambiguous@240/seed-11` and should be re-run on the
first real telemetry the project obtains.

## Verification

- `tests/test_stage2_lattice.py::test_measured_transition_log_loss_learned_versus_hash_bucket`
  — reproduces the table above and asserts only that the budgets were matched.
- `tests/test_stage2_lattice.py::test_atom_identity_is_order_dependent_which_stability_alone_hides`
  — pins the vacuous-stability trap.
- `tests/test_stage2_lattice.py::test_max_macro_zero_performs_no_merges` — the
  fixed-K control (spec §5) is a real setting, not a dead branch.
- Reproduce the headline numbers with
  `cd <repo> && PYTHONHASHSEED=0 python -m pytest tests/test_stage2_lattice.py -q -s -k measured`.

## Prior art

No novelty claimed. The outcome repeats ADR-0010's citation of Bilot et al.,
"Sometimes Simpler is Better" (USENIX Security 2025): a hand-specified discrete
key over an existing semantic representation beat a learned online clusterer on
both quality and cost. It is also the ordinary result for online k-prototype
clustering on low-dimensional near-one-hot input, where the discrete key *is* the
cluster structure.
