# PocketSec — Stage 1: SSIR and the Security State Calculus

**Specification version:** 1.0
**Source of truth:** `PocketSec_Stage_1_SSIR_Security_State_Final.docx`
**Status:** implemented; acceptance gate passing. D1.13 freeze **resolved
narrowly** — see ADR-0007; field widths remain provisional.

> **Thesis.** Observe only what uncertainty justifies. Represent only what
> changes security decisions. Maintain what is now true, not merely what
> happened. Preserve the causal reason it became true.

## The two questions

| Question | Answered by |
|---|---|
| What changed? | `SSIRTransitionV1` — τ = (A, R, O, ΔS, U, N, P, T, E) |
| What is now true? | `SecurityStateV1` / the Host Security State |

They are separate, separately versioned types. Collapsing them would make
"the host is currently compromised" indistinguishable from "something happened".

## Pipeline

```
Linux sources -> RawEventV1 -> EventAssembler (fusion) -> EvidenceEvent
                                                              |
                                                     SemanticCompiler
                                     /            |            |          \
                             EntityRegistry  OperationRules  Novelty   Evidence
                                     \            |            |          /
                                            SSIRTransitionV1
                                     /        |         |        \
                          HostSecurityState  Causal   AOP    Aggregation
```

Every module is under `pocketsec/stage1/`. The `SemanticCompiler` is the
**compatibility boundary**: different sensors describing the same behaviour
converge here or nowhere.

## Deliverables

| ID | Deliverable | Where |
|---|---|---|
| D1.1 | SSIR v1 binary spec + versioning | `ssir/transition.py`, `ssir/codec.py` |
| D1.2 | RawEventV1 + EvidenceEvent | `telemetry/raw_event_v1.py`, `telemetry/assembler.py` |
| D1.3 | Entity + relation semantic compiler | `compiler/` |
| D1.4 | Host Security State + calculus | `state/security_state.py` |
| D1.5 | Security Potential Φ + calibration | `state/potential.py` |
| D1.6 | Conditional Novelty Engine | `novelty/` |
| D1.7 | Behaviour Epoch Model | `epoch/model.py` |
| D1.8 | Multi-resolution causal state | `causal/memory.py` |
| D1.9 | Adaptive Observation Policy | `observation/policy.py` |
| D1.10 | Semantic aggregation policy | `aggregation/policy.py` |
| D1.11 | Information Guillotine + Pareto | `guillotine/ablation.py` |
| D1.12 | Adversarial / drift test reports | `labs/adversarial.py` |
| D1.13 | Stage 2 fixtures + replay corpus | `labs/corpus.py`, `slot.py` |

## The three independent signals

The spec requires novelty **N**, security potential **Φ** and confidence **U**
to stay separate, and the implementation keeps them in separate fields with
separate producers.

| Signal | Asks | Produced by |
|---|---|---|
| Novelty N | how unfamiliar is this? | `NoveltyEngine` (8-context tensor) |
| Potential Φ | how security-sensitive is the resulting state? | `phi(SecurityStateV1)` |
| Confidence U | how certain are the observations and semantics? | entity beliefs + fusion quality |

**Novelty is not maliciousness.** A compiler emitting never-before-seen object
files is maximally novel and completely benign; measured on the corpus at
novelty 1.00, Φ 0.75. A pure-novelty detector fires on it — that is the
`NoveltyStatisticalSlot` control, and its false positives are the argument for
the state calculus existing.

## Security Potential Φ

Composition, not severity summing. Every weight is an explicit documented rule:

- **Base**: per-dimension monotone contributions (deliberately modest).
- **Interactions**: six named combinations, each with a written rationale —
  `exfiltration_triad`, `privileged_credential_access`, `credential_egress`,
  `privileged_persistence`, `boundary_escape`, `discovery_to_credential`.

Measured on the escalation chain `sudo -> read /etc/shadow -> connect external`:
base 5.25, interactions 8.50, total 13.75. **Interactions dominate**, which is
the Stage 1 hypothesis under test — and `calibrate()` reports the margin over an
additive control (`composition_gain`) rather than asserting it.

The test that keeps Φ honest: a root admin editing `sources.list` scores under
4.0 with **no** interaction active. Privilege alone is not danger.

## Bounded by construction

Every hot-path structure declares a cap and reports its own footprint.

| Structure | Bound | Measured |
|---|---|---|
| Novelty engine (8 contexts × 3 tiers) | LRU 512 / CMS 512×4 / Bloom 4096 | ~164 KB |
| Causal memory | 512 nodes, 64 at L0 | ~2 KB on the corpus |
| Entity registry | 2048 entities, LRU | eviction counted |
| Event assembler | 4096 pending, oldest-first eviction | loss counted |
| AOP | 8 concurrent, 30 s, 500 extra events/s, 256 KB | caps-hit recorded |
| Lineage state | 256, lowest-Φ evicted | — |

Whole Stage 1 replay: **peak RSS 24.6 MB against the 100 MB Edge target**,
1.8e-04 CPU s/transition.

Under a 400-event flood the assembler evicts oldest-first and counts it, the
Bloom filter converges to ~56% fill rather than saturating, and aggregation
coalesces 99% of the repetition — while every high-consequence transition is
still emitted.

## What the adversarial suite measures

| Test | Result |
|---|---|
| Renaming | identical Φ (13.75) after renaming to `/tmp/.x91` |
| Unseen binary | exfiltration triad still fires for a never-seen executable |
| Obfuscation | mangled command lines change nothing |
| Timing shift | time-shifted chain reaches the same state |
| High-novelty benign | novelty 1.00, Φ 0.75 — stays low-potential |
| Epoch poisoning | max-novelty uncorroborated change **refused**; corroborated accepted |
| Flood | bounds held, 99% aggregated |
| Sensor disagreement | uncertainty rose (0.55 vs 0.30) |

## The Information Guillotine (D1.11) and the D1.13 freeze

The first frontier was **degenerate** — 8 of 9 cuts cost nothing, because the
original corpus's benign and malicious scenarios shared almost no operations.
That measured the corpus, not the representation. Fixing it exposed three
methodology defects and one corpus bug, each now pinned by a test:

1. **Hand-picked probe weights.** Removing novelty and timing *raised* PR-AUC,
   which says the weights were wrong. The probe is now a plain L2 logistic
   regression **refitted per ablation** on a split disjoint from the one it
   scores, so each point answers "how much separation is still achievable
   without this information".
2. **A benign-only fit split.** A supervised probe with no positives produced an
   inverted ranking and a baseline PR-AUC of 0.23 against a 0.355 base rate —
   worse than random. `LogisticProbe.fit` now refuses a single-class split.
3. **`time_bucket` constant corpus-wide.** `emit` hard-coded a 1 ms gap, so
   timing measured as useless for reasons of our own making.
4. **Corpus bug:** the timing discriminator pair returned the *same* behaviours
   for both labels — pure label noise, capping achievable PR-AUC.

### The measured frontier (held out, hard corpus)

| cut | bytes | PR-AUC |
|---|---|---|
| full | 37 | 0.996 |
| −exact_identity | 29 | 0.996 |
| −evidence_link | 25 | 0.996 |
| −object_semantics | 23 | 0.992 |
| −actor_semantics | 21 | 0.992 |
| −capability_delta | 17 | 0.875 |
| −uncertainty | 16 | 0.867 |
| −novelty | 12 | 0.830 |
| −timing | 11 | 0.822 |
| −causal_memory | 2 | 0.398 |

### Why the knee is not the freeze

Cumulative ablation finds the cheapest viable path; **leave-one-out** finds what
a family uniquely contributes. They disagree under redundancy, and a freeze
needs both. Measured over 5 draws:

| Family | Redundant on | LOO cost (min/mean/max) |
|---|---|---|
| `exact_identity` | **100%** | 0.0000 / 0.0000 / 0.0000 |
| `evidence_link` | **100%** | 0.0000 / 0.0000 / 0.0000 |
| `actor_semantics` | 60% — **unstable** | 0.0000 / 0.0019 / 0.0094 |
| `object_semantics` | **0%** | 0.0024 / 0.0053 / 0.0115 |
| `capability_delta` | 0% | 0.0084 / 0.0260 / 0.0494 |
| `uncertainty` | 0% | 0.0265 / 0.0296 / 0.0377 |
| `novelty` | 0% | 0.0216 / 0.0469 / 0.0677 |
| `timing` | 0% | 0.0067 / 0.0127 / 0.0253 |
| `causal_memory` | 0% | 0.0000 / 0.0000 / 0.0000 |

**`actor_semantics` is the finding.** A single draw called it redundant and the
knee recommended dropping it; across draws it is redundant only 60% of the time.
A single-frontier freeze would have removed a load-bearing field.

`causal_memory` has zero unique contribution but a cumulative cost of 0.513: it
is the last carrier standing, not a redundant one.

### Freeze decision (ADR-0007)

Only **`exact_identity`** is frozen out of the model-facing encoding, at L0–L2.
It remains at L3 for hub correlation and investigation. `evidence_link` is free
for detection and **retained anyway** — the investigator's path back to raw
evidence is a Stage 0 invariant, and measurement does not get to overrule it.

Saving: 8 bytes of 37. A larger cut was available on paper and is not supported
by measurement.

## What is still not settled

1. **All data is synthetic.** Every number here demonstrates the mechanism, not
   detection quality. Stage 0 fair-comparison rule 7 applies.
2. **Confidence is uncalibrated.** Both Stage 1 slots report
   `calibration_id=None` rather than inventing one.
3. **Field widths remain provisional.** Only the presence/absence decision in
   ADR-0007 is settled; 64/48/40/32/24/16-byte packing targets are untested.
4. **One probe family.** The frontier reflects what a linear probe can extract.
   A different model class could find information this one cannot.

## Extension points for Stage 2

Stage 2 receives a measured, minimised representation rather than raw logs. It
may choose any architecture: `StateCalculusSlot` (symbolic) and
`NoveltyStatisticalSlot` (statistical) both consume identical SSIR and disagree
on 42 of 60 corpus windows, which is the evidence that the representation is not
tuned to one consumer.
