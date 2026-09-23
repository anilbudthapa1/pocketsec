# PocketSec — Stage 1: SSIR and the Security State Calculus

**Specification version:** 1.0
**Source of truth:** `PocketSec_Stage_1_SSIR_Security_State_Final.docx`
**Status:** implemented; acceptance gate passing. **Not frozen** — D1.13 freeze
is still open, see "What is not settled" below.

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

## What is not settled

Honest limitations, recorded rather than smoothed over:

1. **The Information Guillotine frontier is degenerate on this corpus.** Only
   1 of 9 cuts measurably costs security retention, because the synthetic
   scenarios are separable by many redundant signals. The report says so itself
   (`ParetoReport.degenerate`). **The knee must not be used to justify dropping
   fields at the D1.13 freeze.** A harder corpus is the blocking prerequisite.
2. **All data is synthetic.** Every number here demonstrates the mechanism, not
   detection quality. Stage 0 fair-comparison rule 7 applies.
3. **Confidence is uncalibrated.** Both Stage 1 slots report
   `calibration_id=None` rather than inventing one.
4. **SSIR field widths are provisional.** The spec asks for 64/48/40/32/24/16
   byte targets to be challenged; the codec supports arbitrary retained-field
   sets, but the freeze decision awaits (1).

## Extension points for Stage 2

Stage 2 receives a measured, minimised representation rather than raw logs. It
may choose any architecture: `StateCalculusSlot` (symbolic) and
`NoveltyStatisticalSlot` (statistical) both consume identical SSIR and disagree
on 42 of 60 corpus windows, which is the evidence that the representation is not
tuned to one consumer.
