# D1.13 — Stage 2 entry criteria

**Stage 2:** DTL — predictive multi-timescale learning, Behaviour Atoms, the
transition lattice, Future Cones, uncertainty and bounded counterfactuals.

Stage 2 researches the *intelligence mechanism*. It receives a measured,
minimised representation of Linux security reality, not raw logs.

## Entry criteria

All thirteen Stage 1 acceptance criteria pass, verified by
`python -m pocketsec.stage1.cli gate` (exit 0). Stage 0's gate must still pass
too: Stage 0's measurement rules bind every later stage.

## What Stage 2 receives

| Interface | Schema | Stability |
|---|---|---|
| `SSIRTransitionV1` | `pocketsec.ssir_transition.v1` | versioned; breaking change needs a new `$id` |
| `SecurityStateV1` | Python type, per lineage + host join | versioned with SSIR |
| Replay corpus | `pocketsec.stage1.labs.corpus` | deterministic from a seed |
| Reference slots | `StateCalculusSlot`, `NoveltyStatisticalSlot` | Stage 0 `ModelSlot` protocol |

Stage 2 reports through `pocketsec.stage0.benchmark.harness.run_benchmark`
unchanged. Security and resource cost are reported together, always.

## The extension point

Stage 2 adds predictive intelligence **behind the model slot**. It may:

- consume any subset of SSIR fields, at any representation level;
- maintain its own learned state, atoms and lattices;
- request higher representation levels through the AOP budget;
- propose new novelty contexts.

Stage 2 **may not**, without an ADR and a new schema `$id`:

- change τ = (A, R, O, ΔS, U, N, P, T, E) or the state lattices;
- collapse novelty, security potential and uncertainty into one score — they
  are required to stay independent;
- grant response authority from a model output (ADR-0003);
- inline raw evidence instead of referencing it by digest;
- remove the bounds on any hot-path structure;
- open a behaviour epoch from behavioural novelty alone.

## Freeze status

The D1.13 freeze is **resolved narrowly** (ADR-0007). The frontier is now
measured on a hard corpus with a held-out fitted probe and is no longer
degenerate; `exact_identity` is frozen out of the model-facing encoding at
L0–L2 and retained at L3.

Stage 2 must not treat the remaining fields as provisional: seven of nine
families are justified by measurement across draws, and `actor_semantics`
specifically was shown to be load-bearing on 40% of draws despite looking
redundant on one. Removing a field needs a fresh stability run and an ADR.

**Still open, carried into Stage 2:**

- Field *widths* are untested. The spec asks for 64/48/40/32/24/16-byte packing
  targets to be challenged; only presence/absence has been settled.
- The frontier reflects one probe family (a linear model). A different model
  class could extract information this one cannot, which is Stage 2's business.
- All corpora remain synthetic.
