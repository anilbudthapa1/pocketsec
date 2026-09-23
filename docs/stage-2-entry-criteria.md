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

## Blocking prerequisite carried forward

**The Information Guillotine frontier is degenerate on the current synthetic
corpus** (1 of 9 cuts informative). The D1.13 field freeze is therefore *not*
complete: no SSIR field may be dropped on the strength of the current knee.

Stage 2 may proceed — it does not depend on the freeze — but a harder corpus is
required before any field is removed, and `ParetoReport.degenerate` must read
false before the freeze is claimed.
