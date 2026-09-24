# ADR-0113 — Stage 2 has an executable gate, and it reports FAILED

- **Status:** Accepted
- **Date:** 2026-09-25
- **Stage:** 2
- **Deciders:** Stage 2 completion wave, integrator
- **Supersedes / superseded by:** none; complements ADR-0009, ADR-0010, ADR-0114–0122

## Context

Stage 0 and Stage 1 each ship `gate.py` with `run_gate() -> GateReport`, and each
is wired to a CLI that exits non-zero on failure. Stage 2 had neither. Its status
lived in one line of `planning/PROGRESS.md`:

> **Stage 2: PARTIAL (D2.1–D2.5), gate BLOCKED (2026-09-24)** — DTL fails its own
> falsification criterion 1.

That sentence was true and it was also unverifiable. Nothing recomputed it,
nothing would notice if it stopped being true, and nothing said *which* of the
thirteen criteria failed or by how much. A stage may not be declared failed by
prose, for exactly the reason it may not be declared passed by prose: the claim
is not attached to a measurement anyone can re-run.

Worse, "BLOCKED" is ambiguous in a way "FAILED" is not. Blocked reads as *waiting
on something*; the measured position is that three criteria cannot be met on any
corpus this repository can generate (ADR-0010, ADR-0120) and several others are
met only in their explicit rejection branch. That is a result, not a queue.

Measured this session, on `ambiguous` count=60 train seed=3 / eval seed=11, by
`pocketsec.stage2.research.cli:measure_frontier`:

| baseline | PR-AUC | parameters | µs/event |
|---|---|---|---|
| phi-oracle | 1.0000 | 0 | 0.08 |
| mlp-pooled | 1.0000 | 4657 | 8.13 |
| tcn | 1.0000 | 6961 | 16.58 |

Both learned models are dominated by a zero-parameter scorer at identical
detection. `saturation_check` calls the same split degenerate with reason
`ORDER_FREE_BASELINE_TIES_BEST`.

## Decision

**`pocketsec/stage2/gate.py` implements all thirteen Stage 2 acceptance criteria
as executable checks, `pocketsec/stage2/cli.py` exposes them as
`pocketsec-stage2 gate`, and the gate reports FAILED.** Three rules bind it:

1. **Every check runs the real subsystem.** No check reads a decision out of a
   document. Where an ADR is consulted at all (G2.4, G2.6), it is consulted
   *beside* a measurement this run reproduced, never instead of one.
2. **A criterion that cannot be met fails, and says why with a number.** It is
   never restated until it passes, never marked pending, and never quietly
   dropped. `NOT_YET_JUSTIFIED` is a failure.
3. **Rejection is a pass only in the branch the architecture gate names.**
   G2.4 ("Behaviour Atoms are stable enough to reuse, **or** the discrete layer
   is rejected") and G2.6 ("Future Cone adds measurable value, **or** is
   removed") pass in their rejection branch only when the mechanism is off *in
   code* and this run reproduces the measurement that rejected it.

The gate is a runtime module, so it is stdlib-only and may not import
`stage2/research/` (ADR-0001, ADR-0008). The baseline suite therefore does not
run inside it. Offline research measures the frontier and writes
`results/stage2-frontier.json`; the gate reads that file and **refuses evidence
whose `(corpus, count, seed)` does not match the split it ran itself**. Missing
evidence makes G2.1 and G2.2 fail as `UNMEASURED`, never pass.

## Options considered

| Option | Security cost | Resource cost | Complexity | Why not chosen |
|---|---|---|---|---|
| Keep the prose status in `PROGRESS.md` | A false claim survives indefinitely; no test notices a regression | none | none | The claim is unverifiable, which is the defect |
| Executable gate, research imported lazily inside the three checks that need it | numpy reaches a runtime module through a deferred import — the exact back door `test_runtime_never_imports_research_code` exists to block | numpy on the endpoint | low | Rejected during this wave: the AST test failed on `gate.py:220` and the honest fix was the data seam, not an exemption |
| Executable gate + research-written evidence file (**chosen**) | none; the runtime stays stdlib-only and refuses mismatched evidence | one JSON file in `results/` | one dataclass and one loader | — |
| Restate G2.1/G2.2/G2.3 so the gate passes | Catastrophic: the repository would then claim a Stage 2 that measurement contradicts | none | none | This is the failure mode the honesty contract exists to prevent |

## Consequences

**Accepted costs.** `pocketsec-stage2 gate` exits 1, and will keep exiting 1
until real telemetry or a genuinely different mechanism changes a measurement.
CI cannot treat a green Stage 2 gate as a precondition for anything, and should
not: Stage 3's entry criterion is the export interface (G2.13), not a passing
Stage 2.

The gate is slow — it compiles two corpus splits through Stage 1 and runs the
drift corpus, the poison suite and the counterfactual probes. That is the price
of running the subsystems rather than reading about them.

**Bounded state.** No new endpoint state. The gate allocates the same bounded
structures the runtime does (`WindowStore` ≤ 64 lineages, `TransitionLattice`
≤ 4096 edges, `TransitionCache` ≤ 1024 entries, `WorkLedger` ≤ 4096 accounts) and
measures the result with `ResourceSampler` against the Stage 0 `edge` profile.
The Stage 3 export it builds is written to a temporary directory and deleted.

**Reversibility.** Deleting `gate.py` and `cli.py` restores the previous state,
and nothing else depends on them. The frontier evidence file is regenerable by
re-running the research CLI.

**What would change this decision.** A corpus — almost certainly real telemetry
— on which a predictive core beats a TCN on detection, compute or attribution,
and on which `saturation_check` does not refuse. Then G2.1 and G2.2 become
measurable and this gate will say so without being edited.
