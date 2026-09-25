# ADR-0033 — The primary reasoning bound is work units, not milliseconds

- **Status:** Accepted
- **Date:** 2026-09-25
- **Stage:** 4
- **Deciders:** Stage 4 integrator
- **Supersedes / superseded by:** none

## Context

An attacker who can make the system branch without limit has a denial of service, and Stage 4
branches on purpose. So every quantity that grows with attacker-controlled input needs a bound
that holds by construction, and hitting a bound must degrade **explicitly** rather than
silently dropping the true world.

The obvious bound for "reasoning time" is milliseconds. On this host that would be a coin
flip. A Stage 2 gate run reported 855.31 and 3040.63 µs/event for the same two passes that read
122.48 and 647.23 at a quieter moment — a **7× inflation** between load 8–12 and load 23–67.
Measured in this session, on an ostensibly idle host, `/proc/loadavg` moved between **0.45 and
10.27** while two other waves ran their own suites. A wall-clock bound would make G4.9 a
measurement of the load average.

**What was measured this session**, under `build_world_flood(count=40, seed=23)`, with every
bound sampled at each of 1120 update steps rather than only at the end:

| bounded quantity | worst observed | bound | reached? |
|---|---|---|---|
| worlds in the field | 3 | 8 | no |
| sparse world graph nodes | 9 | 512 | no |
| sparse world graph edges | 5 | 1024 | no |
| claims in the graph | 12 | 256 | no |
| reasoning units, **per incident** | 2961 | 4096 | no |
| incident state bytes | 29651 | 8388608 | no |
| `Truncation` records emitted | **5028** | — | — |

Sampling at every step rather than at the end is not fussiness: a bound exceeded mid-incident
and pruned back under it is precisely the shape an attacker aiming at the bound would produce,
and an end-state check would see a compliant field.

## Decision

**`EntropyBudget.max_reasoning_units` is the contract. `max_reasoning_ms` is advisory and
observed-only. Every loss records a `Truncation`.**

1. **Work units are deterministic.** `WORK_UNITS` charges per step and scales with the things
   an attacker controls — world count *and* spine length. A spine-free charge stayed flat at 4
   units while wall clock grew 2.55–2.66× from a 6-node to a 48-node spine, so the budget could
   not see work the attacker was buying; the per-spine-node term was added for that measured
   reason and the measurement is recorded in the constant's docstring.
2. **`BudgetController.charge` saturates rather than raising.** It clamps at
   `max_reasoning_units` and records the overrun as `refused_units`. That is what makes
   `spend_report()["reasoning_units"] <= max_reasoning_units` true *by construction*, which is
   the invariant G4.9 asserts. Raising mid-incident would surface a budget as a crash.
3. **The reasoning bound is per incident, and the gate compares it per incident.** The gate's
   first run compared `LucidEngine.work_units` — cumulative across the whole walk — against a
   per-incident budget, and reported 106035 against 4096 as a violated bound. The bound was
   never violated. The retraction is in `docs/stage-4-findings.md`; the per-update sum equals
   the controller's own `spend_report()["reasoning_units"]` exactly (measured 2558 against 2558
   on the first flood case) and is reachable without touching private incident state.
4. **A silent drop is a defect.** `Truncation(what, identifier, reason, consequence_lost)`
   records every loss, `what` is validated against a closed `TRUNCATION_KINDS` vocabulary, and
   `consequence_lost` carries the Φ-scale consequence so an auditor can tell a bound that shed
   noise from a bound that shed the answer. `TombstoneLedger.record` returns the truncations it
   caused rather than the spec's `None`, because eviction is a loss.
5. **Provenance outlives its record.** `MAX_TOMBSTONES = 32` evicts tombstones, but the two
   things that must outlive a record do not get evicted — the sha256 digest set
   (`MAX_RETAINED_DIGESTS = 4096`) and the oscillation guard's refuted-mechanism set
   (`MAX_TRACKED_MECHANISMS = 512`) **refuse new entries** rather than dropping old ones, each
   emitting a named `Truncation`. No prior provenance is ever deleted; what an operator must
   know is that past 512 mechanisms the guard stops arming for *new* ones.

## Options considered

| Option | Security cost | Resource cost | Complexity | Why not chosen |
|---|---|---|---|---|
| **A. Work units as the contract, ms advisory, saturating charge** (chosen) | bound holds by construction; 5028 losses recorded explicitly over 1120 flood steps | 2961/4096 units and 29651/8388608 bytes at the worst flood step | moderate | — |
| B. Wall-clock milliseconds as the contract | **high**: the bound becomes a function of other processes. At the measured 7× inflation, the same incident passes at load 8 and is truncated at load 23 — and the truncation drops a world, so the *answer* depends on the host's load | none | lower | Unreproducible on this host, and a gate criterion that cannot be reproduced is not a criterion |
| C. Raise on budget exhaustion | moderate: a budget becomes a crash, and the crash is attacker-triggerable mid-incident | none | lower | Contradicts ADR-0034: a Stage 4 failure may only widen uncertainty. Saturating and recording `refused_units` keeps the invariant true and the incident alive |
| D. Unbounded world set with pruning by utility | **highest**: the denial of service is the whole point of the bound | unbounded | lower | The 2 GB host target is a hard constraint, and "prune later" is not a bound |
| E. Evict tombstone digests to stay under `MAX_TOMBSTONES` | moderate: an evicted digest lets the same refuted world re-spawn, and the field oscillates while the budget drains | slightly lower | lower | Deleting provenance is forbidden outright. Refusing new digests past the ceiling loses the *guard* for new mechanisms, which is a smaller and a *recorded* loss |

## Consequences

**Accepted costs.** Two numbers instead of one: a contract in work units and an observation in
milliseconds, and a reader has to know which is which. `max_reasoning_ms` is reported and never
asserted; G4.9's detail string says so explicitly.

A real limitation, stated because the flood did not exercise it: **the world bound was never
reached.** The flood peaked at 3 of 8 worlds, so this gate run demonstrates the bounds *holding*
and does not demonstrate explicit degradation *at* a bound.
`tests/test_stage4_lifecycle.py` drives that path with a 700-step synthetic adversarial residual
stream and a 400-step flood through the real field, and that is where the at-the-bound behaviour
is pinned. A reader should not take G4.9's pass — it does not pass — or its bound table as
evidence that truncation-at-the-bound was tested here.

**Bounded state.** That is the subject. Every figure above is measured, and the ceilings are
declared parameters rather than fitted ones: `MAX_WORLDS = 8`, `MAX_GRAPH_NODES = 512`,
`MAX_GRAPH_EDGES = 1024`, `MAX_CLAIMS_PER_GRAPH = 256`, `MAX_INCIDENT_BYTES = 8 MiB`,
`DEFAULT_MAX_REASONING_UNITS = 4096`. None was tuned against a corpus, deliberately — a
threshold reported as a finding is a fabricated result.

**Reversibility.** The budget is a dataclass passed into `LucidConfig`; raising a ceiling is a
constructor argument. `EntropyBudget` re-declares `DEFAULT_MAX_WORLDS` etc. rather than
importing `MAX_WORLDS`, because `worlds/field.py` holds an `EntropyBudget` field and importing
it there would close a cycle through `graph/`; a mirror test asserts each value against its
owning module and names any it could not check. That duplication is deliberate, pinned, and the
alternative was an import cycle.

**Authority.** No. A budget refuses work; it cannot grant any.

## Verification

- `python -m pocketsec.stage4.cli flood` — every bound and whether it was reached, with
  `/proc/loadavg`.
- `python -m pocketsec.stage4.cli gate` — G4.9 reports all six quantities against their bounds,
  the truncation count, and which bounds were reached.
- `tests/test_stage4_lifecycle.py` — the at-the-bound behaviour, on a 700-step adversarial
  residual stream and a 400-step flood through the real `CausalBeliefField`.
- `tests/test_stage4_gate.py::test_the_four_construction_criteria_are_the_ones_that_can_be_settled`
  pins that G4.9's detail carries "All within bound: True" alongside its failing clause, so a
  future regression in the bounds cannot hide behind the clause that already fails.

## Prior art

No novelty claim is made. Deterministic work accounting in place of wall clock is ordinary
practice for reproducible resource limits. Stage 4's ledger bindings are H3 and H7, both
`NOT_REVIEWED` in `docs/prior-art/ledger.json`.


## Amendment — 2026-09-26, review-fix wave (S4-REV-01, S4-SEC-01, S4-FC-04, S4-RES-01, S4-RES-03, S4-REV-10, S4-SEC-09, S4-FC-05)

**Decision point 2 and option A's "bound holds by construction" are corrected.** What held by
construction was a *counter*: `BudgetController.charge` saturates after the work it books has
already run, and no engine step consulted `exhausted()` first. The review drove one incident for
1000 updates and every step kept running while `spend_report()` read 4096/4096. The §20
`ResolutionHorizon` was never charged by anything, so it could not close either. That is not a
work bound, and option D's rationale — "the bound excludes a DoS" — did not hold for the work.

What the engine now does, and what G4.9 now measures:

1. `LucidEngine.update` checks `BudgetController.units_exhausted()` **before** fission/fusion and
   the optional passes, refuses them, and records one `Truncation` (reason
   `max_reasoning_units:<cap>:optional_and_fission_passes_refused`). Kill, spawn and prune stay
   mandatory: refusing a birth to save units would drop the true world silently.
2. Every update charges the horizon — one transition, its work units, and the escalations Stage
   1's AOP granted (which also charge `sensor_escalation`, so `max_sensor_escalations` can now
   trigger). Once the horizon's transition or work-unit budget is spent, an update only extends the
   evidence lineage (one work unit) and the refusal is one recorded `Truncation`; a verdict reached
   before those transitions arrived is downgraded, because it never read them.
3. Per-incident state is bounded: the shadow keeps only the `observation_incomplete` transitions
   that can change it, and the field's truncation log is deduplicated and capped at 256 records
   plus one overflow record per kind (`graph/sparse_world_graph.py:append_truncations`).
4. A birth refused at `max_worlds` is now a world-kind `Truncation` carrying the residual's
   consequence. The "5028 losses recorded explicitly" in option A's row were none of them world
   losses; the refusal at capacity was discarded.

Measured by G4.9 in the review-fix session (one incident held open for all 1120 same-epoch flood
transitions): the horizon closed at update 55, every later update cost 1 unit, state bytes were
54781 at the half-way point and 54781 at the end, the truncation log held 257 of a 267 cap, and the
last-100 over first-100 mean CPU per update was 1.088 at loadavg 1.89 in one run and 0.675 at
loadavg 8.78 in the final gate run — reported, not asserted, and the spread is the host's contention.
The capacity arm at `max_worlds=2` wrote 40 world-kind records. **Consequence accepted:** most
corpus incidents (53 of 60) now reach the 64-transition horizon and stop reasoning there; that is
the §20 bound doing what it says, and it is why reasoning spent on inert mechanisms is now a
measured cost (ADR-0036 amendment).
