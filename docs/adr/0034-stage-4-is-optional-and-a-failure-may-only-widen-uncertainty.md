# ADR-0034 — Stage 4 is optional, and a failure may only widen uncertainty

- **Status:** Accepted
- **Date:** 2026-09-25
- **Stage:** 4
- **Deciders:** Stage 4 integrator
- **Supersedes / superseded by:** none

## Context

Acceptance criterion 11 is "Stage 4 remains optional to core Stage 1–3 detection if it
crashes". The project lead stated the reason for building it first, and it is an engineering
judgement rather than a ceremony: **if Stage 4 cannot crash safely, nothing else about it
matters.** Stage 4 is the most speculative machinery in the system — ten subsystems, bounded
world enumeration, counterfactual perturbation, active sensing — attached to a detection path
that already works and already has measured results.

There are two ways this could have been got wrong and the architecture makes both easy. The
first is a layer: Stage 4 sitting *in* the detection path, so a raise in a counterfactual
takes a verdict down with it. The second is subtler and worse: Stage 4 degrading into a
*more confident* answer. A subsystem that fails and leaves the verdict at `BENIGN` has turned
a crash into an all-clear.

**What was measured this session.** Ten subsystems × 12 incidents, each fault raised at the
incident's **middle** transition and nowhere else, with the hooks bound to the real Stage 4
modules rather than to stand-ins:

| quantity | value |
|---|---|
| exceptions that escaped `run_attached_cognition` | **0** |
| Stage 1 `ScenarioResult` digest, against the no-Stage-4 baseline | **unchanged** for all ten |
| Stage 2 verdicts, against the same baseline | **unchanged** for all ten |
| failing subsystems that wrote a `DegradationRecord` with their own `FALLBACKS` string | **10 of 10** |
| records whose `at_sequence` was 0 (i.e. the fault was not mid-incident) | **0** |
| Stage 4 verdicts under a crash that were `BENIGN` or otherwise committal | **0** |
| `pocketsec/stage1/` or `pocketsec/stage2/` modules importing `pocketsec.stage4` (AST) | **0** |

This is one of the four criteria spec §6.1 says this wave can actually settle, and it is the
one it settles most cleanly. `G4.11` passes.

## Decision

**Stage 4 is an attachment, not a layer, and its failure may only ever widen uncertainty.**

Five parts, each of which the code obeys:

1. **T7 is structural.** No module under `pocketsec/stage1/` or `pocketsec/stage2/` may import
   `pocketsec.stage4`, asserted by an AST walk with a committed negative fixture of relative
   import forms. Detection cannot depend on cognition, so cognition cannot break it.
2. **Every subsystem call is wrapped.** `engine/degradation.py:guarded` catches
   `BaseException` except `KeyboardInterrupt` and `SystemExit`, writes exactly one
   `DegradationRecord` per failed scope, and returns the declared fallback. The record carries
   a one-line message capped at 240 characters — never a traceback, because a traceback in a
   degradation record is an exfiltration channel and an unbounded field at once.
3. **The fallback is declared, not invented.** `FALLBACKS` holds the §45 rule per subsystem
   and construction is refused if a record's fallback does not match its subsystem's entry.
   A fallback chosen at the crash site is a fallback nobody reviewed.
4. **A crash may not produce a committal verdict, and may never produce `BENIGN`.** A crashed
   `CLAIM_COMPILER` yields `Verdict.UNIDENTIFIABLE` (nothing was resolved); a crash in any of
   the other nine downgrades the compiler's verdict to `UNKNOWN` (`DEGRADED_VERDICT`). Both
   are in `NON_COMMITTAL_VERDICTS`. The two are kept apart because "no resolution" and "a
   resolution the surrounding reasoning no longer supports" are different facts about the run.
5. **The ledger is bounded.** `MAX_DEGRADATION_RECORDS = 64`, with drops counted rather than
   silent. A subsystem is disabled after its first failure, so ten subsystems cannot fill it;
   the cap exists for the caller that re-attaches per incident and never drains.

## Options considered

| Option | Security cost | Resource cost | Complexity | Why not chosen |
|---|---|---|---|---|
| **A. Attachment + `guarded` + declared fallbacks + non-committal downgrade** (chosen) | lowest measured: 0 escapes, 0 digest changes, 0 committal verdicts under ten injected faults | one bounded ledger, ≤64 records, one line each | moderate: ten wrapped scopes | — |
| B. Stage 4 in the detection path, wrapped at the top level | **high**: one try/except cannot tell which subsystem failed, so the fallback cannot be the one §45 declares for it, and the verdict degrades wholesale | lower | lower | The measurement that matters is per-subsystem. A single outer catch would have reported "Stage 4 failed" for all ten cases and could not have shown that a `CLAIM_COMPILER` failure differs from a `WORLD_GRAPH` failure |
| C. Let exceptions propagate and have the caller decide | **highest**: Stage 1's verdict becomes contingent on Stage 4 not raising, which is the opposite of the criterion | none | lowest | This is the failure mode the criterion exists to prevent |
| D. Degrade to the last known verdict | **highest**: on a crash mid-incident the last known verdict may be `BENIGN`, so a failure becomes an all-clear | none | low | Refused. `DEGRADED_VERDICT` is in `NON_COMMITTAL_VERDICTS` and the gate asserts no crash ever yields `BENIGN` |
| E. Catch `Exception` rather than `BaseException` | moderate: a `MemoryError` or a subsystem-raised `BaseException` subclass escapes and takes the detection path with it | none | none | The 2 GB host target makes `MemoryError` a realistic subsystem failure, not a theoretical one. `KeyboardInterrupt` and `SystemExit` are re-raised, because swallowing an operator's interrupt is its own defect |

## Consequences

**Accepted costs.** Ten guarded scopes per update step, and a fallback value declared at
every call site. Failures become data rather than stack traces, which means a genuinely
broken subsystem can run degraded for a long time without anyone noticing — so the
degradation ledger is part of `IncidentResolution` and of the Stage 5 export, not an internal
detail. `Stage4ResourceReport` refuses `within_target=True` beside a missing observation for
the same reason.

**Bounded state.** Yes, and bounded on purpose: `MAX_DEGRADATION_RECORDS = 64`, messages
capped at 240 characters, drops counted. Measured peak incident state under the adversarial
flood is 29651 B against `MAX_INCIDENT_BYTES = 8388608`.

**Reversibility.** Total. Removing Stage 4 is removing the attachment call; nothing under
`stage1/` or `stage2/` references it, which is what T7 guarantees structurally rather than by
convention. `CBFSlot` satisfies `ModelSlot` and abstains by default via
`NullIncidentEngine`, following `NullModelSlot`'s precedent, so a deployment can carry the
slot without carrying the engine.

**Authority.** No — and this ADR is part of why. A degraded Stage 4 produces a
non-committal verdict and an `information_gaps` list; it cannot produce an instruction, and
it cannot produce `BENIGN`. See ADR-0039 for the seam.

## Verification

- `python -m pocketsec.stage4.cli gate` — G4.11 reports the ten-subsystem injection with the
  escape count, the digest comparison and the fallback-string check.
- `tests/test_stage4_optionality.py` — 53 test functions, 363 parametrized cases, including
  the paired baseline/healthy/faulted replays.
- `tests/test_stage4_gate.py::test_g4_11_injected_faults_into_the_real_subsystems_not_stand_ins`
  — pins that the gate's hooks call the real modules, because a fault injected into a
  stand-in proves the harness is isolated rather than the subsystem.
- `tests/test_stage4_gate.py::test_an_injected_fault_fires_mid_incident_and_nowhere_else` —
  pins that the fault lands at `evidence.middle_sequence` and that this is greater than 0.
- `tests/test_stage4_boundary.py::test_no_earlier_stage_imports_stage4` — the structural half.

## Prior art

No novelty claim is made. Guarded degradation with declared fallbacks is ordinary
fault-tolerant engineering; nothing here asserts priority. Stage 4's ledger bindings are H3
and H7, both `NOT_REVIEWED` in `docs/prior-art/ledger.json`.


## Amendment — 2026-09-26, review-fix wave (S4-FC-01, S4-FC-03, S4-MEAS-06, S4-REV-06, S4-FC-09, S4-RES-04, S4-SEC-06, S4-SEC-05)

**The Context table above measured the integrator's hook harness, not the engine.** The review ran
G4.11 with every `LucidEngine` entry point replaced by a function that raised, and it still
reported PASS with zero escapes. Decision point 2 ("Every subsystem call is wrapped") was also
false for the engine: `visibility_adjusted_verdict`, `gaps_from`, `uncertainty_of` and the export
fallback in `close_incident` ran unguarded, and all four escaped when faulted. And the ledger was
engine-lifetime, so one fault downgraded every later incident's verdict and was exported in their
Stage 5 records.

Now:

1. G4.11 has an **engine arm** (`pocketsec/stage4/gate_optionality.py`): the real engine, driven
   `open_incident -> update -> resolve -> close_incident`, with a fault patched into each of 11
   real call sites and armed for one incident, mid-incident. It fails on any escape, any committal
   verdict for the faulted incident, a faulted incident with no record, a record leaking into
   another incident, or a fault point that never fired. The hook arm is kept beside it.
2. Every call in `resolve` and `close_incident` goes through `guarded`; a failed export retries on a
   minimal field and then falls back to a record built from primitives only.
3. Each incident owns its `DegradationLedger`; `engine.degradation` is the roll-up for reporting.
   Verdict downgrades and the exported `degradations` read the incident's own ledger.
4. `CBFSlot.predict` now also guards building the prediction from a well-typed engine outcome, so a
   NaN confidence degrades the slot instead of escaping. A wrong return *type* still raises, as a
   wiring error an existing test pins.

Part 5 above ("A subsystem is disabled after its first failure") describes the hook harness only;
the engine re-runs a failing step on every transition, and each run writes a record into the
incident's bounded ledger.
