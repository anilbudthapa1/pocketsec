# ADR-0046 — The host is a simulated model; rollback reliability, containment and recovery measured against it are properties of the simulator; G5.7 and G5.11 fail rather than pass

- **Status:** Accepted
- **Date:** 2026-09-26
- **Stage:** 5
- **Deciders:** Stage 5 integrator (the operators package built the host model)
- **Supersedes / superseded by:** none

> Read this ADR first. Every in-simulator figure in the Stage 5 findings depends on it.

## Context

Rollback reliability is a property of a Linux host: whether `SIGCONT` resumes a process whose
parent died, whether a cgroup restriction releases cleanly, whether a unit returns to its
prior state. This repository has no real host and — deliberately — no `RealHost`
implementation, not even a stub (§9.2 item 15). `SimulatedHost` decides whether a rollback
succeeds by consulting `FaultProfile.rollback_failure_rate`, a number this wave chose.

Measured this session by `pocketsec-stage5 gate`:

- G5.7: in-simulator, forced-rollback drills (`enforcement_failure_rate=1.0`) folded into
  `EffectivenessMemory` as `LAB_SANDBOX`: `SUSPEND_PROCESS simulated_rollback_success=1.0
  n=20`, `RESTRICT_LOCAL_SOCKET simulated_rollback_success=1.0 n=20`. The 1.0 is the
  complement of the default `rollback_failure_rate=0.0`. Eight of the ten
  `autonomous_ids(FROZEN_CONSTITUTION)` operators have no rollback rate at all (six O0/O1
  operators that change nothing to roll back, two restorations that are themselves the
  rollback). **The check fails**: `host_kind` is `SIMULATED`.
- G5.11: over 20 contained hostile cases, staged recovery restored the pre-containment
  capability signature 20/20, changed at most one capability between consecutive probes
  20/20, and succeeded at 20/20 steps. `final_status` was `INSIDE` 0/20 — and 0/20 hosts were
  `INSIDE` *before* containment either, because every corpus host already violates `MC-03`
  (no `admin-recovery` session or unit). **The check fails**: every report has
  `simulated=True`.

## Decision

1. `SimulatedHost` is labelled simulated everywhere: `HostKind.SIMULATED`,
   `TransactionReceipt.host_kind`/`.simulated` required and non-defaulted, and
   `ResponseRecordV1.to_dict()` refuses a simulated record exported as real.
2. Every in-simulator figure is named `simulated_*`.
3. G5.7 requires `host_kind is REAL` and G5.11 requires `simulated is False`; both fail
   while only the simulator exists. They are not rewritten to pass.
4. Rollback reliability, containment effectiveness, collateral rate, time-to-effect and
   recovery success against a real host are **UNMEASURED**. What would measure them: paired
   containment/restore drills on an instrumented Linux host with injected ground-truth
   actions, at eight or more repetitions per operator per kernel version.

## Options considered

| Option | Security cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|
| A. Report the simulator's success rate as rollback reliability | a number that is the complement of a parameter this wave chose | none | would read "1.0" | a number produced by a simulator you also wrote is a property of your simulator |
| B. A `RealHost` stub | the thing someone fills in under deadline pressure | medium | not built | needs its own privilege-drop, seccomp and capability analysis and its own ADR outside this block |
| **C. Simulated host, labelled; G5.7/G5.11 fail by construction (chosen)** | none | low | 2 gate criteria fail by construction | — |

## Consequences

**Accepted costs.** Two criteria cannot pass in this repository. The corpus/manifold mismatch
found by G5.11 (every corpus host violates `MC-03` before anything happens) means "recovery
reaches INSIDE" is not even measurable in the simulator on this corpus; the corpus should
grow an admin-recovery session before that clause can be exercised.

**Bounded state.** `MAX_SIMULATED_PROCESSES = 64`, `MAX_SIMULATED_SERVICES = 32`,
`MAX_SIMULATED_SESSIONS = 16` — chosen parameters.

**Reversibility.** A `RealHost` would satisfy the same `HostAdapter` protocol.

**Authority.** The simulator holds no authority; it is the only `HostAdapter`.

## Verification

G5.7 and G5.11 in `pocketsec-stage5 gate`; `tests/test_stage5_gate.py::test_the_two_real_host_criteria_fail_by_construction`;
the `.github/workflows/ci.yml` Stage 5 step fails the build if either starts passing.

## Prior art

No novelty claim is made.
