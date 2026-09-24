# ADR-0114 — A path is reported skipped only when the ledger proves the work did not run

- **Status:** Accepted
- **Date:** 2026-09-24
- **Stage:** 2
- **Deciders:** Stage 2 completion wave, `routing` work package
- **Supersedes:** the notional path accounting recorded in ADR-0010. **Extends:**
  ADR-0001 (stdlib-only runtime), ADR-0003 (no authority in model output).

## Context

ADR-0010 recorded the single most damning measurement in Stage 2:

> the Need router reports 100% of events resolved on cheap paths (P0–P2) while
> the model is still 3.4× slower than the TCN. The path accounting is notional:
> every branch is computed regardless of its gate, so routing labels work rather
> than avoiding it.

Two numbers from that entry, both already in the repository and neither produced
in this session: the router costs **−0.115 PR-AUC** on the ambiguous corpus, and
`DTLConvModel` runs at **22.3 µs/event** against the TCN's **6.6** while
reporting a 100 % cheap-path histogram. The reported wake rate was a *label*
attached to each event by `DTLModel.path_histogram`
(`research/dtl.py:515-558`), computed from a need score and never checked
against what the forward pass actually executed. Stage 2 acceptance criterion 10
asks the stage to "quantify how much traffic avoids expensive inference". The
existing mechanism could satisfy that criterion while avoiding nothing.

The defect is not a bug in the router. It is that the *caller decided the path*.
Any accounting in which a caller states its own path can produce a 100 % cheap
histogram over a run that computed everything, and no reviewer reading the
histogram can tell.

## Decision

`ExecutionPath` is **derived**, never declared.

`pocketsec/stage2/router/accounting.py` records units of work
(`WorkKind` × `performed` × `units`) and derives the reported path from the
highest-cost `WorkKind` that was actually performed, ordered by
`core_ids.PATH_COST_UNITS`. Concretely:

1. `WorkLedger.close()` takes no path argument and never will.
2. `PathAccount.__post_init__` re-derives the path from its own `work` tuple and
   raises `ContractError` on a mismatch, so the type cannot be constructed with a
   cheap path over expensive work even by a caller that bypasses the ledger.
3. A record with `performed=False` must cost `0.0` units. "Units I avoided" is
   the exact shape of a phantom saving, so it is a contract error.
4. `measured(ledger, kind, units)` writes its record in a `finally` block and
   **never writes a skip**. A raise or an early return inside the body still
   charges the work, because compute spent halfway through inference was still
   spent. A genuine skip is recorded by the branch that did not enter the block.
5. `WorkLedger.assert_no_phantom_savings()` raises when any kind appears both
   skipped and performed, checking the open account as well as the closed ones.
6. `router/policy.py` keeps the deterministic need-score policy (DTL-F02) and
   imports nothing from `accounting`. The policy *proposes*; the ledger *decides*
   what is reported. A test asserts the import does not exist.

`ROUTER_DEFAULT_ENABLED = False`. This ADR does not ship a router, because no
measured design in this repository delivers savings. It ships the accounting that
makes a future savings claim checkable.

`compute_units_per_event()` reports units **actually spent**, not a
`PATH_COST_UNITS`-weighted total. `PATH_COST_UNITS`' docstring claims calibration
from measured CPU time and no calibration code exists anywhere in the repository,
so a weighted figure would be a policy simulation wearing a measurement's
clothes. `WorkLedger.to_dict()` therefore emits
`"path_cost_units_calibrated": false`.

## Options considered

| Option | Security cost | Resource cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|---|
| **A. Keep the need-score histogram (status quo of ADR-0010)** | None directly, but it makes criterion 10 unfalsifiable | 0 | lowest | **Measured: reports 100 % P0–P2 while running at 22.3 µs/event vs the TCN's 6.6 (ADR-0010).** The claim and the cost contradict each other | Rejected. A metric that cannot fail is not a metric |
| **B. Caller declares a path, ledger records it** | Same failure, now with a data structure | ~34.6 µs/event for a 6-record account (measured this session) | low | **Unmeasurable by construction**: nothing distinguishes a declared cheap path from an earned one | Rejected. This is option A with more code |
| **C. Derive the path from performed work (chosen)** | None. Carries no authority (ADR-0003); it is bookkeeping, not a verdict | **Measured this session: 34.58 µs/event for a 6-record account, 3000 accounts in 0.1037 s.** Ledger bounded at 4096 accounts, truncation explicit | moderate — one enum, three dataclasses, one context manager, 374 lines | **Measured this session:** the ADR-0010 defect simulation (gate every branch, compute all of them) reports **P0 fraction 0.0000, P4 fraction 1.0000, 91.0 performed units/event** — i.e. the false saving is refused. The honest-skip control reports **P0 fraction 1.0000, 1.0 unit/event** | Chosen |
| **D. Wall-clock timing per branch instead of unit records** | None | Higher: `perf_counter` around every branch, and timing noise at ~µs granularity | moderate | **Not measured.** Per-branch wall clock at single-µs scale is dominated by the timer; `research/sleeping_brain.py` already measures whole-path µs/event, which is the honest cost number | Rejected as the *primary* mechanism; retained as the companion figure the ledger's docstring points at |

The simplest option (A) was rejected because it failed to be falsifiable: it
produced a 100 % cheap-path number over a run that computed every branch.

## Consequences

**Accepted costs.** Every call site that wants a path must record its work, so
the accounting is intrusive by design — a subsystem that forgets to record is
reported as P0 with zero units, which understates it. That is the safe direction
only because *any* performed expensive record lifts the whole event; it is not
safe if a subsystem records nothing at all. `measured()` exists to make the
correct call the short one.

`measured()` never records a skip, which means the flag is constant inside it.
That is deliberate: the skip belongs to the branch that did not run, and making
the two shapes textually different is what keeps a reviewer able to see which is
which.

**Bounded state.** `WorkLedger` retains at most `MAX_LEDGER_EVENTS = 4096`
closed accounts. Beyond that, accounts are still returned to the caller but no
longer retained and `truncated()` returns `True`, so `histogram()` and
`compute_units_per_event()` describe the retained accounts and say so.
`begin()` refuses to open a second account while one is open, because an
abandoned account silently loses its records.

**Reversibility.** The module is additive and stdlib-only. Removing it removes
the ability to make a checkable savings claim; it breaks nothing else. The
rejected router is not resurrected by this ADR and `ROUTER_DEFAULT_ENABLED`
stays `False` until a measurement reverses −0.115.

**Authority.** None. A `PathAccount` is bookkeeping about compute, carries no
verdict, no score and no evidence, and nothing in it can grant execution
authority (ADR-0003).

## Verification

`tests/test_stage2_routing.py`, 49 tests, all passing this session. The
load-bearing one is
`test_a_gate_that_computes_every_branch_cannot_report_a_saving`, which
reproduces the ADR-0010 defect exactly — the policy proposes P0 for all 24
events and every branch is then computed — and asserts the ledger reports a P0
fraction of 0.0 and a P4 fraction of 1.0. Its positive control is
`test_a_genuine_skip_is_the_only_way_to_earn_a_cheap_path`.

The anti-weakening test is `test_no_caller_may_declare_a_path`: it asserts by
`inspect.signature` that `WorkLedger.close()` takes only `self`, that no module
function accepts a `path` parameter, and that `PathAccount(path=P0, work=(a
performed COUNTERFACTUAL,))` raises `ContractError`. If ADR-0114 is ever undone,
that test fails.

Stage 2 gate checks G2.3 and G2.10 are the intended consumers.

## Prior art

No novelty claimed. This is standard accounting discipline — record the work, do
not let the payer write the receipt — applied to a wake-rate metric. The
underlying lesson matches the spec's own cited warning (Bilot et al., "Sometimes
Simpler is Better", USENIX Security 2025): the elaborate mechanism did not beat
the simple one, and the number that said otherwise was measuring itself. No
`docs/prior-art/ledger.json` entry is required because no novelty is claimed.
