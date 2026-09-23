# ADR-0005 — Security state is tracked per causal lineage, not only per host

- **Status:** Accepted
- **Date:** 2026-09-24
- **Stage:** 1
- **Deciders:** Stage 1 implementation session

## Context

Stage 1 section 4 says "maintain a compact state S_t updated by each accepted
transition", which reads as one state per host. Implemented literally, that
state saturates almost immediately and stops meaning anything: root exists on
every machine, some process has external reachability on every machine, and
something reads a credential file on every machine during normal boot.

A host-wide join would therefore report the exfiltration triad as permanently
active on an idle server. Φ would be pinned high, ΔΦ would be zero for every
transition, and responsibility scoring — which is defined in terms of ΔΦ —
would collapse to noise.

The security meaning is not "root exists" but "*this* actor lineage gained root
**and** read a credential **and** can reach the internet".

## Decision

`SecurityStateV1` is tracked **per causal lineage**, keyed on the actor's stable
identity (boot + pid + start time). The Host Security State is the lattice
**join** over live lineages, retained for the "what is now true about this
machine" question that the spec assigns to it.

Φ and ΔΦ are computed per lineage. Only the lineage view feeds the interaction
terms, responsibility scoring and the Adaptive Observation Policy.

The lineage table is bounded (`max_lineages`, default 256) and evicts the
**lowest-Φ** lineage rather than the oldest, so an active attack chain stays
resident while a noisy build process churns through slots.

## Options considered

| Option | Result | Why not chosen |
|---|---|---|
| Per-lineage state, host join for reporting | Φ separates benign 0.62 / malicious 9.46 on the corpus | **chosen** |
| Single host-wide state | Saturates; ΔΦ → 0; responsibility scoring unusable | measured to be meaningless on any realistic host |
| Per-process with no ancestry | Loses the chain: a child that inherits credentials looks innocent | fails the multi-step attack case Stage 1 exists to catch |

## Consequences

**Accepted costs.** Two state views to keep straight. The host join is
order-independent (lattice join is commutative and associative), so the host
view never depends on lineage visit order — tested.

**Bounded state.** Adds one bounded table, capped at 256 lineages with
Φ-ordered eviction.

**Reversibility.** The host view is derived, so reverting means dropping the
lineage table and reading the join directly.

**Authority.** None. This is representation, not response.

## Verification

`tests/test_stage1_semantics.py::test_join_is_order_independent`,
`test_privilege_alone_is_not_dangerous`, and
`tests/test_stage1_pipeline.py::test_benign_privileged_work_stays_low_potential`.

## Prior art

No novelty claimed. Taint- and lineage-tracking are long-established in
provenance IDS work; see `docs/prior-art/ledger.json` entry H7.
