# ADR-NNNN — <short decision title>

- **Status:** Proposed | Accepted | Superseded by ADR-NNNN | Deprecated
- **Date:** YYYY-MM-DD
- **Stage:** 0–12
- **Deciders:** <who>
- **Supersedes / superseded by:** <ADR ids, or none>

> An ADR is required whenever a change touches a **contract**, a **persistence
> format**, an **authority boundary**, or the **resource model**. Those four are
> the things later stages are not allowed to quietly renegotiate.

## Context

What forced a decision? Include the measurement or constraint that made the
status quo untenable. If a number motivated this, state the measured number and
where it came from — not an estimate.

## Decision

The decision, stated so someone can tell whether the code obeys it.

## Options considered

| Option | Security cost | Resource cost | Complexity | Why not chosen |
|---|---|---|---|---|
| A | | | | |
| B | | | | |

Stage 0 principle: architecture complexity must justify itself against a simpler
baseline. If the simplest option was rejected, say what it failed to do.

## Consequences

**Accepted costs.** What gets worse, and what that is worth.

**Bounded state.** Does this change endpoint memory, queues or caches? By how
much, measured how?

**Reversibility.** How is this undone? If a compiled or learned artifact is
involved, what is the demotion or rollback path?

**Authority.** Does this move anything closer to granting execution authority
from a model output? If yes, this ADR needs a Stage 5 review before it is
Accepted.

## Verification

How a reviewer confirms the code matches this decision: the test ids, the gate
check, the benchmark case.

## Prior art

Required for any novelty claim. Link the `docs/prior-art/ledger.json` entry.
