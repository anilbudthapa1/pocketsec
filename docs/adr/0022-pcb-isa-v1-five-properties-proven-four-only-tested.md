# ADR-0022 — PCB ISA v1: five properties proven by construction, four only tested

- **Status:** Accepted
- **Date:** 2026-09-25
- **Stage:** 3
- **Deciders:** Stage 3 integrator
- **Supersedes / superseded by:** none

## Context

The PocketSec Cell Bytecode verifier (D3.6) is where formal-verification language
is most tempting. A bytecode VM that is "safe" because no test broke it is an
empirical claim, and stating it as anything stronger would be the kind of
overreach this project's gate exists to catch.

## Decision

`pocketsec/stage3/bytecode/verifier.py` publishes two disjoint tuples, and the
distinction is enforced in code rather than by review.

**`PROVEN_PROPERTIES` — proven by construction.** The proof of each is one
sentence about the ISA, not about a test suite:

1. *termination* — the program is straight-line; the ISA defines no jump, branch
   or call opcode, and `instruction_count <= MAX_INSTRUCTIONS` is checked
   statically;
2. *no unbounded loop* — by the same absence: no opcode can move the program
   counter backwards;
3. *no dynamic allocation* — `max_stack_depth` is computed exactly by abstract
   interpretation over a straight-line program and checked against `MAX_STACK`;
4. *operand-type safety* — abstract stack typing over a straight-line program is
   exact rather than an approximation, so a type error is a decision;
5. *bounded state access* — every `LOAD_*` operand indexes a fixed-size
   `CellFrame` and is range-checked at verification time; there is no indirect
   load.

`STRUCTURAL_PROVEN_PROPERTIES` carries the one statement a non-BYTECODE form may
make, because the five above are statements about an ISA and a lookup table has
none. Letting a table report "abstract interpretation found depth 0" would read
as a stronger claim than the one actually made.

**`TESTED_ONLY_PROPERTIES` — empirical, and worded as such everywhere.** That the
VM does not corrupt host state, that `decode(encode(p)) == p` over the generated
corpus, that no verified program has exceeded its declared `max_steps`, and that
operand values beyond the range check are resisted: each is "no test has observed
otherwise", and each says so in its own text.

`AssuranceLevel.A5` may be assigned only for a property in the proven set, and
`promote_cell` enforces it mechanically. A VM that is safe only because no test
broke it is A4 at best.

## Options considered

| Option | Security cost | Resource cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|---|
| A: two disjoint tuples, A5 gated on the proven one | none | none | low | gate G3.12(a): a forged A5 with a merely-empirical property and no prover is refused | **chosen** |
| B: one "verified properties" list | **high** — an empirical claim inherits a structural label | none | lower | the disjointness assertion would have nothing to assert | this is the exact overreach the criterion forbids |
| C: prove the four empirically-held properties | none | none | very high | out of scope for this wave; no prover module exists | would be a real improvement, deferred honestly |

## Consequences

**Accepted costs.** No Stage 3 cell reaches A5 in this wave, because no prover
module exists to name.

**Bounded state.** `MAX_INSTRUCTIONS = MAX_CELL_STEPS = 64`, `MAX_STACK = 16`,
`MAX_CONSTANTS = 32`, `MAX_SET_MEMBERS = 32`, plus the bounds this wave added for
the pools the spec left open: `MAX_SETS = 8`, `MAX_WINDOW_KEYS = 16`,
`MAX_TABLE_ENTRIES = 1024`. An unbounded set pool would be an unbounded operator,
and "bounded operator form" is what G3.3 checks.

**Reversibility.** Moving a property from proven to tested-only is a one-line
edit plus a reword; the gate's disjointness and wording checks make the move
visible.

**Authority.** `RAISE_OBSERVATION` emits an `EscalationDecision` marked *not
escalated*, reason `REQUESTED_BY_CELL_PENDING_AOP`. A cell requests escalation;
only the Adaptive Observation Policy holds the budget. No second escalation type
exists in Stage 3.

## Verification

`tests/test_stage3_bytecode.py`; gate criterion G3.12 parts (a) and (b), which
assert the two sets are disjoint, that no proven entry appeals to testing, and
that every tested-only entry words itself as empirical.

## Prior art

No novelty claim. `docs/prior-art/ledger.json`, entry H4.
