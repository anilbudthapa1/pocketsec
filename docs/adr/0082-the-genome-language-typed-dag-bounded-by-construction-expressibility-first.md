# ADR-0082 — The genome language: a typed DAG, termination and memory by construction, `DIV` included, macros expanded before validation, expressibility checked first

- **Status:** Accepted
- **Date:** 2026-09-26
- **Stage:** 9
- **Deciders:** Stage 9 integrator (decided at spec time, `docs/stage-9-spec.md` §4.3–§4.5; measured in the integration session)
- **Supersedes / superseded by:** none

> Contract ADR. It fixes `pocketsec.computational_genome.v1` @ 1.0.0 and the typed IR
> `pocketsec-onto-ir.1.0.0`.

## Context

The lead's orders: the genome language is typed, so every well-typed genome terminates within a
bounded number of work units and allocates bounded memory, and ill-typed genomes cannot be
constructed. Also: *check expressibility first*. A language that cannot express the incumbent
cannot find a cheaper equivalent. Stage 3's bytecode lacked division, and Stage 3's PCB ISA has no
arithmetic, `MAX` or per-lineage register (spec M0.10).

## Decision

1. **A program is a DAG of typed nodes whose argument indices are strictly below their own
   index.** It runs once per event, in index order. There is no jump, loop or call node. A loop
   can only be spelled as a forward or self reference, refused as `FORWARD_REFERENCE` or
   `SELF_REFERENCE`. Recursion can only be spelled as a self-referencing macro, refused at
   `with_macro` as `MACRO_CYCLE`, with inlining depth capped by `MACRO_DEPTH`. Unbounded
   allocation can only be spelled as a ring above `MAX_RING` or a table above its cap (refused
   at construction), or as more lineages than `MAX_LINEAGES` (cut at run time by LRU eviction,
   which is counted and recorded in `SessionRun`).
2. **Static bounds are exact and declared.** A genome declares `declared_max_state_bytes` and
   `declared_max_steps_per_event`, and construction refuses a declaration below the computed
   static bound (`DECLARED_BOUND_UNDERSTATED`). `SessionRun.work_units` equals
   `events * update_wu + readouts * readout_wu` for every scored session.
3. **`DIV` is in the seed alphabet** (safe: `0.0` on a zero divisor), so the Φ-oracle's exact
   *score values* (`|ΔΦ| / (|ΔΦ| + 8)`), not only its ranking, can be expressed.
4. **Macros are expanded before validation.** Every stored genome is validated against
   `SEED_ALPHABET`, so a promoted primitive changes what the search proposes and the description
   length it pays, never what the runtime executes.
5. **Expressibility is a precondition of G9.1**, measured on ambiguous count 60, seed 11, with the
   SSIR sessions (Stage 2's `lineage_windows` needs them).

## Options considered

| Option | Security cost | Resource cost | Complexity | Measured consequence (this session) | Why not chosen |
|---|---|---|---|---|---|
| A. Reuse Stage 3's PCB bytecode | none | lowest | low | cannot express the Φ-oracle: no `MAX`, no arithmetic, no per-lineage register (spec M0.10). DAEDALUS's `lower_to_pcb` reports every gate successor NOT PCB-expressible | cannot express the incumbent |
| B. A general interpreter with loops and a step budget | termination by budget only, not by type | a budget is a runtime property | medium | not built | the lead requires refusal at construction |
| C. A typed DAG, no loops, `DIV` included (chosen) | none | the interpreter costs ~9x a hand loop (spec M0.8); the HIL ratio this session is in docs/stage-9-findings.md | medium | `phi-oracle-squashed`, `phi-oracle-raw`, `reduced-tcn`, `order-free-control`, H1 and H2 are all **exact** (max abs error 0.0, 60 sessions). Deterministic Stage 2 scorers: `max_over_window` 96/96 exact; `last_in_window` 55/96; `mean_over_window` 46/96. The misses are sessions where Stage 2's causal-root lineage window and the genome's `actor_slot` lineage partition differ (reported, not hidden) | chosen |
| D. The full Stage 2 TCN as a genome | none | 6961 weights | — | not expressible: 6961 weights against `MAX_CONSTANTS = 32` (arithmetic from architecture constants, not a measurement). The reduced one-channel operator family is exact | the full instance exceeds the bound; its family does not |

## Consequences

**Accepted costs.** A genome cannot hold more than 32 constants or 32 nodes per program, so a
large learned model is inexpressible by design. Mean and last scorers are exact only where the
two lineage partitions agree.

**Bounded state.** Per session at most `MAX_LINEAGES * state_bytes_per_lineage` plus bounded side
tables and scratch. `MAX_SESSION_EVENTS = 4096`, with truncation counted.

**Reversibility.** Schema and IR versions are pinned; a change needs a new `$id` and an ADR.

**Authority.** A genome reads `EncodedTransition` fields only. Identity and `display_name` are
unreachable (ADR-0007). No primitive touches a file, the network or a process.

## Verification

`tests/test_stage9_ir.py` (refusals of loop, recursion and allocation genomes; exact WU),
`tests/test_stage9_genome.py`, gate check G9.1 precondition (a), `pocketsec-stage9 expressibility`.

## Prior art

None claimed. Bounded-by-construction DAG languages are standard (e.g. eBPF's verifier bounds
loops and stack).

## Addendum A (2026-09-26, review-wave fixes): the session event bound fails closed

`MAX_SESSION_EVENTS = 4096` used to cut a session's *head*: the phenotype scored the first 4096
events, dropped the rest, and returned an ordinary score. `truncated_events` was counted inside
one `SessionRun` and read by nothing else. An attacker who emits 4096 cheap events before acting
therefore got a confident, benign-looking score with nothing flagged (S9-FC-02, S9-CX-01,
S9-BOUND-01). The repository's own test pinned that behaviour (`score == 0.1  # the 0.99 events
were never processed`).

Decision: a session longer than `MAX_SESSION_EVENTS` **abstains** (`score=None`), does no work,
and counts its overflow in `truncated_events`. This is the successor contract's
`ABSTAIN_UNKNOWN` and the module's own rule for a starved meter ("never a partial score"). The
bound is unchanged, so `session_wu_max` and every static bound still hold. `FitnessRecord` now
carries `truncated_sessions`, and ARGUS has a lifecycle DEFENCE, `session_cap_padding`, that
requires every head-padded session to abstain.

What this does NOT buy: detection. Padding past the bound now yields UNKNOWN instead of a benign
score; ranked as 0.0, it still takes AP to chance. That is a coverage denial the output makes
visible, not a closed evasion. A streaming (unbounded-session, bounded-state) scorer would close
it and is not built. Verification: `tests/test_stage9_ir.py::test_events_beyond_the_session_cap_are_counted_and_never_processed`,
`tests/test_stage9_argus.py::test_padding_a_session_past_the_event_cap_buys_unknown_not_a_benign_score`,
`tests/test_stage9_evaluation.py::test_fitness_carries_sessions_that_hit_the_event_cap`.
