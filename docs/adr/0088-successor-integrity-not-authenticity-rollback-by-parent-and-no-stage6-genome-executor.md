# ADR-0088 — The successor package: digests are integrity, not authenticity; rollback is by parent genome; Stage 6 has no genome executor (B9-2)

- **Status:** Accepted
- **Date:** 2026-09-26
- **Stage:** 9
- **Deciders:** Stage 9 integrator (decided at spec time, `docs/stage-9-spec.md` §4.18, §11 B9-2)
- **Supersedes / superseded by:** none

> Persistence-format and authority ADR. It fixes what a `ProofCarryingSuccessorV1` proves,
> and what it does not.

## Context

A search winner leaves Stage 9 as a `ProofCarryingSuccessorV1` (schema
`pocketsec.proof_carrying_successor.v1` @ 1.0.0). It carries the genome, its contract, its
measured evidence and a rollback artifact. Three questions needed an answer before anything
consumes it:

1. What does the package's signature prove?
2. What does "rollbackable" mean when the thing installed is a genome?
3. Can Stage 6 install it?

## Decision

1. **Integrity, not authenticity.** `signatures = (("sha256-content", <digest of the canonical
   payload>),)`. `__post_init__` refuses any payload whose recomputed digest differs, whose
   genome digest differs from the embedded genome, whose contract check fails, whose rollback
   parent differs from its recorded digest, or that holds a `FORBIDDEN_AUTHORITY_FIELDS` key. A
   content digest proves the bytes were not altered after signing. It proves nothing about *who*
   signed, and no key exists. `tampered_successor` makes four tamperings (a metric edit, a
   rollback-parent edit, a re-digested genome edit, a signature edit), and all four must be
   refused. G9.6 requires 4/4.
2. **Rollback is by parent genome.** The package carries its parent's genome and the parent's
   held-out scores digest. In the gate the parent is the Φ-oracle, the zero-parameter
   incumbent any successor would replace. Stage 9's own lab `CandidateRegistry` (bounded at 64
   installs, evictions counted, holding no production state) installs a successor and rolls it
   back. The restored genome must rescore the held-out split to the recorded digest byte for
   byte.
3. **Stage 6 has no candidate kind that executes a genome** (ADR-0056: candidate kinds are
   exactly those with an executor). `Stage6Exit.hand_over` therefore offers the *evidence
   sessions* behind a successor (at most 8 `TRANSITION_EPISODE` capsules, counterexamples first)
   to a caller-built `QuarantineGateway.admit`, and records each verdict verbatim. Nothing Stage
   9 discovers can be installed by Stage 6 today. That is blocker **B9-2**, which Stage 9 does
   not work around. Whether Stage 6 gains a genome kind is the lead's decision.

## Options considered

| Option | Security cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|
| A. An HMAC or key signature | a key with no custodian or rotation story | medium | none: no key infrastructure exists in Stages 0-9 | would claim authenticity nobody can check |
| B. A content digest, described as integrity (chosen) | cannot prove origin | low | 4/4 tamperings refused on every gate successor (G9.6, this session's gate run) | chosen |
| C. Roll back to "the previous install" | depends on registry history that eviction can drop | low | none | the parent can be evicted; the package would not be self-sufficient |
| D. Carry the parent in the package (chosen) | the package grows by one genome | low | restored held-out scores digest equals the recorded one for every gate successor (G9.6) | chosen |
| E. Invent a Stage 6 genome kind from Stage 9 | Stage 9 editing Stage 6's contract | high | none | outside this wave's ownership (spec §5 rule 1) |

## Consequences

**Accepted costs.** G9.6's rollback is proven only inside Stage 9's lab registry. The Stage 6
verdicts are recorded, and no Stage 6 install is claimed.

**Bounded state.** `MAX_REGISTRY = 64`, `MAX_EXIT_CAPSULES = 8`, `MAX_COUNTEREXAMPLES = 64`.

**Reversibility.** Schema version 1.0.0. A change needs a new `$id` and an ADR.

**Authority.** Nothing moves closer to authority: the package is a candidate and carries no
authority key.

## Verification

`tests/test_stage9_successor.py`, gate check G9.6.

## Prior art

ADR-0052 (Stage 6 rollback by fossil digest), ADR-0056 (candidate kinds with an executor).
