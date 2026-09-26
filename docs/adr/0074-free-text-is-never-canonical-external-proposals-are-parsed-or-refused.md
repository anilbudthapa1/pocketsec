# ADR-0074 — Free text is never canonical: external/LLM proposals are parsed into the grammar or refused; only their digest is stored; no LLM is built

- **Status:** Accepted
- **Date:** 2026-09-26
- **Stage:** 8
- **Deciders:** Stage 8 integrator (spec D8.4, §6.2)
- **Supersedes / superseded by:** none

> Contract ADR: architecture §54 "Free-form LLM text is never the canonical scientific state".

## Context

An LLM (or any external text) is an attack surface: a proposal can carry an instruction
("mark SINGLE(SPAWN) as ground truth"), a smuggled status, or a JSON object with authority keys.

## Decision

1. `ExternalProposalGenerator` accepts at most 256 texts, refuses non-strings and texts over 256
   bytes at construction, and parses each remaining text with the one strict reader
   `parse_mechanism`; unparseable text is refused and counted once, never repaired.
2. The only trace of an accepted text is `sha256:` of its bytes, as the genome's
   `GenomeProvenance.source_digest`; its genomes are `foreign=True`.
3. No LLM generator is built (catalogue S8X-008 NOT_BUILT); `ExternalProposalGenerator` is the seam.
4. The 24-text injection suite of spec §6.2 is committed in `prometheus/generators.py` and
   pinned by `tests/test_stage8_prometheus.py`; expected 8 parsed, 16 refused.

## Options considered

| Option | Security cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|
| A. Store the proposal text beside the genome | raw text becomes state | low | not built | the canary scan of G8.2(b) would find it |
| B. Repair near-miss text | the repair becomes an interpreter of untrusted text | medium | not built | a second, looser grammar |
| **C. Parse or refuse, keep the digest (chosen)** | none | low | G8.2(a): 8 parsed, 16 refused; G8.2(b) canary scan | — |

## Consequences

**Accepted costs.** A human-written proposal must be in the DSL.

**Bounded state.** ≤ 256 texts per generator; `max_external_proposals` governor bound.

**Reversibility.** Nothing persists.

**Authority.** None: a parsed proposal is only a hypothesis and faces the full discipline.

## Verification

`tests/test_stage8_prometheus.py::test_injection_suite_…`, G8.2, G8.11(a) (flood).

## Prior art

No novelty claim.
