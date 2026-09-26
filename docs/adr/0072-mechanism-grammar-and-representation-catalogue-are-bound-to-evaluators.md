# ADR-0072 — The mechanism grammar and the representation catalogue are bound to evaluators and executors

- **Status:** Accepted
- **Date:** 2026-09-26
- **Stage:** 8
- **Deciders:** Stage 8 integrator (spec D8.3, D8.14)
- **Supersedes / superseded by:** none

> Contract ADR: it fixes what a hypothesis may say and what FORGE may compile into.

## Context

Lesson 3 of Stages 2–7: never define a catalogue richer than its consumer. Lesson 2: check the
representation can EXPRESS the function first (Stage 3's bytecode could only emit a constant).
The architecture lists causal relations (`enables`, `causes_candidate`, `suppresses`,
`requires`) and modifiers (`rare`, `epoch-specific`, `user-specific`, `visibility-dependent`,
`collective`), and FORGE targets including Knowledge Cells, tiny neural nets, INT8 and ONNX.

## Decision

1. The grammar is `SINGLE`, `PRECEDES`, `CO_OCCURS`, `WITHOUT` over ≤ 2 Stage 6 `MotifStep`-shaped
   predicates of one actor, plus `REPEATED(p, k)` (k ≤ 8), DSL ≤ 256 bytes. Every member has an
   evaluator (`Mechanism.matches`).
2. Causal relations and the five other modifiers are NOT BUILT: on observational replay each
   causal relation is indistinguishable from `PRECEDES`/`CO_OCCURS` (the identifiability gate
   would always answer `EQUIVALENCE_CLASS`), and the modifiers have no evaluator in the step type.
3. FORGE's catalogue is `TYPED_RULE, MOTIF, FSM, THRESHOLD, LOGISTIC, PROTOTYPE, STUMP_TREE`, each
   with an executor. Expressibility is checked before compiling: `MOTIF` refuses `CO_OCCURS`,
   `WITHOUT`, `REPEATED` and forbidden observations; `FSM` refuses state counts > 8.
4. NOT BUILT: `KNOWLEDGE_CELL` (Stage 3's `CellISA` is single-frame and straight-line; that seam
   is Stage 9's), neural students (ADR-0070), INT8 and ONNX export.

## Options considered

| Option | Security cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|
| A. Build the causal relations | none directly | high | not built | no honest evaluator without intervention; every verdict would be EQUIVALENCE_CLASS |
| **B. Four relations + REPEATED (chosen)** | none | low | PM2 (`REPEATED`) makes `MOTIF` refuse with `MOTIF_CANNOT_EXPRESS_REPEATED` — the expressibility check fires (G8.7(c)) | — |
| C. Compile to Stage 3 Knowledge Cells | none | high | not built | the ISA cannot express a per-actor two-step relation |

## Consequences

**Accepted costs.** The grammar cannot express actor properties, timing, rarity or chains > 2.
PM2 is expected to be refuted by its MONITORING_AGENT doppelgänger for exactly that reason.

**Bounded state.** Mechanisms are ≤ 256 bytes by construction.

**Reversibility.** A grammar change is a new `GRAMMAR_VERSION`.

**Authority.** None.

## Verification

`tests/test_stage8_foundation.py` (grammar round trip, size cap), `tests/test_stage8_forge.py`
(expressibility refusals), G8.7(c).

## Prior art

No novelty claim.
