# ADR-0031 — The typed claim graph is six classes, not a tagged string

- **Status:** Accepted
- **Date:** 2026-09-25
- **Stage:** 4
- **Deciders:** Stage 4 integrator
- **Supersedes / superseded by:** none

## Context

The typed epistemic claim graph is not documentation. It is the mechanism that makes
"authoritative output contains zero unsupported factual claims" a **graph walk** instead of a
promise, and it is the one component of Stage 4 with value independent of whether competing
worlds turn out to be worth their cost (ADR-0036).

The failure it exists to prevent has a specific shape: an inference presented as an
observation. "Credentials were stolen" where the evidence supports "a process read a file
whose path matches a credential store". Every system that summarises security telemetry is one
careless sentence away from that, and the careless sentence is indistinguishable from the
careful one once both are strings.

A `kind: str` field would have made the separation a convention. Conventions are enforced by
reviewers, and the project's own record on this is unambiguous: S2-AUTH-01 was a boundary
"enforced in both directions by tests" that two checkers missed at once while `MEMORY.md` and
the interfaces document both asserted it held.

**What was measured this session**, over 60 exported resolutions covering 372 authoritative
claims:

| quantity | value |
|---|---|
| members of the `TypedClaim` union | 6, equal to `len(ClaimKind)` |
| `kind_of` coverage over those members | all 6 `ClaimKind` values |
| `AUTHORITATIVE_KINDS` | `{OBS, DER}` — INF and CF are structurally excluded |
| spec §D4.13 laundering attempts (a)–(g) refused | **7 of 7** |
| `unsupported_authoritative()` | **0** |
| `amplification_violations()` | **0** |
| authoritative claims of kind INF/CF/EXT/UNK | **0** |
| claim kinds actually exercised on real incidents | OBS, DER, INF, UNK |
| `theory.unbound_terms()` | `()` |

## Decision

**Six distinct frozen dataclasses, a closed `AUTHORITATIVE_KINDS`, and refusal at
construction — not validation at emission.**

1. **`TypedClaim` is a closed union of `ObservedClaim`, `DerivedClaim`, `InferredClaim`,
   `CounterfactualClaim`, `ExternalClaim`, `UnknownClaim`.** A caller cannot construct a
   seventh kind, cannot retag one as another, and cannot pass a string where a kind is
   expected. `kind_of` is total over the union.
2. **`AUTHORITATIVE_KINDS = {OBS, DER}`.** `ClaimGraph.insert(claim, authoritative=True)`
   raises `LaunderingAttempt` for anything else. An inference can never be emitted as
   authoritative, and that is a type-level fact rather than a review outcome.
3. **A `DerivedClaim`'s premises must all be in `DERIVABLE_FROM = {OBS, DER}`.** No derivation
   may rest on an inference. The rule closes the obvious laundering route: OBS → DER → INF →
   DER, with the second DER marked authoritative. That is fixture (g) and it raises.
4. **`ObservedClaim` is the only kind that may cite evidence, and its digest must match
   `^sha256:[0-9a-f]{64}$`.** Raw evidence stays referenced by digest, never inlined.
5. **The walk re-checks the digest rather than trusting the constructor.**
   `traces_to_observation(claim_id)` re-validates the pattern at every root. The spec's prose
   only required the constructor to refuse a bad digest, but G4.8 is about the digests in the
   *exported* object, and a walk that trusted the constructor would not be a walk. A test
   injects a tampered `EvidenceRef` past `__post_init__` and asserts the walk catches it.
6. **Closed vocabularies are enforced, not documented.** `KNOWLEDGE_SOURCES` = {attack, sigma,
   local} and `UNKNOWN_REASONS` = {shadowed, not_observed, insufficient_evidence} raise on
   anything else, and the error names the permitted set. A closed vocabulary enforced by
   convention is the failure this ADR exists to prevent.

## Options considered

| Option | Security cost | Resource cost | Complexity | Why not chosen |
|---|---|---|---|---|
| **A. Six frozen dataclasses + closed authoritative set** (chosen) | lowest measured: 7/7 laundering attempts refused, 0 unsupported claims over 372 authoritative ones | six small frozen records; graph bounded at `MAX_CLAIMS_PER_GRAPH = 256`, measured peak 12 on real incidents | moderate: `kw_only=True` is forced on all six, so callers construct with keywords | — |
| B. One `Claim` class with `kind: str` | **high**: every refusal becomes a runtime string comparison someone can bypass with a typo, and the seven laundering fixtures become seven code reviews | slightly lower | lower | The separation would be a convention. S2-AUTH-01 is this repository's own proof that a convention asserted to be tested can be neither |
| C. Six classes, but validate at emission rather than at insert | moderate: an invalid graph exists in memory until someone exports it, and an intermediate consumer sees it as valid | same | lower | `unsupported_authoritative()` would then report on a graph that should never have been built. Refusing at `insert` means the invalid state is unrepresentable |
| D. Allow INF in `AUTHORITATIVE_KINDS` behind a flag | **highest**: the flag is the laundering route, and it would be set by whoever most wanted the claim | none | none | Refused. This is the single property the stage exists to guarantee |
| E. Trust `ObservedClaim.__post_init__` for digests and skip re-checking in the walk | moderate: a record mutated or deserialised past the constructor carries a bad digest into the export | cheaper walk | lower | G4.8's subject is the exported object. A test constructs exactly that case and the walk catches it |

## Consequences

**Accepted costs.** All six classes are `kw_only=True` — forced, not stylistic: the shared base
carries defaulted fields (`premises`, `evidence`) and every subclass adds required ones, which
is a "non-default argument follows default argument" error otherwise. Every caller in every
other Stage 4 package constructs claims with keywords.

Two narrower costs are worth naming because they are places where the rule was *not* applied
uniformly, each with a reason:

- **`UnknownClaim` is exempt from the forbidden-verb arm of §21.** §23's own example unknown is
  "direct exfiltration evidence"; naming an unobserved possibility is the opposite of
  amplifying it, and refusing it would make the UNK vocabulary unable to describe the gaps it
  exists for.
- **A hedged claim may carry a forbidden verb.** Without `HEDGE_MARKERS` the spec's own example
  `mechanism_id` "compromised_admin_session" would be uncompilable, because "possible
  compromised admin session" contains "compromised". §21's own line is that "possible
  credential access" is permitted where "password stolen" is not, so the hedge *is* the
  distinction the section draws. The object-class arm still applies to hedged claims, which is
  what refuses "possible credential exfiltration" from `CREDENTIAL_MATERIAL` evidence.

**Bounded state.** `MAX_CLAIMS_PER_GRAPH = 256`, `MAX_CLAIM_DEPTH = 8`,
`MAX_PREMISES_PER_CLAIM`, `MAX_TRUNCATION_RECORDS = 64` with the overflow record *counting*
the losses it stands for. Measured peak on real incidents: 12 claims. The truncation record is
`graph/sparse_world_graph.Truncation`, collapsed from a duplicate declaration by the
integrator after verifying the two were field-for-field identical.

**Reversibility.** The claim graph is the component most worth keeping if the rest of Stage 4
is removed, and it is deliberately separable: `claims/` imports the foundation and
`graph/sparse_world_graph.py` (stdlib + Stage 0 only), and consumes worlds, shadows and
verdicts through narrow structural Protocols rather than imports. F1's stated fallback —
"reduce Stage 4 to B6 plus the typed claim graph" — is a real option because of that.

**Authority.** This ADR is the main thing standing between a model's summary and a reader who
believes it. It grants nothing; it takes away the ability to state an inference as a fact.

## Verification

- `tests/test_stage4_claims.py` — 56 tests, including the seven laundering fixtures, the
  tampered-digest injection, and the mutation checks on the §21 arms.
- `pocketsec/stage4/gate_criteria.py:laundering_probes` — the same seven, runnable from the
  gate, so the adversarial suite is not only a test.
- `python -m pocketsec.stage4.cli gate` — G4.7 reports the structural facts and which kinds
  were actually exercised; G4.8 reports the unsupported count with a vacuity guard, so a zero
  over zero claims fails.
- `tests/test_stage4_gate.py::test_all_seven_laundering_attempts_are_refused`.

## Prior art

No novelty claim is made. Typed provenance and justification graphs are long-standing in the
literature. Stage 4's ledger bindings are H3 and H7, both `NOT_REVIEWED` in
`docs/prior-art/ledger.json`.


## Amendment — 2026-09-26, review-fix wave (S4-FC-02, S4-REV-09, S4-SEC-02, S4-FC-13, S4-REV-12, S4-SEC-03, S4-SEC-08)

**"Closed by construction" was closed by convention in one place.** `kind_of` read the class's
overridable `_KIND` attribute, so a subclass of `InferredClaim` declaring `_KIND = DER` was accepted
as authoritative and passed both G4.8 walks. `kind_of` now looks the claim's exact class up in a
fixed six-entry table and refuses anything else, subclasses included.

**The compiler laundered one inference.** It emitted, for every world, an authoritative DER reading
"N observation(s) form the causal spine of <world>" — whether those observations belong to that
world is the hypothesis. It is removed; the world's INF headline is premised directly on its OBS
claims. `compiler.DERIVATION_RULE_CATALOGUE` is the closed set of DER rules allowed to be
authoritative, and it is empty. G4.8 now also anchors every authoritative OBS digest to the digests
the incident's own Stage 1 telemetry carried. **Consequence accepted: G4.7's behavioural half —
"OBS, DER, INF and UNK all exercised on real output" — now fails**, because no honest DER exists;
the requirement was not relaxed.

The Stage 5 wire walk (now `pocketsec/stage4/stage5_walk.py`) refuses duplicate claim ids instead of
keeping the last row, runs on `CBFResolutionV1.from_dict` as well as `to_dict`, refuses
authority-named keys in hypothesis and gap rows on every construction path, and is memoised so a
crafted diamond of premises cannot make it exponential.
