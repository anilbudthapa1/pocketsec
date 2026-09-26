# ADR-0065 — What leaves the host, by field; evidence as keyed commitments; `attack_mappings` always empty; DP only on population count releases (geometric mechanism); PrivacyCost, policy distance and architecture distance not bound

- **Status:** Accepted
- **Date:** 2026-09-26
- **Stage:** 7
- **Deciders:** Stage 7 integrator (decided at spec time, `docs/stage-7-spec.md` D7.2, D7.3, D7.5, D7.6, §10; written after the measurement and review-fix sessions)
- **Supersedes / superseded by:** none

> Persistence-format and privacy ADR. It fixes the exact wire content of a
> `KnowledgeCapsuleV1` and the exact scope of the one differential-privacy claim. The
> measurements below were made by attack on a synthetic corpus; none is a guarantee.

## Context

"Raw telemetry stays local" is not a privacy result. A sharing design leaks through whatever
fields it adds for its own convenience: identifiers, timestamps, evidence digests a peer can
test guesses against, and context sketches that single out a host. Architecture §29 asks that
privacy cost be accounted, not asserted.

Three architecture terms needed a disclosure the receiver could consume:
- §8's `PrivacyCost(K)` in knowledge gravity: the receiver cannot observe what disclosing a
  capsule cost its sender.
- §7's `policy_distance` and `architecture_distance`: no exported field carries them, and
  exporting a policy digest would be new disclosure with no other consumer (lesson 3).
- `attack_mappings` "if evidenced": nothing in Stage 7 evidences an ATT&CK mapping.

## Decision

1. **The wire is exactly `privacy/distiller.py:EXPORT_FIELD_TABLE`**: 38 flattened key paths of
   `KnowledgeCapsuleV1.to_dict()`, each with a disclosure class and rationale. An undeclared
   field cannot leave. Counted this session by class:

   | class | paths | what it discloses |
   |---|---|---|
   | PROTOCOL | 16 | schema, type, stance, ids, `signature`, `key_id`, `sequence` (**reveals export volume**), rounds, parents, revocation fields, `attack_mappings`, `privacy_class` |
   | SEMANTIC_CLASS | 3 | `semantic_invariant` (relation id and property bitmasks only), `compact_feature_signature`, `causal_motif` |
   | COARSE_CONTEXT | 9 | `epoch_context.software_epoch` (**unkeyed** hash of kernel id and package digest: linkable across hosts sharing an image, by design), `epoch_context.visibility`, `source_context_sketch.role` (disclosed by design), `source_context_sketch.family_profile` (4-level share per relation family), `time_window` (rounds), `observability.*` |
   | SELF_REPORTED_COUNT | 6 | `validation_summary.*`, `falsification_summary.*` |
   | PSEUDONYM | 3 | `provenance_commitment.contributor` = `"peer-" + HMAC(host_secret, "contributor:" + scope)[:16]` (links every capsule of one host in one scope, by design), `provenance_root`, `independence_group` |
   | COMMITMENT | 1 | `provenance_commitment.evidence_commitments` |

2. **Evidence leaves only as keyed commitments:** `"hc-" + HMAC(host_secret, "evidence:" +
   digest)[:32]`. `evidence_commitment` refuses anything but a `sha256:<64 hex>` digest. A peer
   cannot test membership of an evidence digest it guesses; the contributor can open the
   commitment later.
3. **Never leaves:** raw event fields (paths, addresses, ports, uids, pids, command lines),
   `EncodedStep.features`, `time_bucket`, `delta_phi`, `source_group`, causal and parent
   signatures, raw `sha256:` evidence digests, Stage 6 capsule ids and source groups,
   `SystemIdentity` fields in clear, labels, and any baseline or normality anchor. Every string
   value must fullmatch `WIRE_STRING_SHAPES`, and `residual_identifier_hits` re-screens every
   compiled capsule and every received one.
4. **`attack_mappings` is always `()` in v1.** Construction refuses a non-empty value.
5. **DP is claimed only for the per-round population count release** that feeds collective
   novelty (`privacy/ledger.py:release_counts`). The mechanism is two-sided geometric (discrete
   Laplace) noise of scale 1/ε with integer output. The claim is pure ε-DP per released count,
   under a per-host, per-pattern contribution clamp of 1 that the **caller** must enforce, with
   basic composition across releases enforced by the ledger's budget (`EPSILON_BUDGET = 4.0`
   over a sliding `PRIVACY_WINDOW_ROUNDS = 64`, global across scopes). The default RNG is
   `secrets.SystemRandom()`. A seeded RNG voids the claim. It is not formally verified.
   **No DP is claimed for knowledge capsules.** Their privacy is generalisation plus
   commitments, measured by attack. They are charged to the ledger with `epsilon=None`: they use
   the release budget, never the ε budget.
6. **Not bound:** `PrivacyCost(K)` (`KnowledgeGravity` has no field for it; the sender's
   `PrivacyLedger` enforces disclosure instead), and `policy_distance` and
   `architecture_distance` (typed `None` on `EpistemicDistance`, so they cannot be mistaken for
   a measured zero). All three are UNMEASURED.

## Options considered

| Option | Security cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|
| A. Share raw `EncodedStep` records (Stage 6's fleet-item format) | full membership leakage | none | raw-steps control: membership advantage 1.000 (G7.7) | leaks exactly what the distilled form hides |
| B. Share raw evidence digests | a peer confirms a guessed digest by lookup | none | not built | commitments close this at no detection cost |
| **C. Field table, generalisation and keyed commitments (chosen)** | coarse context is a quasi-identifier (below) | medium | 0 canary hits; membership advantage 0.000 (G7.7, findings §M.1) | — |
| D. DP on knowledge capsules | a noised bitmask no longer matches anything; lesson 3 | high | not built | no consumer of a noisy motif exists |
| **E. DP only on population count releases (chosen)** | utility falls with ε (below) | low | DP curve in G7.7(e) | — |
| F. Export a policy digest to build `policy_distance` | new disclosure with no other consumer | low | not built | lesson 3 |
| G. SIEM oracle (every raw labelled episode to the receiver) | every canary leaves | none | recall 0.750 at 1303 raw strings exposed (G7.7(f), findings §M.1) | the upper bound, reported as the trade-off |

## Consequences

**Measured** (synthetic corpus 7 unless stated; findings §M.1, §M.7, §R.5):
- Canary scan: **0 hits** over 2553 distinct exported blobs × 3177 raw strings, canaries and
  Stage 1 digests. The emitted fields equal the table for all 5 knowledge types.
- Membership inference: distilled advantage **0.000** against 1.000 for raw steps.
- Property inference (exhaustive leave-one-host-out, corrected in §R.5): distilled 20/22 =
  0.909 (chance 0.727, advantage 0.182); raw steps 21/24 = 0.875 (chance 0.667, advantage
  0.208). **In accuracy, the distilled export classifies the undisclosed property at least as
  well as raw steps.** The earlier reading "leaks a little less than raw" is withdrawn.
- **The coarse context singles hosts out.** (role, family_profile) alone gives an anonymity set
  of 1 to 10 of 22 exporting hosts on corpus 7 and 8 of 22 on corpus 11
  (`benchmarks/stage7/linkability.py`, findings §M.7). The findings RETRACT the spec's "nothing
  host-identifying leaves the host" for the coarse-context fields. No k-anonymity is applied.
  The generator has 4 software images; a real fleet with more images would make
  `software_epoch` a stronger identifier. That follows from the definition and was not measured.
- DP curve on population counts (seeded RNG, so a utility measurement and **not private**):

  | ε | novelty recall | count-membership advantage |
  |---|---|---|
  | 0.1 | 0.000 | 0.105 |
  | 0.5 | 0.000 | 0.175 |
  | 1.0 | 0.141 | 0.435 |
  | 2.0 | 0.641 | 0.755 |
  | exact | 1.000 | 1.000 |

  No ε gives both useful recall and low advantage.
- **DP is INERT on the fabric path.** `release_counts` is called only from `labs/`, and no
  runtime code calls `observe_population`, so the differential-privacy ablation fires 0 times on
  the fabric and is INERT (findings §R.5). The claim in point 5 covers a release path no runtime
  code exercises today.

**Accepted costs.**
- `sequence` reveals a host's export volume over time. Longitudinal volume leakage and timing
  side channels are UNMEASURED.
- **The ledger under-counts multi-pattern hosts.** A host contributing to *m* patterns in one
  release loses *m*·ε, but the ledger charges ε once per release (the spec's accounting). Its
  docstring says so.
- **The residual screen is a shape check** (S7-AUTH-09, findings §R.7). A HEX-encoded path fits
  the commitment and root shapes, and would pass both the screen and the canary scan.
- Self-reported counts are unverifiable by the receiver and forgeable.

**Bounded state.** `PrivacyLedger` entries are a bounded FIFO report with evictions counted. The
budget is enforced from a separate release log bounded by `max_releases`, so evicting a report
row never frees budget. `MAX_KNOWLEDGE_CAPSULE_BYTES = 4096`. All chosen parameters.

**Reversibility.** Adding a wire field means adding a table row.
`tests/test_stage7_privacy.py::test_export_field_table_is_exactly_the_wire_keys` asserts that
each type emits no undeclared path, that its paths equal the table's expectation for that
payload (a null `observability` record drops its three sub-paths), and that the union over the
five types equals `EXPORT_FIELD_TABLE`. The table and the wire cannot drift apart silently. Removing coarse-context fields would lower
linkability and weaken epistemic distance. ADR-0069 measured distance as HARMFUL as a weight in
any case.

**Authority.** None. This ADR governs disclosure only.

## What would reopen this decision

- A k-anonymity or coarsening rule for `(role, family_profile)` whose anonymity sets are
  measured, since the current fields single out 36–45 % of exporting hosts on this corpus.
- A runtime caller of `release_counts`, which would make the DP claim live and require a
  CSPRNG-backed measurement and an analysis of the per-release charge.
- A consumer for policy or architecture context that justifies its disclosure.
- Evidence that ATT&CK mappings can be derived and verified locally, which would let
  `attack_mappings` carry values.

## Verification

- `tests/test_stage7_privacy.py` (field table, residual screen, canaries, commitments, ledger),
  including `::test_export_field_table_is_exactly_the_wire_keys` and
  `::test_no_raw_fleet_string_survives_export` (the `NO_RAW_HOST_DATA_EXPORT` binding).
- Gate G7.7 (a)–(f). `labs/privacy_attacks.py`: `canary_scan`, `membership_inference`,
  `property_inference`, the DP curve.
- This session: `EXPORT_FIELD_TABLE` has 38 entries (16 PROTOCOL, 3 SEMANTIC_CLASS,
  9 COARSE_CONTEXT, 6 SELF_REPORTED_COUNT, 3 PSEUDONYM, 1 COMMITMENT);
  `dataclasses.fields(EpistemicDistance)` types `policy` and `architecture` as `None`;
  `KnowledgeGravity` has no privacy-cost field. The Stage 7 suite ran 397 tests, 0 failures
  (see ADR-0061, Verification).

## Prior art

None claimed. The geometric mechanism is Ghosh, Roughgarden and Sundararajan (2009); basic
composition is standard. The DP claim here is narrower than either paper allows.
