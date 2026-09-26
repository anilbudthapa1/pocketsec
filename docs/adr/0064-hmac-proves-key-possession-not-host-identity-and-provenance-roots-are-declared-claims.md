# ADR-0064 — HMAC-SHA256 with simulated pre-provisioned keys proves key possession, not host identity; provenance roots are declared claims; Ed25519, mTLS and QUIC are UNMEASURED

- **Status:** Accepted
- **Date:** 2026-09-26
- **Stage:** 7
- **Deciders:** Stage 7 integrator (decided at spec time, `docs/stage-7-spec.md` D7.4, §6.1, §9.2, §10; written after the measurement and review-fix sessions)
- **Supersedes / superseded by:** none

> Claim-scoping ADR. It says what Stage 7's signatures and roots prove, so that no figure
> elsewhere is read as proving more. Every docstring in Stage 7 that signs or verifies cites it.

## Context

ADR-0001 keeps the endpoint runtime free of third-party dependencies. The standard library has
`hmac` and `hashlib`. It has no asymmetric signatures (Ed25519), no key agreement, and no TLS
client-certificate or QUIC stack that Stage 7 could use in-process without a network. The spec
forbids `socket`, `ssl` and every other network or execution primitive under `pocketsec/stage7/`
(§2.2), and the fleet is simulated in-process.

Stage 6's `fleet/package.py` already takes this position for its own import path: HMAC-SHA256
"proves key membership, not host identity", and N Sybil hosts sharing one key are one vote.

Stage 7 counts evidence per **dependence cluster** (ECHO), and clusters start from each peer's
declared `provenance_root`, the administrative domain it says it belongs to. Nothing on the
endpoint can check that claim against a real domain.

## Decision

1. **Integrity is HMAC-SHA256** over `KnowledgeCapsuleV1.unsigned_bytes()`, checked with
   `hmac.compare_digest` (`identity/integrity.py`). A valid signature proves that *someone
   holding the key registered as `key_id`* produced those bytes unaltered. Nothing more.
2. **Keys are simulated and pre-provisioned.** `labs/simulated_fleet.py:simulated_key_provisioning`
   derives one pairwise key per (peer, receiver) from a lab seed. That is **key possession, not
   host identity**. A stolen key is a full impersonation. No Stage 7 module calls a valid
   signature "authentication" of a host.
3. **What the keyring does enforce:** key-to-contributor binding (a capsule whose
   `provenance_commitment.contributor` is not the key's owner is refused
   `contributor_key_mismatch`); rotation with a grace window of `KEY_GRACE_ROUNDS = 8` rounds;
   immediate revocation; no re-registration of a `key_id`; reclamation of dead records only
   (review fix R7-4); and a state digest that lets the fabric disable exchange when the trust
   store is corrupt. The replay guard bounds a replay window by `MAX_EXPIRY_HORIZON_ROUNDS = 64`
   once its entries have been evicted.
4. **The bridge's HMAC is local integrity only.** `Stage6Bridge` signs each package with a key
   it derives itself (`HMAC(bridge_secret, cluster_id)`) and verifies it against its own keyring.
   It proves the package was not altered between building and conversion on this host, and
   nothing about any peer.
5. **Provenance roots are declared claims.** `independence_group` must equal
   `provenance_root`, and both are what the sender says. In `DependenceGraph`, a shared root
   (`SAME_ROOT`) can **join** identities and never proves them independent. Behavioural edges
   (`NEAR_IDENTICAL`, `COMMON_PARENT`, `BIRTH_CO_TIMING`) can merge further.
6. **UNMEASURED, stated as such everywhere:** Ed25519 or any asymmetric per-host signature,
   mutual TLS, QUIC, real key agreement, real identity binding, and attestation of
   administrative domains. Protobuf/FlatBuffers and zstd are UNMEASURED for the same reason;
   S7X-64 uses `zlib` as a stdlib stand-in, and S7X-63 measures HMAC only.

## Options considered

| Option | Security cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|
| A. Ed25519 per-host signatures | binds a signature to one key pair, still not to a real host without a PKI | needs a third-party library | not built | ADR-0001: none in stdlib |
| B. Hand-rolled asymmetric crypto or key agreement | a hand-rolled primitive is its own vulnerability | high | not built | out of scope; would need its own review and ADR |
| C. mTLS / QUIC transport | transport authentication only; roots stay claims | needs `ssl`/network | not built | no network exists; `ssl` and `socket` are forbidden in Stage 7 (spec §2.2) |
| **D. HMAC-SHA256 with simulated pre-provisioned keys, claim scoped to key possession (chosen)** | stolen key = full impersonation; roots unverifiable | low | 372 of 372 authority-word injections refused (G7.2); forged-signature and replay cases refused in `tests/test_stage7_ingress.py` | — |
| E. Trust declared roots as independence | a Sybil mints a fresh root per identity for free | none | the `dependence_clustering=False` control; clustering's ablation measured −10.093 amplification against it (findings §M.5.1) | declared roots cost the adversary nothing |

## Consequences

**Accepted costs.**
- **The adaptive Sybil arm defeats Stage 7, as predicted.** Spec §6.1 declared SYBIL_ADAPTIVE
  unmeetable: forged roots, staggered births and jittered summaries defeat every behavioural
  edge by construction. Measured (gate G7.4, findings §M.1): ECHO's amplification on
  SYBIL_ADAPTIVE was 4.590–12.467 across S = 1…128 against a bound of 2.0, so **G7.4 FAILS**.
  ECHO's break point there is an identity share of 0.143 (S = 4), against MEDIAN's 0.04 and
  ROOT_QUORUM+LV's 0.077 (findings §M.3). On SYBIL_DECLARED_ROOT and SYBIL_FORGED_ROOTS, ECHO's
  amplification was 0.000 at every S.
- **The poison that gets through is handed to Stage 6.** SYBIL_ADAPTIVE at S ≥ 4 bridged 22
  poison decisions into 66–134 Stage 6 capsules over 24 receivers (corpus 7), all `UNCERTAIN`
  and none `TRUSTED_CANDIDATE` (findings §M.3). Stage 6's foreign prior stopped them, not
  Stage 7 (ADR-0067).
- **Budgets are keyed on an unauthenticated label** (open defect S7-AUTH-06, findings §R.8).
  The governor's per-peer inbound byte caps are checked before integrity, on the transport's
  sender label. Garbage can spend a round's inbound budget before any signature is checked.
  Fixing it needs authenticated sender binding before budgeting, which this ADR does not provide.
- **A replay can outlive the guard.** Once a key's high-water entry and a capsule's seen-id
  entry are both evicted, only `expiry_round` stops a replay. The window is bounded, not closed
  (`test_replay_after_eviction_is_bounded_by_expiry`).
- No figure in the Stage 7 findings says anything about a real peer's identity.

**Bounded state.** The keyring holds at most `MAX_KEYS = 1024` records. Since R7-4 it reclaims
REVOKED and expired-ROTATED records first, and live keys are never evicted. Under the gate's
720-round churn it refused 0 registrations after the fix, against 727 before (findings §R.4).
Keys must be at least `MIN_KEY_BYTES = 16` bytes (Stage 6's constant). All are chosen
parameters, not measurements.

**Reversibility.** An asymmetric scheme would replace `Keyring.sign`/`verify` behind the same
`IntegrityVerdict`. The claim in this ADR would then be restated, not removed: a key pair is
still not a host without an identity authority.

**Authority.** None granted. A valid signature makes a capsule well-formed foreign input and
nothing more (`CollectiveLaw.FOREIGN_IS_UNTRUSTED_EVEN_SIGNED`; the ingress's best outcome is
`POOLED`).

## What would reopen this decision

- A third-party dependency for asymmetric signatures being admitted by an ADR that amends
  ADR-0001 for Stage 7.
- An identity authority that binds provenance roots to real administrative domains (attestation
  or a PKI). It would close SYBIL_ADAPTIVE, which today breaks every variant at S = 4
  (findings §M.10).
- A real network transport. mTLS/QUIC would then be measurable and S7-AUTH-06 could be fixed by
  budgeting on an authenticated sender.

## Verification

- `tests/test_stage7_ingress.py::test_a_validly_signed_capsule_is_only_ever_pooled`,
  `::test_tampered_unsigned_unknown_revoked_rotated_keys`,
  `::test_contributor_key_mismatch_refused`, `::test_replay_and_duplicate_refused`,
  `::test_replay_after_eviction_is_bounded_by_expiry`.
- `tests/test_stage7_graph.py::test_staggered_jittered_sybils_are_not_merged` pins the adaptive
  gap as current behaviour.
- Gate G7.4 (expected to FAIL on SYBIL_ADAPTIVE; its detail cites this ADR) and G7.2.
- S7X-63 row: "HMAC-SHA256 only; Ed25519 UNMEASURED" (`labs/seventy_two_experiments.py`).
- This session: `grep -rniE "ed25519|quic|mtls" pocketsec/stage7` finds only the UNMEASURED
  notes; the Stage 7 suite ran 397 tests, 0 failures (see ADR-0061, Verification).

## Prior art

None claimed. The HMAC construction is RFC 2104. Stage 6's `fleet/package.py` states the same
key-membership limit for its own import path.
