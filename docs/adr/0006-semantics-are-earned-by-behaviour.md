# ADR-0006 — Semantics are earned by behaviour; names are evidence only

- **Status:** Accepted
- **Date:** 2026-09-24
- **Stage:** 1
- **Deciders:** Stage 1 implementation session

## Context

Stage 1 non-goals forbid making executable names or raw command strings
mandatory model vocabulary, and section 22 requires that renaming common tools
must not collapse semantics into identity memorisation.

The tempting implementation is a path table: `/usr/bin/curl` → NETWORK_CLIENT.
It is accurate on a clean host and worthless against an attacker, who renames
the binary. It also fails on every binary the table has never heard of, which
on a real host is most of them.

## Decision

A **capability property is granted only by an observed operation.** A process
becomes `NETWORK_CLIENT` by calling connect, `CREDENTIAL_READER` by reading a
credential, `PROCESS_SPAWNER` by spawning. `BEHAVIOURAL_PROPERTIES` enumerates
these, and nothing in the compiler assigns one from a path or command line.

**Object properties come from host metadata**, because whether `/etc/shadow`
holds credentials is a fact about the filesystem, not about who touched it.
That asymmetry is deliberate and is the dividing line: facts about the host are
looked up, facts about behaviour are earned.

`display_name` is retained on every entity for investigation and is excluded
from the SSIR binary encoding, which carries only an opaque 32-bit identity
handle.

## Consequences

**Accepted costs.** A process is uncharacterised on first sight and carries high
uncertainty until it acts. This is correct — we genuinely do not know what it
is — and it is what drives the Adaptive Observation Policy to escalate on
exactly those actors.

**Corollary discovered during implementation.** Treating "no properties
asserted" as maximum uncertainty was wrong. A classifier that ran and found
nothing has produced a *negative result*, which is information. Conflating it
with "never considered" gave routine log reads 0.55 uncertainty, which
suppressed aggregation entirely and would have driven constant needless
observation escalation. `SemanticBelief.classify` now records evaluated-absent
properties explicitly at low belief, and `note_observation` lets an actor's
uncertainty fall as it is watched behaving consistently.

**Reversibility.** Path-based hints could be added as a *prior* later, but they
must never be sufficient on their own; the adversarial tests would catch it.

**Authority.** None.

## Verification

`tests/test_stage1_semantics.py::test_classification_records_negative_results`
and the renaming / unseen-binary / obfuscation tests in the adversarial suite,
which measure identical Φ (13.75) across renamed and unseen binaries.

## Prior art

No novelty claimed. Behaviour-based typing is standard in provenance IDS
literature; see ledger entries H2 and H7.
