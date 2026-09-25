"""D4.13 part two — the claim graph that refuses to launder an inference.

``ClaimGraph`` holds typed claims and the subset marked *authoritative*. It is
immutable: ``insert`` returns a new graph, because an authoritative output that
could be edited in place has no auditable predecessor.

Four refusals, every one raising :class:`LaunderingAttempt`:

1. ``authoritative=True`` with a kind outside ``AUTHORITATIVE_KINDS`` — an INF or
   CF claim can never be emitted as authoritative, at any support;
2. a ``DerivedClaim`` any of whose premises is outside ``DERIVABLE_FROM`` — no
   deterministic derivation may rest on a model's guess;
3. a premise id absent from the graph — no dangling support, so the G4.8 walk
   can never terminate on "the premise is elsewhere";
4. depth above ``MAX_CLAIM_DEPTH``, or a cycle — a cycle is the shape that makes
   a claim support itself, which is how a chain "roots in OBS" without ever
   reaching one.

The same refusals run in ``__post_init__``, not only in ``insert``. That is
deliberate: a caller who builds ``ClaimGraph(claims=..., authoritative=...)``
directly must not get a weaker object than one built by inserting, or the
invariant would be a property of the API rather than of the type.

:meth:`ClaimGraph.unsupported_authoritative` is the mechanical form of gate
criterion 8 — **G4.8 is that method returning ``()``**.

Bounds are hard: ``MAX_CLAIMS_PER_GRAPH`` claims, ``MAX_CLAIM_DEPTH`` premise
depth. Hitting a bound produces a recorded :class:`ClaimTruncation`, never a
silent drop, because an attacker who can make the graph grow without limit
otherwise gets to choose which true claim disappears.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage4.claims.typed_claim import (
    AUTHORITATIVE_KINDS,
    DERIVABLE_FROM,
    ClaimKind,
    CounterfactualClaim,
    DerivedClaim,
    ExternalClaim,
    InferredClaim,
    ObservedClaim,
    TypedClaim,
    UnknownClaim,
    kind_of,
)
from pocketsec.stage4.graph.sparse_world_graph import Truncation

__all__ = [
    "EMPTY_CLAIM_GRAPH",
    "MAX_CLAIMS_PER_GRAPH",
    "MAX_CLAIM_DEPTH",
    "MAX_TRUNCATION_RECORDS",
    "ClaimGraph",
    "ClaimTruncation",
    "LaunderingAttempt",
]

#: Hard bound on graph size. Asserted under the adversarial branch flood (G4.9).
MAX_CLAIMS_PER_GRAPH: int = 256
#: Hard bound on premise-chain depth. Bounds the G4.8 walk to
#: ``MAX_CLAIM_DEPTH * MAX_PREMISES_PER_CLAIM`` edges per authoritative claim.
MAX_CLAIM_DEPTH: int = 8
#: Bound on the truncation log itself. Past this, further losses are coalesced
#: into one overflow record that *counts* them, so the log cannot become the
#: unbounded thing it exists to prevent.
MAX_TRUNCATION_RECORDS: int = 64

_OVERFLOW_IDENTIFIER = "truncation_log_overflow"
#: Re-checked during the G4.8 walk, not only at construction: see
#: ``ClaimGraph.traces_to_observation``.
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class LaunderingAttempt(ContractError):
    """Raised when an insert would let an INF/CF/EXT/UNK claim support an authoritative one.

    A subclass of ``ContractError`` on purpose: this is a contract violation, and
    Stage 0's rule is that contracts fail loudly rather than being weakened to
    make a caller pass.
    """


#: The claim graph's truncation record **is** the world graph's. Collapsed by the
#: integrator: the two were declared separately during the wave because package 3's
#: declared dependency set was "foundation only", and they were then verified
#: field-for-field identical (``what``, ``identifier``, ``reason``, ``consequence_lost``,
#: all frozen, all slotted). Two identical records is how a hole gets closed in one of
#: them and not the other (the S2-AUTH-01 lesson).
#:
#: ``Truncation`` is the one kept, and it is the *stricter* of the two: it validates
#: ``what`` against the closed ``TRUNCATION_KINDS`` vocabulary, which ``ClaimTruncation``
#: did not, and it refuses a negative ``consequence_lost``. Every construction site in
#: this package already passes ``what="claim"``, which is in that vocabulary, and already
#: passes ``consequence_lost`` explicitly — so nothing here relied on the looser
#: constructor or on its ``= 0.0`` default.
#:
#: The claims package's original reason for declaring its own was that a runtime import
#: would "couple the honesty mechanism to a subsystem that consumes it". That reason does
#: not hold on inspection: nothing under ``graph/`` imports ``claims/``, and
#: ``graph/sparse_world_graph.py`` depends on the stdlib and Stage 0 alone, so the claim
#: graph gains no fragility from it. The alias is kept rather than the name removed, so
#: every existing caller and import of ``ClaimTruncation`` keeps working.
ClaimTruncation = Truncation


def _append_truncation(
    existing: tuple[ClaimTruncation, ...], record: ClaimTruncation
) -> tuple[ClaimTruncation, ...]:
    """Append within ``MAX_TRUNCATION_RECORDS``, coalescing the overflow.

    Once the log is full the final slot becomes an overflow record whose
    ``consequence_lost`` counts the losses it stands for. The count is what keeps
    this from being the silent drop the log exists to forbid.
    """
    if len(existing) < MAX_TRUNCATION_RECORDS:
        return (*existing, record)
    tail = existing[-1]
    if tail.identifier == _OVERFLOW_IDENTIFIER:
        coalesced = ClaimTruncation(
            what=tail.what,
            identifier=_OVERFLOW_IDENTIFIER,
            reason=tail.reason,
            consequence_lost=tail.consequence_lost + 1.0,
        )
        return (*existing[:-1], coalesced)
    coalesced = ClaimTruncation(
        what="claim",
        identifier=_OVERFLOW_IDENTIFIER,
        reason="truncation_log_full",
        consequence_lost=2.0,
    )
    return (*existing[:-1], coalesced)


def _kind_specific(claim: TypedClaim) -> dict[str, Any]:
    """The kind's own fields, for ``to_dict``. Exhaustive over the six kinds."""
    if isinstance(claim, ObservedClaim):
        return {"sensor": claim.sensor.value, "at_sequence": claim.at_sequence}
    if isinstance(claim, DerivedClaim):
        return {"rule_id": claim.rule_id}
    if isinstance(claim, InferredClaim):
        return {
            "world_id": claim.world_id,
            "support": claim.support,
            "shadow_penalty": claim.shadow_penalty,
        }
    if isinstance(claim, CounterfactualClaim):
        return {
            "target_signature": claim.intervention.target_signature,
            "outcome_shift": claim.outcome_shift,
        }
    if isinstance(claim, ExternalClaim):
        return {
            "knowledge_source": claim.knowledge_source,
            "source_version": claim.source_version,
            "rationale": claim.rationale,
        }
    if isinstance(claim, UnknownClaim):
        return {"reason": claim.reason, "shadow_region": claim.shadow_region}
    raise ContractError(f"unknown claim type {type(claim).__name__}")  # pragma: no cover


@dataclass(frozen=True, slots=True)
class ClaimGraph:
    """An immutable typed claim graph plus the ids marked authoritative."""

    claims: Mapping[str, TypedClaim]
    authoritative: frozenset[str] = frozenset()
    truncated: tuple[ClaimTruncation, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.claims, Mapping):
            raise ContractError(f"ClaimGraph.claims must be a mapping, got {type(self.claims)}")
        snapshot: dict[str, TypedClaim] = {}
        for key, claim in self.claims.items():
            kind_of(claim)  # refuses anything that is not one of the six kinds
            if key != claim.claim_id:
                raise ContractError(f"ClaimGraph key {key!r} != claim_id {claim.claim_id!r}")
            snapshot[key] = claim
        if len(snapshot) > MAX_CLAIMS_PER_GRAPH:
            raise ContractError(
                f"ClaimGraph holds {len(snapshot)} claims, bound is {MAX_CLAIMS_PER_GRAPH}"
            )
        object.__setattr__(self, "claims", MappingProxyType(snapshot))
        object.__setattr__(self, "authoritative", frozenset(self.authoritative))
        object.__setattr__(self, "truncated", tuple(self.truncated))
        for record in self.truncated:
            if not isinstance(record, ClaimTruncation):
                raise ContractError("ClaimGraph.truncated entries must be ClaimTruncation")
        self._validate_structure()

    # --- construction-time invariants ------------------------------------

    def _validate_structure(self) -> None:
        """Run every ``insert`` refusal over the whole graph.

        Called from ``__post_init__`` so a directly constructed graph is never
        weaker than an inserted one.
        """
        for claim_id in sorted(self.authoritative):
            claim = self.claims.get(claim_id)
            if claim is None:
                raise LaunderingAttempt(f"authoritative id {claim_id!r} is not in the graph")
            if kind_of(claim) not in AUTHORITATIVE_KINDS:
                raise LaunderingAttempt(
                    f"claim {claim_id!r} of kind {kind_of(claim).value} may never be "
                    f"authoritative; permitted kinds are "
                    f"{sorted(k.value for k in AUTHORITATIVE_KINDS)}"
                )
        for claim in self.claims.values():
            self._validate_premises(claim)
        for claim_id in sorted(self.claims):
            self._depth_of(claim_id)

    def _validate_premises(self, claim: TypedClaim) -> None:
        for premise in claim.premises:
            parent = self.claims.get(premise)
            if parent is None:
                raise LaunderingAttempt(
                    f"claim {claim.claim_id!r} cites premise {premise!r} which is not "
                    "in the graph; dangling support is unverifiable"
                )
            if isinstance(claim, DerivedClaim) and kind_of(parent) not in DERIVABLE_FROM:
                raise LaunderingAttempt(
                    f"DerivedClaim {claim.claim_id!r} rests on {premise!r} of kind "
                    f"{kind_of(parent).value}; a derivation must root in OBS"
                )

    def _depth_of(self, claim_id: str, _stack: tuple[str, ...] = ()) -> int:
        """Longest premise chain below ``claim_id``; refuses cycles and overdepth."""
        if claim_id in _stack:
            raise LaunderingAttempt(
                f"premise cycle through {claim_id!r}: {' -> '.join((*_stack, claim_id))}"
            )
        claim = self.claims[claim_id]
        if not claim.premises:
            return 0
        deeper = _stack + (claim_id,)
        if len(deeper) > MAX_CLAIM_DEPTH:
            raise LaunderingAttempt(
                f"premise chain through {claim_id!r} exceeds MAX_CLAIM_DEPTH={MAX_CLAIM_DEPTH}"
            )
        depth = 1 + max(self._depth_of(premise, deeper) for premise in claim.premises)
        if depth > MAX_CLAIM_DEPTH:
            raise LaunderingAttempt(
                f"claim {claim_id!r} sits at depth {depth}, bound is {MAX_CLAIM_DEPTH}"
            )
        return depth

    # --- mutation by copy -------------------------------------------------

    def insert(self, claim: TypedClaim, *, authoritative: bool = False) -> ClaimGraph:
        """Return a new graph with ``claim`` added.

        Raises :class:`LaunderingAttempt` for any of the four refusals. When the
        size bound is reached the claim is *not* added and a
        :class:`ClaimTruncation` is recorded instead: refusing explicitly is the
        only behaviour that cannot be used to make a true claim vanish.
        """
        kind = kind_of(claim)
        if claim.claim_id in self.claims:
            raise ContractError(f"claim {claim.claim_id!r} is already in the graph")
        if authoritative and kind not in AUTHORITATIVE_KINDS:
            raise LaunderingAttempt(
                f"claim {claim.claim_id!r} of kind {kind.value} may never be authoritative; "
                f"permitted kinds are {sorted(k.value for k in AUTHORITATIVE_KINDS)}"
            )
        if len(self.claims) >= MAX_CLAIMS_PER_GRAPH:
            record = ClaimTruncation(
                what="claim",
                identifier=claim.claim_id,
                reason=f"max_claims_per_graph:{MAX_CLAIMS_PER_GRAPH}",
                consequence_lost=1.0,
            )
            return ClaimGraph(
                claims=self.claims,
                authoritative=self.authoritative,
                truncated=_append_truncation(self.truncated, record),
            )
        claims = {**self.claims, claim.claim_id: claim}
        marked = self.authoritative | {claim.claim_id} if authoritative else self.authoritative
        return ClaimGraph(claims=claims, authoritative=marked, truncated=self.truncated)

    def with_truncation(self, record: ClaimTruncation) -> ClaimGraph:
        """Record a loss that happened outside ``insert`` (a compiler refusal)."""
        return ClaimGraph(
            claims=self.claims,
            authoritative=self.authoritative,
            truncated=_append_truncation(self.truncated, record),
        )

    # --- queries ----------------------------------------------------------

    def roots_of(self, claim_id: str) -> tuple[TypedClaim, ...]:
        """The premise-less claims reachable from ``claim_id``, id-sorted."""
        if claim_id not in self.claims:
            raise ContractError(f"claim {claim_id!r} is not in the graph")
        seen: set[str] = set()
        roots: dict[str, TypedClaim] = {}
        stack = [claim_id]
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            claim = self.claims[current]
            if not claim.premises:
                roots[current] = claim
                continue
            stack.extend(claim.premises)
        return tuple(roots[key] for key in sorted(roots))

    def traces_to_observation(self, claim_id: str) -> bool:
        """True when every root below ``claim_id`` is a digest-valid ``ObservedClaim``.

        Also requires every intermediate claim to be of a kind in
        ``DERIVABLE_FROM``: a chain that passes through an INF has not been
        traced to an observation just because its leaves happen to be OBS.

        The digest pattern is re-checked here rather than trusted from
        ``ObservedClaim.__post_init__``. G4.8 is read as a property of the graph
        that is *exported*, and the whole point of a walk is that it does not
        depend on the constructor having been the only way in.
        """
        if claim_id not in self.claims:
            raise ContractError(f"claim {claim_id!r} is not in the graph")
        roots = self.roots_of(claim_id)
        if not roots:
            return False
        for root in roots:
            if not isinstance(root, ObservedClaim) or not root.evidence:
                return False
            if not all(_DIGEST_RE.fullmatch(ref.digest) for ref in root.evidence):
                return False
        seen: set[str] = set()
        stack = [claim_id]
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            claim = self.claims[current]
            if kind_of(claim) not in DERIVABLE_FROM:
                return False
            stack.extend(claim.premises)
        return True

    def unsupported_authoritative(self) -> tuple[str, ...]:
        """Authoritative ids whose premise chain does not terminate in OBS.

        **G4.8 is this method returning ``()``.** It is the whole of "the
        authoritative output contains zero unsupported factual claims", expressed
        as something a test can run rather than something a reviewer can believe.
        """
        offenders = [
            claim_id
            for claim_id in sorted(self.authoritative)
            if not self.traces_to_observation(claim_id)
        ]
        return tuple(offenders)

    def unanchored_observations(self, known_digests: frozenset[str]) -> tuple[str, ...]:
        """Authoritative OBS ids citing a digest that is not in ``known_digests``.

        :meth:`unsupported_authoritative` is structural: it checks the digest's
        *shape*, so a sha256-shaped digest no telemetry ever produced counts as
        support (S4-FC-02). This is the other half — the caller passes the digests
        the incident's telemetry actually carried, and an OBS naming anything else
        is a fabricated observation however well-formed it is.
        """
        offenders = []
        for claim_id in sorted(self.authoritative):
            claim = self.claims.get(claim_id)
            if not isinstance(claim, ObservedClaim):
                continue
            if any(ref.digest not in known_digests for ref in claim.evidence):
                offenders.append(claim_id)
        return tuple(offenders)

    def uncatalogued_derivations(self, catalogue: frozenset[str]) -> tuple[str, ...]:
        """Authoritative DER ids whose ``rule_id`` is not in the closed ``catalogue``.

        A DER is only as honest as its rule: authoritative status is earned by the
        text being a deterministic function of the premises. Free DER text passed
        the structural walk whatever it asserted, so the rule set is closed and a
        rule outside it is a finding (S4-FC-02).
        """
        offenders = []
        for claim_id in sorted(self.authoritative):
            claim = self.claims.get(claim_id)
            if kind_of(claim) is ClaimKind.DER and getattr(claim, "rule_id", None) not in catalogue:
                offenders.append(claim_id)
        return tuple(offenders)

    def kinds_present(self) -> Mapping[ClaimKind, int]:
        """Count per kind. A separation that never exercises a kind proves nothing."""
        counts: dict[ClaimKind, int] = {}
        for claim in self.claims.values():
            kind = kind_of(claim)
            counts[kind] = counts.get(kind, 0) + 1
        return MappingProxyType(counts)

    def depth(self) -> int:
        """Deepest premise chain in the graph; 0 for a graph of roots only."""
        if not self.claims:
            return 0
        return max(self._depth_of(claim_id) for claim_id in self.claims)

    def to_dict(self) -> dict[str, Any]:
        """Canonical JSON-safe form. Keys name concepts, never Stage 4 classes."""
        return {
            "schema": "pocketsec.typed_claim_graph.v1",
            "claims": [
                {
                    "claim_id": claim.claim_id,
                    "kind": kind_of(claim).value,
                    "subject": claim.subject,
                    "text": claim.text,
                    "premises": list(claim.premises),
                    "evidence": [ref.to_dict() for ref in claim.evidence],
                    **_kind_specific(claim),
                }
                for claim in (self.claims[key] for key in sorted(self.claims))
            ],
            "authoritative": sorted(self.authoritative),
            "truncated": [record.to_dict() for record in self.truncated],
            "kinds": {kind.value: count for kind, count in sorted(self.kinds_present().items())},
            "unsupported_authoritative": list(self.unsupported_authoritative()),
        }


#: The zero value. Every compilation starts here rather than from a mutable dict.
EMPTY_CLAIM_GRAPH = ClaimGraph(claims=MappingProxyType({}))
