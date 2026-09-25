"""D4.13 part three — the claim compiler and §21's semantic conservation.

Architecture §23: human-readable claims are *compiled* from typed evidence, not
generated freely. :class:`CompiledClaim` is that template as data — headline plus
``because`` / ``against`` / ``unknown`` — and :meth:`CompiledClaim.render` is the
authoritative rendering. A language model may paraphrase it afterwards
(``verbalizer.py``), never instead of it.

This module is also the one place in Stage 4 where factual amplification could
enter, so §21 is enforced here rather than reviewed here. §21's own example:

    evidence says   process P read object classified CREDENTIAL_MATERIAL
    Stage 4 may say  possible credential access
    Stage 4 may NOT  password stolen

``AMPLIFICATION_RULES`` is the closed mapping from an observed object class to
the strongest claim permitted about it, and ``FORBIDDEN_AMPLIFICATIONS`` holds
the verbs that assert a completed compromise. ``insert_conserved`` refuses to add
a claim carrying one of those verbs unless an ``ObservedClaim`` in its own
premise chain already carries it — that is, unless something was actually seen.

What this module refuses to do:

* it never emits a claim stronger than the object class its evidence names;
* it never fabricates a sensor: evidence whose store does not name one becomes a
  recorded :class:`ClaimTruncation`, not an ``ObservedClaim`` with a plausible
  guess (ADR-0004's "``None`` never means zero", generalised);
* it never marks an INF, CF, EXT or UNK claim authoritative — that refusal lives
  in ``graph.insert`` and this module does not work around it;
* it never imports the packages that supply its inputs. ``field``, ``shadow`` and
  ``verdict`` arrive as structural Protocols, so the honesty mechanism stays
  testable on its own and does not couple ``claims`` to ``visibility`` or
  ``resolution``.

The amplification exemption for ``UnknownClaim`` is deliberate: §21 forbids
*amplification*, and naming an unobserved possibility ("direct exfiltration
evidence — not seen") is the opposite of asserting it.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from pocketsec.stage0.contracts.common import ContractError, EvidenceRef
from pocketsec.stage4.claims.graph import (
    EMPTY_CLAIM_GRAPH,
    ClaimGraph,
    ClaimTruncation,
)
from pocketsec.stage4.claims.typed_claim import (
    ClaimKind,
    InferredClaim,
    ObservedClaim,
    TypedClaim,
    UnknownClaim,
    kind_of,
    sensor_of_evidence,
)

__all__ = [
    "AMPLIFICATION_RULES",
    "DERIVATION_RULE_CATALOGUE",
    "FORBIDDEN_AMPLIFICATIONS",
    "HEDGE_MARKERS",
    "MAX_COMPILED_CLAIMS",
    "MAX_COMPILED_SECTION",
    "AmplificationRefusal",
    "CompiledClaim",
    "FieldLike",
    "ShadowLike",
    "VerdictLike",
    "WorldLike",
    "amplification_violations",
    "compile_typed_claim_graph",
    "insert_conserved",
    "normalise_claim_token",
    "observed_object_classes",
    "permitted_inferences",
]

#: Verbs that assert a *completed* compromise. A claim may only carry one when an
#: observation in its own premise chain carries it too, or when the claim is
#: explicitly hedged (see ``HEDGE_MARKERS``).
FORBIDDEN_AMPLIFICATIONS: frozenset[str] = frozenset(
    {"stolen", "exfiltrated", "compromised", "breached"}
)

#: Openers that make a claim a possibility rather than a fact. §21's whole line is
#: that "possible credential access" is permitted where "password stolen" is not,
#: so the hedge is load-bearing vocabulary, not decoration. A hedged claim still
#: has to satisfy ``AMPLIFICATION_RULES`` when the evidence named an object class,
#: which is what stops the hedge from being a universal escape.
HEDGE_MARKERS: frozenset[str] = frozenset(
    {"possible", "possibly", "candidate", "suspected", "consistent_with", "may_have"}
)

#: Kinds subject to the forbidden-verb arm: everything that asserts something.
_VERB_CHECKED_KINDS = frozenset({ClaimKind.DER, ClaimKind.INF, ClaimKind.CF, ClaimKind.EXT})
#: Kinds subject to the object-class arm: everything that *interprets*. A DER is a
#: deterministic restatement, and its honesty is already carried by
#: ``DERIVABLE_FROM`` plus ``traces_to_observation``.
_RULE_CHECKED_KINDS = frozenset({ClaimKind.INF, ClaimKind.CF, ClaimKind.EXT})

#: Observed object class -> the strongest claim permitted about it (§21).
#:
#: Every value is a *possibility*, which is the entire content of the rule: the
#: strongest thing an object classification licenses is that access was possible.
#: ``CREDENTIAL_MATERIAL`` is §21's own wording; ``CREDENTIAL`` and the rest are
#: the real ``SemanticProperty`` values Stage 1 emits, so the rule fires whether
#: the classification came from the architecture's vocabulary or the code's.
AMPLIFICATION_RULES: Mapping[str, frozenset[str]] = {
    "CREDENTIAL_MATERIAL": frozenset({"possible_credential_access"}),
    "CREDENTIAL": frozenset({"possible_credential_access"}),
    "CREDENTIAL_READER": frozenset({"possible_credential_access"}),
    "AUTHORIZATION_DATA": frozenset({"possible_authorization_data_access"}),
    "PERSISTENCE": frozenset({"possible_persistence_write"}),
    "PERSISTENCE_WRITER": frozenset({"possible_persistence_write"}),
    "EXTERNAL_ENDPOINT": frozenset({"possible_external_communication"}),
    "SYSTEM_BINARY": frozenset({"possible_system_binary_modification"}),
    "ROOT_OWNED": frozenset({"possible_root_owned_object_access"}),
}

#: At most four worlds are compiled. §23's template is for a human reader; a
#: nine-world report is a data dump, and the bound is also what keeps compilation
#: cost flat while the field branches under flood.
MAX_COMPILED_CLAIMS: int = 4
#: Bound on each ``because`` / ``against`` / ``unknown`` section.
MAX_COMPILED_SECTION: int = 8

#: The closed set of ``DerivedClaim.rule_id`` values whose text is a deterministic
#: function of their premises and brings in no hypothesis. **Empty**: the compiler
#: emits no DER. Its only one was "N observation(s) form the causal spine of
#: <world>", which is world attribution under a DER type and was removed (S4-FC-02).
#: G4.8 fails any authoritative DER whose rule is not listed here, so adding a rule is
#: a deliberate, reviewable act rather than a string a compiler can invent.
DERIVATION_RULE_CATALOGUE: frozenset[str] = frozenset()

_TOKEN_RE = re.compile(r"[^a-z0-9]+")
_UPPER_TOKEN_RE = re.compile(r"[A-Z][A-Z0-9_]{2,}")
_MARKER_STRIP_RE = re.compile(r"^\s*\[[A-Z]{3}\]\s*")


class AmplificationRefusal(ContractError):
    """Raised when a claim would assert more than its evidence supports (§21)."""


# --- structural inputs ---------------------------------------------------------


@runtime_checkable
class WorldLike(Protocol):
    """The part of ``SecurityWorldV1`` the compiler reads, and no more.

    Deliberately narrow. A Protocol that mirrors every field of the real type
    would be a second copy of it, drifting silently; this one names exactly the
    four attributes the compiler touches, so a change in either direction is a
    visible change here.
    """

    world_id: str
    mechanism_id: str
    forbidden_evidence: frozenset[str]
    evidence_refs: tuple[EvidenceRef, ...]


@runtime_checkable
class FieldLike(Protocol):
    """The part of ``CausalBeliefField`` the compiler reads."""

    incident_id: str
    at_sequence: int
    worlds: tuple[WorldLike, ...]

    def support_vector(self) -> Mapping[str, float]: ...


@runtime_checkable
class ShadowRegionLike(Protocol):
    """The part of ``ShadowRegion`` the compiler reads."""

    signal: str
    reason: str


@runtime_checkable
class ShadowLike(Protocol):
    """The part of ``SensorShadow`` the compiler reads."""

    regions: tuple[ShadowRegionLike, ...]

    def confidence_penalty(self) -> float: ...


@runtime_checkable
class VerdictLike(Protocol):
    """The part of ``IdentifiabilityVerdict`` the compiler reads.

    Only ``discriminating_observations``: an empty tuple means no affordable
    observation separates the survivors, which is the one fact §23's ``unknown``
    section needs. The compiler does not re-derive identifiability.
    """

    discriminating_observations: tuple[str, ...]


# --- semantic conservation -----------------------------------------------------


def normalise_claim_token(text: str) -> str:
    """Lowercase, underscore-joined form used for rule matching.

    ``"[INF] Possible credential access"`` -> ``"possible_credential_access"``. The
    leading kind marker is stripped so the hedge sits at the front where
    ``_is_hedged`` can see it, and matching by containment is what lets a claim add
    qualifiers ("possible credential access by lineage L") without escaping the rule.
    """
    stripped = _MARKER_STRIP_RE.sub("", text.strip())
    return _TOKEN_RE.sub("_", stripped.lower()).strip("_")


def _is_hedged(token: str) -> bool:
    """True when the normalised text opens with a ``HEDGE_MARKERS`` word."""
    return any(token == hedge or token.startswith(f"{hedge}_") for hedge in HEDGE_MARKERS)


def permitted_inferences(object_class: str) -> frozenset[str]:
    """The strongest claims permitted about ``object_class``; empty when unruled."""
    return AMPLIFICATION_RULES.get(object_class, frozenset())


def observed_object_classes(claims: Sequence[TypedClaim]) -> frozenset[str]:
    """``AMPLIFICATION_RULES`` keys named by the ``ObservedClaim``s in ``claims``.

    A key counts when it is the observation's ``subject`` or appears as an
    uppercase token in its text, because Stage 1 and Stage 3 both write object
    classifications in that form.
    """
    found: set[str] = set()
    for claim in claims:
        if not isinstance(claim, ObservedClaim):
            continue
        if claim.subject in AMPLIFICATION_RULES:
            found.add(claim.subject)
        for token in _UPPER_TOKEN_RE.findall(claim.text):
            if token in AMPLIFICATION_RULES:
                found.add(token)
    return frozenset(found)


def amplification_violations(claims: Sequence[TypedClaim]) -> tuple[str, ...]:
    """Claim ids in ``claims`` that amplify beyond what the sequence observed.

    ``claims`` is expected to be a claim plus its premise chain — the flattened
    form a :class:`CompiledClaim` holds. Two arms:

    1. **forbidden verb.** A DER/INF/CF/EXT claim carrying a
       ``FORBIDDEN_AMPLIFICATIONS`` verb that no ``ObservedClaim`` in the sequence
       carries, and that is not hedged. "password stolen" is refused; "possible
       compromised session" is not, because it asserts a possibility.
    2. **object class.** An INF/CF/EXT claim made where the observations named an
       ``AMPLIFICATION_RULES`` key whose permitted set the claim's text does not
       satisfy. This is the arm that refuses "possible credential exfiltration"
       from evidence that only classified an object ``CREDENTIAL_MATERIAL``.

    ``ObservedClaim`` is exempt because it *is* the evidence; ``UnknownClaim`` is
    exempt because naming an unobserved possibility is the opposite of amplifying.

    **G4.8 requires this to return ``()``.**
    """
    observed_text = " ".join(
        claim.text.lower() for claim in claims if isinstance(claim, ObservedClaim)
    )
    permitted: set[str] = set()
    for object_class in observed_object_classes(claims):
        permitted |= permitted_inferences(object_class)
    offenders: list[str] = []
    for claim in claims:
        kind = kind_of(claim)
        token = normalise_claim_token(claim.text)
        if kind in _VERB_CHECKED_KINDS and not _is_hedged(token):
            lowered = claim.text.lower()
            if any(v in lowered and v not in observed_text for v in FORBIDDEN_AMPLIFICATIONS):
                offenders.append(claim.claim_id)
                continue
        if kind in _RULE_CHECKED_KINDS and permitted:
            if not any(allowed in token for allowed in permitted):
                offenders.append(claim.claim_id)
    return tuple(sorted(dict.fromkeys(offenders)))


def insert_conserved(
    graph: ClaimGraph, claim: TypedClaim, *, authoritative: bool = False
) -> ClaimGraph:
    """Insert ``claim`` under §21, on top of ``graph.insert``'s four refusals.

    The chain is walked inside ``graph`` — the claim's own premises plus their
    roots — so "unless evidence supports that stronger statement" is a lookup
    rather than a judgement. Raises :class:`AmplificationRefusal`.
    """
    chain: list[TypedClaim] = [claim]
    for premise in claim.premises:
        parent = graph.claims.get(premise)
        if parent is None:
            continue
        chain.append(parent)
        chain.extend(graph.roots_of(premise))
    if claim.claim_id in amplification_violations(chain):
        classes = sorted(observed_object_classes(chain))
        permitted: set[str] = set()
        for object_class in classes:
            permitted |= permitted_inferences(object_class)
        raise AmplificationRefusal(
            f"claim {claim.claim_id!r} ({claim.text!r}) amplifies beyond its evidence; "
            f"observed object classes {classes} permit {sorted(permitted)}"
        )
    return graph.insert(claim, authoritative=authoritative)


# --- the compiled claim --------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CompiledClaim:
    """§23's template, as data: headline + because / against / unknown."""

    headline: TypedClaim
    because: tuple[TypedClaim, ...] = ()
    against: tuple[TypedClaim, ...] = ()
    unknown: tuple[UnknownClaim, ...] = ()

    def __post_init__(self) -> None:
        kind_of(self.headline)
        for name in ("because", "against", "unknown"):
            object.__setattr__(self, name, tuple(getattr(self, name)))
        for name in ("because", "against"):
            section = getattr(self, name)
            if len(section) > MAX_COMPILED_SECTION:
                raise ContractError(f"CompiledClaim.{name} bound is {MAX_COMPILED_SECTION}")
            for claim in section:
                if isinstance(claim, UnknownClaim):
                    raise ContractError(
                        f"an UnknownClaim belongs in CompiledClaim.unknown, not {name}"
                    )
        if len(self.unknown) > MAX_COMPILED_SECTION:
            raise ContractError(f"CompiledClaim.unknown bound is {MAX_COMPILED_SECTION}")
        for claim in self.unknown:
            if not isinstance(claim, UnknownClaim):
                raise ContractError("CompiledClaim.unknown holds UnknownClaim only")
        ids = [claim.claim_id for claim in self.all_claims()]
        if len(ids) != len(set(ids)):
            raise ContractError("CompiledClaim must not repeat a claim across its sections")

    def all_claims(self) -> tuple[TypedClaim, ...]:
        """Headline plus every section, in render order."""
        return (self.headline, *self.because, *self.against, *self.unknown)

    def render(self) -> str:
        """The deterministic, authoritative rendering. No model involved."""
        lines = [f"[{kind_of(self.headline).value}] {self.headline.text}"]
        for name, section in (("because", self.because), ("against", self.against)):
            if not section:
                continue
            lines.append(f"{name}:")
            lines.extend(f"  [{kind_of(c).value}] {c.text}" for c in section)
        lines.append("unknown:")
        if self.unknown:
            lines.extend(f"  [UNK] {c.text}" for c in self.unknown)
        else:
            # A statement about the record, never about the world: "nothing was
            # recorded as unknown" is not "nothing is unknown".
            lines.append("  (none recorded)")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "headline": self.headline.claim_id,
            "because": [c.claim_id for c in self.because],
            "against": [c.claim_id for c in self.against],
            "unknown": [c.claim_id for c in self.unknown],
            "render": self.render(),
        }


# --- compilation ---------------------------------------------------------------


#: A locator usable verbatim in ``evidence:<locator>``: the claim-subject alphabet,
#: short enough that the prefixed subject stays inside ``MAX_SUBJECT_LENGTH``.
_LOCATOR_LABEL_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.:/\-]{0,118}$")


def _evidence_label(ref: EvidenceRef) -> str:
    """The locator when it fits a claim subject, else a digest-derived label.

    Stage 0 only requires a locator to be non-empty, and a legal 120-character Stage 1
    ``record_id`` — or a store locator carrying ``#`` or a space — made
    ``ObservedClaim`` refuse the subject. That exception aborted the WHOLE compile,
    for every world, erasing the incident's authoritative output over one reference
    (S4-SEC-06). The digest is what identifies evidence anyway; the locator is a
    convenience, so falling back to the digest loses nothing a reader can check.
    """
    if _LOCATOR_LABEL_RE.fullmatch(ref.locator):
        return ref.locator
    return f"sha256-{ref.digest.removeprefix('sha256:')[:16]}"


def _observation_layer(
    graph: ClaimGraph, world: WorldLike, *, at_sequence: int
) -> tuple[ClaimGraph, tuple[str, ...]]:
    """One ``ObservedClaim`` per evidence reference whose store names a sensor."""
    ids: list[str] = []
    for index, ref in enumerate(world.evidence_refs):
        sensor = sensor_of_evidence(ref)
        claim_id = f"obs.{world.world_id}.{index}"
        if sensor is None:
            graph = graph.with_truncation(
                ClaimTruncation(
                    what="claim",
                    identifier=claim_id,
                    reason=f"evidence_store_names_no_sensor:{ref.store}",
                    consequence_lost=0.0,
                )
            )
            continue
        label = _evidence_label(ref)
        claim = ObservedClaim(
            claim_id=claim_id,
            subject=f"evidence:{label}",
            text=f"{sensor.value} recorded evidence {label}",
            evidence=(ref,),
            sensor=sensor,
            at_sequence=at_sequence,
        )
        graph = insert_conserved(graph, claim, authoritative=True)
        ids.append(claim_id)
    return graph, tuple(ids)


def _unknown_layer(
    graph: ClaimGraph,
    shadow: ShadowLike | None,
    verdict: VerdictLike | None,
    *,
    competing: bool,
) -> tuple[ClaimGraph, tuple[UnknownClaim, ...]]:
    """One ``UnknownClaim`` per shadow region, plus one when the field cannot separate.

    The identifiability unknown is emitted only when worlds are actually
    ``competing``: "no affordable observation separates the survivors" is a
    statement about a choice, and asserting it over a single-world field would be
    a manufactured unknown, which is as dishonest as a manufactured certainty.
    """
    produced: list[UnknownClaim] = []
    regions = tuple(shadow.regions) if shadow is not None else ()
    for index, region in enumerate(regions[:MAX_COMPILED_SECTION]):
        claim = UnknownClaim(
            claim_id=f"unk.shadow.{index}",
            subject=region.signal,
            text=f"{region.signal} was not observable ({region.reason})",
            reason="shadowed",
            shadow_region=region.signal,
        )
        graph = graph.insert(claim)
        produced.append(claim)
    if len(regions) > MAX_COMPILED_SECTION:
        graph = graph.with_truncation(
            ClaimTruncation(
                what="claim",
                identifier="unk.shadow.overflow",
                reason=f"max_compiled_section:{MAX_COMPILED_SECTION}",
                consequence_lost=float(len(regions) - MAX_COMPILED_SECTION),
            )
        )
    if competing and verdict is not None and not verdict.discriminating_observations:
        claim = UnknownClaim(
            claim_id="unk.identifiability",
            subject="identifiability",
            text="no affordable observation separates the surviving explanations",
            reason="insufficient_evidence",
        )
        graph = graph.insert(claim)
        produced.append(claim)
    return graph, tuple(produced)


def _world_claims(
    graph: ClaimGraph, world: WorldLike, *, support: float, shadow_penalty: float, at_sequence: int
) -> tuple[ClaimGraph, InferredClaim | None, tuple[str, ...]]:
    """The OBS -> INF chain for one world. OBS is authoritative, INF never.

    There is deliberately **no DER between them.** The first version emitted, for
    every world, an authoritative ``DerivedClaim`` reading "N observation(s) form the
    causal spine of <world>". Whether those observations belong to that world *is*
    the hypothesis, so that was INF content under a DER type — and on incidents that
    resolved UNIDENTIFIABLE it asserted, authoritatively, that the same observations
    were the spine of three competing worlds (S4-FC-02 / S4-REV-09). A DER here
    would have to be a deterministic function of its premises that brings in no
    world; nothing the compiler knows about a world is that, so the attribution is
    carried by the INF headline, which can never be authoritative.
    """
    graph, obs_ids = _observation_layer(graph, world, at_sequence=at_sequence)
    if not obs_ids:
        return graph, None, ()
    if len(obs_ids) > MAX_COMPILED_SECTION:
        # The extra observations stay in the graph as authoritative OBS claims;
        # what is lost is their place in this world's inference, and that loss is
        # recorded rather than left for a reader to infer from a count.
        graph = graph.with_truncation(
            ClaimTruncation(
                what="claim",
                identifier=f"inf.{world.world_id}",
                reason=f"max_premises_per_claim:{MAX_COMPILED_SECTION}",
                consequence_lost=float(len(obs_ids) - MAX_COMPILED_SECTION),
            )
        )
    inferred = InferredClaim(
        claim_id=f"inf.{world.world_id}",
        subject=f"world:{world.world_id}",
        text=f"possible {world.mechanism_id.replace('_', ' ')}",
        premises=obs_ids[:MAX_COMPILED_SECTION],
        world_id=world.world_id,
        support=support,
        shadow_penalty=shadow_penalty,
    )
    graph = insert_conserved(graph, inferred)
    return graph, inferred, obs_ids


def _assemble(
    graph: ClaimGraph,
    world: WorldLike,
    inferred: InferredClaim,
    *,
    obs_ids: tuple[str, ...],
    unknowns: tuple[UnknownClaim, ...],
) -> CompiledClaim:
    """§23's four sections for one world.

    An observation the world *forbids* is evidence against it, so it moves out of
    ``because`` and into ``against`` rather than appearing in both — a claim that
    supports and contradicts the same world reads as support.
    """
    because = tuple(graph.claims[oid] for oid in obs_ids[:MAX_COMPILED_SECTION])
    against = tuple(
        graph.claims[oid]
        for oid in obs_ids
        if graph.claims[oid].subject in world.forbidden_evidence
    )
    contested = {claim.claim_id for claim in against}
    return CompiledClaim(
        headline=inferred,
        because=tuple(claim for claim in because if claim.claim_id not in contested),
        against=against[:MAX_COMPILED_SECTION],
        unknown=unknowns[:MAX_COMPILED_SECTION],
    )


def compile_typed_claim_graph(
    field: FieldLike,
    *,
    shadow: ShadowLike | None = None,
    verdict: VerdictLike | None = None,
) -> tuple[ClaimGraph, tuple[CompiledClaim, ...]]:
    """CBF-F18 — compile a belief field into a typed graph and §23's claims.

    Deterministic: worlds are taken in descending support then ascending
    ``world_id``, so the same field compiles to byte-identical output. Returns
    ``(graph, compiled)``; ``graph.unsupported_authoritative()`` on the result is
    what G4.8 measures.
    """
    support = field.support_vector()
    penalty = shadow.confidence_penalty() if shadow is not None else 0.0
    graph, unknowns = _unknown_layer(
        EMPTY_CLAIM_GRAPH, shadow, verdict, competing=len(field.worlds) > 1
    )
    ordered = sorted(
        field.worlds, key=lambda w: (-float(support.get(w.world_id, 0.0)), w.world_id)
    )
    compiled: list[CompiledClaim] = []
    for world in ordered[:MAX_COMPILED_CLAIMS]:
        graph, inferred, obs_ids = _world_claims(
            graph,
            world,
            support=float(support.get(world.world_id, 0.0)),
            shadow_penalty=penalty,
            at_sequence=field.at_sequence,
        )
        if inferred is None:
            continue
        compiled.append(_assemble(graph, world, inferred, obs_ids=obs_ids, unknowns=unknowns))
    if len(ordered) > MAX_COMPILED_CLAIMS:
        graph = graph.with_truncation(
            ClaimTruncation(
                what="claim",
                identifier=f"incident:{field.incident_id}",
                reason=f"max_compiled_claims:{MAX_COMPILED_CLAIMS}",
                consequence_lost=float(len(ordered) - MAX_COMPILED_CLAIMS),
            )
        )
    return graph, tuple(compiled)
