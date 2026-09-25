"""D4.16 / CBF-F20 — the only artefact Stage 5 ever sees, and what it refuses to carry.

Architecture §49 says Stage 5 "should not need to reinterpret raw logs": it
receives the surviving world set, the consequence distribution, the evidence
lineage, the uncertainty, the identifiability state and the recommended
information gaps. This module is that handoff, and it is **plain JSON with a
canonical digest**, mirroring the shape Stage 3 already shipped for its own seam
(``pocketsec/stage3/stage4_interface.py``). Trust rule T1 also lets Stage 5
import the typed objects directly; both are supported, and both go through this
module so there is one place where the refusals live.

Why plain JSON rather than the live objects, stated because it looks like extra
work: Stage 4 will be redesigned. ADR-0036 may recommend deleting the multi-world
machinery outright. A handoff that carries ``SecurityWorldV1`` instances couples
Stage 5's lifetime to Stage 4's class names; a handoff that carries rows of
strings and floats survives the redesign. Stage 3's seam docstring makes the same
argument in the other direction and it was right.

**Three refusals, all at export time.**

1. *No key may name a Stage 4 class* (:data:`FORBIDDEN_SEAM_TOKENS`). The same
   mechanism as Stage 3's, including the deliberately-absent list: a token that
   appears inside a legitimate field name is not banned, because a refusal so
   total that no resolution can cross it would be deleted within a week rather
   than respected.
2. *No unsupported authoritative claim* — the OBS/DER walk of
   :func:`unsupported_authoritative_rows` runs over the **exported rows**, not
   over the live :class:`~pocketsec.stage4.claims.graph.ClaimGraph`, and a
   non-empty result raises. G4.8 is measured on this object because this object
   is the only thing that leaves the stage; a graph that was clean in memory and
   dirty on the wire would pass a check nobody could act on.
3. *No inferred claim smuggled in as authority* — a hypothesis may cite an INF,
   CF, EXT or UNK claim (that is what hypotheses are made of), but such a claim
   may never appear in the exported ``authoritative`` set, and every cited
   ``claim_id`` must resolve to a row in the exported graph. A dangling citation
   is a factual claim Stage 5 cannot audit, which is the same defect as an
   unsupported one.

:class:`InformationGap` is a **question**, never an instruction. It has no
``action`` field, no ``remediation`` field and no field whose name contains any
:data:`~pocketsec.stage0.contracts.threat_prediction_v1.FORBIDDEN_AUTHORITY_FIELDS`
token (ADR-0003, trust rule T5), and its prose is checked against
:data:`IMPERATIVE_TOKENS` so "what would discriminate these worlds" cannot decay
into "block this process" one refactor at a time. Only Stage 5's typed operators
touch privilege; Stage 4 tells it what it does not know.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    EvidenceRef,
    digest_of_bytes,
    register_schema,
    require_finite_unit_interval,
    require_identifier,
)
from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage4.stage5_walk import (
    MAX_EXPORT_CHAIN_DEPTH,
    refuse_authority_keys,
    refuse_dangling_citations,
    refuse_laundered_kinds,
    row_index,
    unsupported_authoritative_rows,
)
from pocketsec.stage4.worlds.world import authority_named_fields

__all__ = [
    "CBF_RESOLUTION_V1_ID",
    "CBF_RESOLUTION_V1_VERSION",
    "FORBIDDEN_SEAM_TOKENS",
    "IMPERATIVE_TOKENS",
    "MAX_EXPORT_CHAIN_DEPTH",
    "MAX_GAPS_PER_RESOLUTION",
    "MAX_HYPOTHESES_PER_RESOLUTION",
    "CBFResolutionV1",
    "IncidentHypothesis",
    "InformationGap",
    "export_incident_world_record",
    "seam_violations",
    "unsupported_authoritative_rows",
    "write_resolution",
]

CBF_RESOLUTION_V1_ID = "pocketsec.cbf_resolution.v1"
CBF_RESOLUTION_V1_VERSION = register_schema(CBF_RESOLUTION_V1_ID, "1.0.0")

#: Bounded because this is endpoint state that gets written to disk. ``MAX_WORLDS``
#: is 8 and the field cannot hold more, so 8 hypotheses is the real ceiling; 16
#: leaves room for ``MAX_WORLDS_CEILING`` without a second constant to keep in
#: step.
MAX_HYPOTHESES_PER_RESOLUTION: int = 16
#: One gap per candidate sensor action, and there are six of those (§17).
MAX_GAPS_PER_RESOLUTION: int = 8
#: The premise chain the export-time walk will follow before calling a claim
#: unsupported. ``claims/graph.py`` bounds depth at 8; doubling it here means a
#: graph that somehow exceeded its own bound is reported as unsupported rather
#: than recursing until the interpreter complains.

#: Stage 4 class names Stage 5 must never see as a key, compared against keys
#: with separators stripped so ``security_world``, ``securityWorld`` and
#: ``SecurityWorld`` are all caught.
#:
#: **Deliberately absent**, exactly as Stage 3's list documents its own
#: omissions: ``claimgraph`` (the payload's own ``claim_graph`` key *is* the
#: graph), ``informationgap`` (``information_gaps``), ``truncation``
#: (``truncations``), ``degradationrecord`` (``degradations``), ``shadowregion``
#: (an ``UnknownClaim`` row carries ``shadow_region``, whose value is the *name of
#: the blind signal* and the entire content of the claim), ``intervention`` and
#: ``resolution`` (``resolution_id``, and a ``CounterfactualClaim`` row carries
#: ``target_signature``). Banning those would mean no resolution could cross the
#: seam at all — a refusal so total it would be deleted rather than respected.
FORBIDDEN_SEAM_TOKENS = frozenset(
    {
        "securityworld",
        "securityworldv1",
        "causalbelieffield",
        "beliefgeometry",
        "worldsupport",
        "worldsupportstate",
        "latentsecuritystate",
        "sensorshadow",
        "visibilitymodel",
        "visibilityobservation",
        "evidencetension",
        "tensionterm",
        "negativeevidenceverdict",
        "observedclaim",
        "derivedclaim",
        "inferredclaim",
        "counterfactualclaim",
        "externalclaim",
        "unknownclaim",
        "typedclaim",
        "compiledclaim",
        "launderingattempt",
        "worldtombstone",
        "tombstoneledger",
        "sparseworldgraph",
        "worldgraphnode",
        "entropybudget",
        "budgetcontroller",
        "lucidengine",
        "lucidconfig",
        "updateoutcome",
        "incidentfuturecone",
        "causalbranch",
        "identifiabilityverdict",
        "identifiabilitystate",
        "resolutionhorizon",
        "horizonoutcome",
        "sequentialevidence",
        "epochcalibration",
        "calibrationreport",
        "observationplan",
        "observationrequest",
        "sensorcost",
        "sensoraction",
        "interventionresult",
        "responsibilityflux",
        "stressresult",
        "perturbationkind",
        "selfquestioningverdict",
        "crystalknowledge",
        "cellstresssignal",
        "crystalcandidatesignal",
        "degradationledger",
        "dominancetest",
        "evidenceregime",
        "birthrefusal",
        "deathcause",
        "incidentevidence",
        "incidentcase",
        "groundtruthworld",
        "cbfslot",
        "cbfresolution",
        "cbfresolutionv1",
        "incidenthypothesis",
    }
)

#: Words that turn a question into an order. Checked against
#: :attr:`InformationGap.why_it_matters`, which is the one free-text field that
#: crosses this seam. ADR-0003: no Stage 4 output carries response authority, and
#: the cheapest way for that to erode is prose.
IMPERATIVE_TOKENS = frozenset(
    {
        "block",
        "kill",
        "quarantine",
        "terminate",
        "remediate",
        "revoke",
        "disable",
        "isolate",
        "contain",
        "delete",
        "execute",
        "sudo",
        "shutdown",
        "reboot",
        "unload",
    }
)

_WORD_RE = re.compile(r"[a-z]+")


def seam_violations(payload: object, *, prefix: str = "resolution") -> tuple[str, ...]:
    """Return every key path whose name would leak a Stage 4 class across the seam.

    Recursive over mappings and sequences because the payload is nested three
    deep and a violation buried in ``hypotheses[2].claim_ids`` is exactly as
    coupling as one at the top level.
    """
    found: list[str] = []
    if isinstance(payload, Mapping):
        for key, value in payload.items():
            path = f"{prefix}.{key}"
            flattened = str(key).lower().replace("_", "").replace("-", "")
            if any(token in flattened for token in FORBIDDEN_SEAM_TOKENS):
                found.append(path)
            found.extend(seam_violations(value, prefix=path))
    elif isinstance(payload, (list, tuple)):
        for index, item in enumerate(payload):
            found.extend(seam_violations(item, prefix=f"{prefix}[{index}]"))
    return tuple(found)


def _require_json(value: object, *, field: str) -> Any:
    """Refuse anything that is not a JSON scalar, list or mapping.

    A Stage 4 object that reached here would serialise by accident (or not at
    all) and would put a class name on the wire, so the refusal is structural
    rather than a ``json.dumps`` failure later.
    """
    if value is None or isinstance(value, (str, bool, int, float)):
        if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
            raise ContractError(f"{field} must be a finite number, got {value!r}")
        return value
    if isinstance(value, Mapping):
        clean: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ContractError(f"{field} keys must be strings, got {type(key).__name__}")
            clean[key] = _require_json(item, field=f"{field}.{key}")
        return clean
    if isinstance(value, (list, tuple)):
        return [_require_json(item, field=f"{field}[{index}]") for index, item in enumerate(value)]
    raise ContractError(
        f"{field} holds {type(value).__name__}, which is not plain JSON; Stage 5 reads "
        "rows of strings and numbers so that Stage 4 can be redesigned without it"
    )


def _plain_rows(rows: Sequence[Mapping[str, Any]], *, field: str) -> tuple[Mapping[str, Any], ...]:
    normalised: list[Mapping[str, Any]] = []
    for index, row in enumerate(rows):
        where = f"{field}[{index}]"
        if not isinstance(row, Mapping):
            raise ContractError(f"{where} must be a mapping, got {type(row).__name__}")
        clean = _require_json(row, field=where)
        offenders = seam_violations(clean, prefix=where)
        if offenders:
            raise ContractError(
                f"{where} names Stage 4 classes {list(offenders)}; Stage 5 reads plain data"
            )
        normalised.append(clean)
    return tuple(normalised)


def _refuse_authority_named_fields(instance: object) -> None:
    """T5 audit, run in ``__post_init__`` the way ``KnowledgeCellV1`` does."""
    offenders = authority_named_fields(type(instance))
    if offenders:
        raise ContractError(
            f"{type(instance).__name__} names authority fields {list(offenders)}; a Stage 4 "
            "output carries no response authority (ADR-0003)"
        )


@dataclass(frozen=True, slots=True)
class InformationGap:
    """A recommended gap: what Stage 4 could not see and why it mattered.

    A **question**, never an instruction. ``would_discriminate`` names the world
    ids the missing observation would separate, which is the only reason a gap is
    worth reporting: a gap that separates nothing is noise, and the constructor
    refuses one.
    """

    signal: str
    why_it_matters: str
    would_discriminate: tuple[str, ...]
    affordable: bool

    def __post_init__(self) -> None:
        _refuse_authority_named_fields(self)
        if not isinstance(self.signal, str) or not self.signal.strip():
            raise ContractError("InformationGap.signal must be a non-empty string")
        if not isinstance(self.why_it_matters, str) or not self.why_it_matters.strip():
            raise ContractError(
                "InformationGap.why_it_matters must say why the gap matters; a gap with no "
                "reason is not actionable evidence, it is a to-do list"
            )
        object.__setattr__(self, "would_discriminate", tuple(self.would_discriminate))
        if len(self.would_discriminate) < 2:
            raise ContractError(
                f"InformationGap({self.signal!r}).would_discriminate names "
                f"{len(self.would_discriminate)} worlds; a gap that separates fewer than two "
                "explanations discriminates nothing"
            )
        if not isinstance(self.affordable, bool):
            raise ContractError("InformationGap.affordable must be a bool")
        self._refuse_instruction()

    def _refuse_instruction(self) -> None:
        """Refuse prose that reads as an order rather than a question.

        Applied to ``why_it_matters`` only. ``signal`` is not checked because
        ``privilege_change`` is a real ``MANDATORY_SIGNALS`` member and refusing
        to *name* it would make the most consequential gap in the system
        unreportable — the value/field-name distinction of §2.4.
        """
        words = set(_WORD_RE.findall(self.why_it_matters.lower()))
        offenders = sorted(words & IMPERATIVE_TOKENS)
        if offenders:
            raise ContractError(
                f"InformationGap({self.signal!r}).why_it_matters reads as an instruction "
                f"({offenders}); Stage 4 states what it does not know and Stage 5 decides "
                "what to do about it (ADR-0003)"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "signal": self.signal,
            "why_it_matters": self.why_it_matters,
            "would_discriminate": list(self.would_discriminate),
            "affordable": self.affordable,
        }


@dataclass(frozen=True, slots=True)
class IncidentHypothesis:
    """One surviving world, as Stage 5 sees it: a mechanism, its weight, its receipts."""

    mechanism_id: str
    support: float
    consequence: float
    uncertainty: float
    claim_ids: tuple[str, ...]
    evidence_refs: tuple[EvidenceRef, ...]

    def __post_init__(self) -> None:
        _refuse_authority_named_fields(self)
        require_identifier(self.mechanism_id, "IncidentHypothesis.mechanism_id")
        require_finite_unit_interval(self.support, "IncidentHypothesis.support")
        require_finite_unit_interval(self.uncertainty, "IncidentHypothesis.uncertainty")
        if not isinstance(self.consequence, (int, float)) or isinstance(self.consequence, bool):
            raise ContractError("IncidentHypothesis.consequence must be a number")
        consequence = float(self.consequence)
        if consequence != consequence or consequence < 0.0:
            raise ContractError(
                f"IncidentHypothesis.consequence must be finite and >= 0, got {consequence!r}"
            )
        object.__setattr__(self, "consequence", consequence)
        object.__setattr__(self, "claim_ids", tuple(self.claim_ids))
        object.__setattr__(self, "evidence_refs", tuple(self.evidence_refs))
        for ref in self.evidence_refs:
            if not isinstance(ref, EvidenceRef):
                raise ContractError(
                    "IncidentHypothesis.evidence_refs holds "
                    f"{type(ref).__name__}; evidence crosses a seam as an EvidenceRef so the "
                    "digest travels with it"
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "mechanism_id": self.mechanism_id,
            "support": self.support,
            "consequence": self.consequence,
            "uncertainty": self.uncertainty,
            "claim_ids": list(self.claim_ids),
            "evidence_digests": [ref.digest for ref in self.evidence_refs],
        }


# --- the export-time unsupported-claim walk ----------------------------------


@dataclass(frozen=True, slots=True)
class CBFResolutionV1:
    """§49's handoff. Every nested member is plain JSON; ``to_dict`` does the refusing."""

    resolution_id: str
    incident_id: str
    epoch_id: int
    verdict: Verdict
    #: An ``IdentifiabilityState`` member value, carried as a string so Stage 5
    #: does not import Stage 4's enum to read it.
    identifiability: str
    hypotheses: tuple[Mapping[str, Any], ...]
    consequence_distribution: Mapping[str, float]
    claim_graph: Mapping[str, Any]
    evidence_lineage: tuple[Mapping[str, str], ...]
    uncertainty: float
    shadow: Mapping[str, Any]
    information_gaps: tuple[Mapping[str, Any], ...]
    truncations: tuple[Mapping[str, Any], ...]
    degradations: tuple[Mapping[str, Any], ...]
    interface_version: str = CBF_RESOLUTION_V1_VERSION

    def __post_init__(self) -> None:
        _refuse_authority_named_fields(self)
        require_identifier(self.resolution_id, "CBFResolutionV1.resolution_id")
        require_identifier(self.incident_id, "CBFResolutionV1.incident_id")
        require_identifier(self.interface_version, "CBFResolutionV1.interface_version")
        if not isinstance(self.epoch_id, int) or isinstance(self.epoch_id, bool):
            raise ContractError("CBFResolutionV1.epoch_id must be an int")
        object.__setattr__(self, "verdict", Verdict(self.verdict))
        if not isinstance(self.identifiability, str) or not self.identifiability.strip():
            raise ContractError("CBFResolutionV1.identifiability must be a non-empty string")
        require_finite_unit_interval(self.uncertainty, "CBFResolutionV1.uncertainty")
        for name in (
            "hypotheses",
            "evidence_lineage",
            "information_gaps",
            "truncations",
            "degradations",
        ):
            object.__setattr__(
                self, name, _plain_rows(getattr(self, name), field=f"CBFResolutionV1.{name}")
            )
        for name in ("claim_graph", "shadow"):
            value = getattr(self, name)
            if not isinstance(value, Mapping):
                raise ContractError(f"CBFResolutionV1.{name} must be a mapping")
            object.__setattr__(
                self, name, _require_json(value, field=f"CBFResolutionV1.{name}")
            )
        object.__setattr__(
            self,
            "consequence_distribution",
            _checked_consequences(self.consequence_distribution),
        )
        refuse_authority_keys(self.hypotheses, field="CBFResolutionV1.hypotheses")
        refuse_authority_keys(self.information_gaps, field="CBFResolutionV1.information_gaps")
        if len(self.hypotheses) > MAX_HYPOTHESES_PER_RESOLUTION:
            raise ContractError(
                f"CBFResolutionV1 carries {len(self.hypotheses)} hypotheses, over "
                f"MAX_HYPOTHESES_PER_RESOLUTION={MAX_HYPOTHESES_PER_RESOLUTION}"
            )
        if len(self.information_gaps) > MAX_GAPS_PER_RESOLUTION:
            raise ContractError(
                f"CBFResolutionV1 carries {len(self.information_gaps)} gaps, over "
                f"MAX_GAPS_PER_RESOLUTION={MAX_GAPS_PER_RESOLUTION}"
            )

    def to_dict(self) -> dict[str, Any]:
        """The wire form, or a refusal. Both of the §4 refusals live here.

        Ordering matters: the claim walk runs before the seam scan, because an
        unsupported factual claim is the more serious of the two findings and the
        error message a reader sees should name it.
        """
        refuse_laundered_kinds(self.claim_graph)
        refuse_dangling_citations(self.hypotheses, self.claim_graph)
        offending_claims = unsupported_authoritative_rows(self.claim_graph)
        if offending_claims:
            raise ContractError(
                f"CBFResolutionV1({self.resolution_id!r}) would export "
                f"{list(offending_claims)} as authoritative without an OBS-rooted premise "
                "chain carrying sha256 digests; G4.8 is measured here because this payload "
                "is the only artefact Stage 5 sees"
            )
        payload: dict[str, Any] = {
            "interface_version": self.interface_version,
            "schema_id": CBF_RESOLUTION_V1_ID,
            "resolution_id": self.resolution_id,
            "incident_id": self.incident_id,
            "epoch_id": self.epoch_id,
            "verdict": self.verdict.value,
            "identifiability": self.identifiability,
            "uncertainty": self.uncertainty,
            "hypotheses": [dict(row) for row in self.hypotheses],
            "consequence_distribution": dict(sorted(self.consequence_distribution.items())),
            "claim_graph": dict(self.claim_graph),
            "evidence_lineage": [dict(row) for row in self.evidence_lineage],
            "shadow": dict(self.shadow),
            "information_gaps": [dict(row) for row in self.information_gaps],
            "truncations": [dict(row) for row in self.truncations],
            "degradations": [dict(row) for row in self.degradations],
        }
        offenders = seam_violations(payload)
        if offenders:
            raise ContractError(
                f"CBFResolutionV1.to_dict would leak Stage 4 class names {list(offenders)}; "
                "Stage 4 is going to be redesigned and a handoff that carries objects "
                "becomes a coupling"
            )
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> CBFResolutionV1:
        """Rebuild from the wire form. Lossless against :meth:`to_dict`.

        Runs the same export-time refusals as :meth:`to_dict` before returning: a
        reader rebuilding a resolution from a file accepted a payload that marked an
        INF claim authoritative, because only the writer walked the graph (S4-REV-12).
        """
        resolution = cls._build(payload)
        resolution.to_dict()
        return resolution

    @classmethod
    def _build(cls, payload: Mapping[str, Any]) -> CBFResolutionV1:
        try:
            return cls(
                resolution_id=str(payload["resolution_id"]),
                incident_id=str(payload["incident_id"]),
                epoch_id=int(payload["epoch_id"]),
                verdict=Verdict(payload["verdict"]),
                identifiability=str(payload["identifiability"]),
                hypotheses=tuple(payload["hypotheses"]),
                consequence_distribution=dict(payload["consequence_distribution"]),
                claim_graph=dict(payload["claim_graph"]),
                evidence_lineage=tuple(payload["evidence_lineage"]),
                uncertainty=float(payload["uncertainty"]),
                shadow=dict(payload["shadow"]),
                information_gaps=tuple(payload["information_gaps"]),
                truncations=tuple(payload["truncations"]),
                degradations=tuple(payload["degradations"]),
                interface_version=str(
                    payload.get("interface_version", CBF_RESOLUTION_V1_VERSION)
                ),
            )
        except KeyError as exc:
            raise ContractError(f"CBFResolutionV1 missing field {exc.args[0]!r}") from exc


def _checked_consequences(value: object) -> Mapping[str, float]:
    if not isinstance(value, Mapping):
        raise ContractError("CBFResolutionV1.consequence_distribution must be a mapping")
    snapshot: dict[str, float] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key:
            raise ContractError("consequence_distribution keys must be non-empty strings")
        if isinstance(item, bool) or not isinstance(item, (int, float)):
            raise ContractError(f"consequence_distribution[{key!r}] must be a number")
        numeric = float(item)
        if numeric != numeric or numeric < 0.0:
            raise ContractError(
                f"consequence_distribution[{key!r}] must be finite and >= 0, got {numeric!r}"
            )
        snapshot[key] = numeric
    return snapshot


def _claims_of_world(world_id: str, known: frozenset[str]) -> tuple[str, ...]:
    """The claim ids ``claims/compiler.py`` emits for one world, filtered to what exists.

    Exact rather than a substring search. The compiler's id scheme is
    ``obs.<world_id>.<n>`` / ``der.<world_id>`` / ``inf.<world_id>``, so an exact
    match is available and a fuzzy one would let a citation resolve to a
    different world's claim — the same two-disjoint-key-spaces defect that made
    Stage 2's credit assignment never fire (S2-FC-01).
    """
    prefix = f"obs.{world_id}."
    return tuple(
        sorted(
            claim_id
            for claim_id in known
            if claim_id in (f"der.{world_id}", f"inf.{world_id}")
            or claim_id.startswith(prefix)
        )
    )


def _hypothesis_rows(
    field: Any, *, claim_graph: Mapping[str, Any]
) -> tuple[tuple[Mapping[str, Any], ...], dict[str, float]]:
    """Project the surviving worlds into rows, dropping citations the graph lacks.

    Dropping rather than raising: a world whose claims were truncated out of the
    graph is still a surviving explanation Stage 5 must see, and silently
    renaming the incident's leading hypothesis to keep a citation would be the
    worse trade. The drop is visible because the row's ``claim_ids`` shortens.
    """
    rows: list[Mapping[str, Any]] = []
    consequences: dict[str, float] = {}
    known = frozenset(row_index(claim_graph))
    support = dict(field.support_vector())
    ordered = sorted(
        field.worlds, key=lambda w: (-float(support.get(w.world_id, 0.0)), w.world_id)
    )
    for world in ordered[:MAX_HYPOTHESES_PER_RESOLUTION]:
        cited = _claims_of_world(world.world_id, known)
        hypothesis = IncidentHypothesis(
            mechanism_id=world.mechanism_id,
            support=max(0.0, min(1.0, float(support.get(world.world_id, 0.0)))),
            consequence=float(world.latent_state.consequence),
            uncertainty=float(world.uncertainty),
            claim_ids=cited,
            evidence_refs=tuple(world.evidence_refs),
        )
        rows.append(hypothesis.to_dict())
        consequences[world.mechanism_id] = hypothesis.consequence
    return tuple(rows), consequences


def export_incident_world_record(
    field: Any,
    *,
    verdict: Any,
    resolution_id: str,
    claim_graph: Mapping[str, Any] | None = None,
    gaps: Sequence[InformationGap] = (),
    degradations: Sequence[Mapping[str, Any]] = (),
) -> CBFResolutionV1:
    """CBF-F20 — project a resolved belief field into the Stage 5 handoff.

    ``verdict`` is an ``IdentifiabilityVerdict``: its ``to_verdict()`` gives the
    frozen Stage 0 enum member and its ``state`` gives the identifiability
    string. Stage 4 mints no parallel vocabulary (ADR-0032), so both come from
    one object and cannot disagree.

    ``claim_graph`` defaults to the field's own compiled graph. It is a parameter
    because ``LucidEngine.close_incident`` may have compiled the graph under a
    :func:`~pocketsec.stage4.engine.degradation.guarded` scope that failed, and
    exporting an empty graph with the degradation recorded beats exporting the
    stale one.
    """
    require_identifier(resolution_id, "export_incident_world_record resolution_id")
    graph_payload = _graph_payload(field, claim_graph)
    rows, consequences = _hypothesis_rows(field, claim_graph=graph_payload)
    shadow = field.sensor_shadow
    gap_rows = tuple(gap.to_dict() for gap in gaps[:MAX_GAPS_PER_RESOLUTION])
    return CBFResolutionV1(
        resolution_id=resolution_id,
        incident_id=field.incident_id,
        epoch_id=int(field.epoch_id),
        verdict=verdict.to_verdict(),
        identifiability=str(getattr(verdict.state, "value", verdict.state)),
        hypotheses=rows,
        consequence_distribution=consequences,
        claim_graph=graph_payload,
        evidence_lineage=tuple(
            {"store": ref.store, "locator": ref.locator, "digest": ref.digest}
            for ref in field.evidence_refs
        ),
        uncertainty=_field_uncertainty(field),
        shadow=shadow.to_dict() if shadow is not None else {},
        information_gaps=gap_rows,
        truncations=tuple(_truncation_row(item) for item in field.truncations),
        degradations=tuple(dict(row) for row in degradations),
    )


def _graph_payload(field: Any, claim_graph: Mapping[str, Any] | None) -> Mapping[str, Any]:
    if claim_graph is not None:
        return dict(claim_graph)
    live = getattr(field, "claim_graph", None)
    if live is None:
        return {"schema": "pocketsec.typed_claim_graph.v1", "claims": [], "authoritative": []}
    return dict(live.to_dict())


def _field_uncertainty(field: Any) -> float:
    """The leading world's uncertainty, raised by the shadow penalty.

    Maximum rather than mean over the worlds would be the conservative reading,
    but the leader is the explanation the resolution is *about*; the alternatives
    show up as hypotheses in their own right. The shadow penalty is added because
    a blind region cannot reduce uncertainty, only raise it.
    """
    if not field.worlds:
        return 1.0
    leaders = field.leaders(n=1)
    base = float(leaders[0].uncertainty) if leaders else 1.0
    shadow = field.sensor_shadow
    penalty = float(shadow.confidence_penalty()) if shadow is not None else 0.0
    return max(0.0, min(1.0, base + penalty * (1.0 - base)))


def _truncation_row(item: Any) -> dict[str, Any]:
    return {
        "what": str(getattr(item, "what", "unknown")),
        "identifier": str(getattr(item, "identifier", "")),
        "reason": str(getattr(item, "reason", "")),
        "consequence_lost": float(getattr(item, "consequence_lost", 0.0)),
    }


def write_resolution(resolution: CBFResolutionV1, path: Path) -> str:
    """Write canonical JSON and return its ``sha256:`` digest.

    Canonical (sorted keys, no NaN, fixed indent, trailing newline) so the digest
    is reproducible: Stage 10 can certify the resolution it reads is the one
    Stage 4 wrote, which is the same lineage guarantee ``EvidenceRef`` gives raw
    evidence. Writing goes through ``to_dict``, so a resolution that fails either
    refusal never reaches the filesystem.
    """
    payload = (
        json.dumps(resolution.to_dict(), sort_keys=True, allow_nan=False, indent=2).encode(
            "utf-8"
        )
        + b"\n"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return digest_of_bytes(payload)
