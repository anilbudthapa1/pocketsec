"""Build ``AlertFacts`` from the alert handoff — the one wire form the explainer reads.

What this module is FOR: a live system, a saved file, and the demo all reach the
explainer through the same plain-JSON handoff, so there is exactly one parser to
trust. The handoff (schema ``pocketsec.assistant.alert_handoff.v1``) is:

* ``resolution`` — Stage 4's ``CBFResolutionV1.to_dict()``. It is re-validated with
  ``CBFResolutionV1.from_dict``, which re-runs Stage 4's own export-time refusals
  (laundered kinds, unsupported authoritative claims). An explainer that accepted a
  payload Stage 4 would refuse would explain a forgery.
* ``synthetic`` — required and must be a bool. A record that omits it could be read
  as real telemetry by accident, the same reasoning as ADR-0046.
* ``events`` / ``lineages`` — Stage 1 transitions and per-lineage state, projected by
  ``capture.py``. Optional: without them the explainer says it only has the export.
* ``assessment`` — optional extras only the live ``IncidentResolution`` holds
  (confidence, horizon, the engine's own one-line detail).
* ``response`` / ``leases`` — optional Stage 5 ``ResponseRecordV1.to_dict()`` and
  seam-safe lease rows. Read as plain rows: this package imports nothing from Stage 5,
  so no code path here can reach an executor.

Everything is validated at this boundary: digests must match ``sha256:<64 hex>``,
enums must be known, numbers finite, strings are cut to ``MAX_TEXT`` and scrubbed of
control characters (a recorded path is attacker-chosen text headed for a terminal).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from pocketsec.assistant.facts import (
    MAX_CITED,
    MAX_EVENTS,
    MAX_GAPS,
    MAX_HYPOTHESES,
    MAX_LINEAGES,
    MAX_TRUNCATION_GROUPS,
    MAX_UNKNOWNS,
    AlertFacts,
    Assessment,
    CitedObservation,
    Event,
    EventLedger,
    EventMeaning,
    FactKind,
    Gap,
    Hypothesis,
    LeaseRow,
    Lineage,
    TruncationGroup,
    Unknown,
)
from pocketsec.assistant.readers import (
    DIGEST_RE,
    HandoffError,
    clean_text,
    integer,
    names,
    number,
    opt_bool,
    opt_text,
)
from pocketsec.assistant.readers import (
    digest as read_digest,
)
from pocketsec.assistant.readers import (
    rows as row_list,
)
from pocketsec.assistant.response_rows import response_facts
from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.ssir.relations import Relation
from pocketsec.stage1.state.security_state import DIMENSIONS
from pocketsec.stage4.stage5_interface import CBFResolutionV1

__all__ = [
    "EVIDENCE_CAP_FAMILY",
    "HANDOFF_SCHEMA",
    "MAX_DIGESTS_PER_FACT",
    "MAX_INPUT_EVENTS",
    "HandoffError",
    "facts_from_handoff",
    "select_event_rows",
]

HANDOFF_SCHEMA = "pocketsec.assistant.alert_handoff.v1"
#: Stage 4's truncation reason for evidence dropped by the export's reference cap
#: (``lucid_support.py``: ``max_field_evidence_refs:<N>``).
EVIDENCE_CAP_FAMILY = "max_field_evidence_refs"
#: Event rows read from one handoff. Stage 4's own per-incident bound
#: (``incident_corpus.MAX_BEHAVIOURS_PER_INCIDENT``); rows past it are counted, not read.
MAX_INPUT_EVENTS = 4096
#: Evidence digests kept per hypothesis or lineage: enough to cite, not a dump.
MAX_DIGESTS_PER_FACT = 8

_RELATIONS = frozenset(relation.name for relation in Relation)


def _fact_suffix(value: str) -> str:
    return value[7:23]


# --- Stage 4: the resolution -------------------------------------------------------------


def _resolution(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise HandoffError("resolution must be a CBFResolutionV1 object")
    try:
        return CBFResolutionV1.from_dict(value).to_dict()
    except ContractError as exc:
        raise HandoffError(f"resolution refused by Stage 4's own checks: {exc}") from exc
    except (KeyError, TypeError, ValueError) as exc:
        raise HandoffError(f"resolution is malformed: {type(exc).__name__}") from exc


def _assessment(wire: Mapping[str, Any], extras: object) -> Assessment:
    extra = extras if isinstance(extras, Mapping) else {}
    confidence = extra.get("confidence")
    return Assessment(
        fact_id="rec:assessment",
        kind=FactKind.REC,
        source=f"record:resolution/{wire['resolution_id']}",
        digests=(),
        incident_id=clean_text(wire["incident_id"], "incident_id"),
        resolution_id=clean_text(wire["resolution_id"], "resolution_id"),
        verdict=clean_text(wire["verdict"], "verdict"),
        identifiability=clean_text(wire["identifiability"], "identifiability"),
        uncertainty=number(wire["uncertainty"], "uncertainty"),
        confidence=None if confidence is None else number(confidence, "assessment.confidence"),
        horizon=opt_text(extra.get("horizon"), "assessment.horizon"),
        detail=opt_text(extra.get("detail"), "assessment.detail"),
        lineage_rows=len(wire["evidence_lineage"]),
    )


def _claim_rows(wire: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    graph = wire.get("claim_graph") or {}
    return [row for row in row_list(graph.get("claims"), "claim_graph.claims")]


def _hypotheses(wire: Mapping[str, Any], claims: list[Mapping[str, Any]]) -> tuple[Hypothesis, ...]:
    text_of = {row.get("claim_id"): row.get("text") for row in claims}
    out: list[Hypothesis] = []
    for index, row in enumerate(row_list(wire["hypotheses"], "hypotheses")[:MAX_HYPOTHESES]):
        inf_ids = [c for c in row.get("claim_ids", ()) if str(c).startswith("inf.")]
        claim_id = inf_ids[0] if inf_ids else None
        listed = row.get("evidence_digests", ())[:MAX_DIGESTS_PER_FACT]
        digests = [d for d in listed if DIGEST_RE.match(str(d))]
        text = text_of.get(claim_id) if claim_id else None
        out.append(
            Hypothesis(
                fact_id=f"inf:{index}",
                kind=FactKind.INF,
                source=claim_id or f"record:hypotheses[{index}]",
                digests=tuple(digests[:MAX_DIGESTS_PER_FACT]),
                rank=index + 1,
                mechanism_id=clean_text(row["mechanism_id"], "hypotheses.mechanism_id"),
                support=number(row["support"], "hypotheses.support"),
                consequence=number(row["consequence"], "hypotheses.consequence"),
                text=None if text is None else clean_text(text, "claim.text"),
            )
        )
    return tuple(out)


def _cited(claims: list[Mapping[str, Any]]) -> tuple[CitedObservation, ...]:
    out: list[CitedObservation] = []
    for row in claims:
        if row.get("kind") != "OBS" or not row.get("evidence"):
            continue
        ref = row["evidence"][0]
        claim_id = clean_text(row["claim_id"], "claim.claim_id")
        out.append(
            CitedObservation(
                fact_id=f"obs:{claim_id}",
                kind=FactKind.OBS,
                source=claim_id,
                digests=(read_digest(ref.get("digest"), "claim.evidence.digest"),),
                claim_id=claim_id,
                text=clean_text(row.get("text", ""), "claim.text"),
                sensor=clean_text(row.get("sensor", ""), "claim.sensor", limit=32),
                store=clean_text(ref.get("store", ""), "claim.evidence.store", limit=64),
                locator=clean_text(ref.get("locator", ""), "claim.evidence.locator", limit=64),
            )
        )
    return tuple(out[:MAX_CITED])


# --- Stage 1: events and lineages -------------------------------------------------------


def _row_priority(row: Mapping[str, Any], cited: frozenset[str]) -> tuple[int, float, int]:
    digest = str(row.get("digest"))
    raw = row.get("delta_phi")
    delta = float(raw) if isinstance(raw, (int, float)) and not isinstance(raw, bool) else 0.0
    moved = delta > 0
    tier = 0 if digest in cited else 1 if moved else 2 if row.get("relation") == "EXECUTE" else 3
    sequence = row.get("sequence")
    return (tier, -delta, sequence if isinstance(sequence, int) else 0)


def select_event_rows(
    rows: Sequence[Mapping[str, Any]], cited: frozenset[str]
) -> list[Mapping[str, Any]]:
    """Keep at most ``MAX_EVENTS``: cited first, then state changes, then program runs.

    The cap is recorded in the ``EventLedger`` so an answer can say events were dropped;
    a bounded buffer must never silently become "nothing else happened".
    """
    unique: dict[str, Mapping[str, Any]] = {}
    for row in rows:
        unique.setdefault(str(row.get("digest")), row)
    ranked = sorted(unique.values(), key=lambda row: _row_priority(row, cited))
    kept = ranked[:MAX_EVENTS]
    return sorted(kept, key=lambda row: _row_priority(row, frozenset())[2])


def _raised(value: object, field: str) -> tuple[tuple[str, str, str], ...]:
    out: list[tuple[str, str, str]] = []
    for item in _triples(value, field):
        dimension, before, after = item
        if dimension not in DIMENSIONS:
            raise HandoffError(f"{field} names unknown dimension")
        lattice = DIMENSIONS[dimension]
        try:
            out.append((dimension, lattice(before).name, lattice(after).name))
        except ValueError as exc:
            raise HandoffError(f"{field} level out of range") from exc
    return tuple(out)


def _triples(value: object, field: str) -> list[tuple[str, int, int]]:
    if not isinstance(value, (list, tuple)):
        raise HandoffError(f"{field} must be a list of [dimension, from, to]")
    out: list[tuple[str, int, int]] = []
    for item in value[: len(DIMENSIONS)]:
        if not isinstance(item, (list, tuple)) or len(item) != 3:
            raise HandoffError(f"{field} rows must be [dimension, from, to]")
        out.append((str(item[0]), integer(item[1], field), integer(item[2], field)))
    return out


def _export_status(digest: str, exported: frozenset[str], cut: frozenset[str]) -> str:
    if digest in exported:
        return "exported"
    return "cut" if digest in cut else "unreferenced"


def _event(
    row: Mapping[str, Any],
    cited_by: Mapping[str, tuple[str, ...]],
    exported: frozenset[str],
    cut: frozenset[str],
) -> tuple[Event, EventMeaning]:
    digest = read_digest(row.get("digest"), "events.digest")
    relation = clean_text(row.get("relation"), "events.relation", limit=32)
    if relation not in _RELATIONS:
        raise HandoffError("events.relation is not a Stage 1 relation")
    sequence = integer(row.get("sequence"), "events.sequence")
    suffix = _fact_suffix(digest)
    event = Event(
        fact_id=f"evt:{suffix}",
        kind=FactKind.OBS,
        source=digest,
        digests=(digest,),
        sequence=sequence,
        actor=clean_text(row.get("actor"), "events.actor", limit=64),
        relation=relation,
        object_kind=clean_text(row.get("object_kind", ""), "events.object_kind", limit=32),
        object_name=clean_text(row.get("object_name", ""), "events.object_name"),
        store=clean_text(row.get("store", ""), "events.store", limit=64),
        locator=clean_text(row.get("locator", ""), "events.locator", limit=64),
        cited_by=cited_by.get(digest, ()),
        export_status=_export_status(digest, exported, cut),
    )
    meaning = EventMeaning(
        fact_id=f"der:{suffix}",
        kind=FactKind.DER,
        source="rule:stage1.state_calculus",
        digests=(digest,),
        sequence=sequence,
        rule="stage1.state_calculus",
        raised=_raised(row.get("raised", ()), "events.raised"),
        delta_phi=number(row.get("delta_phi", 0.0), "events.delta_phi"),
        object_classes=names(row.get("object_properties", ()), "events.object_properties"),
        actor_capabilities=names(row.get("actor_properties", ()), "events.actor_properties"),
    )
    return event, meaning


def _cut_digests(wire: Mapping[str, Any]) -> frozenset[str]:
    """Digests the export dropped because of its evidence-reference cap."""
    return frozenset(
        str(row.get("identifier"))
        for row in row_list(wire["truncations"], "truncations")
        if str(row.get("reason", "")).startswith(EVIDENCE_CAP_FAMILY)
        and DIGEST_RE.match(str(row.get("identifier")))
    )


def _events(
    payload: Mapping[str, Any],
    cited: tuple[CitedObservation, ...],
    wire: Mapping[str, Any],
) -> tuple[tuple[Event, ...], tuple[EventMeaning, ...], EventLedger]:
    exported = frozenset(str(row.get("digest")) for row in wire["evidence_lineage"])
    cut = _cut_digests(wire)
    supplied = row_list(payload.get("events"), "events")
    raw = supplied[:MAX_INPUT_EVENTS]
    cited_by: dict[str, tuple[str, ...]] = {}
    for obs in cited:
        cited_by[obs.digests[0]] = (*cited_by.get(obs.digests[0], ()), obs.claim_id)
    kept = select_event_rows(raw, frozenset(cited_by))
    pairs = [_event(row, cited_by, exported, cut) for row in kept]
    total = payload.get("events_total", len(supplied))
    total = max(integer(total, "events_total"), len(supplied))
    ledger = EventLedger(
        fact_id="rec:events",
        kind=FactKind.REC,
        source="record:stage1.transitions",
        digests=(),
        total=total,
        kept=len(pairs),
        dropped=total - len(pairs),
    )
    return tuple(e for e, _ in pairs), tuple(m for _, m in pairs), ledger


def _lineage(row: Mapping[str, Any], rank: int, of: int) -> Lineage:
    actor = clean_text(row.get("actor"), "lineages.actor", limit=64)
    state = []
    for item in _pairs(row.get("state", ()), "lineages.state"):
        if item[0] not in DIMENSIONS or item[1] not in DIMENSIONS[item[0]].__members__:
            raise HandoffError("lineages.state names an unknown dimension or level")
        state.append(item)
    listed = row.get("digests", ())[:MAX_DIGESTS_PER_FACT]
    digests = [read_digest(d, "lineages.digests") for d in listed]
    binary = row.get("binary")
    return Lineage(
        fact_id=f"lin:{actor}",
        kind=FactKind.DER,
        source="rule:stage1.lineage_state",
        digests=tuple(digests),
        actor=actor,
        rank=rank,
        of=of,
        phi=number(row.get("phi", 0.0), "lineages.phi"),
        state=tuple(state),
        binary=None if binary is None else clean_text(binary, "lineages.binary"),
        capabilities=names(row.get("capabilities", ()), "lineages.capabilities"),
    )


def _pairs(value: object, field: str) -> list[tuple[str, str]]:
    if not isinstance(value, (list, tuple)):
        raise HandoffError(f"{field} must be a list of [dimension, level]")
    out: list[tuple[str, str]] = []
    for item in value[: len(DIMENSIONS)]:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            raise HandoffError(f"{field} rows must be [dimension, level]")
        out.append((str(item[0]), str(item[1])))
    return out


def _lineages(payload: Mapping[str, Any]) -> tuple[Lineage, ...]:
    listed = list(row_list(payload.get("lineages"), "lineages"))
    ranked = sorted(listed, key=lambda r: (-number(r.get("phi", 0.0), "phi"), str(r.get("actor"))))
    of = len(ranked)
    return tuple(_lineage(row, i + 1, of) for i, row in enumerate(ranked[:MAX_LINEAGES]))


# --- unknowns, truncations, gaps ------------------------------------------------------


def _regions(shadow: Mapping[str, Any]) -> dict[str, tuple[tuple[str, ...], str | None]]:
    """Shadow signal -> (blind sensors, Stage 4's recorded reason for the region)."""
    out: dict[str, tuple[tuple[str, ...], str | None]] = {}
    for region in row_list(shadow.get("regions"), "shadow.regions"):
        reason = region.get("reason")
        out[str(region.get("signal"))] = (
            names(region.get("sensors_blind", ()), "shadow.sensors_blind"),
            None if reason is None else clean_text(reason, "shadow.reason", limit=48),
        )
    return out


def _unknowns(
    claims: list[Mapping[str, Any]],
    shadow: Mapping[str, Any],
    lineages: tuple[Lineage, ...],
    leases: tuple[LeaseRow, ...],
    *,
    has_response: bool,
) -> tuple[Unknown, ...]:
    regions = _regions(shadow)
    out: list[Unknown] = []
    for row in claims:
        if row.get("kind") != "UNK":
            continue
        claim_id = clean_text(row["claim_id"], "claim.claim_id")
        region = row.get("shadow_region") or None
        sensors, shadow_reason = regions.get(str(region), ((), None))
        out.append(
            Unknown(
                fact_id=f"unk:{claim_id}",
                kind=FactKind.UNK,
                source=claim_id,
                digests=(),
                reason=clean_text(row.get("reason", ""), "claim.reason", limit=32),
                signal=None if region is None else clean_text(region, "claim.shadow_region"),
                text=clean_text(row.get("text", ""), "claim.text"),
                sensors=sensors,
                shadow_reason=None if region is None else shadow_reason,
            )
        )
    for lineage in lineages:
        if lineage.binary is None:
            out.append(
                _derived_unknown(
                    f"program:{lineage.actor}",
                    f"no program run was observed for process {lineage.actor}",
                    f"record:stage1.lineage/{lineage.actor}",
                )
            )
    out.extend(_lease_unknowns(leases))
    if not has_response:
        out.append(
            _derived_unknown(
                "response",
                "no record from PocketSec's response stage is attached to this alert",
                "record:response",
            )
        )
    return tuple(out[:MAX_UNKNOWNS])


def _lease_unknowns(leases: tuple[LeaseRow, ...]) -> list[Unknown]:
    """An expired lease whose reversal outcome is absent (or still pending).

    ``rolled_back`` is ``None`` both when the key is missing and while Stage 5's
    sweeper call is still returning. Neither says the change was left in place, so the
    explainer holds it as an unknown, never as "no reversal was attempted".
    """
    return [
        _derived_unknown(
            f"lease:{index}",
            f"whether the change under lease {lease.lease_id} was reversed is not recorded",
            lease.source,
        )
        for index, lease in enumerate(leases)
        if lease.expired_at is not None and lease.rolled_back is None
    ]


def _derived_unknown(key: str, text: str, source: str) -> Unknown:
    """Absences the record implies. Phrased as "not observed", never as "did not"."""
    return Unknown(
        fact_id=f"unk:{key}",
        kind=FactKind.UNK,
        source=source,
        digests=(),
        reason="not_observed",
        signal=None,
        text=text,
        sensors=(),
    )


def _truncations(wire: Mapping[str, Any]) -> tuple[TruncationGroup, ...]:
    groups: dict[str, list[Mapping[str, Any]]] = {}
    for row in row_list(wire["truncations"], "truncations"):
        family = str(row.get("reason", "unspecified")).split(":")[0] or "unspecified"
        groups.setdefault(clean_text(family, "truncations.reason", limit=48), []).append(row)
    for row in row_list(wire["degradations"], "degradations"):
        groups.setdefault("degradation", []).append(
            {"reason": " ".join(f"{k}={v}" for k, v in sorted(row.items())), "identifier": ""}
        )
    out: list[TruncationGroup] = []
    for family, members in sorted(groups.items())[:MAX_TRUNCATION_GROUPS]:
        digests = [
            str(r.get("identifier")) for r in members if DIGEST_RE.match(str(r.get("identifier")))
        ]
        out.append(
            TruncationGroup(
                fact_id=f"trunc:{family}",
                kind=FactKind.REC,
                source="record:resolution.truncations",
                digests=tuple(digests[:MAX_DIGESTS_PER_FACT]),
                family=family,
                count=len(members),
                example_reason=clean_text(str(members[0].get("reason", "")), "truncations.reason"),
                example_identifier=clean_text(
                    str(members[0].get("identifier", "")), "truncations.id"
                ),
            )
        )
    return tuple(out)


def _gaps(wire: Mapping[str, Any]) -> tuple[Gap, ...]:
    return tuple(
        Gap(
            fact_id=f"gap:{index}",
            kind=FactKind.REC,
            source=f"record:resolution.information_gaps[{index}]",
            digests=(),
            signal=clean_text(row.get("signal", ""), "gaps.signal", limit=64),
            why_it_matters=clean_text(str(row.get("why_it_matters", "")), "gaps.why"),
            affordable=opt_bool(row.get("affordable"), "gaps.affordable"),
        )
        for index, row in enumerate(
            row_list(wire["information_gaps"], "information_gaps")[:MAX_GAPS]
        )
    )


# --- the entry point ----------------------------------------------------------------


def facts_from_handoff(payload: Mapping[str, Any]) -> AlertFacts:
    """Validate one handoff and build its facts, or raise ``HandoffError``.

    Any structural surprise deeper in the payload (a missing key, a list where an
    object belongs) is reported as a ``HandoffError`` too, so a caller has exactly one
    refusal to handle and a malformed file can never crash the chat loop.
    """
    try:
        return _build(payload)
    except HandoffError:
        raise
    except (KeyError, TypeError, AttributeError, IndexError, ValueError) as exc:
        raise HandoffError(f"handoff is malformed ({type(exc).__name__})") from exc
    except ArithmeticError as exc:
        # An integer too large for a float, say. Arithmetic on attacker-sized input.
        raise HandoffError("handoff holds a number out of range") from exc
    except RecursionError as exc:
        raise HandoffError("handoff is nested too deeply") from exc


def _build(payload: Mapping[str, Any]) -> AlertFacts:
    if not isinstance(payload, Mapping):
        raise HandoffError("handoff must be an object")
    schema = payload.get("schema", HANDOFF_SCHEMA)
    if schema != HANDOFF_SCHEMA:
        raise HandoffError("handoff schema is not pocketsec.assistant.alert_handoff.v1")
    synthetic = payload.get("synthetic")
    if not isinstance(synthetic, bool):
        raise HandoffError("handoff.synthetic must be an explicit bool")
    wire = _resolution(payload.get("resolution"))
    claims = _claim_rows(wire)
    cited = _cited(claims)
    events, meanings, ledger = _events(payload, cited, wire)
    lineages = _lineages(payload)
    response, receipts, denials, leases = response_facts(payload, wire["incident_id"])
    return AlertFacts(
        alert_id=clean_text(wire["incident_id"], "incident_id", limit=128),
        synthetic=synthetic,
        provenance=clean_text(payload.get("provenance", "unspecified"), "provenance"),
        assessment=_assessment(wire, payload.get("assessment")),
        ledger=ledger,
        hypotheses=_hypotheses(wire, claims),
        cited=cited,
        events=events,
        meanings=meanings,
        lineages=lineages,
        unknowns=_unknowns(
            claims, wire["shadow"], lineages, leases, has_response=response is not None
        ),
        truncations=_truncations(wire),
        gaps=_gaps(wire),
        response=response,
        receipts=receipts,
        denials=denials,
        leases=leases,
    )
