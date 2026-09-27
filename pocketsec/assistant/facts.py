"""The typed, bounded facts one alert carries — the only material the explainer may use.

What this module is FOR: the alert explainer answers questions with no language model,
so the honesty of every answer is exactly the honesty of the facts it is filled from.
This module is the fact model. Each fact is a frozen dataclass that says, in its own
fields, *what kind of knowledge it is* (``FactKind``) and *where it came from*
(``source`` — a claim id or a record path — plus the evidence ``digests`` it rests on).

The six epistemic kinds are Stage 4's (``pocketsec/stage4/claims/typed_claim.py``):
OBS / DER / INF / CF / EXT / UNK. A seventh, ``REC``, is added and is deliberately
separate: it marks a statement about **PocketSec's own record** — "the verdict is
UNKNOWN", "confidence is 0.0", "SENTINEL returned PASS". Those are true statements
about what the system wrote down, not observations of the host, and filing them under
OBS would let a record value borrow the authority of a sensor reading.

Why ``support_text``: the grounding guard (``guard.py``) checks every digit run and
every security-dimension word in a sentence against the values of the facts the
sentence cites. A fact's support text is the lower-cased concatenation of *all* its
recorded values, computed from the dataclass fields, so no template can quote a value
the fact does not hold.

Every collection is bounded (``MAX_*``) and every string is cut to ``MAX_TEXT`` with
control characters replaced, because the text of a recorded path is attacker-chosen
and ends up on an analyst's terminal.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from enum import StrEnum

__all__ = [
    "EXPORT_STATUSES",
    "KIND_STRENGTH",
    "MAX_CITED",
    "MAX_EVENTS",
    "MAX_GAPS",
    "MAX_HYPOTHESES",
    "MAX_LEASES",
    "MAX_LINEAGES",
    "MAX_RECEIPTS",
    "MAX_TEXT",
    "MAX_TRUNCATION_GROUPS",
    "MAX_UNKNOWNS",
    "AlertFacts",
    "Assessment",
    "CitedObservation",
    "Denial",
    "Event",
    "EventLedger",
    "EventMeaning",
    "Fact",
    "FactKind",
    "Gap",
    "Hypothesis",
    "LeaseRow",
    "Lineage",
    "Receipt",
    "ResponseSummary",
    "TruncationGroup",
    "Unknown",
]

#: Per-alert bounds. An alert is something a person reads; these are generous for
#: that and small enough that a flood of transitions cannot become an unbounded buffer.
MAX_EVENTS = 128
MAX_LINEAGES = 16
MAX_HYPOTHESES = 16
MAX_CITED = 32
MAX_UNKNOWNS = 32
MAX_TRUNCATION_GROUPS = 16
MAX_GAPS = 8
MAX_RECEIPTS = 16
MAX_LEASES = 16
#: Stage 4's own claim-text bound (``typed_claim.MAX_CLAIM_TEXT``), reused.
MAX_TEXT = 240


EXPORT_STATUSES = ("exported", "cut", "unreferenced")


class FactKind(StrEnum):
    """Stage 4's six epistemic kinds, plus REC for statements about PocketSec's record."""

    OBS = "OBS"
    DER = "DER"
    INF = "INF"
    CF = "CF"
    EXT = "EXT"
    UNK = "UNK"
    REC = "REC"


#: Strongest first. A sentence citing several facts carries the weakest kind among
#: them, so an inference can never ride on an observation's tag.
KIND_STRENGTH: tuple[FactKind, ...] = (
    FactKind.OBS,
    FactKind.DER,
    FactKind.REC,
    FactKind.EXT,
    FactKind.CF,
    FactKind.INF,
    FactKind.UNK,
)


_PROVENANCE_FIELDS = frozenset({"fact_id", "kind", "source", "digests"})


@dataclass(frozen=True, slots=True)
class Fact:
    """Provenance every fact carries. Subclasses add the typed values."""

    fact_id: str
    kind: FactKind
    source: str
    digests: tuple[str, ...]

    def support_text(self) -> str:
        """Every recorded value of this fact, lower-cased: what a sentence may quote.

        The provenance fields (id, kind, source, digests) are left out on purpose. They
        are hex identifiers, and a 64-character digest contains nearly every short digit
        run, so including them would let an invented "4" pass the number check.
        """
        parts: list[str] = []
        for item in fields(self):
            if item.name not in _PROVENANCE_FIELDS:
                _flatten(getattr(self, item.name), parts)
        return " ".join(parts).lower()


def _flatten(value: object, into: list[str]) -> None:
    if isinstance(value, (tuple, list)):
        for item in value:
            _flatten(item, into)
    elif value is not None:
        into.append(str(value))


@dataclass(frozen=True, slots=True)
class Assessment(Fact):
    """REC: what Stage 4 recorded about its own conclusion."""

    incident_id: str
    resolution_id: str
    verdict: str
    identifiability: str
    uncertainty: float
    confidence: float | None
    horizon: str | None
    detail: str | None
    lineage_rows: int


@dataclass(frozen=True, slots=True)
class Hypothesis(Fact):
    """INF: one surviving explanation and the weight Stage 4 gave it. Never a finding."""

    rank: int
    mechanism_id: str
    support: float
    consequence: float
    text: str | None


@dataclass(frozen=True, slots=True)
class CitedObservation(Fact):
    """OBS: an evidence reference Stage 4's claim graph cites for an explanation."""

    claim_id: str
    text: str
    sensor: str
    store: str
    locator: str


@dataclass(frozen=True, slots=True)
class Event(Fact):
    """OBS: one Stage 1 transition — who did what to which object, as recorded."""

    sequence: int
    actor: str
    relation: str
    object_kind: str
    object_name: str
    store: str
    locator: str
    cited_by: tuple[str, ...]
    #: ``exported`` (in the export's evidence lineage), ``cut`` (named in a
    #: ``max_field_evidence_refs`` truncation row: dropped by the export's size cap), or
    #: ``unreferenced`` (the export never mentions this digest).
    export_status: str


@dataclass(frozen=True, slots=True)
class EventMeaning(Fact):
    """DER: what Stage 1's fixed state rules made of one observed event."""

    sequence: int
    rule: str
    raised: tuple[tuple[str, str, str], ...]
    delta_phi: float
    object_classes: tuple[str, ...]
    actor_capabilities: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Lineage(Fact):
    """DER: one process lineage's accumulated security state under Stage 1's calculus."""

    actor: str
    rank: int
    of: int
    phi: float
    state: tuple[tuple[str, str], ...]
    binary: str | None
    capabilities: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Unknown(Fact):
    """UNK: something the record does not know. Never to be restated as "did not happen"."""

    reason: str
    signal: str | None
    text: str
    sensors: tuple[str, ...]
    #: Stage 4's ``ShadowRegion.reason`` for a shadowed signal (one of
    #: ``sensor_shadow.SHADOW_REASONS``), else ``None``. Kept because the four reasons
    #: mean different things: "no evidence the sensors can see it" is not "the sensor
    #: path was dropped", and a template that ignored it would say the wrong one.
    shadow_reason: str | None = None


@dataclass(frozen=True, slots=True)
class TruncationGroup(Fact):
    """REC: rows the record dropped or cut, grouped by why."""

    family: str
    count: int
    example_reason: str
    example_identifier: str


@dataclass(frozen=True, slots=True)
class Gap(Fact):
    """REC: an observation Stage 4 said would help tell explanations apart."""

    signal: str
    why_it_matters: str
    affordable: bool | None


@dataclass(frozen=True, slots=True)
class EventLedger(Fact):
    """REC: how many events the record held and how many this alert kept."""

    total: int
    kept: int
    dropped: int


@dataclass(frozen=True, slots=True)
class ResponseSummary(Fact):
    """REC: the Stage 5 response record's header."""

    record_id: str
    plan_decision: str
    host_kind: str
    simulated: bool
    #: ``ResponseRecordV1.truncations[].reason``: rows the *record* left out to stay
    #: bounded. Not the planner's rationale — the record has no such field — so a
    #: template must never present these as why the plan was chosen.
    truncations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Receipt(Fact):
    """REC: one Stage 5 transaction receipt, seam-safe row form."""

    operator_id: str
    authority: str
    outcome: str
    verdict: str
    denial_reasons: tuple[str, ...]
    rollback_operator_id: str | None
    lease_id: str | None
    verification: str | None
    checks_passed: int
    checks_total: int
    simulated: bool


@dataclass(frozen=True, slots=True)
class Denial(Fact):
    """REC: a transaction SENTINEL (or an earlier gate) refused."""

    operator_id: str
    outcome: str
    kernel_ran: bool
    denial_reasons: tuple[str, ...]
    simulated: bool


@dataclass(frozen=True, slots=True)
class LeaseRow(Fact):
    """REC: a time-limited change and what happened when its time ran out."""

    lease_id: str
    operator_id: str
    granted_at: int
    ttl_seconds: int
    expires_at: int
    hard_deadline: int
    rollback_operator_id: str | None
    expired_at: int | None
    rolled_back: bool | None


@dataclass(frozen=True, slots=True)
class AlertFacts:
    """Everything the explainer knows about one alert. Frozen; questions cannot touch it."""

    alert_id: str
    synthetic: bool
    provenance: str
    assessment: Assessment
    ledger: EventLedger
    hypotheses: tuple[Hypothesis, ...]
    cited: tuple[CitedObservation, ...]
    events: tuple[Event, ...]
    meanings: tuple[EventMeaning, ...]
    lineages: tuple[Lineage, ...]
    unknowns: tuple[Unknown, ...]
    truncations: tuple[TruncationGroup, ...]
    gaps: tuple[Gap, ...]
    response: ResponseSummary | None
    receipts: tuple[Receipt, ...]
    denials: tuple[Denial, ...]
    leases: tuple[LeaseRow, ...]

    def all_facts(self) -> tuple[Fact, ...]:
        head: tuple[Fact, ...] = (self.assessment, self.ledger)
        tail: tuple[Fact, ...] = () if self.response is None else (self.response,)
        return (
            *head,
            *self.hypotheses,
            *self.cited,
            *self.events,
            *self.meanings,
            *self.lineages,
            *self.unknowns,
            *self.truncations,
            *self.gaps,
            *tail,
            *self.receipts,
            *self.denials,
            *self.leases,
        )

    def get(self, fact_id: str) -> Fact | None:
        for fact in self.all_facts():
            if fact.fact_id == fact_id:
                return fact
        return None

    def event_for(self, digest: str) -> Event | None:
        return next((event for event in self.events if event.digests[0] == digest), None)

    def meaning_for(self, digest: str) -> EventMeaning | None:
        return next((m for m in self.meanings if m.digests[0] == digest), None)
