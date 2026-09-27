"""One sentence-builder per question type. Every sentence is filled from facts.

What this module is FOR: the explainer's actual wording. Each builder takes an alert's
facts and returns ``(sentences, note_keys)``. A sentence is made only through
``say(text, *facts)``, which computes its epistemic kind as the *weakest* kind among
the facts it cites — so a sentence that mentions an inference is an inference, and a
sentence that mentions an unknown is an unknown, whatever the template intended.

Rules every template here follows (``guard.py`` enforces them, and anything that fails
is withheld rather than shown):

* numbers are quoted with ``quote_number`` — exact, or truncated with "about";
* an inference names itself as possible ("possible explanations");
* an unknown says "unknown" or "not observed" and is never phrased as an absence of
  activity; the shadow regions in particular describe sensor *coverage*, and an
  observed event that contradicts one is shown next to it;
* nothing says what Stage 4 concluded unless Stage 4 recorded it. The events ranked in
  "why" are ranked by Stage 1's state-change score, and a note says so;
* nothing glosses a recorded value with a cause the record does not hold. The
  wording for identifiability UNKNOWN and for a confidence of 0.0 says only what is
  true in every case Stage 4 produces them (a review found both over-read).

The response-side builders (what was done, undo, requests, advice) live in
``response_templates.py``; ``say`` and the shared unknown sentences in
``template_kit.py``.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping

from pocketsec.assistant.facts import (
    AlertFacts,
    Event,
    EventMeaning,
    Lineage,
    TruncationGroup,
    Unknown,
)
from pocketsec.assistant.guard import quote_number
from pocketsec.assistant.handoff import EVIDENCE_CAP_FAMILY
from pocketsec.assistant.phrasing import (
    NOVEL_PREFIX,
    capability_phrase,
    class_phrase,
    dimension_phrase,
    horizon_phrase,
    identifiability_phrase,
    join_phrases,
    level_phrase,
    mechanisms_phrase,
    permitted_reading,
    relation_phrase,
    shadow_phrase,
    truncation_phrase,
)
from pocketsec.assistant.response_templates import (
    action_request,
    advice,
    how_to_undo,
    what_action,
)
from pocketsec.assistant.template_kit import (
    NON_COMMITTAL,
    Built,
    no_response,
    say,
    short_digest,
    unknown_fact,
)
from pocketsec.assistant.wording import Sentence

__all__ = ["BUILDERS", "NON_COMMITTAL", "Builder", "Built", "say"]


# --- shared pieces -------------------------------------------------------------------


def _top_changes(facts: AlertFacts, limit: int) -> list[tuple[Event, EventMeaning]]:
    ranked = sorted(
        (m for m in facts.meanings if m.delta_phi > 0), key=lambda m: (-m.delta_phi, m.sequence)
    )
    out: list[tuple[Event, EventMeaning]] = []
    for meaning in ranked[:limit]:
        event = facts.event_for(meaning.digests[0])
        if event is not None:
            out.append((event, meaning))
    return out


def _step(event: Event) -> Sentence:
    action = relation_phrase(event.relation, event.object_kind, event.object_name)
    return say(f"Step {event.sequence}: process {event.actor} {action}.", event)


def _raise(meaning: EventMeaning) -> Sentence | None:
    if not meaning.raised:
        return None
    changes = join_phrases(
        f"{dimension_phrase(dim)} to {level_phrase(after)}"
        for dim, _before, after in meaning.raised
    )
    return say(
        f"By PocketSec's fixed state rules this raised {changes} "
        f"(change score {quote_number(meaning.delta_phi)}).",
        meaning,
    )


def _classes(event: Event, meaning: EventMeaning) -> Sentence | None:
    if not meaning.object_classes or not event.object_name:
        return None
    reading = permitted_reading(meaning.object_classes)
    classes = join_phrases(class_phrase(name) for name in meaning.object_classes)
    tail = f"; the strongest reading those rules allow is {reading}" if reading else ""
    return say(
        f"PocketSec's rules classify {event.object_name} as {classes}{tail}.", event, meaning
    )


def _export_gap(facts: AlertFacts, event: Event) -> Sentence | None:
    """Say when an event shown here is not in the export Stage 4 handed on, and why."""
    if event.export_status == "exported":
        return None
    cap = next((t for t in facts.truncations if t.family == EVIDENCE_CAP_FAMILY), None)
    if event.export_status == "cut" and cap is not None:
        limit = truncation_phrase(cap.example_reason) or f"has a size limit ({cap.example_reason})"
        return say(
            f"Step {event.sequence}'s evidence reference was one of {cap.count} cut from the "
            f"exported record, which {limit}; the event itself comes from PocketSec's event "
            "record.",
            event,
            cap,
        )
    return say(
        f"Step {event.sequence} is not referenced in the exported record; the event comes "
        "from PocketSec's event record.",
        event,
    )


def _event_block(facts: AlertFacts, event: Event, meaning: EventMeaning) -> list[Sentence]:
    parts = [_step(event), _raise(meaning), _classes(event, meaning), _export_gap(facts, event)]
    return [part for part in parts if part is not None]


def _lineage_state(lineage: Lineage) -> Sentence:
    state = join_phrases(f"{dimension_phrase(d)} {level_phrase(v)}" for d, v in lineage.state)
    rank = (
        f"the highest of the {lineage.of} processes PocketSec tracked here"
        if lineage.rank == 1
        else f"number {lineage.rank} of the {lineage.of} processes PocketSec tracked here"
    )
    held = f"ends with {state}" if state else "raised no security state"
    return say(
        f"Taken together, process {lineage.actor} {held}; its security-state score is "
        f"{quote_number(lineage.phi)}, {rank}.",
        lineage,
    )


def _hypotheses(facts: AlertFacts, limit: int) -> list[Sentence]:
    listed = facts.hypotheses[:limit]
    if not listed:
        return []
    weights = {h.support for h in facts.hypotheses}
    if len(listed) > 1 and len(weights) == 1:
        names = mechanisms_phrase((h.mechanism_id, "") for h in listed)
        text = (
            f"PocketSec is weighing {len(facts.hypotheses)} possible explanations and gives "
            f"each the same weight, {quote_number(listed[0].support)}: {names}."
        )
    else:
        weighed = mechanisms_phrase((h.mechanism_id, quote_number(h.support)) for h in listed)
        text = f"Possible explanations, with the weight PocketSec gives each: {weighed}."
    # Cite every hypothesis: the count quoted above is a property of all of them.
    return [say(text, *facts.hypotheses)]


def _novel_note(facts: AlertFacts) -> list[str]:
    novel = any(h.mechanism_id.startswith(NOVEL_PREFIX) for h in facts.hypotheses)
    return ["NOVEL"] if novel else []


def _novelty_line(facts: AlertFacts) -> list[Sentence]:
    """How many of the explanations are unfamiliar, counted from the hypotheses."""
    total = len(facts.hypotheses)
    novel = sum(1 for h in facts.hypotheses if h.mechanism_id.startswith(NOVEL_PREFIX))
    if not novel:
        return []
    if novel == total:
        text = {
            1: "The one possible explanation it holds is an unresolved novel mechanism.",
            2: "Both possible explanations it holds are unresolved novel mechanisms.",
        }.get(total, f"All {total} possible explanations it holds are unresolved novel mechanisms.")
    else:
        text = (
            f"{novel} of the {total} possible explanations it holds are unresolved novel "
            "mechanisms; the others are mechanisms PocketSec knows."
        )
    return [say(text, *facts.hypotheses)]


def _identifiability_unknown(facts: AlertFacts) -> list[Sentence]:
    found = unknown_fact(facts, "unk:unk.identifiability")
    if found is None:
        return []
    return [
        say(
            "Which of the remaining explanations is right is unknown: PocketSec knows of no "
            "affordable observation that would separate them.",
            found,
        )
    ]


def _cited_observations(facts: AlertFacts, limit: int) -> list[Sentence]:
    return [
        say(
            f"The engine's explanations cite {obs.sensor} sensor record {obs.locator} "
            f"(digest {short_digest(obs.digests[0])}).",
            obs,
        )
        for obs in facts.cited[:limit]
    ]


# --- WHY_FLAGGED ---------------------------------------------------------------------


def _assessment_lines(facts: AlertFacts) -> list[Sentence]:
    a = facts.assessment
    out = [
        say(
            f"PocketSec's reasoning engine recorded the verdict {a.verdict} for incident "
            f"{a.incident_id}: {identifiability_phrase(a.identifiability)}.",
            a,
        )
    ]
    if a.identifiability == "UNKNOWN":
        out.extend(_novelty_line(facts))
    if a.horizon:
        out.append(
            say(f"When it handed the incident on, {horizon_phrase(a.horizon)}.", a)
        )
    return out


def why_flagged(facts: AlertFacts, expanded: bool) -> Built:
    out = _assessment_lines(facts)
    notes: list[str] = []
    if facts.events:
        for event, meaning in _top_changes(facts, 6 if expanded else 3):
            out.extend(_event_block(facts, event, meaning))
        if facts.lineages and facts.lineages[0].phi > 0:
            out.append(_lineage_state(facts.lineages[0]))
        notes.append("RANKING")
    else:
        out.extend(_cited_observations(facts, 4))
        notes.append("NO_EVENTS")
    out.extend(_hypotheses(facts, 4))
    return out, [*notes, *_novel_note(facts)]


# --- WHAT_HAPPENED -------------------------------------------------------------------


def _impact(facts: AlertFacts, event: Event) -> tuple[int, float, int]:
    """Sort key: state changes first (largest first), then cited events, then program runs.

    The same ordering "why" uses for its top events, so the first page of "what
    happened" can never leave out the events "why" calls the most significant.
    """
    meaning = facts.meaning_for(event.digests[0])
    delta = 0.0 if meaning is None else meaning.delta_phi
    tier = 0 if delta > 0 else 1 if event.cited_by else 2
    return (tier, -delta, event.sequence)


def what_happened(facts: AlertFacts, expanded: bool) -> Built:
    if not facts.events:
        return _cited_observations(facts, 8), ["NO_EVENTS"]
    chosen = [
        event
        for event in facts.events
        if event.cited_by or event.relation == "EXECUTE" or _impact(facts, event)[0] == 0
    ]
    limit = 24 if expanded else 8
    by_impact = sorted(chosen, key=lambda e: _impact(facts, e))
    shown = sorted(by_impact[:limit], key=lambda e: e.sequence)
    which = (
        "the ones that changed the security state most, then events the reasoning engine "
        "cited, then program runs"
        if len(chosen) > limit
        else "the ones that changed the security state, ran a program, or were cited by the "
        "reasoning engine"
    )
    out = [
        say(
            f"PocketSec's event record holds {facts.ledger.total} events for this incident. "
            f"Below, in step order, are {which}.",
            facts.ledger,
        )
    ]
    for event in shown:
        out.append(_step(event))
        meaning = facts.meaning_for(event.digests[0])
        change = None if meaning is None else _raise(meaning)
        if change is not None:
            out.append(change)
    notes = ["NO_CLOCK"]
    if len(chosen) > limit:
        notes.append("MORE_CAPPED" if expanded else "MORE")
    return out, notes


# --- WHICH_PROCESS -------------------------------------------------------------------


def _program_line(facts: AlertFacts, lineage: Lineage) -> Sentence | None:
    if lineage.binary is not None:
        ran = next(
            (
                e
                for e in facts.events
                if e.actor == lineage.actor
                and e.relation == "EXECUTE"
                and e.object_name == lineage.binary
            ),
            None,
        )
        return say(f"Process {lineage.actor} ran the program {lineage.binary}.", ran or lineage)
    missing = unknown_fact(facts, f"unk:program:{lineage.actor}")
    if missing is None:
        return None
    return say(
        f"The program name for process {lineage.actor} is unknown: no program run by it was "
        "observed in the recorded events.",
        missing,
    )


def which_process(facts: AlertFacts, expanded: bool) -> Built:
    if not facts.lineages:
        return [], ["NO_EVENTS" if not facts.events else "NO_FACTS", "PROCESS_NAMES"]
    out: list[Sentence] = []
    for lineage in facts.lineages[: 6 if expanded else 3]:
        program = _program_line(facts, lineage)
        if program is not None:
            out.append(program)
        if lineage.capabilities:
            abilities = join_phrases(capability_phrase(c) for c in lineage.capabilities)
            out.append(
                say(
                    f"PocketSec's behaviour rules say process {lineage.actor} {abilities}.", lineage
                )
            )
        out.append(_lineage_state(lineage))
    return out, ["PROCESS_NAMES"]


# --- HOW_SURE ------------------------------------------------------------------------


def how_sure(facts: AlertFacts, expanded: bool) -> Built:
    a = facts.assessment
    out: list[Sentence] = []
    if a.confidence is not None:
        out.append(
            say(
                f"PocketSec's recorded confidence is {quote_number(a.confidence)} and its "
                f"recorded uncertainty is {quote_number(a.uncertainty)}.",
                a,
            )
        )
    else:
        out.append(
            say(
                "No confidence value was recorded for this alert; its recorded uncertainty is "
                f"{quote_number(a.uncertainty)}.",
                a,
            )
        )
    if a.confidence == 0.0:
        # No causal gloss: Stage 4 records 0.0 when there is no shadow model, when any
        # expected signal is an unknown hole, or when the leader's uncertainty is 1.0
        # (``lucid_steps.confidence_of``). The record does not say which, so neither
        # does this sentence.
        out.append(
            say(
                "A confidence of 0.0 is not a statement that the activity is harmless.",
                a,
            )
        )
    if a.verdict in NON_COMMITTAL:
        out.append(
            say(
                f"The verdict {a.verdict} is an abstention: PocketSec records UNKNOWN rather "
                "than guess when the evidence does not decide.",
                a,
            )
        )
    out.extend(_hypotheses(facts, 16 if expanded else 4))
    if a.detail:
        out.append(say(f'The engine\'s own note reads: "{a.detail}".', a))
    out.extend(_identifiability_unknown(facts))
    return out, _novel_note(facts)


# --- WHAT_UNKNOWN --------------------------------------------------------------------


def _shadow_lines(facts: AlertFacts, unknown: Unknown) -> list[Sentence]:
    signal = unknown.signal or ""
    sensors = join_phrases(unknown.sensors) or "its sensors"
    region = shadow_phrase(unknown.shadow_reason, sensors, signal)
    out = [
        say(
            f"{region}, so its coverage of that signal is unknown; this is a statement about "
            "sensor coverage only, and leaves the host's activity undecided.",
            unknown,
        )
    ]
    contrary = next(
        (m for m in facts.meanings if any(dim == signal for dim, _b, _a in m.raised)), None
    )
    if contrary is not None:
        out.append(
            say(
                f"Even so, observed events in this incident did change "
                f"{dimension_phrase(signal)}, for example step {contrary.sequence}.",
                contrary,
            )
        )
    return out


def _unknown_line(facts: AlertFacts, unknown: Unknown) -> list[Sentence]:
    if unknown.reason == "shadowed" and unknown.signal:
        return _shadow_lines(facts, unknown)
    if unknown.fact_id == "unk:unk.identifiability":
        return _identifiability_unknown(facts)
    if unknown.fact_id == "unk:response":
        return no_response(facts, "any response was taken")
    return [say(f"Unknown to the record: {unknown.text}.", unknown)]


def _truncation_line(group: TruncationGroup) -> Sentence:
    if group.family == EVIDENCE_CAP_FAMILY:
        limit = truncation_phrase(group.example_reason) or "keeps a fixed maximum"
        text = (
            f"{group.count} evidence references were left out of the exported record because "
            f"it {limit}."
        )
    elif group.family == "resolution_horizon_exhausted":
        text = "The reasoning engine stopped at its work limit before settling the incident."
    elif group.family == "endpoint_absent":
        text = (
            f"{group.count} links in PocketSec's causal record were dropped because one end "
            "was outside this incident's record."
        )
    else:
        text = f"{group.count} record entries were cut ({group.example_reason})."
    return say(text, group)


def what_unknown(facts: AlertFacts, expanded: bool) -> Built:
    out: list[Sentence] = []
    programs = [u for u in facts.unknowns if u.fact_id.startswith("unk:program:")]
    for unknown in facts.unknowns:
        if unknown not in programs:
            out.extend(_unknown_line(facts, unknown))
    if programs:
        actors = join_phrases(u.fact_id.split(":")[-1] for u in programs)
        out.append(
            say(
                "The program each of these processes ran is unknown, because no program "
                f"start by them was observed: {actors}.",
                *programs,
            )
        )
    out.extend(_truncation_line(group) for group in facts.truncations)
    if facts.ledger.dropped > 0:
        ledger = facts.ledger
        out.append(
            say(
                f"Only {ledger.kept} of the {ledger.total} recorded events were kept for this "
                "alert; the rest are not shown.",
                ledger,
            )
        )
    out.extend(
        say(
            f"Observing {gap.signal} would help tell the explanations apart: {gap.why_it_matters}.",
            gap,
        )
        for gap in facts.gaps
    )
    return out, ["NO_CLOCK"]


# --- FALSE_ALARM / EVIDENCE ------------------------------------------------------------


def false_alarm(facts: AlertFacts, expanded: bool) -> Built:
    a = facts.assessment
    if a.verdict in NON_COMMITTAL:
        out = [
            say(
                f"PocketSec reached no conclusion either way: its recorded verdict is "
                f"{a.verdict}, which means the evidence did not decide it; it is not a "
                "benign finding.",
                a,
            )
        ]
    else:
        out = [say(f"PocketSec's recorded verdict is {a.verdict}.", a)]
    out.extend(_hypotheses(facts, 4))
    out.extend(_identifiability_unknown(facts))
    for event, meaning in _top_changes(facts, 1):
        out.extend(part for part in (_step(event), _raise(meaning)) if part is not None)
    return out, ["FALSE_ALARM_RULE", *_novel_note(facts)]


def evidence(facts: AlertFacts, expanded: bool) -> Built:
    a = facts.assessment
    out = [say(f"The exported record lists {a.lineage_rows} evidence references.", a)]
    out.extend(_cited_observations(facts, 8 if expanded else 4))
    for event, _meaning in _top_changes(facts, 6 if expanded else 3):
        out.append(
            say(
                f"Step {event.sequence} comes from {event.store} record {event.locator} "
                f"(digest {short_digest(event.digests[0])}).",
                event,
            )
        )
    out.extend(_truncation_line(g) for g in facts.truncations if g.family == EVIDENCE_CAP_FAMILY)
    return out, ["RAW_BYTES", "RECORD_NUMBERS"]


Builder = Callable[[AlertFacts, bool], Built]


def _static(*notes: str) -> Builder:
    def build(facts: AlertFacts, expanded: bool) -> Built:
        return [], list(notes)

    return build


#: Keyed by ``Intent`` value. Total over the intents: a new intent without a builder
#: fails ``answers.answer`` loudly rather than answering with nothing.
BUILDERS: Mapping[str, Builder] = {
    "WHY_FLAGGED": why_flagged,
    "WHAT_HAPPENED": what_happened,
    "WHICH_PROCESS": which_process,
    "HOW_SURE": how_sure,
    "WHAT_UNKNOWN": what_unknown,
    "WHAT_ACTION": what_action,
    "HOW_TO_UNDO": how_to_undo,
    "FALSE_ALARM": false_alarm,
    "EVIDENCE": evidence,
    "ACTION_REQUEST": action_request,
    "ADVICE": advice,
    "HELP": _static("HELP_ASK", "HELP_COMMANDS", "HELP_TAGS"),
    # The unmatched-question reply. A detected injection gets the stricter
    # "OUT_OF_SCOPE" note instead (``answers.answer``): a person who typed "thanks"
    # should not be answered as if they had tried to rewrite the record.
    "OUT_OF_SCOPE": _static("NO_MATCH", "HELP_ASK"),
}
