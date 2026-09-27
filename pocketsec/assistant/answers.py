"""Answers: the guarded, rendered result of one question about one alert.

What this module is FOR: turning an intent and an alert's facts into something a person
reads — and making sure nothing ungrounded reaches them. ``answer`` runs the intent's
template (``templates.py``), passes every sentence through the grounding guard
(``guard.py``), and *withholds* any sentence that fails, adding a note that it did.
The failure mode is a shorter answer, never an unsupported sentence.

Rendering is line-oriented so it can be checked by parsing (``guard.verify_rendered``):

    Alert 1 | s4-inc-0011-0006 | SYNTHETIC demo data
    Question type: WHY_FLAGGED (matched: why, flag)
    - <sentence> (observed) [1]
    - <sentence> (inferred, not certain) [2,3]
    Note: <a fixed catalogue string>
    Sources:
      [1] evt:7418187c4a2b (OBS)

By default the source list is brief: fact id and kind. ``full_sources=True`` (the
CLI's ``--sources`` and ``/sources``) adds each fact's claim id or record path and its
evidence digest; ``to_dict`` (``--json``) always carries them. A person reading an
answer needs to know where a sentence came from, not a 64-hex digest on every line.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pocketsec.assistant.facts import AlertFacts, Fact
from pocketsec.assistant.guard import check_sentence
from pocketsec.assistant.intents import Classification, Intent

#: Intents whose answer describes recorded actions. If the question used an action
#: verb in any role, the answer also says the assistant itself acts on nothing.
_ACTION_ANSWERS = frozenset({Intent.WHAT_ACTION, Intent.HOW_TO_UNDO, Intent.ADVICE})
from pocketsec.assistant.templates import BUILDERS
from pocketsec.assistant.wording import EXAMPLES, HEDGE_WORDS, NOTES, TAGS, Sentence

__all__ = [
    "HEDGE_WORDS",
    "NOTES",
    "Answer",
    "answer",
    "clarification",
    "notice",
]


@dataclass(frozen=True, slots=True)
class Answer:
    """One reply. ``alert`` is ``None`` only for replies that concern no alert."""

    alert: AlertFacts | None
    intent: Intent
    sentences: tuple[Sentence, ...]
    notes: tuple[str, ...]
    classification: Classification | None = None
    withheld: int = 0

    def cited_facts(self) -> tuple[Fact, ...]:
        """Every cited fact, in first-citation order, each once."""
        if self.alert is None:
            return ()
        order = dict.fromkeys(fid for s in self.sentences for fid in s.fact_ids)
        found = (self.alert.get(fid) for fid in order)
        return tuple(fact for fact in found if fact is not None)

    def _header(self, short_id: int | None) -> list[str]:
        if self.alert is None:
            lines = ["No alert open"]
        else:
            origin = "SYNTHETIC lab data" if self.alert.synthetic else "recorded data"
            number = "?" if short_id is None else str(short_id)
            lines = [f"Alert {number} | {self.alert.alert_id} | {origin}"]
        label = self.intent.value
        c = self.classification
        if c is not None and c.needs_clarification:
            noun = "candidate" if len(c.alternatives) == 1 else "candidates"
            label = f"unclear ({noun}: " + ", ".join(i.value for i in c.alternatives) + ")"
        elif c is not None and c.matched:
            label += " (matched: " + ", ".join(c.matched) + ")"
        return [*lines, f"Question type: {label}"]

    def render(self, *, short_id: int | None, full_sources: bool = False) -> str:
        cited = self.cited_facts()
        number = {fact.fact_id: index + 1 for index, fact in enumerate(cited)}
        lines = self._header(short_id)
        for sentence in self.sentences:
            refs = ",".join(str(number[fid]) for fid in sentence.fact_ids)
            lines.append(f"- {sentence.text} ({TAGS[sentence.kind]}) [{refs}]")
        lines.extend(f"Note: {note}" for note in self.notes)
        if cited:
            lines.append("Sources:")
            lines.extend(
                f"  [{number[f.fact_id]}] {f.fact_id} ({f.kind.value})"
                + (f" {_source_label(f)}" if full_sources else "")
                for f in cited
            )
        return "\n".join(lines)

    def to_dict(self, *, short_id: int | None) -> dict[str, Any]:
        c = self.classification
        return {
            "alert_id": None if self.alert is None else self.alert.alert_id,
            "short_id": short_id,
            "synthetic": None if self.alert is None else self.alert.synthetic,
            "record_provenance": None if self.alert is None else self.alert.provenance,
            "intent": self.intent.value,
            "needs_clarification": bool(c and c.needs_clarification),
            "alternatives": [] if c is None else [i.value for i in c.alternatives],
            "matched": [] if c is None else list(c.matched),
            "sentences": [
                {
                    "text": s.text,
                    "kind": s.kind.value,
                    "tag": TAGS[s.kind],
                    "fact_ids": list(s.fact_ids),
                }
                for s in self.sentences
            ],
            "notes": list(self.notes),
            "provenance": [
                {
                    "fact_id": f.fact_id,
                    "kind": f.kind.value,
                    "source": f.source,
                    "digests": list(f.digests),
                }
                for f in self.cited_facts()
            ],
            "withheld": self.withheld,
        }


def _source_label(fact: Fact) -> str:
    if fact.digests and fact.digests[0] != fact.source:
        return f"{fact.source} {fact.digests[0]}"
    return fact.source


def answer(
    intent: Intent,
    facts: AlertFacts,
    *,
    expanded: bool = False,
    classification: Classification | None = None,
) -> Answer:
    """Build, guard and return the answer to ``intent`` for one alert."""
    drafted, note_keys = BUILDERS[intent.value](facts, expanded)
    kept = tuple(s for s in drafted if not check_sentence(s, facts))
    withheld = len(drafted) - len(kept)
    notes = [NOTES[key] for key in _note_keys(intent, note_keys, classification)]
    if withheld:
        notes.append(NOTES["WITHHELD"])
    if not kept and not notes:
        notes.append(NOTES["NO_FACTS"])
    return Answer(
        alert=facts,
        intent=intent,
        sentences=kept,
        notes=tuple(dict.fromkeys(notes)),
        classification=classification,
        withheld=withheld,
    )


def _note_keys(
    intent: Intent, note_keys: list[str], classification: Classification | None
) -> list[str]:
    """The builder's notes, adjusted for how the question was asked."""
    if classification is None:
        return note_keys
    if intent is Intent.OUT_OF_SCOPE and "injection" in classification.matched:
        return ["OUT_OF_SCOPE"]
    if classification.mentions_action and intent in _ACTION_ANSWERS:
        return ["NO_AUTHORITY", *note_keys]
    return note_keys


def clarification(classification: Classification, facts: AlertFacts | None) -> Answer:
    """An ambiguous question: no facts, just the candidate questions to choose from."""
    lead = "CLARIFY_ONE" if len(classification.alternatives) == 1 else "CLARIFY"
    notes = [NOTES[lead], *(EXAMPLES[i.value] for i in classification.alternatives)]
    return Answer(
        alert=facts,
        intent=classification.intent,
        sentences=(),
        notes=tuple(dict.fromkeys(notes)),
        classification=classification,
    )


def notice(note_key: str, intent: Intent, facts: AlertFacts | None) -> Answer:
    """A reply that is only a fixed note (no alert open, unknown alert number)."""
    return Answer(alert=facts, intent=intent, sentences=(), notes=(NOTES[note_key],))
