"""A bounded conversation about a small set of alerts.

What this module is FOR: holding the state a chat needs and nothing more — the alerts
on offer, which one is open, and a short history so a follow-up ("tell me more",
"what about alert 2?") can reuse the previous question. The history is a
``deque(maxlen=MAX_HISTORY)``: a long session cannot grow memory.

What a session can never do: change a fact. ``AlertFacts`` are frozen and the session
only ever *reads* them; no question text is stored, only the intent it was classified
as and the alert it concerned. Alert numbers are minted here (1, 2, 3 in load order)
for convenience, and are never presented as evidence: an answer's sources are always
the alert's own facts.

Switching alerts is never silent: a question that names another alert ("why was
alert 2 flagged?") opens it and says so in a note, the way ``/open`` does. A bare
"#2" is not an alert reference (see ``intents``), so a question about step #2 stays
on the open alert.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass, replace

from pocketsec.assistant.answers import Answer, answer, clarification, notice
from pocketsec.assistant.facts import AlertFacts
from pocketsec.assistant.intents import (
    MAX_QUESTION_CHARS,
    MIN_SCORE,
    Classification,
    Intent,
    classify,
)
from pocketsec.assistant.wording import NOTES

__all__ = ["MAX_ALERTS", "MAX_HISTORY", "Session", "Turn"]

MAX_HISTORY = 32
#: A chat over more alerts than this is a triage queue, which is a different tool.
MAX_ALERTS = 256
#: Alert numbers are small. A longer digit string is not a number worth converting
#: (``int()`` refuses past 4300 digits, and raises on non-ASCII digits like "²").
_MAX_REF_DIGITS = 6


@dataclass(frozen=True, slots=True)
class Turn:
    """What a session remembers of one question: never the text, only its meaning."""

    intent: Intent
    alert_id: str | None
    expanded: bool


class Session:
    def __init__(self, alerts: Sequence[AlertFacts], *, max_history: int = MAX_HISTORY) -> None:
        self.alerts: tuple[AlertFacts, ...] = tuple(alerts[:MAX_ALERTS])
        self.current: AlertFacts | None = self.alerts[0] if self.alerts else None
        self.history: deque[Turn] = deque(maxlen=max_history)

    def short_id(self, facts: AlertFacts | None) -> int | None:
        if facts is None:
            return None
        return next(
            (i + 1 for i, a in enumerate(self.alerts) if a.alert_id == facts.alert_id), None
        )

    def find(self, ref: str) -> AlertFacts | None:
        """An alert by its session number (``2``) or its full incident id."""
        text = ref.strip().lstrip("#").lower()
        if text.isascii() and text.isdigit() and len(text) <= _MAX_REF_DIGITS:
            index = int(text) - 1
            return self.alerts[index] if 0 <= index < len(self.alerts) else None
        return next((a for a in self.alerts if a.alert_id.lower() == text), None)

    def open(self, ref: str) -> AlertFacts | None:
        found = self.find(ref)
        if found is not None:
            self.current = found
        return found

    def _intent_for(self, result: Classification, switched: bool) -> tuple[Intent | None, bool]:
        """The intent to answer and whether to expand, after follow-up handling.

        A question that only names an alert ("what about alert 2", "and alert 3?")
        repeats the previous question for that alert. A follow-up on the same alert
        ("tell me more") expands the previous answer.
        """
        last = self.history[-1] if self.history else None
        bare_reference = result.score < MIN_SCORE and not result.needs_clarification
        if result.alert_ref is not None and (bare_reference or (result.follow_up and switched)):
            return (last.intent if last else Intent.WHY_FLAGGED), False
        if result.follow_up and last is not None:
            return last.intent, True
        if result.needs_clarification:
            return None, False
        return result.intent, False

    def _nothing_more(self, reply: Answer, intent: Intent) -> Answer:
        """Say so when "tell me more" would only repeat what was already shown."""
        assert self.current is not None
        base = answer(intent, self.current, expanded=False)
        last = self.history[-1] if self.history else None
        if reply.sentences != base.sentences and not (last and last.expanded):
            return reply
        return replace(reply, notes=(*reply.notes, NOTES["NOTHING_MORE"]))

    def ask(self, question: str) -> Answer:
        """Answer one question. Never raises on user input; never echoes it."""
        result = classify(question[:MAX_QUESTION_CHARS])
        switched = False
        if result.alert_ref is not None:
            found = self.find(result.alert_ref)
            if found is None:
                return notice("UNKNOWN_ALERT", result.intent, self.current)
            switched = found is not self.current
            self.open(result.alert_ref)
        if self.current is None:
            return notice("NO_ALERT", result.intent, None)
        intent, expanded = self._intent_for(result, switched)
        if intent is None:
            reply = clarification(result, self.current)
        else:
            reply = answer(intent, self.current, expanded=expanded, classification=result)
            if expanded:
                reply = self._nothing_more(reply, intent)
            self.history.append(Turn(intent, self.current.alert_id, expanded))
        if switched:
            reply = replace(reply, notes=(*reply.notes, NOTES["SWITCHED_ALERT"]))
        return reply
