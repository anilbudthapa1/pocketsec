"""The pieces every sentence-builder shares: ``say`` and the common unknown sentences.

What this module is FOR: ``templates.py`` (what the record says about the host) and
``response_templates.py`` (what PocketSec's response stage recorded) both build
sentences the same way. Keeping ``say`` here means there is one place that decides a
sentence's epistemic kind — the weakest kind among the facts it cites — and no
builder can choose a stronger tag by hand.
"""

from __future__ import annotations

from pocketsec.assistant.facts import AlertFacts, Fact, Unknown
from pocketsec.assistant.guard import weakest_kind
from pocketsec.assistant.wording import Sentence

__all__ = [
    "NON_COMMITTAL",
    "REACHED_HOST",
    "Built",
    "no_response",
    "say",
    "short_digest",
    "unknown_fact",
]

Built = tuple[list[Sentence], list[str]]

#: Verdicts that commit to nothing. Stage 0's non-committal set, written out so the
#: explainer never reads UNKNOWN as benign.
NON_COMMITTAL = frozenset({"UNKNOWN", "UNIDENTIFIABLE", "INSUFFICIENT_EVIDENCE"})
#: Receipt outcomes whose operator actually touched the (simulated) host. Every other
#: outcome was stopped first, and must never be narrated as "it ran".
REACHED_HOST = frozenset(
    {"COMMITTED_VERIFIED", "COMMITTED_UNVERIFIED", "ROLLED_BACK", "ROLLBACK_FAILED"}
)


def say(text: str, *facts: Fact) -> Sentence:
    return Sentence(text, weakest_kind(f.kind for f in facts), tuple(f.fact_id for f in facts))


def short_digest(digest: str) -> str:
    return digest[:19] + "..."


def unknown_fact(facts: AlertFacts, fact_id: str) -> Unknown | None:
    return next((u for u in facts.unknowns if u.fact_id == fact_id), None)


def no_response(facts: AlertFacts, subject: str) -> list[Sentence]:
    """``Whether <subject> is unknown``: said when no response record is attached."""
    missing = unknown_fact(facts, "unk:response")
    if missing is None:
        return []
    return [
        say(
            f"Whether {subject} is unknown to me: {missing.text}, so nothing about a response "
            "is recorded here.",
            missing,
        )
    ]
