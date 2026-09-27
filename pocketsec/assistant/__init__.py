"""PocketSec's alert explainer: answers questions about an alert with no language model.

What this package is FOR: letting a person ask "why was this flagged?", "how sure are
you?" or "can I undo it?" about a PocketSec alert and get plain-English answers built
only from facts the alert carries. It has two parts and no model:

1. a deterministic intent classifier (``intents.py``, word lists in ``lexicon.py``);
2. sentence templates (``templates.py``, ``response_templates.py``) filled from typed
   facts (``facts.py``), each
   sentence tagged with its epistemic kind and the fact ids it cites, and checked by
   a grounding guard (``guard.py``) before it is shown.

It consumes the stages through their public wire forms only — Stage 4's
``CBFResolutionV1``, Stage 1's transitions (captured in ``capture.py``), and Stage 5's
``ResponseRecordV1`` read as plain rows — and it carries no authority (ADR-0003): it
imports nothing from Stage 5, and there is no path from a question to anything that
acts. See ``docs/assistant.md``.

This ``__init__`` re-exports the public surface. Unlike a stage package (whose
``__init__`` stays empty by the integration plan's rule), the assistant is one tool
with one entry surface, and a caller should not need to know its module layout.
"""

from __future__ import annotations

from pocketsec.assistant.answers import Answer, answer
from pocketsec.assistant.capture import handoff_from_run
from pocketsec.assistant.facts import AlertFacts, FactKind
from pocketsec.assistant.guard import check_answer, verify_rendered
from pocketsec.assistant.handoff import HANDOFF_SCHEMA, HandoffError, facts_from_handoff
from pocketsec.assistant.intents import Classification, Intent, classify
from pocketsec.assistant.session import Session

__all__ = [
    "HANDOFF_SCHEMA",
    "AlertFacts",
    "Answer",
    "Classification",
    "FactKind",
    "HandoffError",
    "Intent",
    "Session",
    "answer",
    "check_answer",
    "classify",
    "facts_from_handoff",
    "handoff_from_run",
    "verify_rendered",
]
