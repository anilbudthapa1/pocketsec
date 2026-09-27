"""The explainer's closed vocabulary: provenance tags, fixed notes, hedges, sentences.

What this module is FOR: everything the explainer can say that is *not* filled from a
fact lives here, as constants. There are only two kinds of line in an answer:

* a **sentence** — built from facts, carrying one ``FactKind`` and the ids of the facts
  it cites, rendered with its provenance tag, e.g. ``(observed)``;
* a **note** — a fixed string from ``NOTES``, rendered as ``Note: ...``. Notes say
  how to read an answer or what the assistant cannot do. They never state a fact
  about an alert, which is why they may carry no tag, and why the rendered-text
  checker accepts a note only if it is one of these exact strings.

No note contains user text. The explainer never repeats what a user typed.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from pocketsec.assistant.facts import FactKind

__all__ = [
    "EXAMPLES",
    "HEDGE_WORDS",
    "NOTES",
    "NOTE_TEXTS",
    "TAGS",
    "TAG_TO_KIND",
    "Sentence",
]

#: The tag each kind of sentence ends with. Plain English, because the reader is not
#: assumed to know what OBS or INF means.
TAGS: Mapping[FactKind, str] = MappingProxyType(
    {
        FactKind.OBS: "observed",
        FactKind.DER: "derived by fixed rules from observed events",
        FactKind.INF: "inferred, not certain",
        FactKind.CF: "counterfactual, not observed",
        FactKind.EXT: "external knowledge, not observed here",
        FactKind.UNK: "unknown",
        FactKind.REC: "as recorded by PocketSec",
    }
)
TAG_TO_KIND: Mapping[str, FactKind] = MappingProxyType({v: k for k, v in TAGS.items()})

#: Words that make a sentence a possibility rather than a finding. An INF sentence
#: must carry one (Stage 4's ``HEDGE_MARKERS`` makes the same rule for claim text).
HEDGE_WORDS: tuple[str, ...] = (
    "possible",
    "possibly",
    "may ",
    "might",
    "could be",
    "not certain",
    "not confirmed",
    "candidate",
)

NOTES: Mapping[str, str] = MappingProxyType(
    {
        "RANKING": (
            "The events above are ranked by how much PocketSec's state rules say each one "
            "changed the host's security state. The reasoning engine itself did not single "
            "them out as its reasons."
        ),
        "NO_EVENTS": (
            "I only have the exported record for this alert, not the underlying events, so "
            "I can't describe the activity itself."
        ),
        "NO_CLOCK": "PocketSec's event record keeps the order of events, not clock times.",
        "MORE": (
            "These are the most significant events first. Ask 'tell me more' to see more of "
            "them."
        ),
        "MORE_CAPPED": "The event record holds more of these events than I show at once.",
        "NOTHING_MORE": "That is all I can show for this question.",
        "RECORD_NUMBERS": (
            "Sensor record names (such as ebpf-00047) are each sensor's own numbering. They "
            "do not line up with step numbers."
        ),
        "NOVEL": (
            "'Unresolved novel mechanism' is PocketSec's name for activity that matches none "
            "of the mechanisms it knows. It is a label for the unfamiliar, not a finding of "
            "harm."
        ),
        "PROCESS_NAMES": (
            "PocketSec identifies a process by its lineage (process id and start time), "
            "not by name. Role words like 'web server' are not recorded."
        ),
        "NO_AUTHORITY": (
            "I can only explain what PocketSec recorded. I cannot run commands, change the "
            "host, or approve anything, and nothing you type here is ever run."
        ),
        "WHERE_OPERATORS_ACT": (
            "Changes to a host are made only by PocketSec's response stage, behind its "
            "SENTINEL safety checks, or by a human operator working through that stage."
        ),
        "UNDO_AUTHORITY": (
            "I can't undo anything myself. A human operator performs reversals through "
            "PocketSec's response stage."
        ),
        "FALSE_ALARM_RULE": (
            "I can't declare an alert a false alarm. The recorded evidence and a human "
            "analyst settle that."
        ),
        "NO_FACTS": "I don't have evidence about that for this alert.",
        "OUT_OF_SCOPE": (
            "I only answer questions about the facts recorded for the open alert. I can't "
            "take new instructions, add facts, or change what the record says."
        ),
        "NO_MATCH": "I didn't catch that. I answer questions about the open alert.",
        "NO_ADVICE": (
            "I can't recommend what to do. I can tell you what PocketSec recorded and what it "
            "asked for; deciding what to do belongs to a human analyst."
        ),
        "SWITCHED_ALERT": (
            "Your question named another alert, so that alert is now open (shown above)."
        ),
        "CLARIFY": "I'm not sure which question you mean. Did you mean one of these?",
        "CLARIFY_ONE": "I'm not sure what you mean. Did you mean this?",
        "RAW_BYTES": (
            "Evidence is referenced by SHA-256 digest. The raw sensor bytes are not kept, "
            "so a digest cannot be re-checked here."
        ),
        "WITHHELD": ("Some sentences were withheld because they failed the grounding check."),
        "NO_ALERT": ("No alert is open. Use /alerts to list them and /open <number> to pick one."),
        "UNKNOWN_ALERT": "There is no alert with that number or id. Use /alerts to list them.",
        "HELP_ASK": (
            "You can ask: why was this flagged? what happened? which process? how sure are "
            "you? what don't you know? what was done? how do I undo it? is it a false "
            "alarm? show me the evidence."
        ),
        "HELP_COMMANDS": (
            "Commands: /alerts, /open <number or incident id>, /sources (full sources of the "
            "last answer), /help, /quit. You can also name an alert in a question, e.g. 'why "
            "was alert 2 flagged?'"
        ),
        "HELP_TAGS": (
            "Every sentence ends with where it came from: (observed), (derived by fixed "
            "rules from observed events), (inferred, not certain), (unknown), or (as "
            "recorded by PocketSec). The numbers in brackets point to the sources list."
        ),
        "SYNTHETIC": (
            "This alert is synthetic: it comes from PocketSec's lab corpus, not from real "
            "telemetry."
        ),
    }
)

#: One example question per intent, offered when a question is ambiguous. Keys are
#: ``Intent`` values; kept as strings so this module does not import the classifier.
EXAMPLES: Mapping[str, str] = MappingProxyType(
    {
        "WHY_FLAGGED": 'Try: "why was this flagged?"',
        "WHAT_HAPPENED": 'Try: "what happened?"',
        "WHICH_PROCESS": 'Try: "which process did this?"',
        "HOW_SURE": 'Try: "how sure are you?"',
        "WHAT_UNKNOWN": 'Try: "what don\'t you know?"',
        "WHAT_ACTION": 'Try: "what was done about it?"',
        "HOW_TO_UNDO": 'Try: "how do I undo it?"',
        "FALSE_ALARM": 'Try: "is this a false alarm?"',
        "EVIDENCE": 'Try: "show me the evidence"',
        "HELP": 'Try: "help"',
        "ADVICE": 'Try: "what should I do now?"',
        "OUT_OF_SCOPE": 'Try: "help"',
        "ACTION_REQUEST": 'Try: "what was done about it?"',
    }
)

#: Every string the checker will accept as a note line.
NOTE_TEXTS: frozenset[str] = frozenset(NOTES.values()) | frozenset(EXAMPLES.values())


@dataclass(frozen=True, slots=True)
class Sentence:
    """One factual sentence: its text, its epistemic kind, and the facts it cites."""

    text: str
    kind: FactKind
    fact_ids: tuple[str, ...]
