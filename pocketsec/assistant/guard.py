"""The grounding guard: every sentence must be supported by the facts it cites.

What this module is FOR: a template can drift. A sentence that quotes a number the
facts never held, names a security dimension the evidence never raised, drops the
hedge from an inference, or turns "not observed" into "did not happen" is exactly the
hallucination this explainer exists to avoid. This module checks for all of them,
mechanically, on every sentence before it is shown (``answers.py`` withholds any
sentence that fails), and again on the *rendered text* (``verify_rendered``), which is
what a person actually reads: ``cli.py`` runs it on every text answer just before
printing and prints a fixed refusal note instead if it finds a problem.

It is Stage 4's verbalizer guard (``stage4/claims/verbalizer.py``) extended rather than
reused as-is: that guard checks a sentence against one compiled claim's text, which
would reject a correct sentence quoting a resolved transition (a path, an address, a
change score). Here the supported text is the union of the cited facts' own values.
It keeps the forbidden amplification verbs and the introduced security terms, and
tightens three rules that a review showed were too loose:

* **Numbers are whole tokens.** ``198.51.100.9`` is not supported by
  ``198.51.100.91``, and ``5`` is not supported by ``65``. A shortened decimal is
  accepted only as ``about <prefix>`` (``quote_number``'s own form).
* **Rule (d) is per clause, with a narrow exemption.** Stage 4's marker list holds
  everyday words ("data", "recorded", "sensor"), so "the recorded data shows no file
  was modified" passed it. Here every negated clause of a sentence that cites an
  unknown — or that mentions an unknown's subject — must itself be a coverage
  statement ("unknown", "not observed", "no evidence that", "no X was observed").
* **Events are checked by field.** A step number, a process id, the relation verb,
  a path and a rank word ("highest") must each match a fact the sentence cites.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Protocol

from pocketsec.assistant.facts import (
    KIND_STRENGTH,
    AlertFacts,
    Event,
    EventMeaning,
    Fact,
    FactKind,
    Lineage,
)
from pocketsec.assistant.phrasing import RELATION_VERBS, relation_verb
from pocketsec.assistant.wording import HEDGE_WORDS, NOTE_TEXTS, TAG_TO_KIND, Sentence
from pocketsec.stage1.observation.policy import MANDATORY_SIGNALS
from pocketsec.stage1.state.security_state import DIMENSIONS
from pocketsec.stage4.claims.compiler import FORBIDDEN_AMPLIFICATIONS
from pocketsec.stage4.claims.verbalizer import NEGATION_CUES

__all__ = [
    "CERTAINTY_WORDS",
    "COVERAGE_PATTERNS",
    "EXONERATION_PATTERNS",
    "FORBIDDEN_WORDS",
    "MAX_SENTENCE_CHARS",
    "check_answer",
    "check_sentence",
    "is_coverage_statement",
    "quote_number",
    "verify_rendered",
    "weakest_kind",
]

#: A sentence is a sentence; anything longer is a dump or a template bug.
MAX_SENTENCE_CHARS = 480

#: Stage 4's completed-compromise verbs plus the chat-register ones a user might expect.
#: Allowed only inside a hedged INF sentence whose cited fact itself carries the word.
FORBIDDEN_WORDS: frozenset[str] = FORBIDDEN_AMPLIFICATIONS | frozenset(
    {"hacked", "attacker", "malware", "infected", "stole", "steal", "exfiltration"}
)

#: Sentences that would turn a hole in the record into an exoneration.
EXONERATION_PATTERNS: tuple[str, ...] = (
    r"\bdid ?n[o']?t (happen|occur)",
    r"\bnever (happened|occurred)",
    r"\bnothing (happened|occurred)",
    r"\bthere (was|were) no\b",
    r"\bno \w+ (happened|occurred|took place)",
    r"\b(it|this) (is|was) (a |just a )?false (alarm|positive)",
)

#: Words that state an inference as settled. An INF sentence may carry none of them,
#: whatever hedge it also carries ("possible explanation ... was ruled out").
CERTAINTY_WORDS: tuple[str, ...] = (
    "determined",
    "ruled out",
    "definitely",
    "certainly",
    "proven",
    "established",
    "the cause",
    "for sure",
    "no doubt",
    "confirmed that",
)

#: What makes a negated clause a statement about knowledge or coverage rather than
#: about the host. Deliberately narrow: each is a phrase whose subject is what is
#: known ("is unknown", "no X was observed", "no evidence that"), never a bare word
#: like "data" or "sensor" that any sentence can carry.
COVERAGE_PATTERNS: tuple[str, ...] = (
    r"\bunknown\b",
    r"\bnot (?:yet )?(?:been )?(?:observed|observable|recorded)\b",
    r"\bunobserv",
    r"\bno evidence\b",
    r"\bknows? of no\b",
    r"\b(?:no|nothing)\b(?:\s+[\w'-]+){0,5}?\s+(?:was|were|is|are)\s+"
    r"(?:observed|recorded|attached|seen)\b",
    r"\bnot a (?:statement|benign finding|finding|real machine)\b",
    r"\bnot (?:certain|confirmed)\b",
)

#: Numbers as whole tokens: ``198.51.100.91`` is one token, ``8443`` another.
_NUMBERS = re.compile(r"\d+(?:\.\d+)*")
_ABOUT = re.compile(r"about (\d+\.\d+)")
#: A quoted digest (full or shortened). Its digits are an identifier, not a quantity,
#: and are checked by the source list instead of by the number rule.
_HEX_REF = re.compile(r"sha256:[0-9a-f]+")
_WORDS = re.compile(r"[a-z][a-z0-9_]{3,}")
_CLAUSES = re.compile(r"[;:,()]|\. |\b(?:and|but|so|while|whereas|because|although|yet)\b")
_STEP = re.compile(r"\bstep (\d+)")
_PROCESS = re.compile(r"\bprocess (\d+)\b")
_PATH = re.compile(r"(?<![\w:/])/[\w.\-/]*[\w\-/]")
_RANK = re.compile(r"number (\d+) of the (\d+)")
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_SECURITY_TERMS = tuple(sorted(set(DIMENSIONS) | set(MANDATORY_SIGNALS)))
#: Words too common to tie a sentence to one unknown. The derived unknowns ("no program
#: run was observed for process N") would otherwise make every sentence that mentions a
#: process and a negation look like it resolves them.
_UNKNOWN_STOPWORDS = frozenset(
    {
        "that",
        "this",
        "with",
        "from",
        "were",
        "have",
        "been",
        "into",
        "which",
        "there",
        "about",
        "could",
        "would",
        "what",
        "when",
        "than",
        "then",
        "observable",
        "observed",
        "evidence",
        "unknown",
        "stage",
        "response",
        "record",
        "attached",
        "alert",
        "process",
        "program",
        "visibility",
        "pocketsec",
        "whether",
        "under",
        "change",
        "recorded",
    }
)


class AnswerLike(Protocol):
    """The slice of ``answers.Answer`` the guard reads (a protocol, to avoid a cycle)."""

    @property
    def sentences(self) -> tuple[Sentence, ...]: ...

    @property
    def notes(self) -> tuple[str, ...]: ...


def quote_number(value: float) -> str:
    """A recorded number as text: exact when short, otherwise truncated with "about".

    Truncated, never rounded, so a quoted figure can only understate a value — a
    confidence of 0.6666... is "about 0.6666", never "0.67". 0.0 stays "0.0".
    """
    text = repr(float(value))
    if len(text) <= 6 or "e" in text or "." not in text:
        return text
    whole, _, fraction = text.partition(".")
    return f"about {whole}.{fraction[:4]}"


def weakest_kind(kinds: Iterable[FactKind]) -> FactKind:
    """The least certain kind among ``kinds``: the tag a combined sentence must carry."""
    return max(kinds, key=KIND_STRENGTH.index)


def _unknown_words(facts: AlertFacts) -> dict[str, frozenset[str]]:
    out: dict[str, frozenset[str]] = {}
    for fact in facts.unknowns:
        words = set(_WORDS.findall(f"{fact.signal or ''} {fact.text}".lower()))
        out[fact.fact_id] = frozenset(words - _UNKNOWN_STOPWORDS)
    return out


def _number_violations(lowered: str, supported: str) -> list[str]:
    supported_numbers = set(_NUMBERS.findall(_HEX_REF.sub(" ", supported)))
    shortened = set(_ABOUT.findall(lowered))
    found: list[str] = []
    for number in _NUMBERS.findall(_HEX_REF.sub(" ", lowered)):
        if number in supported_numbers:
            continue
        if number in shortened and any(s.startswith(number) for s in supported_numbers):
            continue
        found.append(f"invented_number:{number}")
    return found


def _content_violations(sentence: Sentence, supported: str) -> list[str]:
    lowered = sentence.text.lower()
    found: list[str] = []
    for word in sorted(FORBIDDEN_WORDS):
        if re.search(rf"\b{word}\b", lowered) and not (
            word in supported and sentence.kind is FactKind.INF
        ):
            found.append(f"forbidden_word:{word}")
    found.extend(_number_violations(lowered, supported))
    found.extend(
        f"introduced_term:{term}"
        for term in _SECURITY_TERMS
        if term in lowered and term not in supported
    )
    found.extend(
        f"introduced_path:{path}"
        for path in _PATH.findall(lowered)
        if path.rstrip(".") not in supported
    )
    found.extend("exoneration" for p in EXONERATION_PATTERNS if re.search(p, lowered))
    return found


def _clauses(lowered: str) -> list[str]:
    return [part.strip() for part in _CLAUSES.split(lowered) if part and part.strip()]


def is_coverage_statement(clause: str) -> bool:
    """True when ``clause`` talks about what is known, not about what the host did."""
    return any(re.search(pattern, clause) for pattern in COVERAGE_PATTERNS)


def _uncovered_negations(lowered: str) -> list[str]:
    """Negated clauses that are not coverage statements: each one reads as a denial."""
    return [
        clause
        for clause in _clauses(lowered)
        if any(cue in f"{clause} " for cue in NEGATION_CUES) and not is_coverage_statement(clause)
    ]


def _epistemic_violations(sentence: Sentence, facts: AlertFacts, cited: list[Fact]) -> list[str]:
    lowered = sentence.text.lower()
    found: list[str] = []
    cites_inference = any(f.kind is FactKind.INF for f in cited)
    if sentence.kind is FactKind.INF and not any(h in lowered for h in HEDGE_WORDS):
        found.append("unhedged_inference")
    if cites_inference or sentence.kind is FactKind.INF:
        found.extend(f"certain_inference:{w}" for w in CERTAINTY_WORDS if w in lowered)
    if sentence.kind is FactKind.UNK and not is_coverage_statement(lowered):
        found.append("unmarked_unknown")
    denials = _uncovered_negations(lowered)
    if not denials:
        return found
    cited_unknowns = [f.fact_id for f in cited if f.kind is FactKind.UNK]
    found.extend(f"negated_unknown:{fact_id}" for fact_id in cited_unknowns)
    for fact_id, words in _unknown_words(facts).items():
        if fact_id in cited_unknowns:
            continue
        if any(re.search(rf"\b{re.escape(w)}\b", clause) for clause in denials for w in words):
            found.append(f"negated_unknown:{fact_id}")
    return found


def _event_violations(sentence: Sentence, cited: list[Fact]) -> list[str]:
    """Step numbers, process ids, verbs and rank words must match the cited facts."""
    lowered = sentence.text.lower()
    found: list[str] = []
    sequences = {f.sequence for f in cited if isinstance(f, (Event, EventMeaning))}
    found.extend(
        f"wrong_step:{m.group(1)}"
        for m in _STEP.finditer(lowered)
        if int(m.group(1)) not in sequences
    )
    actors = {f.actor for f in cited if isinstance(f, (Event, Lineage))}
    if actors:
        found.extend(
            f"wrong_actor:{m.group(1)}"
            for m in _PROCESS.finditer(lowered)
            if m.group(1) not in actors
        )
    events = [f for f in cited if isinstance(f, Event)]
    if events:
        own = {relation_verb(e.relation) for e in events}
        found.extend(
            f"wrong_verb:{verb}"
            for verb in sorted(RELATION_VERBS - own)
            if re.search(rf"\b{verb}\b", lowered)
        )
    found.extend(_rank_violations(lowered, [f for f in cited if isinstance(f, Lineage)]))
    return found


def _rank_violations(lowered: str, lineages: list[Lineage]) -> list[str]:
    found: list[str] = []
    if "highest" in lowered and not any(x.rank == 1 for x in lineages):
        found.append("wrong_rank:highest")
    if "lowest" in lowered and not any(x.rank == x.of for x in lineages):
        found.append("wrong_rank:lowest")
    for match in _RANK.finditer(lowered):
        pair = (int(match.group(1)), int(match.group(2)))
        if not any((x.rank, x.of) == pair for x in lineages):
            found.append(f"wrong_rank:{pair[0]}")
    return found


def check_sentence(sentence: Sentence, facts: AlertFacts) -> tuple[str, ...]:
    """Every reason ``sentence`` may not be shown for this alert; empty means it may."""
    if not sentence.fact_ids:
        return ("unsourced",)
    cited: list[Fact] = []
    for fact_id in sentence.fact_ids:
        fact = facts.get(fact_id)
        if fact is None:
            return (f"unknown_fact:{fact_id}",)
        cited.append(fact)
    found: list[str] = []
    if sentence.kind is not weakest_kind(f.kind for f in cited):
        found.append("kind_mismatch")
    if len(sentence.text) > MAX_SENTENCE_CHARS:
        found.append("too_long")
    if _CONTROL.search(sentence.text):
        found.append("control_characters")
    supported = " ".join(f.support_text() for f in cited)
    found.extend(_content_violations(sentence, supported))
    found.extend(_epistemic_violations(sentence, facts, cited))
    found.extend(_event_violations(sentence, cited))
    return tuple(found)


def check_answer(answer: AnswerLike, facts: AlertFacts) -> tuple[str, ...]:
    """All violations in one answer, each prefixed with its sentence index."""
    found = [
        f"{index}:{problem}"
        for index, sentence in enumerate(answer.sentences)
        for problem in check_sentence(sentence, facts)
    ]
    found.extend(f"note:{n[:40]}" for n in answer.notes if n not in NOTE_TEXTS)
    return tuple(found)


# --- the rendered-text checker -----------------------------------------------------------

_TAG_ALTERNATION = "|".join(re.escape(tag) for tag in TAG_TO_KIND)
_SENTENCE_LINE = re.compile(
    rf"^- (?P<body>.+) \((?P<tag>{_TAG_ALTERNATION})\) \[(?P<refs>\d+(?:,\d+)*)\]$"
)
_SOURCE_LINE = re.compile(r"^  \[(?P<n>\d+)\] (?P<fact>\S+) \((?P<kind>[A-Z]{2,3})\)(?: .*)?$")
_HEADER_PREFIXES = ("Alert ", "No alert open", "Question type: ")


def _parse(text: str) -> tuple[list[tuple[int, re.Match[str]]], dict[int, str], list[str]]:
    sentences: list[tuple[int, re.Match[str]]] = []
    sources: dict[int, str] = {}
    problems: list[str] = []
    in_sources = False
    for number, line in enumerate(text.splitlines()):
        if not line.strip():
            continue
        if line == "Sources:":
            in_sources = True
        elif in_sources and (match := _SOURCE_LINE.match(line)):
            sources[int(match.group("n"))] = f"{match.group('fact')} {match.group('kind')}"
        elif not in_sources and line.startswith("- "):
            match = _SENTENCE_LINE.match(line)
            if match is None:
                problems.append(f"line {number}: sentence without tag or sources")
            else:
                sentences.append((number, match))
        elif not in_sources and line.startswith("Note: "):
            if line[len("Note: ") :] not in NOTE_TEXTS:
                problems.append(f"line {number}: note not in the fixed catalogue")
        elif not in_sources and number < 2 and line.startswith(_HEADER_PREFIXES):
            continue
        else:
            problems.append(f"line {number}: stray line")
    return sentences, sources, problems


def verify_rendered(text: str, facts: AlertFacts) -> tuple[str, ...]:
    """Parse rendered answer text back to facts; return every problem found.

    A factual line must end ``(<tag>) [n,...]``; each ``n`` must be listed under
    ``Sources:`` as a fact of this alert with the kind it claims; the tag must be the
    weakest kind among the cited facts; and the sentence must pass ``check_sentence``.
    Note lines must be exact catalogue strings. Anything else is a stray line.
    """
    sentences, sources, problems = _parse(text)
    for number, match in sentences:
        refs = [int(n) for n in match.group("refs").split(",")]
        fact_ids: list[str] = []
        for ref in refs:
            if ref not in sources:
                problems.append(f"line {number}: cites [{ref}], which is not a listed source")
                continue
            fact_id, kind = sources[ref].split(" ")
            fact = facts.get(fact_id)
            if fact is None or fact.kind.value != kind:
                problems.append(f"line {number}: source [{ref}] is not a fact of this alert")
                continue
            fact_ids.append(fact_id)
        if len(fact_ids) != len(refs):
            continue
        rebuilt = Sentence(match.group("body"), TAG_TO_KIND[match.group("tag")], tuple(fact_ids))
        problems.extend(f"line {number}: {p}" for p in check_sentence(rebuilt, facts))
    return tuple(problems)
