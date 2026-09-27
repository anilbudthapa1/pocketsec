"""Deterministic intent classification for questions about an alert. No model, no guessing.

What this module is FOR: mapping "y did u flag this" to ``WHY_FLAGGED`` with plain
code — normalised tokens, a keyword/phrase lexicon with weights, casual-form and
contraction expansion, and typo tolerance of one edit on words of five or more
letters. The project's own rule applies: do not learn what plain code can do exactly.

Three safety properties are decided here, before any answer exists:

* **Requests to act are recognised as such.** An action verb is a request by default
  ("kill it", "go ahead and kill it", "you should suspend it", "approve it"); it is a
  question only after a question auxiliary ("did you kill it?", "was it blocked?"),
  and a request for advice after "should I" / "how do I" / "how to" (``ADVICE``).
  Shell metacharacters or command words force ``ACTION_REQUEST`` whatever else the
  text says. ``mentions_action`` records that any action or undo verb appeared, so the
  answer can restate that the assistant acts on nothing. The classifier only labels;
  there is no code path from a label to anything that acts.
* **Injection is recognised.** "ignore previous instructions", fake ``[OBS]`` claim
  markers and "you are now ..." are ``OUT_OF_SCOPE``: the explainer cannot take new
  instructions or new facts from a question.
* **Ambiguity is admitted.** A weak or tied score returns ``needs_clarification`` with
  at most three candidates. A guess is never presented as an answer.

An alert is named only as "alert N", "incident N", "same for N" or a full incident
id. A bare "#N" is not an alert reference: "what happened at step #2?" is about a
step. The reference is removed before scoring, so "what about alert 2" is a pure
reference (and a follow-up), not a weak WHY_FLAGGED question.

``Classification.matched`` holds lexicon words only (a fuzzy match is reported as
``~word``), never the user's own tokens, so nothing a user typed is ever echoed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from pocketsec.assistant.lexicon import (
    ACTION_VERBS,
    ADVICE_SUBJECTS,
    CASUAL_FORMS,
    COMMAND_WORDS,
    COMMON_WORDS,
    FOLLOW_UP_TRIGGERS,
    FOLLOW_UP_WORDS,
    INJECTION_PATTERNS,
    KEYWORDS,
    MODALS,
    NO_FUZZY_TARGETS,
    PHRASES,
    QUESTION_ACTION_VERBS,
    QUESTION_AUXILIARIES,
    SHELL_PATTERN,
    UNDO_VERBS,
)

__all__ = [
    "MARGIN",
    "MAX_QUESTION_CHARS",
    "MIN_SCORE",
    "Classification",
    "Intent",
    "classify",
    "edit_distance_at_most_one",
    "normalise",
]

#: Questions are cut here before anything else runs, so input size cannot become cost.
MAX_QUESTION_CHARS = 500
#: Below this, a question is too weak to answer and is sent back for clarification.
MIN_SCORE = 2.0
#: If the best two intents are closer than this, ask which one was meant.
MARGIN = 1.0
#: Typo tolerance applies only at or above this word length: "undi" is not "undo".
FUZZY_MIN_LENGTH = 5
_FORCED = 10.0
_REQUEST = 6.0
_INJECTION = 7.0
_QUESTION_ACTION = 4.0
_UNKNOWN_RULE = 4.0
#: Added to HOW_TO_UNDO when an undo verb appears in any form: "restore the process" is
#: about undoing, even though "process" is itself a WHICH_PROCESS word.
_UNDO_VERB = 2.0


class Intent(StrEnum):
    WHY_FLAGGED = "WHY_FLAGGED"
    WHAT_HAPPENED = "WHAT_HAPPENED"
    WHICH_PROCESS = "WHICH_PROCESS"
    HOW_SURE = "HOW_SURE"
    WHAT_UNKNOWN = "WHAT_UNKNOWN"
    WHAT_ACTION = "WHAT_ACTION"
    HOW_TO_UNDO = "HOW_TO_UNDO"
    FALSE_ALARM = "FALSE_ALARM"
    EVIDENCE = "EVIDENCE"
    HELP = "HELP"
    ADVICE = "ADVICE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    ACTION_REQUEST = "ACTION_REQUEST"


@dataclass(frozen=True, slots=True)
class Classification:
    intent: Intent
    score: float
    matched: tuple[str, ...]
    alternatives: tuple[Intent, ...]
    needs_clarification: bool
    follow_up: bool
    alert_ref: str | None
    #: True when an action or undo verb appeared in the question in any role. The
    #: answer then carries the no-authority note even when the question is read as
    #: "what was done?", so a reply listing receipts is never mistaken for the
    #: assistant having acted.
    mentions_action: bool = False


_CONTRACTIONS = (
    (re.compile(r"\bcan'?t\b"), "can not"),
    (re.compile(r"\bwon'?t\b"), "will not"),
    (re.compile(r"n't\b"), " not"),
    (re.compile(r"'re\b"), " are"),
    (re.compile(r"'ve\b"), " have"),
    (re.compile(r"'m\b"), " am"),
    (re.compile(r"'ll\b"), " will"),
    (re.compile(r"'d\b"), " would"),
    (re.compile(r"'s\b"), " is"),
)
_TOKEN_RE = re.compile(r"[a-z0-9]+(?:[._][a-z0-9]+)*")
_ALERT_REF_RE = re.compile(
    r"\b(?:alert|incident)\s*(?:number\s*|no\.?\s*)?#?\s*(\d{1,6})\b"
    r"|\bsame for\s*(?:alert\s*)?#?\s*(\d{1,6})\b"
    r"|\b([a-z0-9]+-inc-[a-z0-9-]+|inc-[a-z0-9-]+)\b"
)
#: Three or more of one letter: "whyyy" -> "why", "sooo" -> "so". English has no
#: word with a letter tripled, so collapsing loses nothing.
_REPEATS = re.compile(r"([a-z])\1{2,}")
_LEXICON: dict[str, tuple[Intent, float]] = {}
for _intent_name, _words in KEYWORDS.items():
    for _word, _weight in _words.items():
        _LEXICON[_word] = (Intent(_intent_name), _weight)
_FUZZY_TARGETS = tuple(
    sorted(w for w in _LEXICON if len(w) >= FUZZY_MIN_LENGTH and w not in NO_FUZZY_TARGETS)
)


def edit_distance_at_most_one(left: str, right: str) -> bool:
    """True when one substitution, insertion, deletion or adjacent swap turns left into right."""
    if left == right:
        return True
    if abs(len(left) - len(right)) > 1:
        return False
    if len(left) == len(right):
        diffs = [i for i, (a, b) in enumerate(zip(left, right, strict=True)) if a != b]
        if len(diffs) == 1:
            return True
        return (
            len(diffs) == 2
            and diffs[1] == diffs[0] + 1
            and left[diffs[0]] == right[diffs[1]]
            and left[diffs[1]] == right[diffs[0]]
        )
    short, long_ = (left, right) if len(left) < len(right) else (right, left)
    return any(long_[:index] + long_[index + 1 :] == short for index in range(len(long_)))


def normalise(text: str) -> list[str]:
    """Lower-case, expand contractions and casual forms, and split into tokens."""
    lowered = text[:MAX_QUESTION_CHARS].lower().replace("\u2019", "'")
    for pattern, replacement in _CONTRACTIONS:
        lowered = pattern.sub(replacement, lowered)
    tokens: list[str] = []
    for token in _TOKEN_RE.findall(_REPEATS.sub(r"\1", lowered)):
        tokens.extend(CASUAL_FORMS.get(token, token).split())
    return tokens


def _canonical(tokens: list[str]) -> tuple[list[str], list[str]]:
    """Replace near-miss tokens with their lexicon word; report them as ``~word``."""
    fixed: list[str] = []
    fuzzy: list[str] = []
    for token in tokens:
        # Action and undo verbs are exempt: "terminate" is one edit from "terminated",
        # and turning a request into a question about the past is exactly the wrong
        # correction. Common words are exempt because they are already spelt right.
        exempt = token in ACTION_VERBS or token in UNDO_VERBS or token in COMMON_WORDS
        if token in _LEXICON or exempt or len(token) < FUZZY_MIN_LENGTH:
            fixed.append(token)
            continue
        # A typo almost never changes the first letter; a different word usually does
        # ("locked" / "blocked", "course" / "source").
        match = next(
            (
                w
                for w in _FUZZY_TARGETS
                if w[0] == token[0] and edit_distance_at_most_one(token, w)
            ),
            None,
        )
        fixed.append(match or token)
        if match:
            fuzzy.append(match)
    return fixed, fuzzy


def _keyword_scores(tokens: list[str], fuzzy: list[str]) -> dict[Intent, list[tuple[str, float]]]:
    hits: dict[Intent, list[tuple[str, float]]] = {}
    for word in dict.fromkeys(tokens):
        if word in _LEXICON:
            intent, weight = _LEXICON[word]
            label = f"~{word}" if word in fuzzy else word
            hits.setdefault(intent, []).append((label, weight))
    joined = f" {' '.join(tokens)} "
    for intent_name, phrases in PHRASES.items():
        for phrase, weight in phrases.items():
            if f" {phrase} " in joined:
                hits.setdefault(Intent(intent_name), []).append((phrase, weight))
    negated = {"not", "no", "never"} & set(tokens)
    perceived = {"know", "see", "observe", "tell", "visible"} & set(tokens)
    if negated and perceived:
        hits.setdefault(Intent.WHAT_UNKNOWN, []).append(("not know", _UNKNOWN_RULE))
    return hits


def _verb_role(tokens: list[str], index: int) -> str:
    """How the action verb at ``index`` is used: "request", "question" or "advice".

    Request is the default. The unsafe mistake is reading a request as a question
    (the answer then lists what was done, as if in reply), so only an explicit
    question auxiliary or an advice form moves a verb out of it.
    """
    before = tokens[:index]
    if QUESTION_AUXILIARIES & set(before):
        return "question"
    if index >= 2 and tokens[index - 2] == "how" and tokens[index - 1] == "to":
        return "advice"
    pairs = zip(before, before[1:], strict=False)
    if any(modal in MODALS and subject in ADVICE_SUBJECTS for modal, subject in pairs):
        return "advice"
    return "request"


def _action_scores(tokens: list[str], raw: str) -> tuple[float, float, float, list[str]]:
    """(request score, question-about-action score, advice score, matched verbs)."""
    if re.search(SHELL_PATTERN, raw) or COMMAND_WORDS & set(tokens):
        return _FORCED, 0.0, 0.0, ["shell"]
    request, asked, advice, verbs = 0.0, 0.0, 0.0, []
    for index, token in enumerate(tokens):
        if token not in ACTION_VERBS:
            continue
        verbs.append(token)
        role = _verb_role(tokens, index)
        if role == "request":
            request = _REQUEST
        elif role == "advice":
            advice = _REQUEST
        elif token in QUESTION_ACTION_VERBS:
            asked = _QUESTION_ACTION
    return request, asked, advice, verbs


def _undo_verbs(tokens: list[str]) -> tuple[list[str], bool]:
    """Undo verbs present, and whether any is used as a request ("please rollback")."""
    found: list[str] = []
    requested = False
    for index, token in enumerate(tokens):
        is_roll = token == "roll" and "back" in tokens[index + 1 : index + 4]
        if token in UNDO_VERBS or is_roll:
            found.append(token)
            requested = requested or _verb_role(tokens, index) == "request"
    return found, requested


def _alert_ref(raw: str) -> tuple[str | None, str]:
    """The alert a question names, and the question with that reference removed."""
    lowered = raw[:MAX_QUESTION_CHARS].lower()
    match = _ALERT_REF_RE.search(lowered)
    if match is None:
        return None, raw
    ref = match.group(1) or match.group(2) or match.group(3)
    keep = "same for" if match.group(2) else ""
    return ref, f"{raw[: match.start()]} {keep} {raw[match.end() :]}"


def _is_follow_up(tokens: list[str]) -> bool:
    return (
        bool(tokens) and set(tokens) <= FOLLOW_UP_WORDS and bool(set(tokens) & FOLLOW_UP_TRIGGERS)
    )


def _totals(
    hits: dict[Intent, list[tuple[str, float]]],
    scores: tuple[float, float, float, list[str]],
    undo: list[str],
) -> dict[Intent, tuple[float, tuple[str, ...]]]:
    request, asked, advice, verbs = scores
    totals = {
        intent: (sum(w for _, w in rows), tuple(t for t, _ in rows))
        for intent, rows in hits.items()
    }
    if request:
        totals[Intent.ACTION_REQUEST] = (request, tuple(verbs))
    if asked:
        score, terms = totals.get(Intent.WHAT_ACTION, (0.0, ()))
        totals[Intent.WHAT_ACTION] = (score + asked, (*terms, *verbs))
    if advice:
        score, terms = totals.get(Intent.ADVICE, (0.0, ()))
        totals[Intent.ADVICE] = (score + advice, (*terms, *verbs))
    if undo:
        score, terms = totals.get(Intent.HOW_TO_UNDO, (0.0, ()))
        extra = tuple(v for v in undo if v not in terms)
        totals[Intent.HOW_TO_UNDO] = (score + _UNDO_VERB, (*terms, *extra))
    return totals


def classify(question: str) -> Classification:
    """Label one question. Deterministic: same text, same result, any hash seed."""
    raw = question[:MAX_QUESTION_CHARS]
    ref, rest_of_question = _alert_ref(raw)
    tokens, fuzzy = _canonical(normalise(rest_of_question))
    scores = _action_scores(tokens, raw.lower())
    request, verbs = scores[0], scores[3]
    undo, undo_requested = _undo_verbs(tokens)
    acting = bool(verbs) or undo_requested
    totals = _totals(_keyword_scores(tokens, fuzzy), scores, undo)
    follow = _is_follow_up(tokens)
    injected = any(re.search(p, raw.lower()) for p in INJECTION_PATTERNS)
    if request >= _FORCED or (injected and request):
        return Classification(
            Intent.ACTION_REQUEST, request, tuple(verbs), (), False, False, ref, True
        )
    if injected:
        return Classification(
            Intent.OUT_OF_SCOPE, _INJECTION, ("injection",), (), False, False, ref, acting
        )
    order = list(Intent)
    ranked = sorted(totals.items(), key=lambda kv: (-kv[1][0], order.index(kv[0])))
    if not ranked:
        return Classification(Intent.OUT_OF_SCOPE, 0.0, (), (), False, follow, ref, acting)
    (best, (score, matched)), others = ranked[0], ranked[1:]
    runner_up = others[0][1][0] if others else 0.0
    if score < MIN_SCORE or (runner_up > 0 and score - runner_up < MARGIN):
        alternatives = tuple(intent for intent, _ in ranked[:3])
        return Classification(best, score, matched, alternatives, True, follow, ref, acting)
    return Classification(best, score, matched, (), False, follow, ref, acting)
