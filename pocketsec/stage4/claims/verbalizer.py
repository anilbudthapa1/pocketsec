"""D4.15 — the guard around an optional verbalizer. The guard is the deliverable.

Architecture §34 reduces the tiny language model to one job: linguistic
compression of an already-typed claim graph. The pipeline is

    CBF/LUCID -> typed claim graph -> deterministic validator -> optional
    verbalizer -> claim/evidence checker -> output

and everything that matters for hallucination cost lives in the last checker.
:func:`validate_verbalization` is that checker. **No language model ships in this
wave**: ``VERBALIZER_DEFAULT_ENABLED`` is ``False``, ``verbalizer=None`` is the
shipped configuration, and whether a real tiny LM helps is UNMEASURED because
there is no local model in this repository to measure. What *is* measurable is
whether the guard catches an unsupported proposition, so that is what is built
and tested.

Four refusal classes, from the spec:

a. a ``FORBIDDEN_AMPLIFICATIONS`` verb that is not in the compiled claim;
b. a ``DIMENSIONS`` key or ``MANDATORY_SIGNALS`` name absent from the compiled
   claim's premise chain — the model may not introduce a security dimension the
   evidence never mentioned;
c. a digit sequence that does not appear in the compiled claim — invented counts,
   sequence numbers and timestamps are the most quotable kind of hallucination;
d. the negation of a compiled ``UnknownClaim`` — turning "not observed" into
   "did not happen" converts a hole into an exoneration, and an exoneration is
   the most dangerous sentence this system can emit.

(d) deliberately distinguishes *restating* an unknown from *resolving* it. "direct
exfiltration evidence was not observed" is the unknown, faithfully paraphrased.
"there was no exfiltration" is a new fact. The rule is: a negation cue near an
unknown's content words is refused unless the same sentence carries an epistemic
marker (evidence / observed / visibility / unknown / insufficient). It is a
heuristic over a closed token set, it is stated here so it can be argued with, and
its failure mode is a fallback to deterministic text — never an emitted claim.

What this module refuses to do: it never lets a verbalizer failure reach the
caller. A raising verbalizer is caught and recorded, because an optional
component that can crash the incident path is not optional (D4.17).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Protocol

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.observation.policy import MANDATORY_SIGNALS
from pocketsec.stage1.state.security_state import DIMENSIONS
from pocketsec.stage4.claims.compiler import FORBIDDEN_AMPLIFICATIONS, CompiledClaim

__all__ = [
    "EPISTEMIC_MARKERS",
    "MAX_VERBALIZED_TEXT",
    "NEGATION_CUES",
    "VERBALIZER_DEFAULT_ENABLED",
    "Verbalizer",
    "VerbalizerVerdict",
    "validate_verbalization",
    "verbalize_guarded",
]

#: Never required for detection or resolution, and off until measured.
VERBALIZER_DEFAULT_ENABLED: bool = False

#: A verbalization is a compression of one compiled claim, so it can never be
#: longer than a few times the claim it compresses.
MAX_VERBALIZED_TEXT: int = 1024

#: Bound on reported offenders, so a pathological text cannot produce an
#: unbounded verdict object.
MAX_UNSUPPORTED_REPORTED: int = 16

NEGATION_CUES: tuple[str, ...] = (
    "no ",
    "not ",
    "never",
    "without",
    "ruled out",
    "absent",
    "none",
    "did not",
    "cannot",
    "nothing",
)

#: Words that mark a sentence as talking about *knowledge* rather than about the
#: world. Their presence is what separates a faithful restatement of an unknown
#: from a claim that the unknown thing did not happen.
EPISTEMIC_MARKERS: tuple[str, ...] = (
    "evidence",
    "observ",
    "unknown",
    "unobserv",
    "visib",
    "shadow",
    "insufficient",
    "recorded",
    "telemetry",
    "sensor",
    "seen",
    "data",
)

_DIGITS_RE = re.compile(r"\d+")
_WORD_RE = re.compile(r"[a-z][a-z0-9_]{3,}")
_SENTENCE_RE = re.compile(r"[.;:\n]+")

#: Words too common to identify an unknown's subject matter.
_STOPWORDS = frozenset(
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
        "direct",
        "also",
        "then",
        "than",
        "when",
        "what",
        "could",
        "would",
        "about",
        "observable",
        "observed",
        "evidence",
        "unknown",
    }
)


class Verbalizer(Protocol):
    """A paraphraser. It receives typed claims and returns prose, nothing else."""

    def verbalize(self, compiled: CompiledClaim) -> str: ...


@dataclass(frozen=True, slots=True)
class VerbalizerVerdict:
    """The guard's decision plus the text that is actually safe to emit."""

    accepted: bool
    text: str
    rejected_reason: str = ""
    unsupported_propositions: tuple[str, ...] = ()
    fell_back: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.accepted, bool):
            raise ContractError("VerbalizerVerdict.accepted must be a bool")
        if not isinstance(self.text, str) or not self.text:
            raise ContractError("VerbalizerVerdict.text must be non-empty")
        object.__setattr__(self, "unsupported_propositions", tuple(self.unsupported_propositions))
        if self.accepted and self.rejected_reason:
            raise ContractError("an accepted verbalization cannot carry a rejected_reason")
        if self.accepted and self.fell_back:
            raise ContractError("an accepted verbalization did not fall back")
        if not self.accepted and not self.rejected_reason:
            raise ContractError("a rejected verbalization must name its reason")

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "text": self.text,
            "rejected_reason": self.rejected_reason,
            "unsupported_propositions": list(self.unsupported_propositions),
            "fell_back": self.fell_back,
        }


def _compiled_text(compiled: CompiledClaim) -> str:
    """Every word the typed claims actually contain, lowercased."""
    return " ".join(claim.text.lower() for claim in compiled.all_claims())


def _significant_words(text: str) -> frozenset[str]:
    return frozenset(w for w in _WORD_RE.findall(text.lower()) if w not in _STOPWORDS)


def _forbidden_verbs(produced: str, supported: str) -> tuple[str, ...]:
    lowered = produced.lower()
    return tuple(
        verb
        for verb in sorted(FORBIDDEN_AMPLIFICATIONS)
        if verb in lowered and verb not in supported
    )


def _introduced_terms(produced: str, supported: str) -> tuple[str, ...]:
    """DIMENSIONS keys and MANDATORY_SIGNALS the compiled claim never mentioned."""
    lowered = produced.lower()
    vocabulary = sorted(set(DIMENSIONS) | set(MANDATORY_SIGNALS))
    return tuple(term for term in vocabulary if term in lowered and term not in supported)


def _invented_digits(produced: str, supported: str) -> tuple[str, ...]:
    return tuple(
        sorted({run for run in _DIGITS_RE.findall(produced) if run not in supported})
    )


def _negated_unknowns(compiled: CompiledClaim, produced: str) -> tuple[str, ...]:
    """Unknown ids the produced text asserts away rather than restates."""
    offenders: list[str] = []
    sentences = [s.strip().lower() for s in _SENTENCE_RE.split(produced) if s.strip()]
    for unknown in compiled.unknown:
        words = _significant_words(f"{unknown.subject} {unknown.text}")
        if not words:
            continue
        for sentence in sentences:
            if not any(cue in sentence for cue in NEGATION_CUES):
                continue
            if not any(word in sentence for word in words):
                continue
            if any(marker in sentence for marker in EPISTEMIC_MARKERS):
                continue
            offenders.append(unknown.claim_id)
            break
    return tuple(sorted(dict.fromkeys(offenders)))


def _reject(compiled: CompiledClaim, reason: str, offenders: tuple[str, ...]) -> VerbalizerVerdict:
    return VerbalizerVerdict(
        accepted=False,
        text=compiled.render(),
        rejected_reason=reason,
        unsupported_propositions=offenders[:MAX_UNSUPPORTED_REPORTED],
        fell_back=True,
    )


def validate_verbalization(compiled: CompiledClaim, produced: str) -> VerbalizerVerdict:
    """Accept ``produced`` only if every proposition in it is already compiled.

    On rejection the returned ``text`` is ``compiled.render()`` and ``fell_back``
    is ``True``, so a caller that ignores ``accepted`` still emits safe text. That
    is intentional: the failure mode of this guard must be deterministic prose,
    not an exception and not the model's sentence.
    """
    if not isinstance(produced, str) or not produced.strip():
        return _reject(compiled, "empty_verbalization", ())
    if len(produced) > MAX_VERBALIZED_TEXT:
        return _reject(compiled, f"text_too_long:{len(produced)}", ())
    supported = _compiled_text(compiled)
    verbs = _forbidden_verbs(produced, supported)
    if verbs:
        return _reject(compiled, "forbidden_amplification", verbs)
    terms = _introduced_terms(produced, supported)
    if terms:
        return _reject(compiled, "unsupported_security_term", terms)
    digits = _invented_digits(produced, supported)
    if digits:
        return _reject(compiled, "invented_quantity", digits)
    negated = _negated_unknowns(compiled, produced)
    if negated:
        return _reject(compiled, "negated_unknown", negated)
    return VerbalizerVerdict(accepted=True, text=produced, fell_back=False)


def verbalize_guarded(
    compiled: CompiledClaim, verbalizer: Verbalizer | None
) -> VerbalizerVerdict:
    """Run ``verbalizer`` behind the guard, falling back to deterministic text.

    ``verbalizer=None`` is the shipped configuration and is not an error: it
    returns the deterministic rendering with ``fell_back=True``. A verbalizer that
    raises is caught and recorded the same way, because an optional linguistic
    layer may never take the incident path down with it.
    """
    if verbalizer is None:
        return VerbalizerVerdict(
            accepted=False,
            text=compiled.render(),
            rejected_reason="verbalizer_disabled",
            fell_back=True,
        )
    try:
        produced = verbalizer.verbalize(compiled)
    except Exception as exc:  # noqa: BLE001 - an optional layer may not propagate
        return _reject(compiled, f"verbalizer_raised:{type(exc).__name__}", ())
    return validate_verbalization(compiled, produced)
