"""Behavioural invariant discovery — architecture §8/§9, D3.3.

This module composes :mod:`~pocketsec.stage3.invariants.motifs` and
:mod:`~pocketsec.stage3.invariants.anti_unification` into falsifiable
:class:`~pocketsec.stage3.cells.invariant.Invariant` objects, and then tries to
break them.

What it is **for** is producing the *hypothesis* a Knowledge Cell may later be
crystallised from — a claim of the form "any actor with these semantics, in this
relation family, raises these security dimensions" — together with everything
needed to refute it: the observation that would falsify it, the epochs it was
seen to hold in, the number of contradicting windows, and the evidence lineage.

What it **refuses** to do:

* **It refuses to count events as support.** ``Invariant.support`` is the number
  of distinct *causal lineages* in which the invariant held. A pattern seen a
  thousand times inside one lineage has exactly one witness. Frequency is not
  corroboration (ADR-0007); a discovery engine that counted repetitions would
  hand an attacker a cheap way to manufacture consensus by looping.
* **It refuses to emit an unfalsifiable invariant.** Every emitted invariant
  carries a non-empty ``falsifier`` naming the observation that would refute it,
  and a non-empty ``evidence`` tuple. A motif whose supporting transitions carry
  no ``EvidenceRef`` yields **no invariant at all** — evidence is referenced,
  never invented, so "we have a pattern but no evidence lineage" is an
  abstention and not a weaker claim.
* **It refuses to generalise over identities.** Generalisation runs through
  :func:`~pocketsec.stage3.invariants.anti_unification.anti_unify`, which cannot
  read a name. Identities are used here only to count independent witnesses.

Everything is stdlib and every accumulator is bounded; nothing grows with corpus
size without a declared cap that is reported or raised on, never exceeded in
silence.
"""

from __future__ import annotations

import hashlib
import json
import random
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace

from pocketsec.stage0.contracts.common import ContractError, EvidenceRef
from pocketsec.stage1.ssir.entities import Entity
from pocketsec.stage1.ssir.relations import Relation
from pocketsec.stage1.ssir.transition import SSIRTransitionV1
from pocketsec.stage1.state.security_state import DIMENSIONS, SecurityStateV1
from pocketsec.stage3.cells.invariant import (
    MAX_ANTECEDENT_TERMS,
    ConsequentSpec,
    Invariant,
    PredicateRole,
    SemanticPredicate,
)
from pocketsec.stage3.invariants.anti_unification import anti_unify, semantic_class
from pocketsec.stage3.invariants.motifs import (
    MAX_MOTIF_LENGTH,
    MotifStep,
    SessionLike,
    TransitionMotif,
    extract_motifs_bounded,
    lineage_transitions,
    motif_step,
    phi_band,
)
from pocketsec.stage3.theory import SecurityConsequence, consequence_of

__all__ = [
    "MAX_ANTECEDENT_TERMS",
    "MAX_CLUSTERS",
    "MAX_EVIDENCE_PER_INVARIANT",
    "MAX_INVARIANTS",
    "MAX_SUBSTITUTIONS",
    "MAX_WINDOWS_PER_LENGTH",
    "MIN_LINEAGE_SUPPORT",
    "InvariantFit",
    "TransitionWindow",
    "counterfactual_substitution",
    "cross_epoch_validate",
    "discover_invariants",
    "epoch_accident_reason",
    "evaluate_invariant",
    "is_explicitly_epoch_bound",
    "minimal_conditions",
    "observed_epochs",
    "predictive_equivalence_clusters",
]

#: Hard cap on invariants held at once (D3.3 bounds).
MAX_INVARIANTS = 256

#: Distinct causal lineages an invariant needs before it is worth stating.
MIN_LINEAGE_SUPPORT = 4

# ``MAX_ANTECEDENT_TERMS`` is imported from ``cells/invariant.py`` and re-exported
# rather than restated: the bound is enforced by ``Invariant.__post_init__``, and a
# second copy here would drift into a discovery engine that builds antecedents the
# type then refuses.

#: Evidence references retained per invariant. Bounded because a cell's
#: lineage must fit on a 2 GB host; the selection is deterministic, not a
#: sample of convenience.
MAX_EVIDENCE_PER_INVARIANT = 16

#: Windows materialised per window length before the corpus is refused.
MAX_WINDOWS_PER_LENGTH = 65536

#: Equivalence clusters returned at once.
MAX_CLUSTERS = 256

#: Actor substitutions attempted in one counterfactual probe.
MAX_SUBSTITUTIONS = 64


# --- window materialisation ---------------------------------------------------


@dataclass(frozen=True, slots=True)
class TransitionWindow:
    """One length-``k`` slice of a single causal lineage.

    Carries the reconstructed post-state of each transition, because
    ``consequence_of`` needs "what is now true" and not only "what changed".
    """

    lineage: str
    transitions: tuple[SSIRTransitionV1, ...]
    states: tuple[SecurityStateV1, ...]
    steps: tuple[MotifStep, ...]

    @property
    def epoch(self) -> int:
        return self.transitions[-1].epoch_id

    @property
    def final(self) -> SSIRTransitionV1:
        return self.transitions[-1]

    @property
    def final_state(self) -> SecurityStateV1:
        return self.states[-1]


def _lineage_states(transitions: Sequence[SSIRTransitionV1]) -> tuple[SecurityStateV1, ...]:
    """Replay a lineage's deltas into the post-state after each transition.

    Stage 1 starts every lineage at the ``SecurityStateV1`` default and raises
    monotonically (ADR-0005), so folding ``StateDelta.raised`` forward
    reconstructs the same states rather than approximating them. A delta naming
    a dimension this build does not know is a contract error, not a skip.
    """
    state = SecurityStateV1()
    out: list[SecurityStateV1] = []
    for transition in transitions:
        for name, (_before, after) in transition.state_delta.raised.items():
            enum_type = DIMENSIONS.get(name)
            if enum_type is None:
                raise ContractError(f"unknown state dimension in delta: {name!r}")
            state = state.raised_to(name, enum_type(after))
        out.append(state)
    return tuple(out)


def _windows_of_length(
    lineages: Mapping[str, tuple[SSIRTransitionV1, ...]], k: int
) -> tuple[TransitionWindow, ...]:
    """Every length-``k`` window in the corpus, or a refusal if there are too many."""
    windows: list[TransitionWindow] = []
    for key, transitions in lineages.items():
        if len(transitions) < k:
            continue
        states = _lineage_states(transitions)
        steps = [motif_step(transition) for transition in transitions]
        for start in range(len(transitions) - k + 1):
            stop = start + k
            if len(windows) >= MAX_WINDOWS_PER_LENGTH:
                raise ContractError(
                    f"corpus produces more than MAX_WINDOWS_PER_LENGTH="
                    f"{MAX_WINDOWS_PER_LENGTH} windows at k={k}; sub-sample the corpus "
                    "rather than discovering from a silently truncated sample"
                )
            windows.append(
                TransitionWindow(
                    lineage=key,
                    transitions=tuple(transitions[start:stop]),
                    states=tuple(states[start:stop]),
                    steps=tuple(steps[start:stop]),
                )
            )
    return tuple(windows)


def _all_windows(sessions: Sequence[SessionLike]) -> dict[int, tuple[TransitionWindow, ...]]:
    """Windows for every admissible length, keyed by length."""
    lineages, _skipped, _dropped = lineage_transitions(sessions)
    return {k: _windows_of_length(lineages, k) for k in range(1, MAX_MOTIF_LENGTH + 1)}


def _flatten(windows: Mapping[int, tuple[TransitionWindow, ...]]) -> tuple[TransitionWindow, ...]:
    return tuple(window for k in sorted(windows) for window in windows[k])


# --- antecedent / consequent evaluation ---------------------------------------


def _role_binding(
    window: TransitionWindow, predicate: SemanticPredicate
) -> tuple[Entity, Relation]:
    """Which entity a predicate is tested against.

    Positional by construction: an ``ACTOR`` term describes who *opened* the
    window, an ``OBJECT`` term describes what the window *ended on*. Fixing the
    convention here is what makes a discovered antecedent re-checkable later.
    """
    if predicate.role is PredicateRole.ACTOR:
        first = window.transitions[0]
        return first.actor, first.relation
    last = window.transitions[-1]
    return last.object, last.relation


def _matches(window: TransitionWindow, antecedent: Sequence[SemanticPredicate]) -> bool:
    for predicate in antecedent:
        entity, relation = _role_binding(window, predicate)
        if not predicate.matches(entity, relation):
            return False
    return True


def _satisfies(window: TransitionWindow, consequent: ConsequentSpec) -> bool:
    final = window.final
    if not consequent.required_dimensions <= final.state_delta.dimensions:
        return False
    if final.delta_phi < consequent.min_delta_phi:
        return False
    kinds = frozenset(ref.store for ref in final.evidence)
    if not consequent.required_evidence_kinds <= kinds:
        return False
    return consequence_of(final.state_delta, window.final_state) >= consequent.consequence


@dataclass(frozen=True, slots=True)
class InvariantFit:
    """How an invariant fared against a corpus."""

    matching: int
    support: int
    contradictions: int
    epochs: frozenset[int]
    identities: frozenset[str]

    @property
    def holds(self) -> bool:
        return self.matching > 0 and self.contradictions == 0


def _fit(
    antecedent: Sequence[SemanticPredicate],
    consequent: ConsequentSpec,
    windows: Iterable[TransitionWindow],
) -> InvariantFit:
    matching = 0
    contradictions = 0
    lineages: set[str] = set()
    epochs: set[int] = set()
    identities: set[str] = set()
    for window in windows:
        if not _matches(window, antecedent):
            continue
        matching += 1
        if _satisfies(window, consequent):
            lineages.add(window.lineage)
            epochs.add(window.epoch)
            identities.add(window.transitions[0].actor.identity)
        else:
            contradictions += 1
    return InvariantFit(
        matching=matching,
        support=len(lineages),
        contradictions=contradictions,
        epochs=frozenset(epochs),
        identities=frozenset(identities),
    )


def evaluate_invariant(
    invariant: Invariant, sessions: Sequence[SessionLike]
) -> InvariantFit:
    """Re-measure an invariant against a corpus, at every window length."""
    return _fit(invariant.antecedent, invariant.consequent, _flatten(_all_windows(sessions)))


# --- invariant construction ---------------------------------------------------


def _describe(predicate: SemanticPredicate) -> str:
    required = ",".join(sorted(prop.value for prop in predicate.required_properties))
    forbidden = ",".join(sorted(prop.value for prop in predicate.forbidden_properties))
    family = predicate.relation_family.name if predicate.relation_family is not None else "ANY"
    text = f"{predicate.role.value}[{required}]"
    if forbidden:
        text += f" without [{forbidden}]"
    return f"{text} in {family}"


def _falsifier(antecedent: Sequence[SemanticPredicate], consequent: ConsequentSpec) -> str:
    """The observation that would refute the invariant. Never empty."""
    terms = " and ".join(_describe(predicate) for predicate in antecedent)
    dimensions = ",".join(sorted(consequent.required_dimensions)) or "(no dimension)"
    return (
        f"a transition window in which {terms} holds, but the final transition does not "
        f"raise {{{dimensions}}} with delta_phi >= {consequent.min_delta_phi:.4f} at "
        f"consequence >= {consequent.consequence.name}"
    )


def _invariant_id(antecedent: Sequence[SemanticPredicate], consequent: ConsequentSpec) -> str:
    """A deterministic id: the same claim always gets the same identity."""
    payload = {
        "antecedent": [
            {
                "role": predicate.role.value,
                "required": sorted(prop.value for prop in predicate.required_properties),
                "forbidden": sorted(prop.value for prop in predicate.forbidden_properties),
                "family": (
                    None if predicate.relation_family is None else int(predicate.relation_family)
                ),
                "kind": None if predicate.entity_kind is None else int(predicate.entity_kind),
            }
            for predicate in antecedent
        ],
        "consequent": {
            "dimensions": sorted(consequent.required_dimensions),
            "min_delta_phi": round(consequent.min_delta_phi, 6),
            "evidence_kinds": sorted(consequent.required_evidence_kinds),
            "consequence": int(consequent.consequence),
        },
    }
    material = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"inv:{hashlib.sha256(material).hexdigest()[:16]}"


def _consequent_from(windows: Sequence[TransitionWindow]) -> ConsequentSpec | None:
    """The strongest consequent every supporting window actually satisfies.

    Intersections and minima throughout: the claim is what *all* of them showed,
    so a single weak observation weakens the claim rather than being outvoted.

    Returns ``None`` when the windows share no raised dimension. That is an
    abstention, not a defect: a motif whose occurrences agree on nothing they
    changed predicts no security-state movement, and ``ConsequentSpec`` refuses
    such a claim outright.
    """
    finals = [window.final for window in windows]
    dimensions = frozenset.intersection(
        *(final.state_delta.dimensions for final in finals)
    )
    if not dimensions:
        return None
    evidence_kinds = frozenset.intersection(
        *(frozenset(ref.store for ref in final.evidence) for final in finals)
    )
    consequence = min(
        consequence_of(window.final.state_delta, window.final_state) for window in windows
    )
    return ConsequentSpec(
        required_dimensions=dimensions,
        min_delta_phi=round(min(final.delta_phi for final in finals), 6),
        required_evidence_kinds=evidence_kinds,
        consequence=SecurityConsequence(consequence),
    )


def _evidence_of(windows: Sequence[TransitionWindow]) -> tuple[EvidenceRef, ...]:
    """A bounded, deterministic union of the supporting evidence references."""
    refs: dict[tuple[str, str, str], EvidenceRef] = {}
    for window in windows:
        for transition in window.transitions:
            for ref in transition.evidence:
                refs[(ref.store, ref.locator, ref.digest)] = ref
    ordered = [refs[key] for key in sorted(refs)]
    return tuple(ordered[:MAX_EVIDENCE_PER_INVARIANT])


def _antecedent_from(
    windows: Sequence[TransitionWindow], motif: TransitionMotif
) -> tuple[SemanticPredicate, ...]:
    actors = [window.transitions[0].actor for window in windows]
    objects = [window.transitions[-1].object for window in windows]
    actor_predicate = anti_unify(actors, PredicateRole.ACTOR, motif.steps[0][0])
    object_predicate = anti_unify(objects, PredicateRole.OBJECT, motif.steps[-1][0])
    terms = [term for term in (actor_predicate, object_predicate) if term is not None]
    return tuple(terms[:MAX_ANTECEDENT_TERMS])


def _build_invariant(
    motif: TransitionMotif,
    supporting: Sequence[TransitionWindow],
    corpus: Sequence[TransitionWindow],
    *,
    min_support: int,
) -> Invariant | None:
    """One motif to one invariant, or ``None``.

    ``None`` — an abstention — is returned when the motif generalises to nothing
    (no shared asserted property), when its occurrences agree on no raised
    dimension, when it has too few independent witnesses, or when its evidence
    lineage is empty. None of those is repaired into a weaker invariant.
    """
    antecedent = _antecedent_from(supporting, motif)
    if not antecedent:
        return None
    consequent = _consequent_from(supporting)
    if consequent is None:
        return None
    evidence = _evidence_of(supporting)
    if not evidence:
        return None
    fit = _fit(antecedent, consequent, corpus)
    if fit.support < min_support or not fit.epochs:
        return None
    return Invariant(
        invariant_id=_invariant_id(antecedent, consequent),
        antecedent=antecedent,
        consequent=consequent,
        support=fit.support,
        contradictions=fit.contradictions,
        identities_collapsed=len(fit.identities),
        epochs=fit.epochs,
        falsifier=_falsifier(antecedent, consequent),
        evidence=evidence,
    )


def _rank(invariant: Invariant) -> tuple[int, int, int, str]:
    """Most-witnessed, least-contradicted, most-specific, then id for ties."""
    specificity = sum(len(term.required_properties) for term in invariant.antecedent)
    return (-invariant.support, invariant.contradictions, -specificity, invariant.invariant_id)


def discover_invariants(
    sessions: Sequence[SessionLike],
    *,
    min_support: int = MIN_LINEAGE_SUPPORT,
    max_invariants: int = MAX_INVARIANTS,
) -> tuple[Invariant, ...]:
    """Discover falsifiable behavioural invariants over a corpus replay.

    ``min_support`` is a count of **distinct causal lineages**, never of events:
    a motif repeated five hundred times by one process has one witness and will
    not clear a support of four. Every returned invariant carries a non-empty
    ``falsifier`` and a non-empty ``evidence`` tuple.

    Contradicted hypotheses are **returned, with their count**, not dropped. §8
    is explicit that an invariant "remains a hypothesis until its boundary and
    security-equivalence requirements are established", so a relationship with
    many witnesses and many contradicting windows is exactly the input the
    boundary engine exists to narrow. Filtering those out here would hide the
    failure rate from the stage that has to bound it, and would let a caller
    read ``support`` as if it were accuracy. ``support`` is a witness count and
    nothing else; ``contradictions`` is the other half of the answer.
    """
    if min_support < 1:
        raise ContractError(f"min_support must be >= 1, got {min_support!r}")
    if not 1 <= max_invariants <= MAX_INVARIANTS:
        raise ContractError(
            f"max_invariants must be in [1, {MAX_INVARIANTS}], got {max_invariants!r}"
        )
    windows_by_length = _all_windows(sessions)
    corpus = _flatten(windows_by_length)
    found: dict[str, Invariant] = {}
    for k in range(1, MAX_MOTIF_LENGTH + 1):
        extraction = extract_motifs_bounded(sessions, k=k, min_support=min_support)
        by_steps: dict[tuple[MotifStep, ...], list[TransitionWindow]] = {}
        for window in windows_by_length[k]:
            by_steps.setdefault(window.steps, []).append(window)
        for motif in extraction.motifs:
            supporting = by_steps.get(motif.steps)
            if not supporting:
                continue
            invariant = _build_invariant(motif, supporting, corpus, min_support=min_support)
            if invariant is not None:
                found.setdefault(invariant.invariant_id, invariant)
    return tuple(sorted(found.values(), key=_rank)[:max_invariants])


# --- minimal-feature search ---------------------------------------------------


def minimal_conditions(invariant: Invariant, sessions: Sequence[SessionLike]) -> Invariant:
    """Greedily drop antecedent terms while the consequent stays invariant.

    The consequent is **never** rewritten — this function returns an invariant
    with the same ``consequent`` object it was given, so "minimising" can never
    quietly weaken what is being claimed. A removal is kept only when it does
    not lose support and does not gain a contradiction. At least one term always
    survives: a zero-term antecedent matches the whole host.

    An invariant the corpus never exercises is returned **unchanged**. Every
    removal would look free against zero matching windows, so minimising there
    would broaden a rule on the strength of having observed nothing.
    """
    corpus = _flatten(_all_windows(sessions))
    consequent = invariant.consequent
    baseline = _fit(invariant.antecedent, consequent, corpus)
    if baseline.matching == 0:
        return invariant
    terms = list(invariant.antecedent)
    index = 0
    while len(terms) > 1 and index < len(terms):
        trial = terms[:index] + terms[index + 1 :]
        fit = _fit(trial, consequent, corpus)
        if fit.support >= baseline.support and fit.contradictions <= baseline.contradictions:
            terms = trial
            baseline = fit
            continue
        index += 1
    reduced = tuple(terms)
    if reduced == invariant.antecedent:
        return invariant
    return replace(
        invariant,
        invariant_id=_invariant_id(reduced, consequent),
        antecedent=reduced,
        support=baseline.support,
        contradictions=baseline.contradictions,
        identities_collapsed=len(baseline.identities),
        # ``Invariant.epochs`` is required non-empty. A reduced form with no
        # satisfying window has no measured epochs, so the declared binding is
        # carried over rather than invented — narrowing, never widening.
        epochs=baseline.epochs or invariant.epochs,
        falsifier=_falsifier(reduced, consequent),
    )


# --- predictive equivalence ---------------------------------------------------


def _future_signature(transitions: Sequence[SSIRTransitionV1]) -> tuple[object, ...]:
    """What security future a history implies, identity-free."""
    states = _lineage_states(transitions)
    final = states[-1]
    raised = frozenset(
        name for transition in transitions for name in transition.state_delta.dimensions
    )
    total_phi = sum(transition.delta_phi for transition in transitions)
    return (
        tuple(final.to_levels()[name] for name in DIMENSIONS),
        tuple(sorted(raised)),
        phi_band(total_phi),
    )


def predictive_equivalence_clusters(
    sessions: Sequence[SessionLike], *, max_clusters: int = MAX_CLUSTERS
) -> tuple[frozenset[str], ...]:
    """Group lineages whose histories imply equivalent security futures.

    Members are lineage keys. Clusters are ranked by size and truncated at
    ``max_clusters``; the cap is a declared bound, so a caller asking for ten
    clusters knows it may be seeing ten of many.
    """
    if not 1 <= max_clusters <= MAX_CLUSTERS:
        raise ContractError(
            f"max_clusters must be in [1, {MAX_CLUSTERS}], got {max_clusters!r}"
        )
    lineages, _skipped, _dropped = lineage_transitions(sessions)
    buckets: dict[tuple[object, ...], set[str]] = {}
    for key, transitions in lineages.items():
        if not transitions:
            continue
        buckets.setdefault(_future_signature(transitions), set()).add(key)
    clusters = sorted(
        (frozenset(members) for members in buckets.values()),
        key=lambda members: (-len(members), sorted(members)),
    )
    return tuple(clusters[:max_clusters])


# --- counterfactual substitution ----------------------------------------------


def counterfactual_substitution(
    invariant: Invariant, sessions: Sequence[SessionLike], *, seed: int
) -> tuple[bool, tuple[str, ...]]:
    """Swap semantically equivalent actors and see whether the outcome survives.

    Two actors are equivalent when they share an ``EntityKind`` and an asserted
    property mask — nothing identity-shaped participates in the class. For each
    class, windows that match the invariant's antecedent are compared pairwise:
    if one actor's window satisfies the consequent and another's does not, the
    required outcome depended on *which* actor rather than on its semantics, and
    the invariant is reported **unstable** with the substitution that broke it.

    Returns ``(stable, broken)``. ``broken`` is empty exactly when ``stable``.
    """
    corpus = _flatten(_all_windows(sessions))
    classes: dict[tuple[int, int], dict[str, bool]] = {}
    for window in corpus:
        if not _matches(window, invariant.antecedent):
            continue
        actor = window.transitions[0].actor
        outcomes = classes.setdefault(semantic_class(actor), {})
        # A lineage that ever fails the consequent counts as failing: the claim
        # is universal, so one refutation is the whole answer for that actor.
        identity = actor.identity
        outcomes[identity] = outcomes.get(identity, True) and _satisfies(
            window, invariant.consequent
        )
    rng = random.Random(seed)
    broken: list[str] = []
    for outcomes in classes.values():
        satisfying = sorted(key for key, ok in outcomes.items() if ok)
        failing = sorted(key for key, ok in outcomes.items() if not ok)
        if not satisfying or not failing:
            continue
        for _ in range(min(MAX_SUBSTITUTIONS, len(satisfying) * len(failing))):
            source = rng.choice(satisfying)
            target = rng.choice(failing)
            broken.append(f"{source}->{target}")
            if len(broken) >= MAX_SUBSTITUTIONS:
                break
        if len(broken) >= MAX_SUBSTITUTIONS:
            break
    unique = tuple(sorted(set(broken))[:MAX_SUBSTITUTIONS])
    return (not unique, unique)


# --- cross-epoch validation ---------------------------------------------------


def cross_epoch_validate(
    invariant: Invariant, sessions: Sequence[SessionLike]
) -> frozenset[int]:
    """The epochs in which the invariant holds without contradiction.

    An epoch qualifies when at least one window there matches the antecedent and
    every matching window satisfies the consequent. Epochs the invariant was
    never exercised in are absent, not assumed.
    """
    corpus = _flatten(_all_windows(sessions))
    per_epoch: dict[int, list[TransitionWindow]] = {}
    for window in corpus:
        per_epoch.setdefault(window.epoch, []).append(window)
    holding = set()
    for epoch, windows in per_epoch.items():
        fit = _fit(invariant.antecedent, invariant.consequent, windows)
        if fit.holds:
            holding.add(epoch)
    return frozenset(holding)


def observed_epochs(sessions: Sequence[SessionLike]) -> frozenset[int]:
    """Every epoch id present in the corpus replay."""
    return frozenset(
        transition.epoch_id for session in sessions for transition in session.transitions
    )


def is_explicitly_epoch_bound(
    invariant: Invariant, sessions: Sequence[SessionLike]
) -> bool:
    """Does the invariant already declare exactly the epochs it survives in?"""
    return frozenset(invariant.epochs) == cross_epoch_validate(invariant, sessions)


def epoch_accident_reason(
    invariant: Invariant, sessions: Sequence[SessionLike]
) -> str | None:
    """Why this invariant looks like one accidental configuration, or ``None``.

    §9 rejects "a relationship that exists only because of one accidental
    configuration **unless it is explicitly epoch-bound**". A single-epoch
    relationship is flagged **either way**: the declared ``epochs`` field cannot
    excuse it, because :func:`discover_invariants` fills that field from the
    same measurement, so self-labelling would let every discovered invariant
    launder its own narrowness. What the explicit binding buys is stated in the
    reason — it tells a caller the narrowness is already on the record and the
    crystallisation decision is theirs, not that the narrowness went away.
    """
    holds = cross_epoch_validate(invariant, sessions)
    observed = observed_epochs(sessions)
    if not holds:
        return f"holds in no observed epoch of {sorted(observed)}"
    if len(observed) < 2 or len(holds) > 1:
        return None
    binding = (
        "already bound to that epoch, so crystallise it epoch-bound or not at all"
        if frozenset(invariant.epochs) == holds
        else f"while claiming epochs {sorted(invariant.epochs)}: bind it or discard it"
    )
    return (
        f"holds only in epoch {sorted(holds)[0]} of observed {sorted(observed)}; {binding}"
    )
