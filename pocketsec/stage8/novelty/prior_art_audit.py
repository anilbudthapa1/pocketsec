"""D8.13 / PROM-F24 — the conservative prior-art audit: is this theory already known here?

A discovery engine that rediscovers what the repository already knows and calls it new is
worse than no engine: it spends review attention on nothing and erodes trust in the rest.
This module compares a theory's mechanism against a **local library** of known mechanisms
and classifies it conservatively. It never claims novelty.

The library is **computed, not hand-written.** :func:`stage1_known_mechanisms` replays each
``ATTACK_*`` chain of ``stage1/labs/corpus.py`` through a fresh ``Stage1Pipeline``, encodes it
with Stage 2's encoder via Stage 6's ``EncodedStep`` (Stage 6's actor-slot rule), and emits,
from each chain's escalating steps (Stage 6's ``is_escalating``):

- one ``SINGLE`` of each escalating step's *maximal* predicate (its relation, every property
  bit it carries, every dimension it raised), and
- one ``PRECEDES`` of the maximal predicates of each consecutive pair of escalating steps of
  one actor.

Each entry's ``known_id`` is ``"stage1:<CHAIN>"``, e.g. ``"stage1:ATTACK_EXFIL"``.
:func:`known_library` adds Stage 6 trusted motifs, Stage 7 seeds and theories already
validated in this run.

Coverage: predicate ``P`` covers ``Q`` when their relations are equal and each of ``Q``'s
masks is a subset of ``P``'s (``P.implies(Q)``). Classification, first hit wins:

- ``KNOWN`` — one library entry has the same relation kind (relation, modifier, repeat count)
  and step-wise coverage in either direction (``CO_OCCURS`` is order-free);
- ``KNOWN_COMBINATION`` — every step is covered by some entry, but no single entry covers it;
- ``CONTEXT_EXTENSION`` — at least one step is covered;
- ``POTENTIALLY_NOVEL`` — nothing is covered. This is a statement about a local library of a
  few dozen entries, not about the literature.

What it refuses to do:

- ``novelty_claim_permitted`` is True only when the class is ``POTENTIALLY_NOVEL`` **and** the
  bound hypothesis's :class:`PriorArtEntry` permits a claim (literature and patent review
  both ``REVIEWED`` with citations, ``stage0/prior_art.py``). Every entry is
  ``NOT_REVIEWED`` today, so no Stage 8 theory may be called new.
- It holds no ATT&CK, Sigma, YARA or literature index (none exists offline, and there is no
  network): ``matched_known`` holds local library ids only.
- It emits no free text. The only place the word for "new" appears in its output is the
  enum value ``POTENTIALLY_NOVEL``.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from functools import lru_cache

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.hypotheses import HYPOTHESES
from pocketsec.stage0.prior_art import PriorArtLedger, ReviewStatus
from pocketsec.stage1.labs import corpus as stage1_corpus
from pocketsec.stage1.labs.corpus import Scenario
from pocketsec.stage1.pipeline import Stage1Pipeline
from pocketsec.stage6.capsule.experience_capsule import EncodedStep
from pocketsec.stage6.memory.semantic import MotifStep, is_escalating, motif_pattern_key
from pocketsec.stage8.forge.package import NoveltyClass
from pocketsec.stage8.genome.grammar import Mechanism, MechanismRelation, StepPredicate
from pocketsec.stage8.genome.hypothesis import HypothesisGenome

__all__ = [
    "ABLATION_HYPOTHESIS",
    "MAX_KNOWN_LIBRARY",
    "MAX_MATCHED_KNOWN",
    "STAGE1_KNOWN_CHAINS",
    "KnownMechanism",
    "NoveltyAudit",
    "audit",
    "known_library",
    "stage1_known_mechanisms",
]

#: Spec §2.6: Stage 8's ablation rows (and this audit's default prior-art entry) bind to H8.
ABLATION_HYPOTHESIS: str = "H8"
#: Every attack chain of the Stage 1 replay corpus, in the order the corpus defines them.
STAGE1_KNOWN_CHAINS: tuple[str, ...] = (
    "ATTACK_EXFIL",
    "ATTACK_PERSISTENCE",
    "ATTACK_UNSEEN_MEMORY",
    "ATTACK_UNSEEN_ESCAPE",
)
#: Chosen, not measured: a library past this size is refused rather than silently cut.
MAX_KNOWN_LIBRARY: int = 1024
#: At most this many library ids are named per audit (sorted, so the cut is deterministic).
MAX_MATCHED_KNOWN: int = 16

_LIBRARY_HOST = "stage8-novelty-library"
_REVIEW_ORDER = (ReviewStatus.NOT_REVIEWED, ReviewStatus.IN_PROGRESS, ReviewStatus.REVIEWED)


@dataclass(frozen=True, slots=True)
class KnownMechanism:
    """One mechanism the repository already knows, and where that knowledge came from."""

    # "stage1:ATTACK_EXFIL", "stage6:motif:<hex>", "stage7:mech-<hex>", "validated:hyp-<hex>"
    known_id: str
    mechanism: Mechanism
    source: str  # a code path or a hypothesis id, never prose

    def __post_init__(self) -> None:
        for name in ("known_id", "source"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value or not value.isascii() or " " in value:
                raise ContractError(f"KnownMechanism.{name} must be a non-empty ASCII code")
        if not isinstance(self.mechanism, Mechanism):
            raise ContractError("KnownMechanism.mechanism must be a Mechanism")


@dataclass(frozen=True, slots=True)
class NoveltyAudit:
    """The audit's answer. Plain data; a claim is permitted only under the rule above."""

    hypothesis_id: str
    classification: NoveltyClass
    matched_known: tuple[str, ...]
    external_review: ReviewStatus
    novelty_claim_permitted: bool

    def __post_init__(self) -> None:
        if not isinstance(self.classification, NoveltyClass):
            raise ContractError(
                f"classification must be a NoveltyClass, got {self.classification!r}")
        if not isinstance(self.external_review, ReviewStatus):
            raise ContractError("external_review must be a ReviewStatus")
        matched = tuple(self.matched_known)
        if len(matched) > MAX_MATCHED_KNOWN or len(set(matched)) != len(matched):
            raise ContractError(f"matched_known holds <= {MAX_MATCHED_KNOWN} distinct ids")
        if self.classification is NoveltyClass.POTENTIALLY_NOVEL and matched:
            raise ContractError("a theory that matched the library is not POTENTIALLY_NOVEL")
        if self.classification is not NoveltyClass.POTENTIALLY_NOVEL and not matched:
            raise ContractError(f"{self.classification} must name the library ids it matched")
        if self.novelty_claim_permitted and (
            self.classification is not NoveltyClass.POTENTIALLY_NOVEL
            or self.external_review is not ReviewStatus.REVIEWED
        ):
            raise ContractError("a claim needs POTENTIALLY_NOVEL and a REVIEWED prior-art entry")
        object.__setattr__(self, "matched_known", matched)


def _maximal(step: EncodedStep) -> StepPredicate:
    """The most specific predicate one step satisfies: everything it carries is required."""
    return StepPredicate(
        relation=step.relation,
        require_properties=step.object_property_mask,
        forbid_properties=0,
        require_raised=step.state_delta_mask,
    )


def _encode_chain(name: str) -> tuple[EncodedStep, ...]:
    chain = getattr(stage1_corpus, name)
    # A fresh pipeline per chain: Stage 1 carries lineage state across scenarios on a
    # shared pipeline (MEMORY corpus trap), which would change what each chain encodes to.
    result = Stage1Pipeline(host_id=_LIBRARY_HOST).run_scenario(
        Scenario(name=name, behaviours=chain, label=1)
    )
    slots: dict[str, int] = {}  # Stage 6's rule: order of first appearance of the actor
    return tuple(
        EncodedStep.from_transition(t, actor_slot=slots.setdefault(t.actor.identity, len(slots)))
        for t in result.transitions
    )


def _chain_mechanisms(steps: Sequence[EncodedStep]) -> tuple[Mechanism, ...]:
    escalating = [step for step in steps if is_escalating(step)]
    found: dict[str, Mechanism] = {}
    for step in escalating:
        single = Mechanism(MechanismRelation.SINGLE, (_maximal(step),))
        found.setdefault(single.digest(), single)
    by_actor: dict[int, list[EncodedStep]] = {}
    for step in escalating:
        by_actor.setdefault(step.actor_slot, []).append(step)
    for own in by_actor.values():
        for first, second in zip(own, own[1:], strict=False):
            a, b = _maximal(first), _maximal(second)
            if a == b:
                continue  # PRECEDES(p, p) is not a grammar member (it is REPEATED(p, 2))
            pair = Mechanism(MechanismRelation.PRECEDES, (a, b))
            found.setdefault(pair.digest(), pair)
    return tuple(found.values())


@lru_cache(maxsize=1)
def stage1_known_mechanisms() -> tuple[KnownMechanism, ...]:
    """The Stage 1 attack chains as known mechanisms. Computed by replay, cached (immutable)."""
    library: list[KnownMechanism] = []
    for name in STAGE1_KNOWN_CHAINS:
        source = f"pocketsec.stage1.labs.corpus:{name}"
        library.extend(
            KnownMechanism(known_id=f"stage1:{name}", mechanism=mechanism, source=source)
            for mechanism in _chain_mechanisms(_encode_chain(name))
        )
    return tuple(library)


def _motif_mechanism(motif: Sequence[MotifStep]) -> Mechanism:
    steps = tuple(
        StepPredicate(m.relation, m.require_properties, m.forbid_properties, m.require_raised)
        for m in motif
    )
    relation = MechanismRelation.SINGLE if len(steps) == 1 else MechanismRelation.PRECEDES
    return Mechanism(relation, steps)


def known_library(
    *,
    stage6_motifs: Sequence[Sequence[MotifStep]] = (),
    stage7_seeds: Sequence[Mechanism] = (),
    validated: Sequence[HypothesisGenome] = (),
) -> tuple[KnownMechanism, ...]:
    """Stage 1's chains plus Stage 6 motifs, Stage 7 seeds and this run's validated theories."""
    library = list(stage1_known_mechanisms())
    for motif in stage6_motifs:
        steps = tuple(motif)
        if any(not isinstance(step, MotifStep) for step in steps):
            raise ContractError("stage6_motifs must be sequences of MotifStep")
        library.append(KnownMechanism(
            known_id="stage6:" + motif_pattern_key(steps),
            mechanism=_motif_mechanism(steps),
            source="pocketsec.stage6.memory.semantic:MotifStep",
        ))
    for seed in stage7_seeds:
        if not isinstance(seed, Mechanism):
            raise ContractError("stage7_seeds must be Mechanism values")
        library.append(KnownMechanism(
            known_id="stage7:" + seed.digest(), mechanism=seed,
            source="pocketsec.stage8.adapters.stage7:seeds_from_capsules",
        ))
    for genome in validated:
        if not isinstance(genome, HypothesisGenome):
            raise ContractError("validated must be HypothesisGenome values")
        library.append(KnownMechanism(
            known_id="validated:" + genome.hypothesis_id,
            mechanism=genome.proposed_mechanism, source=genome.hypothesis_id,
        ))
    if len(library) > MAX_KNOWN_LIBRARY:
        raise ContractError(
            f"the known library holds <= {MAX_KNOWN_LIBRARY} entries, got {len(library)}")
    return tuple(library)


def _step_covered(p: StepPredicate, q: StepPredicate) -> bool:
    """Coverage in either direction: one predicate is a specialisation of the other."""
    return p.implies(q) or q.implies(p)


def _same_kind(a: Mechanism, b: Mechanism) -> bool:
    return (a.relation, a.modifier, a.repeat_min) == (b.relation, b.modifier, b.repeat_min)


def _covers_mechanism(known: Mechanism, theory: Mechanism) -> bool:
    if not _same_kind(known, theory):
        return False
    pairs = [tuple(zip(known.steps, theory.steps, strict=True))]
    if theory.relation is MechanismRelation.CO_OCCURS:  # order-free relation
        pairs.append(tuple(zip(known.steps, reversed(theory.steps), strict=True)))
    # Each step may be covered in either direction. Of the two readings of "step-wise
    # coverage in either direction" this is the one that says KNOWN more often: the
    # conservative choice when the cost of the other error is a false claim of newness.
    return any(all(_step_covered(p, q) for p, q in pairing) for pairing in pairs)


def _classify(
    mechanism: Mechanism, library: Sequence[KnownMechanism]
) -> tuple[NoveltyClass, tuple[str, ...]]:
    whole = sorted({k.known_id for k in library if _covers_mechanism(k.mechanism, mechanism)})
    if whole:
        return NoveltyClass.KNOWN, tuple(whole[:MAX_MATCHED_KNOWN])
    covered_steps = 0
    partial: set[str] = set()
    for step in mechanism.steps:
        hits = {k.known_id for k in library
                if any(_step_covered(p, step) for p in k.mechanism.steps)}
        covered_steps += bool(hits)
        partial |= hits
    ids = tuple(sorted(partial)[:MAX_MATCHED_KNOWN])
    if covered_steps == len(mechanism.steps):
        return NoveltyClass.KNOWN_COMBINATION, ids
    if covered_steps:
        return NoveltyClass.CONTEXT_EXTENSION, ids
    return NoveltyClass.POTENTIALLY_NOVEL, ()


def _weakest_review(prior_art: PriorArtLedger, bound_hypothesis: str) -> ReviewStatus:
    entry = prior_art.entries.get(bound_hypothesis)
    if entry is None:
        return ReviewStatus.NOT_REVIEWED
    return min(entry.literature_status, entry.patent_status, key=_REVIEW_ORDER.index)


def audit(
    genome: HypothesisGenome,
    library: Sequence[KnownMechanism],
    *,
    prior_art: PriorArtLedger,
    bound_hypothesis: str = ABLATION_HYPOTHESIS,
) -> NoveltyAudit:
    """Classify ``genome`` against ``library``; permit a claim only under the prior-art rule."""
    if not isinstance(genome, HypothesisGenome):
        raise ContractError(f"audit needs a HypothesisGenome, got {type(genome).__name__}")
    if not isinstance(prior_art, PriorArtLedger):
        raise ContractError("audit needs the Stage 0 PriorArtLedger")
    if bound_hypothesis not in HYPOTHESES:
        raise ContractError(f"{bound_hypothesis!r} is not a registered hypothesis")
    library = tuple(library)
    if len(library) > MAX_KNOWN_LIBRARY or any(not isinstance(k, KnownMechanism) for k in library):
        raise ContractError(f"library must be <= {MAX_KNOWN_LIBRARY} KnownMechanism values")
    classification, matched = _classify(genome.proposed_mechanism, library)
    entry = prior_art.entries.get(bound_hypothesis)
    permitted = (
        classification is NoveltyClass.POTENTIALLY_NOVEL
        and entry is not None
        and entry.novelty_claim_permitted
    )
    return NoveltyAudit(
        hypothesis_id=genome.hypothesis_id,
        classification=classification,
        matched_known=matched,
        external_review=_weakest_review(prior_art, bound_hypothesis),
        novelty_claim_permitted=permitted,
    )
