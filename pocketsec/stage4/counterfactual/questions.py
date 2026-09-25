"""D4.11 — the self-questioning engine (architecture §24).

For every high-consequence world, eight challenges are generated and **executed**.
§24 is explicit that these are structured tests, not prompts: nothing here builds a
string and hands it to a model, and there is no path from a challenge to natural
language that anything downstream acts on (ADR-0003).

``Challenge.material`` is the field the ablation reads. Self-questioning only survives
if it finds something ordinary validation does not (falsifier F8), so ``material`` is
set for a genuinely non-obvious finding — an unfalsifiable world, an authoritative claim
resting on a blind spot, responsibility concentrated in one event, an external mapping
carrying more weight than the evidence under it — and **not** merely for the challenge
having run. :func:`judge_self_questioning` turns that into the verdict, and it returns
``NOT_YET_JUSTIFIED`` rather than ``REJECTED`` when nothing is found: on a corpus with
no headroom, "found nothing" is uninformative, which is ADR-0009's lesson and the
distinction F8 draws by name.

What this module refuses to do:

- It never counts an unanswerable question as an answer. ``answered=False`` rows exist,
  they carry the reason, and :func:`materially_challenged` ignores them.
- It never treats a shadowed absence as evidence against a world. That is §8's classic
  trap: absence only counts where the signal was actually observable.
- It never reads a claim's *text* to decide anything. It reads kinds, subjects and
  premises — structure, not prose.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.causal.memory import CausalNode
from pocketsec.stage4.counterfactual.intervention import (
    Intervention,
    InterventionKind,
    calculate_responsibility_flux,
    counterfactual_intervene,
    normalised_support,
)
from pocketsec.stage4.counterfactual.stress import (
    PerturbationKind,
    StressMaterial,
    stress_world_adversarially,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from pocketsec.stage4.claims.graph import ClaimGraph
    from pocketsec.stage4.visibility.sensor_shadow import SensorShadow
    from pocketsec.stage4.worlds.field import CausalBeliefField
    from pocketsec.stage4.worlds.world import SecurityWorldV1

__all__ = [
    "ALTERNATIVE_MARGIN",
    "CONCENTRATION_THRESHOLD",
    "MATERIAL_FIELD_DISTANCE",
    "MAX_QUESTIONS_PER_WORLD",
    "Challenge",
    "QuestionKind",
    "SelfQuestioningVerdict",
    "judge_self_questioning",
    "materially_challenged",
    "self_question_world",
]

#: §24 lists eight questions. Exactly eight, asserted against the enum.
MAX_QUESTIONS_PER_WORLD: int = 8
#: A rival within this much normalised support is a *material* alternative.
ALTERNATIVE_MARGIN: float = 0.15
#: One event holding more than this share of total responsibility flux is a finding:
#: §24's fourth question exists because a conclusion resting on a single event is one
#: perturbation away from collapsing.
CONCENTRATION_THRESHOLD: float = 0.5
#: Field movement past which an intervention counts as having changed the conclusion.
MATERIAL_FIELD_DISTANCE: float = 1e-9


class QuestionKind(StrEnum):
    """§24's eight questions, verbatim in intent."""

    WHAT_WOULD_FALSIFY = "WHAT_WOULD_FALSIFY"
    WHAT_ALTERNATIVE_EXPLAINS = "WHAT_ALTERNATIVE_EXPLAINS"
    WHICH_CLAIM_DEPENDS_ON_BLINDNESS = "WHICH_CLAIM_DEPENDS_ON_BLINDNESS"
    WHICH_EVENT_CARRIES_TOO_MUCH = "WHICH_EVENT_CARRIES_TOO_MUCH"
    WHAT_EXPECTED_EVIDENCE_IS_ABSENT = "WHAT_EXPECTED_EVIDENCE_IS_ABSENT"
    WOULD_RENAMING_CHANGE_IT = "WOULD_RENAMING_CHANGE_IT"
    WOULD_REMOVING_NOVELTY_CHANGE_IT = "WOULD_REMOVING_NOVELTY_CHANGE_IT"
    IS_EXTERNAL_MAPPING_STRONGER_THAN_EVIDENCE = "IS_EXTERNAL_MAPPING_STRONGER_THAN_EVIDENCE"


class SelfQuestioningVerdict(StrEnum):
    """What an ablation may conclude about D4.11 from a corpus run."""

    MATERIAL = "MATERIAL"
    NOT_YET_JUSTIFIED = "NOT_YET_JUSTIFIED"


@dataclass(frozen=True, slots=True)
class Challenge:
    """One executed challenge, with the reason it did or did not find anything."""

    kind: QuestionKind
    answered: bool
    finding: str
    material: bool
    claim_ids_affected: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.kind, QuestionKind):
            raise ContractError(f"kind must be a QuestionKind, got {self.kind!r}")
        if self.material and not self.answered:
            raise ContractError(
                "a challenge that could not be answered cannot be material: "
                f"{self.kind.value}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "answered": self.answered,
            "finding": self.finding,
            "material": self.material,
            "claim_ids_affected": list(self.claim_ids_affected),
        }


def _covers(shadow: SensorShadow | None, signal: str) -> bool:
    return bool(shadow is not None and shadow.covers(signal))


def _claim_kind(claim: object) -> str:
    """The claim's kind as a plain string.

    Read structurally rather than by importing ``ClaimKind``: the claim graph imports
    ``Intervention`` from this package, and a runtime import back would be a cycle. A
    ``StrEnum``'s ``str()`` is its value, so this is exact for the real type.
    """
    return str(getattr(claim, "kind", ""))


def _q_falsify(world: SecurityWorldV1, field: CausalBeliefField,
               shadow: SensorShadow | None) -> Challenge:
    others: frozenset[str] = frozenset()
    for other in field.worlds:
        if other.world_id != world.world_id:
            others |= frozenset(other.expected_evidence)
    falsifiers = frozenset(world.forbidden_evidence) | (others - frozenset(world.expected_evidence))
    observable = frozenset(s for s in falsifiers if not _covers(shadow, s))
    if not falsifiers:
        return Challenge(
            kind=QuestionKind.WHAT_WOULD_FALSIFY,
            answered=True,
            finding="no observation in this vocabulary would falsify this world",
            material=True,
        )
    if not observable:
        return Challenge(
            kind=QuestionKind.WHAT_WOULD_FALSIFY,
            answered=True,
            finding=f"every falsifier is shadowed: {sorted(falsifiers)}",
            material=True,
        )
    return Challenge(
        kind=QuestionKind.WHAT_WOULD_FALSIFY,
        answered=True,
        finding=f"observable falsifiers: {sorted(observable)}",
        material=False,
    )


def _q_alternative(world: SecurityWorldV1, field: CausalBeliefField,
                   observed: frozenset[str]) -> Challenge:
    explained = frozenset(world.expected_evidence) & observed
    weights = normalised_support(field)
    mine = weights.get(world.world_id, 0.0)
    rivals = [
        other.world_id
        for other in field.worlds
        if other.world_id != world.world_id
        and explained <= frozenset(other.expected_evidence)
        and abs(weights.get(other.world_id, 0.0) - mine) <= ALTERNATIVE_MARGIN
    ]
    if len(field.worlds) < 2:
        return Challenge(
            kind=QuestionKind.WHAT_ALTERNATIVE_EXPLAINS,
            answered=False,
            finding="the field holds a single world; no alternative exists to compare",
            material=False,
        )
    return Challenge(
        kind=QuestionKind.WHAT_ALTERNATIVE_EXPLAINS,
        answered=True,
        finding=(
            f"material alternatives within {ALTERNATIVE_MARGIN}: {sorted(rivals)}"
            if rivals
            else "no rival explains the same observed evidence at comparable support"
        ),
        material=bool(rivals),
    )


def _q_blindness(graph: ClaimGraph | None, shadow: SensorShadow | None) -> Challenge:
    if graph is None:
        return Challenge(
            kind=QuestionKind.WHICH_CLAIM_DEPENDS_ON_BLINDNESS,
            answered=False,
            finding="no claim graph supplied",
            material=False,
        )
    shadowed = tuple(
        claim_id
        for claim_id, claim in graph.claims.items()
        if _covers(shadow, str(getattr(claim, "subject", "")))
    )
    authoritative = tuple(cid for cid in shadowed if cid in graph.authoritative)
    return Challenge(
        kind=QuestionKind.WHICH_CLAIM_DEPENDS_ON_BLINDNESS,
        answered=True,
        finding=(
            f"{len(authoritative)} authoritative of {len(shadowed)} claims rest on a "
            "shadowed subject"
        ),
        material=bool(authoritative),
        claim_ids_affected=tuple(sorted(shadowed)),
    )


def _q_concentration(field: CausalBeliefField, spine: Sequence[CausalNode]) -> Challenge:
    if not spine:
        return Challenge(
            kind=QuestionKind.WHICH_EVENT_CARRIES_TOO_MUCH,
            answered=False,
            finding="no causal spine supplied",
            material=False,
        )
    fluxes = calculate_responsibility_flux(field, spine, at_sequence=field.at_sequence)
    total = sum(flux.flux for flux in fluxes)
    if total <= 0.0:
        return Challenge(
            kind=QuestionKind.WHICH_EVENT_CARRIES_TOO_MUCH,
            answered=True,
            finding="no event moves the field; responsibility is not concentrated",
            material=False,
        )
    top = max(fluxes, key=lambda f: f.flux)
    share = top.flux / total
    return Challenge(
        kind=QuestionKind.WHICH_EVENT_CARRIES_TOO_MUCH,
        answered=True,
        finding=f"{top.node_signature} carries {share:.4f} of total responsibility flux",
        material=share > CONCENTRATION_THRESHOLD,
    )


def _q_absence(world: SecurityWorldV1, shadow: SensorShadow | None,
               observed: frozenset[str]) -> Challenge:
    absent = frozenset(world.expected_evidence) - observed
    informative = frozenset(s for s in absent if not _covers(shadow, s))
    unknown = absent - informative
    return Challenge(
        kind=QuestionKind.WHAT_EXPECTED_EVIDENCE_IS_ABSENT,
        answered=True,
        finding=(
            f"informative absences {sorted(informative)}; "
            f"unknown (shadowed) absences {sorted(unknown)}"
        ),
        material=bool(informative),
    )


def _q_renaming(field: CausalBeliefField, world_id: str, spine: Sequence[CausalNode],
                observed: frozenset[str]) -> Challenge:
    identities = {node.actor_identity for node in spine if node.actor_identity}
    if not identities:
        return Challenge(
            kind=QuestionKind.WOULD_RENAMING_CHANGE_IT,
            answered=False,
            finding="no spine node carries an identity to rename",
            material=False,
        )
    renames = {identity: f"{identity}.renamed" for identity in sorted(identities)}
    material = StressMaterial(
        observed_signals=observed, spine=tuple(spine), identity_renames=renames
    )
    rows = stress_world_adversarially(
        field,
        world_id,
        corpus_hook=lambda kind: (
            material if kind is PerturbationKind.RENAME_SEMANTIC_PRESERVING else None
        ),
    )
    row = next(r for r in rows if r.kind is PerturbationKind.RENAME_SEMANTIC_PRESERVING)
    return Challenge(
        kind=QuestionKind.WOULD_RENAMING_CHANGE_IT,
        answered=True,
        finding=row.detail,
        material=row.spurious_detected,
    )


def _q_novelty(field: CausalBeliefField, world_id: str,
               spine: Sequence[CausalNode]) -> Challenge:
    if not spine:
        return Challenge(
            kind=QuestionKind.WOULD_REMOVING_NOVELTY_CHANGE_IT,
            answered=False,
            finding="no causal spine supplied",
            material=False,
        )
    target = max(spine, key=lambda n: (max(0.0, n.delta_phi), n.signature))
    result = counterfactual_intervene(
        field,
        Intervention(kind=InterventionKind.REMOVE_NOVELTY, target_signature=target.signature),
        spine=spine,
    )
    shift = result.support_shift.get(world_id, 0.0)
    return Challenge(
        kind=QuestionKind.WOULD_REMOVING_NOVELTY_CHANGE_IT,
        answered=True,
        finding=(
            f"removing novelty moves the field {result.field_distance:.6f} and this "
            f"world {shift:+.6f}"
        ),
        material=result.field_distance > MATERIAL_FIELD_DISTANCE,
    )


def _q_external(graph: ClaimGraph | None) -> Challenge:
    if graph is None:
        return Challenge(
            kind=QuestionKind.IS_EXTERNAL_MAPPING_STRONGER_THAN_EVIDENCE,
            answered=False,
            finding="no claim graph supplied",
            material=False,
        )
    external = tuple(
        claim_id for claim_id, claim in graph.claims.items() if _claim_kind(claim) == "EXT"
    )
    if not external:
        return Challenge(
            kind=QuestionKind.IS_EXTERNAL_MAPPING_STRONGER_THAN_EVIDENCE,
            answered=True,
            finding="no external-knowledge claim is present to outrank the evidence",
            material=False,
        )
    unsupported = tuple(
        claim_id for claim_id in external if not graph.traces_to_observation(claim_id)
    )
    return Challenge(
        kind=QuestionKind.IS_EXTERNAL_MAPPING_STRONGER_THAN_EVIDENCE,
        answered=True,
        finding=(
            f"{len(unsupported)} of {len(external)} external claims do not trace to an "
            "observation"
        ),
        material=bool(unsupported),
        claim_ids_affected=tuple(sorted(unsupported)),
    )


def self_question_world(
    field: CausalBeliefField,
    world_id: str,
    *,
    shadow: SensorShadow | None,
    graph: ClaimGraph | None,
    observed: frozenset[str] = frozenset(),
    spine: Sequence[CausalNode] = (),
) -> tuple[Challenge, ...]:
    """CBF-F15 — run §24's eight challenges against one world.

    ``observed`` and ``spine`` are the incident's own evidence; both default to empty so
    the function is callable before either exists, in which case the affected challenges
    come back ``answered=False`` with the reason rather than inventing a finding.

    Returns exactly ``MAX_QUESTIONS_PER_WORLD`` challenges, in enum order.
    """
    world = field.world(world_id)
    if world is None:
        raise ContractError(f"world {world_id!r} is not in incident {field.incident_id!r}")
    challenges = (
        _q_falsify(world, field, shadow),
        _q_alternative(world, field, observed),
        _q_blindness(graph, shadow),
        _q_concentration(field, spine),
        _q_absence(world, shadow, observed),
        _q_renaming(field, world_id, spine, observed),
        _q_novelty(field, world_id, spine),
        _q_external(graph),
    )
    if len(challenges) != MAX_QUESTIONS_PER_WORLD:  # pragma: no cover - fixed tuple
        raise ContractError("the challenge set must hold exactly eight questions")
    return challenges


def materially_challenged(challenges: Sequence[Challenge]) -> tuple[Challenge, ...]:
    """The challenges that actually found something. Unanswered rows never count."""
    return tuple(c for c in challenges if c.answered and c.material)


def judge_self_questioning(
    runs: Sequence[Sequence[Challenge]],
) -> tuple[SelfQuestioningVerdict, Mapping[str, int]]:
    """Read F8 off a corpus run: MATERIAL, or NOT_YET_JUSTIFIED — never REJECTED.

    The distinction is the whole point. If self-questioning finds nothing on a corpus
    that offers nothing to find, the correct conclusion is that the mechanism is
    unjustified *so far*, not that it is refuted (ADR-0009's lesson). Returns the
    verdict with the per-kind material counts, so a reader can see which of the eight
    questions carried the result instead of trusting a single boolean.
    """
    counts = dict.fromkeys((kind.value for kind in QuestionKind), 0)
    answered = 0
    for run in runs:
        for challenge in run:
            if challenge.answered:
                answered += 1
            if challenge.answered and challenge.material:
                counts[challenge.kind.value] += 1
    counts["_answered"] = answered
    verdict = (
        SelfQuestioningVerdict.MATERIAL
        if any(value for key, value in counts.items() if not key.startswith("_"))
        else SelfQuestioningVerdict.NOT_YET_JUSTIFIED
    )
    return verdict, counts
