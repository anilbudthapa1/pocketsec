"""The ONE door from Stage 9 to Stage 6 (ADR-0081): hand evidence to the quarantine, record.

Search has no production authority. The only way anything Stage 9 finds can move toward
trusted state is Stage 6's quarantine -> validation -> promotion boundary, entered through
``QuarantineGateway.admit``. This module is the only Stage 9 file that imports the gateway
or the capsule builders, and the only one that calls ``.admit``; ``successor/boundary.py``
proves both by AST.

What it hands over, and why that is all it can hand over: Stage 6's candidate kinds are
exactly those with an executor (ADR-0056) and none of them executes a computational
genome (blocker B9-2). So the exit offers the *evidence sessions* that justified a
successor, as ``TRANSITION_EPISODE`` capsules built by Stage 6's own
``capsule_from_scenario``, under a provenance that claims nothing: ``DERIVED_INFERENCE``,
no label, one independence group per successor (its capsules are not independent of each
other, and saying otherwise would inflate Stage 6's independence count).

What it refuses to do:

* construct a gateway. The caller (the gate, or a lab test) builds and binds it; a door
  that builds its own receiver is not a door;
* call anything on the gateway but ``admit``, or act on a verdict. Verdicts are recorded
  verbatim as ``(capsule_id, bucket, reasons)``; ``TRUSTED_CANDIDATE`` is counted by the
  caller, never followed;
* offer more than :data:`MAX_EXIT_CAPSULES` capsules per successor. Extra evidence is
  counted as truncated, not silently dropped;
* hand over a successor that does not re-verify from its own bytes.

Importing this module loads Stage 5 transitively through ``pocketsec.stage6.capsule``
(M0.9). That residual is declared (ADR-0081) and bounded by ``boundary.py``: every path
from this file to Stage 5 must pass through ``pocketsec.stage6.capsule.*``, and no other
Stage 9 runtime module may reach Stage 5 at all.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.epoch.model import Epoch
from pocketsec.stage1.pipeline import ScenarioResult
from pocketsec.stage6.capsule.experience_capsule import (
    ExperienceCapsuleV1,
    LabelOrigin,
    SourceClass,
    SourceProvenance,
    capsule_from_scenario,
)
from pocketsec.stage6.capsule.quarantine import QuarantineGateway, QuarantineVerdict
from pocketsec.stage9.successor.proof_carrying import ProofCarryingSuccessorV1

__all__ = [
    "EXIT_HOST_ID",
    "EXIT_LINEAGE",
    "EXIT_SOURCE_ID",
    "MAX_EXIT_CAPSULES",
    "ExitReceipt",
    "Stage6Exit",
    "exit_provenance",
]

MAX_EXIT_CAPSULES = 8
EXIT_SOURCE_ID = "stage9-ontogenesis"
EXIT_LINEAGE: tuple[str, ...] = ("stage9", "ontogenesis")
EXIT_HOST_ID = "lab"


@dataclass(frozen=True, slots=True)
class ExitReceipt:
    """What happened at the door, verbatim. It is a record, never an instruction."""

    successor_digest: str
    offered: int
    #: (capsule_id, bucket, reasons) exactly as Stage 6 returned them.
    verdicts: tuple[tuple[str, str, tuple[str, ...]], ...]
    #: Evidence entries beyond MAX_EXIT_CAPSULES, counted and not offered.
    truncated_evidence: int = 0
    #: (evidence index, reason) for entries Stage 6's capsule builder refused to build.
    unbuilt: tuple[tuple[int, str], ...] = ()


def exit_provenance(successor_digest: str) -> SourceProvenance:
    """The provenance every exit capsule carries: a derived inference that claims nothing."""
    return SourceProvenance(
        source_class=SourceClass.DERIVED_INFERENCE,
        source_id=EXIT_SOURCE_ID,
        independence_group="stage9-" + successor_digest[7:23],
        label_origin=LabelOrigin.NONE,
        transformation_lineage=EXIT_LINEAGE,
        host_id=EXIT_HOST_ID,
    )


class Stage6Exit:
    """Offer a successor's evidence to a caller-built Stage 6 gateway, and record the answer."""

    def __init__(self, gateway: QuarantineGateway) -> None:
        if not isinstance(gateway, QuarantineGateway):
            raise ContractError("Stage6Exit needs a Stage 6 QuarantineGateway built by the caller")
        self._gateway = gateway
        self._offered_total = 0

    @property
    def offered_total(self) -> int:
        """Capsules offered through this exit so far (the firing count)."""
        return self._offered_total

    def hand_over(self, successor: ProofCarryingSuccessorV1, *,
                  evidence: Sequence[ScenarioResult], epoch: Epoch,
                  sequence: int) -> ExitReceipt:
        """Build <= MAX_EXIT_CAPSULES capsules, pass each to ``admit``, record the verdicts."""
        verified = ProofCarryingSuccessorV1.from_dict(successor.to_dict())
        digest = verified.content_digest
        capsules, unbuilt = self._build(evidence[:MAX_EXIT_CAPSULES], digest, epoch, sequence)
        verdicts = tuple(_recorded(self._gateway.admit(capsule)) for capsule in capsules)
        self._offered_total += len(capsules)
        return ExitReceipt(
            successor_digest=digest,
            offered=len(capsules),
            verdicts=verdicts,
            truncated_evidence=max(0, len(evidence) - MAX_EXIT_CAPSULES),
            unbuilt=tuple(unbuilt),
        )

    @staticmethod
    def _build(evidence: Sequence[ScenarioResult], digest: str, epoch: Epoch,
               sequence: int) -> tuple[list[ExperienceCapsuleV1], list[tuple[int, str]]]:
        provenance = exit_provenance(digest)
        capsules: list[ExperienceCapsuleV1] = []
        unbuilt: list[tuple[int, str]] = []
        for index, result in enumerate(evidence):
            try:
                capsules.append(capsule_from_scenario(
                    result, epoch=epoch, provenance=provenance, sequence=sequence + index))
            except ContractError as exc:
                unbuilt.append((index, str(exc)))
        return capsules, unbuilt


def _recorded(verdict: QuarantineVerdict) -> tuple[str, str, tuple[str, ...]]:
    return (verdict.capsule_id, str(verdict.bucket.value), tuple(verdict.reasons))
