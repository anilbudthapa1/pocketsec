"""G9.6's evidence: every winner taken to a successor package, rolled back, and handed over.

For each distinct search winner: DAEDALUS ``synthesize`` -> ``build_successor`` -> Stage 9's
own lab :class:`CandidateRegistry` install then rollback (the restored parent must score the
held-out split byte-identically to the digest the package carries) -> ``tampered_successor``
(four tamperings, four refusals) -> :meth:`Stage6Exit.hand_over` on a LAB gateway.

The lab gateway is a real Stage 6 ``QuarantineGateway`` bound to ``genesis_state``, built here
because the harness is the one place allowed to construct one (spec §2.3; the Stage 7 lab
precedent, ADR-0061). This module never calls ``admit``: ``successor/stage6_exit.py`` is the
one door (ADR-0081). The verdicts come back verbatim and are only recorded; nothing here
reads a bucket to decide anything, and G9.7 checks that by AST.

The rollback parent is the Φ-oracle: every successor would replace the zero-parameter
incumbent, so rolling back restores it (ADR-0088). A successor that IS the Φ-oracle (or scores
identically to it) makes that rollback unfalsifiable, so the evidence also records what the
registry held after install and after rollback, and G9.6 counts such a rollback as vacuous
(S9-R5, S9-FC-05). Rollback is proven only inside Stage 9's
lab registry: Stage 6 has no candidate kind that executes a genome (B9-2).
"""

from __future__ import annotations

from collections.abc import Sequence

from pocketsec.stage1.epoch.model import Epoch, SystemIdentity
from pocketsec.stage1.pipeline import ScenarioResult
from pocketsec.stage6.capsule.quarantine import QuarantineGateway
from pocketsec.stage6.fossils.lineage import KnowledgeLineageDAG
from pocketsec.stage6.memory.semantic import genesis_state
from pocketsec.stage6.provenance.ledger import ProvenanceLedger
from pocketsec.stage9.daedalus.synthesizer import synthesize
from pocketsec.stage9.gate_build import need, transformed
from pocketsec.stage9.gate_state import Stage9GateContext, SuccessorEvidence
from pocketsec.stage9.genome.computational import ComputationalGenomeV1
from pocketsec.stage9.genome.expressibility import phi_oracle_genome
from pocketsec.stage9.ontogenesis.fitness import (
    EvaluationSuite,
    FitnessRecord,
    scores_digest,
    session_scores,
)
from pocketsec.stage9.renormalization.laboratory import decide, fpr_threshold
from pocketsec.stage9.successor.proof_carrying import (
    CandidateRegistry,
    build_successor,
    tampered_successor,
)
from pocketsec.stage9.successor.stage6_exit import MAX_EXIT_CAPSULES, Stage6Exit
from pocketsec.stage9.symmetry.suite import invariance

__all__ = ["LAB_IDENTITY", "counterexamples", "hand_over_successors", "lab_gateway"]

#: The lab host every gate capsule is attributed to. Not a real host (spec §6.1).
LAB_IDENTITY = SystemIdentity(kernel_id="k-stage9-gate-lab")


def lab_gateway() -> QuarantineGateway:
    """A real Stage 6 gateway over genesis state, owned by this gate run only."""
    gateway = QuarantineGateway(ledger=ProvenanceLedger(), lineage=KnowledgeLineageDAG())
    state = genesis_state(identity=LAB_IDENTITY)
    gateway.bind_trusted_view(lambda: state)
    return gateway


def counterexamples(
    genome: ComputationalGenomeV1, record: FitnessRecord, heldout: EvaluationSuite
) -> tuple[str, ...]:
    """Sample ids whose decision the worst variant flipped, at a clean benign FPR-0.05 cut."""
    clean = heldout.clean.dataset
    worst = next(
        (v.dataset for v in heldout.attacked if v.key.attack_id == record.worst_variant), None
    )
    if worst is None:  # the clean split is the worst case: nothing was flipped by an attack
        return ()
    scores = session_scores(genome, clean)
    benign = [s for s, sample in zip(scores, clean.samples, strict=True) if sample.label == 0]
    threshold = fpr_threshold(benign)
    before = dict(zip((s.sample_id for s in clean.samples), decide(scores, threshold), strict=True))
    after = dict(
        zip(
            (s.sample_id for s in worst.samples),
            decide(session_scores(genome, worst), threshold),
            strict=True,
        )
    )
    return tuple(sorted(sid for sid, decision in before.items() if after.get(sid) != decision))


def _evidence(flipped: Sequence[str], results: Sequence[ScenarioResult]) -> list[ScenarioResult]:
    """The counterexample sessions first, then the rest, in held-out order (<= 8 are used)."""
    by_id = {f"{r.scenario.name}-{i:04d}": r for i, r in enumerate(results)}
    first = [by_id[sid] for sid in flipped if sid in by_id]
    chosen = {id(r) for r in first}
    return first + [r for r in results if id(r) not in chosen and r.transitions]


def _one(
    ctx: Stage9GateContext,
    genome: ComputationalGenomeV1,
    train: FitnessRecord,
    held: FitnessRecord,
    exit_door: Stage6Exit,
    sequence: int,
) -> SuccessorEvidence:
    heldout = need(ctx.heldout, "held-out suite")
    clean = heldout.clean.dataset
    parent = phi_oracle_genome()
    parent_digest = scores_digest(session_scores(parent, clean))
    flipped = counterexamples(genome, held, heldout)
    invariants = [
        invariance(genome, clean, data, t) for t, data in transformed(ctx, train=False).items()
    ]
    measured = next((m for m in ctx.measurements if m.genome_digest == genome.digest), None)
    synth = synthesize(genome, clean)
    successor = build_successor(
        synth,
        train=train,
        heldout=held,
        parent=parent,
        parent_scores_digest=parent_digest,
        counterexamples=flipped,
        invariance=invariants,
        measured=measured,
        experiment_id=None,
        base_rate=heldout.base_rate,
    )
    registry = CandidateRegistry()
    receipt_in = registry.install(successor)
    installed = registry.active()
    restored = registry.rollback(receipt_in)
    after_rollback = registry.active()
    evidence = _evidence(flipped, ctx.heldout_results)
    epoch = Epoch(epoch_id=1, identity=LAB_IDENTITY, key=LAB_IDENTITY.key(), opened_at_ns=0)
    receipt = exit_door.hand_over(successor, evidence=evidence, epoch=epoch, sequence=sequence)
    return SuccessorEvidence(
        genome_digest=genome.digest,
        successor_digest=successor.content_digest,
        restored_digest=restored.digest,
        restored_scores_digest=scores_digest(session_scores(restored, clean)),
        parent_scores_digest=successor.rollback_artifact.parent_scores_digest,
        tampering=tampered_successor(successor),
        offered=receipt.offered,
        capsules_built=min(len(evidence), MAX_EXIT_CAPSULES) - len(receipt.unbuilt),
        verdicts=receipt.verdicts,
        unit_checks_passed=synth.unit_checks_passed,
        pcb_expressible=synth.pcb.expressible,
        pcb_reason=synth.pcb.reason,
        installed_digest=receipt_in.installed_digest,
        installed_scores_digest=(
            "" if installed is None else scores_digest(session_scores(installed, clean))
        ),
        parent_digest=parent.digest,
        active_after_install=None if installed is None else installed.digest,
        active_after_rollback=None if after_rollback is None else after_rollback.digest,
    )


def hand_over_successors(ctx: Stage9GateContext) -> list[SuccessorEvidence]:
    """One :class:`SuccessorEvidence` per distinct winner, through one lab gateway."""
    exit_door = Stage6Exit(lab_gateway())
    out: list[SuccessorEvidence] = []
    for index, (genome, train, held) in enumerate(ctx.winners.values()):
        # capsule i of successor k gets sequence 1 + k*MAX + i: distinct, never reused
        out.append(_one(ctx, genome, train, held, exit_door, 1 + index * MAX_EXIT_CAPSULES))
    return out
