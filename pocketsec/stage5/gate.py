"""The Stage 5 acceptance gate (``docs/stage-5-spec.md`` §6), as an executable check.

Fifteen criteria, one per bullet of architecture §45, each evaluated by running the real
subsystems rather than inspecting a document. Like every earlier stage's gate this is
code: ``pocketsec-stage5 gate`` exits non-zero if any criterion fails.

Four things about this gate are worth stating before anyone reads a result off it.

**It is expected to fail, and its failures are Stage 5's findings.** The spec said so in
advance (§6.1): G5.7 and G5.11 fail *by construction* while the only host is the
simulated one, because a rollback or recovery rate measured against a simulator this wave
wrote is a property of that simulator. A 15/15 from this gate would be evidence that a
check cannot fail (§4.9 Rule B), not evidence of success.

**This is the only module outside ``executor/`` and ``recovery/`` that names
``TransactionalExecutor``.** Spec §5.1 rule 4 permits those two directories, and spec §6
G5.2(a) requires the gate to read ``get_type_hints(TransactionalExecutor.execute)`` —
the two cannot both hold, so ADR-0041 names this file as the third and last permitted
site. The labs never construct an executor: they are *handed* one through the factories
below, and ``tests/test_stage5_boundary.py`` asserts that nothing but ``cli.py`` and the
``gate_*`` modules imports this module, so the permission does not leak into runtime.

**No check reads a document to decide a mechanism question.** Two read files and both
are *about* files: G5.13's subject is the assurance table and the findings language,
and G5.15's subject is the findings document and the ledgers. Everything else runs the
subsystem it names, and every check has a non-compliant input that makes it fail
(``tests/test_stage5_gate.py::test_g5_*``, one per check, §4.9 Rule B).

**Nothing measured here is a detection result, and no timing is a device figure.** Every
corpus is synthetic, the harm tables share an author with the planner (§9.2), and every
in-simulator figure is a property of ``SimulatedHost``. ``/proc/loadavg`` is recorded
beside every timing because a Stage 2 gate saw 7x inflation on this contended host.

This gate **never** appends to ``experiments/registry.jsonl`` (spec §2.7). Ablation rows
are recorded in a temporary registry, and G5.1 and G5.15 assert the real ledger is
byte-identical before and after the run.
"""

from __future__ import annotations

import hashlib
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pocketsec.stage0.gate import REPO_ROOT, GateReport
from pocketsec.stage5 import gate_construction as construction
from pocketsec.stage5 import gate_measured as measured
from pocketsec.stage5 import gate_runtime as runtime
from pocketsec.stage5.executor.journal import RollbackJournal
from pocketsec.stage5.executor.lease import LeaseRegistry
from pocketsec.stage5.executor.transactional import TransactionalExecutor, TransactionReceipt
from pocketsec.stage5.executor.verify import PostconditionProbe
from pocketsec.stage5.governor import ResourceGovernor
from pocketsec.stage5.labs.baselines import (
    BASELINES,
    REFERENCE_ARM_ID,
    BaselineOutcome,
    BaselineRig,
    reference_arm,
    run_arm,
)
from pocketsec.stage5.labs.response_corpus import ResponseCase, build_response_corpus
from pocketsec.stage5.resources import loadavg
from pocketsec.stage5.sentinel.kernel import SentinelKernel

__all__ = [
    "CORPUS_COUNT",
    "CORPUS_SEED",
    "EXPERIMENT_ID",
    "REGISTRY_PATH",
    "STAGE5_HYPOTHESIS",
    "RecordedAction",
    "Stage5GateContext",
    "TransactionalExecutor",
    "assemble_executor",
    "executor_for_race",
    "executor_for_rig",
    "registry_digest",
    "run_gate",
]

#: Spec §2.8: Stage 5 mints no hypothesis and uses the grammar's own ``BASE`` token.
STAGE5_HYPOTHESIS = "BASE"
EXPERIMENT_ID = "PS-S5-20260925-BASE-safe-gate-0001"

#: The shared corpus every comparison runs on. Twenty cases is the size every package
#: measured against, so a figure in the findings can be traced to one corpus digest.
CORPUS_COUNT = 20
CORPUS_SEED = 11

REGISTRY_PATH = REPO_ROOT / "experiments" / "registry.jsonl"


def registry_digest(path: Path = REGISTRY_PATH) -> str | None:
    """sha256 of the real experiment ledger's bytes, or ``None`` when it does not exist."""
    if not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


# --- the privileged factories: the only place an executor is assembled -----------------


def executor_for_rig(rig: BaselineRig) -> TransactionalExecutor:
    """The real executor for one benchmark rig, wired from the rig's own components.

    Every component comes from the rig, which ``labs.baselines.build_rig`` builds from
    ``FROZEN_CONSTITUTION`` — ``ResponseConstitution.__post_init__`` refuses anything
    weaker, so no permissive kernel can be passed through here.
    """
    return TransactionalExecutor(
        kernel=rig.kernel,
        host=rig.host,
        journal=rig.journal,
        gate=rig.gate,
        governor=rig.governor,
        leases=rig.leases,
        probe=rig.probe,
        clock=rig.clock,
        tokens=rig.tokens,
    )


def assemble_executor(
    *,
    host: Any,
    clock: Any,
    invariants: Any,
    tokens: Any,
    leases: LeaseRegistry | None = None,
) -> TransactionalExecutor:
    """A real executor around ``host`` on the frozen constitution, fresh everything else.

    For the gate's own lab rigs (G5.7, G5.10, G5.11) and the TOCTOU races. The kernel
    is always built from ``FROZEN_CONSTITUTION``; there is no parameter through which a
    weaker one could arrive.
    """
    from pocketsec.stage5.constitution.invariants import FROZEN_CONSTITUTION
    from pocketsec.stage5.evidence.preservation_gate import (
        DEFAULT_RETENTION,
        EvidencePreservationGate,
    )

    return TransactionalExecutor(
        kernel=SentinelKernel(constitution=FROZEN_CONSTITUTION, invariants=invariants, clock=clock),
        host=host,
        journal=RollbackJournal(),
        gate=EvidencePreservationGate(policy=DEFAULT_RETENTION, invariants=invariants),
        governor=ResourceGovernor(),
        leases=leases if leases is not None else LeaseRegistry(clock=clock),
        probe=PostconditionProbe(invariants=invariants),
        clock=clock,
        tokens=tokens,
    )


def executor_for_race(setup: Any) -> TransactionalExecutor:
    """The real executor for one ``labs.toctou`` race, around the racing host adapter."""
    return assemble_executor(
        host=setup.host, clock=setup.clock, invariants=setup.invariants, tokens=setup.tokens
    )


@dataclass(frozen=True, slots=True)
class RecordedAction:
    """One transaction an arm ran, with the rig it ran on. Observation only."""

    arm: str
    rig: BaselineRig
    executor: TransactionalExecutor
    operator: Any
    token: Any
    receipt: TransactionReceipt


class _RecordingExecutor:
    """Forwards to the real executor and keeps each receipt. It decides nothing."""

    __slots__ = ("_arm", "_inner", "_rig", "_sink")

    def __init__(
        self, *, arm: str, rig: BaselineRig, inner: TransactionalExecutor, sink: list[Any]
    ) -> None:
        self._arm, self._rig, self._inner, self._sink = arm, rig, inner, sink

    def execute(self, operator: Any, token: Any, *, resolution: Any) -> TransactionReceipt:
        receipt = self._inner.execute(operator, token, resolution=resolution)
        self._sink.append(
            RecordedAction(self._arm, self._rig, self._inner, operator, token, receipt)
        )
        return receipt

    def reclaim_settled_state(self) -> int:
        """Forwarded, because the lease sweeper calls it after an undo commits.

        Without it the sweeper raised ``AttributeError`` inside ``run_arm`` and the whole
        gate crashed before any check ran; a wrapper that records must not also narrow
        the interface the sweeper is written against.
        """
        return self._inner.reclaim_settled_state()


def _recording_factory(arm: str, sink: list[RecordedAction]) -> Any:
    def build(rig: BaselineRig) -> _RecordingExecutor:
        return _RecordingExecutor(arm=arm, rig=rig, inner=executor_for_rig(rig), sink=sink)

    return build


def _corpus_digest(cases: Sequence[ResponseCase]) -> str:
    from pocketsec.stage5.labs.response_corpus import corpus_digest

    return corpus_digest(cases)


@dataclass
class Stage5GateContext:
    """One shared corpus run, so fifteen checks do not replay it fifteen times."""

    corpus: tuple[ResponseCase, ...]
    corpus_sha256: str
    outcomes: Mapping[str, BaselineOutcome]
    actions: tuple[RecordedAction, ...]
    registry_before: str | None
    scratch: Path
    loadavg_at_build: tuple[float, float, float]
    notes: list[str] = field(default_factory=list)

    @classmethod
    def build(cls, *, count: int = CORPUS_COUNT, seed: int = CORPUS_SEED) -> Stage5GateContext:
        before = registry_digest()
        corpus = build_response_corpus(count=count, seed=seed)
        sink: list[RecordedAction] = []
        policies = {**BASELINES, REFERENCE_ARM_ID: reference_arm}
        outcomes = {
            arm: run_arm(
                policy, corpus, baseline_id=arm, build_executor=_recording_factory(arm, sink)
            )
            for arm, policy in policies.items()
        }
        return cls(
            corpus=corpus,
            corpus_sha256=_corpus_digest(corpus),
            outcomes=outcomes,
            actions=tuple(sink),
            registry_before=before,
            scratch=Path(tempfile.mkdtemp(prefix="pocketsec-stage5-gate-")),
            loadavg_at_build=loadavg(),
        )

    def actions_of(self, arm: str) -> tuple[RecordedAction, ...]:
        return tuple(action for action in self.actions if action.arm == arm)


def run_gate(ctx: Stage5GateContext | None = None) -> GateReport:
    """Evaluate all fifteen Stage 5 acceptance criteria against one shared run."""
    ctx = ctx if ctx is not None else Stage5GateContext.build()
    return GateReport(
        checks=(
            construction.check_frozen_upstream(ctx),
            construction.check_typed_operators_only(ctx),
            construction.check_sentinel_independent_denial(),
            construction.check_no_text_grants_authority(ctx),
            construction.check_identity_revalidated(ctx),
            runtime.check_interventions_leased(ctx),
            runtime.check_rollback_reliability(ctx),
            runtime.check_evidence_and_invariants(ctx),
            measured.check_multi_world_collateral(ctx),
            runtime.check_post_action_verification(),
            runtime.check_safe_recovery(ctx),
            measured.check_bounded_under_load(ctx),
            measured.check_assurance_table(),
            measured.check_ablation_survival(ctx),
            measured.check_no_novelty_claim(ctx),
        )
    )
