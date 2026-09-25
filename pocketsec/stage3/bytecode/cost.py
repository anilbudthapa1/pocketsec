"""What one PCB program costs, split between verification and execution.

This module exists because two ratios were published without one. The findings
document carried `CellVM.run / CellVM._execute` and
`CellVM.run / a handwritten Python function` in prose, cited `verifier.py` for a
"2.9-4.9x band" that file does not report, and named no code that produced
either number. Its own Corrections table said the fix was to land a producer
here or withdraw the figures. This is the producer.

Three paths are timed over the same frames in the same process:

* :meth:`CellVM.run` — the shipped contract. It verifies on every call, which is
  the whole point of D3.6: a program is re-checked before it is trusted, never
  marked "already verified".
* :meth:`CellVM._execute` — the interpreter alone, given the decoding ``verify``
  already produced. Private, and reached through
  :class:`pocketsec.stage3.bytecode.vm.CellVM` on purpose: the comparison is
  *within* the shipped object, so the ratio says what verification costs rather
  than what a different implementation would cost.
* a handwritten Python function computing the same answer with no ISA, no
  verifier and no stack. The control for "is the bytecode layer worth anything at
  all", and it is meant to win on time.

**Absolute microseconds here are not device measurements.** This host is shared;
:func:`loadavg` is recorded beside every figure and only the within-run ratios
transfer. Best-of-N, never the mean, for the same reason
``labs/baselines.measure_microseconds`` uses it.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage3.bytecode.isa import DELTA_SLOTS, Instruction, Op, encode
from pocketsec.stage3.bytecode.verifier import verify_and_decode
from pocketsec.stage3.bytecode.vm import CellVM
from pocketsec.stage3.cells.operator import OperatorForm, OperatorProgram
from pocketsec.stage3.resources import loadavg

if TYPE_CHECKING:  # pragma: no cover - typing only
    from pocketsec.stage3.cells.frame import CellFrame

__all__ = [
    "HANDWRITTEN_CONTROL_SOURCE",
    "VmCostReport",
    "handwritten_clamp01",
    "measure_vm_cost",
    "phi_clamp_program",
]

#: Timing repetitions. Best-of-N, matching ``labs/baselines.TIMING_REPETITIONS``'s
#: convention: the minimum is the figure least polluted by unrelated load.
COST_REPETITIONS = 7

#: The control's source, carried in the report so a reader can see exactly what
#: the bytecode layer is being compared against rather than trusting a label.
HANDWRITTEN_CONTROL_SOURCE = (
    "def handwritten_clamp01(delta_phi: float) -> float: "
    "return 0.0 if delta_phi < 0.0 else (1.0 if delta_phi > 1.0 else delta_phi)"
)


def handwritten_clamp01(delta_phi: float) -> float:
    """The same answer the program computes, with no ISA, verifier or stack.

    Returns a bare float rather than a ``CellResult``, and that asymmetry is
    stated rather than hidden: the control does not carry evidence, does not
    report a delta and cannot abstain, so it is not a substitute for the VM. It is
    a floor on what the answer costs.
    """
    if delta_phi < 0.0:
        return 0.0
    return 1.0 if delta_phi > 1.0 else delta_phi


def phi_clamp_program() -> OperatorProgram:
    """``LOAD_DELTA; UPDATE_PHI; PRESERVE_EVIDENCE; RETURN_STATE``.

    The same four instructions ``labs/cell_path.phi_oracle_cell`` ships, so the
    ratio below is about the operator the stage actually measures elsewhere.
    """
    return OperatorProgram(
        form=OperatorForm.BYTECODE,
        words=encode(
            (
                Instruction(Op.LOAD_DELTA, DELTA_SLOTS.index("delta_phi")),
                Instruction(Op.UPDATE_PHI, 0),
                Instruction(Op.PRESERVE_EVIDENCE, 0),
                Instruction(Op.RETURN_STATE, 0),
            )
        ),
        table={},
        max_steps=4,
        max_state_bytes=320,
    )


@dataclass(frozen=True, slots=True)
class VmCostReport:
    """Three per-frame costs and the two ratios between them.

    Every field is ``float | None``. ``None`` is UNMEASURED and is never rendered
    as a small number: a path that could not be timed has no cost here, and the
    ratios that depend on it are ``None`` too.
    """

    frames: int
    repetitions: int
    run_us: float | None
    #: Named ``interpreter_us`` rather than ``execute_us``: the second token is in
    #: ``FORBIDDEN_AUTHORITY_FIELDS`` (ADR-0003), and the rule is broader than the
    #: harm here — a timing field grants nothing — but a rule with one exemption
    #: has none. ``CellResult.steps_taken`` was renamed for the same reason.
    interpreter_us: float | None
    handwritten_us: float | None
    loadavg: tuple[float, float, float]
    measured_by: str
    control_source: str = HANDWRITTEN_CONTROL_SOURCE

    def __post_init__(self) -> None:
        if self.frames < 1:
            raise ContractError("VmCostReport needs at least one frame to have timed")
        if ":" not in self.measured_by:
            raise ContractError(
                f"VmCostReport.measured_by must look like 'module:function', "
                f"got {self.measured_by!r}"
            )

    @property
    def run_over_interpreter(self) -> float | None:
        """What verifying on every call costs, as a multiple of executing."""
        return _ratio(self.run_us, self.interpreter_us)

    @property
    def run_over_handwritten(self) -> float | None:
        """What the whole bytecode layer costs, against the bare answer."""
        return _ratio(self.run_us, self.handwritten_us)

    def to_dict(self) -> dict[str, Any]:
        return {
            "frames": self.frames,
            "repetitions": self.repetitions,
            "run_us_per_frame": self.run_us,
            "interpreter_us_per_frame": self.interpreter_us,
            "handwritten_us_per_frame": self.handwritten_us,
            "run_over_interpreter": self.run_over_interpreter,
            "run_over_handwritten": self.run_over_handwritten,
            "loadavg": list(self.loadavg),
            "measured_by": self.measured_by,
            "control_source": self.control_source,
            "note": (
                "Absolute microseconds are not device measurements: this host is "
                "shared and the load average is recorded beside them. Only the two "
                "ratios transfer, and the handwritten control returns a bare float "
                "rather than a CellResult."
            ),
        }


def _ratio(numerator: float | None, denominator: float | None) -> float | None:
    if numerator is None or denominator is None or not denominator:
        return None
    return numerator / denominator


def _best_us(work: Callable[[], None], *, frames: int, repetitions: int) -> float | None:
    if frames < 1:
        return None
    best: float | None = None
    for _ in range(max(1, repetitions)):
        started = time.perf_counter()
        work()
        elapsed = time.perf_counter() - started
        best = elapsed if best is None else min(best, elapsed)
    return None if best is None else best / frames * 1e6


def measure_vm_cost(
    frames: Sequence[CellFrame],
    *,
    program: OperatorProgram | None = None,
    repetitions: int = COST_REPETITIONS,
    measured_by: str = "pocketsec.stage3.bytecode.cost:measure_vm_cost",
) -> VmCostReport:
    """Time ``run``, ``_execute`` and the handwritten control over ``frames``.

    ``_execute`` is given the decoding ``verify_and_decode`` already produced, once, outside
    the timed loop — which is exactly the split being measured. Nothing here
    caches a verification result into ``run``: the contract that a program is
    re-verified on every call is the thing whose cost is being reported, not a
    thing to optimise away for a better number.
    """
    if not frames:
        raise ContractError("measure_vm_cost needs at least one frame")
    operator = program or phi_clamp_program()
    vm = CellVM()
    verified = verify_and_decode(operator)
    if not verified.report.ok:
        raise ContractError(
            f"measure_vm_cost will not time a program that does not verify: "
            f"{list(verified.report.failures)}"
        )

    def _run() -> None:
        for frame in frames:
            vm.run(operator, frame)

    def _interpret() -> None:
        for frame in frames:
            vm._execute(
                verified.instructions, frame, verified.constants, verified.sets
            )

    def _control() -> None:
        for frame in frames:
            handwritten_clamp01(frame.delta_phi)

    count = len(frames)
    return VmCostReport(
        frames=count,
        repetitions=max(1, repetitions),
        run_us=_best_us(_run, frames=count, repetitions=repetitions),
        interpreter_us=_best_us(_interpret, frames=count, repetitions=repetitions),
        handwritten_us=_best_us(_control, frames=count, repetitions=repetitions),
        loadavg=loadavg(),
        measured_by=measured_by,
    )
