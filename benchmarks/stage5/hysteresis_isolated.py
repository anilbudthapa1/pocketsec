"""The lease/hysteresis controller in isolation, against a single-threshold control.

Usage: ``python benchmarks/stage5/hysteresis_isolated.py [--record EXPERIMENT_ID]``

ADR-0049 records hysteresis as unmeasurable end to end: the corpus is single-shot and
the full planner never reaches an ACT. This measures the **mechanism** directly: the
real ``HysteresisController`` with ``DEFAULT_HYSTERESIS`` (enter 6.0, exit 3.0, dwell
120 s, cooldown 300 s, 3 cycles) versus a single threshold at 6.0 with no dwell, no
cooldown and no cycle cap (B8's rule), over three Phi sequences sampled every 30 s for
two hours. It says what the controller does to a belief trace; it says nothing about
whether any real host's belief trace looks like these.

Sequences (all synthetic):
  S1 oscillation — Phi alternates 5.5 / 6.5 every sample (a belief flapping on the line).
  S2 noise       — Phi uniform in [3.5, 8.5], ``random.Random(11)``.
  S3 step        — Phi 4.0 for 10 min, then 10.0 for the rest (a real escalation).
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import loadavg, record  # noqa: E402

from pocketsec.stage5.executor.identity import ManualClock  # noqa: E402
from pocketsec.stage5.executor.lease import (  # noqa: E402
    DEFAULT_HYSTERESIS,
    ControlDecision,
    HysteresisController,
)

STEP_SECONDS, SAMPLES, THRESHOLD = 30, 240, 6.0
TARGET = "sha256:" + "a" * 64


@dataclass
class _Receipt:
    """The four members ``note_outcome`` reads, and nothing else."""

    target_digest: str
    at: int
    rollback_attempted: bool = False

    def reached_host(self) -> bool:
        return True

    def committed_at(self) -> int:
        return self.at


def sequences() -> dict[str, list[float]]:
    rng = random.Random(11)
    return {
        "S1_oscillation": [5.5 if i % 2 == 0 else 6.5 for i in range(SAMPLES)],
        "S2_noise": [rng.uniform(3.5, 8.5) for _ in range(SAMPLES)],
        "S3_step": [4.0 if i < 20 else 10.0 for i in range(SAMPLES)],
    }


def controller(trace: list[float]) -> dict[str, object]:
    clock = ManualClock(at=0)
    ctl = HysteresisController(policy=DEFAULT_HYSTERESIS, clock=clock)
    active, acts, releases, escalations, first_act = False, 0, 0, 0, None
    for i, value in enumerate(trace):
        now = i * STEP_SECONDS
        decision = ctl.decide(target_digest=TARGET, phi_total=value, now=now,
                              active_lease=object() if active else None)  # type: ignore[arg-type]
        if decision is ControlDecision.ACT:
            ctl.note_outcome(_Receipt(TARGET, now))  # type: ignore[arg-type]
            active, acts = True, acts + 1
            first_act = now if first_act is None else first_act
        elif decision is ControlDecision.RELEASE:
            active, releases = False, releases + 1
        elif decision is ControlDecision.ESCALATE:
            escalations += 1
    return {"acts": acts, "releases": releases, "escalate_samples": escalations,
            "first_act_seconds": first_act, "active_at_end": active}


def single_threshold(trace: list[float]) -> dict[str, object]:
    active, acts, releases, first_act = False, 0, 0, None
    for i, value in enumerate(trace):
        if not active and value >= THRESHOLD:
            active, acts = True, acts + 1
            first_act = i * STEP_SECONDS if first_act is None else first_act
        elif active and value < THRESHOLD:
            active, releases = False, releases + 1
    return {"acts": acts, "releases": releases, "escalate_samples": 0,
            "first_act_seconds": first_act, "active_at_end": active}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--record", metavar="EXPERIMENT_ID")
    args = parser.parse_args()
    before = loadavg()
    out = {name: {"hysteresis": controller(trace), "single_threshold": single_threshold(trace)}
           for name, trace in sequences().items()}
    for name, row in out.items():
        print(f"{name}: {json.dumps(row)}")
    after = loadavg()
    print(f"loadavg before {before} after {after}")
    if args.record:
        digest = __import__("hashlib").sha256(json.dumps(sequences()).encode()).hexdigest()
        record(
            experiment_id=args.record,
            title="Hysteresis controller in isolation vs a single threshold, three Phi traces",
            slot_name="stage5-hysteresis-controller",
            dataset_name="stage5-hysteresis-traces-seed11",
            dataset_version="stage5-hysteresis-traces-v0.1.0",
            dataset_sha256=digest,
            seeds={"noise": 11},
            notes=json.dumps(out) + "; mechanism in isolation, not an end-to-end result",
            payload={"loadavg_before": before, "loadavg_after": after, "results": out,
                     "policy": str(DEFAULT_HYSTERESIS), "step_seconds": STEP_SECONDS,
                     "samples": SAMPLES},
            command="PYTHONHASHSEED=0 .venv/bin/python benchmarks/stage5/hysteresis_isolated.py",
        )


if __name__ == "__main__":
    main()
