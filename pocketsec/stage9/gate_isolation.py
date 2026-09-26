"""G9.10(b): is the endpoint still useful with Stages 7-9 completely absent?

"The final endpoint remains useful with Stage 7-9 networking/research completely absent"
(phase file §69). Absence is made real, not assumed: a fresh interpreter installs a
``sys.meta_path`` finder that raises on any ``pocketsec.stage7``, ``stage8`` or ``stage9``
import, then computes the Φ-oracle's held-out AP through Stage 2's own
``gate_measures.compile_split`` and ``max(features[73])``. That figure must equal the one this
process computes from the gate's own held-out split to 1e-12, and exceed the base rate.

``subprocess`` is used here and nowhere else in Stage 9 except the other ``gate*.py`` files
(spec §2.2's declared exemption); the child runs a fixed program with two integer arguments.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

from pocketsec.stage0.benchmark.security_metrics import average_precision
from pocketsec.stage0.gate import REPO_ROOT
from pocketsec.stage9.gate_build import need
from pocketsec.stage9.gate_state import IsolationResult, Stage9GateContext

__all__ = ["CHILD_PROGRAM", "PHI_INDEX", "REFUSED_PACKAGES", "measure_isolation"]

#: The Φ-oracle's squashed-|ΔΦ| slot (``PHI_SQUASHED_FEATURE_INDEX``), restated so the child
#: needs nothing from Stage 9; a drift is caught because both figures must agree.
PHI_INDEX = 73
REFUSED_PACKAGES = ("pocketsec.stage7", "pocketsec.stage8", "pocketsec.stage9")
#: Generous: the child compiles one 240-session split on a contended host.
_TIMEOUT_SECONDS = 900

CHILD_PROGRAM = r"""
import importlib.abc, json, sys
REFUSED = ("pocketsec.stage7", "pocketsec.stage8", "pocketsec.stage9")
class Refuse(importlib.abc.MetaPathFinder):
    hits = 0
    def find_spec(self, name, path=None, target=None):
        if any(name == p or name.startswith(p + ".") for p in REFUSED):
            Refuse.hits += 1
            raise ImportError(f"{name} is absent in this process (G9.10)")
        return None
sys.meta_path.insert(0, Refuse())
try:
    import pocketsec.stage9
except ImportError:
    pass
from pocketsec.stage0.benchmark.security_metrics import average_precision
from pocketsec.stage2.gate_measures import compile_split
count, seed, index = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
split = compile_split("ambiguous", count=count, seed=seed)
labels = list(split.dataset.labels)
scores = [max(step.features[index] for step in s.steps) for s in split.dataset.samples]
loaded = sorted(m for m in sys.modules if any(m == p or m.startswith(p + ".") for p in REFUSED))
print(json.dumps({"ap": average_precision(labels, scores), "base_rate": sum(labels) / len(labels),
                  "refused": Refuse.hits, "loaded": loaded}))
"""


def _in_process_ap(ctx: Stage9GateContext) -> tuple[float | None, float]:
    dataset = need(ctx.heldout, "held-out suite").clean.dataset
    scores = [max(step.features[PHI_INDEX] for step in s.steps) for s in dataset.samples]
    labels = list(dataset.labels)
    return average_precision(labels, scores), sum(labels) / len(labels)


def measure_isolation(ctx: Stage9GateContext) -> IsolationResult:
    """Run the child; compare its AP with this process's. Any child failure is recorded."""
    in_process, base_rate = _in_process_ap(ctx)
    cfg = ctx.config
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            CHILD_PROGRAM,
            str(cfg.count),
            str(cfg.heldout_seed),
            str(PHI_INDEX),
        ],
        capture_output=True,
        text=True,
        timeout=_TIMEOUT_SECONDS,
        cwd=REPO_ROOT,
        env={**os.environ, "PYTHONHASHSEED": "0"},
        check=False,
    )
    if completed.returncode != 0:
        tail = completed.stderr.strip().splitlines()[-3:]
        return IsolationResult(
            None,
            in_process,
            base_rate,
            completed.returncode,
            0,
            (),
            f"child failed: {' | '.join(tail)}",
        )
    payload = json.loads(completed.stdout.strip().splitlines()[-1])
    loaded = payload["loaded"]
    return IsolationResult(
        subprocess_ap=payload["ap"],
        in_process_ap=in_process,
        base_rate=payload["base_rate"],
        returncode=completed.returncode,
        refused_imports=int(payload["refused"]),
        loaded=tuple(loaded),
        detail=(
            f"Stage 7-9 modules loaded in the child: {loaded or 'none'}; the finder refused "
            f"{payload['refused']} import attempt(s); in-process base rate {base_rate}"
        ),
    )
