"""Register an already-produced Stage 7 measurement JSON in the experiment ledger.

The measurement scripts in this directory write ``results/*.json`` and never touch the ledger
unless asked. This is the explicit act that appends one digest-chained row per result
(``ExperimentRegistry.register`` refuses a reused id). Run it ALONE: two concurrent writers
can fork the chain, and a write during a ``pocketsec-stage7 gate`` run breaks G7.11's
byte-identical-ledger clause for a reason that is not the gate's.

    python benchmarks/stage7/register.py EXPERIMENT_ID RESULT_JSON "TITLE" "PRODUCING COMMAND"
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import record  # noqa: E402


def _digest(payload: dict, corpus_seed: int) -> str:  # type: ignore[type-arg]
    """The held-out dataset's sha256 when the payload carries it, else the corpus digest."""
    if payload.get("dataset_sha256"):
        value = str(payload["dataset_sha256"])
        return value if value.startswith("sha256:") else "sha256:" + value
    from _common import corpus_digest

    from pocketsec.stage7.labs.fleet_corpus import build_fleet_corpus

    return corpus_digest(build_fleet_corpus(seed=corpus_seed))


def main() -> int:
    experiment_id, path, title, command = sys.argv[1:5]
    payload = json.loads(Path(path).read_text())
    seeds = {"corpus": int(payload.get("corpus_seed", 7)), "fleet": int(payload.get("seed", 0))}
    record(experiment_id=experiment_id, hypothesis="H8", title=title,
           slot_name="stage7-antibody-set", dataset_name="stage7-fleet-corpus",
           dataset_version="stage7-fleet-corpus-v0.1.0",
           dataset_sha256=_digest(payload, seeds["corpus"]),
           seeds=seeds, notes=json.dumps({"source": Path(path).name, "synthetic": True}),
           payload=payload, command=command)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
