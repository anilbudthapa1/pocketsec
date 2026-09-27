"""Demo alerts: a few SYNTHETIC Stage 4 incidents, driven through the real engine, fast.

What this module is FOR: ``pocketsec-chat demo`` needs real alerts to explain, and
there is no real telemetry yet. So it builds Stage 4's synthetic incident corpus,
replays a handful of incidents through Stage 1 and the LUCID engine exactly as the
Stage 4 gate does (``gate_criteria.drive_engine``), and captures each run into the
alert handoff. Every alert it returns is marked ``synthetic=True``.

Why not ``Stage4GateContext.build()``: it also runs the dropped-telemetry arm and every
baseline, which is the wrong cost for a chat demo. Measured on this machine (see
``docs/assistant.md``) the path below is a couple of seconds.

The one approximation, stated: the visibility model is fitted on this small corpus
(``DEMO_CORPUS_COUNT`` incidents, half fitted, half held out) rather than on the gate's
sixty, so the shadow regions an alert reports can differ from a full gate run. The
incidents, their transitions and their evidence digests are the same as in the gate
corpus: ``build_incident_corpus`` is deterministic in (count, seed) for the shared
prefix of incident ids.

Incidents are picked by fixed index, not by label. Corpus ground truth
(``IncidentCase.truth``) is never read here or anywhere in the assistant.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from pocketsec.assistant.capture import handoff_from_run
from pocketsec.assistant.facts import AlertFacts
from pocketsec.assistant.handoff import facts_from_handoff
from pocketsec.stage1.observation.policy import AdaptiveObservationPolicy
from pocketsec.stage4.gate_criteria import CORPUS_SEED, drive_engine, measure_visibility_split
from pocketsec.stage4.labs.baseline_metrics import replay_corpus
from pocketsec.stage4.labs.incident_corpus import build_incident_corpus

__all__ = [
    "DEMO_CORPUS_COUNT",
    "DEMO_CORPUS_SEED",
    "DEMO_INDICES",
    "DEMO_PROVENANCE",
    "build_demo_alerts",
    "build_demo_handoffs",
    "build_demo_runs",
]

#: The gate's own seed (``gate_criteria.CORPUS_SEED``), reused rather than chosen.
DEMO_CORPUS_SEED = CORPUS_SEED
#: Small enough to start in seconds; large enough to fit a visibility model on half.
DEMO_CORPUS_COUNT = 10
#: Which incidents become demo alerts. Fixed indices, chosen for variety of shape
#: (event counts, number of surviving explanations, horizon outcome), never by label.
DEMO_INDICES: tuple[int, ...] = (0, 1, 3, 6)

DEMO_PROVENANCE = (
    f"SYNTHETIC: Stage 4 build_incident_corpus(count={DEMO_CORPUS_COUNT}, "
    f"seed={DEMO_CORPUS_SEED}) replayed through Stage 1 and the LUCID engine"
)


@lru_cache(maxsize=1)
def build_demo_runs() -> tuple[Any, ...]:
    """The engine runs behind the demo alerts. Cached: one build per process."""
    cases = build_incident_corpus(count=DEMO_CORPUS_COUNT, seed=DEMO_CORPUS_SEED)
    model = measure_visibility_split(cases).model
    picked = [cases[index] for index in DEMO_INDICES]
    runs, _engine = drive_engine(
        replay_corpus(picked), model, observation=AdaptiveObservationPolicy()
    )
    return runs


def build_demo_handoffs() -> tuple[dict[str, Any], ...]:
    return tuple(
        handoff_from_run(run, synthetic=True, provenance=DEMO_PROVENANCE)
        for run in build_demo_runs()
    )


@lru_cache(maxsize=1)
def build_demo_alerts() -> tuple[AlertFacts, ...]:
    """The demo alerts as facts. Every one is ``synthetic=True``."""
    return tuple(facts_from_handoff(payload) for payload in build_demo_handoffs())
