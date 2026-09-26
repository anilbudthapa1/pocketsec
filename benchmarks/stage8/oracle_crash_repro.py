"""Minimal reproduction of the ORACLE posterior defect found in this session.

``run_discovery`` on PLANTED content seed 0 with RANDOM_BASELINE generating 768 draws per cluster
and run seed 1 raises ``ContractError: restricting a posterior must keep some probability mass``
from ``oracle/information_gain.py`` (``Posterior.restricted``) via ``oracle/planner.py``
``_execute``; ``_execute`` in ``labs/discovery_run.py`` catches only ``WorkBudgetExceeded``, so
the whole research run aborts. The same config with ``oracle_policy=None`` completes.

Usage: ``PYTHONHASHSEED=0 python benchmarks/stage8/oracle_crash_repro.py``
"""

from __future__ import annotations

import functools
from dataclasses import replace

from _common import loadavg

import pocketsec.stage8.labs.discovery_run as dr
from pocketsec.stage8.genome.hypothesis import GeneratorKind
from pocketsec.stage8.labs.discovery_corpus import CorpusArm, build_discovery_corpus
from pocketsec.stage8.prometheus.generators import RandomGenerator

corpus = build_discovery_corpus(arm=CorpusArm.PLANTED, seed=0)
config = dr.RunConfig(arm=CorpusArm.PLANTED, seed=1, generators=(GeneratorKind.RANDOM_BASELINE,))
dr.RandomGenerator = functools.partial(RandomGenerator, count=768)
print("loadavg", loadavg())
try:
    dr.run_discovery(corpus, config)
    print("completed: defect NOT reproduced")
except Exception as exc:  # noqa: BLE001 - the point is to show what escapes
    print(f"RAISED {type(exc).__module__}.{type(exc).__name__}: {exc}")
report = dr.run_discovery(corpus, replace(config, oracle_policy=None))
print(f"oracle_policy=None: completed, registered {report.registered}, "
      f"reproduced {len(report.reproduced)}, work units {report.governor.spent}")
