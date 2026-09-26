"""Where the trap dies, and whether its placement decides it (review finding F1, 2026-09-27).

The lead's trap is a hypothesis true on TRAIN by construction and false held out. The corpus
places it on a bare ``fork`` (SPAWN), a NON-escalating step. The review showed the in-loop kill
(``refuted_at=challenge:COUNTERFACTUAL_INVARIANCE``) came from DECOY_INSERTION adding
non-escalating donor steps, which a SINGLE over a non-escalating step matches: a vocabulary
artefact, not falsification. This script re-runs the trap twice on PLANTED content seed 0 with
the production-default ``RunConfig(seed=0)``:

* ``fork``        -- the authored, non-escalating trap (SINGLE(SPAWN));
* ``setuid uid 0`` -- the same trap placed on an ESCALATING step no family uses (relation
  SETUID, raised bit 1), which no decoy can ever match.

For each it prints the ``TrapOutcome`` of ``run_discovery``, the trap genome's agreement under
each PRESERVING relation (``_Run.invariance``, i.e. with the fix's decoy filter), and the
vault-alone probe. Run it with ``PYTHONPATH`` pointing at a pre-fix tree to see the old path.

Usage: ``PYTHONHASHSEED=0 python benchmarks/stage8/trap_placement.py``
"""

from __future__ import annotations

import time

from _common import loadavg

from pocketsec.stage1.labs.corpus import Behaviour
from pocketsec.stage8.genome.hypothesis import (
    Direction, GeneratorKind, GenomeProvenance, ObservationScope, ResidualType, genome_for,
)
from pocketsec.stage8.labs import discovery_corpus as dc
from pocketsec.stage8.labs import discovery_run as dr

TRAPS = (("fork (authored, non-escalating)", Behaviour("fork", {})),
         ("setuid uid 0 (escalating)", Behaviour("setuid", {"uid": "0"})))


def _trap_genome(mechanism):  # type: ignore[no-untyped-def]
    return genome_for(mechanism, direction=Direction.MALICIOUS,
                      scope=ObservationScope((), frozenset({ResidualType.OBSERVATION}), ()),
                      provenance=GenomeProvenance(GeneratorKind.SYMBOLIC_ENUMERATOR,
                                                  "sha256:" + "0" * 64, False, 0))


def main() -> None:
    for name, behaviour in TRAPS:
        dc.TRAP_BEHAVIOUR = behaviour
        corpus = dc.build_discovery_corpus(arm=dc.CorpusArm.PLANTED, seed=0)
        trap = corpus.trap_mechanism
        config = dr.RunConfig(arm=dc.CorpusArm.PLANTED, seed=0)
        run = dr._Run(corpus, config, dr._Knobs(), None, None)
        bench = run.invariance_bench()
        genome = _trap_genome(trap)
        per_relation = {}
        for relation_id, pairs in bench:
            rate = run.invariance(genome, ((relation_id, pairs),)) if hasattr(run, "invariance") \
                else sum(genome.decides(a) == genome.decides(b) for a, b in pairs) / len(pairs)
            per_relation[relation_id] = None if rate is None else round(rate, 3)
        started = time.perf_counter()
        report = dr.run_discovery(corpus, config)
        seconds = time.perf_counter() - started
        probe = dr.probe_trap_at_holdout(corpus, seed=0)
        print(f"== trap on {name}: {trap.to_dsl()}")
        print(f"   invariance per PRESERVING relation (trap genome): {per_relation}")
        print(f"   run_discovery TrapOutcome: {report.trap}")
        print(f"   vault-alone probe: refuted={probe.refuted} refuted_at={probe.refuted_at}")
        print(f"   run wall {seconds:.1f} s at loadavg {loadavg()} (observed, never asserted)")


if __name__ == "__main__":
    main()
