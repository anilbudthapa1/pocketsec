"""Does the NAIVE control (no vault, no Bonferroni) select the trap? Checked by digest."""
from dataclasses import replace

from _common import loadavg

from pocketsec.stage8.labs.discovery_corpus import CorpusArm, build_discovery_corpus
from pocketsec.stage8.labs.discovery_run import RunConfig, run_discovery

c = build_discovery_corpus(arm=CorpusArm.PLANTED, seed=0)
r = run_discovery(c, replace(RunConfig(arm=CorpusArm.PLANTED, seed=0),
                             holdout_discipline=False, bonferroni=False))
d = c.trap_mechanism.digest()
sel = [r.ledger.genome(h).proposed_mechanism for h in r.survived]
print("loadavg", loadavg(), "NAIVE selected", len(sel), "trap among selected:",
      any(m.digest() == d for m in sel), "trap DSL", c.trap_mechanism.to_dsl())
