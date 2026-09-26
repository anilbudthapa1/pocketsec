"""Stage 7 — does the exported COARSE context fingerprint the exporting host?

The export field table (``privacy/distiller.py:EXPORT_FIELD_TABLE``) declares three coarse
context fields on every capsule: ``source_context_sketch.role``,
``source_context_sketch.family_profile`` and ``epoch_context.software_epoch`` (an UNKEYED hash
of kernel id and package digest). The contributor pseudonym already links one host's capsules
to each other by design; the question here is different: **without** the pseudonym, how many
hosts share the coarse tuple a capsule carries (its anonymity set)? An anonymity set of 1
means the coarse context alone singles the host out within the fleet.

It reads the capsules the simulated honest hosts actually export
(``SimulatedFleet.local_capsules``), so every figure is over real compiled wire objects. The
fleet is simulated and synthetic: host software images in the corpus are generated, so the
figures describe this generator's diversity, not a real fleet's.

    PYTHONHASHSEED=0 python benchmarks/stage7/linkability.py [--corpus-seed 7]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import RESULTS_DIR, loadavg  # noqa: E402

from pocketsec.stage7.labs.fleet_corpus import build_fleet_corpus  # noqa: E402
from pocketsec.stage7.labs.simulated_fleet import (  # noqa: E402
    AdversaryArm,
    FleetSpec,
    SimulatedFleet,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus-seed", type=int, default=7)
    args = parser.parse_args()
    corpus = build_fleet_corpus(seed=args.corpus_seed)
    fleet = SimulatedFleet(corpus, FleetSpec(arm=AdversaryArm.NONE, seed=0))
    per_host: dict[str, set[tuple]] = defaultdict(set)  # type: ignore[type-arg]
    capsules = 0
    for host in corpus.hosts:
        for c in fleet.local_capsules(host.host_id):
            capsules += 1
            per_host[host.host_id].add((
                str(c.source_context_sketch.role), c.epoch_context.software_epoch,
                tuple(c.source_context_sketch.family_profile), str(c.epoch_context.visibility)))
    exporting = sorted(per_host)
    out: dict = {"corpus_seed": args.corpus_seed, "hosts": len(corpus.hosts),  # type: ignore[type-arg]
                 "exporting_hosts": len(exporting), "capsules": capsules, "loadavg": loadavg()}
    projections = {
        "role": lambda t: t[:1],
        "software_epoch": lambda t: t[1:2],
        "role+software_epoch": lambda t: t[:2],
        "role+family_profile": lambda t: (t[0], t[2]),
        "role+software_epoch+family_profile+visibility": lambda t: t,
    }
    for name, proj in projections.items():
        holders: dict[tuple, set[str]] = defaultdict(set)  # type: ignore[type-arg]
        for host_id, tuples in per_host.items():
            for t in tuples:
                holders[proj(t)].add(host_id)
        # a host's anonymity set = smallest set of hosts sharing any tuple it exports
        smallest = {h: min(len(holders[proj(t)]) for t in per_host[h]) for h in exporting}
        out[name] = {
            "distinct_values": len(holders),
            "hosts_singled_out": sum(1 for v in smallest.values() if v == 1),
            "min_anonymity_set_histogram": dict(sorted(Counter(smallest.values()).items())),
        }
        print(f"{name:<48} distinct {len(holders):>3}  hosts with anonymity set 1: "
              f"{out[name]['hosts_singled_out']}/{len(exporting)}  histogram "
              f"{out[name]['min_anonymity_set_histogram']}")
    epochs = {h.host_id: (h.identity.kernel_id, h.identity.package_digest) for h in corpus.hosts}
    out["distinct_software_images_in_corpus"] = len(set(epochs.values()))
    print(f"distinct (kernel_id, package_digest) in the corpus: "
          f"{out['distinct_software_images_in_corpus']} over {len(epochs)} hosts; exporting hosts "
          f"{len(exporting)}; capsules {capsules}")
    path = RESULTS_DIR / f"stage7-linkability-c{args.corpus_seed}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(out, indent=1, sort_keys=True, default=str) + "\n")
    print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
