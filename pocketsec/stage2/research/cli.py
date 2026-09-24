"""``python -m pocketsec.stage2.research.cli`` — the offline half of Stage 2.

``frontier``  fit the baseline suite and write the evidence the gate consumes
``report``    build the full D2.14 findings report, optionally registering it

Everything here may use numpy (ADR-0008) because none of it runs on an endpoint.
That is exactly why it is a separate entry point from ``pocketsec-stage2``: a
runtime module may never import research code, and
``tests/test_repository_structure.py`` enforces it by AST in both directions. So
the split is not stylistic. Research *measures* and writes plain data; the gate
*reads* that data and refuses it when its ``(corpus, count, seed)`` does not
match the split the gate itself ran. It is the Stage 0 hub/model boundary applied
to the acceptance gate.

``frontier`` fits nine baselines including four recurrent ones. Measured on this
host it takes minutes.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from typing import Any

from pocketsec.stage0.gate import REPO_ROOT
from pocketsec.stage2.dataset import Stage2Dataset, build_dataset
from pocketsec.stage2.gate import (
    FRONTIER_PATH,
    GATE_CORPUS,
    GATE_COUNT,
    TEST_SEED,
    TRAIN_SEED,
    FrontierEvidence,
    run_gate,
)
from pocketsec.stage2.research.baselines import build_baselines
from pocketsec.stage2.research.saturation import SHARED_EPOCHS, SHARED_HIDDEN, saturation_check
from pocketsec.stage2.research.sleeping_brain import sleeping_brain_report
from pocketsec.stage2.research.stage2_report import build_report

__all__ = ["main", "measure_frontier"]

_MODULE = "pocketsec.stage2.research.cli"

#: The three models the cost frontier is taken over: the zero-parameter scorer,
#: the order-free pooled control, and the accepted Stage 2 core. ``DTLConvModel``
#: is absent because its dilation-32 branch needs 64 padded steps and the
#: shortest ambiguous session has fewer; a model that cannot process the split is
#: reported missing, never imputed.
TIMED_MODELS: tuple[str, ...] = ("phi-oracle", "mlp-pooled", "tcn")


def measure_frontier(
    train: Stage2Dataset, test: Stage2Dataset, *, experiment_id: str | None = None
) -> FrontierEvidence:
    """Fit the baseline suite once and time the frontier models once.

    A fresh instance per measurement: ``fit`` continues training rather than
    restarting, so re-fitting a model that has already been fitted silently
    doubles its budget and invents an advantage for it.

    The returned evidence is **signed**: it carries a ``content_digest`` over its
    own payload and, when given one, the ``experiment_id`` of the registered run
    it belongs to. The gate refuses evidence without both, because three
    acceptance criteria are decided by this one gitignored file and a hand-written
    copy of it used to flip ADR-0010's rejected result to PASS (S2-AUTH-02).
    """
    verdict = saturation_check(train, test)
    timed = {
        model.name: model
        for model in build_baselines(hidden=SHARED_HIDDEN, epochs=SHARED_EPOCHS)
        if model.name in TIMED_MODELS
    }
    pareto = sleeping_brain_report(
        [timed[name] for name in TIMED_MODELS if name in timed], train, test
    )["pareto"]
    return FrontierEvidence(
        corpus=test.corpus,
        count=len(test),
        seed=test.seed,
        base_rate=test.base_rate,
        scores=dict(verdict.scores),
        degenerate=verdict.degenerate,
        reason=verdict.reason,
        best=verdict.best,
        best_model=verdict.best_model,
        median=verdict.median,
        spread=verdict.spread,
        order_free_baseline=verdict.order_free_baseline,
        phi_oracle=verdict.phi_oracle,
        pareto=dict(pareto),
        measured_by=f"{_MODULE}:measure_frontier",
        experiment_id=experiment_id,
    ).signed()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pocketsec-stage2-research", description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    sub = parser.add_subparsers(dest="command", required=True)
    frontier = sub.add_parser("frontier", help="measure the baseline suite for the gate")
    frontier.add_argument(
        "--gate",
        action="store_true",
        help="run the full acceptance gate with the fresh measurement",
    )
    report = sub.add_parser("report", help="build the D2.14 findings report")
    report.add_argument("--count", type=int, default=240, help="sessions per split")
    report.add_argument(
        "--register",
        action="store_true",
        help="append measured verdicts to experiments/registry.jsonl (append-only)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "frontier":
        return _frontier(as_json=args.json, gate=args.gate)
    return _report(as_json=args.json, count=args.count, register=args.register)


def _frontier_experiment(train: Stage2Dataset, test: Stage2Dataset) -> str:
    """Register this frontier measurement and return its experiment id.

    The frontier was the one Stage 2 measurement that never reached the
    append-only ledger, which is why a hand-written copy of its output file had
    no lineage to check (S2-AUTH-02). Re-measuring the same split reuses the row
    that already exists rather than appending a duplicate: the registry is a
    record of measurements, not of invocations.
    """
    import hashlib

    from pocketsec.stage0.experiments.ids import format_experiment_id, parse_experiment_id
    from pocketsec.stage0.experiments.registry import ExperimentRegistry

    registry = ExperimentRegistry(REPO_ROOT / "experiments" / "registry.jsonl")
    existing = tuple(registry.all())
    slot = f"frontier-{test.corpus}-{len(test)}-{test.seed}"
    for entry in existing:
        if entry.slot_name == slot:
            return entry.experiment_id

    used = {
        parse_experiment_id(entry.experiment_id).sequence
        for entry in existing
        if entry.experiment_id.startswith("PS-S2-")
    }
    experiment_id = format_experiment_id(
        stage=2, hypothesis="H8", slug="baseline-frontier", sequence=max(used, default=0) + 1
    )
    digest = hashlib.sha256(
        json.dumps(test.to_provenance(), sort_keys=True).encode("utf-8")
    ).hexdigest()
    registry.register(
        experiment_id=experiment_id,
        hypothesis="H8",
        title=f"baseline frontier on {test.corpus} count={len(test)} seed={test.seed}",
        slot_name=slot,
        dataset_name=f"{test.corpus}-{len(test)}",
        dataset_version=test.to_provenance().get("encoder_version", "unknown"),
        dataset_sha256=digest,
        git_commit=None,
        seeds={"train": train.seed, "test": test.seed},
        synthetic_data=True,
        notes=(
            "Baseline suite + cost frontier consumed by Stage 2 gate criteria G2.1, "
            "G2.2 and G2.12. Registered so results/stage2-frontier.json has ledger "
            "lineage the gate can verify (S2-AUTH-02); the gate refuses frontier "
            "evidence whose experiment_id is absent here or whose content_digest "
            "does not match its own payload."
        ),
        result_path=str(FRONTIER_PATH.relative_to(REPO_ROOT)),
    )
    return experiment_id


def _frontier(*, as_json: bool, gate: bool) -> int:
    train = build_dataset(
        name="s2-frontier-train", count=GATE_COUNT, seed=TRAIN_SEED, corpus=GATE_CORPUS
    )
    test = build_dataset(
        name="s2-frontier-test", count=GATE_COUNT, seed=TEST_SEED, corpus=GATE_CORPUS
    )
    evidence = measure_frontier(train, test, experiment_id=_frontier_experiment(train, test))
    FRONTIER_PATH.parent.mkdir(parents=True, exist_ok=True)
    FRONTIER_PATH.write_text(
        json.dumps(evidence.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if as_json:
        print(json.dumps(evidence.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"Stage 2 baseline frontier ({evidence.corpus}, count={evidence.count})\n")
        for name, value in sorted(evidence.scores.items()):
            print(f"  {name:<20} {value:.4f}")
        print(f"\n  base rate            {evidence.base_rate:.4f}")
        print(f"  degenerate           {evidence.degenerate} ({evidence.reason})")
        print(f"  cost frontier        {evidence.pareto.get('verdict', 'UNMEASURED')}")
        print(f"\n  written to {FRONTIER_PATH.relative_to(REPO_ROOT)}")
    if not gate:
        return 0
    report = run_gate(frontier=evidence)
    for check in report.checks:
        print(f"  [{'PASS' if check.passed else 'FAIL'}] {check.id}  {check.title}")
    return 0 if report.passed else 1


def _report(*, as_json: bool, count: int, register: bool) -> int:
    report = build_report(count=count)
    payload: dict[str, Any] = report.to_dict()
    if register:
        payload["registered"] = _register(report)
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
        return 0
    print("Stage 2 findings report (D2.14)\n")
    for verdict in report.components:
        print(
            f"  {verdict.verdict:<16} {verdict.component:<28} {verdict.metric}: "
            f"{verdict.with_component} vs {verdict.without_component} ({verdict.control})"
        )
    print(f"\n  saturation  {[v.reason for v in report.saturation]}")
    print(f"  registered  {payload.get('registered', 'not requested')}")
    return 0


def _register(report: Any) -> list[str]:
    """Append one ledger entry per *measured* component verdict.

    The registry is append-only and digest-chained, so this writes exactly the
    verdicts that carry an experiment id and a measured delta. A verdict the
    report marked ``UNMEASURABLE`` has no measurement to register and is skipped
    rather than recorded as though it had one — which is precisely why the gate's
    criterion 12 reads the ledger and not the report.
    """
    import hashlib

    from pocketsec.stage0.experiments.registry import ExperimentRegistry

    registry = ExperimentRegistry(REPO_ROOT / "experiments" / "registry.jsonl")
    known = {entry.experiment_id for entry in registry.all()}
    provenance = report.provenance
    digest = hashlib.sha256(
        json.dumps(provenance["test"], sort_keys=True).encode("utf-8")
    ).hexdigest()
    written: list[str] = []
    for verdict in report.components:
        experiment_id = verdict.experiment_id
        if experiment_id is None or experiment_id in known or verdict.delta is None:
            continue
        registry.register(
            experiment_id=experiment_id,
            hypothesis="H8",
            title=f"{verdict.component} vs {verdict.control} on {verdict.metric}",
            slot_name=verdict.component,
            dataset_name=f"{provenance['corpus']}-{provenance['count']}",
            dataset_version=provenance["encoder_version"],
            dataset_sha256=digest,
            git_commit=None,
            seeds={"train": provenance["train_seed"], "test": provenance["test_seed"]},
            synthetic_data=True,
            notes=(
                f"{verdict.verdict}: with {verdict.with_component} vs without "
                f"{verdict.without_component} (delta {verdict.delta}). {verdict.detail}"
            ),
        )
        written.append(experiment_id)
        known.add(experiment_id)
    return written


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
