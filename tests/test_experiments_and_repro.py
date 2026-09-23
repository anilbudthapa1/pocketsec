"""D0.4 + D0.6 — immutable experiment ids, append-only ledger, reproducibility."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pocketsec.stage0.experiments.ids import format_experiment_id, parse_experiment_id
from pocketsec.stage0.experiments.registry import (
    GENESIS_DIGEST,
    ExperimentRegistry,
    RegistryError,
)
from pocketsec.stage0.repro.environment import EnvironmentFingerprint
from pocketsec.stage0.repro.seeds import COMPONENTS, SeedSet

# --- experiment ids ----------------------------------------------------------


def test_experiment_id_round_trips() -> None:
    value = format_experiment_id(
        stage=0, hypothesis="H0", slug="frequency-baseline", sequence=1, date="20260924"
    )
    assert value == "PS-S0-20260924-H0-frequency-baseline-0001"
    parsed = parse_experiment_id(value)
    assert (parsed.stage, parsed.hypothesis, parsed.sequence) == (0, "H0", 1)
    assert str(parsed) == value


@pytest.mark.parametrize(
    "kwargs",
    [
        {"stage": 13, "hypothesis": "H0", "slug": "x", "sequence": 1},
        {"stage": 0, "hypothesis": "h0", "slug": "x", "sequence": 1},
        {"stage": 0, "hypothesis": "H0", "slug": "Not-Kebab", "sequence": 1},
        {"stage": 0, "hypothesis": "H0", "slug": "x", "sequence": 10_000},
        {"stage": 0, "hypothesis": "H0", "slug": "x", "sequence": 1, "date": "20260231"},
    ],
)
def test_malformed_experiment_ids_are_refused(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        format_experiment_id(**kwargs)  # type: ignore[arg-type]


def test_parsing_a_malformed_id_fails() -> None:
    with pytest.raises(ValueError, match="malformed"):
        parse_experiment_id("PS-S0-20260924-H0-x-1")  # sequence not 4 digits


# --- registry ----------------------------------------------------------------


def _register(registry: ExperimentRegistry, sequence: int) -> None:
    registry.register(
        experiment_id=format_experiment_id(
            stage=0, hypothesis="H0", slug="baseline", sequence=sequence, date="20260924"
        ),
        hypothesis="H0",
        title=f"run {sequence}",
        slot_name="h0-frequency-baseline",
        dataset_name="tiny",
        dataset_version="v0.1.0",
        dataset_sha256="0" * 64,
        git_commit=None,
        seeds={"master": 1},
        synthetic_data=True,
    )


def test_registry_appends_and_reads_back(tmp_path: Path) -> None:
    registry = ExperimentRegistry(tmp_path / "registry.jsonl")
    _register(registry, 1)
    _register(registry, 2)
    entries = registry.all()
    assert len(entries) == 2
    assert entries[0].previous_digest == GENESIS_DIGEST
    assert entries[1].previous_digest == entries[0].entry_digest
    assert registry.verify_integrity() == []


def test_registry_refuses_to_reuse_an_experiment_id(tmp_path: Path) -> None:
    registry = ExperimentRegistry(tmp_path / "registry.jsonl")
    _register(registry, 1)
    with pytest.raises(RegistryError, match="already registered"):
        _register(registry, 1)


def test_registry_exposes_no_update_or_delete() -> None:
    """Prior research artifacts are never deleted, so no API offers to."""
    for forbidden in ("update", "delete", "remove", "edit", "overwrite"):
        assert not hasattr(ExperimentRegistry, forbidden)


def test_registry_detects_content_tampering(tmp_path: Path) -> None:
    path = tmp_path / "registry.jsonl"
    registry = ExperimentRegistry(path)
    _register(registry, 1)
    _register(registry, 2)

    lines = path.read_text(encoding="utf-8").splitlines()
    payload = json.loads(lines[0])
    payload["title"] = "quietly rewritten history"
    lines[0] = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    problems = registry.verify_integrity()
    assert any("modified after it was recorded" in problem for problem in problems)
    assert any("chain break" in problem for problem in problems)


def test_registry_detects_a_removed_entry(tmp_path: Path) -> None:
    path = tmp_path / "registry.jsonl"
    registry = ExperimentRegistry(path)
    _register(registry, 1)
    _register(registry, 2)

    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text(lines[1] + "\n", encoding="utf-8")  # drop the first entry

    assert any("chain break" in problem for problem in registry.verify_integrity())


def test_registry_of_a_missing_file_is_empty_and_intact(tmp_path: Path) -> None:
    registry = ExperimentRegistry(tmp_path / "absent.jsonl")
    assert registry.all() == ()
    assert registry.verify_integrity() == []


def test_registry_rejects_a_malformed_id(tmp_path: Path) -> None:
    registry = ExperimentRegistry(tmp_path / "registry.jsonl")
    with pytest.raises(ValueError, match="malformed"):
        registry.register(
            experiment_id="not-an-id",
            hypothesis="H0",
            title="t",
            slot_name="s",
            dataset_name="d",
            dataset_version="v",
            dataset_sha256="0" * 64,
            git_commit=None,
            seeds={},
            synthetic_data=True,
        )


# --- seeds -------------------------------------------------------------------


def test_seed_derivation_is_deterministic_and_component_distinct() -> None:
    a, b = SeedSet(42), SeedSet(42)
    assert a.derive("model_init") == b.derive("model_init")
    assert a.derive("model_init") != a.derive("sampling")


def test_different_masters_give_different_streams() -> None:
    assert SeedSet(1).derive("sampling") != SeedSet(2).derive("sampling")


def test_seed_set_reports_every_component() -> None:
    seeds = SeedSet(7).as_dict()
    assert seeds["master"] == 7
    assert set(COMPONENTS) <= set(seeds)


def test_negative_master_seed_is_refused() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        SeedSet(-1)


# --- environment fingerprint -------------------------------------------------


def test_fingerprint_captures_the_reproducibility_block() -> None:
    fingerprint = EnvironmentFingerprint.capture(seeds=SeedSet(3))
    payload = fingerprint.to_dict()
    for key in ("python_version", "platform", "kernel", "machine", "seeds", "git_commit"):
        assert key in payload
    assert payload["seeds"]["master"] == 3


def test_a_dirty_or_unpinned_tree_is_not_called_reproducible() -> None:
    """Honesty over convenience: an unpinned run says so."""
    dirty = EnvironmentFingerprint(
        captured_at_ns=0,
        python_version="3.11.0",
        python_implementation="CPython",
        platform_summary="linux",
        kernel="6.0",
        machine="x86_64",
        cpu_count=1,
        git_commit="abc123",
        git_dirty=True,
        pythonhashseed="0",
        seeds={},
        source_root="/tmp",
    )
    assert dirty.is_reproducible is False
    assert any("dirty" in note for note in dirty.caveats)

    unpinned = EnvironmentFingerprint(
        captured_at_ns=0,
        python_version="3.11.0",
        python_implementation="CPython",
        platform_summary="linux",
        kernel="6.0",
        machine="x86_64",
        cpu_count=1,
        git_commit=None,
        git_dirty=None,
        pythonhashseed=None,
        seeds={},
        source_root="/tmp",
    )
    assert unpinned.is_reproducible is False
    assert len(unpinned.caveats) == 2
