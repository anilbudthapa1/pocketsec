"""Stage 2 routing — the bounded lineage window (DTL-F03) and honest path accounting.

Every test here is named after the invariant it defends rather than the function
it calls. The one that matters most is
``test_a_gate_that_computes_every_branch_cannot_report_a_saving``: it reproduces
the exact defect ADR-0010 measured — a router reporting 100 % cheap-path
resolution while every branch was computed regardless of its gate — and asserts
the ledger refuses to report a cheap path for it. If that test ever passes while
the ledger reports P0, `pocketsec/stage2/router/accounting.py` has been weakened
back to the notional accounting this package exists to replace.

Stdlib and pytest only; no numpy, because none of this code is research code.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.labs.corpus import ATTACK_EXFIL, Behaviour, Scenario
from pocketsec.stage1.labs.hard_corpus import build_hard_corpus
from pocketsec.stage1.novelty.engine import NOVELTY_CONTEXTS, NoveltyTensor
from pocketsec.stage1.pipeline import Stage1Pipeline
from pocketsec.stage1.ssir.entities import Entity
from pocketsec.stage1.ssir.relations import Relation, family_of
from pocketsec.stage1.ssir.transition import (
    RepresentationLevel,
    SSIRTransitionV1,
    TemporalContext,
)
from pocketsec.stage1.state.security_state import StateDelta
from pocketsec.stage2.core_ids import PATH_COST_UNITS, ExecutionPath
from pocketsec.stage2.encoder.ssir_encoder import FEATURE_WIDTH
from pocketsec.stage2.router import accounting as accounting_module
from pocketsec.stage2.router import policy as policy_module
from pocketsec.stage2.router.accounting import (
    MAX_LEDGER_EVENTS,
    PathAccount,
    WorkKind,
    WorkLedger,
    WorkRecord,
    measured,
)
from pocketsec.stage2.router.policy import (
    DOCUMENTED_NEED_INDICES,
    NEED_SIGNAL_ORDER,
    ROUTER_DEFAULT_ENABLED,
    NeedSignals,
    need_score,
    route_information_need,
)
from pocketsec.stage2.state import window as window_module
from pocketsec.stage2.state.window import (
    MAX_LINEAGES,
    MAX_WINDOW,
    LineageWindow,
    WindowStore,
)

# --- fixtures and builders ---------------------------------------------------


def _pipeline_transitions(
    behaviours: tuple[Behaviour, ...] = ATTACK_EXFIL, *, offset: int = 1
) -> tuple[SSIRTransitionV1, ...]:
    """Real Stage 1 transitions. A fresh pipeline per call: Stage 1 carries
    lineage state across scenarios, and sharing one would manufacture capability
    accumulation the corpus never described."""
    pipeline = Stage1Pipeline()
    result = pipeline.run_scenario(Scenario("s", behaviours, 1), offset=offset)
    return result.transitions


def _synthetic(
    *,
    signature: str,
    parent: str,
    sequence: int,
    relation: Relation = Relation.READ,
    novelty: float = 0.5,
    uncertainty: float = 0.5,
    responsibility: float = 0.0,
    delta_phi: float = 0.0,
    identity: str = "boot-1:pid-1000:start-7",
    display_name: str = "/usr/bin/curl --exfil",
) -> SSIRTransitionV1:
    """A hand-built transition, for bounds tests that need many distinct chains.

    The identity and display_name defaults are deliberately recognisable strings:
    several tests assert they never reach the lineage key.
    """
    entity = Entity(identity=identity, display_name=display_name)
    return SSIRTransitionV1(
        actor=entity,
        relation=relation,
        object=Entity(identity=identity + ":obj", display_name=display_name + ":obj"),
        state_delta=StateDelta({}),
        uncertainty=uncertainty,
        novelty=NoveltyTensor({context: novelty for context in NOVELTY_CONTEXTS}),
        causal_signature=signature,
        parent_signature=parent,
        responsibility=responsibility,
        temporal=TemporalContext(since_actor_bucket=3, since_host_bucket=4),
        evidence=(),
        epoch_id=0,
        sequence=sequence,
        level=RepresentationLevel.L2,
        delta_phi=delta_phi,
    )


_ROOT = "0" * 16


def _signature(index: int) -> str:
    return f"{index:016x}"


# --- D2.3 / DTL-F03: the bounded window --------------------------------------


def test_window_never_exceeds_max_window_and_says_when_it_truncated() -> None:
    store = WindowStore()
    window = None
    for step in range(MAX_WINDOW + 25):
        window = store.update_multiscale_state(
            _synthetic(
                signature=_signature(step + 1),
                parent=_ROOT if step == 0 else _signature(step),
                sequence=step,
            )
        )
    assert window is not None
    assert len(window.steps) == MAX_WINDOW
    assert window.truncated is True
    stats = store.stats()
    assert stats.transitions_held == MAX_WINDOW
    assert stats.truncated_steps == 25


def test_a_window_that_dropped_nothing_does_not_claim_truncation() -> None:
    """The flag has to mean something, or it is decoration."""
    store = WindowStore()
    window = store.update_multiscale_state(
        _synthetic(signature=_signature(1), parent=_ROOT, sequence=0)
    )
    assert window.truncated is False
    assert store.stats().truncated_steps == 0


def test_truncation_flag_is_sticky_once_a_step_was_dropped() -> None:
    """A later append must not be able to launder an earlier drop."""
    store = WindowStore(max_window=4)
    for step in range(6):
        window = store.update_multiscale_state(
            _synthetic(
                signature=_signature(step + 1),
                parent=_ROOT if step == 0 else _signature(step),
                sequence=step,
            )
        )
    assert window.truncated is True
    later = store.update_multiscale_state(
        _synthetic(signature=_signature(7), parent=_signature(6), sequence=6)
    )
    assert later.truncated is True


def test_lineage_count_never_exceeds_max_lineages_and_evictions_are_counted() -> None:
    store = WindowStore()
    for index in range(MAX_LINEAGES + 30):
        store.update_multiscale_state(
            _synthetic(signature=_signature(index + 1), parent=_ROOT, sequence=index)
        )
        assert store.stats().lineages <= MAX_LINEAGES
    stats = store.stats()
    assert stats.lineages == MAX_LINEAGES
    assert stats.evicted_lineages == 30


def test_eviction_is_lru_by_last_sequence_and_deterministic() -> None:
    store = WindowStore(max_lineages=2)
    store.update_multiscale_state(
        _synthetic(signature=_signature(1), parent=_ROOT, sequence=10)
    )
    store.update_multiscale_state(
        _synthetic(signature=_signature(2), parent=_ROOT, sequence=20)
    )
    store.update_multiscale_state(
        _synthetic(signature=_signature(3), parent=_ROOT, sequence=30)
    )
    assert store.get(_signature(1)) is None  # oldest last_sequence went first
    assert store.get(_signature(2)) is not None
    assert store.get(_signature(3)) is not None


def test_lineage_eviction_counts_the_history_it_discards() -> None:
    """Pins S2-08 (MEDIUM).

    ``WindowStore``'s docstring says "every dropped step is counted in
    ``WindowStats.truncated_steps``". That held for the per-window step cap but
    not for lineage eviction: ``_evict_lineages`` incremented
    ``_evicted_lineages`` and discarded the window's steps without counting
    them, and when the lineage reappeared it got a fresh window with
    ``truncated=False``. The window that had lost the *most* history — all of it
    — was the one reporting none.
    """
    store = WindowStore(max_lineages=2)
    for index in (1, 2):
        for step in range(3):
            store.update_multiscale_state(
                _synthetic(
                    signature=_signature(index),
                    parent=_ROOT,
                    sequence=index * 10 + step,
                )
            )
    assert store.stats().truncated_steps == 0
    held = store.stats().transitions_held

    store.update_multiscale_state(
        _synthetic(signature=_signature(3), parent=_ROOT, sequence=100)
    )
    assert store.get(_signature(1)) is None
    stats = store.stats()
    assert stats.evicted_lineages == 1
    assert stats.truncated_steps == 3, "the evicted window's three steps vanished"
    assert stats.transitions_held == held - 3 + 1

    # The lineage reappears. Its window has dropped history and must say so.
    window = store.update_multiscale_state(
        _synthetic(signature=_signature(1), parent=_ROOT, sequence=200)
    )
    assert len(window.steps) == 1
    assert window.truncated is True, "a reappearing evicted lineage is not complete"


def test_a_replayed_stale_sequence_cannot_evict_a_fresher_lineage() -> None:
    """Adversarial input: a transition with an old sequence number.

    Feeding a full store an ancient event must not push out live lineages. The
    stale arrival is the least-recent thing present, so it is what goes.
    """
    store = WindowStore(max_lineages=2)
    store.update_multiscale_state(
        _synthetic(signature=_signature(1), parent=_ROOT, sequence=100)
    )
    store.update_multiscale_state(
        _synthetic(signature=_signature(2), parent=_ROOT, sequence=200)
    )
    store.update_multiscale_state(
        _synthetic(signature=_signature(3), parent=_ROOT, sequence=1)
    )
    assert store.get(_signature(1)) is not None
    assert store.get(_signature(2)) is not None
    assert store.get(_signature(3)) is None
    assert store.stats().evicted_lineages == 1


@pytest.mark.parametrize("dilation", [1, 2, 4, 8, 16, 32])
def test_dilated_context_is_causal_at_every_dilation_the_core_uses(
    dilation: int,
) -> None:
    """Step t sees only steps <= t. A non-causal window leaks the future."""
    store = WindowStore()
    for step in range(MAX_WINDOW):
        store.update_multiscale_state(
            _synthetic(
                signature=_signature(step + 1),
                parent=_ROOT if step == 0 else _signature(step),
                sequence=step,
                relation=Relation(step % len(Relation)),
            )
        )
    window = store.get(_signature(1))
    assert window is not None
    rows = window.features()
    context = window.dilated_context(dilation)
    kernel = 3
    assert len(context) == len(rows)
    for index, row in enumerate(context):
        assert len(row) == kernel * FEATURE_WIDTH
        for tap in range(kernel):
            offset = (kernel - 1 - tap) * dilation
            source = index - offset
            chunk = row[tap * FEATURE_WIDTH : (tap + 1) * FEATURE_WIDTH]
            expected = rows[source] if source >= 0 else (0.0,) * FEATURE_WIDTH
            assert chunk == expected, (index, tap, dilation)
            # The load-bearing half: never a row from the future.
            assert source <= index


def test_dilated_context_rejects_a_non_causal_request() -> None:
    store = WindowStore()
    window = store.update_multiscale_state(
        _synthetic(signature=_signature(1), parent=_ROOT, sequence=0)
    )
    with pytest.raises(ContractError):
        window.dilated_context(0)
    with pytest.raises(ContractError):
        window.dilated_context(-4)
    with pytest.raises(ContractError):
        window.dilated_context(2, kernel=0)


def test_memory_bytes_is_computed_and_stays_inside_its_own_bound() -> None:
    store = WindowStore()
    for index in range(MAX_LINEAGES):
        for step in range(MAX_WINDOW):
            store.update_multiscale_state(
                _synthetic(
                    signature=_signature(index * 1000 + step + 1),
                    parent=_ROOT if step == 0 else _signature(index * 1000 + step),
                    sequence=index * 1000 + step,
                )
            )
    stats = store.stats()
    assert stats.lineages == MAX_LINEAGES
    assert stats.transitions_held == MAX_LINEAGES * MAX_WINDOW
    assert stats.memory_bytes > 0
    assert store.fixed_bytes() <= store.memory_bound_bytes()
    assert stats.memory_bytes == store.fixed_bytes() + store.evidence_bytes()
    # The bound is a real ceiling, not a running total.
    assert store.memory_bound_bytes() < 8 * 1024 * 1024


def test_a_full_store_stops_growing() -> None:
    """Boundedness means the tenth thousand event costs what the first did."""
    store = WindowStore()
    for index in range(MAX_LINEAGES * MAX_WINDOW):
        store.update_multiscale_state(
            _synthetic(signature=_signature(index + 1), parent=_ROOT, sequence=index)
        )
    saturated = store.stats().memory_bytes
    for index in range(MAX_LINEAGES * MAX_WINDOW, MAX_LINEAGES * MAX_WINDOW + 500):
        store.update_multiscale_state(
            _synthetic(signature=_signature(index + 1), parent=_ROOT, sequence=index)
        )
    assert store.stats().memory_bytes == saturated
    assert store.stats().lineages == MAX_LINEAGES


def test_root_map_is_bounded_and_its_evictions_are_counted() -> None:
    """A signature->root map over an unbounded stream is the classic leak."""
    store = WindowStore(max_lineages=2, max_window=2)
    assert store.max_roots == 4
    keys = set()
    for step in range(20):
        window = store.update_multiscale_state(
            _synthetic(
                signature=_signature(step + 1),
                parent=_ROOT if step == 0 else _signature(step),
                sequence=step,
            )
        )
        keys.add(window.lineage_key)
    assert store.root_evictions() >= 16
    # Evicting the chain head is harmless while the *immediate* parent survives,
    # so the lineage key is still stable here. A gap in the chain is what splits
    # a lineage, and that case is counted by `unresolved_parents()` — see
    # `test_an_unseen_parent_is_counted_not_guessed`.
    assert keys == {_signature(1)}
    assert store.unresolved_parents() == 0


def test_an_unseen_parent_is_counted_not_guessed() -> None:
    """Adversarial input: a forged parent signature nothing ever produced."""
    store = WindowStore()
    window = store.update_multiscale_state(
        _synthetic(signature=_signature(9), parent="deadbeefdeadbeef", sequence=0)
    )
    assert window.lineage_key == "deadbeefdeadbeef"
    assert store.unresolved_parents() == 1


def test_a_chain_shares_one_lineage_key() -> None:
    store = WindowStore()
    keys = set()
    for step in range(10):
        window = store.update_multiscale_state(
            _synthetic(
                signature=_signature(step + 1),
                parent=_ROOT if step == 0 else _signature(step),
                sequence=step,
            )
        )
        keys.add(window.lineage_key)
    assert keys == {_signature(1)}
    assert store.stats().lineages == 1


def test_lineage_key_never_carries_a_pid_a_display_name_or_an_identity() -> None:
    """ADR-0006/0007: the key is earned by behaviour, never by identity."""
    store = WindowStore()
    for transition in _pipeline_transitions():
        window = store.update_multiscale_state(transition)
        key = window.lineage_key
        assert transition.actor.identity not in key
        for label in (
            transition.actor.display_name,
            transition.object.display_name,
            transition.object.identity,
        ):
            # An empty label is vacuously absent, so it proves nothing; the
            # hex-alphabet assertion below is what closes that hole.
            if label:
                assert label not in key
        # A Stage 1 causal signature is 16 lowercase hex characters and nothing
        # else, so no name, path or pid can be hiding inside it.
        assert len(key) == 16
        assert all(character in "0123456789abcdef" for character in key)

    synthetic = _synthetic(signature=_signature(1), parent=_ROOT, sequence=0)
    key = store.update_multiscale_state(synthetic).lineage_key
    assert "1000" not in key
    assert "curl" not in key
    assert synthetic.actor.identity not in key


def test_window_module_never_reads_identity_fields() -> None:
    """Belt and braces, mirroring the encoder's own guard.

    An AST check rather than a text search: a docstring that *names* identity is
    not a violation of the rule.
    """
    tree = ast.parse(Path(window_module.__file__).read_text(encoding="utf-8"))
    attributes = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    assert "identity" not in attributes
    assert "display_name" not in attributes
    assert "actor" not in attributes
    assert "object" not in attributes


def test_window_store_refuses_a_bound_it_cannot_honour() -> None:
    with pytest.raises(ContractError):
        WindowStore(max_lineages=0)
    with pytest.raises(ContractError):
        WindowStore(max_window=0)
    with pytest.raises(ContractError):
        WindowStore(max_lineages=MAX_LINEAGES + 1)
    with pytest.raises(ContractError):
        WindowStore(max_window=MAX_WINDOW + 1)


def test_window_store_refuses_something_that_is_not_a_transition() -> None:
    store = WindowStore()
    with pytest.raises(ContractError):
        store.update_multiscale_state({"causal_signature": "x"})  # type: ignore[arg-type]


def test_lineage_window_refuses_an_oversized_or_unkeyed_window() -> None:
    store = WindowStore()
    window = store.update_multiscale_state(
        _synthetic(signature=_signature(1), parent=_ROOT, sequence=0)
    )
    with pytest.raises(ContractError):
        LineageWindow(lineage_key="", steps=window.steps, truncated=False, last_sequence=0)
    with pytest.raises(ContractError):
        LineageWindow(
            lineage_key="k",
            steps=window.steps * (MAX_WINDOW + 1),
            truncated=True,
            last_sequence=0,
        )


def test_reset_clears_state_and_says_that_it_clears_the_accounting() -> None:
    store = WindowStore()
    for index in range(MAX_LINEAGES + 5):
        store.update_multiscale_state(
            _synthetic(signature=_signature(index + 1), parent=_ROOT, sequence=index)
        )
    assert store.stats().evicted_lineages == 5
    store.reset()
    blank = store.stats()
    assert blank.lineages == 0
    assert blank.transitions_held == 0
    assert blank.evicted_lineages == 0
    assert blank.memory_bytes == 0
    assert "discards" in (WindowStore.reset.__doc__ or "")


def test_the_single_step_control_is_measured_not_assumed(capsys) -> None:  # type: ignore[no-untyped-def]
    """The dumbest baseline for D2.3: a window holding one past transition.

    Spec section 5 names the control and the metrics (next-family accuracy and
    `memory_bytes`). ``max_window=2`` is that control: the current step plus
    exactly one step of history. This test *measures* both windows and asserts
    only what is structurally true — that the wide window costs more memory. It
    deliberately does NOT assert that the wide window predicts better. On this
    corpus it does not, and an assertion in that direction would be this wave
    inventing a win for a mechanism that has not earned one.
    """
    transitions: tuple[SSIRTransitionV1, ...] = ()
    for index, scenario in enumerate(build_hard_corpus(count=12, seed=11, split="train")):
        # A fresh pipeline per scenario: Stage 1 carries lineage state across
        # scenarios on a shared pipeline, and reusing one silently erases the
        # corpus's own signal (`planning/MEMORY.md`, corpus trap).
        transitions += (
            Stage1Pipeline().run_scenario(scenario, offset=index + 1).transitions
        )
    assert len(transitions) >= 40

    results: dict[int, tuple[float, int, int]] = {}
    for max_window in (2, MAX_WINDOW):
        store = WindowStore(max_window=max_window)
        correct = 0
        scored = 0
        for transition in transitions:
            window = store.update_multiscale_state(transition)
            # Only the steps *before* the current one may inform the prediction.
            history = window.steps[:-1]
            predicted = _majority_family(history)
            if predicted is not None:
                scored += 1
                correct += int(predicted == int(family_of(transition.relation)))
        accuracy = correct / scored if scored else 0.0
        results[max_window] = (accuracy, store.stats().memory_bytes, scored)

    wide_accuracy, wide_bytes, wide_scored = results[MAX_WINDOW]
    narrow_accuracy, narrow_bytes, narrow_scored = results[2]
    assert wide_scored > 0 and narrow_scored > 0
    assert wide_bytes > narrow_bytes
    assert 0.0 <= wide_accuracy <= 1.0 and 0.0 <= narrow_accuracy <= 1.0
    print(
        f"MEASURED next-family accuracy over {len(transitions)} hard-corpus "
        f"transitions (count=12, seed=11, split=train, synthetic_data=True): "
        f"window=2 {narrow_accuracy:.4f} on {narrow_scored} predictions "
        f"({narrow_bytes} B) vs window={MAX_WINDOW} {wide_accuracy:.4f} on "
        f"{wide_scored} predictions ({wide_bytes} B)"
    )
    captured = capsys.readouterr()
    assert "MEASURED" in captured.out


def _majority_family(steps: tuple[object, ...]) -> int | None:
    """Most frequent relation family in the history, ties to the lowest id."""
    counts: dict[int, int] = {}
    for step in steps:
        family = step.relation_family  # type: ignore[attr-defined]
        counts[family] = counts.get(family, 0) + 1
    if not counts:
        return None
    return max(sorted(counts), key=lambda family: counts[family])


# --- D2.4 / DTL-F02: the policy ----------------------------------------------


def test_the_router_is_off_by_default_and_says_why() -> None:
    assert ROUTER_DEFAULT_ENABLED is False
    source = Path(policy_module.__file__).read_text(encoding="utf-8")
    assert "0.115" in source, "the default-off flag must cite its measured reason"


def test_need_signals_read_the_documented_slots() -> None:
    transitions = _pipeline_transitions()
    store = WindowStore()
    window = store.update_multiscale_state(transitions[0])
    encoded = window.steps[0]
    signals = NeedSignals.from_encoded(encoded)
    for name in NEED_SIGNAL_ORDER:
        assert getattr(signals, name) == encoded.features[DOCUMENTED_NEED_INDICES[name]]


@pytest.mark.parametrize(
    ("score_target", "expected"),
    [
        (0.0, ExecutionPath.P0_COMPILED),
        (0.20, ExecutionPath.P1_LATTICE),
        (0.40, ExecutionPath.P2_LOCAL),
        (0.60, ExecutionPath.P3_PREDICTIVE),
        (0.90, ExecutionPath.P4_DEEP),
    ],
)
def test_route_information_need_reproduces_the_measured_thresholds(
    score_target: float, expected: ExecutionPath
) -> None:
    """The weights and thresholds must stay identical to the −0.115 mechanism."""
    signals = NeedSignals(
        novelty_peak=score_target / 0.35,
        delta_phi=0.0,
        uncertainty=0.0,
        responsibility=0.0,
        state_delta_magnitude=0.0,
    )
    assert need_score(signals) == pytest.approx(score_target)
    assert route_information_need(signals) is expected


def test_need_signals_reject_impossible_input() -> None:
    with pytest.raises(ContractError):
        NeedSignals(
            novelty_peak=float("nan"),
            delta_phi=0.0,
            uncertainty=0.0,
            responsibility=0.0,
            state_delta_magnitude=0.0,
        )
    with pytest.raises(ContractError):
        NeedSignals(
            novelty_peak=-1.0,
            delta_phi=0.0,
            uncertainty=0.0,
            responsibility=0.0,
            state_delta_magnitude=0.0,
        )
    with pytest.raises(ContractError):
        NeedSignals(
            novelty_peak="high",  # type: ignore[arg-type]
            delta_phi=0.0,
            uncertainty=0.0,
            responsibility=0.0,
            state_delta_magnitude=0.0,
        )


def test_the_policy_cannot_reach_the_ledger() -> None:
    """The policy proposes; the ledger decides. A policy that could write a path
    into the ledger would recreate the ADR-0010 defect, so the import must not
    exist at all."""
    tree = ast.parse(Path(policy_module.__file__).read_text(encoding="utf-8"))
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)
    assert not any("accounting" in name for name in imported), imported


# --- D2.4 / ADR-0114: the ledger --------------------------------------------


def _skipped(ledger: WorkLedger, *kinds: WorkKind) -> None:
    for kind in kinds:
        ledger.record(kind, performed=False, units=0.0, detail="genuinely not run")


def test_p0_is_reported_only_when_nothing_expensive_was_performed() -> None:
    ledger = WorkLedger()
    ledger.begin("cheap")
    ledger.record(WorkKind.CACHE_LOOKUP, performed=True, units=1.0, detail="hit")
    _skipped(
        ledger,
        WorkKind.LATTICE_LOOKUP,
        WorkKind.WINDOW_UPDATE,
        WorkKind.CORE_INFERENCE,
        WorkKind.CONE_EXPANSION,
        WorkKind.COUNTERFACTUAL,
    )
    account = ledger.close()
    assert account.path is ExecutionPath.P0_COMPILED
    assert account.performed_units == 1.0
    ledger.assert_no_phantom_savings()

    ledger.begin("not-cheap")
    ledger.record(WorkKind.CACHE_LOOKUP, performed=True, units=1.0, detail="hit")
    ledger.record(WorkKind.CORE_INFERENCE, performed=True, units=40.0, detail="ran")
    assert ledger.close().path is ExecutionPath.P3_PREDICTIVE


def test_the_path_is_the_highest_cost_work_that_actually_ran() -> None:
    for kind, expected in [
        (WorkKind.CACHE_LOOKUP, ExecutionPath.P0_COMPILED),
        (WorkKind.LATTICE_LOOKUP, ExecutionPath.P1_LATTICE),
        (WorkKind.WINDOW_UPDATE, ExecutionPath.P2_LOCAL),
        (WorkKind.CORE_INFERENCE, ExecutionPath.P3_PREDICTIVE),
        (WorkKind.CONE_EXPANSION, ExecutionPath.P3_PREDICTIVE),
        (WorkKind.COUNTERFACTUAL, ExecutionPath.P4_DEEP),
    ]:
        ledger = WorkLedger()
        ledger.begin(kind.value)
        ledger.record(WorkKind.CACHE_LOOKUP, performed=True, units=1.0)
        ledger.record(kind, performed=True, units=PATH_COST_UNITS[expected])
        assert ledger.close().path is expected


def test_no_caller_may_declare_a_path() -> None:
    """The anti-weakening test: if `close()` ever grows a path parameter, or
    `PathAccount` stops re-deriving, ADR-0114 has been undone."""
    assert list(inspect.signature(WorkLedger.close).parameters) == ["self"]
    for name, function in inspect.getmembers(accounting_module, inspect.isfunction):
        parameters = inspect.signature(function).parameters
        assert "path" not in parameters, f"{name} accepts a caller-supplied path"

    work = (WorkRecord(kind=WorkKind.COUNTERFACTUAL, performed=True, units=200.0),)
    with pytest.raises(ContractError):
        PathAccount(path=ExecutionPath.P0_COMPILED, work=work)


def test_assert_no_phantom_savings_raises_on_a_contradictory_record() -> None:
    ledger = WorkLedger()
    ledger.begin("contradiction")
    ledger.record(WorkKind.CORE_INFERENCE, performed=False, units=0.0, detail="skipped")
    ledger.record(WorkKind.CORE_INFERENCE, performed=True, units=40.0, detail="ran")
    # Caught while still open, before the caller is handed a verdict.
    with pytest.raises(ContractError, match="phantom savings"):
        ledger.assert_no_phantom_savings()
    account = ledger.close()
    assert account.contradictions == frozenset({WorkKind.CORE_INFERENCE})
    with pytest.raises(ContractError, match="phantom savings"):
        ledger.assert_no_phantom_savings()


def test_a_skipped_record_may_not_claim_units_it_did_not_spend() -> None:
    with pytest.raises(ContractError):
        WorkRecord(kind=WorkKind.CORE_INFERENCE, performed=False, units=40.0)
    with pytest.raises(ContractError):
        WorkRecord(kind=WorkKind.CORE_INFERENCE, performed=True, units=float("inf"))
    with pytest.raises(ContractError):
        WorkRecord(kind=WorkKind.CORE_INFERENCE, performed=True, units=-1.0)
    with pytest.raises(ContractError):
        WorkRecord(kind=WorkKind.CORE_INFERENCE, performed=1, units=0.0)  # type: ignore[arg-type]


def test_measured_does_not_bank_a_saving_when_the_body_raises() -> None:
    ledger = WorkLedger()
    ledger.begin("explodes")
    with pytest.raises(ZeroDivisionError):
        with measured(ledger, WorkKind.CORE_INFERENCE, 40.0):
            1 / 0
    account = ledger.close()
    assert account.path is ExecutionPath.P3_PREDICTIVE
    assert account.skipped_kinds == frozenset()
    assert account.performed_units == 40.0
    assert "raised" in account.work[0].detail
    ledger.assert_no_phantom_savings()


def test_measured_charges_the_body_that_returns_early() -> None:
    ledger = WorkLedger()

    def event() -> str:
        ledger.begin("early-return")
        with measured(ledger, WorkKind.COUNTERFACTUAL, 200.0):
            return "bailed out"

    assert event() == "bailed out"
    account = ledger.close()
    assert account.path is ExecutionPath.P4_DEEP
    assert account.performed_units == 200.0


def test_measured_records_nothing_when_the_block_is_never_entered() -> None:
    ledger = WorkLedger()
    ledger.begin("never-entered")
    manager = measured(ledger, WorkKind.CORE_INFERENCE, 40.0)
    del manager
    account = ledger.close()
    assert account.work == ()
    assert account.path is ExecutionPath.P0_COMPILED


def test_the_ledger_refuses_unattributed_and_overlapping_events() -> None:
    ledger = WorkLedger()
    with pytest.raises(ContractError):
        ledger.record(WorkKind.CACHE_LOOKUP, performed=True, units=1.0)
    with pytest.raises(ContractError):
        ledger.close()
    ledger.begin("one")
    with pytest.raises(ContractError):
        ledger.begin("two")
    with pytest.raises(ContractError):
        ledger.begin("")
    ledger.close()
    with pytest.raises(ContractError):
        WorkLedger(max_events=0)


def test_histogram_fractions_sum_to_one() -> None:
    ledger = WorkLedger()
    plan = [
        (WorkKind.CACHE_LOOKUP, 1.0),
        (WorkKind.LATTICE_LOOKUP, 2.0),
        (WorkKind.WINDOW_UPDATE, 8.0),
        (WorkKind.CORE_INFERENCE, 40.0),
        (WorkKind.COUNTERFACTUAL, 200.0),
        (WorkKind.CACHE_LOOKUP, 1.0),
    ]
    for index, (kind, units) in enumerate(plan):
        ledger.begin(f"event-{index}")
        ledger.record(kind, performed=True, units=units)
        ledger.close()
    histogram = ledger.histogram()
    assert sum(histogram.values()) == len(plan)
    assert set(histogram) == {path.value for path in ExecutionPath}
    fractions = ledger.path_fractions()
    assert sum(fractions.values()) == pytest.approx(1.0)
    assert fractions["P0_COMPILED"] == pytest.approx(2 / 6)
    assert ledger.compute_units_per_event() == pytest.approx(sum(u for _, u in plan) / 6)
    assert ledger.truncated() is False


def test_an_empty_ledger_reports_zeros_rather_than_a_flattering_guess() -> None:
    ledger = WorkLedger()
    assert ledger.compute_units_per_event() == 0.0
    assert sum(ledger.path_fractions().values()) == 0.0
    assert ledger.events_seen() == 0
    assert ledger.to_dict()["path_cost_units_calibrated"] is False


def test_the_ledger_truncates_at_its_capacity_and_says_so() -> None:
    ledger = WorkLedger(max_events=8)
    for index in range(20):
        ledger.begin(f"e{index}")
        ledger.record(WorkKind.CACHE_LOOKUP, performed=True, units=1.0)
        ledger.close()
    assert ledger.truncated() is True
    assert len(ledger.accounts()) == 8
    assert ledger.events_seen() == 20
    assert ledger.to_dict()["truncated"] is True


def test_the_default_ledger_capacity_is_the_declared_bound() -> None:
    assert MAX_LEDGER_EVENTS == 4096
    ledger = WorkLedger()
    for index in range(MAX_LEDGER_EVENTS + 3):
        ledger.begin(f"e{index}")
        ledger.record(WorkKind.CACHE_LOOKUP, performed=True, units=1.0)
        ledger.close()
    assert len(ledger.accounts()) == MAX_LEDGER_EVENTS
    assert ledger.truncated() is True


# --- the regression test this package exists for -----------------------------


def test_a_gate_that_computes_every_branch_cannot_report_a_saving() -> None:
    """ADR-0010's exact defect, reproduced and refused.

    The measured failure: the Need router reported 100 % of events resolved on
    cheap paths (P0–P2) while every branch was computed regardless of its gate.
    Below, the policy proposes the cheap path for every event *and* every branch
    is then computed anyway — the notional accounting would report 100 % P0. The
    ledger must report 0 % cheap path, because that is what actually happened.
    """
    ledger = WorkLedger()
    cheap_proposals = 0
    events = 24

    for index in range(events):
        signals = NeedSignals(
            novelty_peak=0.0,
            delta_phi=0.0,
            uncertainty=0.0,
            responsibility=0.0,
            state_delta_magnitude=0.0,
        )
        proposed = route_information_need(signals)
        cheap_proposals += int(proposed is ExecutionPath.P0_COMPILED)

        ledger.begin(f"event-{index}")
        # The gate says "cheap"...
        ledger.record(
            WorkKind.CACHE_LOOKUP,
            performed=True,
            units=1.0,
            detail=f"gate proposed {proposed.value}",
        )
        # ...and then every branch is computed regardless of its gate.
        for kind, units in (
            (WorkKind.LATTICE_LOOKUP, 2.0),
            (WorkKind.WINDOW_UPDATE, 8.0),
            (WorkKind.CORE_INFERENCE, 40.0),
            (WorkKind.CONE_EXPANSION, 40.0),
            (WorkKind.COUNTERFACTUAL, 200.0),
        ):
            with measured(ledger, kind, units):
                _ = sum(range(4))  # a stand-in for the branch that really ran
        ledger.close()

    # The policy did claim every event was cheap. That claim is the defect.
    assert cheap_proposals == events

    # The ledger reports what ran, and nothing cheap did.
    fractions = ledger.path_fractions()
    assert fractions["P0_COMPILED"] == 0.0
    assert fractions["P1_LATTICE"] == 0.0
    assert fractions["P2_LOCAL"] == 0.0
    assert fractions["P4_DEEP"] == 1.0
    assert ledger.histogram()["P4_DEEP"] == events
    assert ledger.compute_units_per_event() == pytest.approx(1 + 2 + 8 + 40 + 40 + 200)
    # No contradiction: the defect here is not double-booking, it is that the
    # expensive work ran. The ledger catches it by deriving the path instead.
    ledger.assert_no_phantom_savings()


def test_a_genuine_skip_is_the_only_way_to_earn_a_cheap_path() -> None:
    """The positive control for the test above: skip the work and P0 is honest."""
    ledger = WorkLedger()
    for index in range(10):
        ledger.begin(f"event-{index}")
        ledger.record(WorkKind.CACHE_LOOKUP, performed=True, units=1.0, detail="hit")
        _skipped(
            ledger,
            WorkKind.LATTICE_LOOKUP,
            WorkKind.WINDOW_UPDATE,
            WorkKind.CORE_INFERENCE,
            WorkKind.CONE_EXPANSION,
            WorkKind.COUNTERFACTUAL,
        )
        ledger.close()
    ledger.assert_no_phantom_savings()
    assert ledger.path_fractions()["P0_COMPILED"] == 1.0
    assert ledger.compute_units_per_event() == pytest.approx(1.0)
