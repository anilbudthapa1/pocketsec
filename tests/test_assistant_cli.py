"""The ``pocketsec-chat`` command line: demo, one-shot ``--ask``, ``--json``, and the REPL."""

from __future__ import annotations

import io
import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from _assistant_support import release_cached_alerts

from pocketsec.assistant.capture import handoff_from_run
from pocketsec.assistant.cli import main
from pocketsec.assistant.demo import build_demo_runs
from pocketsec.assistant.facts import FactKind
from pocketsec.assistant.guard import verify_rendered
from pocketsec.assistant.handoff import facts_from_handoff
from pocketsec.stage0.gate import REPO_ROOT


@pytest.fixture(scope="module", autouse=True)
def _release_cached_alerts() -> Iterator[None]:
    """Free the cached demo runs when this module finishes (see ``_assistant_support``)."""
    yield
    release_cached_alerts()


def _run(argv: list[str], stdin: str = "") -> tuple[int, str]:
    out = io.StringIO()
    code = main(argv, stdin=io.StringIO(stdin), stdout=out)
    return code, out.getvalue()


def test_pyproject_declares_the_console_script() -> None:
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'pocketsec-chat = "pocketsec.assistant.cli:main"' in text


def test_demo_runs_and_labels_its_alerts_synthetic() -> None:
    code, out = _run(["demo"])
    assert code == 0
    assert "SYNTHETIC" in out
    assert "Sources:" in out
    assert "(observed)" in out and "(unknown)" in out


def test_one_shot_ask_answers_about_the_named_alert() -> None:
    code, out = _run(["--ask", "y did u flag this", "--alert", "1"])
    assert code == 0
    assert out.startswith("Alert 1 |")
    assert "SYNTHETIC" in out
    facts = {f.alert_id: f for f in _demo_facts()}
    alert_id = out.split(" | ")[1]
    assert verify_rendered(out.strip(), facts[alert_id]) == ()


def test_one_shot_accepts_the_full_incident_id() -> None:
    alert_id = _demo_facts()[1].alert_id
    code, out = _run(["--ask", "how sure are you", "--alert", alert_id])
    assert code == 0
    assert alert_id in out.splitlines()[0]


def test_json_output_carries_the_provenance_list() -> None:
    code, out = _run(["--ask", "what happened", "--alert", "1", "--json"])
    assert code == 0
    payload = json.loads(out)
    assert payload["intent"] == "WHAT_HAPPENED"
    assert payload["synthetic"] is True
    assert payload["provenance"]
    kinds = {row["kind"] for row in payload["provenance"]}
    assert kinds <= {k.value for k in FactKind}
    assert all(s["fact_ids"] for s in payload["sentences"])


def test_an_unknown_alert_is_refused_without_echoing_it() -> None:
    code, out = _run(["--ask", "why", "--alert", "ZZZ-not-an-alert"])
    assert code == 2
    assert "ZZZ" not in out
    assert "no alert" in out.lower()


def test_the_repl_lists_opens_answers_and_quits() -> None:
    script = "/alerts\n/open 2\nwhy was this flagged\nand how sure?\n/help\nkill it\n/quit\n"
    code, out = _run(["chat"], stdin=script)
    assert code == 0
    assert "Alert 2 |" in out
    assert "Question type: WHY_FLAGGED" in out
    assert "Question type: HOW_SURE" in out
    assert "Question type: ACTION_REQUEST" in out
    assert "/open" in out  # help text lists the commands


def test_the_repl_ends_cleanly_at_end_of_input() -> None:
    code, out = _run(["chat"], stdin="why\n")
    assert code == 0
    assert "Question type: WHY_FLAGGED" in out


def test_a_bundle_file_can_be_loaded(tmp_path: Path) -> None:
    (run, *_rest) = build_demo_runs()
    bundle = handoff_from_run(run, synthetic=True, provenance="cli test")
    path = tmp_path / "alert.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    code, out = _run(["--bundle", str(path), "--ask", "what don't you know", "--alert", "1"])
    assert code == 0
    assert run.export.incident_id in out.splitlines()[0]
    assert "(unknown)" in out


def test_a_broken_bundle_file_is_a_clean_error(tmp_path: Path) -> None:
    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")
    code, out = _run(["--bundle", str(path), "--ask", "why", "--alert", "1"])
    assert code == 2
    assert "could not load" in out.lower()


def _demo_facts() -> tuple:  # type: ignore[type-arg]
    from pocketsec.assistant.demo import build_demo_alerts

    return build_demo_alerts()


def test_bundle_round_trip_matches_the_demo() -> None:
    (run, *_rest) = build_demo_runs()
    bundle = handoff_from_run(run, synthetic=True, provenance="cli test")
    assert facts_from_handoff(bundle).alert_id == run.export.incident_id
