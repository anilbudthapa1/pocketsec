"""The alert explainer's answers: every sentence grounded, every unknown kept unknown.

These tests run the real pipeline: Stage 4's synthetic incident corpus through Stage 1
and the LUCID engine (the demo alerts), and Stage 5's own fixture corpus through the
real executor and lease sweeper (``stage5_bundle``). Nothing here is a hand-written
alert, so a template that drifts from what the stages actually emit fails here.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any

import pytest
from _assistant_support import release_cached_alerts
from _assistant_support import stage5_bundle as build_stage5_bundle

from pocketsec.assistant.answers import HEDGE_WORDS, Answer, answer
from pocketsec.assistant.capture import handoff_from_run
from pocketsec.assistant.demo import build_demo_alerts, build_demo_runs
from pocketsec.assistant.facts import AlertFacts, FactKind
from pocketsec.assistant.guard import (
    EXONERATION_PATTERNS,
    check_answer,
    quote_number,
    verify_rendered,
)
from pocketsec.assistant.handoff import facts_from_handoff
from pocketsec.assistant.intents import Intent
from pocketsec.stage4.claims.compiler import FORBIDDEN_AMPLIFICATIONS
from pocketsec.stage4.claims.verbalizer import EPISTEMIC_MARKERS

ANSWERABLE = tuple(
    intent
    for intent in Intent
    if intent not in {Intent.OUT_OF_SCOPE, Intent.ACTION_REQUEST, Intent.HELP}
)


@pytest.fixture(scope="module", autouse=True)
def _release_cached_alerts() -> Iterator[None]:
    """Free the cached demo runs when this module finishes (see ``_assistant_support``)."""
    yield
    release_cached_alerts()


@pytest.fixture(scope="module")
def alerts() -> tuple[AlertFacts, ...]:
    return build_demo_alerts()


@pytest.fixture(scope="module")
def all_answers(alerts: tuple[AlertFacts, ...]) -> list[tuple[AlertFacts, Answer]]:
    return [(facts, answer(intent, facts)) for facts in alerts for intent in Intent]


@pytest.fixture()
def stage5_bundle() -> dict[str, Any]:
    return build_stage5_bundle()


# --- grounding --------------------------------------------------------------


def test_the_demo_has_several_synthetic_alerts(alerts: tuple[AlertFacts, ...]) -> None:
    assert len(alerts) >= 3
    assert all(facts.synthetic for facts in alerts)
    assert len({facts.alert_id for facts in alerts}) == len(alerts)


def test_every_sentence_of_every_answer_is_grounded(
    all_answers: list[tuple[AlertFacts, Answer]],
) -> None:
    sentences = 0
    for facts, reply in all_answers:
        assert reply.withheld == 0, (reply.intent, check_answer(reply, facts))
        assert check_answer(reply, facts) == ()
        for sentence in reply.sentences:
            sentences += 1
            assert sentence.fact_ids, sentence
            for fact_id in sentence.fact_ids:
                assert facts.get(fact_id) is not None, fact_id
    assert sentences > 100


def test_the_rendered_text_parses_back_to_facts(
    all_answers: list[tuple[AlertFacts, Answer]],
) -> None:
    """The checker reads the text a person sees, not the object that produced it."""
    for facts, reply in all_answers:
        rendered = reply.render(short_id=1)
        assert verify_rendered(rendered, facts) == (), rendered


def test_the_checker_catches_an_untagged_or_unsourced_line(
    alerts: tuple[AlertFacts, ...],
) -> None:
    facts = alerts[0]
    rendered = answer(Intent.WHY_FLAGGED, facts).render(short_id=1)
    lines = rendered.splitlines()
    sentence_at = next(i for i, line in enumerate(lines) if line.startswith("- "))
    untagged = [*lines[:sentence_at], "- The attacker is in your network.", *lines[sentence_at:]]
    assert verify_rendered("\n".join(untagged), facts)
    bad_ref = rendered.replace("[1]", "[99]", 1)
    assert verify_rendered(bad_ref, facts)
    stray = rendered + "\nThis host is definitely safe."
    assert verify_rendered(stray, facts)


def test_every_answerable_intent_says_something_or_says_it_has_nothing(
    all_answers: list[tuple[AlertFacts, Answer]],
) -> None:
    for _facts, reply in all_answers:
        if reply.intent in ANSWERABLE:
            assert reply.sentences or reply.notes, reply.intent


def test_answers_are_deterministic(alerts: tuple[AlertFacts, ...]) -> None:
    for facts in alerts:
        for intent in Intent:
            assert answer(intent, facts).render(short_id=2) == answer(intent, facts).render(
                short_id=2
            )


# --- epistemic honesty ------------------------------------------------------


def test_an_unknown_is_never_negated_into_an_exoneration(
    all_answers: list[tuple[AlertFacts, Answer]],
) -> None:
    unk_sentences = 0
    for facts, reply in all_answers:
        for sentence in reply.sentences:
            lowered = sentence.text.lower()
            for pattern in EXONERATION_PATTERNS:
                assert not re.search(pattern, lowered), sentence.text
            kinds = {facts.get(fid).kind for fid in sentence.fact_ids}  # type: ignore[union-attr]
            if FactKind.UNK in kinds:
                unk_sentences += 1
                assert sentence.kind is FactKind.UNK, sentence
                assert any(marker in lowered for marker in EPISTEMIC_MARKERS), sentence.text
    assert unk_sentences > 0, "the demo alerts carry unknowns; none were rendered"


def test_an_inference_is_always_hedged(all_answers: list[tuple[AlertFacts, Answer]]) -> None:
    inf_sentences = 0
    for facts, reply in all_answers:
        for sentence in reply.sentences:
            kinds = {facts.get(fid).kind for fid in sentence.fact_ids}  # type: ignore[union-attr]
            if FactKind.INF in kinds:
                inf_sentences += 1
                assert sentence.kind in {FactKind.INF, FactKind.UNK}, sentence
            if sentence.kind is FactKind.INF:
                assert any(word in sentence.text.lower() for word in HEDGE_WORDS), sentence.text
    assert inf_sentences > 0


def test_no_forbidden_amplification_ever_appears(
    all_answers: list[tuple[AlertFacts, Answer]],
) -> None:
    for _facts, reply in all_answers:
        text = reply.render(short_id=1).lower()
        for word in FORBIDDEN_AMPLIFICATIONS:
            assert word not in text, (word, reply.intent)


def test_confidence_is_quoted_exactly_and_explained(alerts: tuple[AlertFacts, ...]) -> None:
    for facts in alerts:
        reply = answer(Intent.HOW_SURE, facts)
        text = " ".join(s.text for s in reply.sentences)
        recorded = facts.assessment.confidence
        assert recorded is not None
        assert f"confidence is {quote_number(recorded)}" in text
        if recorded == 0.0:
            assert "0.0" in text
            # Review finding G8: "could not tell the explanations apart" was the
            # template's own causal reading, not a recorded fact. Stage 4 records 0.0
            # for any unknown hole, no shadow model, or leader uncertainty 1.0, so the
            # answer must not name a cause at all.
            assert "could not tell" not in text
            assert "not a statement that the activity is harmless" in text


def test_quote_number_never_rounds_up() -> None:
    assert quote_number(0.0) == "0.0"
    assert quote_number(1.0) == "1.0"
    assert quote_number(0.25) == "0.25"
    assert quote_number(1 / 3) == "about 0.3333"
    assert quote_number(2 / 3) == "about 0.6666"
    assert quote_number(0.99999) == "about 0.9999"


def test_a_false_alarm_question_never_gets_a_yes(
    all_answers: list[tuple[AlertFacts, Answer]],
) -> None:
    for facts, reply in all_answers:
        if reply.intent is not Intent.FALSE_ALARM:
            continue
        text = reply.render(short_id=1).lower()
        assert "is a false alarm" not in text.replace(
            "not concluded that this is a false alarm", ""
        )
        assert "harmless" not in text or "not a benign finding" in text or "not" in text
        if facts.assessment.verdict in {"UNKNOWN", "UNIDENTIFIABLE", "INSUFFICIENT_EVIDENCE"}:
            assert "not a benign finding" in text


def test_why_flagged_names_the_observed_state_changes_not_the_engine(
    alerts: tuple[AlertFacts, ...],
) -> None:
    """The largest observed state changes are shown, labelled as ranking, not as the verdict."""
    for facts in alerts:
        reply = answer(Intent.WHY_FLAGGED, facts)
        top = max(facts.meanings, key=lambda m: (m.delta_phi, -m.sequence))
        cited = {fid for s in reply.sentences for fid in s.fact_ids}
        assert top.fact_id in cited
        assert any("did not single them out" in note for note in reply.notes)


def test_what_happened_is_in_sequence_order(alerts: tuple[AlertFacts, ...]) -> None:
    for facts in alerts:
        reply = answer(Intent.WHAT_HAPPENED, facts)
        steps = [
            int(match.group(1))
            for s in reply.sentences
            if (match := re.match(r"Step (\d+):", s.text))
        ]
        assert steps == sorted(steps) and steps


def test_expanded_answers_say_more_but_stay_bounded(alerts: tuple[AlertFacts, ...]) -> None:
    facts = alerts[0]
    short = answer(Intent.WHAT_HAPPENED, facts)
    longer = answer(Intent.WHAT_HAPPENED, facts, expanded=True)
    assert len(longer.sentences) >= len(short.sentences)
    assert len(longer.sentences) <= 40


def test_which_process_says_when_a_program_name_was_not_observed(
    alerts: tuple[AlertFacts, ...],
) -> None:
    seen_unknown_binary = False
    for facts in alerts:
        reply = answer(Intent.WHICH_PROCESS, facts)
        for sentence in reply.sentences:
            if sentence.kind is FactKind.UNK and "program name" in sentence.text:
                seen_unknown_binary = True
        assert any("not by name" in note for note in reply.notes)
    assert seen_unknown_binary


def test_what_action_without_a_response_record_is_unknown(alerts: tuple[AlertFacts, ...]) -> None:
    facts = alerts[0]
    assert facts.response is None
    for intent in (Intent.WHAT_ACTION, Intent.HOW_TO_UNDO):
        reply = answer(intent, facts)
        assert any(s.kind is FactKind.UNK for s in reply.sentences)
        assert "unknown" in " ".join(s.text for s in reply.sentences).lower()


# --- the other loaders ------------------------------------------------------


def test_export_only_handoff_explains_what_it_lacks() -> None:
    (run, *_rest) = build_demo_runs()
    facts = facts_from_handoff({"resolution": run.export.to_dict(), "synthetic": True})
    assert facts.events == ()
    reply = answer(Intent.WHY_FLAGGED, facts)
    assert any("not the underlying events" in note for note in reply.notes)
    assert check_answer(reply, facts) == ()
    assert any(s.kind is FactKind.OBS for s in answer(Intent.EVIDENCE, facts).sentences)


def test_handoff_round_trips_through_json() -> None:
    (run, *_rest) = build_demo_runs()
    payload = handoff_from_run(run, synthetic=True, provenance="test")
    again = json.loads(json.dumps(payload))
    assert facts_from_handoff(again) == facts_from_handoff(payload)


def test_capture_never_reads_corpus_ground_truth() -> None:
    """The explainer must not see ``IncidentCase.truth``; touching it fails this test."""
    (run, *_rest) = build_demo_runs()

    class _Tripwire:
        def __getattr__(self, name: str) -> Any:
            raise AssertionError(f"capture read run.case.{name}")

    replay = SimpleNamespace(
        result=run.replay.result, pipeline=run.replay.pipeline, case=_Tripwire()
    )
    wrapped = SimpleNamespace(
        export=run.export, resolution=run.resolution, replay=replay, case=_Tripwire()
    )
    payload = handoff_from_run(wrapped, synthetic=True, provenance="tripwire")
    assert payload["resolution"]["incident_id"] == run.export.incident_id


def test_answer_json_carries_the_provenance_list(alerts: tuple[AlertFacts, ...]) -> None:
    facts = alerts[0]
    payload = answer(Intent.WHY_FLAGGED, facts).to_dict(short_id=1)
    json.dumps(payload)
    assert payload["synthetic"] is True
    used = {fid for s in payload["sentences"] for fid in s["fact_ids"]}
    listed = {row["fact_id"] for row in payload["provenance"]}
    assert used == listed
    for row in payload["provenance"]:
        assert row["kind"] in {k.value for k in FactKind}
        assert row["source"]
        for digest in row["digests"]:
            assert re.fullmatch(r"sha256:[0-9a-f]{64}", digest)


# --- Stage 5: a real executed, leased and swept response ---------------------


def test_what_action_reports_the_executed_receipt(stage5_bundle: dict[str, Any]) -> None:
    facts = facts_from_handoff(stage5_bundle)
    reply = answer(Intent.WHAT_ACTION, facts)
    text = " ".join(s.text for s in reply.sentences)
    assert "SUSPEND_PROCESS" in text
    assert "PASS" in text
    assert "simulated" in text.lower()
    assert check_answer(reply, facts) == ()
    assert verify_rendered(reply.render(short_id=1), facts) == ()


def test_how_to_undo_reports_rollback_and_lease(stage5_bundle: dict[str, Any]) -> None:
    facts = facts_from_handoff(stage5_bundle)
    reply = answer(Intent.HOW_TO_UNDO, facts)
    text = " ".join(s.text for s in reply.sentences)
    assert "RESUME_PROCESS" in text
    assert "1900" in text  # expires_at, read from the real lease
    assert "reversed" in text.lower()
    assert any("can't undo anything myself" in note for note in reply.notes)
    assert check_answer(reply, facts) == ()


def test_stage5_fixture_hypotheses_are_hedged(stage5_bundle: dict[str, Any]) -> None:
    facts = facts_from_handoff(stage5_bundle)
    reply = answer(Intent.FALSE_ALARM, facts)
    assert check_answer(reply, facts) == ()
    for sentence in reply.sentences:
        if sentence.kind is FactKind.INF:
            assert "possible" in sentence.text.lower() or "may" in sentence.text.lower()
