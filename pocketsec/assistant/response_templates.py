"""Sentence-builders for what PocketSec's response stage recorded, and for advice.

What this module is FOR: the answers to "what was done?", "how do I undo it?", a
request to act, and "what should I do?". Every sentence here is about Stage 5's
*record* (kind REC) or about its absence (UNK). None of them can do anything: the
facts are plain rows (``response_rows.py``) and this module returns text.

Three rules the review of this module made explicit:

* **"It ran X" only when X reached the host.** A receipt SENTINEL refused is
  reported as submitted and stopped, never as run, and a refusal already listed as
  a denial is not repeated as a receipt (``build_record`` derives every denial from
  a receipt, so they are the same transaction).
* **A missing lease outcome is unknown**, not "no reversal was attempted".
* **Record truncations are not reasons.** ``ResponseRecordV1.truncations`` lists rows
  the record cut to stay bounded; the record has no planner-rationale field, so no
  sentence here claims one.
"""

from __future__ import annotations

from pocketsec.assistant.facts import AlertFacts, Denial, LeaseRow, Receipt
from pocketsec.assistant.phrasing import (
    decision_phrase,
    horizon_phrase,
    join_phrases,
    outcome_phrase,
    truncation_phrase,
)
from pocketsec.assistant.template_kit import (
    REACHED_HOST,
    Built,
    no_response,
    say,
)
from pocketsec.assistant.wording import Sentence

__all__ = ["action_request", "advice", "how_to_undo", "what_action"]

#: Record-truncation lines shown per answer; the rest stay in ``--json``.
MAX_TRUNCATION_LINES = 2


def _is_denial(receipt: Receipt, denials: tuple[Denial, ...]) -> bool:
    """Is this receipt the transaction a denial row was derived from?"""
    return any(
        d.operator_id == receipt.operator_id
        and d.outcome == receipt.outcome
        and d.digests == receipt.digests
        for d in denials
    )


def _receipt_line(receipt: Receipt) -> Sentence:
    checks = (
        f", and {receipt.checks_passed} of {receipt.checks_total} after-checks passed"
        if receipt.checks_total
        else ""
    )
    if receipt.outcome in REACHED_HOST:
        head = f"It ran {receipt.operator_id} (authority {receipt.authority})"
    else:
        head = f"{receipt.operator_id} (authority {receipt.authority}) was submitted and stopped"
    return say(
        f"{head}: {outcome_phrase(receipt.outcome)} ({receipt.outcome}); the safety checker "
        f"SENTINEL's verdict was {receipt.verdict}{checks}.",
        receipt,
    )


def _denial_lines(facts: AlertFacts) -> list[Sentence]:
    out: list[Sentence] = []
    for denial in facts.denials:
        reasons = join_phrases(denial.denial_reasons) or "none listed"
        who = (
            "The safety checker SENTINEL refused"
            if denial.kernel_ran
            else "An earlier gate refused"
        )
        out.append(
            say(f"{who} {denial.operator_id} ({denial.outcome}; reasons: {reasons}).", denial)
        )
    return out


def _truncation_lines(facts: AlertFacts) -> list[Sentence]:
    r = facts.response
    if r is None:
        return []
    out: list[Sentence] = []
    for reason in r.truncations[:MAX_TRUNCATION_LINES]:
        capped = truncation_phrase(reason)
        text = (
            f"The response record {capped}, so some of its entries were left out."
            if capped
            else f"The response record left some entries out ({reason})."
        )
        out.append(say(text, r))
    return out


def _response_header(facts: AlertFacts) -> list[Sentence]:
    r = facts.response
    if r is None:
        return []
    out = [
        say(
            f"PocketSec's response planner decided {r.plan_decision}: "
            f"{decision_phrase(r.plan_decision)}.",
            r,
        )
    ]
    if r.simulated:
        out.append(
            say(f"This response ran on a {r.host_kind.lower()} host, not a real machine.", r)
        )
    return out


def _handoff_line(facts: AlertFacts) -> list[Sentence]:
    a = facts.assessment
    if not a.horizon:
        return []
    return [
        say(
            f"When PocketSec's reasoning engine handed the incident on, "
            f"{horizon_phrase(a.horizon)}.",
            a,
        )
    ]


def what_action(facts: AlertFacts, expanded: bool) -> Built:
    if facts.response is None:
        return [*no_response(facts, "any action was taken"), *_handoff_line(facts)], [
            "WHERE_OPERATORS_ACT"
        ]
    out = _response_header(facts)
    out.extend(
        _receipt_line(receipt)
        for receipt in facts.receipts
        if not _is_denial(receipt, facts.denials)
    )
    out.extend(_denial_lines(facts))
    if not facts.receipts and not facts.denials:
        out.append(say("The response record lists no transactions.", facts.response))
    out.extend(_truncation_lines(facts))
    return out, ["WHERE_OPERATORS_ACT"]


def _undo_receipt_ids(facts: AlertFacts) -> set[str]:
    reversals = {lease.rollback_operator_id for lease in facts.leases if lease.rollback_operator_id}
    return {r.fact_id for r in facts.receipts if r.operator_id in reversals}


def _lease_ending(facts: AlertFacts, lease: LeaseRow) -> Sentence | None:
    if lease.expired_at is None:
        return None
    if lease.rolled_back is True:
        return say(
            f"The lease expired at time {lease.expired_at} and the change was reversed with "
            f"{lease.rollback_operator_id}.",
            lease,
        )
    if lease.rolled_back is False:
        return say(
            f"The lease expired at time {lease.expired_at} and the attempt to reverse the "
            "change failed.",
            lease,
        )
    missing = next((u for u in facts.unknowns if u.source == lease.source), None)
    if missing is None:
        return None
    return say(
        f"The lease expired at time {lease.expired_at}; whether the change was reversed is "
        "unknown, because the outcome is not recorded.",
        lease,
        missing,
    )


def _lease_lines(facts: AlertFacts) -> list[Sentence]:
    out: list[Sentence] = []
    for lease in facts.leases:
        out.append(
            say(
                f"Its lease {lease.lease_id} was granted at time {lease.granted_at} for "
                f"{lease.ttl_seconds} seconds, so it expires at time {lease.expires_at} "
                f"(hard limit {lease.hard_deadline}).",
                lease,
            )
        )
        ending = _lease_ending(facts, lease)
        if ending is not None:
            out.append(ending)
    return out


def _reversal_lines(facts: AlertFacts, changed: list[Receipt]) -> list[Sentence]:
    out: list[Sentence] = []
    for receipt in changed:
        if receipt.rollback_operator_id:
            out.append(
                say(
                    f"{receipt.operator_id} can be reversed with {receipt.rollback_operator_id}.",
                    receipt,
                )
            )
        else:
            out.append(
                say(f"The record names no reversal operator for {receipt.operator_id}.", receipt)
            )
    return out


def how_to_undo(facts: AlertFacts, expanded: bool) -> Built:
    if facts.response is None:
        return no_response(facts, "anything was done"), ["UNDO_AUTHORITY"]
    undo_ids = _undo_receipt_ids(facts)
    changed = [
        r for r in facts.receipts if r.outcome in REACHED_HOST and r.fact_id not in undo_ids
    ]
    out: list[Sentence] = []
    if not changed:
        out.append(
            say(
                "The response record lists no change that reached the host, so there is "
                "nothing recorded to undo.",
                facts.response,
            )
        )
    out.extend(_reversal_lines(facts, changed))
    out.extend(_lease_lines(facts))
    out.extend(
        say(
            f"The reversal {receipt.operator_id} ran: "
            f"{outcome_phrase(receipt.outcome)} ({receipt.outcome}).",
            receipt,
        )
        for receipt in facts.receipts
        if receipt.fact_id in undo_ids
    )
    return out, ["UNDO_AUTHORITY"]


def action_request(facts: AlertFacts, expanded: bool) -> Built:
    notes = ["NO_AUTHORITY", "WHERE_OPERATORS_ACT"]
    if facts.response is None:
        return no_response(facts, "anything was approved"), notes
    out = [
        say(
            f"The safety checker SENTINEL already approved {r.operator_id} for this alert "
            f"(verdict {r.verdict}): {outcome_phrase(r.outcome)}.",
            r,
        )
        for r in facts.receipts
        if r.verdict == "PASS"
    ]
    out.extend(_denial_lines(facts))
    if not out:
        out.append(
            say(
                "The response record lists no transaction SENTINEL approved for this alert.",
                facts.response,
            )
        )
    return out, notes


def advice(facts: AlertFacts, expanded: bool) -> Built:
    """"What should I do?": what PocketSec itself asked for, and no advice beyond it."""
    out = _handoff_line(facts)
    if facts.response is not None:
        out.extend(_response_header(facts)[:1])
    return out, ["NO_ADVICE"]
