"""G7.1, G7.2, G7.3 and G7.9 — the construction and behaviour checks of the Stage 7 gate.

These four criteria are the stage's deliverable: the boundary that keeps foreign knowledge
untrusted. Each is settled twice — by construction (the §5.1 AST rules, evaluated here by
the SAME predicates ``tests/test_stage7_boundary.py`` attacks with negative fixtures) and by
behaviour (the real fabric, bridge, ingress and revocation plane on the simulated fleet).
A check over zero objects is VACUOUS and FAILS with the reason; it never passes on nothing.
"""

from __future__ import annotations

import copy
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.contracts.threat_prediction_v1 import FORBIDDEN_AUTHORITY_FIELDS
from pocketsec.stage0.gate import GateCheck
from pocketsec.stage7.capsule.knowledge_capsule import KnowledgeCapsuleV1
from pocketsec.stage7.constitution.collective import verify_collective_constitution
from pocketsec.stage7.gate_boundary import BOUNDARY_RULES, rule_offenders

if TYPE_CHECKING:
    from pocketsec.stage7.gate import Stage7GateContext

__all__ = [
    "check_g7_1",
    "check_g7_2",
    "check_g7_3",
    "check_g7_9",
    "wire_key_fuzz",
]

_REFUSALS = (ContractError, ValueError, TypeError, KeyError, RecursionError)


def _rules(numbers: tuple[int, ...]) -> tuple[dict[int, int], list[str]]:
    counts: dict[int, int] = {}
    shown: list[str] = []
    for number in numbers:
        offenders = rule_offenders(number)
        counts[number] = len(offenders)
        shown += [f"rule {number}: {o}" for o in offenders[:3]]
    return counts, shown


def _vacuous(what: str) -> str:
    return f"VACUOUS: {what} — a check over zero objects fails"


# --- G7.1 ---------------------------------------------------------------------------------------


def _g7_1_behaviour(ctx: Stage7GateContext) -> tuple[bool, str]:
    obs = ctx.observations
    created = sum(o.created for o in obs)
    admitted = sum(o.admitted for o in obs)
    offered = sum(o.gateway_offered for o in obs)
    mismatched = [m for o in obs for m in o.mismatched]
    ok = bool(obs) and created > 0 and created == admitted == offered and not mismatched
    detail = (f"(b) {len(obs)} suite runs: bridges built {created} ExperienceCapsuleV1, passed "
              f"{admitted} to admit, lab gateways were offered {offered}; mismatched receivers "
              f"{mismatched[:3] or 'none'}")
    if created == 0:
        detail += "; " + _vacuous("no capsule was ever bridged")
    return ok, detail


def _g7_1_unanimous(ctx: Stage7GateContext) -> tuple[bool, str]:
    u = ctx.unanimous
    if u is None:
        return False, "(c) the unanimous-fleet run did not complete"
    sent, held = dict(u.sent), dict(u.held)
    kinds = ("revoke", "support_fp", "contest", "authority")
    every = all(sent.get(k, 0) > 0 and held.get(k, 0) == sent[k] for k in kinds)
    ok = (every and u.min_senders >= ctx.unanimous_peers and u.fp_exercised > 0
          and u.fp_challenged == u.fp_exercised and u.local_intact == u.receivers
          and u.revocations_accepted == 0)
    return ok, (
        f"(c) {u.min_senders} independent-root peers per receiver x {u.receivers} receivers: "
        f"(i) revocations of the local-origin capsule refused local_sovereignty "
        f"{held.get('revoke', 0)}/{sent.get('revoke', 0)}, accepted {u.revocations_accepted}; "
        f"(ii) SUPPORT for a locally-FP rule: {u.fp_challenged}/{u.fp_exercised} receivers "
        f"ended CHALLENGED, never ELIGIBLE, never bridged; (iii) contests of the local "
        f"antibody refused at ingress {held.get('contest', 0)}/{sent.get('contest', 0)}, local "
        f"state intact at {u.local_intact}/{u.receivers}; (iv) authority-keyed payloads "
        f"refused at SCHEMA {held.get('authority', 0)}/{sent.get('authority', 0)}; (v) bridged "
        f"in the unanimous arm {u.bridged}, Stage 6 buckets {dict(u.buckets) or '{}'} "
        f"(reported; M0.2 predicts none TRUSTED_CANDIDATE)"
    )


def check_g7_1(ctx: Stage7GateContext) -> GateCheck:
    """G7.1 — No remote object can bypass Stage 6 quarantine."""
    counts, shown = _rules((5, 6, 7, 10, 11))
    constitution = verify_collective_constitution()
    construction = not any(counts.values()) and constitution == ()
    behaviour, b_detail = _g7_1_behaviour(ctx)
    unanimous, u_detail = _g7_1_unanimous(ctx)
    buckets: dict[str, int] = {}
    for o in ctx.observations:
        for bucket, n in o.buckets:
            buckets[bucket] = buckets.get(bucket, 0) + n
    detail = (
        f"(a) boundary offenders by rule {counts} {shown or ''}; constitution problems "
        f"{list(constitution) or 'none'}. {b_detail}; Stage 6 buckets over the suite "
        f"{buckets or '{}'}. {u_detail}"
    )
    return GateCheck("G7.1", "No remote object can bypass Stage 6 quarantine",
                     construction and behaviour and unanimous, detail)


# --- G7.2 ---------------------------------------------------------------------------------------


def _dict_locations(payload: Any, path: str = "") -> Iterator[tuple[str, dict[str, Any]]]:
    """Every dict in the payload (top level and every nested record, list items included)."""
    if isinstance(payload, dict):
        yield path or "<top>", payload
        for key, value in payload.items():
            yield from _dict_locations(value, f"{path}.{key}" if path else key)
    elif isinstance(payload, list):
        for index, item in enumerate(payload):
            yield from _dict_locations(item, f"{path}[{index}]")


def wire_key_fuzz(capsules: list[KnowledgeCapsuleV1]) -> tuple[int, int, int, list[str]]:
    """Inject each authority word as a key at every record of every capsule's wire payload.

    Returns (injections, refused, controls accepted, leaks). A control — the unmodified
    payload — must round-trip, or every refusal would be vacuous.
    """
    injections = refused = controls = 0
    leaks: list[str] = []
    for capsule in capsules:
        payload = capsule.to_dict()
        controls += KnowledgeCapsuleV1.from_dict(copy.deepcopy(payload)) == capsule
        for index, (where, _) in enumerate(list(_dict_locations(payload))):
            for word in sorted(FORBIDDEN_AUTHORITY_FIELDS):
                probe = copy.deepcopy(payload)
                list(_dict_locations(probe))[index][1][word] = "x"
                injections += 1
                try:
                    KnowledgeCapsuleV1.from_dict(probe)
                except _REFUSALS:
                    refused += 1
                    continue
                leaks.append(f"{capsule.knowledge_type.value}:{where}.{word}")
    return injections, refused, controls, leaks


def check_g7_2(ctx: Stage7GateContext) -> GateCheck:
    """G7.2 — No Stage 7 path can directly execute Stage 5 response."""
    counts, shown = _rules((3, 8, 9, 12))
    samples = list(ctx.capsule_samples.values())
    injections, refused, controls, leaks = wire_key_fuzz(samples)
    authority = ctx.authority_offered
    pooled = sum(n for k, n in authority.items() if k.startswith("adversarial:POOLED"))
    sent = sum(n for k, n in authority.items() if k.startswith("adversarial:"))
    passed = (not any(counts.values()) and injections > 0 and refused == injections
              and controls == len(samples) and sent > 0 and pooled == 0)
    detail = (
        f"boundary offenders by rule {counts} {shown or ''} "
        f"({', '.join(BOUNDARY_RULES[n][0] for n in (3, 8, 9, 12))}); wire-key fuzz: "
        f"{len(FORBIDDEN_AUTHORITY_FIELDS)} words x every record of {len(samples)} knowledge "
        f"types = {injections} injections, {refused} refused by from_dict, leaks "
        f"{leaks[:3] or 'none'}; unmodified controls round-tripped {controls}/{len(samples)}; "
        f"AUTHORITY_INJECTION arm: {sent} adversarial deliveries, {pooled} pooled"
    )
    if sent == 0:
        detail += "; " + _vacuous("the AUTHORITY_INJECTION arm sent nothing")
    return GateCheck("G7.2", "No Stage 7 path can directly execute Stage 5 response",
                     passed, detail)


# --- G7.3 ---------------------------------------------------------------------------------------


def check_g7_3(ctx: Stage7GateContext) -> GateCheck:
    """G7.3 — Local detection remains fully operational with network disabled."""
    counts, shown = _rules((11,))
    rows = ctx.offline
    bad = [h for h, r in rows if not r.identical]
    not_disabled = [h for h, r in rows if not r.corrupt_reached_disabled]
    unfired = [h for h, r in rows if r.crashing_failures == 0 or r.offline_dropped == 0]
    passed = bool(rows) and not bad and not not_disabled and not unfired and counts[11] == 0
    detail = (
        f"{len(rows)} receivers: local-output digest identical with the fabric absent, OFFLINE "
        f"under a FLOOD, crashing every round, DISABLED and with a corrupt keyring at "
        f"{len(rows) - len(bad)}/{len(rows)}; corrupt keyring reached DISABLED at "
        f"{len(rows) - len(not_disabled)}/{len(rows)}; faults fired (crash failures, offline "
        f"drops) {[(h, r.crashing_failures, r.offline_dropped) for h, r in rows]}; T7 offenders "
        f"{counts[11]} {shown or ''}. The partition is simulated: real network loss is UNMEASURED"
    )
    if unfired:
        detail += "; " + _vacuous(f"the injected faults never fired at {unfired}")
    return GateCheck("G7.3", "Local detection remains fully operational with network disabled",
                     passed, detail)


# --- G7.9 ---------------------------------------------------------------------------------------


def check_g7_9(ctx: Stage7GateContext) -> GateCheck:
    """G7.9 — Revocation is targeted and reversible."""
    r = ctx.revocation
    judged, false_accepted, false_changed = ctx.false_revocation
    if r is None or r.target is None:
        note = r.note if r is not None else "the revocation experiment did not run"
        return GateCheck("G7.9", "Revocation is targeted and reversible", False,
                         _vacuous(note))
    echo_exact = r.echo_keys_expected == r.echo_keys_newly_suspect and bool(r.echo_keys_expected)
    passed = (r.signature_valid and r.accepted and r.affected_exact
              and r.non_descendants_changed == 0 and echo_exact
              and r.stage6_expected == r.stage6_reported and bool(r.stage6_expected)
              and r.digest_restored and judged > 0 and false_accepted == 0
              and false_changed == 0)
    detail = (
        f"signed SELF_RETRACTION of {r.target} ({r.note}): {r.reason}; exactly the target and "
        f"its descendants SUSPECT {r.affected_exact}; non-descendants changed "
        f"{r.non_descendants_changed}; ECHO keys newly SUSPECT {list(r.echo_keys_newly_suspect)}"
        f" vs keys beneath {list(r.echo_keys_expected)}; stage6_capsule_ids "
        f"{len(r.stage6_reported)} = STAGE6_LINKs beneath {len(r.stage6_expected)} "
        f"({r.stage6_expected == r.stage6_reported}); reinstate restored the DAG digest "
        f"byte-for-byte {r.digest_restored}. FALSE_REVOCATION arm: {judged} judged, "
        f"{false_accepted} accepted, {false_changed} lineage nodes not LIVE. Stage 6-side "
        f"rollback of the targeted capsules is UNMEASURED: Stage 6 exposes no revocation "
        f"input (B7-2)"
    )
    return GateCheck("G7.9", "Revocation is targeted and reversible", passed, detail)
