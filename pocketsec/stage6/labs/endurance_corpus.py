"""D6.20 — the month/year endurance timeline (architecture §51), and nothing else.

Stage 6 claims long-horizon behaviour, so it needs a corpus with a *history*: a
host that is upgraded, attacked, rolled back, re-attacked and relabelled over a
year. This module builds that year as twelve ``MonthPlan``s of ordinary
``Scenario``s. It is **not** a second corpus builder: every session is minted by
``stage2.labs.drift_corpus``'s ``make_actors`` / ``interleave`` /
``session_behaviour``, and every scenario is a Stage 1 ``Scenario``. What is new
here is the calendar and the block each session carries.

Three construction rules, each the repair of a defect this repository already
shipped once:

* **Session-unique identities** (integration plan §5.4). ``Stage1Pipeline``
  carries lineage state across scenarios; one global session counter feeds
  ``make_actors`` so no pid:start pair is ever reused within a timeline. The
  namespace (``ENDURANCE_NAMESPACE``) is disjoint from Stage 2's 200_000 and
  300_000 namespaces.
* **Matched composition** (MEMORY benchmarking trap 4, E5). Every eval session
  holds five routine actors of two steps and one five-step block whose relations
  are always ``setuid, read, write, connect, send``. The classes differ only in
  *which objects* the block touches and *whether one lineage performs all of it*;
  a bag of relation counts cannot tell them apart.
* **Twins, so a zero-learning control cannot win** (spec §4.20 E2). Each family
  has a benign twin that raises the same state dimensions (the same per-lineage
  cumulative ΔΦ) and matches the same generic motif, differing in one object
  class a refined motif can require or forbid. The spec table words T1 as
  "read CREDENTIAL -> send loopback"; that twin would raise less ΔΦ than F1 and
  hand the ΔΦ control a free separation, so T1 here reads a *staged* credential
  copy under ``/var/tmp`` (CREDENTIAL + TEMP_LOCATION) and ships it off-host.

Ground truth — family, role, the attacking lineage, the labels an analyst would
attach — travels in ``EnduranceSession`` accounting fields and the scenario
*name*, never in a ``Behaviour`` field that would reach telemetry.

Everything is synthetic; every figure derived from it is a synthetic figure.
"""

from __future__ import annotations

import random
from collections.abc import Sequence
from dataclasses import dataclass, replace
from enum import IntEnum

from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage1.epoch.model import EpochDecision, SystemIdentity
from pocketsec.stage1.labs.corpus import Behaviour, Scenario
from pocketsec.stage1.pipeline import Stage1Pipeline
from pocketsec.stage1.telemetry.raw_event_v1 import SensorPath
from pocketsec.stage2.adaptation.epoch_guard import SystemChangeSignal
from pocketsec.stage2.labs.drift_corpus import (
    SessionActor,
    interleave,
    make_actors,
    session_behaviour,
)
from pocketsec.stage2.labs.poison_suite import (
    POISON_TECHNIQUE_SLOW_DRIFT,
    build_poison_suite,
    poison_lineage,
)
from pocketsec.stage6.capsule.experience_capsule import (
    EncodedStep,
    ExperienceCapsuleV1,
    LabelAssertion,
    LabelOrigin,
    SourceClass,
    SourceProvenance,
    capsule_from_label,
    capsule_from_scenario,
)
from pocketsec.stage6.constitution.learning import MIN_INDEPENDENT_GROUPS
from pocketsec.stage6.resources import ResourceSnapshot

__all__ = [
    "ANALYST_GROUPS",
    "ENDURANCE_NAMESPACE",
    "ENDURANCE_SEED",
    "ENDURANCE_VERSION",
    "EVAL_SESSIONS_PER_FAMILY",
    "FAMILIES",
    "POISON_ANALYST_GROUP",
    "ROUTINE_POOLS",
    "SENSOR_DROP_SHARE",
    "SESSIONS_PER_MONTH",
    "TWINS",
    "TWIN_INTRODUCED",
    "YEAR_CYCLES",
    "EnduranceSession",
    "IdentityMint",
    "Month",
    "MonthPlan",
    "SessionLabel",
    "TELEMETRY_HOST",
    "CompiledMonth",
    "CompiledTimeline",
    "StreamEvent",
    "compile_timeline",
    "simulated_snapshot",
    "apply_signal",
    "attacker_session",
    "block_session",
    "build_endurance_timeline",
    "build_year_timeline",
    "compile_session",
    "label_provenance",
    "telemetry_provenance",
]

ENDURANCE_VERSION = "stage6-endurance-v0.1.0"
SESSIONS_PER_MONTH: int = 16
EVAL_SESSIONS_PER_FAMILY: int = 8
YEAR_CYCLES: int = 5
ENDURANCE_SEED: int = 11
#: Disjoint from Stage 2's drift (200_000) and poison (300_000) namespaces.
ENDURANCE_NAMESPACE: int = 600_000
#: M07's sensor change loses this share of *routine* records. Chain steps are
#: never dropped: a dropped chain step would make a session's ground truth a lie.
SENSOR_DROP_SHARE: float = 0.2

FAMILIES: tuple[str, ...] = ("F1", "F2", "F3")
TWINS: tuple[str, ...] = ("T1", "T2", "T3")
#: The calendar month each benign twin first appears in live traffic (§51 table).
TWIN_INTRODUCED: dict[str, int] = {"T1": 1, "T2": 5, "T3": 9}
#: Two independent analyst groups: the label quorum (MIN_INDEPENDENT_LABEL_GROUPS).
ANALYST_GROUPS: tuple[str, ...] = ("analyst:alpha", "analyst:beta")
#: M10's poisoner: one analyst group asserting BENIGN on attack episodes.
POISON_ANALYST_GROUP = "analyst:mallory"

_BOOT = "boot-0001"
_SECOND_NS = 1_000_000_000
_MINUTE_NS = 60 * _SECOND_NS
#: Sessions are sized to fit an episodic skeleton WITHOUT loss. A skeleton is
#: capped at MAX_SKELETON_BYTES (~19 encoded steps measured on this corpus);
#: past that it silently drops the later non-escalating steps, which are exactly
#: the steps that make a *benign* session match a generalised 2-step motif. Then
#: induce_motifs measures precision on a representation the score never uses and
#: every learner ships detectors that fire on everything (measured: 35-step
#: sessions -> 18-step skeletons -> every learner at recall 0.0). Five actors x
#: two routine steps + the five-step block = 15 steps keeps induction and scoring
#: on the same steps. Real sessions are far longer; that loss is a finding about
#: the memory design, not something this corpus may hide from a real host.
_ROUTINE_STEPS = 2
_ROUTINE_ACTORS = 5

_Step = tuple[str, dict[str, str]]
_Pool = tuple[tuple[str, tuple[_Step, ...]], ...]


class Month(IntEnum):
    """Architecture §51, one member per bullet."""

    M01 = 1  # stable host
    M02 = 2  # software update
    M03 = 3  # benign workload expansion
    M04 = 4  # slow poisoning attempt
    M05 = 5  # new attack family
    M06 = 6  # rollback to old stack
    M07 = 7  # sensor change
    M08 = 8  # recurring old attack
    M09 = 9  # benign rare admin
    M10 = 10  # targeted label poison
    M11 = 11  # resource pressure
    M12 = 12  # mixed recurrence


@dataclass(frozen=True, slots=True)
class SessionLabel:
    """One label an analyst (or poisoner) attaches to a session. Accounting-side only."""

    verdict: Verdict
    origin: LabelOrigin
    group: str


@dataclass(frozen=True, slots=True)
class EnduranceSession:
    """One session plus its ground truth. ``family``/``role``/``labels`` never reach telemetry.

    ``role`` is one of routine, attack, twin, poison, eval. For ``poison`` sessions
    ``family`` names the arm (``"P1"`` …) or, for label poison, the targeted family.
    """

    session_id: str
    month: int
    scenario: Scenario
    family: str | None
    role: str
    labels: tuple[SessionLabel, ...] = ()
    sensor: str = "EBPF"


@dataclass(frozen=True, slots=True)
class MonthPlan:
    """One month: the host identity, an optional out-of-band change, and the traffic.

    ``signal_at`` is the index into ``sessions`` before which ``signal`` applies
    (0 = month start). ``pressure`` marks M11: the harness hands learners a
    ``ResourceSnapshot`` above every §40 threshold for the whole month.
    """

    month: int
    identity: SystemIdentity
    signal: SystemChangeSignal | None
    sessions: tuple[EnduranceSession, ...]
    eval_sessions: tuple[EnduranceSession, ...]
    signal_at: int = 0
    pressure: bool = False
    sensor: str = "EBPF"


def _role(name: str, version: str, steps: tuple[_Step, ...]) -> tuple[str, tuple[_Step, ...]]:
    return name, (("execve", {"path": f"/usr/lib/{name}d/{name}d-{version}"}), *steps)


def _loop(op: str, port: str) -> _Step:
    return op, {"raddr": "127.0.0.1", "rport": port}


# --- routine pools -----------------------------------------------------------
# Capability-neutral on purpose: loopback only, no credential objects, no
# privilege change. A role is its binary plus ONE operation: sessions hold
# _ROUTINE_STEPS = 2 steps per actor (binary + operation), so any further step a
# pool listed would be a catalogue richer than its consumer (lesson 3).
_POOL_A: _Pool = (
    _role("web", "1.4", (("read", {"path": "/etc/webd/site.conf"}),)),
    _role("index", "3.1", (("read", {"path": "/srv/index/shard.dat"}),)),
    _role("queue", "2.2", (("read", {"path": "/var/spool/queued/job"}),)),
    _role("metric", "1.0", (("read", {"path": "/proc/self/stat"}),)),
    _role("cache", "0.9", (("read", {"path": "/var/lib/cached/dump.rdb"}),)),
    _role("render", "5.1", (("read", {"path": "/srv/render/template.html"}),)),
)
#: After the M02 upgrade two roles change *mechanism* (the drift-corpus lesson:
#: a path-only change is invisible to a name-free encoder): queue now stages its
#: jobs under /var/tmp and render runs under an interpreter.
_POOL_B: _Pool = (
    _role("web", "2.0", (("read", {"path": "/etc/webd/site.v2.conf"}),)),
    _role("index", "4.0", (("read", {"path": "/srv/index/v2/shard.dat"}),)),
    ("queue", (("execve", {"path": "/usr/lib/queued/queued-3.0"}),
               ("read", {"path": "/var/tmp/queued/job"}))),
    _role("metric", "1.6", (("read", {"path": "/proc/self/stat"}),)),
    _role("cache", "1.2", (("read", {"path": "/var/lib/cached/v1/dump.rdb"}),)),
    ("render", (("execve", {"path": "/usr/bin/python3"}),
                ("read", {"path": "/srv/render/v6/template.html"}))),
)
#: M03: two new services, one on a relation the host never used before
#: (receive) — the benign novelty normality learning must absorb.
_POOL_B3: _Pool = (
    *_POOL_B[:3],
    _role("rotate", "1.0", (("read", {"path": "/var/log/webd/access-2.log"}),)),
    _role("sync", "2.0", (_loop("recv", "7070"),)),
    _POOL_B[5],
)

#: The routine pools by phase, for arms that need the same host traffic.
ROUTINE_POOLS: dict[str, _Pool] = {"A": _POOL_A, "B": _POOL_B, "B3": _POOL_B3}

# --- the five-step blocks ------------------------------------------------------
# Relations are identical for every class: setuid, read, write, connect, send.


def _block(read: str, write: str, raddr: str, rport: str) -> tuple[_Step, ...]:
    return (
        ("setuid", {"target_uid": "0"}),
        ("read", {"path": read}),
        ("write", {"path": write}),
        ("connect", {"raddr": raddr, "rport": rport}),
        ("send", {"raddr": raddr, "rport": rport}),
    )


def _class_block(cls: str, rng: random.Random) -> tuple[_Step, ...]:
    """The block for one class. Draws the same rng calls whatever ``cls`` is."""
    ext = f"203.0.113.{rng.randrange(2, 250)}"
    tag = f"{rng.randrange(16**6):06x}"
    audit, config = "/var/log/audit/sess.log", "/srv/app/config.json"
    blocks = {
        "F1": _block("/etc/shadow", "/var/log/audit/sess.log", ext, "443"),
        "T1": _block(f"/var/tmp/backup-{tag}/.aws/credentials", audit, ext, "443"),
        "T3": _block("/etc/shadow", audit, f"10.20.0.{int(tag[:2], 16) % 250 + 2}", "22"),
        "F2": _block(config, f"/etc/systemd/system/{tag}.service", "127.0.0.1", "8080"),
        "T2": _block(
            config, f"/var/tmp/dpkg-{tag}/etc/systemd/system/pkg.service", "127.0.0.1", "8080"
        ),
        "F3": _block("/srv/data/export.db", f"/var/tmp/.cache-{tag}/stage.tar", ext, "443"),
    }
    return blocks[cls]


def _thread(rng: random.Random, stream: list[Behaviour], actors: list[SessionActor],
            block: tuple[_Step, ...], *, single: bool) -> SessionActor:
    """Insert ``block`` into the stream through one lineage (single) or five distinct ones.

    Both the owner and the spread are always drawn, so the rng — and therefore
    every later draw — is identical for both classes.
    """
    owner = rng.choice(actors)
    spread = rng.sample(actors, k=len(block))
    stride = max(3, len(stream) // (len(block) + 1))
    start = rng.randrange(1, max(2, len(stream) - stride * (len(block) - 1)))
    for offset, step in enumerate(block):
        actor = owner if single else spread[offset]
        at = max(0, min(start + offset * stride, len(stream)))
        stream.insert(at, session_behaviour(actor, step, rng.randrange(5, 40) * _MINUTE_NS))
    return owner


@dataclass
class IdentityMint:
    """The one place session identities come from. Never reused within a timeline."""

    rng: random.Random
    namespace: int = ENDURANCE_NAMESPACE
    counter: int = 0

    def actors(self, pool: _Pool) -> list[SessionActor]:
        self.counter += 1
        return make_actors(
            self.rng, pool, _ROUTINE_ACTORS, session=self.counter, namespace=self.namespace
        )


def block_session(mint: IdentityMint, pool: _Pool, cls: str | None, *, month: int, role: str,
                  labels: tuple[SessionLabel, ...] = (), drop_share: float = 0.0,
                  sensor: str = "EBPF") -> EnduranceSession:
    """One matched-composition session. ``cls=None`` is routine: a block spread over five actors."""
    rng = mint.rng
    actors = mint.actors(pool)
    stream = interleave(rng, [(actor, _ROUTINE_STEPS) for actor in actors])
    if drop_share > 0.0:
        stream = [b for b in stream if rng.random() >= drop_share]
    spread_cls = rng.choice(("F1", "F2", "F3"))
    block = _class_block(cls or spread_cls, rng)
    owner = _thread(rng, stream, actors, block, single=cls is not None)
    name = f"endurance-m{month:02d}-s{mint.counter:05d}"
    if cls in FAMILIES:
        name = f"{name}-attack@{owner.pid}:{owner.start_time}"
    scenario = Scenario(name=name, behaviours=tuple(stream), label=1 if cls in FAMILIES else 0,
                        technique=cls or "routine", unseen_technique=False)
    return EnduranceSession(session_id=name, month=month, scenario=scenario, family=cls,
                            role=role, labels=labels, sensor=sensor)


def _attacker(mint: IdentityMint, children: int) -> list[SessionActor]:
    """Short-lived attacker lineages, from the same identity mint as everything else."""
    mint.counter += 1
    return [
        SessionActor(name=f"stager-{i}", pid=str(mint.namespace + mint.counter * 100 + 50 + i),
                     start_time=str(mint.namespace // 100 + mint.counter * 10 + 5 + i), routine=())
        for i in range(children)
    ]


#: P1 / P1b: an escalation-free staging step on a relation the host's own
#: traffic never uses, so the attacker *owns* its Stage 2 pattern key — the
#: shape of the spec §0 single-source probe that Stage 2 promotes.
_STAGING_STEP: _Step = ("unlink", {"path": "/var/tmp/.x-stage/chunk.part"})
#: P2b: an escalation-free read of attacker staging on the SHARED read key,
#: timed to land first after a genuine upgrade releases Stage 2's anchors. The
#: object is a staged interpreter under /dev/shm (TEMP + USER_WRITABLE +
#: INTERPRETER): no routine role reads anything with that meaning, so capturing
#: the anchor with it is a change of meaning, not a coincidence of paths.
_CAPTURE_STEP: _Step = ("read", {"path": "/dev/shm/.x-stage/perl"})
_STEPS_PER_ATTACKER_SESSION = 8


def attacker_session(mint: IdentityMint, arm: str, *, month: int, seed: int) -> EnduranceSession:
    """An attacker-only session for a DATA / SLOW_DRIFT arm (the capsule is pure poison).

    ``P1``: one lineage, eight staging steps. ``P1b``: fork-spray, the same eight
    steps from four short-lived children (MIN_INDEPENDENT_GROUPS + 1).
    ``P2``: Stage 2's own slow-drift walk, lifted out of ``build_poison_suite``
    (the poison lineage's behaviours only), never re-typed here. ``P2b``: the
    anchor-capture read.
    """
    rng = mint.rng
    if arm == "P2":
        behaviours = _stage2_slow_drift(mint, seed=seed)
    else:
        children = MIN_INDEPENDENT_GROUPS + 1 if arm == "P1b" else 1
        actors = _attacker(mint, children)
        step = _CAPTURE_STEP if arm == "P2b" else _STAGING_STEP
        behaviours = tuple(
            session_behaviour(actors[i % children], step, rng.randrange(2, 60) * _SECOND_NS)
            for i in range(_STEPS_PER_ATTACKER_SESSION)
        )
    name = f"endurance-m{month:02d}-s{mint.counter:05d}-poison-{arm}"
    scenario = Scenario(
        name=name, behaviours=behaviours, label=1, technique=arm, unseen_technique=False
    )
    return EnduranceSession(
        session_id=name, month=month, scenario=scenario, family=arm, role="poison"
    )


def _stage2_slow_drift(mint: IdentityMint, *, seed: int) -> tuple[Behaviour, ...]:
    """Stage 2's slow-drift block, re-identified into this timeline's namespace."""
    suite = build_poison_suite(count=6, seed=seed)
    drift = next(s for s in suite if s.technique == POISON_TECHNIQUE_SLOW_DRIFT)
    lineage = poison_lineage(drift)
    actor = _attacker(mint, 1)[0]
    kept = [b for b in drift.behaviours
            if f"proc:{_BOOT}:{b.fields.get('pid')}:{b.fields.get('start_time')}" == lineage]
    return tuple(b.with_fields(pid=actor.pid, start_time=actor.start_time) for b in kept)


def _labels(verdict: Verdict, groups: Sequence[str] = ANALYST_GROUPS) -> tuple[SessionLabel, ...]:
    return tuple(SessionLabel(verdict=verdict, origin=LabelOrigin.ANALYST, group=g) for g in groups)


_MAL = _labels(Verdict.MALICIOUS)
_BEN = _labels(Verdict.BENIGN)
_POISON_BENIGN = _labels(Verdict.BENIGN, (POISON_ANALYST_GROUP,))

#: Per month: (family/twin classes with their labels), attacker arms, and the
#: routine fill. Recurrences (M08, M12) are UNLABELLED: retention is measured on
#: attacks nobody pointed out again, which is the only honest retention test.
_ClassPlan = tuple[tuple[str, tuple[SessionLabel, ...], int], ...]
_TRAFFIC: dict[int, tuple[_ClassPlan, tuple[str, ...]]] = {
    1: ((("F1", _MAL, 4), ("T1", _BEN, 4)), ()),
    2: ((), ()),
    3: ((), ()),
    4: ((), ("P1", "P1", "P1b", "P1b", "P2", "P2")),
    5: ((("F2", _MAL, 4), ("T2", _BEN, 4)), ()),
    6: ((), ()),
    7: ((("F3", _MAL, 4),), ()),
    8: ((("F1", (), 4),), ()),
    9: ((("T3", _BEN, 4),), ()),
    10: ((("F2", _POISON_BENIGN, 4),), ()),
    11: ((), ()),
    12: (tuple((cls, (), 2) for cls in ("F1", "F2", "F3", "T1", "T2", "T3")), ()),
}


def _identities(cycle: int) -> dict[str, SystemIdentity]:
    a = SystemIdentity(
        kernel_id=f"6.1.{cycle}", package_digest=f"pkg-a-{cycle}", service_digest=f"svc-a-{cycle}"
    )
    b = replace(a, package_digest=f"pkg-b-{cycle}", service_digest=f"svc-b-{cycle}")
    c = replace(b, policy_digest=f"pol-c-{cycle}")
    return {"A": a, "B": b, "C": c}


def _month_frame(month: int, cycle: int) -> tuple[str, SystemChangeSignal | None, _Pool, str]:
    """(context letter, signal, routine pool, sensor) for one calendar month."""
    ctx = {1: "A", 2: "B", 3: "B", 4: "C", 5: "C"}.get(month, "A")
    pool = _POOL_A if ctx == "A" else (_POOL_B if month == 2 else _POOL_B3)
    signal: SystemChangeSignal | None = None
    if month == 1 and cycle > 0:
        changed = frozenset({"kernel_id", "package_digest", "service_digest"})
        signal = SystemChangeSignal(changed=changed, corroborated=changed)
    elif month in (2, 6):
        changed = frozenset(
            {"package_digest", "service_digest"} | ({"policy_digest"} if month == 6 else set())
        )
        signal = SystemChangeSignal(changed=changed, corroborated=changed)
    elif month == 4:
        signal = SystemChangeSignal(
            changed=frozenset({"policy_digest"}), corroborated=frozenset({"policy_digest"})
        )
    return ctx, signal, pool, "AUDITD" if month == 7 else "EBPF"


def _stream(
    mint: IdentityMint, month: int, pool: _Pool, sessions: int, sensor: str, seed: int
) -> tuple[list[EnduranceSession], int]:
    """The month's live traffic, shuffled, and where the month's signal lands."""
    classes, arms = _TRAFFIC[month]
    drop = SENSOR_DROP_SHARE if month == 7 else 0.0
    items: list[EnduranceSession] = []
    for cls, labels, count in classes:
        role = "attack" if cls in FAMILIES else "twin"
        role = "poison" if labels == _POISON_BENIGN else role
        items += [block_session(mint, pool, cls, month=month, role=role, labels=labels,
                                drop_share=drop, sensor=sensor) for _ in range(count)]
    fill = max(0, sessions - len(items) - len(arms) - (1 if arms else 0))
    routine = [
        block_session(mint, pool, None, month=month, role="routine", drop_share=drop, sensor=sensor)
        for _ in range(fill)
    ]
    if month == Month.M01:
        # "Stable host": the host's own routine precedes the first attack, as on
        # any real endpoint. Without it every learner would induce its first
        # detector against an empty benign pool — a cold-start artefact, not a
        # property of any mechanism under test.
        mint.rng.shuffle(items)
        return routine[: fill // 2] + items[:1] + routine[fill // 2:] + items[1:], 0
    items += routine
    mint.rng.shuffle(items)
    if month != 4:
        return items, 0
    # M04: the upgrade lands mid-month; P1/P1b/P2 straddle it, P2b lands first after it.
    half = len(items) // 2
    before = [attacker_session(mint, arm, month=month, seed=seed) for arm in arms[::2]]
    after = [attacker_session(mint, arm, month=month, seed=seed + 1) for arm in arms[1::2]]
    capture = attacker_session(mint, "P2b", month=month, seed=seed)
    ordered = items[:half] + before + [capture] + after + items[half:]
    return ordered, half + len(before)


def _eval(mint: IdentityMint, month: int, pool: _Pool, per_family: int, sensor: str) -> tuple[
    EnduranceSession, ...
]:
    """Held-out probes: every family, the routine, and each twin once it exists on the host.

    A twin enters the eval negatives in the month it first appears in the stream
    (``TWIN_INTRODUCED``). Scoring M01 detectors against the M09 admin before any
    learner could have seen it would pin every learner's recall at 0.0 from M01
    on — the Stage 4 structural-zero failure — and E3 could never be evaluated.
    From its intro month on, a twin *is* scored against every learner, including
    the ones that can no longer learn: that is how never-update pays for a world
    that changed.
    """
    drop = SENSOR_DROP_SHARE if month == 7 else 0.0
    twins = tuple(t for t in TWINS if TWIN_INTRODUCED[t] <= month)
    return tuple(
        block_session(mint, pool, cls, month=month, role="eval", drop_share=drop, sensor=sensor)
        for cls in (*FAMILIES, *twins, None)
        for _ in range(per_family)
    )


def _build(months: int, sessions_per_month: int, eval_per_family: int, seed: int,
           cycle: int, mint: IdentityMint, offset: int) -> list[MonthPlan]:
    if not 1 <= months <= len(Month):
        raise ValueError(f"months must be in [1, {len(Month)}], got {months}")
    if sessions_per_month < 8 or eval_per_family < 1:
        raise ValueError("sessions_per_month must be >= 8 and eval_per_family >= 1")
    ids = _identities(cycle)
    plans: list[MonthPlan] = []
    for month in range(1, months + 1):
        ctx, signal, pool, sensor = _month_frame(month, cycle)
        sessions, signal_at = _stream(mint, month, pool, sessions_per_month, sensor, seed + month)
        evals = _eval(mint, month, pool, eval_per_family, sensor)
        plans.append(MonthPlan(
            month=offset + month, identity=ids[ctx], signal=signal,
            sessions=tuple(_renumber(s, offset + month) for s in sessions),
            eval_sessions=tuple(_renumber(s, offset + month) for s in evals),
            signal_at=signal_at, pressure=month == 11, sensor=sensor,
        ))
    return plans


def _renumber(session: EnduranceSession, month: int) -> EnduranceSession:
    return session if session.month == month else replace(session, month=month)


def build_endurance_timeline(*, months: int = 12, sessions_per_month: int = SESSIONS_PER_MONTH,
                             eval_per_family: int = EVAL_SESSIONS_PER_FAMILY,
                             seed: int = ENDURANCE_SEED) -> tuple[MonthPlan, ...]:
    """The §51 year as ``months`` MonthPlans (a prefix when ``months < 12``)."""
    mint = IdentityMint(rng=random.Random(seed))
    return tuple(_build(months, sessions_per_month, eval_per_family, seed, 0, mint, 0))


def build_year_timeline(
    *,
    cycles: int = YEAR_CYCLES,
    sessions_per_month: int = SESSIONS_PER_MONTH,
    eval_per_family: int = 1,
    seed: int = ENDURANCE_SEED,
) -> tuple[MonthPlan, ...]:
    """``12 * cycles`` months: the year repeated with fresh session seeds and identities.

    Each cycle opens with a corroborated kernel+package change to that cycle's own
    context A, so no cycle's knowledge is keyed to another's identity. One
    identity mint spans the whole run, so no lineage is ever reused. The eval set
    defaults to one session per class: this timeline measures growth and plateau,
    not detection.
    """
    if cycles < 1:
        raise ValueError("cycles must be >= 1")
    mint = IdentityMint(rng=random.Random(seed))
    plans: list[MonthPlan] = []
    for cycle in range(cycles):
        mint.rng = random.Random(seed + 1000 * cycle)
        plans += _build(
            12, sessions_per_month, eval_per_family, seed + 1000 * cycle, cycle, mint, 12 * cycle
        )
    return tuple(plans)


# --- compilation: Stage 1 once, capsules for every learner -------------------------

TELEMETRY_HOST = "lab-host-01"
#: The label capsules' source class per origin. Analysts are people; the lab's
#: ground truth is the lab; a teacher is a (simulated) model.
_ORIGIN_SOURCE: dict[LabelOrigin, SourceClass] = {
    LabelOrigin.ANALYST: SourceClass.ANALYST,
    LabelOrigin.GROUND_TRUTH: SourceClass.LAB_GROUND_TRUTH,
    LabelOrigin.TEACHER: SourceClass.TEACHER,
    LabelOrigin.WEAK: SourceClass.FOREIGN_HOST,
    LabelOrigin.INFERENCE: SourceClass.DERIVED_INFERENCE,
}


def telemetry_provenance(sensor: str) -> SourceProvenance:
    """A sensor capsule. Its per-step independence groups are the hashed lineages."""
    return SourceProvenance(
        source_class=SourceClass.KERNEL_SENSOR, source_id=f"{TELEMETRY_HOST}:{sensor.lower()}",
        independence_group=f"host:{TELEMETRY_HOST}", label_origin=LabelOrigin.NONE,
        transformation_lineage=("stage1.pipeline", f"stage1.sensor:{sensor.lower()}"),
        host_id=TELEMETRY_HOST,
    )


def label_provenance(label: SessionLabel) -> SourceProvenance:
    """A label capsule; ``group`` is the independence group, so one analyst is one vote."""
    return SourceProvenance(
        source_class=_ORIGIN_SOURCE.get(label.origin, SourceClass.ANALYST), source_id=label.group,
        independence_group=label.group, label_origin=label.origin,
        transformation_lineage=("lab.label",), host_id=TELEMETRY_HOST,
    )


def apply_signal(pipeline: Stage1Pipeline, identity: SystemIdentity,
                 signal: SystemChangeSignal | None, *, now_ns: int) -> EpochDecision | None:
    """Put one out-of-band change through Stage 1's own epoch rule. ``None`` = no report."""
    if signal is None:
        return None
    return pipeline.epoch.evaluate(
        observed_identity=identity, corroborating_evidence=signal.corroborated, now_ns=now_ns,
    )


def compile_session(pipeline: Stage1Pipeline, session: EnduranceSession, *, offset: int,
                    sequence: int) -> tuple[ExperienceCapsuleV1, tuple[ExperienceCapsuleV1, ...]]:
    """One session -> its episode capsule and one label capsule per ``SessionLabel``.

    The label capsules name the episode by its content address; the episode
    capsule itself carries no label (ground truth reaches learning only as an
    explicit assertion).
    """
    result = pipeline.run_scenario(
        session.scenario, sensor=SensorPath[session.sensor], offset=offset
    )
    epoch = pipeline.epoch.current
    episode = capsule_from_scenario(
        result, epoch=epoch, provenance=telemetry_provenance(session.sensor), sequence=sequence
    )
    labels = tuple(
        capsule_from_label(
            LabelAssertion(verdict=label.verdict, origin=label.origin, asserted_by=label.group,
                           target_capsule_id=episode.capsule_id),
            epoch=epoch, provenance=label_provenance(label), sequence=sequence + 1 + index,
        )
        for index, label in enumerate(session.labels)
    )
    return episode, labels


def simulated_snapshot(*, pressure: bool) -> ResourceSnapshot:
    """A fixed host reading: calm, or above every §40 threshold (M11). Never the dev host's."""
    if pressure:
        return ResourceSnapshot(memory_pressure=0.95, cpu_load=0.95, incident_urgency=0.9,
                                disk_free_bytes=1 << 20, thermal_ok=False)
    return ResourceSnapshot(memory_pressure=0.2, cpu_load=0.2, incident_urgency=0.0,
                            disk_free_bytes=10 << 30, thermal_ok=True)


@dataclass(frozen=True, slots=True)
class StreamEvent:
    kind: str  # "capsule" | "epoch"
    sequence: int
    capsule: ExperienceCapsuleV1 | None = None
    decision: EpochDecision | None = None
    identity: SystemIdentity | None = None


@dataclass(frozen=True, slots=True)
class CompiledMonth:
    month: int
    context_id: str
    pressure: bool
    events: tuple[StreamEvent, ...]
    eval_families: tuple[str | None, ...]
    eval_steps: tuple[tuple[EncodedStep, ...], ...]
    labelled_families: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CompiledTimeline:
    version: str
    seed: int
    genesis: SystemIdentity
    months: tuple[CompiledMonth, ...]
    poison_ids: frozenset[str]


def compile_timeline(
    timeline: Sequence[MonthPlan], *, seed: int = ENDURANCE_SEED
) -> CompiledTimeline:
    """Stage 1 ONCE: the capsule stream and labelled eval set every learner will share."""
    if not timeline:
        raise ValueError("compile_timeline needs at least one month")
    pipeline = Stage1Pipeline(identity=timeline[0].identity)
    months: list[CompiledMonth] = []
    poison: set[str] = set()
    counter = [0, 0]  # offset, sequence

    def signal_event(plan: MonthPlan) -> StreamEvent | None:
        decision = apply_signal(pipeline, plan.identity, plan.signal, now_ns=counter[0])
        return None if decision is None else StreamEvent(
            "epoch", counter[1], decision=decision, identity=plan.identity
        )

    for plan in timeline:
        events: list[StreamEvent] = []
        for index, session in enumerate((*plan.sessions, None)):
            if index == plan.signal_at and (ev := signal_event(plan)) is not None:
                events.append(ev)
            if session is None:
                break
            counter[0] += 1
            counter[1] += 1 + len(session.labels)
            episode, labels = compile_session(
                pipeline, session, offset=counter[0], sequence=counter[1]
            )
            if session.role == "poison":
                # The episode AND its labels (review F2): an item learned from a label-flip
                # episode may cite only the episode, and it is poison-derived all the same.
                poison.add(episode.capsule_id)
                poison.update(label.capsule_id for label in labels)
            events += [StreamEvent("capsule", counter[1], capsule=c) for c in (episode, *labels)]
        evals = []
        for session in plan.eval_sessions:
            counter[0] += 1
            episode, _ = compile_session(pipeline, session, offset=counter[0], sequence=0)
            evals.append((session.family, episode))
        labelled = tuple(
            sorted(
                {s.family for s in plan.sessions if s.role == "attack" and s.labels} & set(FAMILIES)
            )
        )
        context = evals[0][1].context_id if evals else ""
        months.append(CompiledMonth(
            plan.month, context, plan.pressure, tuple(events),
            tuple(f for f, _ in evals), tuple(c.steps for _, c in evals), labelled,
        ))
    return CompiledTimeline(
        ENDURANCE_VERSION, seed, timeline[0].identity, tuple(months), frozenset(poison)
    )
