"""D2.12 fixture — a concept-drift corpus with a legitimate system change.

The question this corpus exists to answer is the one acceptance criterion 8
asks: *can Stage 2 adapt to a legitimate change without normalising repeated
malicious behaviour?* Those two halves pull in opposite directions, so a corpus
that only contains drift cannot fail the second half, and a corpus that only
contains attacks cannot exercise the first.

Three things therefore happen inside one corpus:

1. **A legitimate package/service change.** Mid-corpus the workload's binaries
   and config objects are replaced: ``webd-1.4`` becomes ``webd-2.0``, doing the
   same job on the same ports. Two of the six roles also change *mechanism* — the
   queue spools through ``/var/tmp`` instead of ``/var/spool``, the renderer runs
   through a system interpreter instead of a private binary — and that part is
   load-bearing. Measured on the first version of this corpus, where only paths
   changed: every pre-change atom was reused unchanged, because ADR-0007 froze
   names out of the model-facing encoding and a rename is therefore invisible to
   it. That is a good property of Stage 1's representation and a useless corpus
   for testing drift, so the corpus now contains drift a semantics-based encoder
   can actually see.
2. **Corroborated and uncorroborated changes, side by side.** One session carries
   the change *with* out-of-band system-change evidence; another carries a
   behaviourally identical change *without* it. Stage 1's rule is that
   behavioural novelty alone can never open an epoch (ADR, ``stage1/epoch``), so
   the second must be refused. Without the second session the anti-poisoning
   property is untested, and an implementation that opened an epoch on novelty
   would score perfectly on drift recovery.
3. **A repeated malicious pattern, in every phase.** The same exfiltration chain,
   on the same objects, performed by a single lineage, over and over — the most
   frequent single behaviour signature in the corpus. Frequency is precisely the
   signal a naive adaptation loop would treat as normality.

**Aggregate-matched, like the ambiguous corpus.** Both classes receive the same
chain on the same objects with the same operation counts; only *attribution*
differs — one lineage performs every stage (malicious) or four distinct lineages
each perform one (benign, and entirely ordinary administration). A corpus whose
attacks used an operation benign traffic never used would hand a bag-of-features
model a free perfect score, which `planning/MEMORY.md` records as benchmarking
trap 4.

**Session-unique process identities are mandatory.** ``Stage1Pipeline`` carries
lineage state across scenarios. A corpus that reuses pids puts every lineage at
saturated privilege by the second session, every chain stage then produces zero
ΔΦ, and the measured median per-class ΔΦ comes out 0.00 for *both* classes — the
defect that forced the retraction of a published result. ``make_actors`` is the
single place identities are minted, and ``tests/test_stage2_adaptation.py``
asserts both the uniqueness and the non-zero median before anything is fitted.

Ground truth about *which* lineage attacked travels in the scenario **name**
(``malicious_lineage``), never in a behaviour field: a marker field would reach
the raw telemetry and could change the semantic key, leaking the label into the
representation the mechanism under test reads.

All data is synthetic; every result derived from it carries ``synthetic_data=True``.
"""

from __future__ import annotations

import random
from collections.abc import Sequence
from dataclasses import dataclass

from pocketsec.stage1.labs.corpus import Behaviour, Scenario

__all__ = [
    "BOOT_ID",
    "DRIFT_TECHNIQUE_CORROBORATED_CHANGE",
    "DRIFT_TECHNIQUE_POST_CHANGE",
    "DRIFT_TECHNIQUE_PRE_CHANGE",
    "DRIFT_TECHNIQUE_REPEATED_ATTACK",
    "DRIFT_TECHNIQUE_UNCORROBORATED_CHANGE",
    "DRIFT_VERSION",
    "SessionActor",
    "build_drift_corpus",
    "interleave",
    "make_actors",
    "malicious_lineage",
    "session_behaviour",
]

DRIFT_VERSION = "stage2-drift-v0.1.0"

#: ``emit`` stamps every record with this boot id, and Stage 1 keys a process
#: lineage on boot+pid+start-time. ``malicious_lineage`` has to rebuild that
#: identity string, so the coupling is named here rather than inlined twice.
BOOT_ID = "boot-0001"

DRIFT_TECHNIQUE_PRE_CHANGE = "pre-change-routine"
DRIFT_TECHNIQUE_POST_CHANGE = "post-change-routine"
DRIFT_TECHNIQUE_CORROBORATED_CHANGE = "corroborated-system-change"
DRIFT_TECHNIQUE_UNCORROBORATED_CHANGE = "uncorroborated-change"
DRIFT_TECHNIQUE_REPEATED_ATTACK = "repeated-exfil"

_SECOND_NS = 1_000_000_000
_MINUTE_NS = 60 * _SECOND_NS

#: Operations each actor contributes per session. Six actors x five steps walks
#: every routine exactly once, which is what keeps the operation multiset — and
#: therefore the session length — identical across both classes.
_STEPS_PER_ACTOR = 5

#: An operation step: the name plus the fields that identify its object.
_Step = tuple[str, dict[str, str]]


@dataclass(frozen=True, slots=True)
class SessionActor:
    """One concurrent process with a session-unique identity."""

    name: str
    pid: str
    start_time: str
    routine: tuple[_Step, ...]

    @property
    def lineage(self) -> str:
        """The Stage 1 lineage key this actor will compile to."""
        return f"proc:{BOOT_ID}:{self.pid}:{self.start_time}"


def make_actors(
    rng: random.Random,
    pool: tuple[tuple[str, tuple[_Step, ...]], ...],
    count: int,
    *,
    session: int,
    namespace: int,
) -> list[SessionActor]:
    """Mint this session's actors with identities no other session reuses.

    ``namespace`` separates two corpora built in one process, so the drift corpus
    and the poison suite cannot collide on a pid and silently share accumulated
    capability through a shared pipeline.
    """
    chosen = rng.sample(pool, min(count, len(pool)))
    return [
        SessionActor(
            name=name,
            pid=str(namespace + session * 100 + index),
            start_time=str(namespace // 100 + session * 10 + index),
            routine=routine,
        )
        for index, (name, routine) in enumerate(chosen)
    ]


def session_behaviour(actor: SessionActor, step: _Step, gap_ns: int) -> Behaviour:
    """Bind one operation to one actor.

    ``pid``/``start_time`` are placed in the behaviour's own fields because
    ``emit`` lets behaviour fields override its per-scenario defaults; that is
    the only way a scenario can contain more than one lineage.
    """
    operation, fields = step
    return Behaviour(
        operation,
        {**fields, "pid": actor.pid, "start_time": actor.start_time, "_gap_ns": str(gap_ns)},
    )


# --- routines ----------------------------------------------------------------
# Every routine uses only operations that also appear in the chain block or in
# another class's routine, so no operation is unique to one label. Routines are
# capability-neutral: loopback networking, no credential objects, no privilege
# change. Stage 1's lattices are monotone, so a routine that already granted
# external reachability would make the chain's marginal ΔΦ zero and erase the
# very signal this corpus measures.

_WEB_A: tuple[_Step, ...] = (
    ("execve", {"path": "/usr/lib/webd/webd-1.4"}),
    ("read", {"path": "/etc/webd/conf.d/site.conf"}),
    ("accept", {"raddr": "127.0.0.1", "rport": "8080"}),
    ("send", {"raddr": "127.0.0.1", "rport": "8080"}),
    ("write", {"path": "/var/log/webd/access-1.4.log"}),
)
_WEB_B: tuple[_Step, ...] = (
    ("execve", {"path": "/usr/lib/webd/webd-2.0"}),
    ("read", {"path": "/etc/webd/conf.d/site.v2.conf"}),
    ("accept", {"raddr": "127.0.0.1", "rport": "8080"}),
    ("send", {"raddr": "127.0.0.1", "rport": "8080"}),
    ("write", {"path": "/var/log/webd/access-2.0.log"}),
)
_INDEX_A: tuple[_Step, ...] = (
    ("execve", {"path": "/usr/lib/indexer/index-3.1"}),
    ("read", {"path": "/srv/index/shard-a.dat"}),
    ("write", {"path": "/srv/index/shard-a.tmp"}),
    ("connect", {"raddr": "127.0.0.1", "rport": "9200"}),
    ("send", {"raddr": "127.0.0.1", "rport": "9200"}),
)
_INDEX_B: tuple[_Step, ...] = (
    ("execve", {"path": "/usr/lib/indexer/index-4.0"}),
    ("read", {"path": "/srv/index/v2/shard-a.dat"}),
    ("write", {"path": "/srv/index/v2/shard-a.tmp"}),
    ("connect", {"raddr": "127.0.0.1", "rport": "9200"}),
    ("send", {"raddr": "127.0.0.1", "rport": "9200"}),
)
_QUEUE_A: tuple[_Step, ...] = (
    ("execve", {"path": "/usr/lib/queued/queued-2.2"}),
    ("read", {"path": "/var/spool/queued/job-0001"}),
    ("write", {"path": "/var/spool/queued/state-2.2"}),
    ("accept", {"raddr": "127.0.0.1", "rport": "4730"}),
    ("send", {"raddr": "127.0.0.1", "rport": "4730"}),
)
#: The 3.0 queue spools through a temp directory instead of /var/spool. A new
#: *mechanism*, not just a new path: the object acquires TEMP_LOCATION and
#: USER_WRITABLE, so the representation genuinely moves. Without at least one
#: role like this the corpus would contain no drift a semantics-based encoder can
#: see at all — measured: with path-only changes every pre-change atom was reused
#: unchanged, because ADR-0007 froze names out of the encoding.
_QUEUE_B: tuple[_Step, ...] = (
    ("execve", {"path": "/usr/lib/queued/queued-3.0"}),
    ("read", {"path": "/var/tmp/queued/job-0001"}),
    ("write", {"path": "/var/tmp/queued/state-3.0"}),
    ("accept", {"raddr": "127.0.0.1", "rport": "4730"}),
    ("send", {"raddr": "127.0.0.1", "rport": "4730"}),
)
_METRIC_A: tuple[_Step, ...] = (
    ("execve", {"path": "/usr/lib/metricd/metricd-1.0"}),
    ("read", {"path": "/proc/self/stat"}),
    ("write", {"path": "/var/lib/metricd/series-1.0.tsdb"}),
    ("connect", {"raddr": "127.0.0.1", "rport": "8125"}),
    ("send", {"raddr": "127.0.0.1", "rport": "8125"}),
)
_METRIC_B: tuple[_Step, ...] = (
    ("execve", {"path": "/usr/lib/metricd/metricd-1.6"}),
    ("read", {"path": "/proc/self/stat"}),
    ("write", {"path": "/var/lib/metricd/series-1.6.tsdb"}),
    ("connect", {"raddr": "127.0.0.1", "rport": "8125"}),
    ("send", {"raddr": "127.0.0.1", "rport": "8125"}),
)
_CACHE_A: tuple[_Step, ...] = (
    ("execve", {"path": "/usr/lib/cached/cached-0.9"}),
    ("read", {"path": "/var/lib/cached/dump-0.9.rdb"}),
    ("write", {"path": "/var/lib/cached/append-0.9.aof"}),
    ("accept", {"raddr": "127.0.0.1", "rport": "6379"}),
    ("send", {"raddr": "127.0.0.1", "rport": "6379"}),
)
_CACHE_B: tuple[_Step, ...] = (
    ("execve", {"path": "/usr/lib/cached/cached-1.2"}),
    ("read", {"path": "/var/lib/cached/v1/dump-1.2.rdb"}),
    ("write", {"path": "/var/lib/cached/v1/append-1.2.aof"}),
    ("accept", {"raddr": "127.0.0.1", "rport": "6379"}),
    ("send", {"raddr": "127.0.0.1", "rport": "6379"}),
)
_RENDER_A: tuple[_Step, ...] = (
    ("execve", {"path": "/usr/lib/render/render-5.1"}),
    ("read", {"path": "/srv/render/template.html"}),
    ("write", {"path": "/srv/render/out-5.1.html"}),
    ("connect", {"raddr": "127.0.0.1", "rport": "7000"}),
    ("send", {"raddr": "127.0.0.1", "rport": "7000"}),
)
#: The 6.0 renderer runs through a system interpreter rather than a private
#: binary. Same job, different mechanism: the executed object acquires
#: SYSTEM_BINARY, ROOT_OWNED and INTERPRETER.
_RENDER_B: tuple[_Step, ...] = (
    ("execve", {"path": "/usr/bin/python3"}),
    ("read", {"path": "/srv/render/v6/template.html"}),
    ("write", {"path": "/var/tmp/render/out-6.0.html"}),
    ("connect", {"raddr": "127.0.0.1", "rport": "7000"}),
    ("send", {"raddr": "127.0.0.1", "rport": "7000"}),
)

_POOL_A: tuple[tuple[str, tuple[_Step, ...]], ...] = (
    ("web", _WEB_A),
    ("index", _INDEX_A),
    ("queue", _QUEUE_A),
    ("metric", _METRIC_A),
    ("cache", _CACHE_A),
    ("render", _RENDER_A),
)
_POOL_B: tuple[tuple[str, tuple[_Step, ...]], ...] = (
    ("web", _WEB_B),
    ("index", _INDEX_B),
    ("queue", _QUEUE_B),
    ("metric", _METRIC_B),
    ("cache", _CACHE_B),
    ("render", _RENDER_B),
)

#: The package-manager transaction that *is* the legitimate change. It replaces
#: one actor's routine rather than being appended, so the corpus keeps its
#: per-operation counts matched across classes: `execve`, `read` and `write`
#: already appear in every routine.
_PACKAGE_TRANSACTION: tuple[_Step, ...] = (
    ("execve", {"path": "/usr/bin/apt"}),
    ("read", {"path": "/var/lib/dpkg/status"}),
    ("write", {"path": "/usr/lib/webd/webd-2.0"}),
    ("execve", {"path": "/usr/bin/systemctl"}),
    ("write", {"path": "/run/systemd/units/webd.service"}),
)

#: The capability chain. ONE chain, drawn by both classes on the same objects,
#: so the malicious pattern is genuinely *repeated* and genuinely indistinguish-
#: able in aggregate. A chain is neither benign nor malicious in itself; only
#: its attribution is.
_CHAIN: tuple[_Step, ...] = (
    ("setuid", {"target_uid": "0"}),
    ("read", {"path": "/etc/shadow"}),
    ("connect", {"raddr": "203.0.113.42", "rport": "443"}),
    ("send", {"raddr": "203.0.113.42", "rport": "443"}),
)


def malicious_lineage(scenario: Scenario) -> str | None:
    """The lineage that performed the attack chain, or ``None`` if benign.

    Ground truth is carried in the scenario name, which never reaches the
    telemetry. A marker inside ``Behaviour.fields`` would be emitted as a raw
    record field and could change the object identity or the novelty context,
    which would leak the label into the representation under test.
    """
    _, _, marker = scenario.name.partition("-attack@")
    if not marker:
        return None
    pid, _, start = marker.partition(":")
    return f"proc:{BOOT_ID}:{pid}:{start}"


def interleave(
    rng: random.Random, plan: Sequence[tuple[SessionActor, int]]
) -> list[Behaviour]:
    """Interleave the actors in random ORDER but fixed COMPOSITION.

    Each actor contributes exactly the number of operations the plan gives it, so
    every session built from the same plan holds the identical operation multiset
    and only the interleaving differs. Drawing the next actor at random instead
    would let session length and operation mix wander with the rng: measured on
    the first version of this corpus, that alone gave an order-free
    multinomial-NB baseline PR-AUC of 0.4324 against a 0.2833 base rate — a
    +0.149 leak carrying no behavioural meaning at all.
    """
    slots = [actor for actor, steps in plan for _ in range(steps)]
    rng.shuffle(slots)
    stream: list[Behaviour] = []
    cursors: dict[str, int] = {actor.name: 0 for actor, _ in plan}
    for actor in slots:
        index = cursors[actor.name]
        cursors[actor.name] = index + 1
        stream.append(
            session_behaviour(
                actor, actor.routine[index % len(actor.routine)], rng.randrange(2, 90) * _SECOND_NS
            )
        )
    return stream


def _thread_chain(
    rng: random.Random,
    stream: list[Behaviour],
    actors: list[SessionActor],
    *,
    single_lineage: bool,
) -> SessionActor | None:
    """Insert the chain, either through one lineage or spread across four.

    Benign stages go to **distinct** actors. Sampling with replacement would put
    two stages on one actor by chance, making that benign session behaviourally
    identical to the malicious case — self-inflicted label noise, and the exact
    defect that produced a retracted +0.042 result.
    """
    if not single_lineage and len(actors) < len(_CHAIN):
        raise RuntimeError(
            f"only {len(actors)} actors for a {len(_CHAIN)}-stage chain; a benign "
            "spread would have to reuse an actor and recreate the single-lineage "
            "pattern this corpus exists to isolate"
        )
    owner = rng.choice(actors)
    spread = [] if single_lineage else rng.sample(actors, k=len(_CHAIN))
    stride = max(4, len(stream) // (len(_CHAIN) + 1))
    start = rng.randrange(1, max(2, len(stream) - stride * (len(_CHAIN) - 1)))
    for offset, step in enumerate(_CHAIN):
        actor = owner if single_lineage else spread[offset]
        at = max(0, min(start + offset * stride, len(stream)))
        stream.insert(at, session_behaviour(actor, step, rng.randrange(5, 40) * _MINUTE_NS))
    return owner if single_lineage else None


def build_drift_corpus(
    *, count: int, seed: int, split: str = "eval"
) -> tuple[Scenario, ...]:
    """Build the drift corpus: three routine phases, three change attempts.

    Two of the three changes are corroborated and one is not; one repeated attack
    pattern runs through every phase.

    Phases, by session index over ``count``:

    * ``[0, 25%)``      routine on the ``-1.4`` generation of binaries, epoch 0.
    * ``25%``           a corroborated **policy** change (epoch 0 -> 1) that does
      not alter the workload. It is first on purpose: promotion needs two distinct
      corroborated epochs, so without it nothing could be trusted before the
      workload change and there would be nothing for the drift to invalidate.
    * ``(25%, 50%)``    the same routine continues, now in epoch 1, earning trust.
    * ``50%``           the corroborated **package** change (epoch 1 -> 2): the
      workload moves to the ``-2.0`` generation, and two of the six roles change
      *mechanism* rather than just path, so the drift is visible to an encoder
      that deliberately ignores names.
    * ``(50%, 70%)``    post-change routine; this is where recovery is measured.
    * ``70%``           a behaviourally identical change with **no** corroborating
      evidence, which must not open an epoch.
    * ``(70%, 100%)``   routine continues on the ``-2.0`` generation.

    Every third session is the repeated attack, in every phase. ``split="train"``
    is benign-only, matching Stage 1's convention.
    """
    rng = random.Random(seed)
    change_one = max(1, int(count * 0.25))
    change_two = max(change_one + 1, int(count * 0.50))
    uncorroborated = max(change_two + 1, int(count * 0.70))
    scenarios: list[Scenario] = []

    for index in range(count):
        # Composition is drawn BEFORE the label so both classes see identically
        # distributed sessions; a class-conditional draw would put a vocabulary
        # difference into the corpus by accident.
        post_change = index >= change_two
        pool = _POOL_B if post_change else _POOL_A
        actors = make_actors(rng, pool, 6, session=index, namespace=200_000)
        malicious = split != "train" and index % 3 == 0 and index not in (
            change_one,
            uncorroborated,
            change_two,
        )

        if index in (change_one, uncorroborated, change_two):
            # Substitute, never append: appending would give the benign class
            # extra operations and hand a counting model a free signal.
            actors[0] = SessionActor(
                name=actors[0].name,
                pid=actors[0].pid,
                start_time=actors[0].start_time,
                routine=_PACKAGE_TRANSACTION,
            )

        stream = interleave(rng, [(actor, _STEPS_PER_ACTOR) for actor in actors])
        owner = _thread_chain(rng, stream, actors, single_lineage=malicious)

        if index in (change_one, change_two):
            technique = DRIFT_TECHNIQUE_CORROBORATED_CHANGE
        elif index == uncorroborated:
            technique = DRIFT_TECHNIQUE_UNCORROBORATED_CHANGE
        elif malicious:
            technique = DRIFT_TECHNIQUE_REPEATED_ATTACK
        elif post_change:
            technique = DRIFT_TECHNIQUE_POST_CHANGE
        else:
            technique = DRIFT_TECHNIQUE_PRE_CHANGE

        name = f"drift-{split}-{index:04d}"
        if owner is not None:
            name = f"{name}-attack@{owner.pid}:{owner.start_time}"
        scenarios.append(
            Scenario(
                name=name,
                behaviours=tuple(stream),
                label=1 if malicious else 0,
                technique=technique,
                unseen_technique=False,
            )
        )
    return tuple(scenarios)
