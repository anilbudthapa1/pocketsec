"""D2.12 fixture — poisoning attempts against the adaptation path.

Acceptance criterion 9 asks whether the quarantine/promotion path holds. A suite
that only contained obvious attacks would validate nothing: an obvious attack is
caught by Stage 1's Φ before adaptation is even consulted. The interesting
adversary is the one aiming at the *learning* loop, trying to make the machine
adopt its behaviour as the new normal.

Three arms, each attacking a different part of the gate:

* **slow drift** — one lineage reads a series of objects that creep from ordinary
  data toward credentials one small step at a time. No single step looks like an
  attack. This is what defeats a quarantine that compares a sample against a
  *moving* prototype, and why ``QuarantineBuffer`` compares against an immutable
  anchor instead.
* **high-frequency repetition** — one lineage repeats a single low-consequence
  pattern many times in one session, buying normality with sheer count. ΔΦ stays
  near zero and the pattern is perfectly self-consistent, so this arm can only be
  stopped by the rule that frequency is never sufficient: promotion needs
  distinct corroborated epochs.
* **near-miss mimicry** — one lineage performs a pattern one object-class away
  from a trusted routine (``/etc/shadow.bak`` where ``/etc/webd/conf.d/site.conf``
  belongs), betting the quantizer will fold it into the neighbouring prototype.

Every session also contains a **legitimate adaptation** counterpart: the control
sessions run the same block on ordinary rotating objects, spread across distinct
actors. Without them the suite could be passed by refusing everything, which is
why ``tests/test_stage2_adaptation.py`` measures the accept-nothing control
explicitly rather than assuming the mechanism does better than it.

**Composition is matched exactly.** Every session — poisoned or not — has the
same operation multiset: five routine actors contributing four operations each,
an adaptation actor contributing eight ``read`` operations, and one capability
chain spread across four distinct routine actors. Only the *objects* and the
*attribution* differ, so no order-free counting model can separate the classes.
The object vocabulary does differ, deliberately and necessarily: the mechanism
under test reads object semantics, and a suite whose poison touched the same
objects as its control would not be a poison suite.

Session-unique process identities, as in ``drift_corpus``: reused pids let
capability accumulate across sessions through the shared ``Stage1Pipeline`` and
drive the measured per-class median ΔΦ to 0.00 for both classes.

All data is synthetic.
"""

from __future__ import annotations

import random

from pocketsec.stage1.labs.corpus import Behaviour, Scenario
from pocketsec.stage2.labs.drift_corpus import (
    BOOT_ID,
    DRIFT_TECHNIQUE_CORROBORATED_CHANGE,
    SessionActor,
    interleave,
    make_actors,
    session_behaviour,
)

__all__ = [
    "POISON_ARMS",
    "POISON_TECHNIQUE_HIGH_FREQUENCY",
    "POISON_TECHNIQUE_LEGITIMATE",
    "POISON_TECHNIQUE_NEAR_MISS",
    "POISON_TECHNIQUE_SLOW_DRIFT",
    "POISON_VERSION",
    "adaptation_lineage",
    "build_poison_suite",
    "poison_lineage",
]

POISON_VERSION = "stage2-poison-v0.1.0"

POISON_TECHNIQUE_SLOW_DRIFT = "slow-drift"
POISON_TECHNIQUE_HIGH_FREQUENCY = "high-frequency-repetition"
POISON_TECHNIQUE_NEAR_MISS = "near-miss-mimicry"
POISON_TECHNIQUE_LEGITIMATE = "legitimate-adaptation"

#: The three poisoning arms, in the order sessions rotate through them.
POISON_ARMS = (
    POISON_TECHNIQUE_SLOW_DRIFT,
    POISON_TECHNIQUE_HIGH_FREQUENCY,
    POISON_TECHNIQUE_NEAR_MISS,
)

_SECOND_NS = 1_000_000_000
_MINUTE_NS = 60 * _SECOND_NS

#: Operations the adaptation actor contributes. Eight is above the default
#: ``min_observations`` of 8 only when a pattern repeats across sessions, which
#: is the point: one session must never be enough.
_ADAPTATION_STEPS = 8
_ROUTINE_STEPS = 4

_Step = tuple[str, dict[str, str]]

# --- routine roles -----------------------------------------------------------
# Four operations each, and between them every operation the chain uses, so no
# operation is unique to one class. Capability-neutral: loopback only, no
# credential objects, no privilege change.

_APP: tuple[_Step, ...] = (
    ("execve", {"path": "/usr/lib/appd/appd-1.0"}),
    ("read", {"path": "/srv/app/data/page.json"}),
    ("write", {"path": "/srv/app/data/page.rendered"}),
    ("send", {"raddr": "127.0.0.1", "rport": "8080"}),
)
_SYNC: tuple[_Step, ...] = (
    ("execve", {"path": "/usr/lib/syncd/syncd-2.3"}),
    ("read", {"path": "/srv/sync/manifest.json"}),
    ("connect", {"raddr": "127.0.0.1", "rport": "7070"}),
    ("send", {"raddr": "127.0.0.1", "rport": "7070"}),
)
_LOGD: tuple[_Step, ...] = (
    ("execve", {"path": "/usr/lib/logd/logd-0.7"}),
    ("read", {"path": "/var/log/appd/current.log"}),
    ("write", {"path": "/var/log/appd/rotated.log"}),
    ("send", {"raddr": "127.0.0.1", "rport": "1514"}),
)
_STATS: tuple[_Step, ...] = (
    ("execve", {"path": "/usr/lib/statsd/statsd-3.1"}),
    ("read", {"path": "/srv/stats/series.tsdb"}),
    ("accept", {"raddr": "127.0.0.1", "rport": "8126"}),
    ("send", {"raddr": "127.0.0.1", "rport": "8126"}),
)
_JOBS: tuple[_Step, ...] = (
    ("execve", {"path": "/usr/lib/jobd/jobd-4.4"}),
    ("read", {"path": "/srv/jobs/queue.dat"}),
    ("write", {"path": "/srv/jobs/queue.state"}),
    ("accept", {"raddr": "127.0.0.1", "rport": "4141"}),
)

#: The adaptation actor's placeholder routine. It is replaced per session with
#: the arm's block, but it must exist in the pool so that ``make_actors``
#: consumes the rng identically for every arm — a class-conditional rng draw
#: would put a composition difference into the corpus by accident.
_ADAPTER_PLACEHOLDER: tuple[_Step, ...] = (
    ("read", {"path": "/srv/app/data/placeholder.dat"}),
)

_ADAPTER_NAME = "adapter"

_POOL: tuple[tuple[str, tuple[_Step, ...]], ...] = (
    ("app", _APP),
    ("sync", _SYNC),
    ("logd", _LOGD),
    ("stats", _STATS),
    ("jobs", _JOBS),
    (_ADAPTER_NAME, _ADAPTER_PLACEHOLDER),
)

# --- the adaptation blocks ---------------------------------------------------

#: Legitimate adaptation: eight ordinary reads that rotate with the workload.
#: These are the samples the gate is *supposed* to let through eventually.
_LEGITIMATE_BLOCK: tuple[_Step, ...] = tuple(
    ("read", {"path": f"/srv/app/data/shard-{index:02d}.dat"}) for index in range(8)
)

#: Slow drift: ordinary, ordinary, ordinary, temp, authorisation, persistence,
#: credential, credential. Each step is a small change from the last; the walk
#: as a whole ends on a private key. Distance from the FIRST sample grows
#: monotonically, which is why the quarantine anchors on the first sample and
#: never on the running mean.
_SLOW_DRIFT_BLOCK: tuple[_Step, ...] = (
    ("read", {"path": "/srv/app/data/shard-00.dat"}),
    ("read", {"path": "/srv/app/data/shard-01.dat"}),
    ("read", {"path": "/srv/app/cfg/app.conf"}),
    ("read", {"path": "/var/tmp/appd/stage.dat"}),
    ("read", {"path": "/etc/passwd"}),
    ("read", {"path": "/etc/cron.d/appd"}),
    ("read", {"path": "/home/app/.ssh/id_ed25519"}),
    ("read", {"path": "/etc/shadow"}),
)

#: High frequency: one low-consequence pattern, eight times. ΔΦ stays at zero and
#: the samples agree with each other perfectly, so nothing but the
#: corroborated-epoch requirement stands between this and trusted state.
_HIGH_FREQUENCY_BLOCK: tuple[_Step, ...] = tuple(
    ("read", {"path": "/var/tmp/appd/session.cache"}) for _ in range(8)
)

#: Near miss: objects one class away from a trusted routine object. Same
#: operation, same directory shape, different security meaning.
_NEAR_MISS_BLOCK: tuple[_Step, ...] = (
    ("read", {"path": "/srv/app/data/shard-00.dat"}),
    ("read", {"path": "/etc/shadow.bak"}),
    ("read", {"path": "/srv/app/data/shard-01.dat"}),
    ("read", {"path": "/etc/sudoers.d/90-appd"}),
    ("read", {"path": "/srv/app/data/shard-02.dat"}),
    ("read", {"path": "/home/app/.ssh/id_rsa.pub"}),
    ("read", {"path": "/srv/app/data/shard-03.dat"}),
    ("read", {"path": "/etc/pam.d/appd"}),
)

_BLOCKS: dict[str, tuple[_Step, ...]] = {
    POISON_TECHNIQUE_LEGITIMATE: _LEGITIMATE_BLOCK,
    POISON_TECHNIQUE_SLOW_DRIFT: _SLOW_DRIFT_BLOCK,
    POISON_TECHNIQUE_HIGH_FREQUENCY: _HIGH_FREQUENCY_BLOCK,
    POISON_TECHNIQUE_NEAR_MISS: _NEAR_MISS_BLOCK,
}

#: The capability chain, spread across four distinct routine actors in EVERY
#: session. It is here to keep `setuid`/`connect`/`send`-to-external in both
#: classes' vocabulary, not to be the label: three unrelated processes each doing
#: one ordinary privileged thing is administration, and no session in this suite
#: performs the whole chain from one lineage.
_CHAIN: tuple[_Step, ...] = (
    ("setuid", {"target_uid": "0"}),
    ("read", {"path": "/etc/shadow"}),
    ("connect", {"raddr": "203.0.113.42", "rport": "443"}),
    ("send", {"raddr": "203.0.113.42", "rport": "443"}),
)


def _lineage_from_name(scenario: Scenario, marker: str) -> str | None:
    _, _, tail = scenario.name.partition(marker)
    if not tail:
        return None
    pid, _, start = tail.partition(":")
    return f"proc:{BOOT_ID}:{pid}:{start}"


def poison_lineage(scenario: Scenario) -> str | None:
    """The lineage attempting to poison the adaptation path, or ``None``.

    Ground truth lives in the scenario name, never in a behaviour field: a marker
    field would be emitted as raw telemetry and could change the object identity
    or the novelty context, leaking the label into the representation the
    mechanism under test reads.
    """
    return _lineage_from_name(scenario, "-poison@")


def adaptation_lineage(scenario: Scenario) -> str | None:
    """The lineage offering adaptation samples, poisoned or legitimate."""
    return poison_lineage(scenario) or _lineage_from_name(scenario, "-adapt@")


def _thread_chain(
    rng: random.Random, stream: list[Behaviour], routine: list[SessionActor]
) -> None:
    """Spread the chain across four distinct routine actors.

    Distinct, not sampled with replacement: two stages on one actor would make
    that session a single-lineage escalation, which is a different experiment and
    would show up as label noise in this one.
    """
    if len(routine) < len(_CHAIN):
        raise RuntimeError(
            f"only {len(routine)} routine actors for a {len(_CHAIN)}-stage chain; "
            "a spread would have to reuse an actor and manufacture a "
            "single-lineage escalation this suite does not model"
        )
    spread = rng.sample(routine, k=len(_CHAIN))
    stride = max(3, len(stream) // (len(_CHAIN) + 1))
    start = rng.randrange(1, max(2, len(stream) - stride * (len(_CHAIN) - 1)))
    for offset, step in enumerate(_CHAIN):
        at = max(0, min(start + offset * stride, len(stream)))
        stream.insert(at, session_behaviour(spread[offset], step, rng.randrange(5, 40) * _MINUTE_NS))


def build_poison_suite(
    *, count: int, seed: int, split: str = "eval"
) -> tuple[Scenario, ...]:
    """Build the poisoning suite: one arm per poisoned session, controls between.

    Every third session (``index % 3 == 1``) is a poisoning attempt, rotating
    through the three arms; the rest are legitimate adaptation controls. One
    session at roughly 40 % carries a corroborated system change, so a legitimate
    pattern can reach the two distinct corroborated epochs promotion requires —
    without it the suite could be passed by a gate that promotes nothing, and the
    accept-nothing control would be indistinguishable from the real mechanism.

    ``split="train"`` contains controls only.
    """
    rng = random.Random(seed)
    change_at = max(1, int(count * 0.40))
    scenarios: list[Scenario] = []

    for index in range(count):
        actors = make_actors(rng, _POOL, len(_POOL), session=index, namespace=300_000)
        routine = [actor for actor in actors if actor.name != _ADAPTER_NAME]
        adapter = next(actor for actor in actors if actor.name == _ADAPTER_NAME)

        poisoned = split != "train" and index % 3 == 1 and index != change_at
        technique = (
            POISON_ARMS[(index // 3) % len(POISON_ARMS)]
            if poisoned
            else POISON_TECHNIQUE_LEGITIMATE
        )
        adapter = SessionActor(
            name=adapter.name,
            pid=adapter.pid,
            start_time=adapter.start_time,
            routine=_BLOCKS[technique],
        )

        plan = [(actor, _ROUTINE_STEPS) for actor in routine]
        plan.append((adapter, _ADAPTATION_STEPS))
        stream = interleave(rng, plan)
        _thread_chain(rng, stream, routine)

        marker = "poison" if poisoned else "adapt"
        name = (
            f"poison-{split}-{index:04d}-{marker}@{adapter.pid}:{adapter.start_time}"
        )
        scenarios.append(
            Scenario(
                name=name,
                behaviours=tuple(stream),
                label=1 if poisoned else 0,
                technique=(
                    DRIFT_TECHNIQUE_CORROBORATED_CHANGE
                    if index == change_at
                    else technique
                ),
                unseen_technique=False,
            )
        )
    return tuple(scenarios)
