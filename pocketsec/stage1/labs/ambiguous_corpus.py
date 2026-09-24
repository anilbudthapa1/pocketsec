"""An intentionally *non-saturated* corpus: multi-actor, interleaved, ambiguous.

Both earlier corpora saturate. The hard corpus ties five architectures at
0.9992; the long-horizon corpus lets a plain TCN reach 1.0000. A task that is
already solved perfectly has no headroom in which a richer representation could
demonstrate benefit, so neither corpus can justify a single DTL component
beyond max-pooling. That is the blocker this corpus exists to remove.

Three properties, each closing a shortcut the earlier corpora left open:

**1. Sessions interleave many concurrent actors.** A real host runs dozens of
processes at once. Each session here weaves 4–8 lineages together, so
consecutive events in the stream usually belong to *different* processes. A
fixed-size convolution window no longer contains a coherent story, and the
security question — "did any single lineage accumulate dangerous capability?" —
requires tracking state per actor across the whole session.

**2. Benign sessions contain legitimate near-misses.** Some benign lineages
complete the full exfiltration triad for good reasons: an admin rotating
credentials and syncing them to a remote vault, a backup agent reading secrets
and uploading them off-host. Security potential alone therefore cannot separate
the classes, which is what made the earlier corpora easy.

**3. Attacks include subtle variants.** Some complete only part of the chain,
or spread it so widely that no window of any dilation spans two stages. These
are deliberately near the decision boundary.

Together these make perfect separation impossible by construction. That is the
point: a corpus with irreducible ambiguity lets models be *compared*, which a
saturated one cannot. Real detection tasks have this property; corpora that do
not are the ones that mislead.

All data remains synthetic.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from pocketsec.stage1.labs.corpus import Behaviour, Scenario

__all__ = ["AMBIGUOUS_VERSION", "ActorRole", "build_ambiguous_corpus"]

AMBIGUOUS_VERSION = "stage1-ambiguous-v0.1.0"

_SECOND_NS = 1_000_000_000
_MINUTE_NS = 60 * _SECOND_NS


@dataclass(frozen=True, slots=True)
class ActorRole:
    """One concurrent process, with the behaviour characteristic of its role."""

    name: str
    pid: str
    start_time: str
    routine: tuple[tuple[str, dict[str, str]], ...]


_WEB_SERVER = (
    ("accept", {"raddr": "10.0.0.51", "rport": "51001"}),
    ("read", {"path": "/var/www/index.html"}),
    ("send", {"raddr": "10.0.0.51", "rport": "51001"}),
    ("read", {"path": "/var/www/static/app.js"}),
)
_BUILD_AGENT = (
    ("execve", {"path": "/usr/bin/make"}),
    ("read", {"path": "/home/ci/src/app.c"}),
    ("write", {"path": "/home/ci/build/app.o"}),
    ("execve", {"path": "/usr/bin/python3"}),
    ("fork", {"cpid": "9100"}),
)
_LOG_SHIPPER = (
    ("read", {"path": "/var/log/syslog"}),
    ("connect", {"raddr": "203.0.113.30", "rport": "443"}),
    ("send", {"raddr": "203.0.113.30", "rport": "443"}),
)
_DB_WORKER = (
    ("read", {"path": "/var/lib/db/shard-1.dat"}),
    ("write", {"path": "/var/lib/db/wal.log"}),
    ("connect", {"raddr": "10.0.0.20", "rport": "5432"}),
)
_ADMIN_ROUTINE = (
    ("execve", {"path": "/usr/bin/apt"}),
    ("setuid", {"target_uid": "0"}),
    ("write", {"path": "/etc/apt/sources.list"}),
    ("read", {"path": "/var/log/dpkg.log"}),
)

_ROLE_POOL: tuple[tuple[str, tuple[tuple[str, dict[str, str]], ...]], ...] = (
    ("web", _WEB_SERVER),
    ("build", _BUILD_AGENT),
    ("shipper", _LOG_SHIPPER),
    ("db", _DB_WORKER),
    ("admin", _ADMIN_ROUTINE),
)

#: Legitimate credential handling that completes the full triad. Benign, and
#: indistinguishable from exfiltration by security potential alone.
_BENIGN_TRIAD_VARIANTS: tuple[tuple[tuple[str, dict[str, str]], ...], ...] = (
    (  # credential rotation, synced to the corporate vault
        ("setuid", {"target_uid": "0"}),
        ("read", {"path": "/etc/shadow"}),
        ("connect", {"raddr": "203.0.113.5", "rport": "443"}),
        ("send", {"raddr": "203.0.113.5", "rport": "443"}),
    ),
    (  # offsite backup of secrets
        ("setuid", {"target_uid": "0"}),
        ("read", {"path": "/root/.ssh/id_rsa"}),
        ("write", {"path": "/backup/keys.tar"}),
        ("connect", {"raddr": "203.0.113.6", "rport": "22"}),
        ("send", {"raddr": "203.0.113.6", "rport": "22"}),
    ),
)

#: Malicious chains. Same operations, same object classes, same capability
#: outcome as the benign triads above.
_ATTACK_VARIANTS: tuple[tuple[tuple[str, dict[str, str]], ...], ...] = (
    (
        ("setuid", {"target_uid": "0"}),
        ("read", {"path": "/etc/shadow"}),
        ("connect", {"raddr": "198.51.100.77", "rport": "443"}),
        ("send", {"raddr": "198.51.100.77", "rport": "443"}),
    ),
    (
        ("setuid", {"target_uid": "0"}),
        ("read", {"path": "/root/.ssh/id_rsa"}),
        ("write", {"path": "/etc/cron.d/sysupdate"}),
        ("connect", {"raddr": "198.51.100.91", "rport": "8443"}),
    ),
)

#: Partial chains: only part of the capability set is reached. Deliberately
#: close to the decision boundary — some are attacks that were interrupted.
_SUBTLE_ATTACKS: tuple[tuple[tuple[str, dict[str, str]], ...], ...] = (
    (
        ("setuid", {"target_uid": "0"}),
        ("read", {"path": "/etc/shadow"}),
    ),
    (
        ("read", {"path": "/root/.ssh/id_rsa"}),
        ("connect", {"raddr": "198.51.100.23", "rport": "443"}),
    ),
)


def _make_roles(rng: random.Random, count: int) -> list[ActorRole]:
    chosen = rng.sample(_ROLE_POOL, min(count, len(_ROLE_POOL)))
    return [
        ActorRole(
            name=name,
            pid=str(2000 + index * 7),
            start_time=str(100 + index),
            routine=routine,
        )
        for index, (name, routine) in enumerate(chosen)
    ]


def _behaviour(actor: ActorRole, operation: str, fields: dict[str, str], gap_ns: int) -> Behaviour:
    return Behaviour(
        operation,
        {
            **fields,
            "pid": actor.pid,
            "start_time": actor.start_time,
            "_gap_ns": str(gap_ns),
        },
    )


def _interleave(
    rng: random.Random,
    roles: list[ActorRole],
    length: int,
    injected: list[tuple[ActorRole, tuple[tuple[str, dict[str, str]], ...]]],
) -> tuple[Behaviour, ...]:
    """Weave every actor's routine together, then thread injected chains through.

    Injected stages are placed far apart on purpose: no window of any dilation
    used by DTL-C (up to 32) spans two stages of the same chain, so the chain
    can only be reconstructed by tracking the actor across the session.
    """
    stream: list[Behaviour] = []
    cursors = {role.name: 0 for role in roles}
    for _ in range(length):
        actor = rng.choice(roles)
        index = cursors[actor.name]
        operation, fields = actor.routine[index % len(actor.routine)]
        cursors[actor.name] = index + 1
        stream.append(
            _behaviour(actor, operation, fields, rng.randrange(2, 90) * _SECOND_NS)
        )

    for actor, chain in injected:
        # Spread stages across the whole stream with a wide, jittered stride.
        span = max(len(stream) - 2, len(chain) + 1)
        stride = max(40, span // max(len(chain), 1))
        position = rng.randrange(1, max(2, span - stride * (len(chain) - 1)))
        for offset, (operation, fields) in enumerate(chain):
            at = min(position + offset * stride + rng.randrange(-5, 6), len(stream))
            stream.insert(
                max(0, at),
                _behaviour(actor, operation, fields, rng.randrange(5, 40) * _MINUTE_NS),
            )
    return tuple(stream)


def build_ambiguous_corpus(
    *, count: int, seed: int, split: str = "eval"
) -> tuple[Scenario, ...]:
    """Build interleaved multi-actor sessions with overlapping class boundaries.

    Roughly a third of sessions are malicious. Benign sessions frequently
    include a legitimate triad, so security potential alone does not separate
    them; malicious sessions sometimes include only a partial chain.
    """
    rng = random.Random(seed)
    scenarios: list[Scenario] = []

    for index in range(count):
        roles = _make_roles(rng, rng.randrange(4, 6))
        length = rng.randrange(50, 90)
        injected: list[tuple[ActorRole, tuple[tuple[str, dict[str, str]], ...]]] = []

        malicious = split != "train" and index % 3 == 0
        # Benign near-miss: a legitimate lineage completes the full triad.
        if rng.random() < (0.45 if not malicious else 0.3):
            injected.append((rng.choice(roles), rng.choice(_BENIGN_TRIAD_VARIANTS)))

        technique = None
        unseen = False
        if malicious:
            subtle = index % 9 == 0
            chain = (
                rng.choice(_SUBTLE_ATTACKS) if subtle else rng.choice(_ATTACK_VARIANTS)
            )
            # The attacking lineage is a role with no business doing this.
            candidates = [r for r in roles if r.name != "admin"] or roles
            injected.append((rng.choice(candidates), chain))
            technique = "partial-chain" if subtle else "interleaved-exfil"
            unseen = subtle

        scenarios.append(
            Scenario(
                f"amb-{split}-{index:04d}" + ("-attack" if malicious else ""),
                _interleave(rng, roles, length, injected),
                1 if malicious else 0,
                technique=technique,
                unseen_technique=unseen,
            )
        )
    return tuple(scenarios)
