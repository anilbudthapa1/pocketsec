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


# Role routines are deliberately **capability-neutral**: loopback networking
# only, no credential or persistence objects, no privilege change. Stage 1's
# capability lattices are monotone, so a role that already holds external
# reachability produces ZERO delta when a chain stage grants it again — which
# made the chain's marginal contribution invisible and the measured per-lineage
# peak delta-phi identical (median 0.00) across both classes.
#
# This is a controlled experiment: the chain must be the only source of
# privilege, credential exposure and external reachability, so that "which
# lineage accumulated capability" is the sole variable. Real hosts of course run
# processes with external access; isolating the variable costs that realism on
# purpose, and the limitation is recorded in the findings document.
_WEB_SERVER = (
    ("accept", {"raddr": "127.0.0.1", "rport": "51001"}),
    ("read", {"path": "/var/www/index.html"}),
    ("send", {"raddr": "127.0.0.1", "rport": "51001"}),
    ("read", {"path": "/var/www/static/app.js"}),
)
_BUILD_AGENT = (
    ("execve", {"path": "/usr/bin/make"}),
    ("read", {"path": "/home/ci/src/app.c"}),
    ("write", {"path": "/home/ci/build/app.o"}),
    ("fork", {"cpid": "9100"}),
)
_LOG_SHIPPER = (
    ("read", {"path": "/var/log/syslog"}),
    ("connect", {"raddr": "127.0.0.1", "rport": "8125"}),
    ("send", {"raddr": "127.0.0.1", "rport": "8125"}),
)
_DB_WORKER = (
    ("read", {"path": "/var/lib/db/shard-1.dat"}),
    ("write", {"path": "/var/lib/db/wal.log"}),
    ("connect", {"raddr": "127.0.0.1", "rport": "5432"}),
)
_ADMIN_ROUTINE = (
    ("execve", {"path": "/usr/bin/apt"}),
    ("read", {"path": "/var/log/dpkg.log"}),
    ("write", {"path": "/var/cache/apt/state"}),
)
_CACHE_NODE = (
    ("accept", {"raddr": "127.0.0.1", "rport": "6379"}),
    ("read", {"path": "/var/lib/cache/dump.rdb"}),
    ("send", {"raddr": "127.0.0.1", "rport": "6379"}),
)
_CRON_RUNNER = (
    ("execve", {"path": "/usr/bin/perl"}),
    ("read", {"path": "/var/spool/cron/jobs"}),
    ("write", {"path": "/var/spool/cron/state"}),
)
_MAIL_AGENT = (
    ("read", {"path": "/var/mail/queue/00001"}),
    ("connect", {"raddr": "127.0.0.1", "rport": "25"}),
    ("send", {"raddr": "127.0.0.1", "rport": "25"}),
)

#: Eight roles, so a session has enough distinct actors to spread the longest
#: chain (5 stages) one stage per actor. With a smaller pool the spread had to
#: reuse actors, recreating the single-lineage pattern in benign sessions.
_ROLE_POOL: tuple[tuple[str, tuple[tuple[str, dict[str, str]], ...]], ...] = (
    ("cache", _CACHE_NODE),
    ("cron", _CRON_RUNNER),
    ("mail", _MAIL_AGENT),
    ("web", _WEB_SERVER),
    ("build", _BUILD_AGENT),
    ("shipper", _LOG_SHIPPER),
    ("db", _DB_WORKER),
    ("admin", _ADMIN_ROUTINE),
)

#: Capability chains. Drawn by BOTH classes: a chain is neither benign nor
#: malicious in itself. Three unrelated processes each doing one of these steps
#: is ordinary administration; one process doing all three is exfiltration.
_CHAIN_POOL: tuple[tuple[tuple[str, dict[str, str]], ...], ...] = (
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

_MORE_CHAINS: tuple[tuple[tuple[str, dict[str, str]], ...], ...] = (
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

_CHAIN_POOL = _CHAIN_POOL + _MORE_CHAINS


def _make_roles(rng: random.Random, count: int, session: int) -> list[ActorRole]:
    """Build this session's actors with **session-unique** process identities.

    The identity must be unique per session. Stage 1 keys lineage state on
    boot+pid+start-time and carries that state forward, so reusing pids across
    sessions let capability accumulate between them: by the second session every
    lineage already held privilege and credential exposure, every chain stage
    produced zero delta-phi, and the median per-lineage peak came out 0.00 for
    both classes. The attribution signal was being erased before any model saw it.
    """
    chosen = rng.sample(_ROLE_POOL, min(count, len(_ROLE_POOL)))
    return [
        ActorRole(
            name=name,
            pid=str(100_000 + session * 100 + index),
            start_time=str(1_000 + session * 10 + index),
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
    chain: tuple[tuple[str, dict[str, str]], ...],
    *,
    single_lineage: bool,
) -> tuple[Behaviour, ...]:
    """Weave the actors' routines together and thread one chain through them.

    **Aggregate-matched by construction.** Every session — benign and malicious
    alike — receives exactly the same chain, the same operations, on the same
    object classes, the same number of times. The *only* difference is
    attribution:

    * ``single_lineage=True``  one actor performs every stage (malicious)
    * ``single_lineage=False`` the stages are spread across different actors
      (benign: three unrelated processes that each did one ordinary thing)

    A model that pools features over the session therefore sees two identical
    distributions and cannot do better than the base rate. Separating them
    requires tracking *which actor* did what, across a session in which the
    stages are deliberately placed far apart. That is the per-lineage
    long-range structure this corpus exists to test, and the earlier version
    leaked it: malicious sessions simply contained more injected events, which
    a bag-of-features model could count.
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

    candidates = list(roles)
    owner = rng.choice(candidates)
    # Stages are spread with a wide stride so no window of any dilation used by
    # DTL-C (up to 32) spans two stages of the same chain.
    span = max(len(stream) - 2, len(chain) + 1)
    stride = max(20, span // max(len(chain), 1))
    position = rng.randrange(1, max(2, span - stride * (len(chain) - 1)))

    # Benign stages go to DISTINCT actors. Sampling with replacement put two or
    # three stages on one actor by chance in some benign sessions, making them
    # indistinguishable from the malicious case and effectively mislabelled —
    # self-inflicted noise that capped every model at ~0.48 PR-AUC.
    if not single_lineage and len(candidates) < len(chain):
        raise RuntimeError(
            f"only {len(candidates)} actors for a {len(chain)}-stage chain; "
            "benign spread would have to reuse an actor and recreate the "
            "single-lineage pattern this corpus exists to isolate"
        )
    spread = rng.sample(candidates, k=len(chain)) if not single_lineage else []
    for offset, (operation, fields) in enumerate(chain):
        actor = owner if single_lineage else spread[offset]
        at = min(position + offset * stride + rng.randrange(-4, 5), len(stream))
        stream.insert(
            max(0, at),
            _behaviour(actor, operation, fields, rng.randrange(5, 40) * _MINUTE_NS),
        )
    return tuple(stream)


def build_ambiguous_corpus(
    *, count: int, seed: int, split: str = "eval"
) -> tuple[Scenario, ...]:
    """Build interleaved multi-actor sessions distinguished only by attribution.

    Roughly a third of sessions are malicious. Benign and malicious sessions are
    matched on every aggregate statistic — same chain, same operations, same
    counts — so the label depends solely on whether one lineage accumulated the
    capability or several unrelated ones each contributed a piece.
    """
    rng = random.Random(seed)
    scenarios: list[Scenario] = []

    for index in range(count):
        roles = _make_roles(rng, rng.randrange(7, 9), session=index)
        length = rng.randrange(50, 90)
        malicious = split != "train" and index % 3 == 0
        # Both classes draw from the SAME chain pool. A chain is neither benign
        # nor malicious in itself; only its attribution is.
        chain = rng.choice(_CHAIN_POOL)
        subtle = malicious and index % 9 == 0
        if subtle:
            chain = chain[: max(2, len(chain) - 2)]

        scenarios.append(
            Scenario(
                f"amb-{split}-{index:04d}" + ("-attack" if malicious else ""),
                _interleave(rng, roles, length, chain, single_lineage=malicious),
                1 if malicious else 0,
                technique=("partial-chain" if subtle else "single-lineage-exfil")
                if malicious
                else None,
                unseen_technique=subtle,
            )
        )
    return tuple(scenarios)
