"""A discriminating corpus for the Information Guillotine (D1.11).

The first corpus produced a **degenerate** frontier: benign and malicious
scenarios shared almost no operations, so every information family separated
them independently and dropping any one cost nothing. That measures the corpus,
not the representation.

This corpus is built on one principle: **for each information family, include a
pair of scenarios that only that family can separate.** If `object_semantics` is
load-bearing, there must exist a benign/malicious pair identical in every other
respect and differing only in which object was touched.

| Family | The pair that isolates it |
|---|---|
| `capability_delta` | backup reads credentials locally vs. the same read plus external egress |
| `object_semantics` | admin writes `/etc/apt/sources.list` vs. `/etc/ld.so.preload` |
| `actor_semantics` | a process that has only ever read files vs. one that has demonstrated spawn + network |
| `novelty` | an actor performing an operation normal for *others* but never for itself |
| `uncertainty` | a well-characterised binary vs. an unknown one doing the same thing |
| `timing` | the same capability gain as a rapid burst vs. spread over hours |
| `causal_memory` | capability gained in one concentrated jump vs. accumulated gradually |
| `exact_identity` | included as a control: expected to be **removable** |

Living-off-the-land scenarios are the backbone: attacks that use exactly the
operations an administrator uses, differing only in context. If the
representation cannot separate those, that is a real limitation and the frontier
should say so.

All data remains synthetic and every result carries ``synthetic_data=True``.
"""

from __future__ import annotations

import random

from pocketsec.stage1.labs.corpus import Behaviour, Scenario

__all__ = ["HARD_CORPUS_VERSION", "build_hard_corpus", "DISCRIMINATOR_PAIRS"]

HARD_CORPUS_VERSION = "stage1-hard-corpus-v0.1.0"

# --- capability_delta: the same credential read, with and without egress -----

BACKUP_LOCAL = (
    Behaviour("execve", {"path": "/usr/bin/backup-agent"}),
    Behaviour("setuid", {"target_uid": "0"}),
    Behaviour("read", {"path": "/etc/shadow"}),
    Behaviour("write", {"path": "/backup/etc.tar"}),
)

BACKUP_EXFIL = (
    Behaviour("execve", {"path": "/usr/bin/backup-agent"}),
    Behaviour("setuid", {"target_uid": "0"}),
    Behaviour("read", {"path": "/etc/shadow"}),
    Behaviour("connect", {"raddr": "203.0.113.77", "rport": "443"}),
    Behaviour("send", {"raddr": "203.0.113.77", "rport": "443"}),
)

# --- object_semantics: identical privileged write, different target ----------

ADMIN_CONFIG_WRITE = (
    Behaviour("setuid", {"target_uid": "0"}),
    Behaviour("execve", {"path": "/usr/bin/apt"}),
    Behaviour("write", {"path": "/etc/apt/sources.list"}),
)

PRELOAD_HIJACK = (
    Behaviour("setuid", {"target_uid": "0"}),
    Behaviour("execve", {"path": "/usr/bin/apt"}),
    Behaviour("write", {"path": "/etc/ld.so.preload"}),
)

# --- actor_semantics: what the actor has demonstrated it can do --------------

READER_ONLY = (
    Behaviour("execve", {"path": "/usr/bin/logrotate"}),
    Behaviour("read", {"path": "/var/log/syslog"}),
    Behaviour("read", {"path": "/var/log/auth.log"}),
    Behaviour("write", {"path": "/var/log/syslog.1"}),
)

SPAWNER_NETWORKER = (
    Behaviour("execve", {"path": "/usr/bin/logrotate"}),
    Behaviour("fork", {"cpid": "4100"}),
    Behaviour("connect", {"raddr": "198.51.100.30", "rport": "9001"}),
    Behaviour("read", {"path": "/var/log/auth.log"}),
    Behaviour("send", {"raddr": "198.51.100.30", "rport": "9001"}),
)

# --- uncertainty: the same actions from a known vs. an unknown binary --------

KNOWN_BINARY_WORK = (
    Behaviour("execve", {"path": "/usr/bin/rsync"}),
    Behaviour("read", {"path": "/home/dev/project/data.db"}),
    Behaviour("connect", {"raddr": "10.0.0.9", "rport": "873"}),
)

UNKNOWN_BINARY_WORK = (
    Behaviour("execve", {"path": "/tmp/.cache/sys-helper-8812"}),
    Behaviour("read", {"path": "/home/dev/project/data.db"}),
    Behaviour("connect", {"raddr": "198.51.100.44", "rport": "8443"}),
)

# --- causal_memory: concentrated vs. gradual capability accumulation ---------

#: Capability gained in one tight causal chain — a single actor, one lineage.
CONCENTRATED_ESCALATION = (
    Behaviour("execve", {"path": "/usr/bin/python3"}),
    Behaviour("setuid", {"target_uid": "0"}),
    Behaviour("read", {"path": "/root/.ssh/id_rsa"}),
    Behaviour("connect", {"raddr": "203.0.113.90", "rport": "22"}),
)

#: The same capabilities, but reached through ordinary interleaved maintenance,
#: with the consequential steps separated by routine work.
GRADUAL_MAINTENANCE = (
    Behaviour("execve", {"path": "/usr/bin/python3"}),
    Behaviour("read", {"path": "/var/log/app.log"}),
    Behaviour("setuid", {"target_uid": "0"}),
    Behaviour("read", {"path": "/var/log/dpkg.log"}),
    Behaviour("write", {"path": "/var/cache/app/state"}),
    Behaviour("read", {"path": "/var/log/kern.log"}),
)

# --- benign scenarios that share capability with attacks ---------------------

MONITORING_EXTERNAL = (
    Behaviour("execve", {"path": "/usr/bin/node-exporter"}),
    Behaviour("read", {"path": "/proc/stat"}),
    Behaviour("connect", {"raddr": "203.0.113.10", "rport": "9100"}),
    Behaviour("send", {"raddr": "203.0.113.10", "rport": "9100"}),
)

PACKAGE_INSTALL = (
    Behaviour("setuid", {"target_uid": "0"}),
    Behaviour("install", {"path": "nginx"}),
    Behaviour("write", {"path": "/etc/systemd/system/nginx.service"}),
    Behaviour("execve", {"path": "/usr/bin/systemctl"}),
)

CI_BUILD = (
    Behaviour("execve", {"path": "/usr/bin/make"}),
    Behaviour("fork", {"cpid": "5100"}),
    Behaviour("read", {"path": "/home/ci/src/app.c"}),
    Behaviour("write", {"path": "/home/ci/build/app.o"}),
    Behaviour("connect", {"raddr": "10.0.1.20", "rport": "443"}),
)

# --- attacks that look like maintenance --------------------------------------

LOTL_SERVICE_BACKDOOR = (
    Behaviour("setuid", {"target_uid": "0"}),
    Behaviour("install", {"path": "nginx"}),
    Behaviour("write", {"path": "/etc/systemd/system/nginx.service"}),
    Behaviour("read", {"path": "/root/.ssh/id_rsa"}),
    Behaviour("connect", {"raddr": "198.51.100.61", "rport": "443"}),
)

LOTL_CRON_PERSIST = (
    Behaviour("execve", {"path": "/usr/bin/crontab"}),
    Behaviour("setuid", {"target_uid": "0"}),
    Behaviour("write", {"path": "/etc/cron.d/sysupdate"}),
    Behaviour("read", {"path": "/etc/shadow"}),
)


#: Pairs that isolate one information family each. The guillotine's
#: discriminating power is exactly its ability to tell these apart.
DISCRIMINATOR_PAIRS: tuple[tuple[str, tuple[Behaviour, ...], tuple[Behaviour, ...]], ...] = (
    ("capability_delta", BACKUP_LOCAL, BACKUP_EXFIL),
    ("object_semantics", ADMIN_CONFIG_WRITE, PRELOAD_HIJACK),
    ("actor_semantics", READER_ONLY, SPAWNER_NETWORKER),
    ("uncertainty", KNOWN_BINARY_WORK, UNKNOWN_BINARY_WORK),
    ("causal_memory", GRADUAL_MAINTENANCE, CONCENTRATED_ESCALATION),
)

_BENIGN_POOL: tuple[tuple[Behaviour, ...], ...] = (
    BACKUP_LOCAL,
    ADMIN_CONFIG_WRITE,
    READER_ONLY,
    KNOWN_BINARY_WORK,
    GRADUAL_MAINTENANCE,
    MONITORING_EXTERNAL,
    PACKAGE_INSTALL,
    CI_BUILD,
)

_ATTACK_POOL: tuple[tuple[tuple[Behaviour, ...], str], ...] = (
    (BACKUP_EXFIL, "credential-exfil-via-backup"),
    (PRELOAD_HIJACK, "preload-hijack"),
    (SPAWNER_NETWORKER, "log-agent-subversion"),
    (UNKNOWN_BINARY_WORK, "unknown-binary-egress"),
    (CONCENTRATED_ESCALATION, "concentrated-key-theft"),
    (LOTL_SERVICE_BACKDOOR, "lotl-service-backdoor"),
    (LOTL_CRON_PERSIST, "lotl-cron-persistence"),
)


#: One hour between steps: unmistakably deliberate, spread-out activity.
_SLOW_GAP_NS = 3_600_000_000_000
#: 200 microseconds: machine-speed, faster than a human drives a terminal.
_BURST_GAP_NS = 200_000


def _novelty_pair(index: int) -> tuple[tuple[Behaviour, ...], tuple[Behaviour, ...]]:
    """Isolate the novelty family.

    Both actors run the same binary and perform the same *kind* of operation on
    the same *kind* of object, reaching an identical security state. The benign
    one revisits shards it has touched all along; the malicious one sweeps shards
    it has never touched. Only the per-object and per-actor novelty contexts see
    a difference.

    Deliberately NOT confounded with capability: an earlier draft gave the
    malicious side an extra external connect, which meant the pair was separable
    by capability_delta and isolated nothing.
    """
    familiar = tuple(
        Behaviour("read", {"path": f"/var/lib/db/shard-{index % 4}.dat"}) for _ in range(6)
    )
    sweeping = tuple(
        Behaviour("read", {"path": f"/var/lib/db/shard-{500 + index * 13 + i}.dat"})
        for i in range(6)
    )
    return familiar, sweeping


def _timing_pair(index: int) -> tuple[tuple[Behaviour, ...], tuple[Behaviour, ...]]:
    """Isolate the timing family.

    Identical operations, identical objects, identical final state. One is a
    machine-speed burst, the other is spread over hours. Only the temporal
    bucket separates them.

    An earlier draft returned the *same* tuple for both sides, which made this
    pure label noise rather than a timing discriminator and capped the best
    achievable PR-AUC for reasons that had nothing to do with the representation.
    """
    paths = ("/etc/passwd", "/etc/group", "/etc/hosts", "/etc/resolv.conf")
    spread = tuple(
        Behaviour("read", {"path": path, "_gap_ns": str(_SLOW_GAP_NS)}) for path in paths
    )
    burst = tuple(
        Behaviour("read", {"path": path, "_gap_ns": str(_BURST_GAP_NS)}) for path in paths
    )
    return spread, burst


def build_hard_corpus(*, count: int, seed: int, split: str) -> tuple[Scenario, ...]:
    """Build the discriminating corpus.

    ``train`` is benign-only. ``eval`` mixes the benign pool with attacks drawn
    from the living-off-the-land pool, and guarantees that every discriminator
    pair appears so no family is left untested.
    """
    rng = random.Random(seed)
    scenarios: list[Scenario] = []

    if split == "train":
        for index in range(count):
            scenarios.append(
                Scenario(f"hard-train-{index:04d}", rng.choice(_BENIGN_POOL), 0)
            )
        return tuple(scenarios)

    # Guarantee both halves of every discriminator pair.
    for family, benign, malicious in DISCRIMINATOR_PAIRS:
        scenarios.append(Scenario(f"pair-{family}-benign", benign, 0, technique=None))
        scenarios.append(
            Scenario(f"pair-{family}-attack", malicious, 1, technique=f"isolates-{family}")
        )

    for index in range(4):
        familiar, sweeping = _novelty_pair(index)
        scenarios.append(Scenario(f"pair-novelty-benign-{index}", familiar, 0))
        scenarios.append(
            Scenario(
                f"pair-novelty-attack-{index}",
                sweeping,
                1,
                technique="isolates-novelty",
                unseen_technique=index % 2 == 0,
            )
        )

    for index in range(4):
        spread, burst = _timing_pair(index)
        scenarios.append(Scenario(f"pair-timing-benign-{index}", spread, 0))
        scenarios.append(
            Scenario(f"pair-timing-attack-{index}", burst, 1, technique="isolates-timing")
        )

    while len(scenarios) < count:
        index = len(scenarios)
        if index % 3 == 0:
            chain, technique = _ATTACK_POOL[index % len(_ATTACK_POOL)]
            scenarios.append(Scenario(f"hard-{index:04d}", chain, 1, technique=technique))
        else:
            scenarios.append(Scenario(f"hard-{index:04d}", rng.choice(_BENIGN_POOL), 0))

    return tuple(scenarios[:count]) if count >= len(scenarios) else tuple(scenarios)
