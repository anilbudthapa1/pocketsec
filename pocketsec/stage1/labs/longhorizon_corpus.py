"""A long-horizon corpus: multi-stage attacks spread across a host session.

The hard corpus (mean 4.14 transitions per scenario) established that the Stage 1
*representation* discriminates. It cannot test Stage 2's central claim. DTL's
``z_host`` block operates on hours-to-days and ``z_epoch`` on configuration
regimes; across four events neither has anything to do, and a pooled
bag-of-features scored 0.9722 while every sequence model scored lower.

So this corpus is built to make the bag of features **insufficient by
construction**:

* A session is 40-120 transitions of ordinary host activity.
* Benign sessions contain every individual operation an attack uses — sudo,
  credential reads, external connections, service writes. Individually, all of
  it is legitimate administration and monitoring.
* A malicious session contains the same *operations* but assembled into an
  escalating chain within one actor lineage, close in time.

The difference is therefore **structure, not vocabulary**: which lineage, in
what order, how close together. A model that pools features cannot see it. A
model that tracks per-lineage state across a long horizon can.

This is living-off-the-land, which is also what makes it realistic. All data
remains synthetic.
"""

from __future__ import annotations

import random

from pocketsec.stage1.labs.corpus import Behaviour, Scenario

__all__ = ["LONG_HORIZON_VERSION", "build_long_horizon_corpus"]

LONG_HORIZON_VERSION = "stage1-longhorizon-v0.1.0"

_MINUTE_NS = 60_000_000_000
_SECOND_NS = 1_000_000_000

#: Ordinary background activity. Every operation an attack needs also appears
#: here, so vocabulary alone carries no signal.
_BACKGROUND: tuple[tuple[str, dict[str, str]], ...] = (
    ("read", {"path": "/var/log/syslog"}),
    ("read", {"path": "/var/log/auth.log"}),
    ("write", {"path": "/var/log/app.log"}),
    ("execve", {"path": "/usr/bin/grep"}),
    ("execve", {"path": "/usr/bin/awk"}),
    # Interpreters run constantly on a real host (build systems, cron jobs,
    # config management). Leaving them out of benign traffic would make
    # "an interpreter ran" a perfect attack tell and hand a bag-of-features
    # model the answer for free.
    ("execve", {"path": "/usr/bin/python3"}),
    ("execve", {"path": "/usr/bin/perl"}),
    ("execve", {"path": "/bin/bash"}),
    ("fork", {"cpid": "7001"}),
    ("read", {"path": "/proc/stat"}),
    ("read", {"path": "/etc/hosts"}),
    ("connect", {"raddr": "10.0.0.20", "rport": "5432"}),
    ("send", {"raddr": "10.0.0.20", "rport": "5432"}),
    ("write", {"path": "/home/dev/build/out.o"}),
    ("read", {"path": "/home/dev/src/app.c"}),
)

#: Legitimate administration: the same privileged operations an attack uses,
#: performed by an admin, spread out, and not assembled into a chain.
_ADMIN_ACTIONS: tuple[tuple[str, dict[str, str]], ...] = (
    ("setuid", {"target_uid": "0"}),
    ("execve", {"path": "/usr/bin/apt"}),
    ("write", {"path": "/etc/apt/sources.list"}),
    ("install", {"path": "nginx"}),
    ("write", {"path": "/etc/systemd/system/nginx.service"}),
    # Legitimate cron persistence, so "wrote to cron" is not an attack tell.
    ("write", {"path": "/etc/cron.d/logrotate-extra"}),
)

#: Legitimate backup: reads credentials — including SSH keys — writes locally,
#: never egresses. Shares every object class the attack touches.
_BACKUP_ACTIONS: tuple[tuple[str, dict[str, str]], ...] = (
    ("execve", {"path": "/usr/bin/backup-agent"}),
    ("read", {"path": "/etc/shadow"}),
    ("read", {"path": "/root/.ssh/id_rsa"}),
    ("write", {"path": "/backup/etc.tar"}),
)

#: Legitimate monitoring: connects externally, regularly, forever.
_MONITOR_ACTIONS: tuple[tuple[str, dict[str, str]], ...] = (
    ("execve", {"path": "/usr/bin/node-exporter"}),
    ("connect", {"raddr": "203.0.113.10", "rport": "9100"}),
    ("send", {"raddr": "203.0.113.10", "rport": "9100"}),
)

#: The attack chain. Every step also occurs benignly above; only the assembly
#: into one escalating lineage is malicious.
_ATTACK_STAGES: tuple[tuple[str, dict[str, str]], ...] = (
    ("execve", {"path": "/usr/bin/python3"}),
    ("setuid", {"target_uid": "0"}),
    ("read", {"path": "/etc/shadow"}),
    ("connect", {"raddr": "198.51.100.77", "rport": "443"}),
    ("send", {"raddr": "198.51.100.77", "rport": "443"}),
)

_SLOW_ATTACK_STAGES: tuple[tuple[str, dict[str, str]], ...] = (
    ("execve", {"path": "/usr/bin/perl"}),
    ("setuid", {"target_uid": "0"}),
    ("write", {"path": "/etc/cron.d/sysupdate"}),
    ("read", {"path": "/root/.ssh/id_rsa"}),
    ("connect", {"raddr": "198.51.100.91", "rport": "8443"}),
)


def _step(operation: str, fields: dict[str, str], gap_ns: int) -> Behaviour:
    return Behaviour(operation, {**fields, "_gap_ns": str(gap_ns)})


def _benign_session(rng: random.Random, length: int) -> tuple[Behaviour, ...]:
    """Background noise plus legitimate privileged work, spread out."""
    steps: list[Behaviour] = []
    # Where the legitimate privileged bursts land.
    admin_at = rng.randrange(5, max(6, length // 2))
    backup_at = rng.randrange(length // 2, max(length // 2 + 1, length - 5))
    monitor_every = rng.choice((7, 11, 13))

    for index in range(length):
        if index == admin_at:
            for operation, fields in _ADMIN_ACTIONS:
                steps.append(_step(operation, fields, rng.randrange(5, 60) * _MINUTE_NS))
            continue
        if index == backup_at:
            for operation, fields in _BACKUP_ACTIONS:
                steps.append(_step(operation, fields, rng.randrange(2, 30) * _MINUTE_NS))
            continue
        if index % monitor_every == 0:
            operation, fields = _MONITOR_ACTIONS[index % len(_MONITOR_ACTIONS)]
            steps.append(_step(operation, fields, rng.randrange(1, 10) * _MINUTE_NS))
            continue
        operation, fields = rng.choice(_BACKGROUND)
        steps.append(_step(operation, fields, rng.randrange(1, 120) * _SECOND_NS))
    return tuple(steps)


def _attack_session(
    rng: random.Random, length: int, *, slow: bool
) -> tuple[Behaviour, ...]:
    """A benign session with an escalating chain woven through it."""
    stages = _SLOW_ATTACK_STAGES if slow else _ATTACK_STAGES
    background = list(_benign_session(rng, length))

    # Spread the chain across the session. A slow variant interleaves widely;
    # a fast one is a tight burst. Both must be caught.
    if slow:
        span = len(background)
        positions = sorted(
            rng.sample(range(2, max(3, span - 1)), min(len(stages), max(1, span - 3)))
        )
        gap = rng.randrange(20, 90) * _MINUTE_NS
    else:
        start = rng.randrange(2, max(3, len(background) - len(stages) - 1))
        positions = list(range(start, start + len(stages)))
        gap = rng.randrange(200, 900) * 1_000  # sub-millisecond burst

    woven = list(background)
    for offset, (position, (operation, fields)) in enumerate(
        zip(positions, stages, strict=False)
    ):
        index = min(position + offset, len(woven))
        woven.insert(index, _step(operation, fields, gap))
    return tuple(woven)


def build_long_horizon_corpus(
    *, count: int, seed: int, split: str = "eval"
) -> tuple[Scenario, ...]:
    """Build long multi-stage sessions.

    ``train`` is benign-only. ``eval`` mixes benign sessions with fast-burst and
    slow-interleaved attack sessions, the latter marked as unseen techniques.
    """
    rng = random.Random(seed)
    scenarios: list[Scenario] = []

    for index in range(count):
        length = rng.randrange(40, 120)
        if split == "train" or index % 3 != 0:
            scenarios.append(
                Scenario(f"lh-{split}-{index:04d}", _benign_session(rng, length), 0)
            )
            continue
        slow = index % 6 == 0
        scenarios.append(
            Scenario(
                f"lh-{split}-{index:04d}-attack",
                _attack_session(rng, length, slow=slow),
                1,
                technique="slow-interleaved-chain" if slow else "burst-chain",
                unseen_technique=slow,
            )
        )
    return tuple(scenarios)
