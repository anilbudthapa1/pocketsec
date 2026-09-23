"""D1.0 / D1.13 — the Telemetry Lab and replay corpus.

Controlled Linux behaviours with synchronised ground truth, emitted through
**two different sensor paths** for the same logical action:

* ``auditd`` style — one logical operation spread across several records
  (SYSCALL + PATH + CWD), which must be fused before compilation.
* ``eBPF`` style — one record per operation, already complete.

Cross-sensor equivalence (acceptance criterion 1) is tested by replaying an
identical scenario through both and comparing the resulting SSIR semantic keys.
If the compiler has leaked any sensor-shaped assumption, this is where it shows.

All data here is **synthetic** and every result derived from it carries
``synthetic_data=True``, per Stage 0 fair-comparison rule 7.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any

from pocketsec.stage1.telemetry.raw_event_v1 import RawEventV1, SensorPath

__all__ = ["Behaviour", "CORPUS_VERSION", "Scenario", "build_corpus", "emit"]

CORPUS_VERSION = "stage1-replay-corpus-v0.1.0"

_BASE_NS = 1_760_000_000_000_000_000


@dataclass(frozen=True, slots=True)
class Behaviour:
    """One logical machine operation with its ground truth."""

    operation: str
    fields: dict[str, str] = field(default_factory=dict)

    def with_fields(self, **extra: str) -> Behaviour:
        return Behaviour(operation=self.operation, fields={**self.fields, **extra})


@dataclass(frozen=True, slots=True)
class Scenario:
    """A named sequence of behaviours with a label."""

    name: str
    behaviours: tuple[Behaviour, ...]
    label: int
    technique: str | None = None
    unseen_technique: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "label": self.label,
            "technique": self.technique,
            "unseen_technique": self.unseen_technique,
            "length": len(self.behaviours),
        }


# --- benign behaviour --------------------------------------------------------

BENIGN_PATTERNS: tuple[tuple[Behaviour, ...], ...] = (
    # A build: lots of file churn, high novelty, zero security consequence.
    (
        Behaviour("execve", {"path": "/usr/bin/gcc"}),
        Behaviour("read", {"path": "/home/dev/src/main.c"}),
        Behaviour("write", {"path": "/home/dev/build/main.o"}),
        Behaviour("write", {"path": "/home/dev/build/a.out"}),
    ),
    # A web server serving a request.
    (
        Behaviour("accept", {"raddr": "10.0.0.5", "rport": "51000"}),
        Behaviour("read", {"path": "/var/www/index.html"}),
        Behaviour("send", {"raddr": "10.0.0.5", "rport": "51000"}),
    ),
    # A backup job reading user data locally.
    (
        Behaviour("execve", {"path": "/usr/bin/tar"}),
        Behaviour("read", {"path": "/home/dev/documents/notes.txt"}),
        Behaviour("write", {"path": "/backup/archive.tar"}),
    ),
    # Routine package query.
    (
        Behaviour("execve", {"path": "/usr/bin/dpkg"}),
        Behaviour("read", {"path": "/var/lib/dpkg/status"}),
    ),
    # Local service chatter.
    (
        Behaviour("connect", {"raddr": "127.0.0.1", "rport": "5432"}),
        Behaviour("send", {"raddr": "127.0.0.1", "rport": "5432"}),
        Behaviour("recv", {"raddr": "127.0.0.1", "rport": "5432"}),
    ),
)

#: A legitimate admin doing privileged work. High Φ, entirely benign — the case
#: that stops Φ from being treated as a threat score.
BENIGN_PRIVILEGED: tuple[Behaviour, ...] = (
    Behaviour("setuid", {"target_uid": "0"}),
    Behaviour("execve", {"path": "/usr/bin/apt"}),
    Behaviour("write", {"path": "/etc/apt/sources.list"}),
)

# --- attack behaviour --------------------------------------------------------

#: The spec's own worked example: sudo -> credential read -> external egress.
ATTACK_EXFIL: tuple[Behaviour, ...] = (
    Behaviour("setuid", {"target_uid": "0"}),
    Behaviour("read", {"path": "/etc/shadow"}),
    Behaviour("connect", {"raddr": "203.0.113.42", "rport": "443"}),
    Behaviour("send", {"raddr": "203.0.113.42", "rport": "443"}),
)

#: Persistence with authority.
ATTACK_PERSISTENCE: tuple[Behaviour, ...] = (
    Behaviour("setuid", {"target_uid": "0"}),
    Behaviour("write", {"path": "/etc/systemd/system/backdoor.service"}),
    Behaviour("execve", {"path": "/usr/bin/systemctl"}),
)

#: Held out of training: memory-scraping credential theft via ptrace. Uses a
#: different route to the same capability set, so it tests behaviour-based
#: generalisation rather than pattern memorisation.
ATTACK_UNSEEN_MEMORY: tuple[Behaviour, ...] = (
    Behaviour("ptrace", {"target_pid": "900"}),
    Behaviour("connect", {"raddr": "198.51.100.7", "rport": "8443"}),
    Behaviour("send", {"raddr": "198.51.100.7", "rport": "8443"}),
)

#: Container escape, also held out.
ATTACK_UNSEEN_ESCAPE: tuple[Behaviour, ...] = (
    Behaviour("setuid", {"target_uid": "0"}),
    Behaviour("mount", {"path": "/proc/1/root"}),
    Behaviour("read", {"path": "/etc/shadow"}),
)


# --- emission ----------------------------------------------------------------


def emit(
    behaviour: Behaviour,
    *,
    sensor: SensorPath,
    index: int,
    host_id: str,
    boot_id: str = "boot-0001",
    pid: str = "1000",
) -> list[RawEventV1]:
    """Emit one behaviour as raw records for a given sensor path.

    The two paths differ in *shape*, not content: auditd splits an operation
    across records sharing an assembly key, eBPF emits one. Both must compile to
    the same SSIR semantics.
    """
    now = _BASE_NS + index * 1_000_000
    common = {"pid": pid, "start_time": "7", "uid": "1000", **behaviour.fields}

    if sensor is SensorPath.EBPF:
        return [
            RawEventV1(
                record_id=f"ebpf-{index:05d}",
                host_id=host_id,
                boot_id=boot_id,
                sensor=SensorPath.EBPF,
                observed_at_ns=now,
                monotonic_ns=index * 1_000_000,
                record_type=behaviour.operation,
                assembly_key=None,
                fields={"operation": f"sys_{behaviour.operation}", **common},
            )
        ]

    # auditd style: a SYSCALL record plus a PATH/SOCKADDR detail record, sharing
    # an assembly key and declaring how many records to expect.
    key = f"audit-{index:05d}"
    detail_type = "SOCKADDR" if "raddr" in behaviour.fields else "PATH"
    return [
        RawEventV1(
            record_id=f"{key}-0",
            host_id=host_id,
            boot_id=boot_id,
            sensor=SensorPath.AUDITD,
            observed_at_ns=now,
            monotonic_ns=index * 1_000_000,
            record_type="SYSCALL",
            assembly_key=key,
            fields={
                "syscall": behaviour.operation.upper(),
                "_expected_records": "2",
                "pid": pid,
                "start_time": "7",
                "uid": "1000",
            },
        ),
        RawEventV1(
            record_id=f"{key}-1",
            host_id=host_id,
            boot_id=boot_id,
            sensor=SensorPath.AUDITD,
            observed_at_ns=now + 1000,
            monotonic_ns=index * 1_000_000 + 1000,
            record_type=detail_type,
            assembly_key=key,
            fields={"_expected_records": "2", **behaviour.fields},
        ),
    ]


def build_corpus(
    *, count: int, seed: int, split: str, include_unseen: bool = True
) -> tuple[Scenario, ...]:
    """Build a deterministic scenario corpus.

    ``split="train"`` is benign-only. ``split="eval"`` mixes benign, benign-
    privileged, seen attacks and — when ``include_unseen`` — techniques that
    appear nowhere in training.
    """
    rng = random.Random(seed)
    scenarios: list[Scenario] = []

    for index in range(count):
        if split == "train":
            scenarios.append(_benign(rng, index))
            continue

        bucket = index % 10
        if bucket == 3:
            scenarios.append(
                Scenario(
                    f"eval-{index:04d}-exfil",
                    ATTACK_EXFIL,
                    1,
                    technique="sudo-credential-exfil",
                )
            )
        elif bucket == 6:
            scenarios.append(
                Scenario(
                    f"eval-{index:04d}-persist",
                    ATTACK_PERSISTENCE,
                    1,
                    technique="privileged-persistence",
                )
            )
        elif bucket == 8 and include_unseen:
            chain, technique = (
                (ATTACK_UNSEEN_MEMORY, "memory-credential-theft")
                if index % 20 == 8
                else (ATTACK_UNSEEN_ESCAPE, "container-escape")
            )
            scenarios.append(
                Scenario(
                    f"eval-{index:04d}-unseen",
                    chain,
                    1,
                    technique=technique,
                    unseen_technique=True,
                )
            )
        elif bucket == 5:
            scenarios.append(
                Scenario(f"eval-{index:04d}-admin", BENIGN_PRIVILEGED, 0, technique="admin-work")
            )
        else:
            scenarios.append(_benign(rng, index))

    return tuple(scenarios)


def _benign(rng: random.Random, index: int) -> Scenario:
    pattern = rng.choice(BENIGN_PATTERNS)
    return Scenario(f"benign-{index:04d}", pattern, 0)
