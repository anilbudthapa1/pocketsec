"""Deterministic synthetic fixture generator for the Stage 0 smoke benchmark.

This data is **synthetic** and exists only to prove the harness runs end to end.
Spec section 13: synthetic performance is labelled synthetic and never presented
as real-world detection quality. Every result produced from it carries
``synthetic_data=True``.

The attack pattern mirrors the spec's own worked example
(``sudo -> credential_read -> unknown_external_network -> RISK_ESCALATION``),
so the fixture exercises a rare-transition chain rather than random noise.
"""

from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Any

from pocketsec.stage0.contracts.common import EvidenceRef, digest_of_bytes
from pocketsec.stage0.contracts.security_event_v1 import (
    SecurityEventSequenceV1,
    SecurityEventV1,
)

__all__ = ["FIXTURE_VERSION", "write_fixture"]

FIXTURE_VERSION = "tiny-linux-events-v0.1.0"

_BENIGN_PATTERNS: tuple[tuple[str, ...], ...] = (
    ("process.exec", "file.open", "file.read", "process.exit"),
    ("process.fork", "process.exec", "net.connect.local", "process.exit"),
    ("file.open", "file.write", "file.close"),
    ("auth.session.open", "process.exec", "file.read", "auth.session.close"),
    ("cron.trigger", "process.exec", "file.read", "process.exit"),
)

# The escalation chain: each step is individually plausible; the ordering is
# what carries the signal.
_ATTACK_CHAIN: tuple[str, ...] = (
    "auth.sudo",
    "cred.read",
    "net.connect.external",
)

_UNSEEN_CHAIN: tuple[str, ...] = (
    "ptrace.attach",
    "mem.dump",
    "net.connect.external",
)


def _make_event(
    *, host: str, index: int, kind: str, sequence_id: str, base_ns: int
) -> SecurityEventV1:
    payload = f"{sequence_id}:{index}:{kind}".encode()
    return SecurityEventV1(
        event_id=f"{sequence_id}-e{index:03d}",
        host_id=host,
        boot_id="boot-0001",
        observed_at_ns=base_ns + index * 1_000_000,
        monotonic_ns=index * 1_000_000,
        source="fixture.synthetic",
        kind=kind,
        attributes={"seq_index": str(index)},
        evidence=(
            EvidenceRef(
                store="fixture",
                locator=f"{sequence_id}#{index}",
                digest=digest_of_bytes(payload),
            ),
        ),
    )


def _build(
    *, sequence_id: str, kinds: tuple[str, ...], host: str, base_ns: int
) -> SecurityEventSequenceV1:
    events = tuple(
        _make_event(host=host, index=i, kind=kind, sequence_id=sequence_id, base_ns=base_ns)
        for i, kind in enumerate(kinds)
    )
    return SecurityEventSequenceV1(
        sequence_id=sequence_id,
        host_id=host,
        events=events,
        window_capacity=64,
        truncated=False,
    )


def _benign(rng: random.Random, sequence_id: str, host: str) -> tuple[str, ...]:
    pattern = list(rng.choice(_BENIGN_PATTERNS))
    if rng.random() < 0.3:
        pattern.insert(rng.randrange(len(pattern)), "file.open")
    return tuple(pattern)


def _malicious(rng: random.Random, chain: tuple[str, ...]) -> tuple[str, ...]:
    prefix = list(rng.choice(_BENIGN_PATTERNS))[:2]
    return tuple(prefix + list(chain))


def write_fixture(
    path: Path, *, split: str, count: int, seed: int, host: str = "fixture-host-01"
) -> dict[str, Any]:
    """Write one JSONL split and return its provenance block.

    ``split="train"`` emits benign traffic only. ``split="eval"`` mixes benign,
    seen-attack and unseen-technique items, the last of which never appears in
    training — a leakage-resistant split by construction (spec section 13).
    """
    if split not in ("train", "eval"):
        raise ValueError(f"split must be 'train' or 'eval', got {split!r}")

    rng = random.Random(seed)
    base_ns = 1_760_000_000_000_000_000
    lines: list[str] = []

    for index in range(count):
        sequence_id = f"{split}-{index:04d}"
        if split == "train":
            kinds, label, technique, unseen = _benign(rng, sequence_id, host), 0, None, False
        elif index % 5 == 3:
            unseen = index % 10 == 8
            chain = _UNSEEN_CHAIN if unseen else _ATTACK_CHAIN
            kinds, label = _malicious(rng, chain), 1
            technique = "memory-credential-theft" if unseen else "sudo-credential-exfil"
        else:
            kinds, label, technique, unseen = _benign(rng, sequence_id, host), 0, None, False

        record = {
            "sequence": _build(
                sequence_id=sequence_id, kinds=kinds, host=host, base_ns=base_ns
            ).to_dict(),
            "label": label,
            "technique": technique,
            "unseen_technique": unseen,
        }
        lines.append(json.dumps(record, sort_keys=True, separators=(",", ":")))

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    from pocketsec.stage0.benchmark.dataset import sha256_file

    return {
        "name": f"tiny-linux-events-{split}",
        "version": FIXTURE_VERSION,
        "split": split,
        "seed": seed,
        "item_count": count,
        "sha256": sha256_file(path),
        "synthetic": True,
        "path": path.name,
    }
