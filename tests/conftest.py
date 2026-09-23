"""Shared fixtures for the Stage 0 test suite."""

from __future__ import annotations

import pytest

from pocketsec.stage0.contracts.common import EvidenceRef, digest_of_bytes
from pocketsec.stage0.contracts.security_event_v1 import (
    SecurityEventSequenceV1,
    SecurityEventV1,
)


def make_event(index: int, kind: str = "process.exec", host: str = "host-a") -> SecurityEventV1:
    return SecurityEventV1(
        event_id=f"ev-{index:03d}",
        host_id=host,
        boot_id="boot-1",
        observed_at_ns=1_000_000_000 + index * 1000,
        monotonic_ns=index * 1000,
        source="test.source",
        kind=kind,
        attributes={"i": str(index)},
        evidence=(
            EvidenceRef(
                store="test", locator=f"e{index}", digest=digest_of_bytes(f"e{index}".encode())
            ),
        ),
    )


def make_sequence(
    kinds: tuple[str, ...] = ("process.exec", "file.open"),
    sequence_id: str = "seq-1",
    host: str = "host-a",
    **kwargs: object,
) -> SecurityEventSequenceV1:
    return SecurityEventSequenceV1(
        sequence_id=sequence_id,
        host_id=host,
        events=tuple(make_event(i, kind, host) for i, kind in enumerate(kinds)),
        **kwargs,  # type: ignore[arg-type]
    )


@pytest.fixture
def sequence() -> SecurityEventSequenceV1:
    return make_sequence()
