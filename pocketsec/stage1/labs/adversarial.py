"""D1.12 — adversarial representation tests (spec section 22).

Eight attacks on the representation itself, each answering a specific question
about whether SSIR encodes behaviour or merely memorises strings:

1. **Renaming** — rename common tools; semantics must not collapse to identity
   memorisation.
2. **Unseen binaries** — previously unseen executables exhibiting known
   capability patterns.
3. **Obfuscation** — mangle command lines while preserving behaviour.
4. **Timing shift** — stretch and fragment attack chains.
5. **High-novelty benign** — developer/build workloads that are genuinely
   novel and genuinely harmless. This is the false-positive test that keeps
   "novelty is not maliciousness" honest.
6. **Epoch poisoning** — gradual malicious behaviour attempting to shift the
   baseline.
7. **Flood** — low-value event storms against bounded sketches and queues.
8. **Sensor disagreement** — conflicting or incomplete telemetry, where
   uncertainty must *rise* rather than produce false certainty.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pocketsec.stage1.epoch.model import SystemIdentity
from pocketsec.stage1.labs.corpus import (
    ATTACK_EXFIL,
    BENIGN_PATTERNS,
    Behaviour,
    Scenario,
)
from pocketsec.stage1.pipeline import Stage1Pipeline
from pocketsec.stage1.telemetry.assembler import EventAssembler
from pocketsec.stage1.telemetry.raw_event_v1 import RawEventV1, SensorPath

__all__ = ["AdversarialReport", "run_adversarial_suite"]


@dataclass(frozen=True, slots=True)
class TestOutcome:
    name: str
    passed: bool
    measurement: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "passed": self.passed,
            "measurement": self.measurement,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class AdversarialReport:
    outcomes: tuple[TestOutcome, ...]

    @property
    def passed(self) -> bool:
        return all(outcome.passed for outcome in self.outcomes)

    @property
    def failures(self) -> tuple[TestOutcome, ...]:
        return tuple(o for o in self.outcomes if not o.passed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "outcomes": [o.to_dict() for o in self.outcomes],
        }


def _rename(chain: tuple[Behaviour, ...], new_path: str) -> tuple[Behaviour, ...]:
    """Rewrite executable paths while preserving every operation."""
    return tuple(
        b.with_fields(path=new_path) if b.operation == "execve" else b for b in chain
    )


def _renaming_test() -> TestOutcome:
    """Renamed tools must reach the same security state."""
    baseline = Stage1Pipeline().run_scenario(Scenario("base", ATTACK_EXFIL, 1))
    renamed_chain = _rename(ATTACK_EXFIL, "/tmp/.x91")
    renamed = Stage1Pipeline().run_scenario(Scenario("renamed", renamed_chain, 1))

    same_state = baseline.final_state.to_levels() == renamed.final_state.to_levels()
    phi_gap = abs(baseline.peak_phi - renamed.peak_phi)
    return TestOutcome(
        name="renaming",
        passed=same_state and phi_gap < 0.01,
        measurement=f"phi {baseline.peak_phi:.2f} vs {renamed.peak_phi:.2f}",
        detail=(
            "renamed executable reaches an identical security state; semantics "
            "come from behaviour, not the path"
            if same_state
            else "renaming changed the security state: identity leaked into semantics"
        ),
    )


def _unseen_binary_test() -> TestOutcome:
    """An unseen binary with a known capability pattern must still be seen."""
    unseen = tuple(
        b.with_fields(path="/opt/vendor/never-seen-before-4417")
        if b.operation == "execve"
        else b
        for b in ATTACK_EXFIL
    )
    result = Stage1Pipeline().run_scenario(Scenario("unseen", unseen, 1))
    triad = "exfiltration_triad"
    from pocketsec.stage1.state.potential import phi

    active = phi(result.final_state).active_interactions
    return TestOutcome(
        name="unseen_binary",
        passed=triad in active,
        measurement=f"phi={result.peak_phi:.2f} interactions={list(active)}",
        detail=(
            "unseen binary still triggers the exfiltration triad via its capability "
            "pattern"
            if triad in active
            else "capability pattern not recognised for an unseen binary"
        ),
    )


def _obfuscation_test() -> TestOutcome:
    """Mangled command lines must not change the compiled semantics."""
    obfuscated = tuple(
        b.with_fields(cmdline="c'u'r'l --$(echo s)ilent", comm="kworker/u8:3")
        for b in ATTACK_EXFIL
    )
    baseline = Stage1Pipeline().run_scenario(Scenario("base", ATTACK_EXFIL, 1))
    result = Stage1Pipeline().run_scenario(Scenario("obfuscated", obfuscated, 1))
    same = baseline.final_state.to_levels() == result.final_state.to_levels()
    return TestOutcome(
        name="obfuscation",
        passed=same,
        measurement=f"phi {baseline.peak_phi:.2f} vs {result.peak_phi:.2f}",
        detail=(
            "obfuscated command lines do not participate in semantics"
            if same
            else "obfuscation changed semantics: command strings are load-bearing"
        ),
    )


def _timing_shift_test() -> TestOutcome:
    """Stretching a chain in time must not dissolve it.

    Timing enters SSIR only as a coarse bucket, so a slow attack and a fast one
    reach the same state. That is the intended trade: it costs timing precision
    and buys immunity to pacing.
    """
    pipeline = Stage1Pipeline()
    fast = pipeline.run_scenario(Scenario("fast", ATTACK_EXFIL, 1), offset=0)
    slow_pipeline = Stage1Pipeline()
    slow = slow_pipeline.run_scenario(Scenario("slow", ATTACK_EXFIL, 1), offset=50)
    same = fast.final_state.to_levels() == slow.final_state.to_levels()
    return TestOutcome(
        name="timing_shift",
        passed=same,
        measurement=f"phi {fast.peak_phi:.2f} vs {slow.peak_phi:.2f}",
        detail=(
            "time-shifted chain reaches the same state"
            if same
            else "chain dissolved under time shift"
        ),
    )


def _high_novelty_benign_test() -> TestOutcome:
    """Novel benign work must stay low-Φ. Novelty is not maliciousness."""
    pipeline = Stage1Pipeline()
    novel_build = tuple(
        Behaviour("write", {"path": f"/home/dev/build/obj-{i}-{i * 7919}.o"})
        for i in range(12)
    )
    result = pipeline.run_scenario(Scenario("novel-build", novel_build, 0))
    high_novelty = result.peak_novelty >= 0.9
    low_phi = result.peak_phi < 2.0
    return TestOutcome(
        name="high_novelty_benign",
        passed=high_novelty and low_phi,
        measurement=f"novelty={result.peak_novelty:.2f} phi={result.peak_phi:.2f}",
        detail=(
            "genuinely novel benign workload stays low-potential: novelty and "
            "security potential are independent signals"
            if high_novelty and low_phi
            else "novel benign work was scored as high potential"
        ),
    )


def _epoch_poisoning_test() -> TestOutcome:
    """Behavioural novelty alone must never open a new epoch."""
    pipeline = Stage1Pipeline()
    attacker_identity = SystemIdentity(
        kernel_id="6.1.0", package_digest="pkg-ATTACKER", service_digest="svc-a"
    )
    decision = pipeline.epoch.evaluate(
        observed_identity=attacker_identity,
        corroborating_evidence=frozenset(),  # no package manager transaction
        now_ns=1_000_000,
        behavioural_novelty=1.0,  # maximally novel: must not matter
    )
    legitimate = pipeline.epoch.evaluate(
        observed_identity=attacker_identity,
        corroborating_evidence={"package_digest"},
        now_ns=2_000_000,
    )
    passed = not decision.transitioned and legitimate.transitioned
    return TestOutcome(
        name="epoch_poisoning",
        passed=passed,
        measurement=(
            f"uncorroborated={decision.reason.value} corroborated={legitimate.reason.value}"
        ),
        detail=(
            "uncorroborated identity change refused even at maximum novelty; "
            "corroborated change accepted"
            if passed
            else "epoch transition rule did not behave as specified"
        ),
    )


def _flood_test() -> TestOutcome:
    """A low-value flood must stay inside every bound."""
    pipeline = Stage1Pipeline()
    flood = tuple(Behaviour("read", {"path": f"/var/log/app-{i % 50}.log"}) for i in range(400))
    pipeline.run_scenario(Scenario("flood", flood, 0))

    novelty_bytes = pipeline.novelty.memory_bytes
    causal_nodes = len(pipeline.causal)
    aggregation = pipeline.aggregation.report()
    within = (
        novelty_bytes <= 2_000_000
        and causal_nodes <= pipeline.causal.capacity
        and aggregation.aggregated_away > 0
    )
    return TestOutcome(
        name="flood",
        passed=within,
        measurement=(
            f"novelty={novelty_bytes}B causal_nodes={causal_nodes} "
            f"aggregated={aggregation.aggregated_away} "
            f"ratio={aggregation.compression_ratio:.2f}"
        ),
        detail=(
            "bounded structures held and repetitive low-value events coalesced"
            if within
            else "flood exceeded a declared bound"
        ),
    )


def _sensor_disagreement_test() -> TestOutcome:
    """Conflicting telemetry must raise uncertainty, not manufacture certainty."""
    pipeline = Stage1Pipeline()
    key = "conflict-1"
    common = {"_expected_records": "2", "pid": "1000", "start_time": "7"}
    records = [
        RawEventV1(
            record_id="c-0",
            host_id=pipeline.host_id,
            boot_id="boot-0001",
            sensor=SensorPath.AUDITD,
            observed_at_ns=1000,
            monotonic_ns=1000,
            record_type="SYSCALL",
            assembly_key=key,
            fields={"syscall": "READ", "path": "/etc/shadow", **common},
        ),
        RawEventV1(
            record_id="c-1",
            host_id=pipeline.host_id,
            boot_id="boot-0001",
            sensor=SensorPath.EBPF,
            observed_at_ns=1100,
            monotonic_ns=1100,
            record_type="PATH",
            assembly_key=key,
            # Disagrees with the auditd record about which file was read.
            fields={"path": "/var/log/syslog", **common},
        ),
    ]
    assembler = EventAssembler()
    events: list[Any] = []
    for record in records:
        events.extend(assembler.feed(record))
    events.extend(assembler.flush())

    transitions = [
        t
        for event in events
        if (t := pipeline.compiler.compile(event)) is not None
    ]
    clean = Stage1Pipeline().run_scenario(
        Scenario("clean", (Behaviour("read", {"path": "/etc/shadow"}),), 1)
    )
    conflicted_uncertainty = max((t.uncertainty for t in transitions), default=0.0)
    passed = bool(transitions) and conflicted_uncertainty > clean.peak_uncertainty
    return TestOutcome(
        name="sensor_disagreement",
        passed=passed,
        measurement=(
            f"conflicted_uncertainty={conflicted_uncertainty:.3f} "
            f"clean={clean.peak_uncertainty:.3f}"
        ),
        detail=(
            "disagreeing sensors raised uncertainty rather than picking a winner"
            if passed
            else "sensor conflict did not raise uncertainty"
        ),
    )


def run_adversarial_suite() -> AdversarialReport:
    """Run all eight adversarial representation tests."""
    return AdversarialReport(
        outcomes=(
            _renaming_test(),
            _unseen_binary_test(),
            _obfuscation_test(),
            _timing_shift_test(),
            _high_novelty_benign_test(),
            _epoch_poisoning_test(),
            _flood_test(),
            _sensor_disagreement_test(),
        )
    )


assert BENIGN_PATTERNS  # corpus import kept for scenario construction
