"""§4.19 — the discovery corpus: a synthetic world built to contain what Stage 8 looks for.

Why Stage 8 builds its own corpus (spec M0.3/M0.4): on every existing corpus either the
Φ-oracle ranks every session perfectly or a 2-step search adds nothing over a single step, so
no discovery engine could beat baseline (1) and baseline (3) at once. This world is designed
so that it *can*, and so that it can also catch an engine that cheats:

* **Planted mechanisms** (``PLANTED_MECHANISMS``, built with ``parse_mechanism``): PM1
  ``PRECEDES(EXECUTE+TEMP_LOCATION,CONNECT+EXTERNAL_ENDPOINT)`` in DROP_EXEC_EGRESS, whose
  sessions sit at the same Φ-oracle score as benign OFFSITE_BACKUP (M0.6); PM2
  ``REPEATED(CONNECT+EXTERNAL_ENDPOINT,4)``; PM3 ``PRECEDES(READ+CREDENTIAL,...)``, which is
  Stage 1's ``ATTACK_EXFIL`` verbatim (the rediscovery control).
* **Benign twins**: SPLIT_ACTORS does PM1's steps in two actors, BUILD_TMP_EXEC runs from
  /tmp without egress, UPDATE_FETCH connects out 1-3 times, OFFSITE_BACKUP reads and sends.
* **The trap**: ``TRAP_BEHAVIOUR`` (a bare ``fork``) prefixes every TRAIN positive and no
  TRAIN negative, and prefixes held-out sessions of both classes with probability 0.5.
  ``SINGLE(SPAWN)`` is therefore perfect on TRAIN by construction and worthless held out:
  the discipline must kill it.
* **NULL arm**: identical content without the trap, labels Bernoulli(0.34) from a label seed
  (``relabel_null`` redraws them without re-rendering). Anything "discovered" here is false.
* **DROPOUT arm**: the PLANTED world with every EXECUTION-family step of half the
  DROP_EXEC_EGRESS sessions deleted (``SENSOR_DROPOUT`` at 1000 ‰): the case the
  identifiability gate must call UNIDENTIFIABLE rather than force.

Every session is a Stage 1 ``Behaviour`` sequence (no new scenario type), rendered once on a
**fresh** ``Stage1Pipeline`` with a session-unique pid (the Stage 2 corpus trap: reused process
identities carry lineage state between sessions and erase the signal). Episodes hold Stage 6
``EncodedStep`` values; the raw ``ScenarioResult`` of each is kept apart in
``DiscoveryCorpus.results`` (raw evidence is never the model representation).

**Author confound, stated (lesson 6).** The planted mechanisms, the twins, the trap, the lab
oracle and the engine are specified by one author (the Stage 8 contract). A discovery made
here shows the machinery works on a world built to contain it; it is not evidence about real
telemetry. ``corpus_preconditions`` measures whether this world is non-degenerate (P1-P5) and
labels every figure it reports; it asserts nothing it did not compute.

What it refuses to do: every behaviour is a synthetic record of an ordinary machine operation
(write, execve, read, connect, send, recv, setuid, fork); nothing here is executed, sent or
written outside this process. It never mints a label outside the lab (``LabOracle`` is the
authorised synthetic ground truth and charges the governor), and it is imported only by
``labs/`` and the harness (boundary rule 10).
"""

from __future__ import annotations

import random
import statistics
import sys
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from pocketsec.stage0.benchmark.security_metrics import average_precision
from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.guillotine.features import LogisticProbe
from pocketsec.stage1.labs.corpus import (
    ATTACK_EXFIL,
    BENIGN_PATTERNS,
    BENIGN_PRIVILEGED,
    CORPUS_VERSION,
    Behaviour,
    Scenario,
    build_corpus,
)
from pocketsec.stage1.labs.hard_corpus import HARD_CORPUS_VERSION, build_hard_corpus
from pocketsec.stage1.pipeline import ScenarioResult, Stage1Pipeline
from pocketsec.stage1.ssir.relations import Relation
from pocketsec.stage6.capsule.experience_capsule import EncodedStep
from pocketsec.stage8.episode import (
    Episode,
    EpisodeContext,
    FitCounts,
    Split,
    episode_from_result,
    fit_counts,
)
from pocketsec.stage8.genome.grammar import (
    Mechanism,
    MechanismRelation,
    StepPredicate,
    parse_mechanism,
)
from pocketsec.stage8.governor.budget import ResearchGovernor
from pocketsec.stage8.laboratory.counterfactual import (
    TransformKind,
    TransformSpec,
    apply_transform,
)

__all__ = [
    "DEFAULT_COUNTS",
    "DISCOVERY_CORPUS_VERSION",
    "DOPPELGANGER_FAMILY_MAP",
    "DROPOUT_SHARE",
    "FAMILY_LABELS",
    "FAMILY_MIX",
    "LAB_ORACLE_COMPONENT",
    "MAX_DOPPELGANGERS",
    "MAX_SESSIONS_PER_SPLIT",
    "MONITORING_AGENT",
    "NATURAL_SPLITS",
    "NULL_BASE_RATE",
    "P1_MAX_PHI_AP",
    "P2_MARGIN",
    "P5_MAX_LOGISTIC_AP",
    "PLANTED_IDS",
    "PLANTED_MECHANISMS",
    "SPLIT_EPOCHS",
    "SPLIT_HOSTS",
    "TRAP_BEHAVIOUR",
    "TRAP_PROBABILITY",
    "CorpusArm",
    "CorpusDoppelgangers",
    "DiscoveryCorpus",
    "Family",
    "LabOracle",
    "PreconditionReport",
    "build_discovery_corpus",
    "content_label",
    "corpus_preconditions",
    "planted_label",
    "relabel_null",
]

DISCOVERY_CORPUS_VERSION = "stage8-discovery-v0.1.0"


class CorpusArm(StrEnum):
    PLANTED = "PLANTED"
    NULL = "NULL"
    DROPOUT = "DROPOUT"


class Family(StrEnum):
    DROP_EXEC_EGRESS = "DROP_EXEC_EGRESS"
    REPEATED_EGRESS = "REPEATED_EGRESS"
    CREDENTIAL_EGRESS = "CREDENTIAL_EGRESS"
    OFFSITE_BACKUP = "OFFSITE_BACKUP"
    BUILD_TMP_EXEC = "BUILD_TMP_EXEC"
    SPLIT_ACTORS = "SPLIT_ACTORS"
    UPDATE_FETCH = "UPDATE_FETCH"
    ADMIN_PRIVILEGED = "ADMIN_PRIVILEGED"
    ROUTINE = "ROUTINE"


# --- chosen parameters (§4.19 / §4.21): every value below is chosen, not measured ------------

FAMILY_LABELS: Mapping[Family, int] = MappingProxyType({
    Family.DROP_EXEC_EGRESS: 1, Family.REPEATED_EGRESS: 1, Family.CREDENTIAL_EGRESS: 1,
    Family.OFFSITE_BACKUP: 0, Family.BUILD_TMP_EXEC: 0, Family.SPLIT_ACTORS: 0,
    Family.UPDATE_FETCH: 0, Family.ADMIN_PRIVILEGED: 0, Family.ROUTINE: 0,
})
FAMILY_MIX: Mapping[Family, float] = MappingProxyType({
    Family.DROP_EXEC_EGRESS: 0.12, Family.REPEATED_EGRESS: 0.12, Family.OFFSITE_BACKUP: 0.12,
    Family.BUILD_TMP_EXEC: 0.12, Family.SPLIT_ACTORS: 0.12, Family.UPDATE_FETCH: 0.12,
    Family.CREDENTIAL_EGRESS: 0.10, Family.ROUTINE: 0.10, Family.ADMIN_PRIVILEGED: 0.08,
})
NATURAL_SPLITS: tuple[Split, ...] = (Split.TRAIN, Split.HOLDOUT, Split.REPLICATION, Split.LAB_POOL)
DEFAULT_COUNTS: Mapping[Split, int] = MappingProxyType({
    Split.TRAIN: 240, Split.HOLDOUT: 240, Split.REPLICATION: 240, Split.LAB_POOL: 120,
    Split.INDEPENDENT: 120,
})
SPLIT_HOSTS: Mapping[Split, tuple[str, ...]] = MappingProxyType({
    Split.TRAIN: ("lab-h01", "lab-h02", "lab-h03", "lab-h04"),
    Split.HOLDOUT: ("lab-h05", "lab-h06", "lab-h07", "lab-h08"),
    Split.REPLICATION: ("lab-h09", "lab-h10", "lab-h11", "lab-h12"),
    Split.LAB_POOL: ("lab-h13", "lab-h14"),
    Split.INDEPENDENT: ("lab-i01", "lab-i02"),   # not fixed by the contract; chosen here
})
SPLIT_EPOCHS: Mapping[Split, int] = MappingProxyType({
    Split.TRAIN: 0, Split.HOLDOUT: 1, Split.REPLICATION: 2, Split.LAB_POOL: 0,
    Split.INDEPENDENT: 3,                        # not fixed by the contract; chosen here
})
TRAP_BEHAVIOUR = Behaviour("fork", {})
TRAP_PROBABILITY: float = 0.5
NULL_BASE_RATE: float = 0.34
DROPOUT_SHARE: float = 0.5
MAX_SESSIONS_PER_SPLIT: int = 5000
MAX_DOPPELGANGERS: int = 256
P1_MAX_PHI_AP: float = 0.85
P2_MARGIN: float = 0.10
P5_MAX_LOGISTIC_AP: float = 0.95
LAB_ORACLE_COMPONENT = "labs.lab_oracle"
MONITORING_AGENT = "MONITORING_AGENT"

PLANTED_IDS: Mapping[Family, str] = MappingProxyType({
    Family.DROP_EXEC_EGRESS: "PM1", Family.REPEATED_EGRESS: "PM2", Family.CREDENTIAL_EGRESS: "PM3",
})
PLANTED_MECHANISMS: Mapping[Family, Mechanism] = MappingProxyType({
    Family.DROP_EXEC_EGRESS: parse_mechanism(
        "PRECEDES(EXECUTE+TEMP_LOCATION,CONNECT+EXTERNAL_ENDPOINT)"),
    Family.REPEATED_EGRESS: parse_mechanism("REPEATED(CONNECT+EXTERNAL_ENDPOINT,4)"),
    Family.CREDENTIAL_EGRESS: parse_mechanism(
        "PRECEDES(READ+CREDENTIAL,CONNECT+EXTERNAL_ENDPOINT)"),
})

#: DoppelgangerFamily member NAME → corpus family (or MONITORING_AGENT / the dpkg pattern).
#: Keyed by name so this module does not import the falsification package's enum.
DOPPELGANGER_FAMILY_MAP: Mapping[str, str] = MappingProxyType({
    "ADMIN_SCRIPT": Family.ADMIN_PRIVILEGED.value,
    "SOFTWARE_UPDATE": Family.UPDATE_FETCH.value,
    "BACKUP": Family.OFFSITE_BACKUP.value,
    "PACKAGE_MANAGER": "DPKG_PATTERN",
    MONITORING_AGENT: MONITORING_AGENT,
    "DEVELOPER_TOOLING": Family.BUILD_TMP_EXEC.value,
    "ORCHESTRATION": Family.SPLIT_ACTORS.value,
})

_DOC = "/home/u/documents/d.txt"
_DPKG = next(p for p in BENIGN_PATTERNS if p[0].fields.get("path") == "/usr/bin/dpkg")
#: Serial ranges keep every session's pid unique corpus-wide (pid = 1000 + 2·serial; the odd
#: pid after it is SPLIT_ACTORS' second actor).
_SERIAL_BASE: Mapping[Split, int] = MappingProxyType({
    Split.TRAIN: 0, Split.HOLDOUT: 10_000, Split.REPLICATION: 20_000, Split.LAB_POOL: 30_000,
    Split.INDEPENDENT: 40_000,
})
_TRAP_SERIAL = 90_000
_DOPPELGANGER_SERIAL = 200_000
_EXECUTION_TARGET = StepPredicate(int(Relation.EXECUTE), 0, 0, 0)


# --- behaviours ---------------------------------------------------------------------------


def _net(rng: random.Random, replication: bool) -> str:
    return f"{'198.51.100' if replication else '203.0.113'}.{rng.randint(1, 254)}"


def _egress(address: str, port: str, operation: str = "send",
            **extra: str) -> tuple[Behaviour, ...]:
    fields = {"raddr": address, "rport": port, **extra}
    return (Behaviour("connect", dict(fields)), Behaviour(operation, dict(fields)))


def _malicious(family: Family, rng: random.Random, replication: bool) -> tuple[Behaviour, ...]:
    if family is Family.DROP_EXEC_EGRESS:
        temp = rng.choice(("/var/tmp", "/dev/shm")) if replication else "/tmp/.cache"
        return (Behaviour("write", {"path": f"{temp}/.x"}),
                Behaviour("execve", {"path": f"{temp}/.x"}),
                Behaviour("read", {"path": _DOC}), *_egress(_net(rng, replication), "443"))
    if family is Family.REPEATED_EGRESS:
        address, k = _net(rng, replication), rng.choice((5, 6, 7) if replication else (4, 5))
        return _egress(address, "443") * k
    return ATTACK_EXFIL


def _benign(family: Family, rng: random.Random, replication: bool,
            second_pid: str) -> tuple[Behaviour, ...]:
    address = _net(rng, replication)
    if family is Family.OFFSITE_BACKUP:
        return (Behaviour("execve", {"path": "/usr/bin/rsync"}), Behaviour("read", {"path": _DOC}),
                *_egress(address, "22"))
    if family is Family.BUILD_TMP_EXEC:
        binary = f"{'/var/tmp' if replication else '/tmp'}/build/a.out"
        return (Behaviour("write", {"path": binary}), Behaviour("execve", {"path": binary}))
    if family is Family.SPLIT_ACTORS:
        temp = rng.choice(("/var/tmp", "/dev/shm")) if replication else "/tmp/.cache"
        return (Behaviour("write", {"path": f"{temp}/x"}),
                Behaviour("execve", {"path": f"{temp}/x"}),
                *_egress(address, "443", pid=second_pid))
    if family is Family.UPDATE_FETCH:
        fetches = _egress(address, "443", "recv") * rng.choice((1, 2, 3))
        return (Behaviour("execve", {"path": "/usr/bin/apt"}), *fetches,
                Behaviour("write", {"path": "/var/cache/apt/p.deb"}))
    if family is Family.ADMIN_PRIVILEGED:
        return BENIGN_PRIVILEGED
    return rng.choice(BENIGN_PATTERNS)


def _behaviours(family: Family, split: Split, rng: random.Random,
                serial: int) -> tuple[Behaviour, ...]:
    replication = split is Split.REPLICATION
    if FAMILY_LABELS[family]:
        return _malicious(family, rng, replication)
    return _benign(family, rng, replication, second_pid=str(1000 + 2 * serial + 1))


def _monitoring_agent(rng: random.Random) -> tuple[Behaviour, ...]:
    """The doppelgänger of PM2: a telemetry shipper. Exists ONLY in ``CorpusDoppelgangers``."""
    return (Behaviour("execve", {"path": "/usr/bin/telegraf"}),
            *(_egress(_net(rng, False), "443") * rng.choice((4, 5, 6))))


def _render(behaviours: tuple[Behaviour, ...], *, host: str, serial: int,
            label: int) -> ScenarioResult:
    """One session on a FRESH pipeline: no lineage state survives from any other session."""
    scenario = Scenario(f"s8-{serial:07d}", behaviours, label)
    return Stage1Pipeline(host_id=host).run_scenario(scenario, offset=2 * serial)


# --- the corpus value ------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DiscoveryCorpus:
    """Every split's episodes, the raw Stage 1 results kept apart, and the derived trap."""

    arm: CorpusArm
    seed: int
    version: str
    splits: Mapping[Split, tuple[Episode, ...]]
    results: Mapping[str, ScenarioResult]
    trap_mechanism: Mechanism
    label_seed: int | None = None                        # NULL arm: the seed of its labels
    dropout_episode_ids: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        object.__setattr__(self, "arm", CorpusArm(self.arm))
        if not isinstance(self.trap_mechanism, Mechanism):
            raise ContractError("DiscoveryCorpus.trap_mechanism must be a Mechanism")
        splits = {Split(key): tuple(value) for key, value in self.splits.items()}
        for split, episodes in splits.items():
            if len(episodes) > MAX_SESSIONS_PER_SPLIT:
                raise ContractError(f"{split} holds {len(episodes)} > {MAX_SESSIONS_PER_SPLIT}")
            if any(not isinstance(e, Episode) or e.split is not split for e in episodes):
                raise ContractError(f"{split} holds an episode of another split")
        ids = [e.episode_id for episodes in splits.values() for e in episodes]
        if len(ids) != len(set(ids)):
            raise ContractError("an episode id appears twice: the splits leak into each other")
        if set(ids) - set(self.results):
            raise ContractError("every episode keeps its raw ScenarioResult")
        object.__setattr__(self, "splits", MappingProxyType(splits))
        object.__setattr__(self, "results", MappingProxyType(dict(self.results)))
        object.__setattr__(self, "dropout_episode_ids", frozenset(self.dropout_episode_ids))

    def episodes(self, split: Split) -> tuple[Episode, ...]:
        return self.splits.get(Split(split), ())

    def stats(self) -> dict[str, Any]:
        per_split = {str(s): len(e) for s, e in self.splits.items()}
        families = Counter(e.context.family or "INDEPENDENT"
                           for es in self.splits.values() for e in es)
        return {"arm": str(self.arm), "seed": self.seed, "label_seed": self.label_seed,
                "sessions": per_split, "families": dict(sorted(families.items())),
                "dropout_sessions": len(self.dropout_episode_ids), "cap": MAX_SESSIONS_PER_SPLIT}

    def memory_bytes(self) -> int:
        """Shallow ``sys.getsizeof`` sum over episodes, steps and feature tuples (a floor)."""
        total = 0
        for episodes in self.splits.values():
            for episode in episodes:
                total += sys.getsizeof(episode) + sys.getsizeof(episode.steps)
                total += sum(sys.getsizeof(s) + sys.getsizeof(s.features) for s in episode.steps)
        return total


def content_label(episode: Episode) -> int | None:
    """The lab truth of an episode's *content*: its family label, 0 for Stage 1 benign.

    Differs from ``episode.label`` only on the NULL arm, whose labels are noise by design.
    """
    family = episode.context.family
    if family in Family.__members__:
        return FAMILY_LABELS[Family(family)]
    if episode.context.corpus in (CORPUS_VERSION, HARD_CORPUS_VERSION):
        return 0
    return None


def planted_label(steps: Sequence[EncodedStep]) -> int:
    """1 iff some planted mechanism matches ``steps``: the lab oracle's whole definition.

    Valid on the natural splits (P3 measures that). It is NOT ground truth for the
    MONITORING_AGENT doppelgänger, which PM2 matches and which is benign by construction:
    that is exactly the case the grammar cannot separate (§4 D8.8).
    """
    if any(not isinstance(step, EncodedStep) for step in steps):
        raise ContractError("planted_label takes EncodedStep values")
    return int(any(m.matches(steps) for m in PLANTED_MECHANISMS.values()))


class LabOracle:
    """The authorised synthetic-world ground truth: ``planted_label``, charged per call."""

    def __init__(self, *, governor: ResearchGovernor) -> None:
        if not isinstance(governor, ResearchGovernor):
            raise ContractError("LabOracle needs the run's ResearchGovernor")
        self._governor = governor
        self._issued = 0

    @property
    def issued(self) -> int:
        """Labels this oracle has answered: its firing count."""
        return self._issued

    def label(self, episode: Episode) -> int:
        if not isinstance(episode, Episode):
            raise ContractError(f"LabOracle.label needs an Episode, got {type(episode).__name__}")
        # One predicate test per step per planted mechanism, paid before the work.
        self._governor.charge(LAB_ORACLE_COMPONENT, len(episode.steps) * len(PLANTED_MECHANISMS))
        self._issued += 1
        return planted_label(episode.steps)


# --- building -------------------------------------------------------------------------------


def _exact_counts(total: int) -> list[Family]:
    """Largest-remainder counts of ``FAMILY_MIX`` with every family present at least once."""
    raw = {f: FAMILY_MIX[f] * total for f in Family}
    counts = {f: int(raw[f]) for f in Family}
    order = sorted(Family, key=lambda f: (-(raw[f] - counts[f]), list(Family).index(f)))
    for family in order[: total - sum(counts.values())]:
        counts[family] += 1
    for family in Family:
        while counts[family] == 0:
            donor = max(Family, key=lambda f: counts[f])
            counts[donor] -= 1
            counts[family] += 1
    return [f for f in Family for _ in range(counts[f])]


def _context(split: Split, index: int, family: str, corpus: str) -> EpisodeContext:
    hosts = SPLIT_HOSTS[split]
    return EpisodeContext(host_id=hosts[index % len(hosts)], epoch_id=SPLIT_EPOCHS[split],
                          family=family, corpus=corpus, synthetic=True)


def _trapped(arm: CorpusArm, split: Split, family: Family, rng: random.Random) -> bool:
    if arm is CorpusArm.NULL:
        return False
    if split is Split.TRAIN:
        return FAMILY_LABELS[family] == 1
    return rng.random() < TRAP_PROBABILITY


def _natural_split(arm: CorpusArm, split: Split, count: int, seed: int,
                   results: dict[str, ScenarioResult]) -> list[Episode]:
    """Content streams (plan, variants) are independent of the trap stream, so the NULL arm
    renders the same sessions as PLANTED minus the trap prefix."""
    plan = _exact_counts(count)
    random.Random(f"{seed}:{split}:plan").shuffle(plan)
    trap_rng = random.Random(f"{seed}:{split}:trap")
    episodes: list[Episode] = []
    for index, family in enumerate(plan):
        serial = _SERIAL_BASE[split] + index
        behaviours = _behaviours(family, split, random.Random(f"{seed}:{split}:{index}"), serial)
        if _trapped(arm, split, family, trap_rng):
            behaviours = (TRAP_BEHAVIOUR, *behaviours)
        context = _context(split, index, family.value, DISCOVERY_CORPUS_VERSION)
        result = _render(behaviours, host=context.host_id, serial=serial,
                         label=FAMILY_LABELS[family])
        episode = episode_from_result(result, split=split, context=context,
                                      label=FAMILY_LABELS[family])
        results[episode.episode_id] = result
        episodes.append(episode)
    return episodes


def _independent_split(count: int, seed: int, results: dict[str, ScenarioResult]) -> list[Episode]:
    """Label-0 Stage 1 sessions (replay ``train`` and hard ``train``): the benign FP control."""
    half = count // 2
    sources = [(s, CORPUS_VERSION) for s in build_corpus(count=half, seed=seed, split="train")]
    sources += [(s, HARD_CORPUS_VERSION)
                for s in build_hard_corpus(count=count - half, seed=seed + 1, split="train")]
    episodes: list[Episode] = []
    for index, (scenario, version) in enumerate(s for s in sources if s[0].label == 0):
        serial = _SERIAL_BASE[Split.INDEPENDENT] + index
        context = _context(Split.INDEPENDENT, index, "", version)
        result = _render(scenario.behaviours, host=context.host_id, serial=serial, label=0)
        episode = episode_from_result(result, split=Split.INDEPENDENT, context=context, label=0)
        results[episode.episode_id] = result
        episodes.append(episode)
    return episodes


def _derive_trap_mechanism() -> Mechanism:
    """``SINGLE`` over the encoded trap step exactly as Stage 1 and Stage 6 encode it."""
    result = _render((TRAP_BEHAVIOUR,), host="lab-trap", serial=_TRAP_SERIAL, label=0)
    context = EpisodeContext(host_id="lab-trap", epoch_id=0, family="",
                             corpus=DISCOVERY_CORPUS_VERSION, synthetic=True)
    (step,) = episode_from_result(result, split=Split.CHALLENGE, context=context, label=None).steps
    predicate = StepPredicate(step.relation, step.object_property_mask, 0, step.state_delta_mask)
    return Mechanism(MechanismRelation.SINGLE, (predicate,))


def _null_labels(splits: Mapping[Split, Sequence[Episode]],
                 label_seed: int) -> dict[Split, tuple[Episode, ...]]:
    rng = random.Random(f"null-labels:{label_seed}")
    relabelled: dict[Split, tuple[Episode, ...]] = {}
    for split, episodes in splits.items():
        if split in NATURAL_SPLITS:
            episodes = [replace(e, label=int(rng.random() < NULL_BASE_RATE)) for e in episodes]
        relabelled[split] = tuple(episodes)
    return relabelled


def _apply_dropout(split: Split, episodes: list[Episode], seed: int,
                   results: dict[str, ScenarioResult], dropped: set[str]) -> list[Episode]:
    """Delete every EXECUTION-family step of half this split's DROP_EXEC_EGRESS sessions."""
    rng = random.Random(f"{seed}:{split}:dropout")
    indices = [i for i, e in enumerate(episodes) if e.context.family == Family.DROP_EXEC_EGRESS]
    chosen = set(rng.sample(indices, int(len(indices) * DROPOUT_SHARE)))
    spec = TransformSpec(TransformKind.SENSOR_DROPOUT, 1000, _EXECUTION_TARGET)
    out: list[Episode] = []
    for index, episode in enumerate(episodes):
        derived = apply_transform(episode, spec, rng=rng) if index in chosen else None
        if derived is not None:
            source = results[episode.episode_id]
            episode = Episode(episode_id="", steps=derived.steps, label=episode.label, split=split,
                              context=episode.context, truncated=episode.truncated)
            results[episode.episode_id] = source   # the raw evidence is the pre-loss session
            dropped.add(episode.episode_id)
        out.append(episode)
    return out


def _validated_counts(counts: Mapping[Split, int]) -> dict[Split, int]:
    out: dict[Split, int] = {}
    for split in (*NATURAL_SPLITS, Split.INDEPENDENT):
        value = counts.get(split, 0) if isinstance(counts, Mapping) else None
        low = len(Family) if split in NATURAL_SPLITS else 0
        if (isinstance(value, bool) or not isinstance(value, int)
                or not low <= value <= MAX_SESSIONS_PER_SPLIT):
            raise ContractError(f"count for {split} must be an int in [{low}, "
                                f"{MAX_SESSIONS_PER_SPLIT}], got {value!r}")
        out[split] = value
    return out


def build_discovery_corpus(*, arm: CorpusArm, seed: int,
                           counts: Mapping[Split, int] = DEFAULT_COUNTS) -> DiscoveryCorpus:
    """Render every split once through Stage 1 on fresh pipelines, deterministically."""
    try:
        arm = CorpusArm(arm)
    except ValueError as exc:
        raise ContractError(f"unknown CorpusArm {arm!r}") from exc
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ContractError(f"seed must be an int, got {seed!r}")
    sizes = _validated_counts(counts)
    results: dict[str, ScenarioResult] = {}
    dropped: set[str] = set()
    splits: dict[Split, tuple[Episode, ...]] = {}
    for split in NATURAL_SPLITS:
        episodes = _natural_split(arm, split, sizes[split], seed, results)
        if arm is CorpusArm.DROPOUT:
            episodes = _apply_dropout(split, episodes, seed, results, dropped)
        splits[split] = tuple(episodes)
    splits[Split.INDEPENDENT] = tuple(_independent_split(sizes[Split.INDEPENDENT], seed, results))
    label_seed = seed if arm is CorpusArm.NULL else None
    if label_seed is not None:
        splits = _null_labels(splits, label_seed)
    kept = {e.episode_id for es in splits.values() for e in es}
    return DiscoveryCorpus(arm=arm, seed=seed, version=DISCOVERY_CORPUS_VERSION, splits=splits,
                           results={k: v for k, v in results.items() if k in kept},
                           trap_mechanism=_derive_trap_mechanism(), label_seed=label_seed,
                           dropout_episode_ids=frozenset(dropped))


def relabel_null(corpus: DiscoveryCorpus, *, label_seed: int) -> DiscoveryCorpus:
    """New Bernoulli(``NULL_BASE_RATE``) labels on the same rendered content (NULL arm only)."""
    if not isinstance(corpus, DiscoveryCorpus) or corpus.arm is not CorpusArm.NULL:
        raise ContractError("relabel_null applies to a NULL-arm DiscoveryCorpus only")
    if isinstance(label_seed, bool) or not isinstance(label_seed, int):
        raise ContractError(f"label_seed must be an int, got {label_seed!r}")
    return replace(corpus, splits=_null_labels(corpus.splits, label_seed), label_seed=label_seed)


# --- doppelgängers ----------------------------------------------------------------------------


class CorpusDoppelgangers:
    """``DoppelgangerSource`` over this world: benign alternatives, label 0 by construction.

    ``family`` is a ``DoppelgangerFamily`` member or its NAME. Episodes are ``Split.CHALLENGE``
    on host ``lab-dop-01`` with the TRAIN/HOLDOUT variant and no trap. ``MONITORING_AGENT``
    exists only here, never in the natural splits.
    """

    def benign_alternatives(self, family: object, *, count: int, seed: int) -> tuple[Episode, ...]:
        name = str(getattr(family, "name", family))
        if name not in DOPPELGANGER_FAMILY_MAP:
            raise ContractError(f"unknown doppelgänger family {family!r}")
        for label, value in (("count", count), ("seed", seed)):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ContractError(f"{label} must be a non-negative int, got {value!r}")
        if count > MAX_DOPPELGANGERS:
            raise ContractError(f"count {count} exceeds MAX_DOPPELGANGERS={MAX_DOPPELGANGERS}")
        kind = list(DOPPELGANGER_FAMILY_MAP).index(name)
        block = (seed % 1000) * len(DOPPELGANGER_FAMILY_MAP) + kind
        first = _DOPPELGANGER_SERIAL + block * MAX_DOPPELGANGERS
        return tuple(self._one(name, first + index, random.Random(f"dop:{name}:{seed}:{index}"))
                     for index in range(count))

    @staticmethod
    def _one(name: str, serial: int, rng: random.Random) -> Episode:
        target = DOPPELGANGER_FAMILY_MAP[name]
        if target == MONITORING_AGENT:
            behaviours = _monitoring_agent(rng)
        elif target == "DPKG_PATTERN":
            behaviours = _DPKG
        else:
            behaviours = _behaviours(Family(target), Split.CHALLENGE, rng, serial)
        context = EpisodeContext(host_id="lab-dop-01", epoch_id=0, family=name,
                                 corpus=DISCOVERY_CORPUS_VERSION, synthetic=True)
        result = _render(behaviours, host=context.host_id, serial=serial, label=0)
        return episode_from_result(result, split=Split.CHALLENGE, context=context, label=0)


# --- preconditions P1-P5 ---------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PreconditionReport:
    """Whether this world is non-degenerate. Every figure is computed on content labels.

    ``planted_f1`` is each planted mechanism's HOLDOUT F1 on its contrast population (its
    family's sessions and every label-0 session), the population P2 compares on;
    ``planted_f1_all_labels`` is the same mechanism against every positive, reported so the
    difference is visible (one mechanism cannot recall another family's positives).
    """

    phi_oracle_holdout_ap: float | None
    best_single_step_holdout_f1: float | None
    planted_f1: tuple[tuple[str, float | None], ...]
    median_delta_phi: tuple[tuple[int, float], ...]
    pooled_logistic_holdout_ap: float | None
    session_unique: bool
    problems: tuple[str, ...]
    best_single_step: str | None = None                 # the DSL of the TRAIN-selected predicate
    planted_f1_all_labels: tuple[tuple[str, float | None], ...] = ()
    planted_label_disagreements: int = 0                # P3: natural sessions, dropout exempt
    independent_planted_matches: int = 0                # P3: INDEPENDENT sessions any PM matches
    #: A partial control for P5 (lesson 4): the same probe with the trap steps left out of
    #: every row. PARTIAL because the trap also shifts the next step's uncertainty and time
    #: bucket, and that residue stays; the exact control is the NULL arm's content, rendered
    #: without the trap, scored on content labels. Reported, never part of ``problems``.
    pooled_logistic_trap_stripped_holdout_ap: float | None = None


def _truth(episodes: Sequence[Episode]) -> list[Episode]:
    return [replace(e, label=content_label(e)) for e in episodes]


def _f1(mechanism: Mechanism, episodes: Sequence[Episode]) -> float | None:
    counts: FitCounts = fit_counts(lambda e: mechanism.matches(e.steps), episodes)
    return counts.f1


def _contrast(corpus: DiscoveryCorpus, split: Split, family: Family) -> list[Episode]:
    return _truth([e for e in corpus.episodes(split)
                   if e.context.family == family.value or content_label(e) == 0])


def _single_step_candidates(corpus: DiscoveryCorpus) -> list[Mechanism]:
    """Exhaustive single-step class over TRAIN: every observed (relation, masks) with every
    sub-mask, minus any predicate the trap step satisfies (P2: trap excluded)."""
    trap = corpus.trap_mechanism.steps[0]
    seen = {(s.relation, s.object_property_mask, s.state_delta_mask)
            for e in corpus.episodes(Split.TRAIN) for s in e.steps}
    out: set[tuple[int, int, int]] = set()
    for relation, props, raised in seen:
        for sub_p in _submasks(props):
            for sub_r in _submasks(raised):
                out.add((relation, sub_p, sub_r))
    mechanisms = []
    for relation, props, raised in sorted(out):
        if relation == trap.relation and props & trap.require_properties == props \
                and raised & trap.require_raised == raised:
            continue
        predicate = StepPredicate(relation, props, 0, raised)
        mechanisms.append(Mechanism(MechanismRelation.SINGLE, (predicate,)))
    return mechanisms


def _submasks(mask: int) -> list[int]:
    subs, sub = [], mask
    while True:
        subs.append(sub)
        if sub == 0:
            return subs
        sub = (sub - 1) & mask


def _p2(corpus: DiscoveryCorpus) -> tuple[float | None, str | None, float | None]:
    """(best single-step HOLDOUT F1, its DSL, PM1 HOLDOUT F1), selected on TRAIN."""
    family = Family.DROP_EXEC_EGRESS
    train = _contrast(corpus, Split.TRAIN, family)
    holdout = _contrast(corpus, Split.HOLDOUT, family)
    scored = [(_f1(m, train), m) for m in _single_step_candidates(corpus)]
    scored = [(f, m) for f, m in scored if f is not None]
    if not scored:
        return None, None, _f1(PLANTED_MECHANISMS[family], holdout)
    best = max(scored, key=lambda pair: (pair[0], -pair[1].description_length_bits()))[1]
    return _f1(best, holdout), best.to_dsl(), _f1(PLANTED_MECHANISMS[family], holdout)


def _p3(corpus: DiscoveryCorpus) -> tuple[list[str], int, int]:
    problems: list[str] = []
    disagreements = 0
    for split in NATURAL_SPLITS:
        for episode in corpus.episodes(split):
            if episode.episode_id in corpus.dropout_episode_ids:
                continue
            truth = content_label(episode)
            disagreements += planted_label(episode.steps) != truth
            for family, mechanism in PLANTED_MECHANISMS.items():
                own = episode.context.family == family.value
                if own != mechanism.matches(episode.steps) and (own or truth == 0):
                    problems.append(f"P3: {PLANTED_IDS[family]} {'misses' if own else 'matches'} "
                                    f"{episode.context.family} {episode.episode_id} in {split}")
    independent = sum(planted_label(e.steps) for e in corpus.episodes(Split.INDEPENDENT))
    if disagreements:
        problems.append(f"P3: planted_label disagrees with the family label on {disagreements}")
    if independent:
        problems.append(f"P3: a planted mechanism matches {independent} INDEPENDENT sessions")
    return problems[:32], disagreements, independent


def _p4(corpus: DiscoveryCorpus) -> tuple[bool, tuple[tuple[int, float], ...]]:
    owners: dict[str, str] = {}
    unique = True
    for episodes in corpus.splits.values():
        for episode in episodes:
            for group in {s.source_group for s in episode.steps}:
                unique &= owners.setdefault(group, episode.episode_id) == episode.episode_id
    peaks: dict[int, list[float]] = {}
    for split in NATURAL_SPLITS:
        for episode in corpus.episodes(split):
            peaks.setdefault(content_label(episode) or 0, []).append(
                max(s.delta_phi for s in episode.steps))
    medians = tuple((label, statistics.median(values)) for label, values in sorted(peaks.items()))
    return unique, medians


def _pooled(episode: Episode, skip: StepPredicate | None) -> list[float]:
    """Order-free pooling: per-feature max and mean over the steps (``skip`` ones left out)."""
    steps = [s for s in episode.steps if skip is None or not skip.matches(s)] or list(episode.steps)
    columns = list(zip(*(s.features for s in steps), strict=True))
    return [max(c) for c in columns] + [sum(c) / len(c) for c in columns]


def _p5(corpus: DiscoveryCorpus, *, strip_trap: bool) -> float | None:
    """Pooled LOGISTIC HOLDOUT AP. ``strip_trap`` is the isolating control: the trap steps
    are left out of every row, so the figure says what the content alone lets it do."""
    skip = corpus.trap_mechanism.steps[0] if strip_trap else None
    train, holdout = _truth(corpus.episodes(Split.TRAIN)), _truth(corpus.episodes(Split.HOLDOUT))
    try:
        probe = LogisticProbe().fit([_pooled(e, skip) for e in train],
                                    [int(e.label or 0) for e in train])
    except ValueError:
        return None  # a single-class TRAIN split cannot teach a probe (LogisticProbe refuses)
    scores = probe.predict([_pooled(e, skip) for e in holdout])
    return average_precision([int(e.label or 0) for e in holdout], scores)


def _checked(problems: list[str], name: str, value: float | None, ok: Callable[[float], bool],
             claim: str) -> None:
    if value is None:
        problems.append(f"{name}: unmeasurable ({claim})")
    elif not ok(value):
        problems.append(f"{name}: {value:.4f} violates {claim}")


def corpus_preconditions(corpus: DiscoveryCorpus) -> PreconditionReport:
    """P1-P5 of §4.19, on content labels; ``problems == ()`` only when all five hold."""
    if not isinstance(corpus, DiscoveryCorpus):
        raise ContractError("corpus_preconditions needs a DiscoveryCorpus")
    holdout = _truth(corpus.episodes(Split.HOLDOUT))
    phi_ap = average_precision([int(e.label or 0) for e in holdout],
                               [e.phi_oracle_score() for e in holdout]) if holdout else None
    best_f1, best_dsl, pm1_f1 = _p2(corpus)
    p3_problems, disagreements, independent = _p3(corpus)
    unique, medians = _p4(corpus)
    logistic_ap = _p5(corpus, strip_trap=False)
    problems: list[str] = []
    _checked(problems, "P1", phi_ap, lambda v: v <= P1_MAX_PHI_AP,
             f"phi-oracle HOLDOUT AP <= {P1_MAX_PHI_AP}")
    if best_f1 is None or pm1_f1 is None:
        problems.append("P2: unmeasurable (no scored single-step candidate or no PM1 F1)")
    elif best_f1 > pm1_f1 - P2_MARGIN:
        problems.append(f"P2: best single-step HOLDOUT F1 {best_f1:.4f} > "
                        f"PM1 {pm1_f1:.4f} - {P2_MARGIN}")
    problems.extend(p3_problems)
    if not unique:
        problems.append("P4: a source group appears in two sessions "
                        "(identities not session-unique)")
    if len(medians) != 2 or any(value == 0.0 for _, value in medians):
        problems.append(f"P4: median peak delta-phi per class must be non-zero, got {medians}")
    _checked(problems, "P5", logistic_ap, lambda v: v < P5_MAX_LOGISTIC_AP,
             f"pooled logistic HOLDOUT AP < {P5_MAX_LOGISTIC_AP}")
    planted = tuple((PLANTED_IDS[f], _f1(m, _contrast(corpus, Split.HOLDOUT, f)))
                    for f, m in PLANTED_MECHANISMS.items())
    everything = tuple((PLANTED_IDS[f], _f1(m, holdout)) for f, m in PLANTED_MECHANISMS.items())
    return PreconditionReport(
        phi_oracle_holdout_ap=phi_ap, best_single_step_holdout_f1=best_f1, planted_f1=planted,
        median_delta_phi=medians, pooled_logistic_holdout_ap=logistic_ap, session_unique=unique,
        problems=tuple(problems), best_single_step=best_dsl, planted_f1_all_labels=everything,
        planted_label_disagreements=disagreements, independent_planted_matches=independent,
        pooled_logistic_trap_stripped_holdout_ap=_p5(corpus, strip_trap=True),
    )
