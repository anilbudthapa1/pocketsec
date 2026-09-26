"""§4.19 — the SIMULATED fleet corpus: roles, hosts, episodes and privacy canaries.

Stage 7 needs a population of hosts that differ from one another, because a corpus in
which every host sees the same traffic cannot tell good aggregation from bad (M0.3/M0.4:
one motif transfers at recall 1.0 and FP 0 on both existing corpora). This generator
builds that population from Stage 1's own scenario vocabulary and nothing else —
``BENIGN_PATTERNS``, ``BENIGN_PRIVILEGED``, the four ``ATTACK_*`` chains, and three new
``Behaviour`` tuples that put deliberate **non-IID collisions** into the fleet:

* ``DESKTOP_WEB_CLIENT`` — benign external egress, the same operations as the tail of
  the exfiltration chains;
* ``ADMIN_CREDENTIAL_ROTATION`` — benign root read and write of ``/etc/shadow``;
* ``ADMIN_SERVICE_INSTALL`` — benign persistence with the same meaning as
  ``ATTACK_PERSISTENCE``. On half of the ADMIN hosts (``late_benign``) it appears only
  in the held-out half, which is what a latent-poison adversary targets: a local benign
  ring built from history cannot see it.

Roles cycle WEB, WEB, DEV, DESKTOP, WEB, ADMIN, so ADMIN is the rare role. Each host
sees 1–2 attack families in its history; its held-out half contains attacks from all
four, so "detection of a family this host never saw" is measurable per receiver.

**Two corpus traps are closed by construction, and checked by** :func:`fleet_preconditions`:

* Stage 1 carries lineage state across scenarios, so every run uses the session-unique
  offset ``host_index * 100000 + episode * 1000`` on a fresh pipeline per host (P2), and
  the median per-class peak |ΔΦ| is required non-zero for both classes (P1);
* a corpus is only worth sharing over if the representation can express the transfer:
  P3 forges a simple oracle motif on one host per family and replays it, with Stage 6's
  own ``match_motif``, on a same-role receiver.

**Privacy canaries.** Every path, user name and address field embeds a host canary
(``<path>.cnry-<host>-fs``, ``cnry-<host>-user``, ``10.<h>.<x>.<y>``) chosen so that the
Stage 1 compiler assigns exactly the same semantic properties as to the original field
(a test replays both and compares masks). ``raw_strings`` is the scan set: every
non-numeric field value used plus every canary. Pure-digit values (ports, uids, pids)
are excluded on purpose: they are identical across hosts, and a substring search for
``"0"`` or ``"443"`` matches any integer on the wire, so including them would make the
scan fail on noise rather than on leakage. ``raw_digests`` is every Stage 1 evidence
digest the corpus produced.

Everything here is synthetic and simulated: no real fleet, host or network exists, and
every fleet-level property measured on this corpus is UNMEASURED for a real deployment.
The oracle motif and the copied rule here are local helpers for the preconditions; the
forge's own ``copied_rule`` lives in ``antibody/forge.py`` and is not imported.
"""

from __future__ import annotations

import random
import statistics
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.epoch.model import SystemIdentity
from pocketsec.stage1.labs.corpus import (
    ATTACK_EXFIL,
    ATTACK_PERSISTENCE,
    ATTACK_UNSEEN_ESCAPE,
    ATTACK_UNSEEN_MEMORY,
    BENIGN_PATTERNS,
    BENIGN_PRIVILEGED,
    Behaviour,
    Scenario,
)
from pocketsec.stage1.pipeline import Stage1Pipeline
from pocketsec.stage1.ssir.transition import SSIRTransitionV1
from pocketsec.stage6.capsule.experience_capsule import EncodedStep
from pocketsec.stage6.memory.semantic import MotifStep, match_motif
from pocketsec.stage7.capsule.knowledge_capsule import RoleClass

__all__ = [
    "ADMIN_CREDENTIAL_ROTATION",
    "ADMIN_SERVICE_INSTALL",
    "ATTACK_EVERY",
    "DESKTOP_WEB_CLIENT",
    "FAMILY_CHAINS",
    "FLEET_CORPUS_VERSION",
    "MAX_FLEET_HOSTS",
    "ROLE_BENIGN",
    "ROLE_CYCLE",
    "AttackFamily",
    "FleetCorpus",
    "FleetEpisode",
    "HostSpec",
    "Precondition",
    "build_fleet_corpus",
    "fleet_preconditions",
    "median_peak_delta_phi",
    "oracle_motif",
    "raw_scan_set",
]

FLEET_CORPUS_VERSION = "stage7-fleet-corpus-v0.1.0"

#: Chosen, not measured. One episode in ATTACK_EVERY is an attack.
ATTACK_EVERY: int = 4
#: The second address octet carries the host index, so the fleet stops at 250 hosts.
MAX_FLEET_HOSTS: int = 250
#: Offsets are host*100000 + episode*1000; more than 99 episodes would collide.
_MAX_EPISODES: int = 99
_MIN_EPISODES: int = 2 * ATTACK_EVERY  # at least one attack in each half
_P3_MIN_RECALL: float = 0.9


class AttackFamily(StrEnum):
    EXFIL = "EXFIL"
    PERSIST = "PERSIST"
    MEMORY_THEFT = "MEMORY_THEFT"
    ESCAPE = "ESCAPE"


FAMILY_CHAINS: Mapping[AttackFamily, tuple[Behaviour, ...]] = MappingProxyType({
    AttackFamily.EXFIL: ATTACK_EXFIL,
    AttackFamily.PERSIST: ATTACK_PERSISTENCE,
    AttackFamily.MEMORY_THEFT: ATTACK_UNSEEN_MEMORY,
    AttackFamily.ESCAPE: ATTACK_UNSEEN_ESCAPE,
})
_FAMILIES: tuple[AttackFamily, ...] = tuple(AttackFamily)

#: Benign external egress (connect external :443, send).
DESKTOP_WEB_CLIENT: tuple[Behaviour, ...] = (
    Behaviour("connect", {"raddr": "198.51.100.80", "rport": "443"}),
    Behaviour("send", {"raddr": "198.51.100.80", "rport": "443"}),
)
#: Benign root credential maintenance: the same reads as the escape chain's tail.
ADMIN_CREDENTIAL_ROTATION: tuple[Behaviour, ...] = (
    Behaviour("setuid", {"target_uid": "0"}),
    Behaviour("read", {"path": "/etc/shadow"}),
    Behaviour("write", {"path": "/etc/shadow"}),
)
#: Benign persistence, the same meaning as ATTACK_PERSISTENCE. ``{canary}`` is the host's.
ADMIN_SERVICE_INSTALL: tuple[Behaviour, ...] = (
    Behaviour("setuid", {"target_uid": "0"}),
    Behaviour("write", {"path": "/etc/systemd/system/{canary}.service"}),
    Behaviour("execve", {"path": "/usr/bin/systemctl"}),
)

ROLE_CYCLE: tuple[RoleClass, ...] = (
    RoleClass.WEB, RoleClass.WEB, RoleClass.DEV, RoleClass.DESKTOP, RoleClass.WEB, RoleClass.ADMIN,
)
ROLE_BENIGN: Mapping[RoleClass, tuple[tuple[Behaviour, ...], ...]] = MappingProxyType({
    RoleClass.WEB: (BENIGN_PATTERNS[1], BENIGN_PATTERNS[4], BENIGN_PATTERNS[3]),
    RoleClass.DEV: (BENIGN_PATTERNS[0], BENIGN_PATTERNS[3], BENIGN_PATTERNS[4]),
    RoleClass.DESKTOP: (BENIGN_PATTERNS[2], BENIGN_PATTERNS[3], DESKTOP_WEB_CLIENT),
    RoleClass.ADMIN: (BENIGN_PRIVILEGED, BENIGN_PATTERNS[2], ADMIN_CREDENTIAL_ROTATION,
                      ADMIN_SERVICE_INSTALL),
})
#: P3 looks for a same-role source/receiver pair in this order (majority role first).
_P3_ROLE_ORDER: tuple[RoleClass, ...] = (
    RoleClass.WEB, RoleClass.DEV, RoleClass.DESKTOP, RoleClass.ADMIN,
)


@dataclass(frozen=True, slots=True)
class HostSpec:
    host_id: str
    role: RoleClass
    identity: SystemIdentity
    families_local: frozenset[AttackFamily]
    canaries: tuple[str, ...]
    late_benign: bool  # the role's rare benign behaviour appears only held-out


@dataclass(frozen=True, slots=True)
class FleetEpisode:
    host_id: str
    index: int
    steps: tuple[EncodedStep, ...]
    label: int
    family: AttackFamily | None
    evidence_digests: tuple[str, ...]
    history: bool  # True = first half (local history), False = held-out


@dataclass(frozen=True, slots=True)
class FleetCorpus:
    version: str
    seed: int
    hosts: tuple[HostSpec, ...]
    episodes: tuple[FleetEpisode, ...]
    raw_strings: frozenset[str]  # every non-numeric Behaviour field value used + every canary
    raw_digests: frozenset[str]  # every Stage 1 evidence sha256 digest produced

    def host(self, host_id: str) -> HostSpec:
        for spec in self.hosts:
            if spec.host_id == host_id:
                return spec
        raise KeyError(host_id)

    def for_host(self, host_id: str, *, history: bool) -> tuple[FleetEpisode, ...]:
        return tuple(e for e in self.episodes if e.host_id == host_id and e.history is history)

    def receivers(self) -> tuple[str, ...]:
        """Hosts whose history lacks at least two families (every host, by construction)."""
        return tuple(h.host_id for h in self.hosts if len(_FAMILIES) - len(h.families_local) >= 2)


@dataclass(frozen=True, slots=True)
class Precondition:
    name: str
    status: str  # "PASS" | "BLOCKED" | "DEGENERATE" | "DEGENERATE_IN_FAVOUR"
    detail: str


# --- canaries ----------------------------------------------------------------------


def _fs_canary(host_id: str) -> str:
    return f"cnry-{host_id}-fs"


def _canary_path(path: str, host_id: str) -> str:
    # A suffix keeps every prefix and substring Stage 1's classifier keys on
    # (/usr/bin/, /etc/shadow, /etc/systemd/), so the semantics are unchanged.
    if "{canary}" in path:
        return path.replace("{canary}", _fs_canary(host_id))
    return f"{path}.{_fs_canary(host_id)}"


def _canary_address(address: str, host_index: int) -> str:
    octets = address.split(".")
    if len(octets) != 4 or not all(o.isdigit() for o in octets):
        raise ContractError(f"fleet corpus addresses are dotted quads, got {address!r}")
    if octets[0] in {"172", "192", "169"}:
        # Re-writing the second octet of these could land in an RFC1918 / link-local
        # prefix and silently turn an external endpoint into a LAN one.
        raise ContractError(f"address {address!r} cannot carry a host canary safely")
    return f"{octets[0]}.{host_index}.{octets[2]}.{octets[3]}"


def _canary_behaviour(behaviour: Behaviour, host_id: str, host_index: int) -> Behaviour:
    fields = dict(behaviour.fields)
    if "path" in fields:
        fields["path"] = _canary_path(fields["path"], host_id)
    if "raddr" in fields:
        fields["raddr"] = _canary_address(fields["raddr"], host_index)
    # The acting user's name: Stage 1 reads it only as novelty context.
    fields["uid"] = f"cnry-{host_id}-user"
    return Behaviour(operation=behaviour.operation, fields=fields)


def _all_patterns() -> tuple[tuple[Behaviour, ...], ...]:
    benign = tuple(p for mix in ROLE_BENIGN.values() for p in mix)
    return (*benign, *FAMILY_CHAINS.values())


def _host_canaries(host_id: str, host_index: int, identity: SystemIdentity) -> tuple[str, ...]:
    addresses = sorted({
        _canary_address(b.fields["raddr"], host_index)
        for pattern in _all_patterns() for b in pattern if "raddr" in b.fields
    })
    return (host_id, _fs_canary(host_id), f"cnry-{host_id}-user", f"cnry-{host_id}-node",
            identity.service_digest, *addresses)


# --- hosts -------------------------------------------------------------------------


def _families_for(role_ordinal: int, rng: random.Random) -> frozenset[AttackFamily]:
    primary = _FAMILIES[role_ordinal % len(_FAMILIES)]
    if rng.random() < 0.5:
        return frozenset({primary})
    return frozenset({primary, _FAMILIES[(role_ordinal + 2) % len(_FAMILIES)]})


def _host_specs(hosts: int, rng: random.Random) -> tuple[HostSpec, ...]:
    ordinals: dict[RoleClass, int] = {}
    specs: list[HostSpec] = []
    for index in range(hosts):
        role = ROLE_CYCLE[index % len(ROLE_CYCLE)]
        ordinal = ordinals.get(role, 0)
        ordinals[role] = ordinal + 1
        host_id = f"h{index:03d}"
        identity = SystemIdentity(
            kernel_id="6.1.0-lab",
            package_digest=f"pkg-{role.value.lower()}-v1",  # hosts of one role share an image
            service_digest=f"svc-cnry-{host_id}",
        )
        specs.append(HostSpec(
            host_id=host_id, role=role, identity=identity,
            families_local=_families_for(ordinal, rng),
            canaries=_host_canaries(host_id, index, identity),
            # Every other ADMIN host, starting with the first, so even one ADMIN is late.
            late_benign=role is RoleClass.ADMIN and ordinal % 2 == 0,
        ))
    return tuple(specs)


# --- episodes ----------------------------------------------------------------------


def _encode(transitions: Sequence[SSIRTransitionV1]) -> tuple[EncodedStep, ...]:
    slots: dict[str, int] = {}
    return tuple(
        EncodedStep.from_transition(t, actor_slot=slots.setdefault(t.actor.identity, len(slots)))
        for t in transitions
    )


@dataclass(frozen=True, slots=True)
class _Plan:
    """What one episode is, before Stage 1 compiles it."""

    behaviours: tuple[Behaviour, ...]
    label: int
    family: AttackFamily | None


def _half_plans(spec: HostSpec, count: int, first: int, *, history: bool,
                rng: random.Random) -> list[_Plan]:
    mix = list(ROLE_BENIGN[spec.role])
    if spec.late_benign:
        mix.remove(ADMIN_SERVICE_INSTALL)
        if not history:
            mix.insert(0, ADMIN_SERVICE_INSTALL)  # first held-out benign episode is the rare one
    start = 0 if spec.late_benign and not history else rng.randrange(len(mix))
    families = sorted(spec.families_local) if history else list(_FAMILIES)
    turn = rng.randrange(len(families))
    plans: list[_Plan] = []
    benign_k = 0
    for index in range(first, first + count):
        if index % ATTACK_EVERY == ATTACK_EVERY - 1:
            family = families[turn % len(families)]
            turn += 1
            plans.append(_Plan(FAMILY_CHAINS[family], 1, family))
        else:
            plans.append(_Plan(mix[(start + benign_k) % len(mix)], 0, None))
            benign_k += 1
    return plans


def _host_episodes(spec: HostSpec, host_index: int, episodes_per_host: int,
                   rng: random.Random) -> tuple[list[FleetEpisode], set[str], set[str]]:
    half = episodes_per_host // 2
    plans = (_half_plans(spec, half, 0, history=True, rng=rng)
             + _half_plans(spec, episodes_per_host - half, half, history=False, rng=rng))
    pipeline = Stage1Pipeline(host_id=f"cnry-{spec.host_id}-node", identity=spec.identity)
    episodes: list[FleetEpisode] = []
    strings: set[str] = set()
    digests: set[str] = set()
    for index, plan in enumerate(plans):
        behaviours = tuple(_canary_behaviour(b, spec.host_id, host_index) for b in plan.behaviours)
        strings.update(v for b in behaviours for v in b.fields.values() if not v.isdigit())
        scenario = Scenario(
            name=f"{spec.host_id}-e{index:03d}", behaviours=behaviours, label=plan.label,
            technique=plan.family.value if plan.family else None,
        )
        # Session-unique offset: the MEMORY corpus trap (lineage state carried across runs).
        result = pipeline.run_scenario(scenario, offset=host_index * 100_000 + index * 1_000)
        evidence = tuple(dict.fromkeys(r.digest for t in result.transitions for r in t.evidence))
        digests.update(evidence)
        episodes.append(FleetEpisode(
            host_id=spec.host_id, index=index, steps=_encode(result.transitions),
            label=plan.label, family=plan.family, evidence_digests=evidence,
            history=index < half,
        ))
    return episodes, strings, digests


def build_fleet_corpus(*, hosts: int = 24, episodes_per_host: int = 40, seed: int = 7) -> FleetCorpus:
    """Compile a deterministic simulated fleet through Stage 1 and Stage 6's step encoder."""
    if isinstance(hosts, bool) or not isinstance(hosts, int) or not 1 <= hosts <= MAX_FLEET_HOSTS:
        raise ContractError(f"hosts must be an int in 1..{MAX_FLEET_HOSTS}, got {hosts!r}")
    if (isinstance(episodes_per_host, bool) or not isinstance(episodes_per_host, int)
            or not _MIN_EPISODES <= episodes_per_host <= _MAX_EPISODES):
        raise ContractError(
            f"episodes_per_host must be an int in {_MIN_EPISODES}..{_MAX_EPISODES}, "
            f"got {episodes_per_host!r}"
        )
    rng = random.Random(seed)
    specs = _host_specs(hosts, rng)
    episodes: list[FleetEpisode] = []
    strings: set[str] = set()
    digests: set[str] = set()
    for index, spec in enumerate(specs):
        built, used, produced = _host_episodes(spec, index, episodes_per_host,
                                               random.Random(seed * 1_000_003 + index))
        episodes.extend(built)
        strings.update(used, spec.canaries)
        digests.update(produced)
    return FleetCorpus(
        version=FLEET_CORPUS_VERSION, seed=seed, hosts=specs, episodes=tuple(episodes),
        raw_strings=frozenset(strings), raw_digests=frozenset(digests),
    )


# --- preconditions -------------------------------------------------------------------


def _escalating(step: EncodedStep) -> bool:
    return bool(step.state_delta_mask) or bool(step.object_property_mask)


def oracle_motif(steps: Sequence[EncodedStep]) -> tuple[MotifStep, ...] | None:
    """A rule copied from one incident: first and last escalating step of its most
    escalating actor, full masks, no minimisation. None = nothing escalates.

    A local precondition helper (the forge's ``copied_rule`` is the control the suite
    uses); it exists so P3/P4 can be settled without depending on another package.
    """
    per_actor: dict[int, list[EncodedStep]] = {}
    for step in steps:
        if _escalating(step):
            per_actor.setdefault(step.actor_slot, []).append(step)
    if not per_actor:
        return None
    slot = max(sorted(per_actor), key=lambda s: len(per_actor[s]))
    chosen = per_actor[slot]
    ends = (chosen[0],) if len(chosen) == 1 else (chosen[0], chosen[-1])
    return tuple(
        MotifStep(relation=s.relation, require_properties=s.object_property_mask,
                  forbid_properties=0, require_raised=s.state_delta_mask)
        for s in ends
    )


def median_peak_delta_phi(corpus: FleetCorpus) -> dict[int, float]:
    """Median per-episode peak |ΔΦ| per label; 0.00 is the identity-reuse signature."""
    peaks: dict[int, list[float]] = {}
    for episode in corpus.episodes:
        peak = max((abs(s.delta_phi) for s in episode.steps), default=0.0)
        peaks.setdefault(episode.label, []).append(peak)
    return {label: statistics.median(values) for label, values in sorted(peaks.items())}


def _p1(corpus: FleetCorpus) -> Precondition:
    medians = median_peak_delta_phi(corpus)
    ok = set(medians) == {0, 1} and all(v > 0.0 for v in medians.values())
    return Precondition("P1", "PASS" if ok else "BLOCKED",
                        f"median peak |dPhi| per class {medians}")


def _p2(corpus: FleetCorpus) -> Precondition:
    owner: dict[str, tuple[str, int]] = {}
    shared = 0
    for episode in corpus.episodes:
        for group in {s.source_group for s in episode.steps}:
            prior = owner.setdefault(group, (episode.host_id, episode.index))
            if prior != (episode.host_id, episode.index):
                shared += 1
    return Precondition("P2", "PASS" if shared == 0 else "BLOCKED",
                        f"{len(owner)} actor identities, {shared} reused across episodes")


def _pair_for(corpus: FleetCorpus,
              family: AttackFamily) -> tuple[HostSpec, tuple[HostSpec, ...]] | None:
    """The first source of ``family`` in role order, and EVERY other host of its role.

    Pooling over all same-role receivers keeps the recall denominator from being the one
    or two held-out episodes a single receiver happens to hold.
    """
    for role in _P3_ROLE_ORDER:
        members = [h for h in corpus.hosts if h.role is role]
        sources = [h for h in members if family in h.families_local]
        if sources and len(members) > 1:
            source = sources[0]
            return source, tuple(h for h in members if h.host_id != source.host_id)
    return None


def _transfer(corpus: FleetCorpus, family: AttackFamily) -> tuple[str, float, int, str]:
    """(status, recall, fp, detail) of an oracle motif moved to every same-role receiver."""
    pair = _pair_for(corpus, family)
    if pair is None:
        return "UNEVALUABLE", 0.0, 0, f"{family.value}: no same-role source/receiver pair"
    source, receivers = pair
    incidents = [e for e in corpus.for_host(source.host_id, history=True) if e.family is family]
    motif = oracle_motif(incidents[0].steps) if incidents else None
    if motif is None:
        return "UNEVALUABLE", 0.0, 0, f"{family.value}: no escalating incident on {source.host_id}"
    names = {h.host_id for h in receivers}
    attacks = [e for e in corpus.episodes
               if e.host_id in names and not e.history and e.family is family]
    benign = [e for e in corpus.episodes if e.host_id in names and e.label == 0]
    hits = sum(1 for e in attacks if match_motif(motif, e.steps))
    fp = sum(1 for e in benign if match_motif(motif, e.steps))
    if not attacks:
        return "UNEVALUABLE", 0.0, fp, f"{family.value}: no held-out {family.value} on receivers"
    recall = hits / len(attacks)
    ok = recall >= _P3_MIN_RECALL and fp == 0
    detail = (f"{family.value} {source.role.value} {source.host_id}->{len(receivers)} receivers: "
              f"recall {hits}/{len(attacks)}, FP {fp}/{len(benign)}")
    return ("OK" if ok else "FAIL"), recall, fp, detail


def _p3_p5(corpus: FleetCorpus) -> tuple[Precondition, Precondition]:
    rows = [_transfer(corpus, family) for family in _FAMILIES]
    detail = "; ".join(row[3] for row in rows)
    p3_ok = all(row[0] == "OK" for row in rows)
    p3 = Precondition("P3", "PASS" if p3_ok else "BLOCKED", detail)
    if any(row[0] == "UNEVALUABLE" for row in rows):
        return p3, Precondition("P5", "BLOCKED", "P3 could not be evaluated for every family")
    saturated = all(row[1] == 1.0 and row[2] == 0 for row in rows)
    p5 = Precondition(
        "P5", "DEGENERATE_IN_FAVOUR" if saturated else "PASS",
        "oracle transfer is 1.0 recall / 0 FP for every family: detection gains are "
        "flagged DEGENERATE_IN_FAVOUR" if saturated else "oracle transfer is not saturated",
    )
    return p3, p5


def _p4(corpus: FleetCorpus) -> Precondition:
    web = [h for h in corpus.hosts if h.role is RoleClass.WEB
           and AttackFamily.PERSIST in h.families_local]
    admins = {h.host_id for h in corpus.hosts if h.role is RoleClass.ADMIN}
    if not web or not admins:
        return Precondition("P4", "DEGENERATE",
                            f"no WEB PERSIST source ({len(web)}) or no ADMIN host ({len(admins)})")
    incidents = [e for e in corpus.for_host(web[0].host_id, history=True)
                 if e.family is AttackFamily.PERSIST]
    motif = oracle_motif(incidents[0].steps) if incidents else None
    if motif is None:
        return Precondition("P4", "DEGENERATE", f"no escalating PERSIST incident on {web[0].host_id}")
    benign = [e for e in corpus.episodes if e.host_id in admins and e.label == 0]
    hits = sum(1 for e in benign if match_motif(motif, e.steps))
    return Precondition(
        "P4", "PASS" if hits else "DEGENERATE",
        f"WEB {web[0].host_id} PERSIST copied rule matches {hits}/{len(benign)} ADMIN benign episodes",
    )


def fleet_preconditions(corpus: FleetCorpus) -> tuple[Precondition, ...]:
    """P1–P5 of §4.19, in order. G7.11 and the suite refuse to run past a BLOCKED one."""
    if not isinstance(corpus, FleetCorpus):
        raise ContractError("fleet_preconditions needs a FleetCorpus")
    p3, p5 = _p3_p5(corpus)
    return (_p1(corpus), _p2(corpus), p3, _p4(corpus), p5)


def raw_scan_set(corpus: FleetCorpus) -> frozenset[str]:
    """Everything a privacy scan must not find in exported bytes: strings and digests."""
    return corpus.raw_strings | corpus.raw_digests
