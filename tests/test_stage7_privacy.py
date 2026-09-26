"""Stage 7 package `privacy`: D7.2 compiler, D7.3 distiller + ledger, §4.19 fleet corpus.

Every test here exercises behaviour or a refusal. The privacy tests always carry a
positive control (a representation that DOES leak, and the scan finding it), because a
scan that finds nothing is only evidence when it demonstrably can find something.
"""

from __future__ import annotations

import json
import math
import random
import statistics
from collections import Counter

import pytest

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.labs.corpus import Behaviour, Scenario
from pocketsec.stage1.pipeline import Stage1Pipeline
from pocketsec.stage1.ssir.relations import Relation
from pocketsec.stage6.capsule.experience_capsule import EncodedStep, PrivacyClass
from pocketsec.stage6.export.learning_record import LearningRecordV1
from pocketsec.stage6.memory.semantic import match_motif
from pocketsec.stage7.capsule import compiler
from pocketsec.stage7.capsule.compiler import (
    ExportContext,
    compile_capsule,
    invariants_from_learning_record,
)
from pocketsec.stage7.capsule.knowledge_capsule import (
    COUNTER_HYPOTHESIS_VALUES,
    MAX_EVIDENCE_COMMITMENTS,
    FalsificationSummary,
    KnowledgeCapsuleV1,
    KnowledgeType,
    MotifRow,
    ObservabilityClaim,
    RevocationGround,
    RoleClass,
    Stance,
    ValidationSummary,
    VisibilityClass,
)
from pocketsec.stage7.labs.fleet_corpus import (
    ADMIN_SERVICE_INSTALL,
    FLEET_CORPUS_VERSION,
    AttackFamily,
    FleetCorpus,
    FleetEpisode,
    _canary_behaviour,
    build_fleet_corpus,
    fleet_preconditions,
    median_peak_delta_phi,
    oracle_motif,
    raw_scan_set,
)
from pocketsec.stage7.privacy.distiller import (
    EXPORT_FIELD_TABLE,
    Disclosure,
    audit_payload,
    canary_hit_count,
    canary_hits,
    contributor_pseudonym,
    distil_context,
    evidence_commitment,
    expected_wire_paths,
    family_profile,
    flatten_keys,
    residual_identifier_hits,
    software_epoch_class,
    undeclared_wire_paths,
)
from pocketsec.stage7.privacy.ledger import (
    MAX_INFERENCE_TESTS,
    NOVELTY_COUNTS,
    PrivacyBudgetExhausted,
    PrivacyLedger,
    geometric_noise,
    release_counts,
)

SECRET = bytes(range(32))
ROOT = "root-" + "a1" * 8
KEY_ID = "key-" + "b2" * 8
SCOPE = "fleet-lab"


@pytest.fixture(scope="module")
def corpus() -> FleetCorpus:
    return build_fleet_corpus(hosts=8, episodes_per_host=40, seed=7)


def _context(corpus: FleetCorpus, host_id: str, *, secret: bytes = SECRET) -> ExportContext:
    spec = corpus.host(host_id)
    counts = Counter(s.relation_family for e in corpus.for_host(host_id, history=True) for s in e.steps)
    return ExportContext(
        host_secret=secret, identity=spec.identity, role=spec.role, provenance_root=ROOT,
        key_id=KEY_ID, visibility_share=0.95, family_counts=dict(counts), fleet_scope=SCOPE,
    )


def _summaries() -> tuple[ValidationSummary, FalsificationSummary]:
    return (ValidationSummary(episodes_replayed=12, true_matches=3, false_matches=0),
            FalsificationSummary(mutations_tried=8, mutations_survived=8,
                                 counter_hypotheses=COUNTER_HYPOTHESIS_VALUES[:2]))


def _incident(corpus: FleetCorpus) -> FleetEpisode:
    return next(e for e in corpus.episodes if e.label == 1 and e.history)


def _invariant(episode: FleetEpisode) -> tuple[MotifRow, ...]:
    motif = oracle_motif(episode.steps)
    assert motif is not None
    return tuple(MotifRow.from_motif_step(step) for step in motif)


def _compile(corpus: FleetCorpus, kind: KnowledgeType, ledger: PrivacyLedger, *,
             sequence: int = 1, **extra: object) -> KnowledgeCapsuleV1:
    incident = _incident(corpus)
    validation, falsification = _summaries()
    invariant = () if kind is KnowledgeType.REVOCATION else _invariant(incident)
    type_fields: dict[str, object] = {}
    if kind in (KnowledgeType.CAMPAIGN_FRAGMENT, KnowledgeType.NEGATIVE_EVIDENCE):
        type_fields["time_window"] = (1, 3)
    if kind is KnowledgeType.NEGATIVE_EVIDENCE:
        type_fields["observability"] = ObservabilityClaim(0.9, 1.0, 0.5)
    if kind is KnowledgeType.REVOCATION:
        type_fields["revocation_target"] = "kc-" + "c3" * 12
        type_fields["revocation_ground"] = RevocationGround.SELF_RETRACTION
    type_fields.update(extra)
    return compile_capsule(
        knowledge_type=kind, invariant=invariant,
        evidence_digests=incident.evidence_digests[:MAX_EVIDENCE_COMMITMENTS],
        validation=validation, falsification=falsification,
        context=_context(corpus, incident.host_id), ledger=ledger,
        created_round=2, sequence=sequence, **type_fields,  # type: ignore[arg-type]
    )


# --- D7.3 distiller: the field table ------------------------------------------------


def test_export_field_table_is_exactly_the_wire_keys(corpus: FleetCorpus) -> None:
    ledger = PrivacyLedger()
    emitted: set[str] = set()
    for kind in KnowledgeType:
        payload = _compile(corpus, kind, ledger).to_dict()
        keys = set(flatten_keys(payload))
        assert undeclared_wire_paths(payload) == (), kind
        assert keys == expected_wire_paths(payload), kind
        emitted |= keys
    # No stale declaration: every table row is emitted by some knowledge type.
    assert emitted == set(EXPORT_FIELD_TABLE)
    # The only per-type difference is the null observability record.
    antibody = _compile(corpus, KnowledgeType.ANTIBODY, ledger, sequence=2).to_dict()
    missing = set(EXPORT_FIELD_TABLE) - set(flatten_keys(antibody))
    assert missing == {"observability.expected_observability", "observability.sensor_health",
                       "observability.temporal_coverage"}
    assert all(isinstance(row.disclosure, Disclosure) for row in EXPORT_FIELD_TABLE.values())


def test_an_undeclared_field_is_named() -> None:
    payload = {"capsule_id": "kc-" + "0" * 24, "host": {"path": "/etc/shadow"}}
    assert undeclared_wire_paths(payload) == ("host.path",)


def test_flatten_keys_list_items_share_the_parent_path() -> None:
    payload = {"a": [1, 2], "b": {"c": [], "d": None}, "e": [{"f": 1}, {"g": 2}], "h": {}}
    assert flatten_keys(payload) == ("a", "b.c", "b.d", "e.f", "e.g", "h")
    with pytest.raises(ContractError):
        flatten_keys({"": 1})
    with pytest.raises(ContractError):
        flatten_keys([1])  # type: ignore[arg-type]


# --- D7.3 distiller: generalisation ---------------------------------------------------


def test_distil_context_levels_and_refusals(corpus: FleetCorpus) -> None:
    identity = corpus.hosts[0].identity
    epoch, sketch = distil_context(identity=identity, role=RoleClass.WEB,
                                   visibility_share=0.9, family_counts={0: 5, 1: 45, 2: 50})
    assert epoch.visibility is VisibilityClass.FULL
    assert epoch.software_epoch == software_epoch_class(identity)
    assert sketch.family_profile == (1, 3, 3, 0, 0, 0, 0, 0)
    for share, level in ((0.8999, VisibilityClass.PARTIAL), (0.5, VisibilityClass.PARTIAL),
                         (0.4999, VisibilityClass.LOW)):
        assert distil_context(identity=identity, role=RoleClass.WEB, visibility_share=share,
                              family_counts={})[0].visibility is level
    # Level edges: 0 | (0, 0.1] | (0.1, 0.4] | > 0.4
    assert family_profile({0: 1, 1: 9}) == (1, 3, 0, 0, 0, 0, 0, 0)
    assert family_profile({0: 2, 1: 3, 2: 5}) == (2, 2, 3, 0, 0, 0, 0, 0)
    assert family_profile({}) == (0,) * 8
    for bad in ({8: 1}, {-1: 1}, {0: -1}, {True: 1}, {0: 1.5}):
        with pytest.raises(ContractError):
            family_profile(bad)  # type: ignore[arg-type]
    for share in (-0.1, 1.1, float("nan")):
        with pytest.raises(ContractError):
            distil_context(identity=identity, role=RoleClass.WEB, visibility_share=share,
                           family_counts={})


def test_software_epoch_is_linkable_only_through_the_image(corpus: FleetCorpus) -> None:
    web = [h for h in corpus.hosts if h.role is RoleClass.WEB]
    admin = next(h for h in corpus.hosts if h.role is RoleClass.ADMIN)
    # Declared linkability: two hosts sharing an image share the class.
    assert software_epoch_class(web[0].identity) == software_epoch_class(web[1].identity)
    assert software_epoch_class(web[0].identity) != software_epoch_class(admin.identity)
    # The per-host service digest is not part of it, so it never reaches the wire.
    assert web[0].identity.service_digest != web[1].identity.service_digest


def test_pseudonym_is_scoped_and_keyed() -> None:
    first = contributor_pseudonym(SECRET, "scope-a")
    assert first == contributor_pseudonym(SECRET, "scope-a")
    assert first != contributor_pseudonym(SECRET, "scope-b")
    assert first != contributor_pseudonym(bytes(32), "scope-a")
    assert first.startswith("peer-") and len(first) == len("peer-") + 16
    with pytest.raises(ContractError):
        contributor_pseudonym(b"short", "scope-a")
    with pytest.raises(ContractError):
        contributor_pseudonym(SECRET, "")


# --- D7.3 distiller: the residual screen and canaries ---------------------------------


def test_residual_screen_catches_every_host_string_shape(corpus: FleetCorpus) -> None:
    clean = _compile(corpus, KnowledgeType.ANTIBODY, PrivacyLedger()).to_dict()
    assert residual_identifier_hits(clean) == ()
    digest = next(iter(corpus.raw_digests))
    planted = {
        "path": "/etc/shadow.cnry-h000-fs", "addr": "10.3.0.5", "digest": digest,
        "cap": "cap-" + "0" * 24, "grp": "grp-" + "0" * 16, "user": "cnry-h000-user",
        "words": ["password"], "blob": b"raw", "nan": float("nan"),
    }
    hits = residual_identifier_hits({**clean, "smuggled": planted})
    for name in ("path", "addr", "digest", "cap", "grp", "user", "words[0]", "blob", "nan"):
        assert any(f"capsule.smuggled.{name}" in hit for hit in hits), name


def test_canary_scan_is_bounded_and_refuses_empty_canaries() -> None:
    blob = b"alpha beta gamma"
    assert canary_hits(blob, ["beta", "delta"]) == ("beta",)
    assert canary_hit_count(blob, ["alpha", "beta", "delta"]) == 2
    many = [f"c{i:03d}" for i in range(100)]
    assert len(canary_hits(" ".join(many).encode(), many)) == 32
    assert canary_hit_count(" ".join(many).encode(), many) == 100
    with pytest.raises(ContractError):
        canary_hits(blob, [""])
    with pytest.raises(ContractError):
        canary_hits("text", ["a"])  # type: ignore[arg-type]


def test_no_raw_fleet_string_survives_export(corpus: FleetCorpus) -> None:
    scan = raw_scan_set(corpus)
    ledger = PrivacyLedger()
    exported: list[bytes] = []
    raw_control: list[bytes] = []
    incidents = [e for e in corpus.episodes if e.label == 1 and e.history]
    for sequence, incident in enumerate(incidents, start=1):
        capsule = compile_capsule(
            knowledge_type=KnowledgeType.ANTIBODY, invariant=_invariant(incident),
            evidence_digests=incident.evidence_digests[:MAX_EVIDENCE_COMMITMENTS],
            validation=_summaries()[0], falsification=_summaries()[1],
            context=_context(corpus, incident.host_id, secret=incident.host_id.encode() * 8),
            ledger=ledger, created_round=1, sequence=sequence,
        )
        exported.append(capsule.canonical_bytes())
        # The control: Stage 6's own fleet item (raw EncodedStep dicts) for the same incident.
        raw_control.append(json.dumps([s.to_dict() for s in incident.steps]).encode())
        assert audit_payload(capsule.to_dict(), canaries=scan).clean
    assert len(exported) >= len(corpus.hosts)  # non-vacuous: every host exported
    assert {e.host_id for e in incidents} == {h.host_id for h in corpus.hosts}
    assert canary_hit_count(b"\n".join(exported), scan) == 0
    assert canary_hit_count(b"\n".join(raw_control), scan) > 0  # the scan can fire
    # Every host's canaries are in the scan set, and the scan finds a planted one.
    for spec in corpus.hosts:
        assert set(spec.canaries) <= corpus.raw_strings
    assert canary_hits(exported[0] + corpus.hosts[0].canaries[1].encode(), scan)


def test_raw_digests_become_commitments(corpus: FleetCorpus) -> None:
    incident = _incident(corpus)
    digests = incident.evidence_digests[:MAX_EVIDENCE_COMMITMENTS]
    capsule = _compile(corpus, KnowledgeType.ANTIBODY, PrivacyLedger())
    commitments = capsule.provenance_commitment.evidence_commitments
    assert commitments == tuple(evidence_commitment(SECRET, d) for d in digests)
    blob = capsule.canonical_bytes()
    assert b"sha256:" not in blob
    assert not any(d.encode() in blob or d[7:].encode() in blob for d in digests)
    # A peer guessing a digest cannot test it without the secret.
    assert evidence_commitment(bytes(32), digests[0]) not in commitments
    for bad in ("/etc/shadow", "sha256:" + "A" * 64, "sha256:" + "0" * 63, "", None):
        with pytest.raises(ContractError):
            evidence_commitment(SECRET, bad)  # type: ignore[arg-type]
    ctx = _context(corpus, incident.host_id)
    validation, falsification = _summaries()
    base = dict(knowledge_type=KnowledgeType.ANTIBODY, invariant=_invariant(incident),
                validation=validation, falsification=falsification, context=ctx,
                created_round=1, sequence=1)
    too_many = tuple(f"sha256:{i:064x}" for i in range(MAX_EVIDENCE_COMMITMENTS + 1))
    for evidence in ((), too_many, ("/var/log/auth.log",), "sha256:" + "0" * 64):
        with pytest.raises(ContractError):
            compile_capsule(evidence_digests=evidence, ledger=PrivacyLedger(), **base)  # type: ignore[arg-type]


def test_export_context_refuses_bad_input_and_hides_the_secret(corpus: FleetCorpus) -> None:
    ctx = _context(corpus, "h000")
    assert SECRET.hex() not in repr(ctx) and str(SECRET) not in repr(ctx)
    good = dict(host_secret=SECRET, identity=ctx.identity, role=RoleClass.WEB,
                provenance_root=ROOT, key_id=KEY_ID, visibility_share=1.0,
                family_counts={}, fleet_scope=SCOPE)
    for field, bad in (("host_secret", b"x" * 15), ("role", "WEB"), ("provenance_root", "root-XYZ"),
                       ("key_id", "key-" + "0" * 15), ("visibility_share", 1.5),
                       ("fleet_scope", "has space"), ("family_counts", [1, 2])):
        with pytest.raises(ContractError):
            ExportContext(**{**good, field: bad})  # type: ignore[arg-type]
    source = {0: 1}
    frozen = ExportContext(**{**good, "family_counts": source})  # type: ignore[arg-type]
    source[0] = 99
    assert frozen.family_counts[0] == 1  # no aliasing of caller state


def test_compiler_screen_is_wired(corpus: FleetCorpus, monkeypatch: pytest.MonkeyPatch) -> None:
    # The schema already refuses non-wire strings, so the compiler's own screen is
    # defence in depth; this proves it runs and refuses rather than exports.
    monkeypatch.setattr(compiler, "residual_identifier_hits", lambda payload: ("capsule.x: planted",))
    ledger = PrivacyLedger()
    with pytest.raises(ContractError, match="residual"):
        _compile(corpus, KnowledgeType.ANTIBODY, ledger)
    # Charged before sealing: a refused capsule still consumed a release (over-count, never under).
    assert [e.release_count for e in ledger.entries()] == [1]


# --- D7.2 compiler --------------------------------------------------------------------


def test_every_knowledge_type_compiles_unsigned_and_is_charged(corpus: FleetCorpus) -> None:
    ledger = PrivacyLedger()
    for sequence, kind in enumerate(KnowledgeType, start=1):
        capsule = _compile(corpus, kind, ledger, sequence=sequence)
        assert capsule.signature == ""
        assert capsule.privacy_class is PrivacyClass.PUBLIC_DERIVED
        assert capsule.independence_group == ROOT == capsule.provenance_commitment.provenance_root
        assert KnowledgeCapsuleV1.from_bytes(capsule.canonical_bytes()) == capsule
    assert {e.representation_type for e in ledger.entries()} == {k.value for k in KnowledgeType}
    assert all(e.dp_epsilon is None and e.dp_delta is None for e in ledger.entries())
    contest = _compile(corpus, KnowledgeType.ANTIBODY, ledger, sequence=9, stance=Stance.CONTEST)
    assert contest.stance is Stance.CONTEST
    with pytest.raises(ContractError):
        _compile(corpus, KnowledgeType.NOVELTY, ledger, sequence=10, stance=Stance.CONTEST)


def test_budget_exhaustion_refuses_before_producing(corpus: FleetCorpus) -> None:
    ledger = PrivacyLedger(max_releases=2)
    produced = [_compile(corpus, KnowledgeType.ANTIBODY, ledger, sequence=i) for i in (1, 2)]
    assert len(produced) == 2
    with pytest.raises(PrivacyBudgetExhausted):
        _compile(corpus, KnowledgeType.ANTIBODY, ledger, sequence=3)
    assert ledger.refusals() == 1
    assert sum(e.release_count for e in ledger.entries()) == 2  # the refused one left no row
    # The epsilon budget refuses a count release before any count is produced.
    eps_ledger = PrivacyLedger(epsilon_budget=4.0)
    for rnd in (0, 1):
        release_counts({"p": 3}, epsilon=1.5, ledger=eps_ledger, recipient_scope=SCOPE,
                       round_index=rnd, rng=random.Random(rnd))
    with pytest.raises(PrivacyBudgetExhausted):
        release_counts({"p": 3}, epsilon=1.5, ledger=eps_ledger, recipient_scope=SCOPE,
                       round_index=2, rng=random.Random(2))


def test_budget_window_slides_and_rounds_only_move_forward() -> None:
    ledger = PrivacyLedger(epsilon_budget=2.0, window_rounds=8)
    ledger.charge(NOVELTY_COUNTS, recipient_scope=SCOPE, round_index=7, epsilon=2.0)
    # A tumbling window would reset at round 8; the sliding window does not.
    with pytest.raises(PrivacyBudgetExhausted):
        ledger.charge(NOVELTY_COUNTS, recipient_scope=SCOPE, round_index=8, epsilon=0.5)
    # A different scope does not get a fresh budget: scopes may collude.
    with pytest.raises(PrivacyBudgetExhausted):
        ledger.charge(NOVELTY_COUNTS, recipient_scope="other-scope", round_index=14, epsilon=0.5)
    entry = ledger.charge(NOVELTY_COUNTS, recipient_scope=SCOPE, round_index=15, epsilon=2.0)
    assert entry.expiry_round == 16 and entry.dp_epsilon == 2.0
    with pytest.raises(ContractError):
        ledger.charge(NOVELTY_COUNTS, recipient_scope=SCOPE, round_index=3)
    for bad in (0.0, -1.0, float("inf"), float("nan"), True):
        with pytest.raises(ContractError):
            ledger.charge(NOVELTY_COUNTS, recipient_scope=SCOPE, round_index=20, epsilon=bad)
    with pytest.raises(ContractError):
        ledger.charge("RAW_TELEMETRY", recipient_scope=SCOPE, round_index=20)


def test_ledger_is_bounded_and_eviction_never_frees_budget() -> None:
    ledger = PrivacyLedger(capacity=3, max_releases=5, window_rounds=64)
    for index in range(5):
        ledger.charge(NOVELTY_COUNTS, recipient_scope=f"scope-{index}", round_index=index)
    assert len(ledger.entries()) == 3 and ledger.evictions() == 2
    with pytest.raises(PrivacyBudgetExhausted):  # 5 releases still counted in the window
        ledger.charge(NOVELTY_COUNTS, recipient_scope="scope-9", round_index=6)
    assert 0 < ledger.memory_bytes() < 4096
    flood = PrivacyLedger()
    for rnd in range(0, 64 * 40, 5):  # a long run of releases: state stays bounded
        flood.charge(KnowledgeType.ANTIBODY.value, recipient_scope=f"s-{rnd}", round_index=rnd)
    assert len(flood.entries()) <= flood.capacity and flood.evictions() > 0
    assert len(flood._log) <= flood.max_releases


def test_exact_release_voids_the_dp_claim_and_is_host_sensitive() -> None:
    ledger = PrivacyLedger()
    noisy = ledger.charge(NOVELTY_COUNTS, recipient_scope=SCOPE, round_index=1, epsilon=0.5)
    assert noisy.dp_epsilon == 0.5 and noisy.sensitivity_class is PrivacyClass.PUBLIC_DERIVED
    exact = ledger.charge(NOVELTY_COUNTS, recipient_scope=SCOPE, round_index=2)
    assert exact.dp_epsilon is None and exact.release_count == 2
    assert exact.sensitivity_class is PrivacyClass.HOST_SENSITIVE
    assert all(e.dp_delta is None for e in ledger.entries())


def test_inference_tests_are_bounded_and_need_a_release() -> None:
    ledger = PrivacyLedger()
    with pytest.raises(ContractError):
        ledger.record_inference_test(NOVELTY_COUNTS, recipient_scope=SCOPE, name="mia", advantage=0.1)
    ledger.charge(NOVELTY_COUNTS, recipient_scope=SCOPE, round_index=0, epsilon=1.0)
    for index in range(MAX_INFERENCE_TESTS + 2):
        ledger.record_inference_test(NOVELTY_COUNTS, recipient_scope=SCOPE,
                                     name=f"mia-{index}", advantage=0.01 * index)
    rows = ledger.entries()[0].inference_test_results
    assert len(rows) == MAX_INFERENCE_TESTS and rows[-1][0] == f"mia-{MAX_INFERENCE_TESTS + 1}"
    assert ledger.dropped_inference_tests() == 2
    with pytest.raises(ContractError):
        ledger.record_inference_test(NOVELTY_COUNTS, recipient_scope=SCOPE, name="x", advantage=1.5)


# --- D7.3 ledger: the mechanism -------------------------------------------------------


def test_geometric_noise_is_integer_and_centred() -> None:
    rng = random.Random(11)
    draws = [geometric_noise(1.0, rng=rng) for _ in range(20_000)]
    assert all(type(d) is int for d in draws)
    alpha = math.exp(-1.0)
    sd = math.sqrt(2 * alpha) / (1 - alpha)  # two-sided geometric
    assert abs(statistics.fmean(draws)) < 5 * sd / math.sqrt(len(draws))
    assert abs(statistics.pvariance(draws) - sd**2) < 0.1 * sd**2
    p_zero = (1 - alpha) / (1 + alpha)
    assert abs(draws.count(0) / len(draws) - p_zero) < 0.02
    wide_rng = random.Random(3)
    wide = [geometric_noise(0.2, rng=wide_rng) for _ in range(2_000)]
    assert statistics.pvariance(wide) > 5 * statistics.pvariance(draws)
    assert geometric_noise(1e6, rng=random.Random(0)) == 0
    for bad_eps in (0.0, -1.0, float("nan"), None):
        with pytest.raises(ContractError):
            geometric_noise(bad_eps)  # type: ignore[arg-type]
    for bad_sens in (0, True, 1.5):
        with pytest.raises(ContractError):
            geometric_noise(1.0, sensitivity=bad_sens)  # type: ignore[arg-type]
    # The default RNG is the system CSPRNG, and still integer-valued.
    assert type(geometric_noise(1.0)) is int


def test_release_counts_exact_control_and_noisy_release() -> None:
    counts = {"motif-a": 4, "motif-b": 0}
    ledger = PrivacyLedger()
    assert release_counts(counts, epsilon=None, ledger=ledger, recipient_scope=SCOPE,
                          round_index=0) == counts
    noisy = release_counts(counts, epsilon=0.5, ledger=ledger, recipient_scope=SCOPE,
                           round_index=1, rng=random.Random(5))
    assert set(noisy) == set(counts) and all(type(v) is int and v >= 0 for v in noisy.values())
    assert sum(e.release_count for e in ledger.entries()) == 2
    for bad in ({"a": -1}, {"": 1}, {"a": 1.0}, {f"k{i}": 1 for i in range(1025)}):
        with pytest.raises(ContractError):
            release_counts(bad, epsilon=1.0, ledger=ledger, recipient_scope=SCOPE,  # type: ignore[arg-type]
                           round_index=2)


# --- D7.2 Stage 6 -> 7 handoff ---------------------------------------------------------


def _record(items: list[dict[str, object]], *, simulated: bool = False) -> LearningRecordV1:
    return LearningRecordV1(
        record_id="lrec-test", trusted_digest="sha256:" + "0" * 64, state_version=1,
        active_context="ctx-" + "0" * 16, items=tuple(items), fossil_hashes=(),
        tombstoned_fossils=0, rollback_rows=(), lineage_intact=True,
        privacy_class="PUBLIC_DERIVED", simulated=simulated,
    )


def _item(kind: str, status: str, simulated: object, motif: list[list[int]]) -> dict[str, object]:
    row: dict[str, object] = {"kind": kind, "pattern_key": "motif:x", "motif": motif, "weight": 1.0,
                              "context_ids": [], "status": status, "candidate_id": "cand-1",
                              "evidence_count": 3}
    if simulated is not None:
        row["simulated"] = simulated
    return row


def test_simulated_learning_rows_are_not_exported() -> None:
    real = [[2, 1, 0, 0]]
    items = [
        _item("DETECTOR", "ACTIVE", False, real),
        _item("DETECTOR", "ACTIVE", True, [[3, 1, 0, 0]]),       # simulated: refused
        _item("DETECTOR", "DORMANT", False, [[4, 1, 0, 0]]),     # not active
        _item("BASELINE", "ACTIVE", False, [[5, 1, 0, 0]]),      # normality: never exported
        _item("DETECTOR", "ACTIVE", None, [[7, 1, 0, 0]]),       # a missing flag is not False
        _item("DETECTOR", "ACTIVE", 0, [[8, 1, 0, 0]]),          # a falsy int is not False
        _item("DETECTOR", "ACTIVE", False, real),                 # duplicate
        _item("DETECTOR", "ACTIVE", False, [[2, 1, 0, 0], [10, 0, 0, 0]]),
    ]
    got = invariants_from_learning_record(_record(items))
    assert got == ((MotifRow(2, 1, 0, 0),), (MotifRow(2, 1, 0, 0), MotifRow(10, 0, 0, 0)))
    # The record-level flag is sticky: a simulated record exports nothing at all.
    assert invariants_from_learning_record(_record(items, simulated=True)) == ()
    for motif in ([], [[1, 1, 1, 0]], [[1, 2, 3]], [[1, 0, 0, 0]] * 3):
        with pytest.raises(ContractError):
            invariants_from_learning_record(_record([_item("DETECTOR", "ACTIVE", False, motif)]))
    with pytest.raises(ContractError):
        invariants_from_learning_record({"items": items})  # type: ignore[arg-type]


# --- §4.19 fleet corpus -----------------------------------------------------------------


def test_corpus_has_nonzero_median_delta_phi_per_class(corpus: FleetCorpus) -> None:
    medians = median_peak_delta_phi(corpus)
    assert set(medians) == {0, 1} and medians[0] > 0.0 and medians[1] > 0.0
    p1 = fleet_preconditions(corpus)[0]
    assert (p1.name, p1.status) == ("P1", "PASS")


def test_corpus_identities_are_session_unique(corpus: FleetCorpus) -> None:
    owners: dict[str, tuple[str, int]] = {}
    for episode in corpus.episodes:
        for group in {s.source_group for s in episode.steps}:
            assert owners.setdefault(group, (episode.host_id, episode.index)) == (
                episode.host_id, episode.index)
    assert fleet_preconditions(corpus)[1].status == "PASS"
    # The check fires: re-use one episode's actors under another index.
    clone = FleetEpisode(host_id="h001", index=99, steps=corpus.episodes[0].steps, label=0,
                         family=None, evidence_digests=(), history=True)
    reused = FleetCorpus(version=corpus.version, seed=corpus.seed, hosts=corpus.hosts,
                         episodes=(*corpus.episodes, clone), raw_strings=corpus.raw_strings,
                         raw_digests=corpus.raw_digests)
    assert fleet_preconditions(reused)[1].status == "BLOCKED"


def test_admin_persistence_collides_with_web_persistence_motif(corpus: FleetCorpus) -> None:
    p4 = fleet_preconditions(corpus)[3]
    assert (p4.name, p4.status) == ("P4", "PASS"), p4.detail
    web = next(h for h in corpus.hosts if h.role is RoleClass.WEB
               and AttackFamily.PERSIST in h.families_local)
    incident = next(e for e in corpus.for_host(web.host_id, history=True)
                    if e.family is AttackFamily.PERSIST)
    motif = oracle_motif(incident.steps)
    assert motif is not None
    persist_write = next(s for s in incident.steps if s.relation == Relation.WRITE)
    admins = {h.host_id for h in corpus.hosts if h.role is RoleClass.ADMIN}
    service_installs = [
        e for e in corpus.episodes if e.host_id in admins and e.label == 0
        and [Relation(s.relation) for s in e.steps] == [Relation.IMPERSONATE, Relation.WRITE,
                                                        Relation.EXECUTE]
    ]
    assert service_installs
    for episode in service_installs:
        # Same meaning as ATTACK_PERSISTENCE: the benign write carries the attack write's props.
        assert episode.steps[1].object_property_mask == persist_write.object_property_mask
        assert match_motif(motif, episode.steps)
    webs = {h.host_id for h in corpus.hosts if h.role is RoleClass.WEB}
    assert not any(match_motif(motif, e.steps) for e in corpus.episodes
                   if e.host_id in webs and e.label == 0)


def test_late_benign_admin_install_appears_only_held_out(corpus: FleetCorpus) -> None:
    late = [h for h in corpus.hosts if h.late_benign]
    assert late and all(h.role is RoleClass.ADMIN for h in late)
    signature = [Relation.IMPERSONATE, Relation.WRITE, Relation.EXECUTE]
    for spec in late:
        def installs(history: bool, host: str = spec.host_id) -> int:
            return sum(1 for e in corpus.for_host(host, history=history) if e.label == 0
                       and [Relation(s.relation) for s in e.steps] == signature)
        assert installs(True) == 0 and installs(False) >= 1


def test_transfer_precondition_reports_saturation(corpus: FleetCorpus) -> None:
    by_name = {p.name: p for p in fleet_preconditions(corpus)}
    assert by_name["P3"].status == "PASS", by_name["P3"].detail
    for family in AttackFamily:
        assert family.value in by_name["P3"].detail
    # M0.3 predicted it: the oracle transfers perfectly, so gains are flagged, not believed.
    assert by_name["P5"].status == "DEGENERATE_IN_FAVOUR"
    # The check can fail: with no held-out EXFIL anywhere, transfer is unevaluable.
    stripped = FleetCorpus(
        version=corpus.version, seed=corpus.seed, hosts=corpus.hosts,
        episodes=tuple(e for e in corpus.episodes
                       if e.history or e.family is not AttackFamily.EXFIL),
        raw_strings=corpus.raw_strings, raw_digests=corpus.raw_digests,
    )
    blocked = {p.name: p.status for p in fleet_preconditions(stripped)}
    assert blocked["P3"] == "BLOCKED" and blocked["P5"] == "BLOCKED"


def test_non_iid_precondition_is_degenerate_without_a_rare_role() -> None:
    no_admin = build_fleet_corpus(hosts=5, episodes_per_host=8, seed=7)
    assert all(h.role is not RoleClass.ADMIN for h in no_admin.hosts)
    p4 = fleet_preconditions(no_admin)[3]
    assert (p4.name, p4.status) == ("P4", "DEGENERATE")


def test_canaries_preserve_stage1_semantics(corpus: FleetCorpus) -> None:
    from pocketsec.stage7.labs.fleet_corpus import FAMILY_CHAINS, ROLE_BENIGN

    patterns = [*{id(p): p for mix in ROLE_BENIGN.values() for p in mix}.values(),
                *FAMILY_CHAINS.values()]
    for pattern in patterns:
        plain = tuple(Behaviour(b.operation, {k: v.replace("{canary}", "svc") for k, v in
                                              b.fields.items()}) for b in pattern)
        marked = tuple(_canary_behaviour(b, "h007", 7) for b in pattern)

        def masks(behaviours: tuple[Behaviour, ...]) -> list[tuple[int, int, int]]:
            result = Stage1Pipeline().run_scenario(Scenario("s", behaviours, 0), offset=3)
            steps = [EncodedStep.from_transition(t, actor_slot=0) for t in result.transitions]
            return [(s.relation, s.object_property_mask, s.state_delta_mask) for s in steps]

        assert masks(plain) == masks(marked), pattern
    assert "cnry-h007-fs" in _canary_behaviour(ADMIN_SERVICE_INSTALL[1], "h007", 7).fields["path"]


def test_corpus_is_deterministic_and_bounded() -> None:
    first = build_fleet_corpus(hosts=2, episodes_per_host=8, seed=3)
    again = build_fleet_corpus(hosts=2, episodes_per_host=8, seed=3)
    assert first.version == FLEET_CORPUS_VERSION
    assert [e.steps for e in first.episodes] == [e.steps for e in again.episodes]
    assert all(e.history == (e.index < 4) for e in first.episodes)
    assert not any(v.isdigit() for v in first.raw_strings)
    assert all(d.startswith("sha256:") for d in first.raw_digests)
    for hosts, episodes in ((0, 40), (251, 40), (2, 7), (2, 100), (True, 40)):
        with pytest.raises(ContractError):
            build_fleet_corpus(hosts=hosts, episodes_per_host=episodes)
