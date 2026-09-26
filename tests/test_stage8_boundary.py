"""Stage 8's dependency and authority boundary (spec §5.1, ADR-0001/0070/0071/0121).

Stage 8 is a research loop with NO production authority. Its only exit is a typed candidate
handed to Stage 6's quarantine through exactly one module (``adapters/stage6.py``); nothing
in Stage 8 may name Stage 5, a Stage 6 writer, or run a process or a socket. These rules are
checked here, for Stage 8 only. ``tests/test_repository_structure.py`` and the Stage 6/7
boundary tests belong to other waves: their *technique* is reused, the files are untouched,
and the one import resolver is IMPORTED from ``pocketsec.stage2.gate_criteria``, never
copied (S2-AUTH-01). The rule predicates themselves live in ONE place,
``pocketsec/stage8/gate_boundary.py`` (the Stage 7 precedent): the gate runs them for
G8.9/G8.10 and this file attacks them with committed negative fixtures.

The sixteen rules of spec §5.1:

1. **R1 / ADR-0001.** Only stdlib roots or ``pocketsec``, including deferred imports.
2. **R2.** No ``pocketsec.stage*.research*`` import; ``pocketsec/stage8/research/`` absent.
3. **T2.** No import of ``pocketsec.stage5`` (relative, deferred, ``from pocketsec import``).
4. **Stage 3/4: nothing. Stage 2: only the two modules and names of §2.3.**
5. **The Stage 6 / Stage 7 allow-list of §2.3**, at module, NAME and importing-FILE grain.
   A whole-module import is refused everywhere (names cannot be checked through it).
6. **Stage 6 writer names** appear nowhere as a Name, Attribute, def, arg or string.
7. **The one door.** A called ``.admit`` appears only in ``adapters/stage6.py``.
8. **No execution or network primitive**, including attribute calls and builtins.
9. **T5.** No annotated ``@dataclass`` field containing an authority word.
10. **Runtime never imports labs**; nothing outside the harness imports the harness.
11. **Nothing earlier depends on Stage 8** (T3's permitted importer imports nothing today).
12. **No second harness, ledger, contracts or corpus type**; ``registry.jsonl`` only in the
    harness.
13. **Dynamic imports** only in ``core_ids.py``, ``constitution/discovery.py`` and
    ``labs/eighty_experiments.py``.
14. **The vault's episodes**: ``_vault_episodes`` only in ``sandbox/integrity.py``.
15. **No empty package (ADR-0121)**; ``experiments/`` and ``hypotheses/`` do not return.
16. **The discovered rule is refused everywhere else** (behavioural, the lead's test).

**Two declared deviations from the spec's literal text (reported to the integrator):**

* *Rule 7.* The spec defines ``ResearchGovernor.admit(bound, current)`` (D8.18) *and* says a
  called ``.admit`` appears only in the adapter; both cannot hold (``prometheus/generators.py``
  and ``sandbox/integrity.py`` call the governor's). AST cannot see types, so the exemption
  is by CALL SHAPE only: exactly two positional arguments, no keywords, the first a string
  literal naming a ``ResearchBudget`` bound. Stage 6's ``admit(capsule)`` raises
  ``ContractError`` for a string, so a call of that shape can never admit anything; and rule
  5 already keeps ``QuarantineGateway`` unimportable outside the adapter and the labs.
* *Rule 4.* The harness (``gate.py``, ``gate_*.py``, ``cli.py``) may import exactly the
  shared resolver ``pocketsec.stage2.gate_criteria:imported_modules``, the Stage 7
  precedent: G8.9/G8.10 must evaluate these rules in-gate and cannot resolve relative
  imports without it. The runtime still may not.

**Rule 16's package** is built through the real FORGE path (the discovery corpus, the
genome, ``compile_all``, ``run_tournament``, ``artifact_hashes_for``) and must pass
``verify_package``. It is not built by ``run_discovery``: at test scale (60 episodes per
split) that took 54 s and produced 0 packages while it was being written (loadavg 3.66).

Every check walks the AST, never the text: docstrings *name* the boundary, and naming it is
not crossing it.
"""

from __future__ import annotations

import ast
import copy
import hashlib
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.contracts.threat_prediction_v1 import FORBIDDEN_AUTHORITY_FIELDS
from pocketsec.stage1.epoch.model import EpochModel, SystemIdentity
from pocketsec.stage2.gate_criteria import imported_modules
from pocketsec.stage5.executor.transactional import _refuse_untyped
from pocketsec.stage6.capsule.experience_capsule import (
    CapsuleKind,
    ContaminationFlag,
    SourceClass,
)
from pocketsec.stage6.capsule.quarantine import QuarantineGateway
from pocketsec.stage6.fossils.lineage import KnowledgeLineageDAG
from pocketsec.stage6.memory.semantic import genesis_state
from pocketsec.stage6.provenance.ledger import ProvenanceLedger
from pocketsec.stage8.adapters.stage6 import Stage6Adapter
from pocketsec.stage8.challenger.adversarial import ChallengeKind, build_challenge_corpus
from pocketsec.stage8.episode import Split
from pocketsec.stage8.forge.compiler import compile_all, load_detector, required_features
from pocketsec.stage8.forge.package import (
    DiscoveryPackageV1,
    FailureCondition,
    FalsificationRecord,
    IdentifiabilityClass,
    NoveltyClass,
    ReproducibilityRecord,
    ReproducibilityStatus,
    ResourceProfile,
    RobustnessProfile,
    artifact_hashes_for,
    verify_package,
)
from pocketsec.stage8.forge.tournament import research_state_bytes_of, run_tournament
from pocketsec.stage8.gate_boundary import (
    ADAPTER,
    BOUNDARY_RULES,
    EARLIER_STAGES,
    FORBIDDEN_DIRECTORIES,
    POCKETSEC_ROOT,
    STAGE6_WRITER_DIGESTS,
    STAGE8_ROOT,
    VAULT_FILE,
    admit_calls,
    definition_hits,
    dynamic_imports,
    execution_primitives,
    imports_harness,
    imports_labs,
    imports_stage5,
    in_labs,
    is_harness,
    is_research,
    is_stage,
    is_vault_attribute,
    is_writer_name,
    label,
    modules_under,
    parse,
    registry_hits,
    rel,
    rule_offenders,
    stage8_files,
    t5_offenders,
    targets,
    third_party,
    upstream_violation,
    vault_hits,
    writer_hits,
)
from pocketsec.stage8.genome.grammar import parse_mechanism
from pocketsec.stage8.genome.hypothesis import (
    Direction,
    FalsifierKind,
    GeneratorKind,
    GenomeProvenance,
    HypothesisGenome,
    ObservationScope,
    ResidualType,
    genome_for,
)
from pocketsec.stage8.governor.budget import ResearchBudget, ResearchGovernor
from pocketsec.stage8.labs.discovery_corpus import CorpusArm, build_discovery_corpus
from pocketsec.stage8.ledger.theory import PreRegistration, TheoryLedger, TheoryStatus
from pocketsec.stage8.sandbox.integrity import HoldoutVault

#: Spec §5.1 rule 6, spelled out HERE (tests/ is outside pocketsec/, where Stage 6's own
#: boundary test forbids these names as string constants). The checker holds their digests.
STAGE6_WRITER_NAMES = frozenset({
    "LearningPromotionController", "TrustedMind", "TrustedKnowledgeState", "KnowledgeItem",
    "EvolutionChamber", "ShadowMind", "CanaryEvaluator", "_install_trusted", "_trusted_state",
    "with_changes", "promote_trusted", "rollback_learning", "_issue_verdict", "_issued_verdicts",
})
VAULT_ATTRIBUTE = "_vault_episodes"


def _stage8_files() -> list[Path]:
    files = stage8_files()
    assert files, "pocketsec/stage8/ holds no modules: every rule would pass vacuously"
    return files


def _per_target(check: Any, files: list[Path]) -> list[str]:
    return [f"{label(p)}:{t.lineno} {'.'.join(filter(None, (t.module, t.name)))} ({why})"
            for p in files for t in targets(p) if (why := check(t, p))]


def _per_node(check: Any, files: list[Path]) -> list[str]:
    return [f"{label(p)}:{line} {what}" for p in files for what, line in check(p)]


def test_the_checker_is_the_gates_and_its_digests_are_the_names() -> None:
    """ONE checker (S2-AUTH-01): the gate runs these predicates and this file attacks them."""
    assert admit_calls.__module__ == "pocketsec.stage8.gate_boundary"
    digests = frozenset(hashlib.sha256(n.encode()).hexdigest() for n in STAGE6_WRITER_NAMES)
    assert digests == STAGE6_WRITER_DIGESTS
    assert all(is_writer_name(n) for n in STAGE6_WRITER_NAMES)
    assert is_vault_attribute(VAULT_ATTRIBUTE) and not is_vault_attribute("vault_episodes")
    assert set(BOUNDARY_RULES) == set(range(1, 16))
    assert all(rule_offenders(r) == () for r in BOUNDARY_RULES), \
        {r: rule_offenders(r) for r in BOUNDARY_RULES if rule_offenders(r)}


def test_the_import_resolver_is_the_shared_one_not_a_copy() -> None:
    assert imported_modules.__module__ == "pocketsec.stage2.gate_criteria"
    from pocketsec.stage8 import gate_boundary
    assert gate_boundary.imported_modules is imported_modules


def test_rule1_stage8_has_no_third_party_imports() -> None:
    offenders = _per_target(lambda t, _p: "third party" if third_party(t) else None,
                            _stage8_files())
    assert not offenders, f"third-party imports in Stage 8 (ADR-0001): {offenders}"


def test_rule2_no_research_import_and_no_research_package() -> None:
    assert not (STAGE8_ROOT / "research").exists()
    offenders = _per_target(lambda t, _p: "research" if is_research(t) else None,
                            _stage8_files())
    assert not offenders, f"Stage 8 importing research code: {offenders}"


def test_rule3_no_stage8_module_imports_stage5() -> None:
    offenders = _per_target(lambda t, _p: "stage5" if imports_stage5(t) else None,
                            _stage8_files())
    assert not offenders, f"Stage 8 importing Stage 5 (T2): {offenders}"


def test_rules4_and_5_upstream_only_through_the_allow_list() -> None:
    offenders = _per_target(lambda t, p: upstream_violation(t, rel(p)), _stage8_files())
    assert not offenders, f"Stage 8 imports outside the §2.3 allow-list: {offenders}"


def test_rule6_no_stage8_module_names_a_stage6_writer() -> None:
    offenders = _per_node(writer_hits, _stage8_files())
    assert not offenders, f"Stage 8 names a Stage 6 writer: {offenders}"


def test_rule7_the_adapter_is_the_one_door_to_admit() -> None:
    offenders = _per_node(admit_calls, _stage8_files())
    assert not offenders, f"a called .admit outside {ADAPTER}: {offenders}"
    calls = [n for n in ast.walk(parse(STAGE8_ROOT / ADAPTER))
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
             and n.func.attr == "admit"]
    assert len(calls) == 1, "the adapter must call gateway.admit exactly once, in one place"


def test_rule8_no_execution_or_network_primitive() -> None:
    offenders = _per_node(execution_primitives, _stage8_files())
    assert not offenders, f"execution/network primitives in Stage 8: {offenders}"


def test_rule9_no_dataclass_field_carries_an_authority_word() -> None:
    offenders = _per_node(t5_offenders, _stage8_files())
    assert not offenders, f"T5 offenders in Stage 8: {offenders}"


def test_rule10_runtime_never_imports_labs_or_the_harness() -> None:
    runtime = [p for p in _stage8_files() if not in_labs(rel(p)) and not is_harness(rel(p))]
    labs = _per_target(lambda t, _p: "runtime imports labs" if imports_labs(t) else None,
                       runtime)
    assert not labs, f"Stage 8 runtime importing labs: {labs}"
    outside = [p for p in modules_under(POCKETSEC_ROOT) if not is_harness(rel(p))]
    harness = _per_target(lambda t, _p: "imports the harness" if imports_harness(t) else None,
                          outside)
    assert not harness, f"modules importing the Stage 8 harness: {harness}"


def test_rule11_no_earlier_stage_depends_on_stage8() -> None:
    offenders = [f"{label(p)}:{t.lineno} {t.module}"
                 for stage in EARLIER_STAGES for p in modules_under(POCKETSEC_ROOT / stage)
                 for t in targets(p) if any(is_stage(c, "stage8") for c in t.candidates())]
    assert not offenders, f"earlier stages importing Stage 8: {offenders}"
    permitted = POCKETSEC_ROOT / "stage6" / "capsule" / "quarantine.py"
    assert permitted.exists(), "T3's one permitted importer moved; re-check the permission"
    assert not [t for t in targets(permitted) if any(is_stage(c, "stage8")
                                                     for c in t.candidates())]


@pytest.mark.parametrize("name", FORBIDDEN_DIRECTORIES)
def test_rule12_no_second_contracts_harness_ledger_or_corpus_directory(name: str) -> None:
    assert not [p for p in STAGE8_ROOT.rglob(name) if p.is_dir()], f"stage8/**/{name}/ exists"


def test_rule12_no_second_harness_ledger_or_corpus_type_and_no_registry_path() -> None:
    offenders = _per_node(definition_hits, _stage8_files())
    assert not offenders, f"a second harness/ledger/corpus/gateway type: {offenders}"
    writers = _per_node(registry_hits, _stage8_files())
    assert not writers, f"registry.jsonl named outside the harness: {writers}"


def test_rule13_dynamic_imports_only_in_the_three_named_files() -> None:
    offenders = _per_node(dynamic_imports, _stage8_files())
    assert not offenders, f"importlib.import_module outside the permitted files: {offenders}"


def test_rule14_the_vault_attribute_is_named_only_by_the_vault() -> None:
    offenders = _per_node(vault_hits, _stage8_files())
    assert not offenders, f"{VAULT_ATTRIBUTE} named outside {VAULT_FILE}: {offenders}"


def _public_definitions(directory: Path) -> list[str]:
    return [node.name for path in modules_under(directory) if path.name != "__init__.py"
            for node in ast.walk(parse(path))
            if isinstance(node, (ast.ClassDef, ast.FunctionDef)) and not node.name.startswith("_")]


def test_rule15_no_empty_package_and_the_deleted_directories_stay_gone() -> None:
    for name in ("experiments", "hypotheses"):
        assert not (STAGE8_ROOT / name).exists(), f"pocketsec/stage8/{name}/ came back"
    packages = sorted(p.parent for p in STAGE8_ROOT.rglob("__init__.py")
                      if "__pycache__" not in p.parts)
    assert packages, "no Stage 8 package has an __init__.py; this rule would pass vacuously"
    empty = [label(d) for d in packages if d != STAGE8_ROOT and not _public_definitions(d)]
    assert not empty, f"Stage 8 packages exporting nothing (ADR-0121): {empty}"
    orphans = [label(d) for d in sorted(STAGE8_ROOT.rglob("*"))
               if d.is_dir() and d.name != "__pycache__" and not (d / "__init__.py").exists()]
    assert not orphans, f"directories under stage8/ that are not packages: {orphans}"


def test_rule15_the_stage8_root_is_a_package() -> None:
    """Spec §2.1: ``pocketsec/stage8/__init__.py`` (integrator-owned, empty) must exist."""
    assert (STAGE8_ROOT / "__init__.py").is_file(), "pocketsec/stage8/__init__.py is missing"


# --- the committed negative fixtures -------------------------------------------------------

_F, _P = ("stage8", "forge"), ("stage8", "prometheus")
NEGATIVE_FIXTURES: tuple[tuple[tuple[str, ...], str, str], ...] = (
    (("stage8", "leak.py"), "from ..stage5 import x\n", "stage5"),
    (("stage8", "leak.py"), "from pocketsec import stage5\n", "stage5"),
    ((*_F, "leak.py"), "def f():\n    import pocketsec.stage5.executor\n", "stage5"),
    (("stage8", "leak.py"), "from . import research\n", "research"),
    ((*_F, "leak.py"), "from ..research import solver\n", "research"),
    ((*_F, "leak.py"), "from ...stage6.promotion import controller\n", "allow_list"),
    ((*_F, "leak.py"), "from pocketsec.stage6.memory.semantic import genesis_state\n",
     "allow_list"),
    ((*_F, "leak.py"), "import pocketsec.stage6.memory.semantic\n", "allow_list"),
    ((*_P, "leak.py"), "from pocketsec.stage6.capsule.quarantine import QuarantineGateway\n",
     "allow_list"),
    ((*_P, "leak.py"), "from pocketsec.stage6.capsule.experience_capsule import "
     "capsule_from_scenario\n", "allow_list"),
    ((*_P, "leak.py"), "from pocketsec.stage7.echo.inference import EchoDecision\n",
     "allow_list"),
    ((*_P, "leak.py"), "from ...stage3.cells import schema\n", "allow_list"),
    ((*_P, "leak.py"), "from pocketsec.stage2.encoder import ssir_encoder\n", "allow_list"),
    ((*_P, "leak.py"), "from pocketsec.stage2.gate_criteria import imported_modules\n",
     "allow_list"),
    ((*_F, "leak.py"), "def f(x):\n    return getattr(x, '_install_trusted')\n", "writer"),
    ((*_F, "leak.py"), "from pocketsec.stage6.shadow.mind import ShadowMind as M\n", "writer"),
    ((*_F, "leak.py"), "def f(state):\n    return state.with_changes()\n", "writer"),
    ((*_F, "leak.py"), "def f(gateway, c):\n    return gateway.admit(c)\n", "admit"),
    ((*_F, "leak.py"), "def f(g, c):\n    return getattr(g, 'admit')(c)\n", "admit"),
    ((*_F, "leak.py"), "def f(g, c):\n    return g.admit('max_population', c, extra=1)\n",
     "admit"),
    ((*_F, "leak.py"), "def f(g, c):\n    return g.admit('not_a_bound', 1)\n", "admit"),
    ((*_F, "leak.py"), "import subprocess\n", "execution"),
    ((*_F, "leak.py"), "import os\ndef f():\n    os.execv('/bin/sh', [])\n", "execution"),
    ((*_F, "leak.py"), "from urllib.request import urlopen\n", "execution"),
    ((*_F, "leak.py"), "def f():\n    import pickle\n", "execution"),
    ((*_F, "leak.py"), "def f(s):\n    return eval(s)\n", "execution"),
    ((*_F, "leak.py"),
     "from dataclasses import dataclass\n@dataclass\nclass R:\n    kill_criterion: str\n", "t5"),
    ((*_F, "leak.py"), "from ..labs import discovery_corpus\n", "labs"),
    ((*_F, "leak.py"), "from pocketsec.stage8 import labs\n", "labs"),
    ((*_F, "leak.py"), "def f():\n    import numpy\n", "third_party"),
    ((*_F, "leak.py"), "import importlib\ndef f(n):\n    return importlib.import_module(n)\n",
     "dynamic"),
    ((*_F, "leak.py"), "def f(v):\n    return v._vault_episodes\n", "vault"),
    ((*_F, "leak.py"), "def f(v):\n    return getattr(v, '_vault_episodes')\n", "vault"),
    ((*_F, "leak.py"), "PATH = 'experiments/registry.jsonl'\n", "registry"),
    ((*_F, "leak.py"), "def f(root):\n    return root / 'registry.jsonl'\n", "registry"),
    ((*_F, "leak.py"), "class ExperimentRegistry:\n    pass\n", "definition"),
)


def _write(tmp_path: Path, where: tuple[str, ...], source: str) -> Path:
    package = tmp_path.joinpath("pocketsec", *where[:-1])
    package.mkdir(parents=True, exist_ok=True)
    path = package / where[-1]
    path.write_text(source, encoding="utf-8")
    return path


def _caught(rule: str, path: Path) -> bool:
    found = targets(path)
    parts = rel(path)
    checks = {
        "stage5": lambda: any(imports_stage5(t) for t in found),
        "research": lambda: any(is_research(t) for t in found),
        "allow_list": lambda: any(upstream_violation(t, parts) for t in found),
        "writer": lambda: bool(writer_hits(path)),
        "admit": lambda: bool(admit_calls(path)),
        "execution": lambda: bool(execution_primitives(path)),
        "t5": lambda: bool(t5_offenders(path)),
        "labs": lambda: not in_labs(parts) and any(imports_labs(t) for t in found),
        "third_party": lambda: any(third_party(t) for t in found),
        "dynamic": lambda: bool(dynamic_imports(path)),
        "vault": lambda: bool(vault_hits(path)),
        "registry": lambda: bool(registry_hits(path)),
        "definition": lambda: bool(definition_hits(path)),
    }
    return checks[rule]()


@pytest.mark.parametrize(("where", "source", "rule"), NEGATIVE_FIXTURES)
def test_a_boundary_violation_is_caught_whatever_its_form(
    where: tuple[str, ...], source: str, rule: str, tmp_path: Path
) -> None:
    assert _caught(rule, _write(tmp_path, where, source)), (rule, source)


def test_the_negative_fixtures_cover_every_form_the_spec_names() -> None:
    sources = {source for _, source, _ in NEGATIVE_FIXTURES}
    assert "from ..stage5 import x\n" in sources
    assert "from . import research\n" in sources
    assert "from ...stage6.promotion import controller\n" in sources
    assert "def f():\n    import numpy\n" in sources
    assert any("getattr(x, '_install_trusted')" in s for s in sources)


def test_the_permitted_forms_are_not_offenders(tmp_path: Path) -> None:
    """Both directions: a predicate refusing everything would pass every rule vacuously."""
    adapter = _write(tmp_path, ("stage8", "adapters", "stage6.py"),
                     "def f(self, c):\n    return self._gateway.admit(c)\n"
                     "from pocketsec.stage6.provenance.trust import score_provenance\n")
    assert admit_calls(adapter) == []
    assert not any(upstream_violation(t, rel(adapter)) for t in targets(adapter))
    governor = _write(tmp_path, ("stage8", "ecology", "pop.py"),
                      "def f(g, n):\n    return g.admit('max_population', n)\n")
    assert admit_calls(governor) == []
    lab = _write(tmp_path, ("stage8", "labs", "lab.py"),
                 "from pocketsec.stage6.memory.semantic import genesis_state\n"
                 "from pocketsec.stage6.capsule.quarantine import QuarantineGateway\n")
    assert not any(upstream_violation(t, rel(lab)) for t in targets(lab))
    gate = _write(tmp_path, ("stage8", "gate_boundary.py"),
                  "from pocketsec.stage2.gate_criteria import imported_modules\n"
                  "from pocketsec.stage8.labs import discovery_corpus\n")
    assert not any(upstream_violation(t, rel(gate)) for t in targets(gate))
    runtime = _write(tmp_path, ("stage8", "forge", "ok.py"),
                     "import re\n"
                     "from pocketsec.stage2.encoder.ssir_encoder import FEATURE_WIDTH\n"
                     "from pocketsec.stage6.resources import WorkMeter\n"
                     "P = re.compile('x')\n\"\"\"Never calls TrustedMind or _vault_episodes.\"\"\"\n"
                     "\"\"\"The gate never writes experiments/registry.jsonl.\"\"\"\n")
    assert not any(upstream_violation(t, rel(runtime)) for t in targets(runtime))
    assert execution_primitives(runtime) == [] and writer_hits(runtime) == []
    assert registry_hits(runtime) == [] and vault_hits(runtime) == []
    function = _write(tmp_path, ("stage8", "forge", "fn.py"),
                      "from pocketsec.stage8.forge.tournament import research_state_bytes_of\n")
    assert not any(is_research(t) for t in targets(function))


# --- rule 16: the discovered rule is refused everywhere else (behavioural) -----------------

_COUNTS = {Split.TRAIN: 60, Split.HOLDOUT: 20, Split.REPLICATION: 60, Split.LAB_POOL: 30,
           Split.INDEPENDENT: 20}
PM1 = "PRECEDES(EXECUTE+TEMP_LOCATION,CONNECT+EXTERNAL_ENDPOINT)"


@dataclass(frozen=True, slots=True)
class _Discovery:
    package: DiscoveryPackageV1
    genome: HypothesisGenome
    compiled: tuple[Any, ...]
    evidence: dict[str, Any]
    ledger: TheoryLedger


def _reproduced_ledger(genome: HypothesisGenome) -> TheoryLedger:
    """REPRODUCED earned through two preregistered vault batches on a full-size corpus: the
    adapter reads the status from the ledger, never from the package (S8-AUTH-01)."""
    corpus = build_discovery_corpus(arm=CorpusArm.PLANTED, seed=3)
    ledger = TheoryLedger()
    ledger.record_birth(genome)
    for split, kind in ((Split.HOLDOUT, FalsifierKind.HOLDOUT_ENRICHMENT),
                        (Split.REPLICATION, FalsifierKind.REPLICATION)):
        vault = HoldoutVault(corpus.episodes(split), split=split, ledger=ledger,
                             governor=ResearchGovernor(ResearchBudget()))
        registration = PreRegistration(
            registration_id="", hypothesis_id=genome.hypothesis_id,
            genome_digest=genome.digest(), split=split, split_digest=vault.split_digest(),
            batch_size=1, alpha=next(f.alpha for f in genome.falsification_tests if f.kind is kind),
            prediction=next(p for p in genome.predicted_observations if p.split is split))
        ledger.preregister(registration)
        (outcome,) = vault.evaluate(vault.seal_batch([registration]))
        assert outcome.survived, (split, outcome.reasons)
    ledger.set_status(genome.hypothesis_id, TheoryStatus.REPRODUCED, reason="test:replicated")
    return ledger


def _fitting(matches: list[Any]) -> list[Any]:
    """Evidence sessions whose digests fit the package's 32 (the production rule)."""
    chosen: list[Any] = []
    digests: set[str] = set()
    for episode in matches:
        union = digests | set(episode.evidence_digests())
        if len(chosen) >= 8 or len(union) > 32:
            break
        chosen.append(episode)
        digests = union
    return chosen


def _receiver() -> QuarantineGateway:
    """A REAL Stage 6 gateway bound to genesis state (the lab receiver, built in the test)."""
    gateway = QuarantineGateway(ledger=ProvenanceLedger(), lineage=KnowledgeLineageDAG())
    state = genesis_state(identity=SystemIdentity())
    gateway.bind_trusted_view(lambda: state)
    return gateway


@pytest.fixture(scope="module")
def discovery() -> _Discovery:
    corpus = build_discovery_corpus(arm=CorpusArm.PLANTED, seed=3, counts=_COUNTS)
    genome = genome_for(parse_mechanism(PM1), direction=Direction.MALICIOUS,
                        scope=ObservationScope((), frozenset({ResidualType.OBSERVATION}), ()),
                        provenance=GenomeProvenance(GeneratorKind.SYMBOLIC_ENUMERATOR,
                                                    "sha256:" + "0" * 64, False, 3))
    governor = ResearchGovernor(ResearchBudget())
    compiled = compile_all(genome, corpus.episodes(Split.TRAIN), governor=governor)
    kinds = tuple(k for k in ChallengeKind if k is not ChallengeKind.POISONED_LABELS)
    challenged = build_challenge_corpus(corpus.episodes(Split.LAB_POOL), kinds=kinds,
                                        rng=random.Random(3), governor=governor,
                                        necessary=genome.necessary_conditions)
    replication = corpus.episodes(Split.REPLICATION)
    # The fixture needs a deployable tournament (a package with an artifact). Deployability
    # includes a measured within-run wall ratio (F2) that reads MOTIF at ~0.96x with ~1 in 10
    # re-measurements above 1.0, so the fixture re-measures up to 5 times. Not a measurement.
    for _ in range(5):
        tournament = run_tournament(genome, compiled, measure_on=replication,
                                    challenge=challenged,
                                    discovery_work_units=governor.meter.spent,
                                    research_state_bytes=research_state_bytes_of(genome),
                                    governor=governor)
        if tournament.selected is not None:
            break
    assert tournament.selected is not None, "fixture expects a deployable PM1 tournament"
    chosen = next(c for c in compiled if c.kind is tournament.selected)
    matches = _fitting([e for e in replication if genome.decides(e) and e.label == 1])
    package = DiscoveryPackageV1(
        package_id="", hypothesis_id=genome.hypothesis_id, mechanism=genome.proposed_mechanism,
        direction=genome.direction, required_features=required_features(chosen),
        detector_candidates=tournament, selected_representation=tournament.selected,
        compiled_artifact=chosen.artifact,
        evidence_lineage=("res-0000000000000000", genome.hypothesis_id,
                          "disc-" + genome.hypothesis_id[4:], tournament.tournament_id),
        evidence_digests=tuple(dict.fromkeys(d for e in matches for d in
                                             e.evidence_digests())),
        evidence_episode_ids=tuple(e.episode_id for e in matches),
        falsification_results=(FalsificationRecord(FalsifierKind.REPLICATION,
                                                   Split.REPLICATION, True, 0.001, 0.05, ""),),
        failure_conditions=(FailureCondition("independent:fp", 0.0, "no independent match"),),
        resource_profile=ResourceProfile(chosen.artifact_bytes,
                                         tournament.deployed_work_units_per_event, None,
                                         (0.0, 0.0, 0.0)),
        robustness_profile=RobustnessProfile((), ()), known_technique_mappings=(),
        novelty_classification=NoveltyClass.CONTEXT_EXTENSION, novelty_claim_permitted=False,
        identifiability=IdentifiabilityClass.EQUIVALENCE_CLASS,
        reproducibility=ReproducibilityRecord(ReproducibilityStatus.REPRODUCED, 1.0, 0.38, 0.0,
                                              0.9, 0.0, False, ()),
        artifact_hashes=artifact_hashes_for(mechanism=genome.proposed_mechanism,
                                            tournament=tournament,
                                            compiled_artifact=chosen.artifact, genome=genome),
        synthetic_data=True,
    )
    assert verify_package(package) == ()
    return _Discovery(package, genome, compiled, dict(corpus.results),
                      _reproduced_ledger(genome))


def test_rule16_the_gateway_refuses_the_package_and_the_detector_by_type(
        discovery: _Discovery) -> None:
    gateway = _receiver()
    for foreign in (discovery.package, discovery.package.to_dict(), discovery.genome,
                    *[load_detector(c) for c in discovery.compiled if c.expressible]):
        with pytest.raises(ContractError, match="only an ExperienceCapsuleV1"):
            gateway.admit(foreign)
    assert gateway.stats().get("offered") == 0, "a refused object must not count as offered"


def test_rule16_stage5_refuses_the_package_and_the_detector_at_its_entry(
        discovery: _Discovery) -> None:
    for foreign in (discovery.package, *[load_detector(c) for c in discovery.compiled
                                         if c.expressible]):
        with pytest.raises(TypeError, match="DefensiveOperator"):
            _refuse_untyped(foreign, None)


def _inject(payload: Any, path: tuple[Any, ...], key: str) -> Any:
    tampered = copy.deepcopy(payload)
    node = tampered
    for step in path:
        node = node[step]
    node[key] = 1
    return tampered


_DEPTHS: tuple[tuple[Any, ...], ...] = (
    (), ("detector_candidates",), ("detector_candidates", "entrants", 0),
    ("compiled_artifact",), ("reproducibility",), ("resource_profile",),
    ("falsification_results", 0),
)


@pytest.mark.parametrize("word", sorted(FORBIDDEN_AUTHORITY_FIELDS))
def test_rule16_authority_keys_are_refused_at_every_depth(discovery: _Discovery,
                                                          word: str) -> None:
    payload = discovery.package.to_dict()
    assert DiscoveryPackageV1.from_dict(payload) == discovery.package  # the untampered path
    for path in _DEPTHS:
        with pytest.raises(ContractError, match="authority"):
            DiscoveryPackageV1.from_dict(_inject(payload, path, f"x_{word}"))
    genome = discovery.genome.to_dict()
    for path in ((), ("provenance",), ("observation_scope",)):
        with pytest.raises(ContractError, match="authority"):
            HypothesisGenome.from_dict(_inject(genome, path, word.upper()))


def test_rule16_the_only_capsules_are_the_adapters_and_they_carry_evidence_only(
        discovery: _Discovery) -> None:
    """created == admitted == the gateway's ``offered`` increase; every capsule is inference
    evidence under ONE group, flagged SIMULATED_RECORD; the discovery itself never crosses."""
    seen: list[Any] = []

    class Recording(QuarantineGateway):
        def admit(self, capsule):  # type: ignore[no-untyped-def]
            seen.append(capsule)
            return super().admit(capsule)

    gateway = Recording(ledger=ProvenanceLedger(), lineage=KnowledgeLineageDAG())
    state = genesis_state(identity=SystemIdentity())
    gateway.bind_trusted_view(lambda: state)
    before = gateway.stats().get("offered")
    adapter = Stage6Adapter(gateway=gateway, ledger=discovery.ledger,
                            epoch=EpochModel(identity=SystemIdentity()).current,
                            run_id="boundary", host_id="lab-host-01", synthetic=True)
    receipt = adapter.hand_over(discovery.package, evidence=discovery.evidence, sequence=1)
    offered = gateway.stats().get("offered") - before
    assert adapter.created() == adapter.admitted() == offered == len(seen) == \
        len(receipt.capsule_ids) > 0
    assert {c.kind for c in seen} == {CapsuleKind.TRANSITION_EPISODE}
    assert {c.source_provenance.source_class for c in seen} == {SourceClass.DERIVED_INFERENCE}
    assert {c.source_provenance.independence_group for c in seen} == {"stage8:boundary"}
    assert all(ContaminationFlag.SIMULATED_RECORD in c.contamination_flags for c in seen)
    package = discovery.package
    secrets = {package.mechanism.to_dsl(), package.detector_candidates.tournament_id,
               *(digest for _, digest in package.artifact_hashes)}
    assert not any(text in repr(c.to_dict()) for c in seen for text in secrets)
