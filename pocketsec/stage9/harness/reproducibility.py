"""D9.20 (ONTO-F20, manifest half) — the Stage 1-9 reproducibility manifest, and its verifier.

A Stage 9 figure is only meaningful with its (corpus, count, seed), the code versions that
compiled the corpus, the schema versions of what it produced, and the environment it ran in:
the Φ-oracle's AP moves 0.40 with corpus size alone (spec M0.2). This module pins all of that
into one content-addressed record, :class:`ReproducibilityManifest`, and re-checks it.

* :func:`build_manifest` captures Stage 0's :class:`EnvironmentFingerprint` (which already
  records a dirty or absent git tree as *not reproducible* rather than hiding it), the seed
  set, the Stage 1 and Stage 2 corpus versions, the encoder version, four schema versions, the
  stage gate commands declared in ``pyproject.toml``, the split digests, the genome digests and
  the experiment ids, then digests the lot.
* :func:`verify_manifest` recomputes that digest, reports any corpus/encoder version the
  current code no longer matches, and — for the split keys it is asked to — recompiles the
  split through ``labs.splits`` and compares content digests byte for byte.

What it refuses to do. It imports no Stage 6 capsule or Stage 9 successor module to learn a
schema version: those modules sit behind the Stage 9 import allow-list (spec §2.3) and the
capsule module's import closure reaches Stage 5. A version is read from Stage 0's
``SCHEMA_REGISTRY`` when this process registered it, otherwise statically from the declaring
module's source by AST (no import), and otherwise recorded as ``None`` — the basis of each is
kept in ``schema_version_basis``. It never writes the experiment ledger, and a manifest with a
wrong digest is still constructible so that :func:`verify_manifest` can report it.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final

from pocketsec.stage0.contracts.common import SCHEMA_REGISTRY, ContractError
from pocketsec.stage0.experiments.ids import parse_experiment_id
from pocketsec.stage0.gate import REPO_ROOT
from pocketsec.stage0.repro.environment import EnvironmentFingerprint
from pocketsec.stage0.repro.seeds import SeedSet
from pocketsec.stage1.labs.ambiguous_corpus import AMBIGUOUS_VERSION
from pocketsec.stage1.labs.corpus import CORPUS_VERSION
from pocketsec.stage2.encoder.ssir_encoder import ENCODER_VERSION
from pocketsec.stage2.labs.drift_corpus import DRIFT_VERSION
from pocketsec.stage9.genome.computational import COMPUTATIONAL_GENOME_V1_ID
from pocketsec.stage9.labs.splits import CORPUS, SplitKey, compile_variant, split_key

__all__ = [
    "MANIFEST_SCHEMAS",
    "PYPROJECT_PATH",
    "ReproducibilityManifest",
    "build_manifest",
    "current_corpus_versions",
    "parse_split_key",
    "stage_gate_entrypoints",
    "verify_manifest",
]

PYPROJECT_PATH: Final = REPO_ROOT / "pyproject.toml"

#: name -> (schema id, declaring module relative to the repository root).
MANIFEST_SCHEMAS: Mapping[str, tuple[str, str]] = MappingProxyType(
    {
        "genome": (COMPUTATIONAL_GENOME_V1_ID, "pocketsec/stage9/genome/computational.py"),
        "successor": (
            "pocketsec.proof_carrying_successor.v1",
            "pocketsec/stage9/successor/proof_carrying.py",
        ),
        "compile_candidate": (
            "pocketsec.compile_candidate.v1",
            "pocketsec/stage2/compile_candidates/candidate.py",
        ),
        "experience_capsule": (
            "pocketsec.experience_capsule.v1",
            "pocketsec/stage6/capsule/experience_capsule.py",
        ),
    }
)

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_SCRIPT = re.compile(r"pocketsec-stage(\d+)")
_KEY_FIELD = re.compile(r"(\w+)=(?:'([^']*)'|(-?\d+))")
_KEY_REPR = re.compile(r"SplitKey\((.*)\)")


def current_corpus_versions() -> Mapping[str, str]:
    """The corpus generator versions the current code would compile with."""
    return MappingProxyType(
        {"ambiguous": AMBIGUOUS_VERSION, "corpus": CORPUS_VERSION, "drift": DRIFT_VERSION}
    )


def _static_schema_version(schema_id: str, source: Path) -> str | None:
    """``register_schema(<ID>, "x.y.z")`` read from ``source`` by AST, without importing it."""
    try:
        tree = ast.parse(source.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, UnicodeDecodeError):
        return None
    names = {
        target.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
        and node.value.value == schema_id
        for target in node.targets
        if isinstance(target, ast.Name)
    }  # fmt: skip
    for node in ast.walk(tree):
        call = node if isinstance(node, ast.Call) else None
        if call is None or getattr(call.func, "id", None) != "register_schema":
            continue
        if len(call.args) == 2 and isinstance(call.args[1], ast.Constant):
            first = call.args[0]
            named = isinstance(first, ast.Name) and first.id in names
            literal = isinstance(first, ast.Constant) and first.value == schema_id
            if named or literal:
                return str(call.args[1].value)
    return None


def _schema_versions() -> tuple[dict[str, str | None], dict[str, str]]:
    versions: dict[str, str | None] = {}
    basis: dict[str, str] = {}
    for name, (schema_id, relative) in MANIFEST_SCHEMAS.items():
        registered = SCHEMA_REGISTRY.get(schema_id)
        if registered is not None:
            versions[name], basis[name] = registered, "SCHEMA_REGISTRY"
            continue
        static = _static_schema_version(schema_id, REPO_ROOT / relative)
        versions[name] = static
        basis[name] = f"STATIC_SOURCE:{relative}" if static is not None else f"ABSENT:{relative}"
    return versions, basis


def stage_gate_entrypoints(pyproject: Path | None = None) -> tuple[str, ...]:
    """``pocketsec-stageN gate`` for every stage 0..9 script declared in ``[project.scripts]``."""
    path = PYPROJECT_PATH if pyproject is None else pyproject
    try:
        scripts = tomllib.loads(path.read_text(encoding="utf-8"))["project"]["scripts"]
    except (OSError, KeyError, TypeError, tomllib.TOMLDecodeError) as exc:
        raise ContractError(f"cannot read [project.scripts] from {path}: {exc}") from exc
    staged = sorted(
        (int(match.group(1)), name)
        for name in scripts
        if (match := _SCRIPT.fullmatch(name)) is not None and int(match.group(1)) <= 9
    )
    return tuple(f"{name} gate" for _, name in staged)


def parse_split_key(text: str) -> SplitKey:
    """Invert ``repr(SplitKey)``; anything else is a :class:`ContractError`."""
    match = _KEY_REPR.fullmatch(text)
    if match is None:
        raise ContractError(f"not a SplitKey repr: {text!r}")
    fields: dict[str, Any] = {}
    for name, string, number in _KEY_FIELD.findall(match.group(1)):
        fields[name] = int(number) if number else string
    try:
        key = SplitKey(**fields)
    except TypeError as exc:
        raise ContractError(f"SplitKey repr has the wrong fields: {text!r}") from exc
    if repr(key) != text:
        raise ContractError(f"SplitKey repr does not round-trip: {text!r}")
    return key


def _plain(value: Any) -> Any:
    """JSON-ready copy: mappings -> dicts, tuples -> lists."""
    if isinstance(value, Mapping):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, tuple | list):
        return [_plain(v) for v in value]
    return value


@dataclass(frozen=True, slots=True)
class ReproducibilityManifest:
    """Everything a Stage 9 figure needs to be recomputed, under one content digest.

    ``stage_gate_entrypoints`` is the spec's ``stage_gate_commands``, renamed: "command" is a
    forbidden authority fragment for Stage 9 field names (spec §2.2).
    """

    environment: Mapping[str, Any]
    seeds: Mapping[str, int]
    corpus_versions: Mapping[str, str]
    encoder_version: str
    schema_versions: Mapping[str, str | None]
    schema_version_basis: Mapping[str, str]
    stage_gate_entrypoints: tuple[str, ...]
    split_digests: Mapping[str, str]
    genome_digests: tuple[str, ...]
    experiment_ids: tuple[str, ...]
    content_digest: str

    def payload(self) -> dict[str, Any]:
        """Every field but the digest, as plain JSON data."""
        return {
            "environment": _plain(self.environment),
            "seeds": _plain(self.seeds),
            "corpus_versions": _plain(self.corpus_versions),
            "encoder_version": self.encoder_version,
            "schema_versions": _plain(self.schema_versions),
            "schema_version_basis": _plain(self.schema_version_basis),
            "stage_gate_entrypoints": list(self.stage_gate_entrypoints),
            "split_digests": _plain(self.split_digests),
            "genome_digests": list(self.genome_digests),
            "experiment_ids": list(self.experiment_ids),
        }

    def compute_digest(self) -> str:
        canonical = json.dumps(self.payload(), sort_keys=True, separators=(",", ":"))
        return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {**self.payload(), "content_digest": self.content_digest}


def _frozen(mapping: Mapping[str, Any]) -> Mapping[str, Any]:
    return MappingProxyType(dict(sorted(mapping.items())))


def _validate_inputs(
    split_digests: Mapping[str, str], genome_digests: Sequence[str], experiment_ids: Sequence[str]
) -> None:
    for key, digest in split_digests.items():
        parse_split_key(key)
        if not _DIGEST.fullmatch(digest):
            raise ContractError(f"split {key} has a malformed digest {digest!r}")
    for digest in genome_digests:
        if not _DIGEST.fullmatch(digest):
            raise ContractError(f"malformed genome digest {digest!r}")
    for experiment_id in experiment_ids:
        parse_experiment_id(experiment_id)


def build_manifest(
    *,
    seeds: SeedSet,
    split_digests: Mapping[str, str],
    genome_digests: Sequence[str],
    experiment_ids: Sequence[str],
) -> ReproducibilityManifest:
    """Capture the environment and every version, and seal the record with its digest."""
    if not isinstance(seeds, SeedSet):
        raise ContractError("build_manifest takes a stage0 SeedSet")
    _validate_inputs(split_digests, genome_digests, experiment_ids)
    versions, basis = _schema_versions()
    unsealed = ReproducibilityManifest(
        environment=_frozen(EnvironmentFingerprint.capture(seeds=seeds).to_dict()),
        seeds=_frozen(seeds.as_dict()),
        corpus_versions=_frozen(current_corpus_versions()),
        encoder_version=ENCODER_VERSION,
        schema_versions=_frozen(versions),
        schema_version_basis=_frozen(basis),
        stage_gate_entrypoints=stage_gate_entrypoints(),
        split_digests=_frozen(split_digests),
        genome_digests=tuple(genome_digests),
        experiment_ids=tuple(experiment_ids),
        content_digest="",
    )
    return _sealed(unsealed)


def _sealed(manifest: ReproducibilityManifest) -> ReproducibilityManifest:
    return replace(manifest, content_digest=manifest.compute_digest())


def _version_drift(manifest: ReproducibilityManifest) -> list[str]:
    problems = [
        f"corpus version drift: {name} recorded {recorded!r}, code has {current!r}"
        for name, current in current_corpus_versions().items()
        if (recorded := manifest.corpus_versions.get(name)) != current
    ]
    if manifest.encoder_version != ENCODER_VERSION:
        problems.append(
            f"encoder version drift: recorded {manifest.encoder_version!r}, "
            f"code has {ENCODER_VERSION!r}"
        )
    return problems


def _recompile_problem(manifest: ReproducibilityManifest, text: str) -> str:
    recorded = manifest.split_digests.get(text)
    if recorded is None:
        return f"split {text} is not in the manifest"
    try:
        key = parse_split_key(text)
    except ContractError as exc:
        return str(exc)
    if key.corpus != CORPUS:
        return f"split {text}: labs.splits compiles only {CORPUS!r}"
    current = split_key(count=key.count, seed=key.seed, attack_id=key.attack_id)
    if current != key:
        return f"split {text}: code versions drifted to {current!r}; not comparable"
    recompiled = compile_variant(count=key.count, seed=key.seed, attack_id=key.attack_id)
    if recompiled.content_digest != recorded:
        return (
            f"split {text}: recompiled to {recompiled.content_digest[:19]}..., "
            f"manifest records {recorded[:19]}..."
        )
    return ""


def verify_manifest(
    manifest: ReproducibilityManifest, *, recompile: Sequence[str] = ()
) -> tuple[str, ...]:
    """Every reason ``manifest`` does not reproduce; ``()`` means it verified.

    Always recomputes the content digest and checks corpus/encoder versions against the
    current code; recompiles only the split keys named in ``recompile`` (each is seconds to
    tens of seconds of compile time).
    """
    problems: list[str] = []
    expected = manifest.compute_digest()
    if manifest.content_digest != expected:
        problems.append(
            f"content digest mismatch: carries {manifest.content_digest[:19]}..., "
            f"content hashes to {expected[:19]}..."
        )
    problems.extend(_version_drift(manifest))
    for text in recompile:
        problem = _recompile_problem(manifest, text)
        if problem:
            problems.append(problem)
    return tuple(problems)
