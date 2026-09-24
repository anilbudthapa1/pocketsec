"""The evidence the Stage 2 gate consumes, and how it is proved authentic.

Split out of ``gate.py`` under ADR-0127. G2.1, G2.2 and G2.12's degeneracy clause
are decided entirely by ``results/stage2-frontier.json``, a file offline research
writes and this runtime module reads — the Stage 0 hub/model boundary applied to
the gate itself, because the baseline suite may use numpy (ADR-0008) and a gate
may not.

That made one gitignored file the deciding input for the stage's central rejected
result, with no digest, no ledger lineage and nothing but a matching
``(corpus, count, seed)`` triple standing between a hand-written copy and a PASS.
Everything here exists to close that: :meth:`FrontierEvidence.signed`,
:func:`load_frontier` and the four refusals in
:func:`frontier_provenance_refusal`.

Stdlib only, like the gate. The ``measured_by`` check is deliberately a *shape*
check and never an import: the CI ``gate`` job installs no numpy, and importing
the named producer to confirm it exists would both break that and open a
dynamic-import hole the AST seam checks cannot see.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.experiments.ids import parse_experiment_id
from pocketsec.stage0.experiments.registry import ExperimentRegistry
from pocketsec.stage0.gate import REPO_ROOT

__all__ = [
    "FRONTIER_PATH",
    "GATE_CORPUS",
    "GATE_COUNT",
    "REGISTRY_PATH",
    "TEST_SEED",
    "TRAIN_SEED",
    "FrontierEvidence",
    "frontier_provenance_refusal",
    "load_frontier",
]

#: The fixed measurement triple. Spec section 0.1: a Stage 2 result quoted
#: without (corpus, count, seed) is void, because a zero-parameter scorer's
#: PR-AUC on this generator moves 0.4025 with sample count alone.
GATE_CORPUS = "ambiguous"
GATE_COUNT = 60
TRAIN_SEED = 3
TEST_SEED = 11

#: Where offline research leaves the baseline-suite measurement for the gate.
FRONTIER_PATH = REPO_ROOT / "results" / "stage2-frontier.json"
#: The append-only, hash-chained ledger a frontier measurement must appear in.
REGISTRY_PATH = REPO_ROOT / "experiments" / "registry.jsonl"


@dataclass(frozen=True, slots=True)
class FrontierEvidence:
    """The baseline suite's measured figures, as plain data.

    Produced by ``pocketsec.stage2.research.cli frontier`` and consumed here.
    Every field is a number research measured; ``measured_by`` names the module
    and function that produced it, so no figure in a gate detail is anonymous.

    Three fields exist to make the file *authentic* rather than merely present,
    and ``_load_frontier`` refuses evidence that fails any of them:

    * ``content_digest`` — ``sha256:`` over the canonical payload of every other
      field. A hand-edited number no longer matches its own digest.
    * ``experiment_id`` — must parse AND be a row in the append-only,
      hash-chained ``experiments/registry.jsonl``. That is the ledger the rest
      of this repository already uses for exactly this purpose; the frontier
      file was the one measurement that bypassed it.
    * ``measured_by`` — must resolve to an importable ``module:function``, so the
      provenance the gate prints names code that exists.

    Why (S2-AUTH-02): three acceptance criteria — G2.1, G2.2 and G2.12's
    degeneracy clause — were decided entirely by ``results/stage2-frontier.json``,
    a gitignored file whose only validation was that its (corpus, count, seed)
    triple matched. A hand-written file flipped G2.1 and G2.2 from FAIL to PASS
    and the gate then printed the file's own ``measured_by`` string as
    provenance. Because the file is gitignored there was no diff to review and
    no lineage to check, and ADR-0010's rejected central result — the learned
    core is dominated by a zero-parameter scorer — became a PASS with zero
    privilege required. ``EvidenceRef`` exists in Stage 0 precisely so "a later
    stage can prove the bytes it reads are the bytes the prediction was made
    from"; this is that rule applied to the gate's own input.
    """

    corpus: str
    count: int
    seed: int
    base_rate: float
    scores: dict[str, float]
    degenerate: bool
    reason: str
    best: float | None
    best_model: str | None
    median: float | None
    spread: float | None
    order_free_baseline: float | None
    phi_oracle: float | None
    pareto: dict[str, Any]
    measured_by: str
    #: The registered experiment this measurement belongs to. ``None`` means the
    #: file carries no ledger lineage, which ``_load_frontier`` refuses.
    experiment_id: str | None = None
    #: ``sha256:`` over ``content_payload()``. ``None`` means unsigned.
    content_digest: str | None = None

    def content_payload(self) -> dict[str, Any]:
        """Everything the digest covers: every field except the digest itself."""
        payload = self.to_dict()
        payload.pop("content_digest", None)
        return payload

    def compute_digest(self) -> str:
        """The digest this evidence should carry, from its own content."""
        canonical = json.dumps(
            self.content_payload(), sort_keys=True, separators=(",", ":")
        )
        return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def signed(self) -> FrontierEvidence:
        """A copy carrying the digest of its own content. Used by the producer."""
        unsigned = replace(self, content_digest=None)
        return replace(unsigned, content_digest=unsigned.compute_digest())

    def to_dict(self) -> dict[str, Any]:
        return {
            "corpus": self.corpus,
            "count": self.count,
            "seed": self.seed,
            "base_rate": self.base_rate,
            "scores": dict(self.scores),
            "degenerate": self.degenerate,
            "reason": self.reason,
            "best": self.best,
            "best_model": self.best_model,
            "median": self.median,
            "spread": self.spread,
            "order_free_baseline": self.order_free_baseline,
            "phi_oracle": self.phi_oracle,
            "pareto": dict(self.pareto),
            "measured_by": self.measured_by,
            "experiment_id": self.experiment_id,
            "content_digest": self.content_digest,
        }

    @classmethod
    def from_dict(cls, payload: Any) -> FrontierEvidence:
        return cls(
            corpus=str(payload["corpus"]),
            count=int(payload["count"]),
            seed=int(payload["seed"]),
            base_rate=float(payload["base_rate"]),
            scores={str(k): float(v) for k, v in payload["scores"].items()},
            degenerate=bool(payload["degenerate"]),
            reason=str(payload["reason"]),
            best=_optional_float(payload.get("best")),
            best_model=payload.get("best_model"),
            median=_optional_float(payload.get("median")),
            spread=_optional_float(payload.get("spread")),
            order_free_baseline=_optional_float(payload.get("order_free_baseline")),
            phi_oracle=_optional_float(payload.get("phi_oracle")),
            pareto=dict(payload.get("pareto", {})),
            measured_by=str(payload["measured_by"]),
            experiment_id=_optional_str(payload.get("experiment_id")),
            content_digest=_optional_str(payload.get("content_digest")),
        )


def _optional_float(value: Any) -> float | None:
    """``None`` stays ``None``: an unmeasured figure never becomes 0.0."""
    return None if value is None else float(value)


def _optional_str(value: Any) -> str | None:
    """``None`` and the empty string both mean absent, never a usable value."""
    return None if value is None or str(value) == "" else str(value)


def load_frontier(path: Path | None = None) -> tuple[FrontierEvidence | None, str]:
    """Read the frontier evidence file, or say precisely why there is none.

    The baseline suite is offline research code and may use numpy (ADR-0008);
    a runtime module may never import it, and this gate is a runtime module —
    ``tests/test_repository_structure.py`` enforces that in both directions. So
    research *measures* and writes data, and the gate *consumes* it, which is the
    Stage 0 hub/model boundary applied to the gate itself.

    Evidence whose (corpus, count, seed) does not match what this gate measured
    is refused rather than quoted: a figure from a different split is not a
    weaker answer to this criterion, it is an answer to a different question.
    """
    # Resolved at call time, not bound as a default: a test that redirects the
    # evidence file must be able to, and a default would silently ignore it.
    path = FRONTIER_PATH if path is None else path
    if not path.is_file():
        return None, (
            f"no frontier evidence at {path.name}: run "
            "`python -m pocketsec.stage2.research.cli frontier` to measure the "
            "baseline suite offline. An unmeasured criterion is not a satisfied one"
        )
    try:
        evidence = FrontierEvidence.from_dict(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return None, f"frontier evidence at {path.name} is unreadable: {exc}"
    if (evidence.corpus, evidence.count, evidence.seed) != (
        GATE_CORPUS,
        GATE_COUNT,
        TEST_SEED,
    ):
        return None, (
            f"frontier evidence was measured on {evidence.corpus} count="
            f"{evidence.count} seed={evidence.seed}, but this gate measures "
            f"{GATE_CORPUS} count={GATE_COUNT} seed={TEST_SEED}; a figure from "
            "another split answers a different question and is refused"
        )
    unauthentic = frontier_provenance_refusal(evidence)
    if unauthentic:
        return None, unauthentic
    return evidence, ""


def frontier_provenance_refusal(evidence: FrontierEvidence) -> str:
    """Empty when the evidence proves where it came from; the reason otherwise.

    Three independent checks, because this one gitignored file decides G2.1 and
    G2.2 — the criteria that carry ADR-0010's rejected central result — and the
    only validation it used to get was that its (corpus, count, seed) matched
    (S2-AUTH-02). A stale run, a merge, a mistaken ``cp`` or a session under
    pressure to make the gate green could convert that rejection into a PASS
    with no diff to review.
    """
    if evidence.content_digest is None:
        return (
            "frontier evidence carries no content_digest, so nothing distinguishes "
            "a measured file from a hand-written one; re-measure with `python -m "
            "pocketsec.stage2.research.cli frontier`"
        )
    expected = evidence.compute_digest()
    if evidence.content_digest != expected:
        return (
            f"frontier evidence does not match its own digest (carries "
            f"{evidence.content_digest[:19]}…, content hashes to {expected[:19]}…): "
            "the file was edited after it was measured"
        )
    if evidence.experiment_id is None:
        return (
            "frontier evidence carries no experiment_id, so it has no lineage in "
            "the append-only ledger; a measurement nobody registered is not "
            "evidence this gate can quote"
        )
    try:
        parse_experiment_id(evidence.experiment_id)
    except (ValueError, ContractError) as exc:
        return f"frontier experiment_id {evidence.experiment_id!r} does not parse: {exc}"
    try:
        registered = {entry.experiment_id for entry in ExperimentRegistry(REGISTRY_PATH).all()}
    except (OSError, ValueError, ContractError) as exc:  # pragma: no cover - IO
        return f"cannot read {REGISTRY_PATH.name} to verify the frontier lineage: {exc}"
    if evidence.experiment_id not in registered:
        return (
            f"frontier experiment_id {evidence.experiment_id!r} is not in "
            f"{REGISTRY_PATH.name}; the ledger is append-only and hash-chained, and a "
            "figure that is not in it has no provenance the gate can check"
        )
    if not _names_a_producer(evidence.measured_by):
        return (
            f"frontier measured_by {evidence.measured_by!r} is not a "
            "'module:function' naming a Stage 2 research producer, so the "
            "provenance the gate would print names nothing"
        )
    return ""


def _names_a_producer(measured_by: str) -> bool:
    """Is ``measured_by`` a ``module:function`` inside the research package?

    Deliberately a *shape* check and not an import. This gate must run under a
    bare ``pip install -e .`` with no numpy, and importing the named module to
    confirm it exists would both break that and open exactly the dynamic-import
    hole the AST seam checks cannot see. The shape rule is the same one
    ``MeasuredCost`` applies, plus the requirement that the producer live in the
    package that is allowed to measure this.
    """
    module_name, separator, attribute = measured_by.partition(":")
    if not separator or not attribute.strip() or not module_name.strip():
        return False
    return module_name.startswith("pocketsec.stage2.research")

