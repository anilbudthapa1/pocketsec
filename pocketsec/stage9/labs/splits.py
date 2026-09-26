"""The compiled corpus splits every Stage 9 fitness number is measured on (spec §4.6).

Stage 9's search is only as honest as the data it is scored on, and the repository has
already been fooled three ways by its own corpora. This module exists so that every
split Stage 9 uses is compiled one way, audited the same way, and identified by a
content digest rather than by a name:

* **One fresh ``Stage1Pipeline`` per variant.** Stage 1 carries lineage state across
  scenarios, so a shared pipeline would let one split warm the novelty engine that
  scores another (``planning/MEMORY.md`` corpus trap). ``compile_scenarios`` builds a
  pipeline, replays ``run_scenario(s, offset=i)`` and encodes with Stage 2's own
  ``dataset._encode`` — the ``stage2/gate_measures.py`` precedent — so Stage 9's
  datasets are byte-identical to Stage 2's for the same input.
* **Identity reuse is counted, not assumed away.** A corpus that reuses a process
  identity between sessions silently erases its own signal (the retracted Stage 2
  result). ``identities_reused_across_sessions`` is computed from
  ``transition.actor.identity`` and an ``EvaluationSuite`` refuses a variant where it
  is not 0. An ARGUS attack that inserts actors must keep it at 0.
* **Saturation is checked before any comparison is believed** (ADR-0010, ADR-0120).
  ``stage9_saturation`` defers to Stage 3's guard and adds one Stage 9 refusal: a
  split on which the zero-parameter Φ-oracle already reaches the ceiling cannot show
  that anything beats it (``PHI_ORACLE_AT_CEILING``).

What this module refuses to do: it never shares a pipeline between variants, never
names a split by anything but its content digest when identity matters, and never
reports a compile time without the load average it was taken under — the host is
shared with other waves, so a bare wall-clock figure would be a contended guess.
"""

from __future__ import annotations

import hashlib
import statistics
import time
from collections.abc import Mapping, Sequence
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from typing import Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.labs.ambiguous_corpus import AMBIGUOUS_VERSION, build_ambiguous_corpus
from pocketsec.stage1.labs.corpus import Scenario
from pocketsec.stage1.pipeline import ScenarioResult, Stage1Pipeline
from pocketsec.stage2.dataset import (
    Stage2Dataset,
    Stage2Sample,
    _encode,  # Stage 2's own encoder (gate_measures precedent)
)
from pocketsec.stage2.encoder.ssir_encoder import ENCODER_VERSION, FEATURE_WIDTH
from pocketsec.stage3.labs.ablation import saturation_guard
from pocketsec.stage6.resources import loadavg

__all__ = [
    "CLEAN",
    "CORPUS",
    "HEADROOM_COUNT",
    "HELDOUT_SEED",
    "MAX_COMPILE_WORKERS",
    "PHI_ORACLE_CEILING",
    "SATURATED_COUNT",
    "SPLITS_VERSION",
    "TRAIN_SEED",
    "CompiledVariant",
    "SaturationCheck",
    "SplitKey",
    "compile_scenarios",
    "compile_variant",
    "compile_variants",
    "dataset_digest",
    "session_content_digest",
    "split_key",
    "stage9_saturation",
]

SPLITS_VERSION = "stage9-splits.1.0.0"

#: Stage 1's ambiguous corpus is the only one in the repository with measured headroom
#: (spec M0.2: Φ-oracle 1.0000 at count 60, 0.5975 at count 240).
CORPUS = "ambiguous"
#: Search, selection and held-out evaluation all run here (ADR-0084).
HEADROOM_COUNT = 240
#: Saturated: used only to place the Φ-oracle and the TCN on one plot and show the trap.
SATURATED_COUNT = 60
TRAIN_SEED = 3
HELDOUT_SEED = 11
#: Chosen, not measured: 4 of this host's 8 cores, leaving room for the other waves.
MAX_COMPILE_WORKERS = 4

#: The attack id of the unattacked variant.
CLEAN = "clean"
#: The attack version recorded on a clean variant, which no transform touched.
_NO_ATTACK_VERSION = "none"

#: A Φ-oracle AP at or above this sits at the ceiling: nothing can beat it by the
#: +0.02 margin every comparison in this stage requires. Chosen, not measured.
PHI_ORACLE_CEILING = 0.99

#: Rounding applied to every float before it is digested, so a digest names content,
#: not the last bit of a float that crossed a process boundary. Chosen.
_DIGEST_DECIMALS = 9


@dataclass(frozen=True, slots=True)
class SplitKey:
    """Everything that decides a variant's content, and nothing that does not."""

    corpus: str
    count: int
    seed: int
    attack_id: str  # CLEAN or an ArgusAttack id
    corpus_version: str
    encoder_version: str
    attack_version: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "corpus": self.corpus,
            "count": self.count,
            "seed": self.seed,
            "attack_id": self.attack_id,
            "corpus_version": self.corpus_version,
            "encoder_version": self.encoder_version,
            "attack_version": self.attack_version,
        }


@dataclass(frozen=True, slots=True)
class CompiledVariant:
    """One compiled split (clean or attacked), with the audit figures that vouch for it."""

    key: SplitKey
    dataset: Stage2Dataset
    content_digest: str
    identities_reused_across_sessions: int
    median_peak_abs_dphi_by_class: tuple[float, float]  # (benign, malicious)
    compile_seconds: float
    loadavg_before: tuple[float, float, float]
    loadavg_after: tuple[float, float, float]
    #: Kept only on the serial path with ``keep_results=True``: the Stage 6 exit needs
    #: ``ScenarioResult``s, and shipping them back from worker processes would cost
    #: memory nothing else uses.
    results: tuple[ScenarioResult, ...] = ()

    @property
    def audit_failures(self) -> tuple[str, ...]:
        """Why this variant must not be scored, or ``()``. Checked by every suite."""
        failures: list[str] = []
        if self.identities_reused_across_sessions != 0:
            failures.append(
                f"{self.identities_reused_across_sessions} actor identities reused across "
                "sessions: Stage 1 carries lineage state between them and the signal erases"
            )
        benign, malicious = self.median_peak_abs_dphi_by_class
        if not (benign > 0.0 and malicious > 0.0):
            failures.append(
                f"median peak |dPhi| by class is ({benign}, {malicious}); both must be > 0 "
                "or the per-lineage signal is saturated away (the retracted Stage 2 result)"
            )
        return tuple(failures)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key.to_dict(),
            "content_digest": self.content_digest,
            "sessions": len(self.dataset),
            "events": self.dataset.transition_count,
            "base_rate": self.dataset.base_rate,
            "identities_reused_across_sessions": self.identities_reused_across_sessions,
            "median_peak_abs_dphi_by_class": list(self.median_peak_abs_dphi_by_class),
            "compile_seconds": self.compile_seconds,
            "loadavg_before": list(self.loadavg_before),
            "loadavg_after": list(self.loadavg_after),
            "audit_failures": list(self.audit_failures),
            "timing_note": "host-contended wall clock, not a device measurement",
        }


def split_key(*, count: int, seed: int, attack_id: str = CLEAN) -> SplitKey:
    """The key of one ambiguous-corpus variant; an unknown attack id is refused."""
    _require_count_and_seed(count, seed)
    version = _NO_ATTACK_VERSION if attack_id == CLEAN else _attack_version(attack_id)
    return SplitKey(
        corpus=CORPUS,
        count=count,
        seed=seed,
        attack_id=attack_id,
        corpus_version=AMBIGUOUS_VERSION,
        encoder_version=ENCODER_VERSION,
        attack_version=version,
    )


def _require_count_and_seed(count: int, seed: int) -> None:
    if isinstance(count, bool) or not isinstance(count, int) or count < 1:
        raise ContractError(f"count must be a positive int, got {count!r}")
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ContractError(f"seed must be an int, got {seed!r}")


def _attack_version(attack_id: str) -> str:
    # Imported here, not at module level: the adversary imports fitness, and fitness
    # imports this module, so a module-level import would be a cycle.
    from pocketsec.stage9.argus.adversary import ARGUS_VERSION, attack_by_id

    attack_by_id(attack_id)  # refuses an unknown id before any compile work
    return ARGUS_VERSION


def _attacked(scenarios: Sequence[Scenario], *, attack_id: str, seed: int) -> tuple[Scenario, ...]:
    if attack_id == CLEAN:
        return tuple(scenarios)
    from pocketsec.stage9.argus.adversary import attack_by_id  # cycle-free, see above

    return attack_by_id(attack_id).apply(scenarios, seed=seed)


# --- digests ------------------------------------------------------------------------------


def _step_text(sample: Stage2Sample) -> str:
    parts: list[str] = []
    for step in sample.steps:
        features = ",".join(repr(round(value, _DIGEST_DECIMALS)) for value in step.features)
        parts.append(
            f"{step.actor_slot}|{step.relation}|{step.state_delta_mask}|"
            f"{round(step.delta_phi, _DIGEST_DECIMALS)!r}|{features}"
        )
    return ";".join(parts)


def session_content_digest(sample: Stage2Sample) -> str:
    """The digest of one session's content, **without** its id.

    Sample ids are per-generator indexes (``amb-eval-0000`` exists at every seed), so
    an id is an identity only within one split. Contamination is therefore detected by
    content: a copied session keeps its content whatever it is renamed to.
    """
    text = f"{sample.label}#{_step_text(sample)}"
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def dataset_digest(dataset: Stage2Dataset) -> str:
    """sha256 over (sample_id, label, actor_slot, relation, state_delta_mask, ΔΦ, features).

    Floats are rounded to 9 decimals first. Identity never enters: ``actor_slot`` is a
    session-local index, not an identity (ADR-0007).
    """
    digest = hashlib.sha256()
    for sample in dataset.samples:
        digest.update(f"{sample.sample_id}#{sample.label}#{_step_text(sample)}\n".encode())
    return "sha256:" + digest.hexdigest()


# --- audit figures ------------------------------------------------------------------------


def _identities_reused(results: Sequence[ScenarioResult]) -> int:
    sessions_by_identity: dict[str, int] = {}
    for result in results:
        for identity in {transition.actor.identity for transition in result.transitions}:
            sessions_by_identity[identity] = sessions_by_identity.get(identity, 0) + 1
    return sum(1 for sessions in sessions_by_identity.values() if sessions > 1)


def _median_peak_abs_dphi(dataset: Stage2Dataset) -> tuple[float, float]:
    peaks: dict[int, list[float]] = {0: [], 1: []}
    for sample in dataset.samples:
        peak = max((abs(step.delta_phi) for step in sample.steps), default=0.0)
        peaks.setdefault(sample.label, []).append(peak)
    # An empty class has no signal to measure; 0.0 makes the audit refuse it.
    return (
        statistics.median(peaks[0]) if peaks[0] else 0.0,
        statistics.median(peaks[1]) if peaks[1] else 0.0,
    )


# --- compilation --------------------------------------------------------------------------


def compile_scenarios(
    scenarios: Sequence[Scenario], *, key: SplitKey, keep_results: bool = False
) -> CompiledVariant:
    """Replay ``scenarios`` through one FRESH Stage 1 pipeline and encode them.

    ``run_scenario(s, offset=i)`` then ``stage2.dataset._encode(result, i)`` — the
    same two calls ``stage2.gate_measures.compile_split`` makes, so nothing here is a
    re-implementation of either stage.
    """
    before = loadavg()
    started = time.perf_counter()
    pipeline = Stage1Pipeline()
    results = tuple(
        pipeline.run_scenario(scenario, offset=index) for index, scenario in enumerate(scenarios)
    )
    samples = tuple(
        sample
        for sample in (_encode(result, index) for index, result in enumerate(results))
        if sample is not None
    )
    dataset = Stage2Dataset(
        name=f"s9-{key.corpus}-{key.count}-{key.seed}-{key.attack_id}",
        corpus=key.corpus,
        seed=key.seed,
        encoder_version=ENCODER_VERSION,
        feature_width=FEATURE_WIDTH,
        samples=samples,
    )
    reused = _identities_reused(results)
    medians = _median_peak_abs_dphi(dataset)
    digest = dataset_digest(dataset)
    elapsed = time.perf_counter() - started
    return CompiledVariant(
        key=key,
        dataset=dataset,
        content_digest=digest,
        identities_reused_across_sessions=reused,
        median_peak_abs_dphi_by_class=medians,
        compile_seconds=elapsed,
        loadavg_before=before,
        loadavg_after=loadavg(),
        results=results if keep_results else (),
    )


def compile_variant(
    *, count: int, seed: int, attack_id: str = CLEAN, keep_results: bool = False
) -> CompiledVariant:
    """Build the ambiguous corpus at (count, seed), apply one attack, compile it."""
    key = split_key(count=count, seed=seed, attack_id=attack_id)
    # ``split="eval"`` at every seed: Stage 1's "train" split contains no malicious
    # session at all, so it could not score anything.
    scenarios = build_ambiguous_corpus(count=count, seed=seed, split="eval")
    return compile_scenarios(
        _attacked(scenarios, attack_id=attack_id, seed=seed), key=key, keep_results=keep_results
    )


def _compile_worker(count: int, seed: int, attack_id: str) -> CompiledVariant:
    """The process-pool entry point. It takes ids only, never attack objects or data.

    Rebuilding the corpus from (count, seed) inside the worker is what makes the
    parallel path produce the same digests as the serial one: nothing but three
    scalars crosses the process boundary on the way in.
    """
    return compile_variant(count=count, seed=seed, attack_id=attack_id)


def compile_variants(
    *, count: int, seed: int, attack_ids: Sequence[str], workers: int = MAX_COMPILE_WORKERS
) -> tuple[CompiledVariant, ...]:
    """Compile several variants of one split, in ``attack_ids`` order.

    ``workers == 1`` compiles serially in this process; more uses a process pool of at
    most ``MAX_COMPILE_WORKERS``. Every id is validated before any work starts.
    """
    if isinstance(workers, bool) or not isinstance(workers, int):
        raise ContractError(f"workers must be an int, got {workers!r}")
    if not 1 <= workers <= MAX_COMPILE_WORKERS:
        raise ContractError(f"workers must be in 1..{MAX_COMPILE_WORKERS}, got {workers}")
    ids = tuple(attack_ids)
    if not ids:
        raise ContractError("compile_variants needs at least one attack id")
    if len(set(ids)) != len(ids):
        raise ContractError(f"attack ids repeat: {ids}")
    for attack_id in ids:
        split_key(count=count, seed=seed, attack_id=attack_id)
    if workers == 1 or len(ids) == 1:
        return tuple(compile_variant(count=count, seed=seed, attack_id=a) for a in ids)
    with ProcessPoolExecutor(max_workers=min(workers, len(ids))) as pool:
        futures = [pool.submit(_compile_worker, count, seed, attack_id) for attack_id in ids]
        return tuple(future.result() for future in futures)


# --- saturation ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SaturationCheck:
    """Whether a split can show that anything beats anything, and what decided it."""

    degenerate: bool
    reason: str
    phi_oracle_at_ceiling: bool
    stage3_verdict: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "degenerate": self.degenerate,
            "reason": self.reason,
            "phi_oracle_at_ceiling": self.phi_oracle_at_ceiling,
            "stage3_verdict": dict(self.stage3_verdict),
        }


def stage9_saturation(
    scores: Mapping[str, float | None], *, phi_oracle: float | None, order_free: float | None
) -> SaturationCheck:
    """Stage 3's saturation guard, plus the Φ-oracle ceiling refusal.

    ``scores`` are the APs of every scorer compared on the split (the Φ-oracle's among
    them). Degenerate if Stage 3's guard says so **or** ``phi_oracle >= 0.99``: on such a
    split a claim to beat the Φ-oracle is a measurement error by definition (spec §8.6).
    An unmeasured Φ-oracle is not at the ceiling — and not evidence of headroom either;
    Stage 3's guard still decides.
    """
    verdict = saturation_guard(list(scores.values()), order_free=order_free)
    at_ceiling = phi_oracle is not None and phi_oracle >= PHI_ORACLE_CEILING
    if at_ceiling:
        reason = (
            f"PHI_ORACLE_AT_CEILING: the zero-parameter Φ-oracle reaches {phi_oracle:.4f} "
            f">= {PHI_ORACLE_CEILING}; nothing can beat it here. Stage 3 guard: {verdict.reason}"
        )
    else:
        reason = verdict.reason
    return SaturationCheck(
        degenerate=verdict.degenerate or at_ceiling,
        reason=reason,
        phi_oracle_at_ceiling=at_ceiling,
        stage3_verdict=verdict.to_dict(),
    )
