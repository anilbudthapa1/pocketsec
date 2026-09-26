# ADR-0080 — Stage 9 layout amendments: no research package, no numpy, `ontogenesis/` holds the search, a lazy `__init__`, and no H15

- **Status:** Accepted
- **Date:** 2026-09-26
- **Stage:** 9
- **Deciders:** Stage 9 integrator (decided at spec time, `docs/stage-9-spec.md` §2.1, §2.2, §2.6; written after the integration session)
- **Supersedes / superseded by:** none. Amends the Stage 9 row of `docs/architecture/stage-3-12-integration-plan.md` §1.2 and §5.2.

> Layout and dependency ADR. It fixes where Stage 9 code lives and what it may import. It
> changes no contract.

## Context

The integration plan (§1.2) gives Stage 9 a `research/` package with numpy, named
`research/{search.py,genome_eval.py}`, and pre-assigns hypothesis H15 through ADR-0012, which was never written.

Neither can be used as written:

- `tests/test_repository_structure.py` hard-codes `RESEARCH_PREFIX = "pocketsec/stage2/research/"`.
  ADR-0011 (`RESEARCH_PREFIXES`) was never written, so a numpy import under
  `pocketsec/stage9/research/` fails `test_runtime_has_no_third_party_imports`, and the lead
  forbids editing that file (spec §0, "facts read from code").
- `pocketsec/stage0/hypotheses.py` holds H0–H8. ADR-0012 (H9–H18) was never written, so an
  H15 experiment id would be well-formed and backed by no hypothesis.
- Nothing Stage 9 needs requires gradient descent. The only neural object in the comparison,
  the Stage 2 TCN, enters as registered frontier evidence (spec M0.12), never as code.

The task that built Stage 9 also asked for a `pocketsec/stage9/__init__.py` "exporting the
stage's public surface", while spec §2.1 says that file is empty. Stages 6 and 7 met the same
pair of demands with a lazy `__getattr__` surface that imports nothing at package import.

## Decision

1. **No `research/` package and no numpy anywhere in Stage 9.** The search and the fitness
   evaluation are stdlib modules: `ontogenesis/search.py` and `ontogenesis/fitness.py`.
   `successor/boundary.numpy_or_research_offenders()` and
   `tests/test_stage9_boundary.py::test_stage9_imports_no_research_package_of_any_stage`
   enforce it, and `test_stage9_imports_no_third_party_module` applies
   `test_repository_structure.py`'s AST technique (through
   `stage2.gate_criteria.imported_modules`) to every Stage 9 file.
2. **The seven pre-existing empty directories are filled, not deleted** (ADR-0121), and every
   subpackage `__init__.py` is empty (docstring only). Consumers import leaf modules.
3. **`pocketsec/stage9/__init__.py` is a lazy surface.** It maps 59 public names (spec §3.3's
   nineteen exposed types plus their entry points) to leaf modules and resolves them with
   `importlib.import_module` on first attribute access. Importing `pocketsec.stage9` imports
   no Stage 9, Stage 5 or Stage 6 module (tested in a clean subprocess). `Stage6Exit`, the gate,
   the CLI and the labs are deliberately not on the surface. This adds one entry to
   `successor/boundary._IMPORT_MODULE_EXEMPT` (the root `__init__.py` only; spec §2.2 listed
   two). It is the fourth declared exemption, and it is the one the Stage 6 and 7 precedents
   already carry.
4. **No H15 is minted.** Stage 9 experiment ids use existing hypotheses by meaning: `H5`
   (adaptive state growth and minimisation) for search, MSSC and state sufficiency; `H6`
   (hierarchical reversible forgetting) for CHRONOS; `BASE` for baselines and controls. The gate's
   id is `PS-S9-20260926-H5-ontogenesis-gate-0001`.
5. **Two field names in spec §4.19/§4.20 are renamed** because they contain
   `FORBIDDEN_AUTHORITY_FIELDS` fragments, which spec §2.2 forbids in Stage 9 class and field
   names: `ResourceObservation.cpu_fraction` → `cpu_share` (`fr-action`), and
   `ReproducibilityManifest.stage_gate_commands` → `stage_gate_entrypoints` (`command`). The same
   rule renamed the integrator's G9.3 record to `CoarseningEvidence` (`abstr-action`).

## Options considered

| Option | Security cost | Resource cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|---|
| A. A `stage9/research/` package with numpy, as the plan says | numpy one import away from the endpoint | none offline | low | fails `test_runtime_has_no_third_party_imports` on the real tree (hard-coded `RESEARCH_PREFIX`, spec §0) | forbidden edit to a shared test; ADR-0011 absent |
| B. stdlib-only search (chosen) | none | the interpreter costs ~9x a hand loop (spec M0.8, not re-measured here) | medium | Stage 9's own third-party and research tests pass on the real tree (this session) | chosen |
| C. An empty `__init__.py` | none | none | lowest | does not meet the task's "export the public surface" | superseded by D |
| D. Lazy `__getattr__` surface (chosen) | a dynamic import the AST closure cannot follow; bounded by excluding the exit, gate, CLI and labs | 0 modules imported at package import (measured, this session) | low | 59 names resolve; `pocketsec.stage9` import loads nothing (test) | chosen |
| E. Mint H15 (plan §5.2) | none | none | needs ADR-0012 (never written) and a prior-art entry in the same commit | `set(ledger.entries) == set(HYPOTHESES)` would fail without them | out of this wave's authority |

## Consequences

**Accepted costs.** The search runs in an interpreted IR, about an order of magnitude slower per
event than a hand loop. Work units, not wall clock, are the cost axis, so this does not bias a
comparison.

**Bounded state.** No change to endpoint state. The lazy surface caches nothing.

**Reversibility.** Adding a research package later needs ADR-0011 (never written) and the shared-test edit from
the lead (blocker B9-3).

**Authority.** None moves.

## Verification

`tests/test_stage9_boundary.py` (third-party, research, lazy-surface tests), gate check G9.7
(`numpy_or_research_offenders`, `dynamic_execution_offenders`, `authority_field_offenders`).

## Prior art

None claimed.
