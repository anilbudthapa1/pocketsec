# ADR-0030 — Stage 4 ships no `research/` package and no third-party import

- **Status:** Accepted
- **Date:** 2026-09-25
- **Stage:** 4
- **Deciders:** Stage 4 integrator
- **Supersedes / superseded by:** none

## Context

ADR-0001 makes the endpoint runtime stdlib-only. ADR-0008 opens one narrow exemption: a
stage's `research/` subpackage may import numpy, because offline research is not endpoint
code, and nothing outside `research/` may import it — enforced in both directions by tests.

The integration plan closes the list of stages that may have `research/`, and **Stage 4 is
not on it**, with the reason stated: bounded-K world enumeration is combinatorial, not
numerical, and must run on the endpoint. Stage 3 faced the identical situation and resolved
it with ADR-0020.

Two mechanical facts make this a decision rather than a note:

- `tests/test_repository_structure.py:79` still reads
  `RESEARCH_PREFIX = "pocketsec/stage2/research/"`. The generalised `RESEARCH_PREFIXES`
  tuple ADR-0011 was pre-assigned to create **was never written**, and that file is not to
  be edited while another wave may be in it.
- The CI `gate` job installs the package bare, with no dev extras. A gate is a runtime
  module, so a third-party import anywhere reachable from `pocketsec/stage4/gate.py` —
  including one deferred inside a function, which an AST walk sees — breaks the gate rather
  than the tests.

**What was measured this session:** 61 modules under `pocketsec/stage4/`, **0** third-party
imports, **0** imports of any `pocketsec.stage*.research*`, **0** imports of
`pocketsec.stage3`, and `pocketsec/stage4/research/` does not exist.

## Decision

**Stage 4 is stdlib-only end to end, including its tests, and it gets its own boundary
test rather than widening Stage 2's.**

1. **No `pocketsec/stage4/research/`, no numpy, no third-party import anywhere** — in the
   runtime, in the labs, or in `tests/test_stage4_*.py`.
2. **Every probability, entropy, divergence and forward-algorithm computation is pure
   Python over `float`, with `math` and `statistics` only.** The §7 baselines were chosen so
   that this is possible: a 2-state HMM forward pass and a categorical Jensen–Shannon over
   at most sixteen worlds are a few dozen lines each, and both are built.
3. **Two named baselines cannot be built and are declared UNMEASURED with this reason.** The
   §42 dynamic Bayesian network and tiny GNN need numerical linear algebra. Fabricating a
   stdlib stand-in and calling it a GNN would be worse than the gap, because a slow or wrong
   baseline flatters the mechanism — `MEMORY.md`'s trap 5 is a detached projection that
   scored 0.55 and 0.94 once fixed.
4. **The rules live in `tests/test_stage4_boundary.py`**, which reimplements for Stage 4 the
   AST technique `tests/test_repository_structure.py` implements for Stages 0–2, and
   **leaves that file untouched.** The import resolver is *imported*, not copied.

## Options considered

| Option | Security cost | Resource cost | Complexity | Why not chosen |
|---|---|---|---|---|
| **A. Stdlib-only, own boundary test** (chosen) | lowest: measured 0 third-party imports across 61 modules, and the gate runs under a bare install | pure-Python arithmetic over at most sixteen worlds; measured peak incident state 29651 B | moderate: a JS divergence and an HMM forward pass had to be written | — |
| B. Add `pocketsec/stage4/research/` under the ADR-0008 exemption | moderate: the exemption widens, and the one-directional check is currently written against a Stage 2 literal, so a Stage 4 research import would be invisible to it | none at runtime | lower: numpy would make the DBN and GNN baselines buildable | The plan's reason stands — the work is combinatorial, not numerical — and the exemption's enforcement does not yet generalise. Widening a boundary whose checker does not cover the new case is how S2-AUTH-01 happened |
| C. Widen `RESEARCH_PREFIX` in `tests/test_repository_structure.py` | none directly | none | lowest | Two waves editing one shared file corrupts both. Stage 3 set the precedent with `tests/test_stage3_boundary.py` |
| D. Build a stdlib DBN and GNN anyway, to fill the §42 table | **high**: a wrong or slow baseline makes the mechanism look better than it is, and the comparison would be published | real, and misleading | high | Trap 5, measured: a detached projection scored 0.55 and 0.94 once fixed. Four of the nine §42 comparisons are declared absent instead, with reasons, in `docs/stage-4-findings.md` |

## Consequences

**Accepted costs.** Four of nine named §42 comparisons are absent — DBN and tiny GNN for this
ADR's reason, provenance-graph scoring and an LLM summarizer because neither exists in this
repository. B2 and B5 are named as **partial** substitutes for the cheap end of the
attribution axis, not as equivalents. That weakens G4.10's coverage, and G4.10 fails for
independent reasons anyway (ADR-0036).

**Bounded state.** Unaffected, and helped: no numpy means no hidden allocator behaviour on a
2 GB host.

**Reversibility.** Adding `research/` later needs this ADR superseded *and* a generalised
`RESEARCH_PREFIXES` check that actually covers the new path, in that order.

**Authority.** No. Fewer dependencies is strictly less supply-chain surface reaching the
endpoint.

## Verification

- `tests/test_stage4_boundary.py::test_stage4_has_no_third_party_imports` — AST over all 61
  modules, allowing only `sys.stdlib_module_names` and `pocketsec`.
- `::test_stage4_never_imports_research_code`, `::test_stage4_never_imports_stage3`,
  `::test_stage4_does_not_hold_a_forbidden_directory[research]`.
- `::test_a_relative_boundary_violation_is_resolved_to_an_absolute_path` — ten committed
  negative fixtures, because a relative import was invisible to two checkers at once
  (S2-AUTH-01).
- The gate runs under a bare install; nothing it reaches imports a third-party module even
  lazily.

## Prior art

No novelty claim is made. Stage 4's ledger bindings are H3 and H7, both `NOT_REVIEWED`.
