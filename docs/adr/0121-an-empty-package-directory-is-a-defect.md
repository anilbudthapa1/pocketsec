# ADR-0121 — An empty package directory is a defect, and is deleted

- **Status:** Accepted
- **Date:** 2026-09-25
- **Stage:** 2
- **Deciders:** Stage 2 completion wave, integrator
- **Supersedes / superseded by:** none

## Context

Four directories under `pocketsec/` held nothing at all. Three were not even
packages — no `__init__.py`, no modules, confirmed with `ls -la` this session:

```
pocketsec/stage2/atoms/       (0 files)
pocketsec/stage2/dtl/         (0 files)
pocketsec/stage2/prediction/  (0 files)
pocketsec/stage1/evidence/    (0 files)
```

`stage1/evidence/` was not in the wave's brief and was found by the structural
test written for the other three, which is the point of writing the test rather
than deleting the three by hand.

Three specific harms, not tidiness:

1. **They are importable by accident.** Python treats a directory with no
   `__init__.py` as a namespace package, so `import pocketsec.stage2.dtl`
   succeeds and yields an empty module. A typo resolves instead of failing.
2. **They are invisible to every structural test.** `_runtime_modules()` globs
   `*.py`; a directory with no `.py` file is checked by nothing. The stdlib-only
   rule, the research-boundary rule and the no-debug-print rule all pass
   vacuously over them.
3. **They name subsystems that were decided against.** `atoms/`, `dtl/` and
   `prediction/` read as the intended homes for the Behaviour Atom layer, the
   DTL core and the predictive heads. The Behaviour Atom layer landed in
   `lattice/`, the recurrent DTL core is rejected (ADR-0009, ADR-0010) and the
   heads landed in `predictors/`. An empty directory with the old name is a
   standing invitation to put code in the wrong place, under a name the
   architecture no longer uses.

Separately, the eleven *real* Stage 2 subpackages (`adaptation`, `cache`,
`compile_candidates`, `counterfactual`, `credit`, `lattice`, `predictors`,
`router`, `state`, `uncertainty`, plus `encoder`) shipped as 0-byte
`__init__.py` with no sibling modules. That is the same defect in a milder form
and this wave closed it by filling them, not by deleting them.

## Decision

**The four empty directories are deleted, and
`tests/test_repository_structure.py` forbids their return.** Two new tests:

- `test_no_stage_directory_is_an_orphan` — every directory under a stage is
  either a package (has `__init__.py`) or does not exist.
- `test_stage2_subpackage_exports_something` — each of the twelve Stage 2
  runtime packages contains at least one public class or function.

The second test scans the package **directory**, not `__init__.py`. The
integration plan (§1.1) requires `__init__.py` to stay empty and consumers to
import from the leaf module, exactly as `encoder/` already did; a test written
against `__init__.py` would contradict the layout rule it is meant to protect.

`pocketsec/stage2/__init__.py` is the one exception and is not empty: it declares
the stage's public surface and resolves it lazily through `__getattr__`, so
`import pocketsec.stage2` stays cheap and no subpackage is imported until a name
from it is used.

## Options considered

| Option | Security cost | Resource cost | Complexity | Why not chosen |
|---|---|---|---|---|
| Leave them as placeholders | A typo resolves silently; three directories carry rejected architecture names | none | none | A placeholder nobody filled in two waves is not a plan |
| Add `__init__.py` to each so they become real packages | Same accidental-import problem, now with the structural tests passing on empty modules | none | none | It makes the defect *look* fixed, which is worse |
| Delete them; forbid recurrence by test (**chosen**) | none | none | two tests | — |

## Consequences

**Accepted costs.** None measured. Nothing imported any of the four; `git status`
showed no tracked file inside them, and the full test suite passes without them.

**Bounded state.** Unaffected.

**Reversibility.** `mkdir` restores any of them, and the structural test will fail
the moment one comes back without content — which is the intended behaviour, not
an obstacle. A future subsystem that genuinely needs one of these names creates
it with a module in it.
