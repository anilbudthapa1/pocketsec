# ADR-0041 — The executor accepts exactly one type; `OperatorSpec` is catalog-only; the gate is the one extra file that may name the executor

- **Status:** Accepted
- **Date:** 2026-09-26
- **Stage:** 5
- **Deciders:** Stage 5 integrator (the operators and executor packages built the construction)
- **Supersedes / superseded by:** amends spec §5.1 rule 4

## Context

The lead's first non-negotiable: only typed operators reach privilege, enforced by
construction. Three constructions carry it:

1. `TransactionalExecutor.execute(operator: DefensiveOperator, ...)` — the annotation is
   exactly `DefensiveOperator` (trust rule T4).
2. `OperatorSpec` cannot be constructed outside `operators/catalog.py`: `__post_init__`
   requires the module-private `_CATALOG_TOKEN`, and `DefensiveOperator.__post_init__`
   requires its `spec` to be a `CATALOG` member **by identity**.
3. An argument vector is assembled only from the closed `ArgvAtom` union
   (`LiteralAtom | FieldAtom`); no field holds a command, a fragment or a template.

Two integration findings forced this ADR.

**Finding 1 — the executor had no runtime backstop at its entry.** `execute` read
`operator.argv()` before anything checked the argument's type, so a `SimpleNamespace` that
defined its own `argv` reached executor code, and `copy.deepcopy` of a real operator — which
never re-runs `__post_init__` — carried a structurally perfect, non-identical spec past the
constructor. SENTINEL's schema check denied both, but only after PREPARE, and a string
arrived as an incidental `AttributeError` rather than a typed refusal. The integrator added
`_refuse_untyped` at the entry: `TypeError` unless the operator is a `DefensiveOperator` and
the token a `CapabilityToken`, and `ContractError` unless the spec is a `CATALOG` member by
identity. Measured by G5.2(b): **5 of 5** forged arguments (str, dict, `SimpleNamespace` with
its own `argv`, a structurally equal `OperatorSpec`, a deep-copied operator) raise at a real
executor, with **0** `host.apply` calls during them.

**Finding 2 — spec §5.1 rule 4 made the stage's own gate unbuildable.** Rule 4 permitted the
name `TransactionalExecutor` only under `executor/` and `recovery/`; spec §6 G5.2(a) requires
the gate to evaluate `get_type_hints(TransactionalExecutor.execute)`, and the labs had to
run "through the real executor". Three packages reported it independently.

## Decision

1. The executor entry refuses anything but a catalog-bound `DefensiveOperator` and a
   `CapabilityToken`, before reading any attribute of either (`executor/transactional.py:_refuse_untyped`).
2. **Rule 4 is amended to a single-file exemption:** `pocketsec/stage5/gate.py` may import
   `TransactionalExecutor`, and nothing else outside `executor/` and `recovery/` may. The labs
   stay forbidden: `labs/toctou.py`, `labs/baselines.py`, `labs/fifty_experiments.py` and
   `resources.py` take an executor *factory* from their caller and cannot assemble one.
3. **Compensating rule:** nothing under `pocketsec/stage5/` imports `pocketsec.stage5.gate`
   except `cli.py` and the `gate_*` check modules, so the gate's factories cannot become a
   runtime library.

## Options considered

| Option | Security cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|
| A. Rule 4 as written | none | none | G5.2(a) cannot be written; the gate cannot run any baseline through the executor | makes the gate impossible |
| B. Exempt `labs/` and `gate.py` | a lab fixture could wire a permissive kernel into an executor and call a race a pass | low | the labs already work through injected factories (0 executor imports needed) | widens the permission for nothing |
| C. Export a factory from `executor/` under another name | the permission exists but is invisible to the rule | low | would pass the boundary test while defeating it | hides the exemption instead of stating it |
| **D. One-file exemption + compensating import rule (chosen)** | the gate can construct executors; nothing else can | low | boundary tests pass, including the new `test_the_executor_exemption_is_one_file_and_it_is_not_a_library` | — |

## Consequences

**Accepted costs.** One more file in the privileged import set. The gate module is
therefore reviewed as privileged code.

**Bounded state.** Unchanged.

**Reversibility.** Delete the gate's factories and the exemption line in
`tests/test_stage5_boundary.py`.

**Authority.** Nothing moves towards model authority; the entry guard removes a path.

## Verification

- `pocketsec-stage5 gate`, G5.2: "(b) 5 of 5 forged arguments ... raised at a real executor,
  host.apply calls during them 0"
- `tests/test_stage5_gate.py::test_g5_2_fails_when_the_executor_entry_stops_refusing` — with
  `_refuse_untyped` patched out, G5.2 fails.
- `tests/test_stage5_gate.py::test_the_executor_entry_refuses_a_deep_copied_operator`
- `tests/test_stage5_boundary.py::test_only_the_executor_and_recovery_import_the_executor`
  and `::test_the_executor_exemption_is_one_file_and_it_is_not_a_library`

## Prior art

No novelty claim is made.

## Fix-wave addendum — 2026-09-26, Stage 5 fix wave

- **The entry guard is recorded as a tested runtime check, not a construction** (finding
  F5-honesty). Decision 1 stands. But its first Context paragraph calls the incidental
  `AttributeError` "the defect", and P1's named test
  (`tests/test_stage5_executor.py::test_a_string_cannot_reach_the_executor`) still accepted
  `AttributeError`. So with `_refuse_untyped` deleted, P1's cited evidence stayed green. The
  test now demands a `TypeError` or `ContractError` whose innermost frame is
  `_refuse_untyped`, adds an impostor that carries its own `argv` and a deep-copied
  operator, and asserts zero `host.apply` calls. The assurance table records P1 as TESTED,
  with `SENSITIVITY_EDITS['P1']` deleting the guard. The out-of-package run passed its
  control and failed under the edit this wave. G5.2(b) already failed with the guard patched
  out (`test_g5_2_fails_when_the_executor_entry_stops_refusing`); G5.13 now probes it too.
- **The privileged import graph no longer loads the gate apparatus** (finding S5-SEC-11).
  `OperatorSpec.__post_init__` and `operators/catalog.py` read `UNMAPPED` and the D3FEND
  id pattern from `operators/d3fend.py`, which imports `stage0.gate`. Importing the
  executor, SENTINEL and the catalog therefore loaded the experiment registry and the
  prior-art ledger. Both names now live in `operators/d3fend_ids.py`, which imports only
  `re`. `tests/test_stage5_boundary.py::test_the_privileged_import_graph_loads_no_gate_and_no_d3fend_adapter`
  checks it in a fresh interpreter.
