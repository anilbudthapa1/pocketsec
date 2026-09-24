# ADR-0127 — Evidence that decides a gate criterion must carry its own provenance

- **Status:** Accepted
- **Date:** 2026-09-25
- **Stage:** 2
- **Deciders:** Stage 2 defect-repair wave, integrator
- **Supersedes / superseded by:** none. Extends ADR-0113 (the gate is code) and
  applies Stage 0's `EvidenceRef` rule to the gate's own input.

## Context

Three acceptance criteria — G2.1, G2.2, and G2.12's degeneracy clause — were
decided entirely by `results/stage2-frontier.json`. That file is gitignored
(`.gitignore:15`, `results/*`), and `_load_frontier`'s only validation was that
its `(corpus, count, seed)` triple matched the gate's.

Reproduced this session (S2-AUTH-02). A hand-written file with nine baselines at
0.99, `pareto.dominated: []`, `degenerate: false` and
`measured_by: "totally.legit:measure"` loaded with an **empty refusal** through
the production path (`gate.FRONTIER_PATH`, the default used by
`Stage2GateContext.build` and therefore by `pocketsec-stage2 gate`), and both
`_baselines_and_pareto` and `_latent_frontier` returned `passed=True`. The gate
then printed the file's own `measured_by` string as provenance.

That converts the project's central rejected result — ADR-0010, the learned core
is dominated by a zero-parameter scorer — into a PASS, with **zero privilege
required and no review surface**: the file is untracked, so there is no diff.

Worse, the one line that would have contradicted the forged PASS was hardcoded.
G2.1's detail asserted unconditionally that "the learned core is beaten on cost by
a zero-parameter scorer … FAILED, not restated", so a *passing* check emitted a
sentence disagreeing with its own verdict. Boilerplate cannot be a signal in
either direction.

The machinery to prevent this already existed and this one file bypassed it:
`experiments/registry.jsonl` is append-only and hash-chained
(`entry_digest`/`previous_digest`), and `EvidenceRef`
(`stage0/contracts/common.py`) exists specifically so "a later stage can prove
the bytes it reads are the bytes the prediction was made from".

## Decision

`FrontierEvidence` carries its own provenance and `_load_frontier` verifies it.
Four independent refusals, each with its own reason string:

1. **`content_digest`** — `sha256:` over the canonical payload of every other
   field. Absent, or not matching the content, is a refusal. A stale run, a
   merge, a mistaken `cp` or a hand edit all fail here.
2. **`experiment_id`** — must parse, and must be a row in
   `experiments/registry.jsonl`. A measurement nobody registered has no lineage
   the gate can check.
3. **`measured_by`** — must be a `module:function` inside
   `pocketsec.stage2.research`. Deliberately a *shape* check and not an import:
   the gate must run under a bare `pip install -e .` with no numpy, and importing
   the named module would both break that and open a dynamic-import hole the AST
   seam checks cannot see.
4. The existing `(corpus, count, seed)` check stays, and is now one of four
   rather than the only one.

`research.cli measure_frontier` returns `.signed()` evidence and registers the
measurement. Re-measuring the same split reuses the existing row rather than
appending a duplicate: the registry records measurements, not invocations. The
row written this session is `PS-S2-20260924-H8-baseline-frontier-0019`, with
`result_path: results/stage2-frontier.json`.

G2.1's verdict language is derived from `passed` and from `core_dominated`, not
hardcoded. Both G2.1 and G2.2 print the experiment id and the digest prefix
beside `measured_by`, so the provenance in the output is checkable rather than
quoted.

## Consequences

- The default remains fail-safe: a missing, unsigned, unregistered or cross-split
  file yields `UNMEASURED` and a FAIL with a specific reason. The gap closed here
  was authenticity, not presence.
- `python -m pocketsec.stage2.research.cli frontier` must be re-run once after
  this change, because the existing file predates the digest. It was, this
  session, and the gate loads it: digest `sha256:1f49ee7b2395…`, experiment
  `PS-S2-20260924-H8-baseline-frontier-0019`.
- G2.1 and G2.2 still **FAIL**, on the same measured figures as before. Nothing
  about this ADR changes a result; it changes whether a result can be forged.
- A future stage that feeds the gate another measured artefact should carry the
  same three fields. The pattern is now in one place to copy.

## Alternatives considered

**Track `results/stage2-frontier.json` in git.** Would give a diff, and does not
give a digest: a committed file can still be edited in the same commit that
changes the gate's verdict, and the honesty contract is about what the code can
check, not what a reviewer might notice.

**Sign the file with a key.** Rejected as over-engineering for a threat model
where anyone who can write `results/` can also write `pocketsec/`. The digest
plus the hash-chained ledger makes tampering *visible*, which is the property
worth having; it does not claim to make it impossible.
