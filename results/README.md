# results/

Benchmark result records (`BenchmarkResult.to_dict()` as JSON), one file per
experiment id.

Contents are git-ignored; the directory and this file are tracked. Results are
retained, never rewritten — see `docs/reproducibility-policy.md` section 7. A
result whose `environment.is_reproducible` is false is still kept, with its
caveats attached.

## `stage2-frontier.json` decides three gate criteria, so it must prove itself

`results/stage2-frontier.json` is not an ordinary result record. It is the
*input* to Stage 2's acceptance gate: G2.1, G2.2 and G2.12's degeneracy clause
are decided by it, and it is what carries ADR-0010's rejected central result into
the verdict. Because this directory is git-ignored there is no diff to review, so
the file has to be checkable on its own terms (ADR-0127).

It therefore carries three provenance fields, and
`pocketsec.stage2.gate_evidence.load_frontier` refuses it without all three:

- `content_digest` — `sha256:` over the canonical payload of every other field.
- `experiment_id` — must parse and must be a row in the append-only, hash-chained
  `experiments/registry.jsonl`.
- `measured_by` — a `module:function` inside `pocketsec.stage2.research`.

Write it only with `python -m pocketsec.stage2.research.cli frontier`, which
signs it and registers the measurement. A hand-edited copy fails its own digest;
an unregistered one has no lineage; and either way the gate reports `UNMEASURED`
with the specific reason rather than quoting the file.
