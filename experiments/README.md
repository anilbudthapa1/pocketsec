# experiments/

`registry.jsonl` is the append-only experiment ledger (D0.4). Unlike the other
artifact stores it **is** tracked in git.

- Experiment ids are immutable and never reused.
- Entries are digest-chained; editing history breaks the chain and
  `verify_integrity()` detects it. The Stage 0 gate runs that check.
- There is no update and no delete API. Refuted experiments, counterexamples and
  negative results stay.
