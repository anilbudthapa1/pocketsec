# datasets/

Evaluation and training splits, plus their `.meta.json` provenance blocks.

Every split declares a name, a version and a SHA-256. `SequenceDataset.load_jsonl`
verifies the digest and refuses to proceed on a mismatch: results computed over
different bytes are not comparable.

Contents are git-ignored. The Stage 0 smoke fixture is generated deterministically
by `pocketsec.stage0.benchmark.fixtures` and is **synthetic**.
