# results/

Benchmark result records (`BenchmarkResult.to_dict()` as JSON), one file per
experiment id.

Contents are git-ignored; the directory and this file are tracked. Results are
retained, never rewritten — see `docs/reproducibility-policy.md` section 7. A
result whose `environment.is_reproducible` is false is still kept, with its
caveats attached.
