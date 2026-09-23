# models/

- `experimental/` — learned model states under evaluation.
- `compiled/` — knowledge compiled to cheap executable detectors or transitions
  (the Stage 0 JIT direction, H4).

Compiled artifacts must retain the lineage needed to **demote** them back to the
learner when their false-positive rate, calibration or environmental validity
deteriorates. Compilation without a decompilation path is out of scope.

Contents are git-ignored; structure is tracked.
