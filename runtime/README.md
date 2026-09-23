# runtime/

Reserved for Stage 1+.

This is the stable hub's deployed runtime: telemetry collection, normalisation,
the deterministic rule path, evidence storage and local presentation — the parts
that outlive any particular model.

Empty at Stage 0 deliberately. Stage 0 non-goal: do not optimise eBPF collection
before the event ontology is defined. See `docs/architecture/hub-model-boundary.md`.
