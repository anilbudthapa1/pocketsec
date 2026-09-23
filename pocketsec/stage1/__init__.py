"""Stage 1 — Security Reality Encoding.

SSIR (Security Semantic Intermediate Representation) + the Host Security State
calculus + Behaviour Epochs + the Adaptive Observation Policy.

Stage 1 turns heterogeneous Linux telemetry into a compact, *source-independent*
representation of security-relevant state transitions, and separately maintains
what is currently true about the host.

    SSIR answers: what changed?
    Host Security State answers: what is now true?

Stage 0's measurement rules bind this stage unchanged; Stage 1 extends the
ontology through ``SecurityEventV1.attributes`` and nowhere else.
"""
