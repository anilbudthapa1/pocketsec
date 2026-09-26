"""D9.17: the proof-carrying successor, the one Stage 6 exit and the AST boundary.

Empty on purpose (spec §2.1): consumers import the leaf modules, so importing this package
never drags in ``stage6_exit`` (and, through Stage 6's capsule package, Stage 5).
"""

__all__: list[str] = []
