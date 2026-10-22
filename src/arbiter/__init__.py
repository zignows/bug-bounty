"""Árbitro — safe foundation package.

This package currently contains only the deterministic, offline core:
the scope model, the policy engine (scope-as-code), and the finding
state machine. None of it performs network activity or touches any
target. Active execution layers are deliberately not part of this base.
"""

__version__ = "0.0.1"
