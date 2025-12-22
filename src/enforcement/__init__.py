"""
JUGGERNAUT RAIL - Enforcement Module

The Deterministic Gate: "No Receipt, No Run"

Patent Reference: "The underlying operation is executed only if (1) a receipt
is generated; (2) the receipt is successfully written to a receipt datastore;
and (3) the receipt signature verifies against a stored public key."
"""

from .gate import GovernanceGate, GateDecision, EnforcementResult

__all__ = [
    "GovernanceGate",
    "GateDecision",
    "EnforcementResult",
]
