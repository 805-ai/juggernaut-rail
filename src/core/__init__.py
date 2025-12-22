"""
JUGGERNAUT RAIL - Core Module
Cryptographic AI Governance Infrastructure

Patents Referenced:
- Application 19/240,581: Blockchain-Based Dynamic Consent Management
- CDT (Consent DNA Token) Provisional Patents
- Zero-Multiplier Veto Architecture Patent

(c) 2025 FinalBoss Tech / Abraham Manzano
"""

from .cdt import ConsentDNAToken, CDTGenerator, CDTValidator
from .receipt import GovernanceReceipt, ReceiptChain, ReceiptGenerator
from .veto import VetoVector, ZeroMultiplierVeto, VetoTrigger
from .policy import PolicyState, PolicyEvaluator, PolicyStore
from .epoch import EpochManager, GlobalEpoch

__all__ = [
    "ConsentDNAToken",
    "CDTGenerator",
    "CDTValidator",
    "GovernanceReceipt",
    "ReceiptChain",
    "ReceiptGenerator",
    "VetoVector",
    "ZeroMultiplierVeto",
    "VetoTrigger",
    "PolicyState",
    "PolicyEvaluator",
    "PolicyStore",
    "EpochManager",
    "GlobalEpoch",
]
