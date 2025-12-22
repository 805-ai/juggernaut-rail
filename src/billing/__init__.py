"""
JUGGERNAUT RAIL - Billing Module

Patent Reference: "CDT + Penny Counter for AI-Driven Billing and Compliance"

Key Innovation: Unified compliance + monetization in single rail
- Each governance receipt increments a penny counter
- Usage tracked per-operation, per-purpose, per-partner
- Integrated Stripe settlement
"""

from .penny_counter import PennyCounter, UsageRecord, BillingTier
from .metering import MeteringEngine, GasCalculator
from .stripe_integration import StripeSettlement, InvoiceGenerator

__all__ = [
    "PennyCounter",
    "UsageRecord",
    "BillingTier",
    "MeteringEngine",
    "GasCalculator",
    "StripeSettlement",
    "InvoiceGenerator",
]
