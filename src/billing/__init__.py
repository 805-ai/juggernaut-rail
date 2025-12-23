"""
JUGGERNAUT RAIL - Billing Module

Patent Reference: "CDT + Penny Counter for AI-Driven Billing and Compliance"

Penny Counter: Local usage metering for license enforcement and compliance.
- Tracks operations per tenant
- Enforces license tier limits
- Provides audit trail for compliance
- Stripe integration for settlement
"""

from .penny_counter import PennyCounter, UsageRecord, BillingTier
from .metering import MeteringEngine, GasCalculator
from .license import LicenseManager, LicenseKey, LicenseTier
from .stripe_integration import (
    StripeIntegration,
    StripeSettlementService,
    StripeCustomer,
    StripeIntegrationError,
)

__all__ = [
    "PennyCounter",
    "UsageRecord",
    "BillingTier",
    "MeteringEngine",
    "GasCalculator",
    "LicenseManager",
    "LicenseKey",
    "LicenseTier",
    "StripeIntegration",
    "StripeSettlementService",
    "StripeCustomer",
    "StripeIntegrationError",
]
