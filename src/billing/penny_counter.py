"""
Penny Counter Implementation

Patent Reference: "CDT + Penny Counter for AI-Driven Billing and Compliance"

Claims: "Upon ALLOW or DENY, minting cryptographically signed receipt and
incrementing usage counter associated with receipt. Transmitting billing
data to payment processing system (Stripe) for settlement."

Key Innovation: Every governance operation is metered and billable.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from enum import Enum
from threading import Lock
import structlog
import json

logger = structlog.get_logger()


class BillingTier(Enum):
    """Pricing tiers for governance operations."""
    FREE = "FREE"
    STARTER = "STARTER"
    PROFESSIONAL = "PROFESSIONAL"
    ENTERPRISE = "ENTERPRISE"


@dataclass
class UsageRecord:
    """
    A single usage record tied to a governance receipt.

    Every receipt generates a usage record for billing.
    """
    record_id: str
    receipt_id: str
    timestamp: str
    tenant_id: str
    operation_type: str
    resource_type: str

    # Metering dimensions
    tokens_processed: int = 0
    signature_verifications: int = 1
    storage_bytes: int = 0
    compute_ms: float = 0.0

    # Cost calculation
    unit_cost_cents: float = 0.0
    total_cost_cents: float = 0.0

    # Billing metadata
    billing_tier: BillingTier = BillingTier.STARTER
    settled: bool = False
    invoice_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_id": self.record_id,
            "receipt_id": self.receipt_id,
            "timestamp": self.timestamp,
            "tenant_id": self.tenant_id,
            "operation_type": self.operation_type,
            "resource_type": self.resource_type,
            "tokens_processed": self.tokens_processed,
            "signature_verifications": self.signature_verifications,
            "storage_bytes": self.storage_bytes,
            "compute_ms": self.compute_ms,
            "unit_cost_cents": self.unit_cost_cents,
            "total_cost_cents": self.total_cost_cents,
            "billing_tier": self.billing_tier.value,
            "settled": self.settled,
            "invoice_id": self.invoice_id,
        }


@dataclass
class TenantUsage:
    """Aggregated usage for a tenant."""
    tenant_id: str
    period_start: str
    period_end: str
    total_operations: int = 0
    total_receipts: int = 0
    total_revocations: int = 0
    total_tokens: int = 0
    total_cost_cents: float = 0.0
    records: List[UsageRecord] = field(default_factory=list)


class PennyCounter:
    """
    The Penny Counter billing engine.

    Patent: "Incrementing usage counter associated with receipt.
    Transmitting billing data to payment processing system for settlement."

    Every governance operation is counted and priced.
    """

    # Default pricing (cents per unit)
    DEFAULT_PRICING = {
        "receipt_generation": 0.01,  # $0.0001 per receipt
        "signature_verification": 0.005,  # $0.00005 per verification
        "cdt_validation": 0.002,  # $0.00002 per CDT check
        "epoch_revocation": 1.0,  # $0.01 per revocation (rare, expensive)
        "storage_per_kb": 0.001,  # $0.00001 per KB stored
        "pqc_signature": 0.05,  # $0.0005 per ML-DSA-65 signature (more compute)
    }

    def __init__(
        self,
        pricing: Optional[Dict[str, float]] = None,
        tier: BillingTier = BillingTier.STARTER,
    ):
        self.pricing = pricing or self.DEFAULT_PRICING.copy()
        self.tier = tier
        self._records: List[UsageRecord] = []
        self._tenant_usage: Dict[str, TenantUsage] = {}
        self._lock = Lock()
        self._counter = 0

        # Tier multipliers
        self._tier_multipliers = {
            BillingTier.FREE: 0.0,  # Free tier
            BillingTier.STARTER: 1.0,
            BillingTier.PROFESSIONAL: 0.8,  # 20% discount
            BillingTier.ENTERPRISE: 0.5,  # 50% discount
        }

    def record_operation(
        self,
        receipt_id: str,
        tenant_id: str,
        operation_type: str,
        resource_type: str = "default",
        tokens_processed: int = 0,
        signature_verifications: int = 1,
        storage_bytes: int = 0,
        compute_ms: float = 0.0,
        use_pqc: bool = False,
    ) -> UsageRecord:
        """
        Record a governance operation for billing.

        This is called after every receipt is generated.
        """
        with self._lock:
            self._counter += 1
            record_id = f"USG-{self._counter:012d}"

        # Calculate cost
        unit_cost = self.pricing["receipt_generation"]
        total_cost = unit_cost

        # Add signature verification cost
        sig_cost = (
            self.pricing["pqc_signature"] if use_pqc
            else self.pricing["signature_verification"]
        )
        total_cost += sig_cost * signature_verifications

        # Add storage cost
        if storage_bytes > 0:
            total_cost += self.pricing["storage_per_kb"] * (storage_bytes / 1024)

        # Apply tier multiplier
        multiplier = self._tier_multipliers.get(self.tier, 1.0)
        total_cost *= multiplier

        record = UsageRecord(
            record_id=record_id,
            receipt_id=receipt_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            tenant_id=tenant_id,
            operation_type=operation_type,
            resource_type=resource_type,
            tokens_processed=tokens_processed,
            signature_verifications=signature_verifications,
            storage_bytes=storage_bytes,
            compute_ms=compute_ms,
            unit_cost_cents=unit_cost,
            total_cost_cents=total_cost,
            billing_tier=self.tier,
        )

        with self._lock:
            self._records.append(record)

            # Update tenant aggregation
            if tenant_id not in self._tenant_usage:
                self._tenant_usage[tenant_id] = TenantUsage(
                    tenant_id=tenant_id,
                    period_start=record.timestamp,
                    period_end=record.timestamp,
                )

            tenant = self._tenant_usage[tenant_id]
            tenant.total_operations += 1
            tenant.total_receipts += 1
            tenant.total_tokens += tokens_processed
            tenant.total_cost_cents += total_cost
            tenant.period_end = record.timestamp
            tenant.records.append(record)

        logger.info(
            "usage_recorded",
            record_id=record_id,
            receipt_id=receipt_id,
            tenant_id=tenant_id,
            cost_cents=total_cost,
        )

        return record

    def record_revocation(self, tenant_id: str, epoch_change: int) -> UsageRecord:
        """
        Record an epoch revocation (expensive operation).
        """
        with self._lock:
            self._counter += 1
            record_id = f"USG-{self._counter:012d}"

        cost = self.pricing["epoch_revocation"]
        multiplier = self._tier_multipliers.get(self.tier, 1.0)
        total_cost = cost * multiplier

        record = UsageRecord(
            record_id=record_id,
            receipt_id=f"REVOKE-{epoch_change}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            tenant_id=tenant_id,
            operation_type="REVOCATION",
            resource_type="epoch",
            unit_cost_cents=cost,
            total_cost_cents=total_cost,
            billing_tier=self.tier,
        )

        with self._lock:
            self._records.append(record)
            if tenant_id in self._tenant_usage:
                self._tenant_usage[tenant_id].total_revocations += 1
                self._tenant_usage[tenant_id].total_cost_cents += total_cost

        logger.info(
            "revocation_recorded",
            record_id=record_id,
            tenant_id=tenant_id,
            epoch=epoch_change,
            cost_cents=total_cost,
        )

        return record

    def get_tenant_usage(self, tenant_id: str) -> Optional[TenantUsage]:
        """Get aggregated usage for a tenant."""
        return self._tenant_usage.get(tenant_id)

    def get_unsettled_records(self, tenant_id: str) -> List[UsageRecord]:
        """Get all unsettled records for a tenant."""
        tenant = self._tenant_usage.get(tenant_id)
        if not tenant:
            return []
        return [r for r in tenant.records if not r.settled]

    def mark_settled(self, record_ids: List[str], invoice_id: str) -> int:
        """Mark records as settled with an invoice ID."""
        count = 0
        with self._lock:
            for record in self._records:
                if record.record_id in record_ids:
                    record.settled = True
                    record.invoice_id = invoice_id
                    count += 1

        logger.info(
            "records_settled",
            count=count,
            invoice_id=invoice_id,
        )

        return count

    def export_for_stripe(self, tenant_id: str) -> Dict[str, Any]:
        """
        Export usage data in Stripe-compatible format.

        This is sent to Stripe for metered billing.
        """
        tenant = self._tenant_usage.get(tenant_id)
        if not tenant:
            return {}

        unsettled = self.get_unsettled_records(tenant_id)

        return {
            "tenant_id": tenant_id,
            "period": {
                "start": tenant.period_start,
                "end": tenant.period_end,
            },
            "usage": {
                "total_operations": len(unsettled),
                "total_tokens": sum(r.tokens_processed for r in unsettled),
                "total_signatures": sum(r.signature_verifications for r in unsettled),
            },
            "amount_cents": sum(r.total_cost_cents for r in unsettled),
            "line_items": [r.to_dict() for r in unsettled[:100]],  # Sample
        }
