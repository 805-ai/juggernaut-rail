"""
Data Models for Persistence Layer

These models mirror the core domain objects but are optimized for database storage.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import json


@dataclass
class EpochRecord:
    """Persisted epoch record."""
    epoch_number: int
    scope: str = "global"
    reason: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    created_by: Optional[str] = None
    id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "epoch_number": self.epoch_number,
            "scope": self.scope,
            "reason": self.reason,
            "created_at": self.created_at,
            "created_by": self.created_by,
        }

    @classmethod
    def from_row(cls, row: Dict[str, Any]) -> "EpochRecord":
        return cls(
            id=row.get("id"),
            epoch_number=row["epoch_number"],
            scope=row.get("scope", "global"),
            reason=row.get("reason"),
            created_at=row["created_at"],
            created_by=row.get("created_by"),
        )


@dataclass
class PolicyRecord:
    """Persisted policy record."""
    policy_id: str
    subject_id: str
    partner_id: str
    purposes: List[str]
    data_categories: List[str]
    retention_period_days: int
    jurisdiction: str
    status: str = "ACTIVE"
    epoch_created: int = 1
    custom_terms: Optional[Dict[str, Any]] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "subject_id": self.subject_id,
            "partner_id": self.partner_id,
            "purposes": self.purposes,
            "data_categories": self.data_categories,
            "retention_period_days": self.retention_period_days,
            "jurisdiction": self.jurisdiction,
            "status": self.status,
            "epoch_created": self.epoch_created,
            "custom_terms": self.custom_terms,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    def to_db_tuple(self) -> tuple:
        """Convert to database insert tuple."""
        return (
            self.policy_id,
            self.subject_id,
            self.partner_id,
            json.dumps(self.purposes),
            json.dumps(self.data_categories),
            self.retention_period_days,
            self.jurisdiction,
            json.dumps(self.custom_terms) if self.custom_terms else None,
            self.status,
            self.epoch_created,
            self.created_at,
            self.updated_at,
        )

    @classmethod
    def from_row(cls, row: Dict[str, Any]) -> "PolicyRecord":
        purposes = row["purposes"]
        if isinstance(purposes, str):
            purposes = json.loads(purposes)

        data_categories = row["data_categories"]
        if isinstance(data_categories, str):
            data_categories = json.loads(data_categories)

        custom_terms = row.get("custom_terms")
        if isinstance(custom_terms, str) and custom_terms:
            custom_terms = json.loads(custom_terms)

        return cls(
            policy_id=row["policy_id"],
            subject_id=row["subject_id"],
            partner_id=row["partner_id"],
            purposes=purposes,
            data_categories=data_categories,
            retention_period_days=row["retention_period_days"],
            jurisdiction=row["jurisdiction"],
            status=row.get("status", "ACTIVE"),
            epoch_created=row.get("epoch_created", 1),
            custom_terms=custom_terms,
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )


@dataclass
class ReceiptRecord:
    """Persisted receipt record."""
    receipt_id: str
    timestamp: str
    agent_id: str
    policy_id: str
    operation_hash: str
    consent_token: str
    action: str
    target_resource: str
    chain_sequence: int
    prev_hash: str
    signature: str
    signature_algorithm: str
    receipt_hash: str
    key_id: Optional[str] = None
    veto_state: Optional[Dict[str, Any]] = None
    broken_seal: bool = False
    regulatory_mode: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "timestamp": self.timestamp,
            "agent_id": self.agent_id,
            "policy_id": self.policy_id,
            "operation_hash": self.operation_hash,
            "consent_token": self.consent_token,
            "action": self.action,
            "target_resource": self.target_resource,
            "chain_sequence": self.chain_sequence,
            "prev_hash": self.prev_hash,
            "signature": self.signature,
            "signature_algorithm": self.signature_algorithm,
            "receipt_hash": self.receipt_hash,
            "key_id": self.key_id,
            "veto_state": self.veto_state,
            "broken_seal": self.broken_seal,
            "regulatory_mode": self.regulatory_mode,
        }

    def to_db_tuple(self) -> tuple:
        return (
            self.receipt_id,
            self.timestamp,
            self.agent_id,
            self.policy_id,
            self.operation_hash,
            self.consent_token,
            self.action,
            self.target_resource,
            self.chain_sequence,
            self.prev_hash,
            self.signature,
            self.signature_algorithm,
            self.key_id,
            json.dumps(self.veto_state) if self.veto_state else None,
            1 if self.broken_seal else 0,
            self.regulatory_mode,
            self.receipt_hash,
        )

    @classmethod
    def from_row(cls, row: Dict[str, Any]) -> "ReceiptRecord":
        veto_state = row.get("veto_state")
        if isinstance(veto_state, str) and veto_state:
            veto_state = json.loads(veto_state)

        return cls(
            receipt_id=row["receipt_id"],
            timestamp=row["timestamp"],
            agent_id=row["agent_id"],
            policy_id=row["policy_id"],
            operation_hash=row["operation_hash"],
            consent_token=row["consent_token"],
            action=row["action"],
            target_resource=row["target_resource"],
            chain_sequence=row["chain_sequence"],
            prev_hash=row["prev_hash"],
            signature=row["signature"],
            signature_algorithm=row["signature_algorithm"],
            receipt_hash=row["receipt_hash"],
            key_id=row.get("key_id"),
            veto_state=veto_state,
            broken_seal=bool(row.get("broken_seal", 0)),
            regulatory_mode=row.get("regulatory_mode"),
        )


@dataclass
class UsageRecord:
    """Persisted usage/billing record."""
    record_id: str
    receipt_id: str
    timestamp: str
    tenant_id: str
    operation_type: str
    resource_type: str
    tokens_processed: int = 0
    signature_verifications: int = 1
    storage_bytes: int = 0
    compute_ms: float = 0.0
    unit_cost_cents: float = 0.0
    total_cost_cents: float = 0.0
    billing_tier: str = "STARTER"
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
            "billing_tier": self.billing_tier,
            "settled": self.settled,
            "invoice_id": self.invoice_id,
        }

    def to_db_tuple(self) -> tuple:
        return (
            self.record_id,
            self.receipt_id,
            self.timestamp,
            self.tenant_id,
            self.operation_type,
            self.resource_type,
            self.tokens_processed,
            self.signature_verifications,
            self.storage_bytes,
            self.compute_ms,
            self.unit_cost_cents,
            self.total_cost_cents,
            self.billing_tier,
            1 if self.settled else 0,
            self.invoice_id,
        )

    @classmethod
    def from_row(cls, row: Dict[str, Any]) -> "UsageRecord":
        return cls(
            record_id=row["record_id"],
            receipt_id=row["receipt_id"],
            timestamp=row["timestamp"],
            tenant_id=row["tenant_id"],
            operation_type=row["operation_type"],
            resource_type=row["resource_type"],
            tokens_processed=row.get("tokens_processed", 0),
            signature_verifications=row.get("signature_verifications", 1),
            storage_bytes=row.get("storage_bytes", 0),
            compute_ms=row.get("compute_ms", 0.0),
            unit_cost_cents=row.get("unit_cost_cents", 0.0),
            total_cost_cents=row.get("total_cost_cents", 0.0),
            billing_tier=row.get("billing_tier", "STARTER"),
            settled=bool(row.get("settled", 0)),
            invoice_id=row.get("invoice_id"),
        )
