"""
Repository Layer for Juggernaut Rail

Provides CRUD operations for all persisted entities.
"""

from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import structlog

from .database import Database, get_database
from .models import PolicyRecord, ReceiptRecord, EpochRecord, UsageRecord

logger = structlog.get_logger()


class EpochRepository:
    """Repository for epoch records."""

    def __init__(self, db: Optional[Database] = None):
        self.db = db or get_database()

    def get_current_epoch(self) -> int:
        """Get the current (highest) epoch number."""
        results = self.db.execute(
            "SELECT MAX(epoch_number) as epoch FROM epochs"
        )
        if results and results[0].get("epoch"):
            return results[0]["epoch"]
        # Initialize epoch 1 if none exists
        self.increment_epoch("global", "INITIALIZATION")
        return 1

    def increment_epoch(
        self,
        scope: str = "global",
        reason: str = "USER_REQUEST",
        created_by: Optional[str] = None,
    ) -> int:
        """Increment epoch and return new value."""
        current = self.get_current_epoch() if self.db.execute("SELECT 1 FROM epochs LIMIT 1") else 0
        new_epoch = current + 1

        now = datetime.now(timezone.utc).isoformat()
        self.db.execute(
            """INSERT INTO epochs (epoch_number, scope, reason, created_at, created_by)
               VALUES (?, ?, ?, ?, ?)""",
            (new_epoch, scope, reason, now, created_by)
        )

        logger.info("epoch_incremented", old=current, new=new_epoch, scope=scope, reason=reason)
        return new_epoch

    def get_epoch_history(self, limit: int = 100) -> List[EpochRecord]:
        """Get epoch history."""
        results = self.db.execute(
            "SELECT * FROM epochs ORDER BY epoch_number DESC LIMIT ?",
            (limit,)
        )
        return [EpochRecord.from_row(r) for r in results]


class PolicyRepository:
    """Repository for policy records."""

    def __init__(self, db: Optional[Database] = None):
        self.db = db or get_database()

    def create(self, policy: PolicyRecord) -> PolicyRecord:
        """Create a new policy."""
        self.db.execute(
            """INSERT INTO policies
               (policy_id, subject_id, partner_id, purposes, data_categories,
                retention_period_days, jurisdiction, custom_terms, status,
                epoch_created, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            policy.to_db_tuple()
        )
        logger.info("policy_created", policy_id=policy.policy_id, subject_id=policy.subject_id)
        return policy

    def get(self, policy_id: str) -> Optional[PolicyRecord]:
        """Get a policy by ID."""
        results = self.db.execute(
            "SELECT * FROM policies WHERE policy_id = ?",
            (policy_id,)
        )
        return PolicyRecord.from_row(results[0]) if results else None

    def get_by_subject(self, subject_id: str) -> List[PolicyRecord]:
        """Get all policies for a subject."""
        results = self.db.execute(
            "SELECT * FROM policies WHERE subject_id = ? AND status = 'ACTIVE'",
            (subject_id,)
        )
        return [PolicyRecord.from_row(r) for r in results]

    def get_by_partner(self, partner_id: str) -> List[PolicyRecord]:
        """Get all policies for a partner."""
        results = self.db.execute(
            "SELECT * FROM policies WHERE partner_id = ? AND status = 'ACTIVE'",
            (partner_id,)
        )
        return [PolicyRecord.from_row(r) for r in results]

    def update_status(self, policy_id: str, status: str) -> bool:
        """Update policy status."""
        now = datetime.now(timezone.utc).isoformat()
        self.db.execute(
            "UPDATE policies SET status = ?, updated_at = ? WHERE policy_id = ?",
            (status, now, policy_id)
        )
        logger.info("policy_status_updated", policy_id=policy_id, status=status)
        return True

    def revoke_by_subject(self, subject_id: str) -> int:
        """Revoke all policies for a subject."""
        now = datetime.now(timezone.utc).isoformat()
        # Get count first
        count_result = self.db.execute(
            "SELECT COUNT(*) as cnt FROM policies WHERE subject_id = ? AND status = 'ACTIVE'",
            (subject_id,)
        )
        count = count_result[0]["cnt"] if count_result else 0

        self.db.execute(
            "UPDATE policies SET status = 'REVOKED', updated_at = ? WHERE subject_id = ? AND status = 'ACTIVE'",
            (now, subject_id)
        )
        logger.info("policies_revoked_by_subject", subject_id=subject_id, count=count)
        return count

    def list_active(self, limit: int = 100, offset: int = 0) -> List[PolicyRecord]:
        """List active policies."""
        results = self.db.execute(
            "SELECT * FROM policies WHERE status = 'ACTIVE' ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset)
        )
        return [PolicyRecord.from_row(r) for r in results]

    def count_active(self) -> int:
        """Count active policies."""
        results = self.db.execute("SELECT COUNT(*) as cnt FROM policies WHERE status = 'ACTIVE'")
        return results[0]["cnt"] if results else 0


class ReceiptRepository:
    """Repository for receipt records."""

    def __init__(self, db: Optional[Database] = None):
        self.db = db or get_database()

    def create(self, receipt: ReceiptRecord) -> ReceiptRecord:
        """Create a new receipt."""
        self.db.execute(
            """INSERT INTO receipts
               (receipt_id, timestamp, agent_id, policy_id, operation_hash,
                consent_token, action, target_resource, chain_sequence, prev_hash,
                signature, signature_algorithm, key_id, veto_state, broken_seal,
                regulatory_mode, receipt_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            receipt.to_db_tuple()
        )
        logger.debug("receipt_created", receipt_id=receipt.receipt_id, action=receipt.action)
        return receipt

    def get(self, receipt_id: str) -> Optional[ReceiptRecord]:
        """Get a receipt by ID."""
        results = self.db.execute(
            "SELECT * FROM receipts WHERE receipt_id = ?",
            (receipt_id,)
        )
        return ReceiptRecord.from_row(results[0]) if results else None

    def get_by_agent(self, agent_id: str, limit: int = 100) -> List[ReceiptRecord]:
        """Get receipts for an agent."""
        results = self.db.execute(
            "SELECT * FROM receipts WHERE agent_id = ? ORDER BY timestamp DESC LIMIT ?",
            (agent_id, limit)
        )
        return [ReceiptRecord.from_row(r) for r in results]

    def get_by_policy(self, policy_id: str, limit: int = 100) -> List[ReceiptRecord]:
        """Get receipts for a policy."""
        results = self.db.execute(
            "SELECT * FROM receipts WHERE policy_id = ? ORDER BY timestamp DESC LIMIT ?",
            (policy_id, limit)
        )
        return [ReceiptRecord.from_row(r) for r in results]

    def get_chain(self, limit: int = 1000) -> List[ReceiptRecord]:
        """Get receipt chain in order."""
        results = self.db.execute(
            "SELECT * FROM receipts ORDER BY chain_sequence ASC LIMIT ?",
            (limit,)
        )
        return [ReceiptRecord.from_row(r) for r in results]

    def get_latest(self) -> Optional[ReceiptRecord]:
        """Get the latest receipt."""
        results = self.db.execute(
            "SELECT * FROM receipts ORDER BY chain_sequence DESC LIMIT 1"
        )
        return ReceiptRecord.from_row(results[0]) if results else None

    def count(self) -> int:
        """Count total receipts."""
        results = self.db.execute("SELECT COUNT(*) as cnt FROM receipts")
        return results[0]["cnt"] if results else 0

    def list_recent(self, limit: int = 100) -> List[ReceiptRecord]:
        """List recent receipts."""
        results = self.db.execute(
            "SELECT * FROM receipts ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        )
        return [ReceiptRecord.from_row(r) for r in results]

    def verify_chain_integrity(self) -> tuple[bool, Optional[str], int]:
        """
        Verify the entire receipt chain integrity.

        Returns (is_valid, error_message, chain_length)
        """
        receipts = self.get_chain(limit=100000)

        if not receipts:
            return (True, None, 0)

        prev_hash = "GENESIS"
        for i, receipt in enumerate(receipts):
            if receipt.chain_sequence != i:
                return (False, f"Chain sequence mismatch at position {i}", i)

            if receipt.prev_hash != prev_hash:
                return (False, f"Hash chain broken at position {i}", i)

            prev_hash = receipt.receipt_hash

        return (True, None, len(receipts))


class UsageRepository:
    """Repository for usage/billing records."""

    def __init__(self, db: Optional[Database] = None):
        self.db = db or get_database()

    def create(self, record: UsageRecord) -> UsageRecord:
        """Create a usage record."""
        self.db.execute(
            """INSERT INTO usage_records
               (record_id, receipt_id, timestamp, tenant_id, operation_type,
                resource_type, tokens_processed, signature_verifications,
                storage_bytes, compute_ms, unit_cost_cents, total_cost_cents,
                billing_tier, settled, invoice_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            record.to_db_tuple()
        )
        return record

    def get_by_tenant(self, tenant_id: str, limit: int = 1000) -> List[UsageRecord]:
        """Get usage records for a tenant."""
        results = self.db.execute(
            "SELECT * FROM usage_records WHERE tenant_id = ? ORDER BY timestamp DESC LIMIT ?",
            (tenant_id, limit)
        )
        return [UsageRecord.from_row(r) for r in results]

    def get_unsettled(self, tenant_id: str) -> List[UsageRecord]:
        """Get unsettled records for a tenant."""
        results = self.db.execute(
            "SELECT * FROM usage_records WHERE tenant_id = ? AND settled = 0 ORDER BY timestamp ASC",
            (tenant_id,)
        )
        return [UsageRecord.from_row(r) for r in results]

    def mark_settled(self, record_ids: List[str], invoice_id: str) -> int:
        """Mark records as settled."""
        if not record_ids:
            return 0

        placeholders = ",".join(["?" for _ in record_ids])
        self.db.execute(
            f"UPDATE usage_records SET settled = 1, invoice_id = ? WHERE record_id IN ({placeholders})",
            (invoice_id, *record_ids)
        )
        logger.info("usage_records_settled", count=len(record_ids), invoice_id=invoice_id)
        return len(record_ids)

    def get_tenant_summary(self, tenant_id: str) -> Dict[str, Any]:
        """Get usage summary for a tenant."""
        results = self.db.execute(
            """SELECT
                COUNT(*) as total_operations,
                SUM(tokens_processed) as total_tokens,
                SUM(total_cost_cents) as total_cost,
                SUM(CASE WHEN settled = 0 THEN total_cost_cents ELSE 0 END) as unsettled_cost
               FROM usage_records WHERE tenant_id = ?""",
            (tenant_id,)
        )

        if results:
            row = results[0]
            return {
                "tenant_id": tenant_id,
                "total_operations": row.get("total_operations", 0) or 0,
                "total_tokens": row.get("total_tokens", 0) or 0,
                "total_cost_cents": row.get("total_cost", 0.0) or 0.0,
                "unsettled_cost_cents": row.get("unsettled_cost", 0.0) or 0.0,
            }

        return {
            "tenant_id": tenant_id,
            "total_operations": 0,
            "total_tokens": 0,
            "total_cost_cents": 0.0,
            "unsettled_cost_cents": 0.0,
        }
