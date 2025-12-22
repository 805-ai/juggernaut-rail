"""
Deterministic Governance Gate

Patent Reference: "NO RECEIPT, NO RUN" invariant
"A mechanism enforcing a no receipt, no run policy. No operation is forwarded
unless a cryptographic governance receipt is generated, canonically hashed,
and signed by a post-quantum resistant signature scheme."

This is the core enforcement layer that gates ALL operations.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, TypeVar, Generic
import structlog

from ..core.cdt import CDTGenerator, CDTValidator, CDTStatus, PolicyState as CDTPolicyState
from ..core.receipt import (
    GovernanceReceipt,
    ReceiptGenerator,
    OperationPayload,
    ReceiptAction,
)
from ..core.veto import VetoVector, ZeroMultiplierVeto, VetoCategory
from ..core.epoch import EpochManager
from ..core.policy import PolicyState, PolicyStore, PolicyEvaluator, Purpose, DataCategory
from ..billing.penny_counter import PennyCounter

logger = structlog.get_logger()

T = TypeVar('T')


class GateDecision(Enum):
    """Gate decision outcomes."""
    ALLOW = "ALLOW"
    DENY = "DENY"
    VETO = "VETO"  # Denied by veto mechanism
    REVOKED = "REVOKED"  # CDT invalid (consent revoked)
    ERROR = "ERROR"


@dataclass
class EnforcementResult(Generic[T]):
    """
    Result of gate enforcement.

    Contains both the decision and the operation result (if allowed).
    """
    decision: GateDecision
    receipt: Optional[GovernanceReceipt]
    result: Optional[T] = None
    error_message: Optional[str] = None
    trust_score: float = 0.0
    veto_vector: Optional[VetoVector] = None
    latency_ms: float = 0.0

    @property
    def allowed(self) -> bool:
        return self.decision == GateDecision.ALLOW


@dataclass
class GateConfig:
    """Configuration for the governance gate."""
    fail_closed: bool = True  # Default DENY if errors occur
    require_pqc: bool = False  # Require post-quantum signatures
    min_trust_score: float = 0.5  # Minimum trust score to allow
    veto_categories: List[VetoCategory] = field(default_factory=lambda: [
        VetoCategory.PII,
        VetoCategory.COPYRIGHT,
        VetoCategory.BIAS,
        VetoCategory.HALLUCINATION,
    ])
    enable_billing: bool = True


class GovernanceGate:
    """
    The Deterministic Governance Gate.

    Patent: "No operation is forwarded unless a cryptographic governance
    receipt is generated, canonically hashed, and signed."

    Flow:
    1. Receive operation request
    2. Validate CDT (consent)
    3. Evaluate veto vectors
    4. Compute trust score
    5. Generate receipt
    6. Execute operation (only if receipt valid)
    7. Meter usage
    """

    def __init__(
        self,
        config: Optional[GateConfig] = None,
        epoch_manager: Optional[EpochManager] = None,
        policy_store: Optional[PolicyStore] = None,
        penny_counter: Optional[PennyCounter] = None,
    ):
        self.config = config or GateConfig()
        self.epoch_manager = epoch_manager or EpochManager()
        self.policy_store = policy_store or PolicyStore()
        self.penny_counter = penny_counter

        self.cdt_generator = CDTGenerator()
        self.cdt_validator = CDTValidator(self.cdt_generator)
        self.receipt_generator = ReceiptGenerator()
        self.veto_engine = ZeroMultiplierVeto()
        self.policy_evaluator = PolicyEvaluator(self.policy_store)

        # Metrics
        self._total_requests = 0
        self._allowed_count = 0
        self._denied_count = 0
        self._vetoed_count = 0

    def gate(
        self,
        operation: OperationPayload,
        policy: PolicyState,
        presented_cdt: Optional[str] = None,
        purpose: Purpose = Purpose.INFERENCE,
        data_category: DataCategory = DataCategory.TEXT,
        content_for_veto: Optional[Any] = None,
        tenant_id: str = "default",
    ) -> EnforcementResult:
        """
        Gate an operation request.

        This is the core enforcement function implementing "NO RECEIPT, NO RUN".

        Args:
            operation: The operation to gate
            policy: Current policy state
            presented_cdt: CDT from the requesting agent
            purpose: Requested purpose
            data_category: Data category being accessed
            content_for_veto: Content to check against veto vectors
            tenant_id: Tenant ID for billing

        Returns:
            EnforcementResult with decision and receipt
        """
        import time
        start_time = time.perf_counter()

        self._total_requests += 1

        try:
            # Step 1: Get current epoch
            current_epoch = self.epoch_manager.get_epoch()

            # Step 2: Generate or validate CDT
            cdt_policy = CDTPolicyState(
                subject_id=policy.subject_id,
                partner_id=policy.partner_id,
                purposes=tuple(p.value for p in policy.purposes),
                data_categories=tuple(d.value for d in policy.data_categories),
                retention_period_days=policy.retention_period_days,
                jurisdiction=policy.jurisdiction.value,
            )

            expected_cdt = self.cdt_generator.generate(cdt_policy, current_epoch)

            if presented_cdt:
                # Validate presented CDT
                status, error = self.cdt_validator.validate_token_string(
                    presented_cdt, cdt_policy, current_epoch
                )

                if status != CDTStatus.VALID:
                    self._denied_count += 1
                    return EnforcementResult(
                        decision=GateDecision.REVOKED,
                        receipt=None,
                        error_message=f"CDT validation failed: {status.value} - {error}",
                        latency_ms=(time.perf_counter() - start_time) * 1000,
                    )

            # Step 3: Evaluate policy
            allowed, deny_reason = self.policy_evaluator.evaluate(
                policy.policy_id, purpose, data_category
            )

            if not allowed:
                self._denied_count += 1
                return EnforcementResult(
                    decision=GateDecision.DENY,
                    receipt=None,
                    error_message=deny_reason,
                    latency_ms=(time.perf_counter() - start_time) * 1000,
                )

            # Step 4: Veto vector evaluation
            trust_score = 1.0
            veto_vector = None

            if content_for_veto is not None:
                trust_score, veto_vector = self.veto_engine.evaluate(
                    content_for_veto,
                    r_actual=self._total_requests,  # Simplified
                )

                if veto_vector.is_vetoed:
                    self._vetoed_count += 1
                    # Generate VETO receipt for audit trail
                    veto_receipt = self.receipt_generator.generate(
                        operation=operation,
                        consent_token=expected_cdt.token_value,
                        veto_state={
                            "vetoed": True,
                            "triggers": [
                                {
                                    "category": t.category.value,
                                    "confidence": t.confidence,
                                }
                                for t in veto_vector.get_active_triggers()
                            ],
                        },
                    )

                    return EnforcementResult(
                        decision=GateDecision.VETO,
                        receipt=veto_receipt,
                        error_message="Operation vetoed by safety check",
                        trust_score=0.0,
                        veto_vector=veto_vector,
                        latency_ms=(time.perf_counter() - start_time) * 1000,
                    )

                if trust_score < self.config.min_trust_score:
                    self._denied_count += 1
                    return EnforcementResult(
                        decision=GateDecision.DENY,
                        receipt=None,
                        error_message=f"Trust score {trust_score:.2f} below threshold {self.config.min_trust_score}",
                        trust_score=trust_score,
                        veto_vector=veto_vector,
                        latency_ms=(time.perf_counter() - start_time) * 1000,
                    )

            # Step 5: Generate governance receipt
            receipt = self.receipt_generator.generate(
                operation=operation,
                consent_token=expected_cdt.token_value,
                veto_state={
                    "vetoed": False,
                    "trust_score": trust_score,
                } if veto_vector else None,
            )

            # Step 6: Record billing
            if self.penny_counter and self.config.enable_billing:
                self.penny_counter.record_operation(
                    receipt_id=receipt.receipt_id,
                    tenant_id=tenant_id,
                    operation_type=operation.action.value,
                    resource_type=operation.target_resource,
                    signature_verifications=1,
                    use_pqc=self.config.require_pqc,
                )

            self._allowed_count += 1

            logger.info(
                "gate_allowed",
                receipt_id=receipt.receipt_id,
                operation=operation.action.value,
                trust_score=trust_score,
                latency_ms=(time.perf_counter() - start_time) * 1000,
            )

            return EnforcementResult(
                decision=GateDecision.ALLOW,
                receipt=receipt,
                trust_score=trust_score,
                veto_vector=veto_vector,
                latency_ms=(time.perf_counter() - start_time) * 1000,
            )

        except Exception as e:
            logger.error("gate_error", error=str(e))

            if self.config.fail_closed:
                self._denied_count += 1
                return EnforcementResult(
                    decision=GateDecision.DENY,
                    receipt=None,
                    error_message=f"Gate error (fail-closed): {str(e)}",
                    latency_ms=(time.perf_counter() - start_time) * 1000,
                )
            else:
                raise

    def get_metrics(self) -> Dict[str, Any]:
        """Get gate metrics."""
        return {
            "total_requests": self._total_requests,
            "allowed": self._allowed_count,
            "denied": self._denied_count,
            "vetoed": self._vetoed_count,
            "allow_rate": self._allowed_count / self._total_requests if self._total_requests > 0 else 0,
        }
