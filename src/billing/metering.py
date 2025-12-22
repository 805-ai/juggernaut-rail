"""
Metering Engine for AI Governance Operations

Patent Reference: "Metering module calculates gas fee based on computational
complexity of verification operations, such as post-quantum signature checks,
and the volume of receipts processed."
"""

from dataclasses import dataclass
from typing import Any, Dict, Optional
from enum import Enum
import structlog
import time

logger = structlog.get_logger()


class OperationComplexity(Enum):
    """Complexity tiers for operations."""
    TRIVIAL = "TRIVIAL"  # Simple lookup
    SIMPLE = "SIMPLE"  # Single signature verify
    MODERATE = "MODERATE"  # Multiple verifications
    COMPLEX = "COMPLEX"  # PQC or chain validation
    EXTREME = "EXTREME"  # Full audit or bulk operations


@dataclass
class GasEstimate:
    """Gas estimate for an operation."""
    operation_type: str
    complexity: OperationComplexity
    base_gas: int
    signature_gas: int
    storage_gas: int
    total_gas: int
    estimated_ms: float
    estimated_cost_cents: float


class GasCalculator:
    """
    Calculates gas for governance operations.

    "Gas" represents computational cost, priced per unit.
    Higher gas = more complex operation = higher cost.
    """

    # Base gas units
    GAS_BASE = 100
    GAS_PER_SIGNATURE_ED25519 = 50
    GAS_PER_SIGNATURE_MLDSA = 500  # 10x more for PQC
    GAS_PER_KB_STORAGE = 10
    GAS_PER_CHAIN_LINK = 20
    GAS_PER_VETO_CHECK = 30

    # Gas to cents conversion
    GAS_PRICE_CENTS = 0.00001  # $0.0000001 per gas unit

    def __init__(self, gas_price_cents: Optional[float] = None):
        self.gas_price = gas_price_cents or self.GAS_PRICE_CENTS

    def estimate(
        self,
        operation_type: str,
        num_signatures: int = 1,
        use_pqc: bool = False,
        storage_kb: float = 0,
        chain_validations: int = 0,
        veto_checks: int = 0,
    ) -> GasEstimate:
        """
        Estimate gas for an operation.
        """
        # Base gas
        base_gas = self.GAS_BASE

        # Signature gas
        sig_unit_gas = self.GAS_PER_SIGNATURE_MLDSA if use_pqc else self.GAS_PER_SIGNATURE_ED25519
        signature_gas = sig_unit_gas * num_signatures

        # Storage gas
        storage_gas = int(self.GAS_PER_KB_STORAGE * storage_kb)

        # Chain and veto gas
        chain_gas = self.GAS_PER_CHAIN_LINK * chain_validations
        veto_gas = self.GAS_PER_VETO_CHECK * veto_checks

        total_gas = base_gas + signature_gas + storage_gas + chain_gas + veto_gas

        # Determine complexity
        if total_gas < 200:
            complexity = OperationComplexity.TRIVIAL
        elif total_gas < 500:
            complexity = OperationComplexity.SIMPLE
        elif total_gas < 1000:
            complexity = OperationComplexity.MODERATE
        elif total_gas < 5000:
            complexity = OperationComplexity.COMPLEX
        else:
            complexity = OperationComplexity.EXTREME

        # Estimate execution time (rough)
        estimated_ms = total_gas * 0.001  # 1ms per 1000 gas

        # Calculate cost
        estimated_cost = total_gas * self.gas_price

        return GasEstimate(
            operation_type=operation_type,
            complexity=complexity,
            base_gas=base_gas,
            signature_gas=signature_gas,
            storage_gas=storage_gas,
            total_gas=total_gas,
            estimated_ms=estimated_ms,
            estimated_cost_cents=estimated_cost,
        )


class MeteringEngine:
    """
    Real-time metering of governance operations.

    Tracks:
    - Operations per second
    - Gas consumed
    - Cost accumulation
    """

    def __init__(self, calculator: Optional[GasCalculator] = None):
        self.calculator = calculator or GasCalculator()
        self._metrics: Dict[str, Any] = {
            "total_operations": 0,
            "total_gas": 0,
            "total_cost_cents": 0.0,
            "operations_per_second": 0.0,
            "last_operation_at": None,
        }
        self._operation_times: list = []
        self._window_seconds = 60

    def meter_operation(
        self,
        operation_type: str,
        num_signatures: int = 1,
        use_pqc: bool = False,
        storage_kb: float = 0,
        chain_validations: int = 0,
        veto_checks: int = 0,
    ) -> GasEstimate:
        """
        Meter an operation and return gas estimate.
        """
        estimate = self.calculator.estimate(
            operation_type=operation_type,
            num_signatures=num_signatures,
            use_pqc=use_pqc,
            storage_kb=storage_kb,
            chain_validations=chain_validations,
            veto_checks=veto_checks,
        )

        now = time.time()

        # Update metrics
        self._metrics["total_operations"] += 1
        self._metrics["total_gas"] += estimate.total_gas
        self._metrics["total_cost_cents"] += estimate.estimated_cost_cents
        self._metrics["last_operation_at"] = now

        # Track for ops/sec calculation
        self._operation_times.append(now)

        # Prune old times
        cutoff = now - self._window_seconds
        self._operation_times = [t for t in self._operation_times if t > cutoff]

        # Calculate ops/sec
        if len(self._operation_times) > 1:
            time_span = self._operation_times[-1] - self._operation_times[0]
            if time_span > 0:
                self._metrics["operations_per_second"] = len(self._operation_times) / time_span

        return estimate

    def get_metrics(self) -> Dict[str, Any]:
        """Get current metering metrics."""
        return self._metrics.copy()

    def get_ops_per_second(self) -> float:
        """Get current operations per second rate."""
        return self._metrics["operations_per_second"]
