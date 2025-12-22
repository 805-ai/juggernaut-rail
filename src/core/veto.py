"""
Zero-Multiplier Veto Architecture Implementation

Patent Reference: "System and Method for Deterministic AI Governance via Cryptographic Receipts"
Claims 1-2: S_Trust = B_base × (R_actual/R_max) × Π(V_crit_i) × Σ(w_j × f_j)
           Any V_crit_i = 0 forces S_Trust = 0.00 INSTANTLY

Key Innovation: Binary veto vectors that instantly kill trust score.
Unlike gradual degradation (Interlock), this is a HARD STOP.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set
import structlog
import hashlib
import json

logger = structlog.get_logger()


class VetoCategory(Enum):
    """
    Critical veto categories per patent specification.
    Any detection triggers immediate zero-multiplication.
    """
    PII = "PII"  # Personal Identifiable Information
    COPYRIGHT = "COPYRIGHT"  # Copyright infringement
    BIAS = "BIAS"  # Discriminatory bias detected
    HALLUCINATION = "HALLUCINATION"  # Factual hallucination
    CONTRAINDICATION = "CONTRAINDICATION"  # Medical contraindication
    SECURITY = "SECURITY"  # Security threat
    REGULATORY = "REGULATORY"  # Regulatory violation
    CUSTOM = "CUSTOM"  # User-defined veto trigger


@dataclass
class VetoTrigger:
    """
    Represents a veto trigger event.
    When triggered, V_crit_i becomes 0, forcing S_Trust to 0.
    """
    category: VetoCategory
    triggered: bool
    trigger_source: str
    confidence: float  # 0.0-1.0, detection confidence
    evidence: Dict[str, Any]
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    trigger_id: str = ""

    def __post_init__(self):
        if not self.trigger_id:
            # Generate unique trigger ID from content
            content = f"{self.category.value}:{self.trigger_source}:{self.timestamp}"
            self.trigger_id = hashlib.sha256(content.encode()).hexdigest()[:16]

    @property
    def V_crit(self) -> int:
        """Return binary veto value: 0 if triggered, 1 if not."""
        return 0 if self.triggered else 1


@dataclass
class VetoVector:
    """
    Collection of veto triggers forming the veto product term.

    Patent: Π(V_crit_i) where any V_crit_i = 0 → product = 0
    """
    triggers: List[VetoTrigger] = field(default_factory=list)
    broken_seal: bool = False
    broken_seal_reason: Optional[str] = None

    def add_trigger(self, trigger: VetoTrigger) -> None:
        """Add a veto trigger to the vector."""
        self.triggers.append(trigger)
        if trigger.triggered:
            logger.critical(
                "veto_triggered",
                category=trigger.category.value,
                source=trigger.trigger_source,
                confidence=trigger.confidence,
                trigger_id=trigger.trigger_id,
            )

    def compute_product(self) -> int:
        """
        Compute Π(V_crit_i).

        Returns 0 if ANY trigger is active, 1 otherwise.
        This is the zero-multiplier: one 0 kills everything.
        """
        for trigger in self.triggers:
            if trigger.V_crit == 0:
                return 0
        return 1

    @property
    def is_vetoed(self) -> bool:
        """True if any veto is active."""
        return self.compute_product() == 0 or self.broken_seal

    def get_active_triggers(self) -> List[VetoTrigger]:
        """Return list of currently active veto triggers."""
        return [t for t in self.triggers if t.triggered]

    def set_broken_seal(self, reason: str) -> None:
        """
        Set broken seal status.

        Patent: "Tampering generates a 'BROKEN_SEAL' receipt,
        notifying insurers/regulators and voiding liability"
        """
        self.broken_seal = True
        self.broken_seal_reason = reason
        logger.critical(
            "broken_seal_alert",
            reason=reason,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )


class ZeroMultiplierVeto:
    """
    The Zero-Multiplier Veto Engine.

    Patent Formula: S_Trust = B_base × (R_actual/R_max) × Π(V_crit_i) × Σ(w_j × f_j)

    Key Behaviors:
    1. Monitors for critical vectors in real-time
    2. Any V_crit_i = 0 → S_Trust = 0.00 instantly
    3. Sub-millisecond execution (<400ns target)
    4. Kernel-level enforcement capability
    """

    def __init__(
        self,
        base_score: float = 1.0,
        r_max: float = 1000.0,  # Max receipts/sec
        feature_weights: Optional[Dict[str, float]] = None,
    ):
        self.base_score = base_score
        self.r_max = r_max
        self.feature_weights = feature_weights or {}
        self.active_veto_vector = VetoVector()
        self._detection_callbacks: Dict[VetoCategory, List[Callable]] = {}

        # Initialize veto state for all categories
        for category in VetoCategory:
            self._detection_callbacks[category] = []

    def register_detector(
        self,
        category: VetoCategory,
        detector: Callable[[Any], tuple[bool, float, Dict[str, Any]]],
    ) -> None:
        """
        Register a detection callback for a veto category.

        Detector should return: (triggered, confidence, evidence)
        """
        self._detection_callbacks[category].append(detector)
        logger.info("detector_registered", category=category.value)

    def evaluate(
        self,
        content: Any,
        r_actual: float,
        features: Optional[Dict[str, float]] = None,
    ) -> tuple[float, VetoVector]:
        """
        Evaluate content and compute trust score.

        Returns:
            (trust_score, veto_vector)

        Trust score is 0.0-1.0 where:
        - 0.0 = Vetoed (blocked)
        - 1.0 = Maximum trust

        Formula: S_Trust = B_base × (R_actual/R_max) × Π(V_crit_i) × Σ(w_j × f_j)
        """
        veto_vector = VetoVector()
        features = features or {}

        # Run all detection callbacks
        for category, detectors in self._detection_callbacks.items():
            for detector in detectors:
                try:
                    triggered, confidence, evidence = detector(content)
                    trigger = VetoTrigger(
                        category=category,
                        triggered=triggered,
                        trigger_source=detector.__name__,
                        confidence=confidence,
                        evidence=evidence,
                    )
                    veto_vector.add_trigger(trigger)
                except Exception as e:
                    logger.error(
                        "detector_error",
                        category=category.value,
                        error=str(e),
                    )

        # Compute components
        receipt_density_ratio = min(r_actual / self.r_max, 1.0)  # Cap at 1.0
        veto_product = veto_vector.compute_product()  # 0 or 1

        # Feature sum: Σ(w_j × f_j)
        feature_sum = 0.0
        for feature_name, value in features.items():
            weight = self.feature_weights.get(feature_name, 1.0)
            feature_sum += weight * value

        # Normalize feature sum to [0, 1]
        if self.feature_weights:
            max_feature_sum = sum(self.feature_weights.values())
            feature_factor = feature_sum / max_feature_sum if max_feature_sum > 0 else 1.0
        else:
            feature_factor = 1.0

        # Final computation: S_Trust = B_base × (R_actual/R_max) × Π(V_crit_i) × Σ(w_j × f_j)
        trust_score = (
            self.base_score
            * receipt_density_ratio
            * veto_product
            * feature_factor
        )

        # Update active vector
        self.active_veto_vector = veto_vector

        logger.info(
            "trust_score_computed",
            score=trust_score,
            receipt_density=receipt_density_ratio,
            veto_product=veto_product,
            feature_factor=feature_factor,
            vetoed=veto_vector.is_vetoed,
        )

        return (trust_score, veto_vector)

    def quick_veto_check(self, category: VetoCategory, evidence: Any) -> bool:
        """
        Fast-path veto check for a single category.

        Returns True if vetoed (should block).
        """
        for detector in self._detection_callbacks.get(category, []):
            try:
                triggered, confidence, _ = detector(evidence)
                if triggered and confidence > 0.9:  # High confidence threshold
                    return True
            except Exception:
                pass
        return False


# Built-in detection functions
def detect_pii_basic(content: str) -> tuple[bool, float, Dict[str, Any]]:
    """
    Basic PII detection.

    In production, this would use more sophisticated NER/regex patterns.
    """
    import re

    patterns = {
        "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        "ssn": r'\b\d{3}-\d{2}-\d{4}\b',
        "phone": r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
        "credit_card": r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
    }

    if not isinstance(content, str):
        content = str(content)

    detections = {}
    for name, pattern in patterns.items():
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            detections[name] = len(matches)

    triggered = len(detections) > 0
    confidence = min(sum(detections.values()) / 3, 1.0) if triggered else 0.0

    return (triggered, confidence, {"patterns_matched": detections})


def detect_bias_keywords(content: str) -> tuple[bool, float, Dict[str, Any]]:
    """
    Basic bias detection via keyword matching.

    In production, this would use ML-based bias detection.
    """
    if not isinstance(content, str):
        content = str(content).lower()
    else:
        content = content.lower()

    # Simplified bias indicators
    bias_indicators = [
        "discriminate", "racist", "sexist", "ageist",
        "all [group] are", "those people", "typical [group]",
    ]

    matches = [ind for ind in bias_indicators if ind in content]
    triggered = len(matches) > 0
    confidence = min(len(matches) / 2, 1.0) if triggered else 0.0

    return (triggered, confidence, {"indicators_found": matches})


def detect_hallucination_markers(content: str) -> tuple[bool, float, Dict[str, Any]]:
    """
    Detect hallucination markers.

    Looks for hedging language that often accompanies confabulation.
    """
    if not isinstance(content, str):
        content = str(content).lower()
    else:
        content = content.lower()

    hallucination_markers = [
        "i believe", "i think", "probably", "might be",
        "i'm not sure but", "i can't verify",
        "as of my knowledge", "i don't have access",
    ]

    matches = [marker for marker in hallucination_markers if marker in content]
    triggered = len(matches) >= 2  # Multiple markers suggest uncertainty
    confidence = min(len(matches) / 4, 1.0) if triggered else 0.0

    return (triggered, confidence, {"markers_found": matches})
