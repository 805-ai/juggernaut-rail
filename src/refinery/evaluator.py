"""
Purity Evaluator

Evaluates content and operations against vertical-specific purity profiles.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
import structlog

from .profiles import (
    PurityProfile,
    PurityCheckResult,
    ViolationDetail,
    Vertical,
    ComplianceFramework,
    get_profile,
)

logger = structlog.get_logger()


@dataclass
class PurityResult:
    """
    Overall purity evaluation result.

    Aggregates results from all applicable profiles.
    """
    passed: bool
    score: float  # 0.0 to 1.0
    verticals_checked: List[Vertical]
    frameworks_checked: Set[ComplianceFramework]
    violations: List[ViolationDetail]
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passed": self.passed,
            "score": self.score,
            "verticals_checked": [v.value for v in self.verticals_checked],
            "frameworks_checked": [f.value for f in self.frameworks_checked],
            "violations": [
                {
                    "rule_id": v.rule_id,
                    "rule_name": v.rule_name,
                    "severity": v.severity,
                    "framework": v.framework.value if v.framework else None,
                    "description": v.description,
                }
                for v in self.violations
            ],
            "violation_counts": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
            },
        }


class PurityEvaluator:
    """
    Evaluates content and operations against purity profiles.

    Can apply multiple profiles for operations spanning verticals.
    """

    def __init__(self, default_verticals: Optional[List[Vertical]] = None):
        self.default_verticals = default_verticals or []
        self._profiles: Dict[Vertical, PurityProfile] = {}

    def _get_profile(self, vertical: Vertical) -> PurityProfile:
        """Get or create a profile instance."""
        if vertical not in self._profiles:
            self._profiles[vertical] = get_profile(vertical)
        return self._profiles[vertical]

    def evaluate(
        self,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
        verticals: Optional[List[Vertical]] = None,
    ) -> PurityResult:
        """
        Evaluate content and metadata against specified profiles.

        Args:
            content: The content to evaluate
            metadata: Operation metadata
            verticals: List of verticals to check (or use defaults)

        Returns:
            PurityResult with aggregated findings
        """
        verticals = verticals or self.default_verticals
        metadata = metadata or {}

        if not verticals:
            # No verticals specified, pass by default
            return PurityResult(
                passed=True,
                score=1.0,
                verticals_checked=[],
                frameworks_checked=set(),
                violations=[],
            )

        all_violations: List[ViolationDetail] = []
        all_frameworks: Set[ComplianceFramework] = set()

        for vertical in verticals:
            try:
                profile = self._get_profile(vertical)
                all_frameworks.update(profile.frameworks)

                # Check content
                content_result = profile.check_content(content)
                all_violations.extend(content_result.violations)

                # Check metadata
                metadata_result = profile.check_metadata(metadata)
                all_violations.extend(metadata_result.violations)

            except ValueError as e:
                logger.warning("profile_not_found", vertical=vertical.value, error=str(e))
                continue

        # Count by severity
        critical = sum(1 for v in all_violations if v.severity == "CRITICAL")
        high = sum(1 for v in all_violations if v.severity == "HIGH")
        medium = sum(1 for v in all_violations if v.severity == "MEDIUM")
        low = sum(1 for v in all_violations if v.severity == "LOW")

        # Calculate score
        # Critical violations = 0 score
        # High violations = -0.3 each
        # Medium violations = -0.1 each
        # Low violations = -0.05 each
        if critical > 0:
            score = 0.0
        else:
            score = max(0.0, 1.0 - (high * 0.3) - (medium * 0.1) - (low * 0.05))

        passed = critical == 0 and high == 0

        logger.info(
            "purity_evaluated",
            verticals=[v.value for v in verticals],
            passed=passed,
            score=score,
            violations=len(all_violations),
        )

        return PurityResult(
            passed=passed,
            score=score,
            verticals_checked=verticals,
            frameworks_checked=all_frameworks,
            violations=all_violations,
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
        )

    def evaluate_for_healthcare(
        self,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> PurityResult:
        """Convenience method for healthcare evaluation."""
        return self.evaluate(content, metadata, [Vertical.HEALTHCARE])

    def evaluate_for_finance(
        self,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> PurityResult:
        """Convenience method for financial services evaluation."""
        return self.evaluate(content, metadata, [Vertical.FINANCE])

    def get_required_disclosures(self, verticals: List[Vertical]) -> List[str]:
        """Get all required disclosures for specified verticals."""
        disclosures = []
        for vertical in verticals:
            try:
                profile = self._get_profile(vertical)
                disclosures.extend(profile.get_required_disclosures())
            except ValueError:
                continue
        return disclosures

    def get_applicable_frameworks(self, verticals: List[Vertical]) -> Set[ComplianceFramework]:
        """Get all applicable compliance frameworks."""
        frameworks = set()
        for vertical in verticals:
            try:
                profile = self._get_profile(vertical)
                frameworks.update(profile.frameworks)
            except ValueError:
                continue
        return frameworks
