"""
Refinery - Vertical-Specific Purity Profiles

Provides industry-specific compliance and safety checks.
"""

from .profiles import (
    PurityProfile,
    HealthcarePurityProfile,
    FinancePurityProfile,
    LegalPurityProfile,
    EducationPurityProfile,
    get_profile,
)
from .evaluator import PurityEvaluator, PurityResult

__all__ = [
    "PurityProfile",
    "HealthcarePurityProfile",
    "FinancePurityProfile",
    "LegalPurityProfile",
    "EducationPurityProfile",
    "get_profile",
    "PurityEvaluator",
    "PurityResult",
]
