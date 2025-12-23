"""
Vertical-Specific Purity Profiles

Each profile defines industry-specific compliance requirements and safety checks.
These profiles are applied on top of the base governance checks.
"""

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Pattern, Set
import structlog

logger = structlog.get_logger()


class Vertical(Enum):
    """Supported industry verticals."""
    HEALTHCARE = "healthcare"
    FINANCE = "finance"
    LEGAL = "legal"
    EDUCATION = "education"
    GOVERNMENT = "government"
    RETAIL = "retail"
    GENERAL = "general"


class ComplianceFramework(Enum):
    """Regulatory compliance frameworks."""
    HIPAA = "HIPAA"
    SOC2 = "SOC2"
    PCI_DSS = "PCI_DSS"
    GDPR = "GDPR"
    CCPA = "CCPA"
    FERPA = "FERPA"
    GLBA = "GLBA"
    FINRA = "FINRA"
    FedRAMP = "FedRAMP"


@dataclass
class ViolationDetail:
    """Details of a purity violation."""
    rule_id: str
    rule_name: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    framework: Optional[ComplianceFramework]
    description: str
    evidence: Optional[str] = None
    remediation: Optional[str] = None


@dataclass
class PurityCheckResult:
    """Result of a single purity check."""
    passed: bool
    violations: List[ViolationDetail] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class PurityProfile(ABC):
    """
    Abstract base class for vertical-specific purity profiles.

    Each profile defines:
    - Required compliance frameworks
    - Prohibited patterns (PII, PHI, financial data, etc.)
    - Required disclosures
    - Data handling requirements
    """

    @property
    @abstractmethod
    def vertical(self) -> Vertical:
        """The industry vertical this profile applies to."""
        pass

    @property
    @abstractmethod
    def frameworks(self) -> Set[ComplianceFramework]:
        """Required compliance frameworks."""
        pass

    @property
    @abstractmethod
    def prohibited_patterns(self) -> Dict[str, Pattern]:
        """Regex patterns for prohibited content."""
        pass

    @abstractmethod
    def check_content(self, content: str) -> PurityCheckResult:
        """Check content against profile rules."""
        pass

    @abstractmethod
    def check_metadata(self, metadata: Dict[str, Any]) -> PurityCheckResult:
        """Check operation metadata against profile rules."""
        pass

    def get_required_disclosures(self) -> List[str]:
        """Get required disclosures for this vertical."""
        return []


class HealthcarePurityProfile(PurityProfile):
    """
    Healthcare (HIPAA) Purity Profile

    Protects PHI (Protected Health Information) and enforces HIPAA requirements.
    """

    PHI_PATTERNS = {
        "medical_record_number": re.compile(r'\b(MRN|Medical Record)[\s:#]*\d{6,}\b', re.I),
        "health_plan_id": re.compile(r'\b(Health Plan|Insurance)[\s:#]*\d{9,}\b', re.I),
        "diagnosis_code": re.compile(r'\b(ICD-?10|ICD-?9)[\s:]*[A-Z]\d{2}\.?\d*\b', re.I),
        "patient_name_context": re.compile(r'\b(patient|pt)[\s:]+[A-Z][a-z]+\s+[A-Z][a-z]+\b', re.I),
        "dob_context": re.compile(r'\b(DOB|Date of Birth|born)[\s:]+\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b', re.I),
        "medication_dosage": re.compile(r'\b\d+\s*(mg|ml|mcg|units)\s+(of\s+)?[A-Z][a-z]+\b', re.I),
    }

    @property
    def vertical(self) -> Vertical:
        return Vertical.HEALTHCARE

    @property
    def frameworks(self) -> Set[ComplianceFramework]:
        return {ComplianceFramework.HIPAA, ComplianceFramework.SOC2}

    @property
    def prohibited_patterns(self) -> Dict[str, Pattern]:
        return self.PHI_PATTERNS

    def check_content(self, content: str) -> PurityCheckResult:
        violations = []

        for pattern_name, pattern in self.PHI_PATTERNS.items():
            matches = pattern.findall(content)
            if matches:
                violations.append(ViolationDetail(
                    rule_id=f"HIPAA-PHI-{pattern_name.upper()}",
                    rule_name=f"PHI Detection: {pattern_name}",
                    severity="CRITICAL",
                    framework=ComplianceFramework.HIPAA,
                    description=f"Potential PHI detected: {pattern_name}",
                    evidence=str(matches[:3]),  # First 3 matches
                    remediation="Remove or de-identify PHI before processing",
                ))

        return PurityCheckResult(
            passed=len(violations) == 0,
            violations=violations,
            metadata={"patterns_checked": len(self.PHI_PATTERNS)},
        )

    def check_metadata(self, metadata: Dict[str, Any]) -> PurityCheckResult:
        violations = []

        # Check for required encryption
        if not metadata.get("encrypted", False):
            violations.append(ViolationDetail(
                rule_id="HIPAA-SEC-001",
                rule_name="Encryption Required",
                severity="HIGH",
                framework=ComplianceFramework.HIPAA,
                description="PHI must be encrypted at rest and in transit",
                remediation="Enable encryption for this operation",
            ))

        # Check for audit logging
        if not metadata.get("audit_logged", True):
            violations.append(ViolationDetail(
                rule_id="HIPAA-AUD-001",
                rule_name="Audit Logging Required",
                severity="HIGH",
                framework=ComplianceFramework.HIPAA,
                description="All PHI access must be logged",
                remediation="Enable audit logging",
            ))

        return PurityCheckResult(
            passed=len(violations) == 0,
            violations=violations,
        )

    def get_required_disclosures(self) -> List[str]:
        return [
            "This system processes Protected Health Information (PHI)",
            "All access is logged per HIPAA requirements",
            "Data is encrypted at rest and in transit",
        ]


class FinancePurityProfile(PurityProfile):
    """
    Financial Services Purity Profile

    Protects financial data and enforces PCI-DSS, SOX, GLBA requirements.
    """

    FINANCIAL_PATTERNS = {
        "credit_card": re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'),
        "bank_account": re.compile(r'\b(account|acct)[\s:#]*\d{8,17}\b', re.I),
        "routing_number": re.compile(r'\b(routing|aba|rtn)[\s:#]*\d{9}\b', re.I),
        "cvv": re.compile(r'\b(cvv|cvc|cvv2)[\s:#]*\d{3,4}\b', re.I),
        "pin": re.compile(r'\b(pin)[\s:#]*\d{4,6}\b', re.I),
        "swift_code": re.compile(r'\b[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?\b'),
    }

    @property
    def vertical(self) -> Vertical:
        return Vertical.FINANCE

    @property
    def frameworks(self) -> Set[ComplianceFramework]:
        return {ComplianceFramework.PCI_DSS, ComplianceFramework.SOC2, ComplianceFramework.GLBA}

    @property
    def prohibited_patterns(self) -> Dict[str, Pattern]:
        return self.FINANCIAL_PATTERNS

    def check_content(self, content: str) -> PurityCheckResult:
        violations = []

        for pattern_name, pattern in self.FINANCIAL_PATTERNS.items():
            matches = pattern.findall(content)
            if matches:
                severity = "CRITICAL" if pattern_name in ["credit_card", "cvv", "pin"] else "HIGH"
                violations.append(ViolationDetail(
                    rule_id=f"PCI-{pattern_name.upper()}",
                    rule_name=f"Financial Data Detection: {pattern_name}",
                    severity=severity,
                    framework=ComplianceFramework.PCI_DSS,
                    description=f"Financial data detected: {pattern_name}",
                    evidence=f"{len(matches)} instance(s) found",
                    remediation="Remove financial data or use tokenization",
                ))

        return PurityCheckResult(
            passed=len(violations) == 0,
            violations=violations,
        )

    def check_metadata(self, metadata: Dict[str, Any]) -> PurityCheckResult:
        violations = []

        # PCI-DSS requires specific controls
        if metadata.get("stores_card_data", False):
            if not metadata.get("pci_compliant_storage", False):
                violations.append(ViolationDetail(
                    rule_id="PCI-DSS-3.4",
                    rule_name="Card Data Storage",
                    severity="CRITICAL",
                    framework=ComplianceFramework.PCI_DSS,
                    description="Card data storage requires PCI-compliant infrastructure",
                    remediation="Use PCI-compliant tokenization service",
                ))

        return PurityCheckResult(
            passed=len(violations) == 0,
            violations=violations,
        )


class LegalPurityProfile(PurityProfile):
    """
    Legal Services Purity Profile

    Protects attorney-client privilege and confidential legal information.
    """

    LEGAL_PATTERNS = {
        "case_number": re.compile(r'\b(case|docket)[\s:#]*\d{2,4}-?[A-Z]{2,4}-?\d{4,8}\b', re.I),
        "privilege_marker": re.compile(r'\b(attorney.client|privileged|confidential|work product)\b', re.I),
        "settlement_amount": re.compile(r'\$\s*\d{1,3}(?:,\d{3})*(?:\.\d{2})?\s*(settlement|damages|award)', re.I),
    }

    @property
    def vertical(self) -> Vertical:
        return Vertical.LEGAL

    @property
    def frameworks(self) -> Set[ComplianceFramework]:
        return {ComplianceFramework.SOC2}

    @property
    def prohibited_patterns(self) -> Dict[str, Pattern]:
        return self.LEGAL_PATTERNS

    def check_content(self, content: str) -> PurityCheckResult:
        violations = []

        # Check for privilege markers
        if self.LEGAL_PATTERNS["privilege_marker"].search(content):
            violations.append(ViolationDetail(
                rule_id="LEGAL-PRIV-001",
                rule_name="Privileged Content Detection",
                severity="CRITICAL",
                framework=None,
                description="Content appears to be attorney-client privileged",
                remediation="Verify authorization before processing privileged content",
            ))

        return PurityCheckResult(
            passed=len(violations) == 0,
            violations=violations,
        )

    def check_metadata(self, metadata: Dict[str, Any]) -> PurityCheckResult:
        return PurityCheckResult(passed=True)


class EducationPurityProfile(PurityProfile):
    """
    Education Purity Profile

    Protects student records per FERPA requirements.
    """

    EDUCATION_PATTERNS = {
        "student_id": re.compile(r'\b(student|pupil)[\s:#]*id[\s:#]*\d{6,10}\b', re.I),
        "grade_record": re.compile(r'\b(GPA|grade)[\s:]*[0-4]\.\d{1,2}\b', re.I),
        "transcript": re.compile(r'\b(transcript|academic record)\b', re.I),
    }

    @property
    def vertical(self) -> Vertical:
        return Vertical.EDUCATION

    @property
    def frameworks(self) -> Set[ComplianceFramework]:
        return {ComplianceFramework.FERPA}

    @property
    def prohibited_patterns(self) -> Dict[str, Pattern]:
        return self.EDUCATION_PATTERNS

    def check_content(self, content: str) -> PurityCheckResult:
        violations = []

        for pattern_name, pattern in self.EDUCATION_PATTERNS.items():
            if pattern.search(content):
                violations.append(ViolationDetail(
                    rule_id=f"FERPA-{pattern_name.upper()}",
                    rule_name=f"Student Record Detection: {pattern_name}",
                    severity="HIGH",
                    framework=ComplianceFramework.FERPA,
                    description=f"Student record data detected: {pattern_name}",
                    remediation="Verify FERPA authorization before processing",
                ))

        return PurityCheckResult(
            passed=len(violations) == 0,
            violations=violations,
        )

    def check_metadata(self, metadata: Dict[str, Any]) -> PurityCheckResult:
        violations = []

        if metadata.get("involves_minor", False):
            if not metadata.get("parental_consent", False):
                violations.append(ViolationDetail(
                    rule_id="FERPA-CONSENT-001",
                    rule_name="Parental Consent Required",
                    severity="CRITICAL",
                    framework=ComplianceFramework.FERPA,
                    description="Processing minor student data requires parental consent",
                    remediation="Obtain parental consent before processing",
                ))

        return PurityCheckResult(
            passed=len(violations) == 0,
            violations=violations,
        )


# Profile registry
PROFILES: Dict[Vertical, type] = {
    Vertical.HEALTHCARE: HealthcarePurityProfile,
    Vertical.FINANCE: FinancePurityProfile,
    Vertical.LEGAL: LegalPurityProfile,
    Vertical.EDUCATION: EducationPurityProfile,
}


def get_profile(vertical: Vertical) -> PurityProfile:
    """Get a purity profile for the specified vertical."""
    profile_class = PROFILES.get(vertical)
    if not profile_class:
        raise ValueError(f"No profile defined for vertical: {vertical}")
    return profile_class()
