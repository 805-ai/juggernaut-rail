"""
License Key Validation

Validates license keys and enforces tier-based usage limits.
Customers purchase a license, deploy Juggernaut Rail, and the
Penny Counter enforces their purchased tier limits.
"""

import hashlib
import hmac
import base64
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Dict, Optional
import structlog

logger = structlog.get_logger()


class LicenseTier(Enum):
    """License tiers with associated limits."""
    TRIAL = "trial"
    STARTER = "starter"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"


@dataclass
class TierLimits:
    """Usage limits per tier."""
    operations_per_month: int
    receipts_stored: int
    agents_allowed: int
    pqc_signatures: bool  # ML-DSA-65 access
    refinery_profiles: bool  # Vertical purity profiles
    support_level: str

    @classmethod
    def for_tier(cls, tier: LicenseTier) -> "TierLimits":
        """Get limits for a tier."""
        limits = {
            LicenseTier.TRIAL: cls(
                operations_per_month=1_000,
                receipts_stored=1_000,
                agents_allowed=1,
                pqc_signatures=False,
                refinery_profiles=False,
                support_level="community",
            ),
            LicenseTier.STARTER: cls(
                operations_per_month=100_000,
                receipts_stored=100_000,
                agents_allowed=10,
                pqc_signatures=False,
                refinery_profiles=False,
                support_level="email",
            ),
            LicenseTier.PROFESSIONAL: cls(
                operations_per_month=1_000_000,
                receipts_stored=1_000_000,
                agents_allowed=100,
                pqc_signatures=True,
                refinery_profiles=True,
                support_level="priority",
            ),
            LicenseTier.ENTERPRISE: cls(
                operations_per_month=-1,  # Unlimited
                receipts_stored=-1,
                agents_allowed=-1,
                pqc_signatures=True,
                refinery_profiles=True,
                support_level="dedicated",
            ),
        }
        return limits[tier]


@dataclass
class LicenseKey:
    """
    Validated license key with metadata.

    License key format: JR-{tier}-{org_hash}-{expiry}-{signature}
    Example: JR-ENT-a1b2c3d4-20261231-xyz789
    """
    key: str
    tier: LicenseTier
    organization_id: str
    issued_at: datetime
    expires_at: datetime
    limits: TierLimits
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_valid(self) -> bool:
        """Check if license is currently valid."""
        now = datetime.now(timezone.utc)
        return now < self.expires_at

    @property
    def is_expired(self) -> bool:
        return not self.is_valid

    @property
    def days_remaining(self) -> int:
        """Days until expiration."""
        delta = self.expires_at - datetime.now(timezone.utc)
        return max(0, delta.days)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key[:20] + "...",  # Truncate for display
            "tier": self.tier.value,
            "organization_id": self.organization_id,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "is_valid": self.is_valid,
            "days_remaining": self.days_remaining,
            "limits": {
                "operations_per_month": self.limits.operations_per_month,
                "agents_allowed": self.limits.agents_allowed,
                "pqc_signatures": self.limits.pqc_signatures,
                "refinery_profiles": self.limits.refinery_profiles,
            },
        }


class LicenseValidationError(Exception):
    """Raised when license validation fails."""
    pass


class LicenseManager:
    """
    Manages license key validation and enforcement.

    License keys are cryptographically signed to prevent tampering.
    The signing secret is only known to FinalBoss Tech.
    """

    # Tier prefixes in license keys
    TIER_PREFIXES = {
        "TRI": LicenseTier.TRIAL,
        "STR": LicenseTier.STARTER,
        "PRO": LicenseTier.PROFESSIONAL,
        "ENT": LicenseTier.ENTERPRISE,
    }

    def __init__(self, signing_secret: Optional[str] = None):
        """
        Initialize license manager.

        Args:
            signing_secret: Secret for validating license signatures.
                           In production, this is embedded in the build.
        """
        self._signing_secret = signing_secret or os.environ.get(
            "LICENSE_SIGNING_SECRET",
            "finalboss-juggernaut-2025"  # Default for development
        )
        self._current_license: Optional[LicenseKey] = None
        self._usage_this_period: int = 0
        self._period_start: datetime = datetime.now(timezone.utc).replace(day=1)

    def validate_key(self, license_key: str) -> LicenseKey:
        """
        Validate a license key and return parsed license info.

        License format: JR-{TIER}-{ORG_ID}-{EXPIRY}-{SIG}
        Example: JR-ENT-ABC123-20261231-a1b2c3d4e5f6
        """
        if not license_key:
            raise LicenseValidationError("License key is required")

        parts = license_key.strip().split("-")

        if len(parts) != 5:
            raise LicenseValidationError("Invalid license key format")

        prefix, tier_code, org_id, expiry, signature = parts

        # Check prefix
        if prefix != "JR":
            raise LicenseValidationError("Invalid license key prefix")

        # Parse tier
        tier = self.TIER_PREFIXES.get(tier_code)
        if not tier:
            raise LicenseValidationError(f"Invalid tier code: {tier_code}")

        # Parse expiry
        try:
            expires_at = datetime.strptime(expiry, "%Y%m%d").replace(tzinfo=timezone.utc)
        except ValueError:
            raise LicenseValidationError("Invalid expiry date format")

        # Verify signature
        payload = f"{prefix}-{tier_code}-{org_id}-{expiry}"
        expected_sig = self._compute_signature(payload)

        if not hmac.compare_digest(signature.lower(), expected_sig[:len(signature)].lower()):
            raise LicenseValidationError("Invalid license signature")

        # Check expiration
        if datetime.now(timezone.utc) > expires_at:
            raise LicenseValidationError("License has expired")

        license = LicenseKey(
            key=license_key,
            tier=tier,
            organization_id=org_id,
            issued_at=datetime.now(timezone.utc),  # We don't store issue date in key
            expires_at=expires_at,
            limits=TierLimits.for_tier(tier),
        )

        logger.info(
            "license_validated",
            tier=tier.value,
            org_id=org_id,
            expires_at=expiry,
        )

        return license

    def _compute_signature(self, payload: str) -> str:
        """Compute HMAC signature for license payload."""
        sig = hmac.new(
            self._signing_secret.encode(),
            payload.encode(),
            hashlib.sha256,
        ).hexdigest()
        return sig[:12]  # Truncated for key readability

    def activate(self, license_key: str) -> LicenseKey:
        """
        Activate a license key for this deployment.
        """
        license = self.validate_key(license_key)
        self._current_license = license
        self._reset_usage_period()

        logger.info(
            "license_activated",
            tier=license.tier.value,
            days_remaining=license.days_remaining,
        )

        return license

    def get_current_license(self) -> Optional[LicenseKey]:
        """Get the currently active license."""
        return self._current_license

    def check_limit(self, operation_count: int = 1) -> tuple[bool, Optional[str]]:
        """
        Check if an operation is allowed under current license limits.

        Returns (allowed, error_message)
        """
        if not self._current_license:
            return False, "No active license"

        if self._current_license.is_expired:
            return False, "License expired"

        limits = self._current_license.limits

        # Check monthly operation limit (-1 = unlimited)
        if limits.operations_per_month > 0:
            # Check if we need to reset the period
            self._check_period_reset()

            if self._usage_this_period + operation_count > limits.operations_per_month:
                return False, f"Monthly operation limit reached ({limits.operations_per_month})"

        return True, None

    def record_usage(self, operation_count: int = 1) -> None:
        """Record usage against the license."""
        self._check_period_reset()
        self._usage_this_period += operation_count

    def _check_period_reset(self) -> None:
        """Reset usage counter if we're in a new month."""
        now = datetime.now(timezone.utc)
        if now.month != self._period_start.month or now.year != self._period_start.year:
            self._reset_usage_period()

    def _reset_usage_period(self) -> None:
        """Reset the usage period."""
        self._usage_this_period = 0
        self._period_start = datetime.now(timezone.utc).replace(day=1)

    def get_usage_stats(self) -> Dict[str, Any]:
        """Get current usage statistics."""
        if not self._current_license:
            return {"error": "No active license"}

        limits = self._current_license.limits
        limit = limits.operations_per_month

        return {
            "tier": self._current_license.tier.value,
            "period_start": self._period_start.isoformat(),
            "operations_used": self._usage_this_period,
            "operations_limit": limit if limit > 0 else "unlimited",
            "operations_remaining": (limit - self._usage_this_period) if limit > 0 else "unlimited",
            "usage_percent": (self._usage_this_period / limit * 100) if limit > 0 else 0,
            "license_days_remaining": self._current_license.days_remaining,
        }

    def check_feature(self, feature: str) -> bool:
        """Check if a feature is available under current license."""
        if not self._current_license:
            return False

        limits = self._current_license.limits

        feature_map = {
            "pqc_signatures": limits.pqc_signatures,
            "refinery_profiles": limits.refinery_profiles,
            "ml_dsa_65": limits.pqc_signatures,
            "healthcare_profile": limits.refinery_profiles,
            "finance_profile": limits.refinery_profiles,
        }

        return feature_map.get(feature, False)

    @staticmethod
    def generate_key(
        tier: LicenseTier,
        org_id: str,
        expires_at: datetime,
        signing_secret: str,
    ) -> str:
        """
        Generate a license key.

        NOTE: This is for FinalBoss Tech internal use only.
        In production, this would be in a separate license server.
        """
        tier_codes = {v: k for k, v in LicenseManager.TIER_PREFIXES.items()}
        tier_code = tier_codes[tier]
        expiry = expires_at.strftime("%Y%m%d")

        payload = f"JR-{tier_code}-{org_id}-{expiry}"
        sig = hmac.new(
            signing_secret.encode(),
            payload.encode(),
            hashlib.sha256,
        ).hexdigest()[:12]

        return f"{payload}-{sig}"
