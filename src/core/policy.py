"""
Policy State Management

Patent Reference: "The policy state describes current consent terms, including
purposes, data categories, retention periods, and jurisdiction."

Implements hierarchical consent with delta permissions from:
- Application 19/240,581: Blockchain-Based Dynamic Consent Management
- Claims regarding "hierarchical consent data structure with delta permissions"
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
from enum import Enum
import hashlib
import json
import structlog

logger = structlog.get_logger()


class Purpose(Enum):
    """Standard consent purposes."""
    TRAINING = "TRAINING"
    INFERENCE = "INFERENCE"
    ANALYTICS = "ANALYTICS"
    PERSONALIZATION = "PERSONALIZATION"
    RESEARCH = "RESEARCH"
    MARKETING = "MARKETING"
    THIRD_PARTY_SHARING = "THIRD_PARTY_SHARING"
    SYNTHETIC_GENERATION = "SYNTHETIC_GENERATION"


class DataCategory(Enum):
    """Data categories covered by consent."""
    BIOMETRIC = "BIOMETRIC"
    LIKENESS = "LIKENESS"
    VOICE = "VOICE"
    TEXT = "TEXT"
    BEHAVIORAL = "BEHAVIORAL"
    FINANCIAL = "FINANCIAL"
    HEALTH = "HEALTH"
    LOCATION = "LOCATION"
    DEMOGRAPHIC = "DEMOGRAPHIC"


class Jurisdiction(Enum):
    """Legal jurisdictions."""
    GDPR_EU = "GDPR_EU"
    CCPA_CA = "CCPA_CA"
    HIPAA_US = "HIPAA_US"
    LGPD_BR = "LGPD_BR"
    POPIA_ZA = "POPIA_ZA"
    PDPA_SG = "PDPA_SG"
    GLOBAL = "GLOBAL"


@dataclass
class PolicyState:
    """
    Complete consent policy state for CDT generation.

    Patent: "The policy state describes current consent terms, including
    purposes, data categories, retention periods, and jurisdiction."
    """
    subject_id: str
    partner_id: str
    purposes: Set[Purpose]
    data_categories: Set[DataCategory]
    retention_period_days: int
    jurisdiction: Jurisdiction
    parent_policy_id: Optional[str] = None  # For hierarchical consent
    delta_permissions: Optional[Dict[str, Any]] = None  # Modifications from parent
    custom_terms: Dict[str, Any] = field(default_factory=dict)
    version: int = 1
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def policy_id(self) -> str:
        """Generate unique policy ID from content hash."""
        content = f"{self.subject_id}:{self.partner_id}:{self.version}"
        return f"POL-{hashlib.sha256(content.encode()).hexdigest()[:12].upper()}"

    def canonicalize(self) -> str:
        """
        Create canonical representation for CDT generation.

        Patent: "Canonical is a function that serializes the policy state
        deterministically"
        """
        canonical_dict = {
            "subject_id": self.subject_id,
            "partner_id": self.partner_id,
            "purposes": sorted([p.value for p in self.purposes]),
            "data_categories": sorted([d.value for d in self.data_categories]),
            "retention_period_days": str(self.retention_period_days),
            "jurisdiction": self.jurisdiction.value,
            "version": str(self.version),
        }

        if self.parent_policy_id:
            canonical_dict["parent_policy_id"] = self.parent_policy_id

        if self.delta_permissions:
            canonical_dict["delta_permissions"] = json.dumps(
                self.delta_permissions, sort_keys=True
            )

        return json.dumps(canonical_dict, sort_keys=True, separators=(',', ':'))

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "policy_id": self.policy_id,
            "subject_id": self.subject_id,
            "partner_id": self.partner_id,
            "purposes": [p.value for p in self.purposes],
            "data_categories": [d.value for d in self.data_categories],
            "retention_period_days": self.retention_period_days,
            "jurisdiction": self.jurisdiction.value,
            "parent_policy_id": self.parent_policy_id,
            "delta_permissions": self.delta_permissions,
            "custom_terms": self.custom_terms,
            "version": self.version,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    def allows(self, purpose: Purpose, data_category: DataCategory) -> bool:
        """Check if policy allows a specific purpose and data category."""
        return purpose in self.purposes and data_category in self.data_categories


class PolicyStore:
    """
    In-memory policy store with persistence hooks.

    In production, backed by MongoDB/PostgreSQL with Redis cache.
    """

    def __init__(self):
        self._policies: Dict[str, PolicyState] = {}
        self._subject_index: Dict[str, List[str]] = {}
        self._partner_index: Dict[str, List[str]] = {}

    def store(self, policy: PolicyState) -> str:
        """Store a policy and return its ID."""
        policy_id = policy.policy_id
        self._policies[policy_id] = policy

        # Index by subject
        if policy.subject_id not in self._subject_index:
            self._subject_index[policy.subject_id] = []
        self._subject_index[policy.subject_id].append(policy_id)

        # Index by partner
        if policy.partner_id not in self._partner_index:
            self._partner_index[policy.partner_id] = []
        self._partner_index[policy.partner_id].append(policy_id)

        logger.info(
            "policy_stored",
            policy_id=policy_id,
            subject_id=policy.subject_id,
            partner_id=policy.partner_id,
        )

        return policy_id

    def get(self, policy_id: str) -> Optional[PolicyState]:
        """Retrieve a policy by ID."""
        return self._policies.get(policy_id)

    def get_for_subject(self, subject_id: str) -> List[PolicyState]:
        """Get all policies for a subject."""
        policy_ids = self._subject_index.get(subject_id, [])
        return [self._policies[pid] for pid in policy_ids if pid in self._policies]

    def get_for_pair(self, subject_id: str, partner_id: str) -> Optional[PolicyState]:
        """Get policy for a specific subject-partner pair."""
        for policy in self.get_for_subject(subject_id):
            if policy.partner_id == partner_id:
                return policy
        return None


class PolicyEvaluator:
    """
    Evaluates operations against policy state.

    Implements the "deterministic gate" from the patent.
    """

    def __init__(self, store: PolicyStore):
        self.store = store

    def evaluate(
        self,
        policy_id: str,
        requested_purpose: Purpose,
        requested_data_category: DataCategory,
    ) -> tuple[bool, Optional[str]]:
        """
        Evaluate if an operation is allowed under a policy.

        Returns (allowed, denial_reason)
        """
        policy = self.store.get(policy_id)

        if not policy:
            return (False, f"Policy {policy_id} not found")

        # Check purpose
        if requested_purpose not in policy.purposes:
            return (
                False,
                f"Purpose {requested_purpose.value} not consented for policy {policy_id}"
            )

        # Check data category
        if requested_data_category not in policy.data_categories:
            return (
                False,
                f"Data category {requested_data_category.value} not consented for policy {policy_id}"
            )

        # Check retention (simplified - in production would check actual dates)

        logger.info(
            "policy_evaluation_passed",
            policy_id=policy_id,
            purpose=requested_purpose.value,
            data_category=requested_data_category.value,
        )

        return (True, None)

    def evaluate_with_hierarchy(
        self,
        policy_id: str,
        requested_purpose: Purpose,
        requested_data_category: DataCategory,
    ) -> tuple[bool, Optional[str]]:
        """
        Evaluate considering hierarchical consent.

        Patent claim 10: "Graph-indexed data structure with constant-time lookup"
        """
        policy = self.store.get(policy_id)

        if not policy:
            return (False, f"Policy {policy_id} not found")

        # Check delta permissions if this is a child policy
        if policy.parent_policy_id and policy.delta_permissions:
            # Delta permissions can grant or revoke specific rights
            delta = policy.delta_permissions

            if delta.get("revoke_purposes"):
                if requested_purpose.value in delta["revoke_purposes"]:
                    return (False, f"Purpose {requested_purpose.value} revoked by delta permission")

            if delta.get("grant_purposes"):
                if requested_purpose.value in delta["grant_purposes"]:
                    # Explicitly granted, check data category separately
                    pass

        # Fall through to normal evaluation
        return self.evaluate(policy_id, requested_purpose, requested_data_category)
