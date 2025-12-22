"""
Consent DNA Token (CDT) Implementation

Patent Reference: "System and Method for Cryptographic Governance Receipt Rail"
Claims 1-2: CDT = Hash(Canonical(Policy_State) || Global_Epoch_Counter)

This implementation provides:
1. Deterministic CDT generation from policy state + epoch
2. Instant revocation via epoch increment
3. Zero propagation latency - no cache invalidation needed
"""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from enum import Enum

import structlog

logger = structlog.get_logger()


class CDTStatus(Enum):
    """CDT validation status"""
    VALID = "VALID"
    REVOKED_EPOCH_MISMATCH = "REVOKED_EPOCH_MISMATCH"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    EXPIRED = "EXPIRED"
    MALFORMED = "MALFORMED"


@dataclass(frozen=True)
class PolicyState:
    """
    Represents the canonical policy state used in CDT generation.

    Per patent specification:
    - purposes: allowed data usage purposes
    - data_categories: types of data covered
    - retention_period_days: how long data can be retained
    - jurisdiction: geographic/legal jurisdiction
    """
    subject_id: str
    partner_id: str
    purposes: tuple[str, ...]  # Immutable tuple for hashing
    data_categories: tuple[str, ...]
    retention_period_days: int
    jurisdiction: str
    custom_terms: Optional[Dict[str, Any]] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def canonicalize(self) -> str:
        """
        Canonicalize policy state per patent specification:
        1. Flatten nested objects
        2. Sort keys lexicographically
        3. Remove extraneous whitespace
        4. Normalize data types to canonical string encodings
        """
        canonical_dict = {
            "subject_id": self.subject_id,
            "partner_id": self.partner_id,
            "purposes": list(sorted(self.purposes)),
            "data_categories": list(sorted(self.data_categories)),
            "retention_period_days": str(self.retention_period_days),  # Normalize to string
            "jurisdiction": self.jurisdiction.upper(),  # Normalize case
        }

        if self.custom_terms:
            # Flatten and sort custom terms
            for key, value in sorted(self.custom_terms.items()):
                canonical_dict[f"custom_{key}"] = str(value)

        # JSON serialization with sorted keys, no whitespace
        return json.dumps(canonical_dict, sort_keys=True, separators=(',', ':'))


@dataclass
class ConsentDNAToken:
    """
    CDT: The cryptographic consent fingerprint.

    Patent Claim: "A Consent DNA Token (CDT) computed as Hash(Canonical(Policy_State) || Global_Epoch_Counter)
    where incrementing a global epoch scalar instantly invalidates all tokens generated under prior epochs."
    """
    token_value: str  # The SHA3-256 hash
    policy_hash: str  # Hash of policy state alone
    epoch: int
    generated_at: str
    subject_id: str
    partner_id: str

    def __str__(self) -> str:
        return f"CDT:{self.token_value[:16]}...@epoch={self.epoch}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "token_value": self.token_value,
            "policy_hash": self.policy_hash,
            "epoch": self.epoch,
            "generated_at": self.generated_at,
            "subject_id": self.subject_id,
            "partner_id": self.partner_id,
        }


class CDTGenerator:
    """
    Generates Consent DNA Tokens per patent specification.

    Key innovation: CDT = Hash(Canonical(Policy_State) || str(Global_Epoch_Counter))

    Epoch increment → ALL prior CDTs become invalid INSTANTLY
    No propagation delay. No cache invalidation. No distributed consensus.
    """

    def __init__(self, hash_algorithm: str = "sha3_256"):
        self.hash_algorithm = hash_algorithm
        self._hash_func = getattr(hashlib, hash_algorithm)

    def generate(self, policy_state: PolicyState, global_epoch: int) -> ConsentDNAToken:
        """
        Generate a CDT from policy state and epoch.

        Patent pseudocode implementation:
        def generate_cdt(policy_state: dict, global_epoch: int) -> str:
            canonical_policy = json.dumps(policy_state, sort_keys=True, separators=(',', ':'))
            input_payload = canonical_policy + str(global_epoch)
            return hashlib.sha3_256(input_payload.encode('utf-8')).hexdigest()
        """
        # Step 1: Canonicalize policy state
        canonical_policy = policy_state.canonicalize()

        # Step 2: Concatenate with epoch
        input_payload = canonical_policy + str(global_epoch)

        # Step 3: Compute SHA3-256 hash
        token_value = self._hash_func(input_payload.encode('utf-8')).hexdigest()

        # Step 4: Also compute policy-only hash for reference
        policy_hash = self._hash_func(canonical_policy.encode('utf-8')).hexdigest()

        logger.info(
            "cdt_generated",
            subject_id=policy_state.subject_id,
            partner_id=policy_state.partner_id,
            epoch=global_epoch,
            token_prefix=token_value[:16],
        )

        return ConsentDNAToken(
            token_value=token_value,
            policy_hash=policy_hash,
            epoch=global_epoch,
            generated_at=datetime.now(timezone.utc).isoformat(),
            subject_id=policy_state.subject_id,
            partner_id=policy_state.partner_id,
        )

    def compute_hash(self, data: str) -> str:
        """Compute hash of arbitrary data using configured algorithm."""
        return self._hash_func(data.encode('utf-8')).hexdigest()


class CDTValidator:
    """
    Validates CDTs against current policy state and epoch.

    Patent Claim: "If the presented CDT matches the reference CDT, consent is
    treated as valid for that request."

    Key insight: Validation is INSTANT because we simply recompute the expected
    CDT from current state. No database lookup of revocation lists needed.
    """

    def __init__(self, generator: Optional[CDTGenerator] = None):
        self.generator = generator or CDTGenerator()

    def validate(
        self,
        presented_cdt: ConsentDNAToken,
        current_policy: PolicyState,
        current_epoch: int,
    ) -> tuple[CDTStatus, Optional[str]]:
        """
        Validate a presented CDT against current state.

        Returns:
            (status, error_message)
        """
        # Recompute reference CDT from current state
        reference_cdt = self.generator.generate(current_policy, current_epoch)

        # Check epoch first (most likely reason for invalidity after revocation)
        if presented_cdt.epoch != current_epoch:
            logger.warning(
                "cdt_epoch_mismatch",
                presented_epoch=presented_cdt.epoch,
                current_epoch=current_epoch,
                subject_id=presented_cdt.subject_id,
            )
            return (
                CDTStatus.REVOKED_EPOCH_MISMATCH,
                f"CDT epoch {presented_cdt.epoch} does not match current epoch {current_epoch}. "
                "Consent may have been revoked or modified."
            )

        # Check token value matches
        if presented_cdt.token_value != reference_cdt.token_value:
            logger.warning(
                "cdt_token_mismatch",
                subject_id=presented_cdt.subject_id,
                presented_prefix=presented_cdt.token_value[:16],
                expected_prefix=reference_cdt.token_value[:16],
            )
            return (
                CDTStatus.INVALID_SIGNATURE,
                "CDT token value does not match expected value for current policy state."
            )

        logger.info(
            "cdt_validated",
            subject_id=presented_cdt.subject_id,
            epoch=current_epoch,
            status="VALID",
        )

        return (CDTStatus.VALID, None)

    def validate_token_string(
        self,
        token_value: str,
        current_policy: PolicyState,
        current_epoch: int,
    ) -> tuple[CDTStatus, Optional[str]]:
        """
        Validate a raw token string (when we only have the hash value).
        """
        reference_cdt = self.generator.generate(current_policy, current_epoch)

        if token_value != reference_cdt.token_value:
            return (CDTStatus.INVALID_SIGNATURE, "Token does not match current policy state and epoch")

        return (CDTStatus.VALID, None)


# Convenience functions matching patent pseudocode exactly
def generate_cdt(policy_state: dict, global_epoch: int) -> str:
    """
    Patent pseudocode implementation (exact match):

    def generate_cdt(policy_state: dict, global_epoch: int) -> str:
        canonical_policy = json.dumps(policy_state, sort_keys=True, separators=(',', ':'))
        input_payload = canonical_policy + str(global_epoch)
        return hashlib.sha3_256(input_payload.encode('utf-8')).hexdigest()
    """
    canonical_policy = json.dumps(policy_state, sort_keys=True, separators=(',', ':'))
    input_payload = canonical_policy + str(global_epoch)
    return hashlib.sha3_256(input_payload.encode('utf-8')).hexdigest()


def verify_cdt(
    presented_token: str,
    policy_state: dict,
    global_epoch: int,
) -> bool:
    """
    Simple verification: does the token match what we'd generate now?
    If epoch has incremented, any old token automatically fails.
    """
    expected_token = generate_cdt(policy_state, global_epoch)
    return presented_token == expected_token
