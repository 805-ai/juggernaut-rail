"""
Tests for Consent DNA Token (CDT) Implementation

Tests the core patent claims:
- CDT = Hash(Canonical(Policy_State) || Global_Epoch_Counter)
- Epoch increment invalidates all prior CDTs
"""

import pytest
from core.cdt import (
    CDTGenerator,
    CDTValidator,
    CDTStatus,
    PolicyState,
    ConsentDNAToken,
    generate_cdt,
    verify_cdt,
)


class TestCDTGeneration:
    """Test CDT generation according to patent specification."""

    def test_generate_deterministic(self):
        """CDT generation must be deterministic for same inputs."""
        generator = CDTGenerator()

        policy = PolicyState(
            subject_id="user-123",
            partner_id="partner-456",
            purposes=("INFERENCE", "ANALYTICS"),
            data_categories=("TEXT",),
            retention_period_days=365,
            jurisdiction="GDPR_EU",
        )

        cdt1 = generator.generate(policy, epoch=1)
        cdt2 = generator.generate(policy, epoch=1)

        assert cdt1.token_value == cdt2.token_value
        assert cdt1.policy_hash == cdt2.policy_hash

    def test_different_epoch_different_cdt(self):
        """Different epochs must produce different CDTs."""
        generator = CDTGenerator()

        policy = PolicyState(
            subject_id="user-123",
            partner_id="partner-456",
            purposes=("INFERENCE",),
            data_categories=("TEXT",),
            retention_period_days=365,
            jurisdiction="GDPR_EU",
        )

        cdt1 = generator.generate(policy, epoch=1)
        cdt2 = generator.generate(policy, epoch=2)

        assert cdt1.token_value != cdt2.token_value
        # Policy hash should be the same (only epoch differs)
        assert cdt1.policy_hash == cdt2.policy_hash

    def test_different_policy_different_cdt(self):
        """Different policies must produce different CDTs."""
        generator = CDTGenerator()

        policy1 = PolicyState(
            subject_id="user-123",
            partner_id="partner-456",
            purposes=("INFERENCE",),
            data_categories=("TEXT",),
            retention_period_days=365,
            jurisdiction="GDPR_EU",
        )

        policy2 = PolicyState(
            subject_id="user-123",
            partner_id="partner-456",
            purposes=("INFERENCE", "TRAINING"),  # Added TRAINING
            data_categories=("TEXT",),
            retention_period_days=365,
            jurisdiction="GDPR_EU",
        )

        cdt1 = generator.generate(policy1, epoch=1)
        cdt2 = generator.generate(policy2, epoch=1)

        assert cdt1.token_value != cdt2.token_value
        assert cdt1.policy_hash != cdt2.policy_hash

    def test_canonicalization_order_independence(self):
        """Canonicalization should produce same result regardless of input order."""
        policy1 = PolicyState(
            subject_id="user-123",
            partner_id="partner-456",
            purposes=("ANALYTICS", "INFERENCE"),  # Order: A, I
            data_categories=("TEXT",),
            retention_period_days=365,
            jurisdiction="GDPR_EU",
        )

        policy2 = PolicyState(
            subject_id="user-123",
            partner_id="partner-456",
            purposes=("INFERENCE", "ANALYTICS"),  # Order: I, A
            data_categories=("TEXT",),
            retention_period_days=365,
            jurisdiction="GDPR_EU",
        )

        # Canonicalization should sort purposes
        assert policy1.canonicalize() == policy2.canonicalize()

    def test_sha3_256_hash_length(self):
        """CDT should be SHA3-256 (64 hex chars)."""
        generator = CDTGenerator()

        policy = PolicyState(
            subject_id="user-123",
            partner_id="partner-456",
            purposes=("INFERENCE",),
            data_categories=("TEXT",),
            retention_period_days=365,
            jurisdiction="GDPR_EU",
        )

        cdt = generator.generate(policy, epoch=1)

        assert len(cdt.token_value) == 64  # SHA3-256 = 256 bits = 64 hex chars


class TestCDTValidation:
    """Test CDT validation and epoch-based revocation."""

    def test_valid_cdt_validates(self):
        """A CDT generated with current epoch should validate."""
        generator = CDTGenerator()
        validator = CDTValidator(generator)

        policy = PolicyState(
            subject_id="user-123",
            partner_id="partner-456",
            purposes=("INFERENCE",),
            data_categories=("TEXT",),
            retention_period_days=365,
            jurisdiction="GDPR_EU",
        )

        cdt = generator.generate(policy, epoch=5)
        status, error = validator.validate(cdt, policy, current_epoch=5)

        assert status == CDTStatus.VALID
        assert error is None

    def test_epoch_mismatch_fails(self):
        """CDT from old epoch should fail validation (INSTANT REVOCATION)."""
        generator = CDTGenerator()
        validator = CDTValidator(generator)

        policy = PolicyState(
            subject_id="user-123",
            partner_id="partner-456",
            purposes=("INFERENCE",),
            data_categories=("TEXT",),
            retention_period_days=365,
            jurisdiction="GDPR_EU",
        )

        # Generate CDT at epoch 1
        cdt = generator.generate(policy, epoch=1)

        # Validate at epoch 2 (epoch incremented = consent revoked)
        status, error = validator.validate(cdt, policy, current_epoch=2)

        assert status == CDTStatus.REVOKED_EPOCH_MISMATCH
        assert "epoch" in error.lower()

    def test_policy_change_fails(self):
        """CDT from changed policy should fail validation."""
        generator = CDTGenerator()
        validator = CDTValidator(generator)

        original_policy = PolicyState(
            subject_id="user-123",
            partner_id="partner-456",
            purposes=("INFERENCE",),
            data_categories=("TEXT",),
            retention_period_days=365,
            jurisdiction="GDPR_EU",
        )

        modified_policy = PolicyState(
            subject_id="user-123",
            partner_id="partner-456",
            purposes=("INFERENCE", "TRAINING"),  # Policy changed!
            data_categories=("TEXT",),
            retention_period_days=365,
            jurisdiction="GDPR_EU",
        )

        cdt = generator.generate(original_policy, epoch=1)
        status, error = validator.validate(cdt, modified_policy, current_epoch=1)

        assert status == CDTStatus.INVALID_SIGNATURE


class TestCDTConvenienceFunctions:
    """Test the standalone convenience functions matching patent pseudocode."""

    def test_generate_cdt_function(self):
        """Test the simple generate_cdt function."""
        policy_dict = {
            "subject_id": "user-123",
            "partner_id": "partner-456",
            "purposes": ["INFERENCE"],
        }

        cdt = generate_cdt(policy_dict, global_epoch=1)

        assert len(cdt) == 64
        assert isinstance(cdt, str)

    def test_verify_cdt_function_valid(self):
        """Test the simple verify_cdt function with valid CDT."""
        policy_dict = {
            "subject_id": "user-123",
            "partner_id": "partner-456",
            "purposes": ["INFERENCE"],
        }

        cdt = generate_cdt(policy_dict, global_epoch=1)
        is_valid = verify_cdt(cdt, policy_dict, global_epoch=1)

        assert is_valid is True

    def test_verify_cdt_function_invalid_epoch(self):
        """Test the simple verify_cdt function with wrong epoch."""
        policy_dict = {
            "subject_id": "user-123",
            "partner_id": "partner-456",
            "purposes": ["INFERENCE"],
        }

        cdt = generate_cdt(policy_dict, global_epoch=1)
        is_valid = verify_cdt(cdt, policy_dict, global_epoch=2)

        assert is_valid is False


class TestInstantRevocation:
    """Test the instant revocation mechanism (core patent claim)."""

    def test_revocation_is_instant(self):
        """Epoch increment should INSTANTLY invalidate all prior CDTs."""
        generator = CDTGenerator()
        validator = CDTValidator(generator)

        policy = PolicyState(
            subject_id="user-123",
            partner_id="partner-456",
            purposes=("INFERENCE",),
            data_categories=("TEXT",),
            retention_period_days=365,
            jurisdiction="GDPR_EU",
        )

        # Generate 100 CDTs at epoch 1
        cdts = [generator.generate(policy, epoch=1) for _ in range(100)]

        # All should be valid at epoch 1
        for cdt in cdts:
            status, _ = validator.validate(cdt, policy, current_epoch=1)
            assert status == CDTStatus.VALID

        # Epoch increment (simulating revocation)
        new_epoch = 2

        # ALL 100 CDTs should now be INSTANTLY invalid
        for cdt in cdts:
            status, _ = validator.validate(cdt, policy, current_epoch=new_epoch)
            assert status == CDTStatus.REVOKED_EPOCH_MISMATCH

    def test_no_cache_needed(self):
        """Demonstrate that no revocation cache/list is needed."""
        generator = CDTGenerator()

        policy = PolicyState(
            subject_id="user-123",
            partner_id="partner-456",
            purposes=("INFERENCE",),
            data_categories=("TEXT",),
            retention_period_days=365,
            jurisdiction="GDPR_EU",
        )

        # Generate CDT at epoch 1
        old_cdt_value = generator.generate(policy, epoch=1).token_value

        # At epoch 2, regenerating the SAME policy produces DIFFERENT CDT
        new_cdt_value = generator.generate(policy, epoch=2).token_value

        assert old_cdt_value != new_cdt_value

        # We don't need to maintain a list of revoked CDTs
        # We just need to know the current epoch
        # Old CDT will simply fail validation because it won't match
