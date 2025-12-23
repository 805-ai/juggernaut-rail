"""
Tests for Cryptographic Primitives

Tests Ed25519, ML-DSA-65, and Hybrid signatures.
"""

import pytest
from crypto.signer import (
    SignatureAlgorithm,
    Ed25519Signer,
    MLDSASigner,
    HybridSigner,
    get_signer,
    LIBOQS_AVAILABLE,
)
from crypto.keys import KeyManager, KeyPair


class TestEd25519Signer:
    """Test Ed25519 signature implementation."""

    def test_generate_key_pair(self):
        """Should generate a valid key pair."""
        signer = Ed25519Signer()

        assert signer.key_id is not None
        assert len(signer.key_id) == 16
        assert signer.algorithm == SignatureAlgorithm.ED25519
        assert signer.is_pqc is False

    def test_sign_and_verify(self):
        """Signature should verify correctly."""
        signer = Ed25519Signer()
        data = b"test message to sign"

        result = signer.sign(data)

        assert result.signature is not None
        assert result.signature_b64 is not None
        assert result.algorithm == SignatureAlgorithm.ED25519

        verify_result = signer.verify(data, result.signature)
        assert verify_result.valid is True

    def test_wrong_data_fails_verification(self):
        """Wrong data should fail verification."""
        signer = Ed25519Signer()
        data = b"original message"

        result = signer.sign(data)
        verify_result = signer.verify(b"different message", result.signature)

        assert verify_result.valid is False

    def test_restore_from_private_key(self):
        """Should restore signer from private key bytes."""
        original = Ed25519Signer()
        private_key = original.get_private_key()

        restored = Ed25519Signer(private_key)

        assert restored.key_id == original.key_id

        # Both should produce same signature
        data = b"test data"
        sig1 = original.sign(data)
        sig2 = restored.sign(data)

        assert sig1.signature == sig2.signature

    def test_base64_sign_verify(self):
        """Test base64 convenience methods."""
        signer = Ed25519Signer()
        data = b"test message"

        sig_b64 = signer.sign_b64(data)
        result = signer.verify_b64(data, sig_b64)

        assert result.valid is True


class TestMLDSASigner:
    """Test ML-DSA-65 signature implementation."""

    def test_simulation_mode(self):
        """ML-DSA should work in simulation mode when liboqs unavailable."""
        signer = MLDSASigner(simulation=True)

        assert signer.algorithm == SignatureAlgorithm.ML_DSA_65
        assert signer.is_pqc is True
        assert signer.is_simulation is True

    def test_sign_verify_simulation(self):
        """Signing should work in simulation mode."""
        signer = MLDSASigner(simulation=True)
        data = b"test message"

        result = signer.sign(data)
        verify_result = signer.verify(data, result.signature)

        assert verify_result.valid is True

    @pytest.mark.skipif(not LIBOQS_AVAILABLE, reason="liboqs not installed")
    def test_real_mldsa_available(self):
        """Test real ML-DSA when liboqs is available."""
        signer = MLDSASigner(simulation=False)

        assert signer.is_simulation is False
        assert signer.key_id.startswith("pqc-")

        data = b"test message"
        result = signer.sign(data)
        verify_result = signer.verify(data, result.signature)

        assert verify_result.valid is True


class TestHybridSigner:
    """Test hybrid Ed25519 + ML-DSA signature implementation."""

    def test_hybrid_signature_structure(self):
        """Hybrid signature should contain both component signatures."""
        signer = HybridSigner()

        assert signer.algorithm == SignatureAlgorithm.HYBRID
        assert signer.is_pqc is True
        assert "hybrid" in signer.key_id

    def test_hybrid_sign_verify(self):
        """Hybrid signature should verify correctly."""
        signer = HybridSigner()
        data = b"test message"

        result = signer.sign(data)

        # Hybrid signature should be larger than Ed25519 alone
        assert len(result.signature) > 64  # Ed25519 is 64 bytes

        verify_result = signer.verify(data, result.signature)
        assert verify_result.valid is True

    def test_hybrid_wrong_data_fails(self):
        """Wrong data should fail hybrid verification."""
        signer = HybridSigner()
        data = b"original message"

        result = signer.sign(data)
        verify_result = signer.verify(b"different message", result.signature)

        assert verify_result.valid is False

    def test_hybrid_tampered_signature_fails(self):
        """Tampered signature should fail."""
        signer = HybridSigner()
        data = b"test message"

        result = signer.sign(data)

        # Tamper with signature
        tampered = bytearray(result.signature)
        tampered[10] ^= 0xFF  # Flip bits
        tampered = bytes(tampered)

        verify_result = signer.verify(data, tampered)
        assert verify_result.valid is False


class TestGetSigner:
    """Test the signer factory function."""

    def test_get_ed25519_signer(self):
        """Factory should return Ed25519 signer."""
        signer = get_signer(SignatureAlgorithm.ED25519)

        assert signer.algorithm == SignatureAlgorithm.ED25519
        assert isinstance(signer, Ed25519Signer)

    def test_get_mldsa_signer(self):
        """Factory should return ML-DSA signer."""
        signer = get_signer(SignatureAlgorithm.ML_DSA_65)

        assert signer.algorithm == SignatureAlgorithm.ML_DSA_65
        assert isinstance(signer, MLDSASigner)

    def test_get_hybrid_signer(self):
        """Factory should return hybrid signer."""
        signer = get_signer(SignatureAlgorithm.HYBRID)

        assert signer.algorithm == SignatureAlgorithm.HYBRID
        assert isinstance(signer, HybridSigner)


class TestKeyManager:
    """Test key management functionality."""

    def test_generate_key(self, temp_keys_dir):
        """Should generate and store a key."""
        manager = KeyManager(storage_path=temp_keys_dir)
        keypair = manager.generate_key(algorithm=SignatureAlgorithm.ED25519)

        assert keypair.key_id is not None
        assert keypair.status == "ACTIVE"
        assert keypair.algorithm == SignatureAlgorithm.ED25519

    def test_get_signer_from_manager(self, temp_keys_dir):
        """Should retrieve signer from stored key."""
        manager = KeyManager(storage_path=temp_keys_dir)
        keypair = manager.generate_key()

        signer = manager.get_signer(keypair.key_id)

        assert signer.key_id == keypair.key_id

        # Should be able to sign
        data = b"test"
        result = signer.sign(data)
        assert signer.verify(data, result.signature).valid

    def test_key_rotation(self, temp_keys_dir):
        """Should support key rotation."""
        manager = KeyManager(storage_path=temp_keys_dir)
        old_keypair = manager.generate_key()

        new_keypair = manager.rotate_key(old_keypair.key_id)

        assert new_keypair.key_id != old_keypair.key_id
        assert new_keypair.status == "ACTIVE"

        # Old key should be marked as rotated
        old_key = manager._keys.get(old_keypair.key_id)
        assert old_key.status == "ROTATED"

    def test_key_revocation(self, temp_keys_dir):
        """Should support key revocation."""
        manager = KeyManager(storage_path=temp_keys_dir)
        keypair = manager.generate_key()

        manager.revoke_key(keypair.key_id)

        revoked = manager._keys.get(keypair.key_id)
        assert revoked.status == "REVOKED"

    def test_export_public_keys(self, temp_keys_dir):
        """Should export public keys for distribution."""
        manager = KeyManager(storage_path=temp_keys_dir)
        manager.generate_key()
        manager.generate_key()

        public_keys = manager.export_public_keys()

        assert len(public_keys) == 2
        for key_id, key_data in public_keys.items():
            assert "public_key" in key_data
            assert "algorithm" in key_data
            assert "private_key" not in key_data  # Should not include private!

    def test_verify_with_any_key(self, temp_keys_dir):
        """Should verify signature against multiple keys."""
        manager = KeyManager(storage_path=temp_keys_dir)
        kp1 = manager.generate_key()
        kp2 = manager.generate_key()

        # Sign with first key
        signer1 = manager.get_signer(kp1.key_id)
        data = b"test message"
        result = signer1.sign(data)

        # Verify against both keys
        is_valid, key_id = manager.verify_with_any_key(data, result.signature)

        assert is_valid is True
        assert key_id == kp1.key_id
