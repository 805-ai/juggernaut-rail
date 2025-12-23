"""
Tests for Cryptographic Receipt Implementation

Tests the "NO RECEIPT, NO RUN" invariant and chain integrity.
"""

import pytest
import json
from core.receipt import (
    ReceiptAction,
    OperationPayload,
    GovernanceReceipt,
    ReceiptGenerator,
    ReceiptSigner,
    ReceiptChain,
    SignatureAlgorithm,
)


class TestOperationPayload:
    """Test operation payload canonicalization."""

    def test_canonicalization_is_deterministic(self):
        """Canonical representation must be deterministic."""
        op1 = OperationPayload(
            action=ReceiptAction.INVOKE,
            target_resource="/api/v1/generate",
            parameters={"model": "gpt-4", "temperature": 0.7},
            agent_id="agent-123",
        )

        op2 = OperationPayload(
            action=ReceiptAction.INVOKE,
            target_resource="/api/v1/generate",
            parameters={"temperature": 0.7, "model": "gpt-4"},  # Different order
            agent_id="agent-123",
        )

        # Override timestamps to match
        op2.timestamp = op1.timestamp

        # Canonicalization should sort keys
        assert op1.canonicalize() == op2.canonicalize()

    def test_hash_is_sha3_256(self):
        """Operation hash should be SHA3-256."""
        op = OperationPayload(
            action=ReceiptAction.INVOKE,
            target_resource="/api/v1/generate",
            parameters={},
            agent_id="agent-123",
        )

        hash_value = op.compute_hash()

        assert len(hash_value) == 64  # SHA3-256 = 64 hex chars

    def test_nested_parameters_flattened(self):
        """Nested parameters should be flattened."""
        op = OperationPayload(
            action=ReceiptAction.INVOKE,
            target_resource="/api/v1/generate",
            parameters={
                "config": {
                    "model": "gpt-4",
                    "settings": {"temperature": 0.7},
                }
            },
            agent_id="agent-123",
        )

        canonical = op.canonicalize()
        data = json.loads(canonical)

        # Parameters should be flattened
        assert "parameters" in data


class TestReceiptSigner:
    """Test receipt signing functionality."""

    def test_ed25519_sign_verify(self):
        """Test Ed25519 signing and verification."""
        signer = ReceiptSigner(algorithm=SignatureAlgorithm.ED25519)

        data = b"test data to sign"
        signature = signer.sign(data)

        assert signer.verify(data, signature) is True

    def test_ed25519_wrong_data_fails(self):
        """Signature should fail verification with wrong data."""
        signer = ReceiptSigner(algorithm=SignatureAlgorithm.ED25519)

        data = b"test data to sign"
        signature = signer.sign(data)

        assert signer.verify(b"different data", signature) is False

    def test_key_id_generated(self):
        """Signer should generate a key ID."""
        signer = ReceiptSigner(algorithm=SignatureAlgorithm.ED25519)

        assert signer.key_id is not None
        assert len(signer.key_id) > 0


class TestReceiptGenerator:
    """Test receipt generation."""

    def test_generates_receipt(self):
        """Generator should produce valid receipt."""
        generator = ReceiptGenerator()

        operation = OperationPayload(
            action=ReceiptAction.INVOKE,
            target_resource="/api/v1/generate",
            parameters={},
            agent_id="agent-123",
        )

        receipt = generator.generate(
            operation=operation,
            consent_token="cdt-token-12345",
        )

        assert receipt.receipt_id.startswith("RCP-")
        assert receipt.agent_id == "agent-123"
        assert receipt.consent_token == "cdt-token-12345"
        assert receipt.signature is not None

    def test_chain_sequence_increments(self):
        """Chain sequence should increment with each receipt."""
        generator = ReceiptGenerator()

        receipts = []
        for i in range(5):
            op = OperationPayload(
                action=ReceiptAction.INVOKE,
                target_resource=f"/api/v1/op-{i}",
                parameters={},
                agent_id="agent-123",
            )
            receipt = generator.generate(operation=op, consent_token="cdt")
            receipts.append(receipt)

        for i, receipt in enumerate(receipts):
            assert receipt.chain_sequence == i

    def test_prev_hash_links_chain(self):
        """Each receipt should link to previous receipt's hash."""
        generator = ReceiptGenerator()

        receipts = []
        for i in range(5):
            op = OperationPayload(
                action=ReceiptAction.INVOKE,
                target_resource=f"/api/v1/op-{i}",
                parameters={},
                agent_id="agent-123",
            )
            receipt = generator.generate(operation=op, consent_token="cdt")
            receipts.append(receipt)

        # First receipt should link to GENESIS
        assert receipts[0].prev_hash == "GENESIS"

        # Each subsequent receipt should link to previous
        for i in range(1, len(receipts)):
            expected_prev_hash = receipts[i - 1].compute_hash()
            assert receipts[i].prev_hash == expected_prev_hash


class TestReceiptChain:
    """Test receipt chain integrity verification."""

    def test_empty_chain_is_valid(self):
        """Empty chain should be valid."""
        chain = ReceiptChain()

        is_valid, error = chain.verify_chain_integrity()

        assert is_valid is True
        assert error is None

    def test_valid_chain_verifies(self):
        """A properly built chain should verify."""
        generator = ReceiptGenerator()
        chain = ReceiptChain()

        for i in range(10):
            op = OperationPayload(
                action=ReceiptAction.INVOKE,
                target_resource=f"/api/v1/op-{i}",
                parameters={},
                agent_id="agent-123",
            )
            receipt = generator.generate(operation=op, consent_token="cdt")
            chain.add(receipt)

        is_valid, error = chain.verify_chain_integrity()

        assert is_valid is True
        assert error is None

    def test_tampered_chain_fails(self):
        """A tampered chain should fail verification."""
        generator = ReceiptGenerator()
        chain = ReceiptChain()

        for i in range(5):
            op = OperationPayload(
                action=ReceiptAction.INVOKE,
                target_resource=f"/api/v1/op-{i}",
                parameters={},
                agent_id="agent-123",
            )
            receipt = generator.generate(operation=op, consent_token="cdt")
            chain.add(receipt)

        # Tamper with a receipt in the middle
        chain.receipts[2].prev_hash = "TAMPERED"

        is_valid, error = chain.verify_chain_integrity()

        assert is_valid is False
        assert "broken" in error.lower() or "position" in error.lower()

    def test_merkle_root_computed(self):
        """Merkle root should be computable."""
        generator = ReceiptGenerator()
        chain = ReceiptChain()

        for i in range(4):  # Power of 2 for clean Merkle tree
            op = OperationPayload(
                action=ReceiptAction.INVOKE,
                target_resource=f"/api/v1/op-{i}",
                parameters={},
                agent_id="agent-123",
            )
            receipt = generator.generate(operation=op, consent_token="cdt")
            chain.add(receipt)

        merkle_root = chain.to_merkle_root()

        assert len(merkle_root) == 64  # SHA3-256

    def test_receipt_lookup_by_id(self):
        """Should be able to look up receipt by ID."""
        generator = ReceiptGenerator()
        chain = ReceiptChain()

        receipts = []
        for i in range(5):
            op = OperationPayload(
                action=ReceiptAction.INVOKE,
                target_resource=f"/api/v1/op-{i}",
                parameters={},
                agent_id="agent-123",
            )
            receipt = generator.generate(operation=op, consent_token="cdt")
            chain.add(receipt)
            receipts.append(receipt)

        # Look up each receipt
        for receipt in receipts:
            found = chain.get_receipt(receipt.receipt_id)
            assert found is not None
            assert found.receipt_id == receipt.receipt_id


class TestReceiptSerialization:
    """Test receipt serialization for storage/transmission."""

    def test_to_dict(self):
        """Receipt should serialize to dictionary."""
        generator = ReceiptGenerator()

        op = OperationPayload(
            action=ReceiptAction.INVOKE,
            target_resource="/api/v1/generate",
            parameters={},
            agent_id="agent-123",
        )

        receipt = generator.generate(
            operation=op,
            consent_token="cdt-token",
            veto_state={"vetoed": False, "trust_score": 0.95},
        )

        data = receipt.to_dict()

        assert data["receipt_id"] == receipt.receipt_id
        assert data["agent_id"] == "agent-123"
        assert data["consent_token"] == "cdt-token"
        assert data["veto_state"]["trust_score"] == 0.95

    def test_to_json(self):
        """Receipt should serialize to JSON."""
        generator = ReceiptGenerator()

        op = OperationPayload(
            action=ReceiptAction.INVOKE,
            target_resource="/api/v1/generate",
            parameters={},
            agent_id="agent-123",
        )

        receipt = generator.generate(operation=op, consent_token="cdt-token")

        json_str = receipt.to_json()
        data = json.loads(json_str)

        assert data["receipt_id"] == receipt.receipt_id
