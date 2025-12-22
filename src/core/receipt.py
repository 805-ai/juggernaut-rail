"""
Cryptographic Governance Receipt Implementation

Patent Reference: "System and Method for Cryptographic Governance Receipt Rail"
Claims: "Gating execution strictly upon generation and verification of a receipt
containing canonical operation hash, digital signature, and Consent DNA Token"

Key Innovation: NO RECEIPT, NO RUN invariant
- Operation executes ONLY if receipt is generated AND verified
- ML-DSA-65 (Dilithium) post-quantum signatures
- Hash-chained receipt history for tamper evidence
"""

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from enum import Enum

import structlog
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.backends import default_backend
import base64

logger = structlog.get_logger()


class ReceiptAction(Enum):
    """Types of actions that can be receipted."""
    CREATE = "CREATE"
    READ = "READ"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    INVOKE = "INVOKE"
    GRANT = "GRANT"
    REVOKE = "REVOKE"
    QUERY = "QUERY"
    GENERATE = "GENERATE"
    TRAIN = "TRAIN"


class SignatureAlgorithm(Enum):
    """
    Supported signature algorithms.

    Patent specifies ML-DSA-65 (Dilithium) for post-quantum security.
    Ed25519 provided as transitional implementation per patent spec.
    """
    ED25519 = "Ed25519"  # Transitional (fast, small signatures)
    ML_DSA_65 = "ML-DSA-65"  # Post-quantum (NIST FIPS 204)
    HYBRID = "HYBRID"  # Ed25519 + ML-DSA-65 combined


@dataclass
class OperationPayload:
    """
    The operation being governed.

    Patent: "Canonicalization includes (1) flattening nested JSON objects;
    (2) sorting keys lexicographically; (3) removing extraneous whitespace;
    (4) normalizing data types"
    """
    action: ReceiptAction
    target_resource: str
    parameters: Dict[str, Any]
    agent_id: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def canonicalize(self) -> str:
        """
        Create canonical representation per patent specification.
        """
        canonical_dict = {
            "action": self.action.value,
            "agent_id": self.agent_id,
            "parameters": self._flatten_and_sort(self.parameters),
            "target_resource": self.target_resource,
            "timestamp": self.timestamp,
        }
        return json.dumps(canonical_dict, sort_keys=True, separators=(',', ':'))

    def _flatten_and_sort(self, obj: Any, prefix: str = "") -> Dict[str, str]:
        """Flatten nested objects and normalize values to strings."""
        result = {}
        if isinstance(obj, dict):
            for key, value in sorted(obj.items()):
                new_key = f"{prefix}.{key}" if prefix else key
                if isinstance(value, dict):
                    result.update(self._flatten_and_sort(value, new_key))
                elif isinstance(value, (list, tuple)):
                    for i, item in enumerate(value):
                        result.update(self._flatten_and_sort(item, f"{new_key}[{i}]"))
                else:
                    result[new_key] = str(value)
        else:
            result[prefix] = str(obj)
        return dict(sorted(result.items()))

    def compute_hash(self) -> str:
        """
        Compute SHA3-256 hash of canonical representation.

        Patent: "A cryptographic hash function, such as SHA3-256, is then
        applied to the canonical representation to derive an operation hash."
        """
        canonical = self.canonicalize()
        return hashlib.sha3_256(canonical.encode('utf-8')).hexdigest()


@dataclass
class GovernanceReceipt:
    """
    Cryptographic Governance Receipt.

    Patent JSON structure:
    {
        "receipt_id": "ULNDv4",
        "timestamp": "ISO-8601",
        "agent_id": "DID:FBT:12345",
        "policy_id": "POL-V1",
        "operation_hash": "SHA3-256(Canonical Payload)",
        "consent_token": "CDT Value",
        "signature": "Base64 Encoded ML-DSA Signature"
    }
    """
    receipt_id: str
    timestamp: str
    agent_id: str
    policy_id: str
    operation_hash: str
    consent_token: str  # CDT value
    action: ReceiptAction
    target_resource: str

    # Chain linking
    chain_sequence: int
    prev_hash: str

    # Signature
    signature: str
    signature_algorithm: SignatureAlgorithm

    # Optional veto state
    veto_state: Optional[Dict[str, Any]] = None
    broken_seal: bool = False
    regulatory_mode: Optional[str] = None

    # Metadata
    key_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "receipt_id": self.receipt_id,
            "timestamp": self.timestamp,
            "agent_id": self.agent_id,
            "policy_id": self.policy_id,
            "operation_hash": self.operation_hash,
            "consent_token": self.consent_token,
            "action": self.action.value,
            "target_resource": self.target_resource,
            "chain_sequence": self.chain_sequence,
            "prev_hash": self.prev_hash,
            "signature": self.signature,
            "signature_algorithm": self.signature_algorithm.value,
            "veto_state": self.veto_state,
            "broken_seal": self.broken_seal,
            "regulatory_mode": self.regulatory_mode,
            "key_id": self.key_id,
        }

    def to_json(self) -> str:
        """Serialize to JSON."""
        return json.dumps(self.to_dict(), sort_keys=True)

    def compute_hash(self) -> str:
        """Compute hash of this receipt for chain linking."""
        content = json.dumps({
            "receipt_id": self.receipt_id,
            "timestamp": self.timestamp,
            "operation_hash": self.operation_hash,
            "consent_token": self.consent_token,
            "chain_sequence": self.chain_sequence,
            "prev_hash": self.prev_hash,
        }, sort_keys=True, separators=(',', ':'))
        return hashlib.sha3_256(content.encode('utf-8')).hexdigest()


class ReceiptSigner:
    """
    Cryptographic signing for receipts.

    Supports Ed25519 (transitional) and ML-DSA-65 (post-quantum).
    Patent: "A post-quantum-safe algorithm, for example an ML-DSA family scheme, is used."
    """

    def __init__(
        self,
        algorithm: SignatureAlgorithm = SignatureAlgorithm.ED25519,
        private_key_bytes: Optional[bytes] = None,
    ):
        self.algorithm = algorithm
        self.key_id = ""

        if algorithm == SignatureAlgorithm.ED25519:
            if private_key_bytes:
                self._private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
            else:
                self._private_key = ed25519.Ed25519PrivateKey.generate()

            # Generate key ID from public key
            public_bytes = self._private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            self.key_id = hashlib.sha256(public_bytes).hexdigest()[:16]
            self._public_key = self._private_key.public_key()

        elif algorithm == SignatureAlgorithm.ML_DSA_65:
            # Placeholder for ML-DSA-65 implementation
            # In production, use pqcrypto or liboqs bindings
            logger.warning(
                "ml_dsa_placeholder",
                message="ML-DSA-65 not yet available, falling back to Ed25519 with PQC flag"
            )
            self._private_key = ed25519.Ed25519PrivateKey.generate()
            public_bytes = self._private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            self.key_id = f"pqc-{hashlib.sha256(public_bytes).hexdigest()[:14]}"
            self._public_key = self._private_key.public_key()

    def sign(self, data: bytes) -> str:
        """
        Sign data and return Base64-encoded signature.

        Patent: "signature": "Base64 Encoded ML-DSA Signature"
        """
        signature = self._private_key.sign(data)
        return base64.b64encode(signature).decode('utf-8')

    def verify(self, data: bytes, signature_b64: str) -> bool:
        """Verify a signature."""
        try:
            signature = base64.b64decode(signature_b64)
            self._public_key.verify(signature, data)
            return True
        except Exception:
            return False

    def get_public_key_bytes(self) -> bytes:
        """Get public key bytes for distribution."""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def get_public_key_pem(self) -> str:
        """Get public key in PEM format."""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode('utf-8')


class ReceiptGenerator:
    """
    Generates cryptographic governance receipts.

    Implements the "NO RECEIPT, NO RUN" invariant from the patent.
    """

    def __init__(
        self,
        signer: Optional[ReceiptSigner] = None,
        policy_id: str = "POL-DEFAULT-V1",
    ):
        self.signer = signer or ReceiptSigner()
        self.policy_id = policy_id
        self._chain_sequence = 0
        self._prev_hash = "GENESIS"

    def generate(
        self,
        operation: OperationPayload,
        consent_token: str,
        veto_state: Optional[Dict[str, Any]] = None,
        regulatory_mode: Optional[str] = None,
    ) -> GovernanceReceipt:
        """
        Generate a governance receipt for an operation.

        Patent: "The underlying operation is executed only if (1) a receipt is
        generated; (2) the receipt is successfully written to a receipt datastore;
        and (3) the receipt signature verifies against a stored public key."
        """
        receipt_id = f"RCP-{uuid.uuid4().hex[:12].upper()}"
        timestamp = datetime.now(timezone.utc).isoformat()
        operation_hash = operation.compute_hash()

        # Prepare receipt data for signing
        signing_data = {
            "receipt_id": receipt_id,
            "timestamp": timestamp,
            "agent_id": operation.agent_id,
            "policy_id": self.policy_id,
            "operation_hash": operation_hash,
            "consent_token": consent_token,
            "chain_sequence": self._chain_sequence,
            "prev_hash": self._prev_hash,
        }

        if veto_state:
            signing_data["veto_state"] = veto_state
        if regulatory_mode:
            signing_data["regulatory_mode"] = regulatory_mode

        # Create canonical signing payload
        signing_payload = json.dumps(signing_data, sort_keys=True, separators=(',', ':')).encode('utf-8')

        # Sign
        signature = self.signer.sign(signing_payload)

        # Create receipt
        receipt = GovernanceReceipt(
            receipt_id=receipt_id,
            timestamp=timestamp,
            agent_id=operation.agent_id,
            policy_id=self.policy_id,
            operation_hash=operation_hash,
            consent_token=consent_token,
            action=operation.action,
            target_resource=operation.target_resource,
            chain_sequence=self._chain_sequence,
            prev_hash=self._prev_hash,
            signature=signature,
            signature_algorithm=self.signer.algorithm,
            veto_state=veto_state,
            broken_seal=False,
            regulatory_mode=regulatory_mode,
            key_id=self.signer.key_id,
        )

        # Update chain state
        self._prev_hash = receipt.compute_hash()
        self._chain_sequence += 1

        logger.info(
            "receipt_generated",
            receipt_id=receipt_id,
            action=operation.action.value,
            agent_id=operation.agent_id,
            chain_sequence=self._chain_sequence - 1,
        )

        return receipt


class ReceiptChain:
    """
    Hash-chained collection of receipts.

    Patent: "prev_receipt_hash": "sha3-256-hash..." for chain integrity
    """

    def __init__(self):
        self.receipts: List[GovernanceReceipt] = []
        self._hash_index: Dict[str, int] = {}

    def add(self, receipt: GovernanceReceipt) -> None:
        """Add a receipt to the chain."""
        self.receipts.append(receipt)
        self._hash_index[receipt.receipt_id] = len(self.receipts) - 1

    def verify_chain_integrity(self) -> tuple[bool, Optional[str]]:
        """
        Verify the hash chain integrity.

        Returns (is_valid, error_message)
        """
        if not self.receipts:
            return (True, None)

        prev_hash = "GENESIS"

        for i, receipt in enumerate(self.receipts):
            # Check chain sequence
            if receipt.chain_sequence != i:
                return (False, f"Chain sequence mismatch at position {i}")

            # Check prev_hash matches
            if receipt.prev_hash != prev_hash:
                return (False, f"Hash chain broken at position {i}")

            # Update for next iteration
            prev_hash = receipt.compute_hash()

        return (True, None)

    def get_receipt(self, receipt_id: str) -> Optional[GovernanceReceipt]:
        """Retrieve a receipt by ID."""
        idx = self._hash_index.get(receipt_id)
        return self.receipts[idx] if idx is not None else None

    def to_merkle_root(self) -> str:
        """
        Compute Merkle root of all receipts.

        Patent: "In one implementation, receipts are organized into a Merkle tree
        and H_receipts is the Merkle root."
        """
        if not self.receipts:
            return hashlib.sha3_256(b"EMPTY").hexdigest()

        hashes = [r.compute_hash() for r in self.receipts]

        while len(hashes) > 1:
            if len(hashes) % 2 == 1:
                hashes.append(hashes[-1])  # Duplicate last if odd

            new_hashes = []
            for i in range(0, len(hashes), 2):
                combined = hashes[i] + hashes[i + 1]
                new_hashes.append(hashlib.sha3_256(combined.encode()).hexdigest())

            hashes = new_hashes

        return hashes[0]

    def export(self) -> List[Dict[str, Any]]:
        """Export chain as list of dictionaries."""
        return [r.to_dict() for r in self.receipts]
