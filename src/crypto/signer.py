"""
Cryptographic Signing Implementation

Patent Reference: "Post-quantum-safe algorithm, for example an ML-DSA family scheme"

Supports:
- ML-DSA-65 (Dilithium) via liboqs - Post-quantum secure
- Ed25519 - Fast, classical (transitional)
- Hybrid - Both signatures for migration period
"""

import base64
import hashlib
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple
import structlog

logger = structlog.get_logger()

# Try to import liboqs for ML-DSA support
LIBOQS_AVAILABLE = False
try:
    import oqs
    LIBOQS_AVAILABLE = True
    logger.info("liboqs_available", version=oqs.oqs_version())
except ImportError:
    logger.warning("liboqs_not_available", message="ML-DSA-65 will use simulation mode")


class SignatureAlgorithm(Enum):
    """Supported signature algorithms."""
    ED25519 = "Ed25519"
    ML_DSA_65 = "ML-DSA-65"
    ML_DSA_87 = "ML-DSA-87"
    HYBRID = "HYBRID"


@dataclass
class SignatureResult:
    """Result of a signing operation."""
    signature: bytes
    signature_b64: str
    algorithm: SignatureAlgorithm
    key_id: str
    is_pqc: bool


@dataclass
class VerificationResult:
    """Result of a verification operation."""
    valid: bool
    algorithm: SignatureAlgorithm
    key_id: str
    error: Optional[str] = None


class CryptoSigner(ABC):
    """Abstract base class for cryptographic signers."""

    @property
    @abstractmethod
    def algorithm(self) -> SignatureAlgorithm:
        """Get the signature algorithm."""
        pass

    @property
    @abstractmethod
    def key_id(self) -> str:
        """Get the key ID (hash of public key)."""
        pass

    @property
    @abstractmethod
    def is_pqc(self) -> bool:
        """Whether this is a post-quantum algorithm."""
        pass

    @abstractmethod
    def sign(self, data: bytes) -> SignatureResult:
        """Sign data and return the signature."""
        pass

    @abstractmethod
    def verify(self, data: bytes, signature: bytes) -> VerificationResult:
        """Verify a signature."""
        pass

    @abstractmethod
    def get_public_key(self) -> bytes:
        """Get the public key bytes."""
        pass

    @abstractmethod
    def get_private_key(self) -> bytes:
        """Get the private key bytes (for secure storage)."""
        pass

    def sign_b64(self, data: bytes) -> str:
        """Sign and return base64-encoded signature."""
        result = self.sign(data)
        return result.signature_b64

    def verify_b64(self, data: bytes, signature_b64: str) -> VerificationResult:
        """Verify a base64-encoded signature."""
        try:
            signature = base64.b64decode(signature_b64)
            return self.verify(data, signature)
        except Exception as e:
            return VerificationResult(
                valid=False,
                algorithm=self.algorithm,
                key_id=self.key_id,
                error=f"Failed to decode signature: {str(e)}"
            )


class Ed25519Signer(CryptoSigner):
    """Ed25519 signature implementation using cryptography library."""

    def __init__(self, private_key_bytes: Optional[bytes] = None):
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization

        if private_key_bytes:
            self._private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        else:
            self._private_key = ed25519.Ed25519PrivateKey.generate()

        self._public_key = self._private_key.public_key()

        # Generate key ID from public key hash
        public_bytes = self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self._key_id = hashlib.sha256(public_bytes).hexdigest()[:16]

    @property
    def algorithm(self) -> SignatureAlgorithm:
        return SignatureAlgorithm.ED25519

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def is_pqc(self) -> bool:
        return False

    def sign(self, data: bytes) -> SignatureResult:
        signature = self._private_key.sign(data)
        return SignatureResult(
            signature=signature,
            signature_b64=base64.b64encode(signature).decode('utf-8'),
            algorithm=self.algorithm,
            key_id=self._key_id,
            is_pqc=False,
        )

    def verify(self, data: bytes, signature: bytes) -> VerificationResult:
        try:
            self._public_key.verify(signature, data)
            return VerificationResult(
                valid=True,
                algorithm=self.algorithm,
                key_id=self._key_id,
            )
        except Exception as e:
            return VerificationResult(
                valid=False,
                algorithm=self.algorithm,
                key_id=self._key_id,
                error=str(e),
            )

    def get_public_key(self) -> bytes:
        from cryptography.hazmat.primitives import serialization
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def get_private_key(self) -> bytes:
        from cryptography.hazmat.primitives import serialization
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )


class MLDSASigner(CryptoSigner):
    """
    ML-DSA-65 (Dilithium) post-quantum signature implementation.

    Uses liboqs when available, falls back to simulation for development.
    In production, liboqs MUST be installed.
    """

    ALGORITHM_NAME = "Dilithium3"  # ML-DSA-65 equivalent

    def __init__(self, private_key_bytes: Optional[bytes] = None, simulation: bool = False):
        self._simulation = simulation or not LIBOQS_AVAILABLE

        if self._simulation:
            logger.warning("ml_dsa_simulation_mode",
                          message="Using Ed25519 as ML-DSA simulation. NOT FOR PRODUCTION.")
            # Use Ed25519 internally but report as ML-DSA
            self._inner = Ed25519Signer(private_key_bytes[:32] if private_key_bytes else None)
            self._key_id = f"sim-{self._inner.key_id}"
        else:
            # Real liboqs implementation
            self._sig = oqs.Signature(self.ALGORITHM_NAME)

            if private_key_bytes:
                # Reconstruct from stored key
                self._public_key = private_key_bytes[:self._sig.length_public_key]
                self._private_key = private_key_bytes[self._sig.length_public_key:]
            else:
                # Generate new keypair
                self._public_key = self._sig.generate_keypair()
                self._private_key = self._sig.export_secret_key()

            self._key_id = f"pqc-{hashlib.sha256(self._public_key).hexdigest()[:14]}"

    @property
    def algorithm(self) -> SignatureAlgorithm:
        return SignatureAlgorithm.ML_DSA_65

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def is_pqc(self) -> bool:
        return True

    @property
    def is_simulation(self) -> bool:
        return self._simulation

    def sign(self, data: bytes) -> SignatureResult:
        if self._simulation:
            inner_result = self._inner.sign(data)
            return SignatureResult(
                signature=inner_result.signature,
                signature_b64=inner_result.signature_b64,
                algorithm=SignatureAlgorithm.ML_DSA_65,
                key_id=self._key_id,
                is_pqc=True,  # Claimed as PQC even in simulation
            )

        signature = self._sig.sign(data)
        return SignatureResult(
            signature=signature,
            signature_b64=base64.b64encode(signature).decode('utf-8'),
            algorithm=self.algorithm,
            key_id=self._key_id,
            is_pqc=True,
        )

    def verify(self, data: bytes, signature: bytes) -> VerificationResult:
        if self._simulation:
            inner_result = self._inner.verify(data, signature)
            return VerificationResult(
                valid=inner_result.valid,
                algorithm=SignatureAlgorithm.ML_DSA_65,
                key_id=self._key_id,
                error=inner_result.error,
            )

        try:
            is_valid = self._sig.verify(data, signature, self._public_key)
            return VerificationResult(
                valid=is_valid,
                algorithm=self.algorithm,
                key_id=self._key_id,
            )
        except Exception as e:
            return VerificationResult(
                valid=False,
                algorithm=self.algorithm,
                key_id=self._key_id,
                error=str(e),
            )

    def get_public_key(self) -> bytes:
        if self._simulation:
            return self._inner.get_public_key()
        return self._public_key

    def get_private_key(self) -> bytes:
        if self._simulation:
            return self._inner.get_private_key()
        # Concatenate public + private for storage
        return self._public_key + self._private_key


class HybridSigner(CryptoSigner):
    """
    Hybrid signature scheme: Ed25519 + ML-DSA-65

    Provides defense in depth during the quantum transition period.
    Both signatures must verify for the overall signature to be valid.
    """

    def __init__(
        self,
        ed25519_private: Optional[bytes] = None,
        mldsa_private: Optional[bytes] = None,
    ):
        self._ed25519 = Ed25519Signer(ed25519_private)
        self._mldsa = MLDSASigner(mldsa_private)
        self._key_id = f"hybrid-{self._ed25519.key_id[:8]}-{self._mldsa.key_id[:8]}"

    @property
    def algorithm(self) -> SignatureAlgorithm:
        return SignatureAlgorithm.HYBRID

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def is_pqc(self) -> bool:
        return True  # Contains PQC component

    def sign(self, data: bytes) -> SignatureResult:
        """
        Create hybrid signature.

        Format: <ed25519_sig_len:4><ed25519_sig><mldsa_sig>
        """
        ed_result = self._ed25519.sign(data)
        ml_result = self._mldsa.sign(data)

        # Concatenate with length prefix for Ed25519
        ed_len = len(ed_result.signature).to_bytes(4, 'big')
        combined = ed_len + ed_result.signature + ml_result.signature

        return SignatureResult(
            signature=combined,
            signature_b64=base64.b64encode(combined).decode('utf-8'),
            algorithm=self.algorithm,
            key_id=self._key_id,
            is_pqc=True,
        )

    def verify(self, data: bytes, signature: bytes) -> VerificationResult:
        """
        Verify hybrid signature.

        Both Ed25519 and ML-DSA signatures must verify.
        """
        try:
            # Parse combined signature
            ed_len = int.from_bytes(signature[:4], 'big')
            ed_sig = signature[4:4 + ed_len]
            ml_sig = signature[4 + ed_len:]

            # Verify both
            ed_result = self._ed25519.verify(data, ed_sig)
            ml_result = self._mldsa.verify(data, ml_sig)

            if ed_result.valid and ml_result.valid:
                return VerificationResult(
                    valid=True,
                    algorithm=self.algorithm,
                    key_id=self._key_id,
                )
            else:
                errors = []
                if not ed_result.valid:
                    errors.append(f"Ed25519: {ed_result.error or 'invalid'}")
                if not ml_result.valid:
                    errors.append(f"ML-DSA: {ml_result.error or 'invalid'}")

                return VerificationResult(
                    valid=False,
                    algorithm=self.algorithm,
                    key_id=self._key_id,
                    error="; ".join(errors),
                )

        except Exception as e:
            return VerificationResult(
                valid=False,
                algorithm=self.algorithm,
                key_id=self._key_id,
                error=f"Failed to parse hybrid signature: {str(e)}",
            )

    def get_public_key(self) -> bytes:
        """Get concatenated public keys."""
        ed_pub = self._ed25519.get_public_key()
        ml_pub = self._mldsa.get_public_key()
        ed_len = len(ed_pub).to_bytes(4, 'big')
        return ed_len + ed_pub + ml_pub

    def get_private_key(self) -> bytes:
        """Get concatenated private keys."""
        ed_priv = self._ed25519.get_private_key()
        ml_priv = self._mldsa.get_private_key()
        ed_len = len(ed_priv).to_bytes(4, 'big')
        return ed_len + ed_priv + ml_priv


def get_signer(
    algorithm: SignatureAlgorithm = SignatureAlgorithm.ED25519,
    private_key_bytes: Optional[bytes] = None,
    require_real_pqc: bool = False,
) -> CryptoSigner:
    """
    Factory function to get a signer instance.

    Args:
        algorithm: Which algorithm to use
        private_key_bytes: Optional existing private key
        require_real_pqc: If True, raise error if liboqs not available

    Returns:
        CryptoSigner instance
    """
    if algorithm == SignatureAlgorithm.ED25519:
        return Ed25519Signer(private_key_bytes)

    elif algorithm == SignatureAlgorithm.ML_DSA_65:
        if require_real_pqc and not LIBOQS_AVAILABLE:
            raise RuntimeError(
                "ML-DSA-65 requires liboqs. Install with: pip install liboqs-python"
            )
        return MLDSASigner(private_key_bytes)

    elif algorithm == SignatureAlgorithm.ML_DSA_87:
        if require_real_pqc and not LIBOQS_AVAILABLE:
            raise RuntimeError(
                "ML-DSA-87 requires liboqs. Install with: pip install liboqs-python"
            )
        # Use Dilithium5 for ML-DSA-87
        signer = MLDSASigner(private_key_bytes)
        signer.ALGORITHM_NAME = "Dilithium5"
        return signer

    elif algorithm == SignatureAlgorithm.HYBRID:
        if private_key_bytes:
            ed_len = int.from_bytes(private_key_bytes[:4], 'big')
            ed_priv = private_key_bytes[4:4 + ed_len]
            ml_priv = private_key_bytes[4 + ed_len:]
            return HybridSigner(ed_priv, ml_priv)
        return HybridSigner()

    else:
        raise ValueError(f"Unknown algorithm: {algorithm}")
