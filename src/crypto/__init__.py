"""
Cryptographic Primitives for Juggernaut Rail

Supports:
- ML-DSA-65 (Dilithium) - Post-quantum signatures (NIST FIPS 204)
- Ed25519 - Classical signatures (transitional)
- Hybrid mode - Both signatures for defense in depth
"""

from .signer import (
    SignatureAlgorithm,
    CryptoSigner,
    Ed25519Signer,
    MLDSASigner,
    HybridSigner,
    get_signer,
)
from .keys import KeyManager, KeyPair

__all__ = [
    "SignatureAlgorithm",
    "CryptoSigner",
    "Ed25519Signer",
    "MLDSASigner",
    "HybridSigner",
    "get_signer",
    "KeyManager",
    "KeyPair",
]
