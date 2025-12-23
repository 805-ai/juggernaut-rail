"""
Key Management for Juggernaut Rail

Provides secure key generation, storage, and rotation.
"""

import base64
import hashlib
import json
import os
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
from pathlib import Path
import structlog

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .signer import SignatureAlgorithm, CryptoSigner, get_signer

logger = structlog.get_logger()


@dataclass
class KeyPair:
    """A cryptographic key pair with metadata."""
    key_id: str
    algorithm: SignatureAlgorithm
    public_key: bytes
    private_key: bytes  # Encrypted if stored
    created_at: str
    expires_at: Optional[str] = None
    status: str = "ACTIVE"  # ACTIVE, ROTATED, REVOKED
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self, include_private: bool = False) -> Dict[str, Any]:
        result = {
            "key_id": self.key_id,
            "algorithm": self.algorithm.value,
            "public_key": base64.b64encode(self.public_key).decode('utf-8'),
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "status": self.status,
            "metadata": self.metadata,
        }
        if include_private:
            result["private_key"] = base64.b64encode(self.private_key).decode('utf-8')
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "KeyPair":
        return cls(
            key_id=data["key_id"],
            algorithm=SignatureAlgorithm(data["algorithm"]),
            public_key=base64.b64decode(data["public_key"]),
            private_key=base64.b64decode(data.get("private_key", "")),
            created_at=data["created_at"],
            expires_at=data.get("expires_at"),
            status=data.get("status", "ACTIVE"),
            metadata=data.get("metadata", {}),
        )


class KeyManager:
    """
    Secure key management for signing operations.

    Features:
    - Encrypted key storage
    - Key rotation support
    - Multiple algorithm support
    - Audit logging
    """

    def __init__(
        self,
        storage_path: Optional[str] = None,
        master_key: Optional[bytes] = None,
    ):
        self.storage_path = Path(storage_path or os.environ.get(
            "KEY_STORAGE_PATH",
            ".keys"
        ))
        self.storage_path.mkdir(parents=True, exist_ok=True)

        # Derive encryption key from master key or environment
        if master_key:
            self._master_key = master_key
        else:
            master_secret = os.environ.get("KEY_MASTER_SECRET", "")
            if master_secret:
                self._master_key = self._derive_key(master_secret.encode())
            else:
                # Generate and store a master key (development only)
                master_key_file = self.storage_path / ".master"
                if master_key_file.exists():
                    self._master_key = master_key_file.read_bytes()
                else:
                    self._master_key = Fernet.generate_key()
                    master_key_file.write_bytes(self._master_key)
                    logger.warning("master_key_generated",
                                  message="Generated new master key. Set KEY_MASTER_SECRET in production.")

        self._fernet = Fernet(self._master_key)
        self._keys: Dict[str, KeyPair] = {}
        self._signers: Dict[str, CryptoSigner] = {}
        self._load_keys()

    def _derive_key(self, secret: bytes) -> bytes:
        """Derive encryption key from master secret."""
        salt = b"juggernaut-rail-v1"  # Static salt, secret provides entropy
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(secret))

    def _load_keys(self) -> None:
        """Load keys from storage."""
        keys_file = self.storage_path / "keys.enc"
        if not keys_file.exists():
            return

        try:
            encrypted_data = keys_file.read_bytes()
            decrypted_data = self._fernet.decrypt(encrypted_data)
            keys_data = json.loads(decrypted_data.decode('utf-8'))

            for key_data in keys_data:
                keypair = KeyPair.from_dict(key_data)
                self._keys[keypair.key_id] = keypair

            logger.info("keys_loaded", count=len(self._keys))
        except Exception as e:
            logger.error("key_load_failed", error=str(e))

    def _save_keys(self) -> None:
        """Save keys to encrypted storage."""
        keys_data = [kp.to_dict(include_private=True) for kp in self._keys.values()]
        json_data = json.dumps(keys_data).encode('utf-8')
        encrypted_data = self._fernet.encrypt(json_data)

        keys_file = self.storage_path / "keys.enc"
        keys_file.write_bytes(encrypted_data)
        logger.debug("keys_saved", count=len(self._keys))

    def generate_key(
        self,
        algorithm: SignatureAlgorithm = SignatureAlgorithm.ED25519,
        expires_days: Optional[int] = 365,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> KeyPair:
        """Generate a new key pair."""
        signer = get_signer(algorithm)

        now = datetime.now(timezone.utc)
        expires_at = None
        if expires_days:
            expires_at = (now + timedelta(days=expires_days)).isoformat()

        keypair = KeyPair(
            key_id=signer.key_id,
            algorithm=algorithm,
            public_key=signer.get_public_key(),
            private_key=signer.get_private_key(),
            created_at=now.isoformat(),
            expires_at=expires_at,
            status="ACTIVE",
            metadata=metadata or {},
        )

        self._keys[keypair.key_id] = keypair
        self._signers[keypair.key_id] = signer
        self._save_keys()

        logger.info("key_generated",
                   key_id=keypair.key_id,
                   algorithm=algorithm.value,
                   expires_at=expires_at)

        return keypair

    def get_signer(self, key_id: Optional[str] = None) -> CryptoSigner:
        """
        Get a signer for the specified key.

        If no key_id provided, uses the current active key.
        """
        if key_id is None:
            # Get most recent active key
            active_keys = [
                kp for kp in self._keys.values()
                if kp.status == "ACTIVE"
            ]
            if not active_keys:
                # Auto-generate a key
                keypair = self.generate_key()
                key_id = keypair.key_id
            else:
                key_id = max(active_keys, key=lambda kp: kp.created_at).key_id

        # Return cached signer if available
        if key_id in self._signers:
            return self._signers[key_id]

        # Reconstruct signer from stored key
        keypair = self._keys.get(key_id)
        if not keypair:
            raise KeyError(f"Key not found: {key_id}")

        if keypair.status != "ACTIVE":
            logger.warning("using_inactive_key", key_id=key_id, status=keypair.status)

        signer = get_signer(keypair.algorithm, keypair.private_key)
        self._signers[key_id] = signer

        return signer

    def rotate_key(
        self,
        old_key_id: str,
        new_algorithm: Optional[SignatureAlgorithm] = None,
    ) -> KeyPair:
        """
        Rotate a key - mark old as rotated, generate new.
        """
        old_keypair = self._keys.get(old_key_id)
        if not old_keypair:
            raise KeyError(f"Key not found: {old_key_id}")

        # Mark old key as rotated
        old_keypair.status = "ROTATED"

        # Generate new key
        algorithm = new_algorithm or old_keypair.algorithm
        new_keypair = self.generate_key(
            algorithm=algorithm,
            metadata={"rotated_from": old_key_id},
        )

        # Clear old signer from cache
        self._signers.pop(old_key_id, None)

        logger.info("key_rotated",
                   old_key_id=old_key_id,
                   new_key_id=new_keypair.key_id)

        return new_keypair

    def revoke_key(self, key_id: str) -> None:
        """Revoke a key - it can no longer be used for signing."""
        keypair = self._keys.get(key_id)
        if not keypair:
            raise KeyError(f"Key not found: {key_id}")

        keypair.status = "REVOKED"
        self._signers.pop(key_id, None)
        self._save_keys()

        logger.info("key_revoked", key_id=key_id)

    def get_public_key(self, key_id: str) -> bytes:
        """Get public key by ID."""
        keypair = self._keys.get(key_id)
        if not keypair:
            raise KeyError(f"Key not found: {key_id}")
        return keypair.public_key

    def list_keys(self, status: Optional[str] = None) -> List[KeyPair]:
        """List all keys, optionally filtered by status."""
        keys = list(self._keys.values())
        if status:
            keys = [k for k in keys if k.status == status]
        return sorted(keys, key=lambda k: k.created_at, reverse=True)

    def export_public_keys(self) -> Dict[str, Dict[str, Any]]:
        """Export all active public keys for distribution."""
        return {
            kp.key_id: {
                "algorithm": kp.algorithm.value,
                "public_key": base64.b64encode(kp.public_key).decode('utf-8'),
                "created_at": kp.created_at,
                "expires_at": kp.expires_at,
            }
            for kp in self._keys.values()
            if kp.status == "ACTIVE"
        }

    def verify_with_any_key(
        self,
        data: bytes,
        signature: bytes,
        key_ids: Optional[List[str]] = None,
    ) -> tuple[bool, Optional[str]]:
        """
        Verify signature against any of the specified keys.

        Useful for verification during key rotation periods.

        Returns (is_valid, key_id_that_verified)
        """
        if key_ids is None:
            key_ids = [kp.key_id for kp in self._keys.values()]

        for key_id in key_ids:
            try:
                signer = self.get_signer(key_id)
                result = signer.verify(data, signature)
                if result.valid:
                    return (True, key_id)
            except Exception:
                continue

        return (False, None)
