"""
Epoch Management for Instant Consent Revocation

Patent Reference: "Consent DNA Token (CDT) derived from Hash(Policy State || Epoch).
Incrementing a global epoch scalar instantly invalidates all tokens generated under prior epochs."

Key Innovation: ZERO propagation latency
- Increment epoch → ALL prior CDTs invalid INSTANTLY
- No cache invalidation needed across services
- No Certificate Revocation List distribution
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional
from threading import Lock
import structlog

logger = structlog.get_logger()


@dataclass
class EpochEvent:
    """Record of an epoch change."""
    old_epoch: int
    new_epoch: int
    reason: str
    timestamp: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class GlobalEpoch:
    """
    The global epoch counter.

    Patent: "An epoch is a monotonic scalar, typically an integer stored in a
    globally accessible configuration store."

    Increment this to instantly invalidate ALL prior consent tokens.
    """

    def __init__(self, initial_epoch: int = 1):
        self._epoch = initial_epoch
        self._lock = Lock()
        self._history: List[EpochEvent] = []
        self._callbacks: List[Callable[[int, int], None]] = []

    @property
    def current(self) -> int:
        """Get current epoch value."""
        return self._epoch

    def increment(self, reason: str = "REVOCATION", metadata: Optional[Dict[str, Any]] = None) -> int:
        """
        Increment the epoch.

        Patent: "To revoke consent or materially change consent terms, the system
        increments the Global Epoch Counter. For example, transitioning from 100 to 101
        immediately changes the CDT output."

        Returns the new epoch value.
        """
        with self._lock:
            old_epoch = self._epoch
            self._epoch += 1
            new_epoch = self._epoch

            event = EpochEvent(
                old_epoch=old_epoch,
                new_epoch=new_epoch,
                reason=reason,
                timestamp=datetime.now(timezone.utc).isoformat(),
                metadata=metadata or {},
            )
            self._history.append(event)

            logger.critical(
                "epoch_incremented",
                old_epoch=old_epoch,
                new_epoch=new_epoch,
                reason=reason,
                effect="ALL_PRIOR_CDTS_INVALIDATED",
            )

            # Notify callbacks
            for callback in self._callbacks:
                try:
                    callback(old_epoch, new_epoch)
                except Exception as e:
                    logger.error("epoch_callback_error", error=str(e))

            return new_epoch

    def register_callback(self, callback: Callable[[int, int], None]) -> None:
        """Register a callback for epoch changes."""
        self._callbacks.append(callback)

    def get_history(self) -> List[EpochEvent]:
        """Get epoch change history."""
        return self._history.copy()

    def __int__(self) -> int:
        return self._epoch

    def __str__(self) -> str:
        return str(self._epoch)


class EpochManager:
    """
    Manages epochs for multiple policy domains.

    Supports per-subject, per-partner, or global epoch strategies.
    """

    def __init__(self, global_epoch: Optional[GlobalEpoch] = None):
        self.global_epoch = global_epoch or GlobalEpoch()
        self._domain_epochs: Dict[str, GlobalEpoch] = {}
        self._lock = Lock()

    def get_epoch(self, domain: Optional[str] = None) -> int:
        """Get current epoch for a domain (or global if no domain)."""
        if domain is None:
            return self.global_epoch.current

        with self._lock:
            if domain not in self._domain_epochs:
                self._domain_epochs[domain] = GlobalEpoch(
                    initial_epoch=self.global_epoch.current
                )
            return self._domain_epochs[domain].current

    def revoke_global(self, reason: str = "GLOBAL_REVOCATION") -> int:
        """
        Global revocation - invalidates ALL CDTs across ALL domains.

        Use for emergency situations or complete policy reset.
        """
        new_epoch = self.global_epoch.increment(reason)

        # Also increment all domain epochs to maintain consistency
        with self._lock:
            for domain, epoch in self._domain_epochs.items():
                epoch.increment(f"{reason}:CASCADED_FROM_GLOBAL")

        logger.warning(
            "global_revocation",
            new_epoch=new_epoch,
            domains_affected=len(self._domain_epochs),
        )

        return new_epoch

    def revoke_domain(self, domain: str, reason: str = "DOMAIN_REVOCATION") -> int:
        """
        Revoke consent for a specific domain only.

        Other domains remain unaffected.
        """
        with self._lock:
            if domain not in self._domain_epochs:
                self._domain_epochs[domain] = GlobalEpoch(
                    initial_epoch=self.global_epoch.current
                )

            new_epoch = self._domain_epochs[domain].increment(reason)

        logger.info(
            "domain_revocation",
            domain=domain,
            new_epoch=new_epoch,
            reason=reason,
        )

        return new_epoch

    def revoke_subject(self, subject_id: str, reason: str = "SUBJECT_REVOCATION") -> int:
        """
        Revoke consent for a specific data subject.

        Creates/updates a subject-specific epoch domain.
        """
        domain = f"subject:{subject_id}"
        return self.revoke_domain(domain, reason)

    def get_subject_epoch(self, subject_id: str) -> int:
        """Get current epoch for a specific subject."""
        return self.get_epoch(f"subject:{subject_id}")

    def is_epoch_valid(self, presented_epoch: int, domain: Optional[str] = None) -> bool:
        """
        Check if a presented epoch is still valid.

        Patent: "If the presented CDT matches the reference CDT, consent is
        treated as valid for that request."
        """
        current = self.get_epoch(domain)
        return presented_epoch == current

    def export_state(self) -> Dict[str, Any]:
        """Export current epoch state for persistence."""
        return {
            "global_epoch": self.global_epoch.current,
            "domain_epochs": {
                domain: epoch.current
                for domain, epoch in self._domain_epochs.items()
            },
            "exported_at": datetime.now(timezone.utc).isoformat(),
        }

    def import_state(self, state: Dict[str, Any]) -> None:
        """Restore epoch state from persistence."""
        with self._lock:
            self.global_epoch = GlobalEpoch(state.get("global_epoch", 1))
            for domain, epoch_val in state.get("domain_epochs", {}).items():
                self._domain_epochs[domain] = GlobalEpoch(epoch_val)

        logger.info(
            "epoch_state_restored",
            global_epoch=self.global_epoch.current,
            domains=len(self._domain_epochs),
        )


class AsyncEpochManager(EpochManager):
    """
    Async-aware epoch manager for high-concurrency scenarios.

    Uses asyncio locks instead of threading locks.
    """

    def __init__(self, global_epoch: Optional[GlobalEpoch] = None):
        super().__init__(global_epoch)
        self._async_lock = asyncio.Lock()

    async def get_epoch_async(self, domain: Optional[str] = None) -> int:
        """Async version of get_epoch."""
        async with self._async_lock:
            return self.get_epoch(domain)

    async def revoke_global_async(self, reason: str = "GLOBAL_REVOCATION") -> int:
        """Async version of revoke_global."""
        async with self._async_lock:
            return self.revoke_global(reason)

    async def revoke_domain_async(self, domain: str, reason: str = "DOMAIN_REVOCATION") -> int:
        """Async version of revoke_domain."""
        async with self._async_lock:
            return self.revoke_domain(domain, reason)
