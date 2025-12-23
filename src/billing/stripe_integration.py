"""
Stripe Integration for Juggernaut Rail

Patent Reference: "CDT + Penny Counter for AI-Driven Billing and Compliance"
Claims: "Transmitting billing data to payment processing system (Stripe) for settlement."

Integrates with Stripe for:
- Metered billing based on usage records
- Subscription management per license tier
- Invoice generation and settlement
"""

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from enum import Enum
import structlog
import json

logger = structlog.get_logger()

# Stripe SDK is optional - graceful degradation if not installed
try:
    import stripe
    STRIPE_AVAILABLE = True
except ImportError:
    STRIPE_AVAILABLE = False
    stripe = None


class StripeIntegrationError(Exception):
    """Raised when Stripe integration fails."""
    pass


@dataclass
class StripeCustomer:
    """Stripe customer representation."""
    customer_id: str
    tenant_id: str
    email: str
    subscription_id: Optional[str] = None
    price_id: Optional[str] = None
    created_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "customer_id": self.customer_id,
            "tenant_id": self.tenant_id,
            "email": self.email,
            "subscription_id": self.subscription_id,
            "price_id": self.price_id,
            "created_at": self.created_at,
        }


@dataclass
class UsageReport:
    """Usage report sent to Stripe."""
    subscription_item_id: str
    quantity: int
    timestamp: int
    action: str = "increment"  # or "set"
    idempotency_key: Optional[str] = None


class StripeIntegration:
    """
    Stripe integration for metered billing.

    Patent: "Upon ALLOW or DENY, minting cryptographically signed receipt and
    incrementing usage counter associated with receipt. Transmitting billing
    data to payment processing system (Stripe) for settlement."

    This is the bridge between Penny Counter usage records and Stripe billing.
    """

    # Default price IDs per tier (configure in Stripe Dashboard)
    DEFAULT_PRICE_IDS = {
        "STARTER": "price_starter_metered",
        "PROFESSIONAL": "price_pro_metered",
        "ENTERPRISE": "price_enterprise_metered",
    }

    def __init__(
        self,
        api_key: Optional[str] = None,
        webhook_secret: Optional[str] = None,
        price_ids: Optional[Dict[str, str]] = None,
    ):
        """
        Initialize Stripe integration.

        Args:
            api_key: Stripe secret key (or STRIPE_API_KEY env var)
            webhook_secret: Stripe webhook signing secret (or STRIPE_WEBHOOK_SECRET env var)
            price_ids: Mapping of tier names to Stripe price IDs
        """
        self.api_key = api_key or os.environ.get("STRIPE_API_KEY")
        self.webhook_secret = webhook_secret or os.environ.get("STRIPE_WEBHOOK_SECRET")
        self.price_ids = price_ids or self.DEFAULT_PRICE_IDS.copy()

        self._customers: Dict[str, StripeCustomer] = {}
        self._initialized = False

        if STRIPE_AVAILABLE and self.api_key:
            stripe.api_key = self.api_key
            self._initialized = True
            logger.info("stripe_integration_initialized")
        else:
            logger.warning(
                "stripe_not_configured",
                stripe_available=STRIPE_AVAILABLE,
                api_key_set=bool(self.api_key),
            )

    @property
    def is_available(self) -> bool:
        """Check if Stripe integration is available."""
        return self._initialized

    def create_customer(
        self,
        tenant_id: str,
        email: str,
        name: Optional[str] = None,
        metadata: Optional[Dict[str, str]] = None,
    ) -> StripeCustomer:
        """
        Create a Stripe customer for a tenant.

        Returns customer info (or mock if Stripe not available).
        """
        if not self._initialized:
            # Mock customer for testing
            customer = StripeCustomer(
                customer_id=f"cus_mock_{tenant_id[:8]}",
                tenant_id=tenant_id,
                email=email,
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            self._customers[tenant_id] = customer
            return customer

        try:
            stripe_customer = stripe.Customer.create(
                email=email,
                name=name,
                metadata={
                    "tenant_id": tenant_id,
                    "source": "juggernaut_rail",
                    **(metadata or {}),
                },
            )

            customer = StripeCustomer(
                customer_id=stripe_customer.id,
                tenant_id=tenant_id,
                email=email,
                created_at=datetime.fromtimestamp(
                    stripe_customer.created, timezone.utc
                ).isoformat(),
            )

            self._customers[tenant_id] = customer

            logger.info(
                "stripe_customer_created",
                customer_id=customer.customer_id,
                tenant_id=tenant_id,
            )

            return customer

        except Exception as e:
            logger.error("stripe_customer_create_failed", error=str(e))
            raise StripeIntegrationError(f"Failed to create customer: {e}")

    def create_subscription(
        self,
        tenant_id: str,
        tier: str,
        trial_days: int = 0,
    ) -> Dict[str, Any]:
        """
        Create a metered subscription for a tenant.

        Args:
            tenant_id: The tenant ID (must have existing customer)
            tier: License tier (STARTER, PROFESSIONAL, ENTERPRISE)
            trial_days: Optional trial period

        Returns:
            Subscription details
        """
        customer = self._customers.get(tenant_id)
        if not customer:
            raise StripeIntegrationError(f"No customer found for tenant {tenant_id}")

        price_id = self.price_ids.get(tier.upper())
        if not price_id:
            raise StripeIntegrationError(f"No price ID configured for tier {tier}")

        if not self._initialized:
            # Mock subscription
            sub_id = f"sub_mock_{tenant_id[:8]}"
            customer.subscription_id = sub_id
            customer.price_id = price_id
            return {
                "subscription_id": sub_id,
                "status": "active",
                "current_period_start": datetime.now(timezone.utc).isoformat(),
                "tier": tier,
            }

        try:
            subscription = stripe.Subscription.create(
                customer=customer.customer_id,
                items=[{"price": price_id}],
                trial_period_days=trial_days if trial_days > 0 else None,
                metadata={
                    "tenant_id": tenant_id,
                    "tier": tier,
                },
            )

            customer.subscription_id = subscription.id
            customer.price_id = price_id

            # Get subscription item ID for usage reporting
            sub_item_id = subscription["items"]["data"][0]["id"]

            logger.info(
                "stripe_subscription_created",
                subscription_id=subscription.id,
                tenant_id=tenant_id,
                tier=tier,
            )

            return {
                "subscription_id": subscription.id,
                "subscription_item_id": sub_item_id,
                "status": subscription.status,
                "current_period_start": datetime.fromtimestamp(
                    subscription.current_period_start, timezone.utc
                ).isoformat(),
                "tier": tier,
            }

        except Exception as e:
            logger.error("stripe_subscription_create_failed", error=str(e))
            raise StripeIntegrationError(f"Failed to create subscription: {e}")

    def report_usage(
        self,
        subscription_item_id: str,
        quantity: int,
        timestamp: Optional[int] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Report usage to Stripe for metered billing.

        Patent: "Incrementing usage counter associated with receipt.
        Transmitting billing data to payment processing system for settlement."

        Args:
            subscription_item_id: The subscription item to bill
            quantity: Number of units to report
            timestamp: Unix timestamp (defaults to now)
            idempotency_key: Unique key to prevent duplicate reports

        Returns:
            Usage record confirmation
        """
        timestamp = timestamp or int(datetime.now(timezone.utc).timestamp())

        if not self._initialized:
            # Mock usage report
            return {
                "id": f"mbur_mock_{timestamp}",
                "subscription_item": subscription_item_id,
                "quantity": quantity,
                "timestamp": timestamp,
                "action": "increment",
            }

        try:
            usage_record = stripe.SubscriptionItem.create_usage_record(
                subscription_item_id,
                quantity=quantity,
                timestamp=timestamp,
                action="increment",
                idempotency_key=idempotency_key,
            )

            logger.info(
                "stripe_usage_reported",
                usage_record_id=usage_record.id,
                quantity=quantity,
                subscription_item=subscription_item_id,
            )

            return {
                "id": usage_record.id,
                "subscription_item": subscription_item_id,
                "quantity": quantity,
                "timestamp": timestamp,
                "action": "increment",
            }

        except Exception as e:
            logger.error("stripe_usage_report_failed", error=str(e))
            raise StripeIntegrationError(f"Failed to report usage: {e}")

    def report_penny_counter_usage(
        self,
        penny_counter_export: Dict[str, Any],
        subscription_item_id: str,
    ) -> Dict[str, Any]:
        """
        Report usage from Penny Counter export to Stripe.

        This bridges the Penny Counter usage records to Stripe billing.

        Args:
            penny_counter_export: Output from PennyCounter.export_for_stripe()
            subscription_item_id: The subscription item to bill

        Returns:
            Settlement summary
        """
        total_ops = penny_counter_export.get("usage", {}).get("total_operations", 0)

        if total_ops == 0:
            return {
                "reported": False,
                "reason": "no_usage",
                "quantity": 0,
            }

        # Create idempotency key from period and tenant
        tenant_id = penny_counter_export.get("tenant_id", "unknown")
        period_end = penny_counter_export.get("period", {}).get("end", "")
        idempotency_key = f"pc_{tenant_id}_{period_end}"

        result = self.report_usage(
            subscription_item_id=subscription_item_id,
            quantity=total_ops,
            idempotency_key=idempotency_key,
        )

        logger.info(
            "penny_counter_usage_settled",
            tenant_id=tenant_id,
            operations=total_ops,
            amount_cents=penny_counter_export.get("amount_cents", 0),
        )

        return {
            "reported": True,
            "quantity": total_ops,
            "usage_record": result,
            "amount_cents": penny_counter_export.get("amount_cents", 0),
        }

    def get_upcoming_invoice(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        """
        Get the upcoming invoice for a tenant.

        Useful for showing users their projected bill.
        """
        customer = self._customers.get(tenant_id)
        if not customer or not customer.subscription_id:
            return None

        if not self._initialized:
            # Mock invoice
            return {
                "amount_due": 0,
                "currency": "usd",
                "period_start": datetime.now(timezone.utc).isoformat(),
                "lines": [],
            }

        try:
            invoice = stripe.Invoice.upcoming(customer=customer.customer_id)

            return {
                "amount_due": invoice.amount_due,
                "currency": invoice.currency,
                "period_start": datetime.fromtimestamp(
                    invoice.period_start, timezone.utc
                ).isoformat(),
                "period_end": datetime.fromtimestamp(
                    invoice.period_end, timezone.utc
                ).isoformat(),
                "lines": [
                    {
                        "description": line.description,
                        "amount": line.amount,
                        "quantity": line.quantity,
                    }
                    for line in invoice.lines.data
                ],
            }

        except stripe.error.InvalidRequestError:
            # No upcoming invoice (new customer, no usage yet)
            return None
        except Exception as e:
            logger.error("stripe_invoice_fetch_failed", error=str(e))
            return None

    def handle_webhook(self, payload: bytes, signature: str) -> Dict[str, Any]:
        """
        Handle Stripe webhook events.

        Args:
            payload: Raw webhook payload
            signature: Stripe-Signature header value

        Returns:
            Processed event data
        """
        if not self._initialized or not self.webhook_secret:
            logger.warning("stripe_webhook_not_configured")
            return {"error": "Webhook not configured"}

        try:
            event = stripe.Webhook.construct_event(
                payload, signature, self.webhook_secret
            )

            logger.info(
                "stripe_webhook_received",
                event_type=event.type,
                event_id=event.id,
            )

            # Handle specific event types
            if event.type == "invoice.paid":
                return self._handle_invoice_paid(event.data.object)
            elif event.type == "invoice.payment_failed":
                return self._handle_payment_failed(event.data.object)
            elif event.type == "customer.subscription.deleted":
                return self._handle_subscription_cancelled(event.data.object)

            return {"event_type": event.type, "processed": True}

        except stripe.error.SignatureVerificationError:
            logger.error("stripe_webhook_signature_invalid")
            raise StripeIntegrationError("Invalid webhook signature")
        except Exception as e:
            logger.error("stripe_webhook_error", error=str(e))
            raise StripeIntegrationError(f"Webhook processing failed: {e}")

    def _handle_invoice_paid(self, invoice: Any) -> Dict[str, Any]:
        """Handle successful payment."""
        tenant_id = invoice.metadata.get("tenant_id")
        logger.info(
            "invoice_paid",
            invoice_id=invoice.id,
            tenant_id=tenant_id,
            amount=invoice.amount_paid,
        )
        return {
            "event": "invoice_paid",
            "tenant_id": tenant_id,
            "amount": invoice.amount_paid,
        }

    def _handle_payment_failed(self, invoice: Any) -> Dict[str, Any]:
        """Handle failed payment - may need to suspend access."""
        tenant_id = invoice.metadata.get("tenant_id")
        logger.warning(
            "payment_failed",
            invoice_id=invoice.id,
            tenant_id=tenant_id,
        )
        return {
            "event": "payment_failed",
            "tenant_id": tenant_id,
            "action_required": "suspend_or_retry",
        }

    def _handle_subscription_cancelled(self, subscription: Any) -> Dict[str, Any]:
        """Handle subscription cancellation."""
        tenant_id = subscription.metadata.get("tenant_id")
        logger.warning(
            "subscription_cancelled",
            subscription_id=subscription.id,
            tenant_id=tenant_id,
        )
        return {
            "event": "subscription_cancelled",
            "tenant_id": tenant_id,
            "action_required": "revoke_access",
        }


class StripeSettlementService:
    """
    Service for periodic settlement of usage to Stripe.

    Runs on a schedule (e.g., hourly) to batch-report usage.
    """

    def __init__(
        self,
        stripe_integration: StripeIntegration,
        penny_counter: Any,  # PennyCounter from penny_counter.py
    ):
        self.stripe = stripe_integration
        self.penny_counter = penny_counter
        self._subscription_items: Dict[str, str] = {}

    def register_tenant(
        self,
        tenant_id: str,
        subscription_item_id: str,
    ) -> None:
        """Register a tenant's subscription item for billing."""
        self._subscription_items[tenant_id] = subscription_item_id

    def settle_tenant(self, tenant_id: str) -> Dict[str, Any]:
        """
        Settle outstanding usage for a tenant.

        Exports from Penny Counter and reports to Stripe.
        """
        subscription_item_id = self._subscription_items.get(tenant_id)
        if not subscription_item_id:
            return {"error": f"No subscription item registered for {tenant_id}"}

        # Export usage from Penny Counter
        usage_export = self.penny_counter.export_for_stripe(tenant_id)

        if not usage_export:
            return {"settled": False, "reason": "no_usage_data"}

        # Report to Stripe
        result = self.stripe.report_penny_counter_usage(
            usage_export, subscription_item_id
        )

        # Mark records as settled if successful
        if result.get("reported"):
            unsettled = self.penny_counter.get_unsettled_records(tenant_id)
            record_ids = [r.record_id for r in unsettled]
            invoice_id = result.get("usage_record", {}).get("id", "pending")
            self.penny_counter.mark_settled(record_ids, invoice_id)

        return result

    def settle_all(self) -> Dict[str, Any]:
        """
        Settle usage for all registered tenants.

        Typically run on a schedule.
        """
        results = {}
        for tenant_id in self._subscription_items:
            try:
                results[tenant_id] = self.settle_tenant(tenant_id)
            except Exception as e:
                results[tenant_id] = {"error": str(e)}

        logger.info(
            "settlement_batch_complete",
            tenants_processed=len(results),
        )

        return results
