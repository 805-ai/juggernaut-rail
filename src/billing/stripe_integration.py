"""
Stripe Payment Integration

Patent Reference: "Transmitting billing data to payment processing system (Stripe) for settlement"

Integrates Penny Counter usage with Stripe's metered billing system.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import structlog
import os

logger = structlog.get_logger()

# Stripe SDK import (graceful fallback if not installed)
try:
    import stripe
    STRIPE_AVAILABLE = True
except ImportError:
    STRIPE_AVAILABLE = False
    logger.warning("stripe_not_installed", message="pip install stripe for payment integration")


@dataclass
class StripeConfig:
    """Stripe configuration."""
    api_key: str
    webhook_secret: Optional[str] = None
    product_id: Optional[str] = None
    price_id: Optional[str] = None  # Metered price
    test_mode: bool = True


class StripeSettlement:
    """
    Settles governance usage via Stripe.

    Implements metered billing:
    1. Create/update subscription with metered pricing
    2. Report usage to Stripe
    3. Stripe invoices customer automatically
    """

    def __init__(self, config: Optional[StripeConfig] = None):
        self.config = config or StripeConfig(
            api_key=os.environ.get("STRIPE_API_KEY", "sk_test_placeholder"),
            webhook_secret=os.environ.get("STRIPE_WEBHOOK_SECRET"),
            test_mode=True,
        )

        if STRIPE_AVAILABLE:
            stripe.api_key = self.config.api_key

    def report_usage(
        self,
        subscription_item_id: str,
        quantity: int,
        timestamp: Optional[int] = None,
        action: str = "increment",
    ) -> Optional[Dict[str, Any]]:
        """
        Report usage to Stripe for metered billing.

        Args:
            subscription_item_id: The Stripe subscription item ID
            quantity: Number of units to report
            timestamp: Unix timestamp (defaults to now)
            action: "increment" or "set"
        """
        if not STRIPE_AVAILABLE:
            logger.warning("stripe_unavailable", message="Stripe SDK not installed")
            return None

        timestamp = timestamp or int(datetime.now(timezone.utc).timestamp())

        try:
            usage_record = stripe.SubscriptionItem.create_usage_record(
                subscription_item_id,
                quantity=quantity,
                timestamp=timestamp,
                action=action,
            )

            logger.info(
                "stripe_usage_reported",
                subscription_item_id=subscription_item_id,
                quantity=quantity,
                usage_record_id=usage_record.id,
            )

            return {
                "id": usage_record.id,
                "quantity": usage_record.quantity,
                "timestamp": usage_record.timestamp,
            }

        except Exception as e:
            logger.error(
                "stripe_usage_error",
                error=str(e),
                subscription_item_id=subscription_item_id,
            )
            return None

    def create_customer(
        self,
        email: str,
        name: str,
        tenant_id: str,
        metadata: Optional[Dict[str, str]] = None,
    ) -> Optional[str]:
        """Create a Stripe customer for a tenant."""
        if not STRIPE_AVAILABLE:
            return None

        try:
            customer = stripe.Customer.create(
                email=email,
                name=name,
                metadata={
                    "tenant_id": tenant_id,
                    "platform": "juggernaut-rail",
                    **(metadata or {}),
                },
            )

            logger.info(
                "stripe_customer_created",
                customer_id=customer.id,
                tenant_id=tenant_id,
            )

            return customer.id

        except Exception as e:
            logger.error("stripe_customer_error", error=str(e))
            return None

    def create_metered_subscription(
        self,
        customer_id: str,
        price_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Create a subscription with metered billing.

        The price should be configured in Stripe as:
        - Usage-based pricing
        - Metered billing (report usage manually)
        """
        if not STRIPE_AVAILABLE:
            return None

        price_id = price_id or self.config.price_id

        if not price_id:
            logger.error("no_price_id", message="Metered price ID not configured")
            return None

        try:
            subscription = stripe.Subscription.create(
                customer=customer_id,
                items=[{"price": price_id}],
                billing_cycle_anchor="now",
            )

            logger.info(
                "stripe_subscription_created",
                subscription_id=subscription.id,
                customer_id=customer_id,
            )

            return {
                "subscription_id": subscription.id,
                "subscription_item_id": subscription["items"]["data"][0]["id"],
                "status": subscription.status,
            }

        except Exception as e:
            logger.error("stripe_subscription_error", error=str(e))
            return None


class InvoiceGenerator:
    """
    Generates invoices from usage records.

    Can be used standalone or with Stripe integration.
    """

    def __init__(self, stripe_settlement: Optional[StripeSettlement] = None):
        self.stripe = stripe_settlement

    def generate_invoice(
        self,
        tenant_id: str,
        usage_data: Dict[str, Any],
        billing_period: Dict[str, str],
    ) -> Dict[str, Any]:
        """
        Generate an invoice from usage data.

        Returns invoice data that can be sent to Stripe or rendered locally.
        """
        import uuid

        invoice_id = f"INV-{uuid.uuid4().hex[:12].upper()}"
        amount_cents = usage_data.get("amount_cents", 0)

        invoice = {
            "invoice_id": invoice_id,
            "tenant_id": tenant_id,
            "billing_period": billing_period,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "draft",
            "currency": "usd",
            "subtotal_cents": amount_cents,
            "tax_cents": 0,  # Would calculate based on jurisdiction
            "total_cents": amount_cents,
            "line_items": [],
        }

        # Add line items
        usage = usage_data.get("usage", {})

        if usage.get("total_operations", 0) > 0:
            invoice["line_items"].append({
                "description": "Governance Operations",
                "quantity": usage["total_operations"],
                "unit_price_cents": 0.01,
                "total_cents": usage["total_operations"] * 0.01,
            })

        if usage.get("total_signatures", 0) > 0:
            invoice["line_items"].append({
                "description": "Cryptographic Signatures",
                "quantity": usage["total_signatures"],
                "unit_price_cents": 0.005,
                "total_cents": usage["total_signatures"] * 0.005,
            })

        logger.info(
            "invoice_generated",
            invoice_id=invoice_id,
            tenant_id=tenant_id,
            total_cents=amount_cents,
        )

        return invoice
