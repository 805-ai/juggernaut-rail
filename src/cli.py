"""
Juggernaut Rail CLI

Commands:
  serve     - Run the governance server
  validate  - Validate a license key
  generate  - Generate a license key (internal use)
  info      - Show license and usage info
"""

import argparse
import os
import sys
from datetime import datetime, timezone, timedelta


def cmd_serve(args):
    """Run the governance server."""
    import uvicorn

    port = args.port or int(os.environ.get("PORT", 8000))
    host = args.host or "0.0.0.0"

    print(f"Starting Juggernaut Rail on {host}:{port}")

    uvicorn.run(
        "src.api.server:app",
        host=host,
        port=port,
        reload=args.reload,
        workers=args.workers,
    )


def cmd_validate(args):
    """Validate a license key."""
    from billing.license import LicenseManager, LicenseValidationError

    manager = LicenseManager()

    try:
        license = manager.validate_key(args.key)
        print(f"License Valid")
        print(f"  Tier: {license.tier.value}")
        print(f"  Organization: {license.organization_id}")
        print(f"  Expires: {license.expires_at.date()}")
        print(f"  Days remaining: {license.days_remaining}")
        print(f"  Operations/month: {license.limits.operations_per_month or 'Unlimited'}")
        print(f"  PQC Signatures: {'Yes' if license.limits.pqc_signatures else 'No'}")
        print(f"  Refinery Profiles: {'Yes' if license.limits.refinery_profiles else 'No'}")
    except LicenseValidationError as e:
        print(f"License Invalid: {e}")
        sys.exit(1)


def cmd_generate(args):
    """Generate a license key (internal use only)."""
    from billing.license import LicenseManager, LicenseTier

    secret = args.secret or os.environ.get("LICENSE_SIGNING_SECRET")
    if not secret:
        print("Error: --secret or LICENSE_SIGNING_SECRET required")
        sys.exit(1)

    tier_map = {
        "trial": LicenseTier.TRIAL,
        "starter": LicenseTier.STARTER,
        "professional": LicenseTier.PROFESSIONAL,
        "enterprise": LicenseTier.ENTERPRISE,
    }

    tier = tier_map.get(args.tier.lower())
    if not tier:
        print(f"Error: Invalid tier. Use: {list(tier_map.keys())}")
        sys.exit(1)

    expires = datetime.now(timezone.utc) + timedelta(days=args.days)

    key = LicenseManager.generate_key(
        tier=tier,
        org_id=args.org,
        expires_at=expires,
        signing_secret=secret,
    )

    print(f"License Key: {key}")
    print(f"  Tier: {tier.value}")
    print(f"  Org: {args.org}")
    print(f"  Expires: {expires.date()}")


def cmd_info(args):
    """Show license and usage info."""
    from billing.license import LicenseManager

    license_key = args.key or os.environ.get("LICENSE_KEY")
    if not license_key:
        print("Error: --key or LICENSE_KEY required")
        sys.exit(1)

    manager = LicenseManager()

    try:
        license = manager.activate(license_key)
        stats = manager.get_usage_stats()

        print("Juggernaut Rail License Info")
        print("=" * 40)
        print(f"Tier: {stats['tier']}")
        print(f"Period Start: {stats['period_start'][:10]}")
        print(f"Operations Used: {stats['operations_used']}")
        print(f"Operations Limit: {stats['operations_limit']}")
        print(f"License Days Remaining: {stats['license_days_remaining']}")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Juggernaut Rail - Cryptographic AI Governance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # serve
    serve_parser = subparsers.add_parser("serve", help="Run the server")
    serve_parser.add_argument("--host", default="0.0.0.0")
    serve_parser.add_argument("--port", type=int, default=8000)
    serve_parser.add_argument("--reload", action="store_true")
    serve_parser.add_argument("--workers", type=int, default=1)

    # validate
    validate_parser = subparsers.add_parser("validate", help="Validate license key")
    validate_parser.add_argument("key", help="License key to validate")

    # generate (internal)
    generate_parser = subparsers.add_parser("generate", help="Generate license key")
    generate_parser.add_argument("--tier", required=True, help="License tier")
    generate_parser.add_argument("--org", required=True, help="Organization ID")
    generate_parser.add_argument("--days", type=int, default=365, help="Days until expiry")
    generate_parser.add_argument("--secret", help="Signing secret")

    # info
    info_parser = subparsers.add_parser("info", help="Show license info")
    info_parser.add_argument("--key", help="License key")

    args = parser.parse_args()

    if args.command == "serve":
        cmd_serve(args)
    elif args.command == "validate":
        cmd_validate(args)
    elif args.command == "generate":
        cmd_generate(args)
    elif args.command == "info":
        cmd_info(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
