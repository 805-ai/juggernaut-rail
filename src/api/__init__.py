"""
JUGGERNAUT RAIL - API Module

Production FastAPI server implementing:
- Governance-as-a-Service (GaaS)
- CDT Management
- Receipt Generation
- Epoch Revocation
- Billing Integration
"""

from .server import app, create_app

__all__ = ["app", "create_app"]
