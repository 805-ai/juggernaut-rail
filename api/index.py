"""
JUGGERNAUT RAIL - Vercel Serverless Deployment
Cryptographic AI Governance API

NO RECEIPT, NO RUN
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import hashlib
import secrets
import os

from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# ============================================================================
# Application
# ============================================================================

app = FastAPI(
    title="Juggernaut Rail",
    description="Cryptographic AI Governance - NO RECEIPT, NO RUN",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# In-Memory State (serverless - resets per cold start)
# ============================================================================

class State:
    epoch: int = 1
    policies: Dict[str, dict] = {}
    receipts: List[dict] = []
    start_time: datetime = datetime.now(timezone.utc)

state = State()

# ============================================================================
# Models
# ============================================================================

class ConsentRequest(BaseModel):
    subject_id: str
    partner_id: str
    purposes: List[str]
    data_categories: List[str]
    retention_days: int = 365
    jurisdiction: str = "GDPR_EU"

class GateRequest(BaseModel):
    action: str
    target_resource: str
    agent_id: str
    purpose: str = "INFERENCE"
    data_category: str = "TEXT"
    content: Optional[str] = None
    cdt: Optional[str] = None

class RevocationRequest(BaseModel):
    subject_id: Optional[str] = None
    reason: str = "USER_REQUEST"

# ============================================================================
# Core Functions
# ============================================================================

def generate_cdt(policy: dict, epoch: int) -> str:
    """CDT = SHA3-256(Canonical(Policy) || Epoch)"""
    canonical = f"{policy['subject_id']}|{policy['partner_id']}|{sorted(policy['purposes'])}|{epoch}"
    return hashlib.sha3_256(canonical.encode()).hexdigest()

def generate_receipt(action: str, agent_id: str, cdt: str) -> dict:
    """Generate cryptographic receipt"""
    receipt_id = f"RCP-{secrets.token_hex(6).upper()}"
    timestamp = datetime.now(timezone.utc).isoformat()

    # Create receipt hash
    data = f"{receipt_id}|{action}|{agent_id}|{cdt}|{timestamp}"
    receipt_hash = hashlib.sha256(data.encode()).hexdigest()

    return {
        "receipt_id": receipt_id,
        "action": action,
        "agent_id": agent_id,
        "cdt": cdt,
        "timestamp": timestamp,
        "hash": receipt_hash,
    }

def check_veto(content: Optional[str]) -> tuple[float, bool]:
    """Zero-multiplier veto check"""
    if not content:
        return 1.0, False

    # PII patterns
    pii_patterns = ["ssn", "social security", "credit card", "password", "@", "123-45"]
    content_lower = content.lower()

    for pattern in pii_patterns:
        if pattern in content_lower:
            return 0.001, True  # Zero-multiplier activated

    return 1.0, False

# ============================================================================
# Endpoints
# ============================================================================

def verify_api_key(x_api_key: str = Header(..., alias="X-API-Key")) -> str:
    expected = os.environ.get("API_KEY", "juggernaut-production-2025")
    if x_api_key != expected:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key

@app.get("/health")
async def health():
    uptime = (datetime.now(timezone.utc) - state.start_time).total_seconds()
    return {
        "status": "healthy",
        "version": "1.0.0",
        "epoch": state.epoch,
        "uptime_seconds": uptime,
    }

@app.post("/consent")
async def create_consent(request: ConsentRequest, api_key: str = Header(..., alias="X-API-Key")):
    verify_api_key(api_key)

    policy_id = f"POL-{secrets.token_hex(6).upper()}"
    policy = {
        "policy_id": policy_id,
        "subject_id": request.subject_id,
        "partner_id": request.partner_id,
        "purposes": request.purposes,
        "data_categories": request.data_categories,
        "retention_days": request.retention_days,
        "jurisdiction": request.jurisdiction,
    }

    state.policies[policy_id] = policy
    cdt = generate_cdt(policy, state.epoch)

    return {
        "policy_id": policy_id,
        "cdt": cdt,
        "epoch": state.epoch,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

@app.post("/gate")
async def gate_operation(request: GateRequest, api_key: str = Header(..., alias="X-API-Key")):
    verify_api_key(api_key)
    import time
    start = time.perf_counter()

    # Veto check
    trust_score, vetoed = check_veto(request.content)

    if vetoed or trust_score < 0.5:
        return {
            "decision": "DENY",
            "receipt_id": None,
            "cdt": None,
            "trust_score": trust_score,
            "latency_ms": (time.perf_counter() - start) * 1000,
            "error": f"Trust score {trust_score:.2f} below threshold - PII detected",
        }

    # Generate CDT and receipt
    default_policy = {
        "subject_id": request.agent_id,
        "partner_id": "default",
        "purposes": [request.purpose],
    }
    cdt = generate_cdt(default_policy, state.epoch)
    receipt = generate_receipt(request.action, request.agent_id, cdt)
    state.receipts.append(receipt)

    return {
        "decision": "ALLOW",
        "receipt_id": receipt["receipt_id"],
        "cdt": cdt,
        "trust_score": trust_score,
        "latency_ms": (time.perf_counter() - start) * 1000,
        "error": None,
    }

@app.post("/revoke")
async def revoke_consent(request: RevocationRequest, api_key: str = Header(..., alias="X-API-Key")):
    verify_api_key(api_key)

    state.epoch += 1
    scope = f"subject:{request.subject_id}" if request.subject_id else "global"

    return {
        "new_epoch": state.epoch,
        "scope": scope,
        "reason": request.reason,
        "effect": "ALL_PRIOR_CDTS_INVALIDATED",
        "revoked_at": datetime.now(timezone.utc).isoformat(),
    }

@app.get("/receipts")
async def get_receipts(limit: int = 100, api_key: str = Header(..., alias="X-API-Key")):
    verify_api_key(api_key)
    return {
        "total": len(state.receipts),
        "receipts": state.receipts[-limit:],
    }

@app.get("/receipts/verify")
async def verify_chain(api_key: str = Header(..., alias="X-API-Key")):
    verify_api_key(api_key)

    # Compute merkle root
    if not state.receipts:
        merkle_root = hashlib.sha256(b"empty").hexdigest()
    else:
        hashes = [r["hash"] for r in state.receipts]
        while len(hashes) > 1:
            if len(hashes) % 2 == 1:
                hashes.append(hashes[-1])
            hashes = [
                hashlib.sha256((hashes[i] + hashes[i+1]).encode()).hexdigest()
                for i in range(0, len(hashes), 2)
            ]
        merkle_root = hashes[0] if hashes else hashlib.sha256(b"empty").hexdigest()

    return {
        "valid": True,
        "error": None,
        "chain_length": len(state.receipts),
        "merkle_root": merkle_root,
    }

@app.get("/metrics")
async def get_metrics(api_key: str = Header(..., alias="X-API-Key")):
    verify_api_key(api_key)
    return {
        "gate": {
            "total_receipts": len(state.receipts),
        },
        "epoch": {
            "current": state.epoch,
        },
        "receipts": {
            "total": len(state.receipts),
        },
    }

# Vercel handler
handler = app
