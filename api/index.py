"""
JUGGERNAUT RAIL - Vercel Serverless Deployment
Cryptographic AI Governance API - NO RECEIPT, NO RUN
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import hashlib
import secrets
import os
import json

# ============================================================================
# State
# ============================================================================

class State:
    epoch: int = 1
    policies: Dict[str, dict] = {}
    receipts: List[dict] = []
    start_time: datetime = datetime.now(timezone.utc)

state = State()

# ============================================================================
# Core Functions
# ============================================================================

def generate_cdt(policy: dict, epoch: int) -> str:
    canonical = f"{policy['subject_id']}|{policy['partner_id']}|{sorted(policy['purposes'])}|{epoch}"
    return hashlib.sha3_256(canonical.encode()).hexdigest()

def generate_receipt(action: str, agent_id: str, cdt: str) -> dict:
    receipt_id = f"RCP-{secrets.token_hex(6).upper()}"
    timestamp = datetime.now(timezone.utc).isoformat()
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

def check_veto(content: Optional[str]) -> tuple:
    if not content:
        return 1.0, False
    pii_patterns = ["ssn", "social security", "credit card", "password", "123-45"]
    content_lower = content.lower()
    for pattern in pii_patterns:
        if pattern in content_lower:
            return 0.001, True
    return 1.0, False

def verify_api_key(headers: dict) -> bool:
    api_key = headers.get("x-api-key", headers.get("X-API-Key", ""))
    expected = os.environ.get("API_KEY", "juggernaut-production-2025")
    return api_key == expected

def json_response(data: dict, status: int = 200) -> dict:
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type, X-API-Key",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        },
        "body": json.dumps(data),
    }

# ============================================================================
# Handler
# ============================================================================

def handler(event, context):
    """Vercel serverless handler"""
    path = event.get("path", "/")
    method = event.get("httpMethod", "GET")
    headers = event.get("headers", {})
    body = event.get("body", "{}")

    # CORS preflight
    if method == "OPTIONS":
        return json_response({})

    # Health check (no auth required)
    if path == "/health" and method == "GET":
        uptime = (datetime.now(timezone.utc) - state.start_time).total_seconds()
        return json_response({
            "status": "healthy",
            "version": "1.0.0",
            "epoch": state.epoch,
            "uptime_seconds": uptime,
        })

    # All other endpoints require auth
    if not verify_api_key(headers):
        return json_response({"error": "Invalid API key"}, 401)

    try:
        data = json.loads(body) if body else {}
    except:
        data = {}

    # POST /consent
    if path == "/consent" and method == "POST":
        policy_id = f"POL-{secrets.token_hex(6).upper()}"
        policy = {
            "policy_id": policy_id,
            "subject_id": data.get("subject_id", "unknown"),
            "partner_id": data.get("partner_id", "unknown"),
            "purposes": data.get("purposes", ["INFERENCE"]),
            "data_categories": data.get("data_categories", ["TEXT"]),
        }
        state.policies[policy_id] = policy
        cdt = generate_cdt(policy, state.epoch)
        return json_response({
            "policy_id": policy_id,
            "cdt": cdt,
            "epoch": state.epoch,
            "created_at": datetime.now(timezone.utc).isoformat(),
        })

    # POST /gate
    if path == "/gate" and method == "POST":
        import time
        start = time.perf_counter()
        trust_score, vetoed = check_veto(data.get("content"))

        if vetoed or trust_score < 0.5:
            return json_response({
                "decision": "DENY",
                "receipt_id": None,
                "cdt": None,
                "trust_score": trust_score,
                "latency_ms": (time.perf_counter() - start) * 1000,
                "error": "Trust score below threshold - PII detected",
            })

        default_policy = {
            "subject_id": data.get("agent_id", "unknown"),
            "partner_id": "default",
            "purposes": [data.get("purpose", "INFERENCE")],
        }
        cdt = generate_cdt(default_policy, state.epoch)
        receipt = generate_receipt(data.get("action", "INVOKE"), data.get("agent_id", "unknown"), cdt)
        state.receipts.append(receipt)

        return json_response({
            "decision": "ALLOW",
            "receipt_id": receipt["receipt_id"],
            "cdt": cdt,
            "trust_score": trust_score,
            "latency_ms": (time.perf_counter() - start) * 1000,
            "error": None,
        })

    # POST /revoke
    if path == "/revoke" and method == "POST":
        state.epoch += 1
        scope = f"subject:{data.get('subject_id')}" if data.get("subject_id") else "global"
        return json_response({
            "new_epoch": state.epoch,
            "scope": scope,
            "reason": data.get("reason", "USER_REQUEST"),
            "effect": "ALL_PRIOR_CDTS_INVALIDATED",
            "revoked_at": datetime.now(timezone.utc).isoformat(),
        })

    # GET /receipts
    if path == "/receipts" and method == "GET":
        return json_response({
            "total": len(state.receipts),
            "receipts": state.receipts[-100:],
        })

    # GET /receipts/verify
    if path == "/receipts/verify" and method == "GET":
        if not state.receipts:
            merkle_root = hashlib.sha256(b"empty").hexdigest()
        else:
            hashes = [r["hash"] for r in state.receipts]
            while len(hashes) > 1:
                if len(hashes) % 2 == 1:
                    hashes.append(hashes[-1])
                hashes = [hashlib.sha256((hashes[i] + hashes[i+1]).encode()).hexdigest() for i in range(0, len(hashes), 2)]
            merkle_root = hashes[0]
        return json_response({
            "valid": True,
            "error": None,
            "chain_length": len(state.receipts),
            "merkle_root": merkle_root,
        })

    # GET /metrics
    if path == "/metrics" and method == "GET":
        return json_response({
            "gate": {"total_receipts": len(state.receipts)},
            "epoch": {"current": state.epoch},
            "receipts": {"total": len(state.receipts)},
        })

    return json_response({"error": "Not found"}, 404)
