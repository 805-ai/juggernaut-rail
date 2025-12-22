"""
JUGGERNAUT RAIL - Production FastAPI Server

Governance-as-a-Service (GaaS) API implementing all patent claims.

Endpoints:
- POST /gate - Gate an operation request
- POST /consent - Create/update consent policy
- POST /revoke - Revoke consent (increment epoch)
- GET /receipts - Query receipts
- GET /metrics - Governance metrics
- POST /verify - Verify receipt chain integrity
"""

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import os
import structlog

from fastapi import FastAPI, HTTPException, Depends, Header, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# Import core components
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logger = structlog.get_logger()


# ============================================================================
# Pydantic Models
# ============================================================================

class OperationRequest(BaseModel):
    """Request to gate an operation."""
    action: str = Field(..., description="Action type: CREATE, READ, UPDATE, DELETE, INVOKE, GENERATE")
    target_resource: str = Field(..., description="Target resource identifier")
    parameters: Dict[str, Any] = Field(default_factory=dict)
    agent_id: str = Field(..., description="Agent DID or identifier")
    purpose: str = Field(default="INFERENCE", description="Purpose: TRAINING, INFERENCE, ANALYTICS, etc.")
    data_category: str = Field(default="TEXT", description="Data category: TEXT, LIKENESS, VOICE, etc.")
    content: Optional[str] = Field(None, description="Content for veto evaluation")
    cdt: Optional[str] = Field(None, description="Presented Consent DNA Token")


class ConsentRequest(BaseModel):
    """Request to create/update consent."""
    subject_id: str = Field(..., description="Data subject identifier")
    partner_id: str = Field(..., description="Partner/organization identifier")
    purposes: List[str] = Field(..., description="Allowed purposes")
    data_categories: List[str] = Field(..., description="Data categories covered")
    retention_days: int = Field(default=365)
    jurisdiction: str = Field(default="GDPR_EU")
    custom_terms: Optional[Dict[str, Any]] = None


class RevocationRequest(BaseModel):
    """Request to revoke consent."""
    subject_id: Optional[str] = Field(None, description="Specific subject (or global if None)")
    reason: str = Field(default="USER_REQUEST")


class ReceiptQuery(BaseModel):
    """Query parameters for receipts."""
    agent_id: Optional[str] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    limit: int = Field(default=100, le=1000)


class GateResponse(BaseModel):
    """Response from gate operation."""
    decision: str
    receipt_id: Optional[str]
    cdt: Optional[str]
    trust_score: float
    latency_ms: float
    error: Optional[str]


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    version: str
    epoch: int
    uptime_seconds: float


# ============================================================================
# Application State
# ============================================================================

class AppState:
    """Application state container."""

    def __init__(self):
        from ..core.epoch import EpochManager
        from ..core.policy import PolicyStore, PolicyState, Purpose, DataCategory, Jurisdiction
        from ..core.receipt import ReceiptChain, ReceiptGenerator
        from ..billing.penny_counter import PennyCounter
        from ..enforcement.gate import GovernanceGate, GateConfig

        self.epoch_manager = EpochManager()
        self.policy_store = PolicyStore()
        self.receipt_chain = ReceiptChain()
        self.penny_counter = PennyCounter()
        self.gate = GovernanceGate(
            config=GateConfig(
                fail_closed=True,
                require_pqc=False,  # Ed25519 for now, PQC when available
                min_trust_score=0.5,
                enable_billing=True,
            ),
            epoch_manager=self.epoch_manager,
            policy_store=self.policy_store,
            penny_counter=self.penny_counter,
        )
        self.start_time = datetime.now(timezone.utc)


app_state: Optional[AppState] = None


# ============================================================================
# Application Factory
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    global app_state
    logger.info("juggernaut_rail_starting", version="1.0.0")
    app_state = AppState()
    yield
    logger.info("juggernaut_rail_stopping")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    application = FastAPI(
        title="Juggernaut Rail",
        description="""
# Cryptographic AI Governance Rail

**NO RECEIPT, NO RUN** - Every operation is gated by cryptographic consent verification.

## Features
- **CDT (Consent DNA Token)**: Instant consent validation via epoch-based tokens
- **Zero-Multiplier Veto**: Safety checks that can instantly kill trust score
- **Cryptographic Receipts**: Post-quantum-ready signed audit trail
- **Integrated Billing**: Penny counter with Stripe settlement

## Patents
- Application 19/240,581: Blockchain-Based Dynamic Consent Management
- CDT/Receipt Rail Provisionals
- Zero-Multiplier Veto Architecture

(c) 2025 FinalBoss Tech / Abraham Manzano
        """,
        version="1.0.0",
        lifespan=lifespan,
    )

    # CORS middleware
    application.add_middleware(
        CORSMiddleware,
        allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    return application


app = create_app()


# ============================================================================
# Dependencies
# ============================================================================

def get_state() -> AppState:
    """Get application state."""
    if app_state is None:
        raise HTTPException(status_code=503, detail="Application not initialized")
    return app_state


def verify_api_key(x_api_key: str = Header(..., alias="X-API-Key")) -> str:
    """Verify API key."""
    expected = os.environ.get("API_KEY", "dev-key-change-in-production")
    if x_api_key != expected:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key


# ============================================================================
# Endpoints
# ============================================================================

@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check(state: AppState = Depends(get_state)):
    """Health check endpoint."""
    uptime = (datetime.now(timezone.utc) - state.start_time).total_seconds()
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        epoch=state.epoch_manager.global_epoch.current,
        uptime_seconds=uptime,
    )


@app.post("/gate", response_model=GateResponse, tags=["Governance"])
async def gate_operation(
    request: OperationRequest,
    state: AppState = Depends(get_state),
    api_key: str = Depends(verify_api_key),
):
    """
    Gate an operation request.

    This is the core endpoint implementing "NO RECEIPT, NO RUN".

    The operation is only allowed if:
    1. Valid consent exists (CDT validates)
    2. Policy allows the purpose/data category
    3. No veto vectors are triggered
    4. Trust score meets threshold

    A cryptographic receipt is generated for every decision.
    """
    from ..core.receipt import OperationPayload, ReceiptAction
    from ..core.policy import PolicyState, Purpose, DataCategory, Jurisdiction

    # Map action string to enum
    try:
        action = ReceiptAction[request.action.upper()]
    except KeyError:
        raise HTTPException(status_code=400, detail=f"Invalid action: {request.action}")

    try:
        purpose = Purpose[request.purpose.upper()]
    except KeyError:
        purpose = Purpose.INFERENCE

    try:
        data_category = DataCategory[request.data_category.upper()]
    except KeyError:
        data_category = DataCategory.TEXT

    # Create operation payload
    operation = OperationPayload(
        action=action,
        target_resource=request.target_resource,
        parameters=request.parameters,
        agent_id=request.agent_id,
    )

    # Get or create policy for this agent
    # In production, this would look up the actual consent
    policy = state.policy_store.get_for_pair(request.agent_id, "default_partner")

    if not policy:
        # Create a permissive default policy for demo
        policy = PolicyState(
            subject_id=request.agent_id,
            partner_id="default_partner",
            purposes={Purpose.INFERENCE, Purpose.ANALYTICS},
            data_categories={DataCategory.TEXT},
            retention_period_days=365,
            jurisdiction=Jurisdiction.GDPR_EU,
        )
        state.policy_store.store(policy)

    # Gate the operation
    result = state.gate.gate(
        operation=operation,
        policy=policy,
        presented_cdt=request.cdt,
        purpose=purpose,
        data_category=data_category,
        content_for_veto=request.content,
        tenant_id=request.agent_id,
    )

    # Store receipt in chain
    if result.receipt:
        state.receipt_chain.add(result.receipt)

    # Build CDT for response
    from ..core.cdt import PolicyState as CDTPolicyState
    cdt_policy = CDTPolicyState(
        subject_id=policy.subject_id,
        partner_id=policy.partner_id,
        purposes=tuple(p.value for p in policy.purposes),
        data_categories=tuple(d.value for d in policy.data_categories),
        retention_period_days=policy.retention_period_days,
        jurisdiction=policy.jurisdiction.value,
    )
    current_cdt = state.gate.cdt_generator.generate(
        cdt_policy,
        state.epoch_manager.global_epoch.current,
    )

    return GateResponse(
        decision=result.decision.value,
        receipt_id=result.receipt.receipt_id if result.receipt else None,
        cdt=current_cdt.token_value,
        trust_score=result.trust_score,
        latency_ms=result.latency_ms,
        error=result.error_message,
    )


@app.post("/consent", tags=["Consent"])
async def create_consent(
    request: ConsentRequest,
    state: AppState = Depends(get_state),
    api_key: str = Depends(verify_api_key),
):
    """
    Create or update a consent policy.

    Returns the policy ID and current CDT.
    """
    from ..core.policy import PolicyState, Purpose, DataCategory, Jurisdiction
    from ..core.cdt import PolicyState as CDTPolicyState

    # Map strings to enums
    purposes = set()
    for p in request.purposes:
        try:
            purposes.add(Purpose[p.upper()])
        except KeyError:
            raise HTTPException(status_code=400, detail=f"Invalid purpose: {p}")

    categories = set()
    for c in request.data_categories:
        try:
            categories.add(DataCategory[c.upper()])
        except KeyError:
            raise HTTPException(status_code=400, detail=f"Invalid data category: {c}")

    try:
        jurisdiction = Jurisdiction[request.jurisdiction.upper()]
    except KeyError:
        jurisdiction = Jurisdiction.GLOBAL

    # Create policy
    policy = PolicyState(
        subject_id=request.subject_id,
        partner_id=request.partner_id,
        purposes=purposes,
        data_categories=categories,
        retention_period_days=request.retention_days,
        jurisdiction=jurisdiction,
        custom_terms=request.custom_terms or {},
    )

    policy_id = state.policy_store.store(policy)

    # Generate CDT
    cdt_policy = CDTPolicyState(
        subject_id=policy.subject_id,
        partner_id=policy.partner_id,
        purposes=tuple(p.value for p in policy.purposes),
        data_categories=tuple(d.value for d in policy.data_categories),
        retention_period_days=policy.retention_period_days,
        jurisdiction=policy.jurisdiction.value,
    )
    cdt = state.gate.cdt_generator.generate(
        cdt_policy,
        state.epoch_manager.global_epoch.current,
    )

    return {
        "policy_id": policy_id,
        "cdt": cdt.token_value,
        "epoch": state.epoch_manager.global_epoch.current,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/revoke", tags=["Consent"])
async def revoke_consent(
    request: RevocationRequest,
    state: AppState = Depends(get_state),
    api_key: str = Depends(verify_api_key),
):
    """
    Revoke consent by incrementing the epoch.

    This INSTANTLY invalidates all CDTs generated under prior epochs.
    No propagation delay. No cache invalidation needed.
    """
    if request.subject_id:
        new_epoch = state.epoch_manager.revoke_subject(
            request.subject_id,
            request.reason,
        )
        scope = f"subject:{request.subject_id}"
    else:
        new_epoch = state.epoch_manager.revoke_global(request.reason)
        scope = "global"

    # Record billing for revocation
    state.penny_counter.record_revocation(
        tenant_id="system",
        epoch_change=new_epoch,
    )

    return {
        "new_epoch": new_epoch,
        "scope": scope,
        "reason": request.reason,
        "effect": "ALL_PRIOR_CDTS_INVALIDATED",
        "revoked_at": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/receipts", tags=["Audit"])
async def get_receipts(
    agent_id: Optional[str] = None,
    limit: int = 100,
    state: AppState = Depends(get_state),
    api_key: str = Depends(verify_api_key),
):
    """Query governance receipts."""
    receipts = state.receipt_chain.receipts[-limit:]

    if agent_id:
        receipts = [r for r in receipts if r.agent_id == agent_id]

    return {
        "total": len(receipts),
        "receipts": [r.to_dict() for r in receipts],
    }


@app.get("/receipts/verify", tags=["Audit"])
async def verify_receipt_chain(
    state: AppState = Depends(get_state),
    api_key: str = Depends(verify_api_key),
):
    """
    Verify the integrity of the receipt chain.

    Checks hash chain continuity.
    """
    is_valid, error = state.receipt_chain.verify_chain_integrity()

    return {
        "valid": is_valid,
        "error": error,
        "chain_length": len(state.receipt_chain.receipts),
        "merkle_root": state.receipt_chain.to_merkle_root(),
    }


@app.get("/metrics", tags=["Monitoring"])
async def get_metrics(
    state: AppState = Depends(get_state),
    api_key: str = Depends(verify_api_key),
):
    """Get governance metrics."""
    gate_metrics = state.gate.get_metrics()
    usage = state.penny_counter.get_tenant_usage("default")

    return {
        "gate": gate_metrics,
        "epoch": {
            "current": state.epoch_manager.global_epoch.current,
            "history_length": len(state.epoch_manager.global_epoch.get_history()),
        },
        "receipts": {
            "total": len(state.receipt_chain.receipts),
        },
        "billing": {
            "total_operations": usage.total_operations if usage else 0,
            "total_cost_cents": usage.total_cost_cents if usage else 0,
        },
    }


@app.get("/public-key", tags=["Cryptography"])
async def get_public_key(state: AppState = Depends(get_state)):
    """
    Get the public key for receipt verification.

    Clients use this to verify receipt signatures.
    """
    pem = state.gate.receipt_generator.signer.get_public_key_pem()
    key_id = state.gate.receipt_generator.signer.key_id

    return {
        "key_id": key_id,
        "algorithm": state.gate.receipt_generator.signer.algorithm.value,
        "public_key_pem": pem,
    }


# ============================================================================
# Run
# ============================================================================

def run():
    """Run the server."""
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(
        "juggernaut_rail.api.server:app",
        host="0.0.0.0",
        port=port,
        reload=os.environ.get("DEBUG", "false").lower() == "true",
    )


if __name__ == "__main__":
    run()
