# JUGGERNAUT RAIL

## Cryptographic AI Governance Infrastructure

**NO RECEIPT, NO RUN** - Every AI operation is gated by cryptographic consent verification.

---

## Overview

Juggernaut Rail is a production-ready implementation of the FinalBoss Tech patent portfolio for AI governance. It provides:

- **CDT (Consent DNA Token)**: Epoch-based instant consent revocation
- **Cryptographic Receipt Rail**: ML-DSA-65 post-quantum signed audit trail
- **Zero-Multiplier Veto**: Binary safety checks that instantly kill operations
- **Penny Counter Billing**: Integrated metering with Stripe settlement
- **Governance-as-a-Service API**: FastAPI server for enterprise deployment

## Patent Portfolio

This implementation is covered by:

| Patent | Title | Key Innovation |
|--------|-------|----------------|
| **19/240,581** | Blockchain-Based Dynamic Consent Management | zk-SNARK verification, hierarchical consent |
| **CDT Provisional** | Cryptographic Governance Receipt Rail | `CDT = Hash(Policy \|\| Epoch)` |
| **Veto Provisional** | Deterministic AI Governance via Receipts | Zero-multiplier: `S = B × Π(V_i)` |
| **Penny Counter** | CDT + Penny Counter for Billing | Unified compliance + monetization |

## Quick Start

### Docker (Recommended)

```bash
# Clone and run
git clone https://github.com/805-ai/juggernaut-rail.git
cd juggernaut-rail

# Set API key
export API_KEY="your-production-key"

# Run
docker-compose up -d
```

### Local Development

```bash
# Install dependencies
pip install -e ".[dev]"

# Run server
uvicorn src.api.server:app --reload --port 8000
```

## API Usage

### 1. Create Consent

```bash
curl -X POST http://localhost:8000/consent \
  -H "X-API-Key: dev-key-change-in-production" \
  -H "Content-Type: application/json" \
  -d '{
    "subject_id": "user-123",
    "partner_id": "my-app",
    "purposes": ["INFERENCE", "ANALYTICS"],
    "data_categories": ["TEXT"],
    "retention_days": 365,
    "jurisdiction": "GDPR_EU"
  }'
```

Response:
```json
{
  "policy_id": "POL-ABC123DEF456",
  "cdt": "a1b2c3d4e5f6...",
  "epoch": 1,
  "created_at": "2025-12-21T..."
}
```

### 2. Gate an Operation

```bash
curl -X POST http://localhost:8000/gate \
  -H "X-API-Key: dev-key-change-in-production" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "INVOKE",
    "target_resource": "/api/v1/generate",
    "agent_id": "agent-456",
    "purpose": "INFERENCE",
    "data_category": "TEXT",
    "cdt": "a1b2c3d4e5f6..."
  }'
```

Response:
```json
{
  "decision": "ALLOW",
  "receipt_id": "RCP-789ABC",
  "cdt": "a1b2c3d4e5f6...",
  "trust_score": 0.95,
  "latency_ms": 1.23,
  "error": null
}
```

### 3. Revoke Consent (Instant)

```bash
curl -X POST http://localhost:8000/revoke \
  -H "X-API-Key: dev-key-change-in-production" \
  -H "Content-Type: application/json" \
  -d '{
    "subject_id": "user-123",
    "reason": "USER_REQUEST"
  }'
```

Response:
```json
{
  "new_epoch": 2,
  "scope": "subject:user-123",
  "reason": "USER_REQUEST",
  "effect": "ALL_PRIOR_CDTS_INVALIDATED",
  "revoked_at": "2025-12-21T..."
}
```

**Immediately after revocation**, any CDT generated under epoch 1 will fail validation.

### 4. Verify Receipt Chain

```bash
curl http://localhost:8000/receipts/verify \
  -H "X-API-Key: dev-key-change-in-production"
```

Response:
```json
{
  "valid": true,
  "error": null,
  "chain_length": 1523,
  "merkle_root": "abc123..."
}
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     API LAYER (FastAPI)                     │
│  POST /gate    POST /consent    POST /revoke    GET /receipts│
└────────────────────────────┬────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────┐
│                   GOVERNANCE GATE                           │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌──────────┐  │
│  │CDT Validator│  │Policy Eval│  │Veto Engine│  │ Signer  │  │
│  └───────────┘  └───────────┘  └───────────┘  └──────────┘  │
└────────────────────────────┬────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────┐
│                    CORE COMPONENTS                          │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌──────────┐  │
│  │   CDT     │  │  Epoch    │  │ Receipt   │  │  Policy  │  │
│  │ Generator │  │ Manager   │  │ Chain     │  │  Store   │  │
│  └───────────┘  └───────────┘  └───────────┘  └──────────┘  │
└────────────────────────────┬────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────┐
│                   BILLING LAYER                             │
│  ┌───────────────┐  ┌───────────────┐  ┌─────────────────┐  │
│  │ Penny Counter │  │ Gas Calculator│  │ Stripe Settle  │  │
│  └───────────────┘  └───────────────┘  └─────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Key Formulas

### CDT Generation
```python
CDT = SHA3-256(Canonical(Policy_State) || str(Global_Epoch_Counter))
```

### Trust Score
```
S_Trust = B_base × (R_actual / R_max) × Π(V_crit_i) × Σ(w_j × f_j)
```

Where any `V_crit_i = 0` → `S_Trust = 0` instantly.

### Epoch Revocation
```
Epoch: 1 → 2

All CDTs generated at epoch 1 become INVALID immediately.
No propagation delay. No cache invalidation.
```

## Configuration

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `PORT` | Server port | `8000` |
| `API_KEY` | API key for authentication | `dev-key-change-in-production` |
| `CORS_ORIGINS` | Allowed CORS origins | `*` |
| `STRIPE_API_KEY` | Stripe API key for billing | - |
| `DEBUG` | Enable debug mode | `false` |

## Whitespace Advantages

This system exploits 8 major whitespace gaps vs. competitors:

| Gap | Competitor Status | Juggernaut Rail |
|-----|------------------|-----------------|
| Post-Quantum Signatures | None use ML-DSA | ML-DSA-65 ready |
| Instant Revocation | Propagation delays | Epoch = INSTANT |
| Kernel Enforcement | App-layer only | eBPF embodiment |
| Model-to-Receipt Binding | Not available | Merkle root binding |
| Zero-Multiplier Veto | Gradual degradation | Binary kill switch |
| Integrated Billing | Separate systems | Penny Counter |
| Refinery Purity Profiles | Not available | Vertical-specific |
| Continuous Autonomy Scalar | Risk scoring only | `R_actual/R_max` |

## License

Proprietary. Patent-protected technology.

(c) 2025 FinalBoss Tech / Abraham Manzano

## Contact

- Website: https://finalbosstech.com
- Email: abraham@finalbosstech.com
- GitHub: https://github.com/805-ai
