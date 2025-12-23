"""
JUGGERNAUT RAIL - Vercel Serverless API
Production-ready serverless deployment with all components inline.
"""

import os
import sys
import hashlib
import json
import uuid
import base64
from datetime import datetime, timezone
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from threading import Lock

import logging
logger = logging.getLogger(__name__)

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


# ============================================================================
# ENUMS
# ============================================================================

class Purpose(Enum):
    TRAINING = "TRAINING"
    INFERENCE = "INFERENCE"
    ANALYTICS = "ANALYTICS"
    PERSONALIZATION = "PERSONALIZATION"
    RESEARCH = "RESEARCH"


class DataCategory(Enum):
    BIOMETRIC = "BIOMETRIC"
    LIKENESS = "LIKENESS"
    VOICE = "VOICE"
    TEXT = "TEXT"
    BEHAVIORAL = "BEHAVIORAL"
    HEALTH = "HEALTH"


class Jurisdiction(Enum):
    GDPR_EU = "GDPR_EU"
    CCPA_CA = "CCPA_CA"
    HIPAA_US = "HIPAA_US"
    GLOBAL = "GLOBAL"


class ReceiptAction(Enum):
    CREATE = "CREATE"
    READ = "READ"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    INVOKE = "INVOKE"
    GENERATE = "GENERATE"


class GateDecision(Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    VETO = "VETO"
    REVOKED = "REVOKED"


class CDTStatus(Enum):
    VALID = "VALID"
    REVOKED_EPOCH_MISMATCH = "REVOKED_EPOCH_MISMATCH"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"


# ============================================================================
# CORE: CDT
# ============================================================================

@dataclass(frozen=True)
class PolicyState:
    subject_id: str
    partner_id: str
    purposes: tuple
    data_categories: tuple
    retention_period_days: int
    jurisdiction: str

    def canonicalize(self) -> str:
        canonical_dict = {
            "subject_id": self.subject_id,
            "partner_id": self.partner_id,
            "purposes": list(sorted(self.purposes)),
            "data_categories": list(sorted(self.data_categories)),
            "retention_period_days": str(self.retention_period_days),
            "jurisdiction": self.jurisdiction.upper(),
        }
        return json.dumps(canonical_dict, sort_keys=True, separators=(',', ':'))


@dataclass
class ConsentDNAToken:
    token_value: str
    policy_hash: str
    epoch: int
    generated_at: str
    subject_id: str
    partner_id: str


class CDTGenerator:
    def __init__(self):
        self._hash_func = hashlib.sha3_256

    def generate(self, policy_state: PolicyState, global_epoch: int) -> ConsentDNAToken:
        canonical_policy = policy_state.canonicalize()
        input_payload = canonical_policy + str(global_epoch)
        token_value = self._hash_func(input_payload.encode('utf-8')).hexdigest()
        policy_hash = self._hash_func(canonical_policy.encode('utf-8')).hexdigest()
        return ConsentDNAToken(
            token_value=token_value,
            policy_hash=policy_hash,
            epoch=global_epoch,
            generated_at=datetime.now(timezone.utc).isoformat(),
            subject_id=policy_state.subject_id,
            partner_id=policy_state.partner_id,
        )


# ============================================================================
# CORE: EPOCH
# ============================================================================

class GlobalEpoch:
    def __init__(self, initial_epoch: int = 1):
        self._epoch = initial_epoch
        self._lock = Lock()
        self._history = []

    @property
    def current(self) -> int:
        return self._epoch

    def increment(self, reason: str = "REVOCATION") -> int:
        with self._lock:
            old_epoch = self._epoch
            self._epoch += 1
            self._history.append({
                "old": old_epoch,
                "new": self._epoch,
                "reason": reason,
                "at": datetime.now(timezone.utc).isoformat()
            })
            return self._epoch

    def get_history(self) -> List:
        return self._history.copy()


class EpochManager:
    def __init__(self):
        self.global_epoch = GlobalEpoch()
        self._domain_epochs = {}
        self._lock = Lock()

    def get_epoch(self, domain: Optional[str] = None) -> int:
        if domain is None:
            return self.global_epoch.current
        with self._lock:
            if domain not in self._domain_epochs:
                self._domain_epochs[domain] = GlobalEpoch(self.global_epoch.current)
            return self._domain_epochs[domain].current

    def revoke_global(self, reason: str = "GLOBAL_REVOCATION") -> int:
        return self.global_epoch.increment(reason)

    def revoke_subject(self, subject_id: str, reason: str = "SUBJECT_REVOCATION") -> int:
        domain = f"subject:{subject_id}"
        with self._lock:
            if domain not in self._domain_epochs:
                self._domain_epochs[domain] = GlobalEpoch(self.global_epoch.current)
            return self._domain_epochs[domain].increment(reason)


# ============================================================================
# CORE: RECEIPT
# ============================================================================

@dataclass
class OperationPayload:
    action: ReceiptAction
    target_resource: str
    parameters: Dict[str, Any]
    agent_id: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def compute_hash(self) -> str:
        canonical = json.dumps({
            "action": self.action.value,
            "agent_id": self.agent_id,
            "target_resource": self.target_resource,
            "timestamp": self.timestamp,
        }, sort_keys=True, separators=(',', ':'))
        return hashlib.sha3_256(canonical.encode('utf-8')).hexdigest()


@dataclass
class GovernanceReceipt:
    receipt_id: str
    timestamp: str
    agent_id: str
    policy_id: str
    operation_hash: str
    consent_token: str
    action: ReceiptAction
    target_resource: str
    chain_sequence: int
    prev_hash: str
    signature: str
    key_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "timestamp": self.timestamp,
            "agent_id": self.agent_id,
            "policy_id": self.policy_id,
            "operation_hash": self.operation_hash,
            "consent_token": self.consent_token,
            "action": self.action.value,
            "target_resource": self.target_resource,
            "chain_sequence": self.chain_sequence,
            "prev_hash": self.prev_hash,
            "signature": self.signature,
            "key_id": self.key_id,
        }

    def compute_hash(self) -> str:
        content = json.dumps({
            "receipt_id": self.receipt_id,
            "timestamp": self.timestamp,
            "operation_hash": self.operation_hash,
            "consent_token": self.consent_token,
            "chain_sequence": self.chain_sequence,
            "prev_hash": self.prev_hash,
        }, sort_keys=True, separators=(',', ':'))
        return hashlib.sha3_256(content.encode('utf-8')).hexdigest()


class ReceiptSigner:
    def __init__(self):
        self._private_key = ed25519.Ed25519PrivateKey.generate()
        public_bytes = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.key_id = hashlib.sha256(public_bytes).hexdigest()[:16]
        self._public_key = self._private_key.public_key()
        self.algorithm = "Ed25519"

    def sign(self, data: bytes) -> str:
        signature = self._private_key.sign(data)
        return base64.b64encode(signature).decode('utf-8')

    def get_public_key_pem(self) -> str:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode('utf-8')


class ReceiptGenerator:
    def __init__(self, policy_id: str = "POL-DEFAULT-V1"):
        self.signer = ReceiptSigner()
        self.policy_id = policy_id
        self._chain_sequence = 0
        self._prev_hash = "GENESIS"

    def generate(self, operation: OperationPayload, consent_token: str) -> GovernanceReceipt:
        receipt_id = f"RCP-{uuid.uuid4().hex[:12].upper()}"
        timestamp = datetime.now(timezone.utc).isoformat()
        operation_hash = operation.compute_hash()

        signing_data = json.dumps({
            "receipt_id": receipt_id,
            "timestamp": timestamp,
            "agent_id": operation.agent_id,
            "policy_id": self.policy_id,
            "operation_hash": operation_hash,
            "consent_token": consent_token,
            "chain_sequence": self._chain_sequence,
            "prev_hash": self._prev_hash,
        }, sort_keys=True, separators=(',', ':')).encode('utf-8')

        signature = self.signer.sign(signing_data)

        receipt = GovernanceReceipt(
            receipt_id=receipt_id,
            timestamp=timestamp,
            agent_id=operation.agent_id,
            policy_id=self.policy_id,
            operation_hash=operation_hash,
            consent_token=consent_token,
            action=operation.action,
            target_resource=operation.target_resource,
            chain_sequence=self._chain_sequence,
            prev_hash=self._prev_hash,
            signature=signature,
            key_id=self.signer.key_id,
        )

        self._prev_hash = receipt.compute_hash()
        self._chain_sequence += 1
        return receipt


class ReceiptChain:
    def __init__(self):
        self.receipts: List[GovernanceReceipt] = []

    def add(self, receipt: GovernanceReceipt):
        self.receipts.append(receipt)

    def verify_chain_integrity(self) -> tuple:
        if not self.receipts:
            return (True, None)
        prev_hash = "GENESIS"
        for i, receipt in enumerate(self.receipts):
            if receipt.chain_sequence != i:
                return (False, f"Chain sequence mismatch at position {i}")
            if receipt.prev_hash != prev_hash:
                return (False, f"Hash chain broken at position {i}")
            prev_hash = receipt.compute_hash()
        return (True, None)

    def to_merkle_root(self) -> str:
        if not self.receipts:
            return hashlib.sha3_256(b"EMPTY").hexdigest()
        hashes = [r.compute_hash() for r in self.receipts]
        while len(hashes) > 1:
            if len(hashes) % 2 == 1:
                hashes.append(hashes[-1])
            new_hashes = []
            for i in range(0, len(hashes), 2):
                combined = hashes[i] + hashes[i + 1]
                new_hashes.append(hashlib.sha3_256(combined.encode()).hexdigest())
            hashes = new_hashes
        return hashes[0]


# ============================================================================
# BILLING: PENNY COUNTER
# ============================================================================

@dataclass
class UsageRecord:
    record_id: str
    receipt_id: str
    timestamp: str
    tenant_id: str
    operation_type: str
    total_cost_cents: float = 0.0


class PennyCounter:
    def __init__(self):
        self._records: List[UsageRecord] = []
        self._counter = 0
        self._lock = Lock()

    def record_operation(self, receipt_id: str, tenant_id: str, operation_type: str) -> UsageRecord:
        with self._lock:
            self._counter += 1
            record = UsageRecord(
                record_id=f"USG-{self._counter:012d}",
                receipt_id=receipt_id,
                timestamp=datetime.now(timezone.utc).isoformat(),
                tenant_id=tenant_id,
                operation_type=operation_type,
                total_cost_cents=0.01,  # 1/100th of a cent per op
            )
            self._records.append(record)
            return record

    def record_revocation(self, tenant_id: str, epoch_change: int):
        with self._lock:
            self._counter += 1
            record = UsageRecord(
                record_id=f"USG-{self._counter:012d}",
                receipt_id=f"REVOKE-{epoch_change}",
                timestamp=datetime.now(timezone.utc).isoformat(),
                tenant_id=tenant_id,
                operation_type="REVOCATION",
                total_cost_cents=1.0,  # Revocations cost more
            )
            self._records.append(record)

    def get_tenant_usage(self, tenant_id: str):
        return {
            "total_operations": len([r for r in self._records if r.tenant_id == tenant_id]),
            "total_cost_cents": sum(r.total_cost_cents for r in self._records if r.tenant_id == tenant_id),
        }


# ============================================================================
# POLICY STORE
# ============================================================================

@dataclass
class FullPolicyState:
    subject_id: str
    partner_id: str
    purposes: Set[Purpose]
    data_categories: Set[DataCategory]
    retention_period_days: int
    jurisdiction: Jurisdiction

    @property
    def policy_id(self) -> str:
        content = f"{self.subject_id}:{self.partner_id}"
        return f"POL-{hashlib.sha256(content.encode()).hexdigest()[:12].upper()}"


class PolicyStore:
    def __init__(self):
        self._policies: Dict[str, FullPolicyState] = {}

    def store(self, policy: FullPolicyState) -> str:
        policy_id = policy.policy_id
        self._policies[policy_id] = policy
        return policy_id

    def get(self, policy_id: str) -> Optional[FullPolicyState]:
        return self._policies.get(policy_id)

    def get_for_pair(self, subject_id: str, partner_id: str) -> Optional[FullPolicyState]:
        for policy in self._policies.values():
            if policy.subject_id == subject_id and policy.partner_id == partner_id:
                return policy
        return None


# ============================================================================
# GOVERNANCE GATE
# ============================================================================

class GovernanceGate:
    def __init__(self, epoch_manager: EpochManager, policy_store: PolicyStore, penny_counter: PennyCounter):
        self.epoch_manager = epoch_manager
        self.policy_store = policy_store
        self.penny_counter = penny_counter
        self.cdt_generator = CDTGenerator()
        self.receipt_generator = ReceiptGenerator()
        self._total_requests = 0
        self._allowed_count = 0
        self._denied_count = 0

    def gate(
        self,
        operation: OperationPayload,
        policy: FullPolicyState,
        presented_cdt: Optional[str],
        purpose: Purpose,
        data_category: DataCategory,
        tenant_id: str,
    ):
        import time
        start = time.perf_counter()
        self._total_requests += 1

        current_epoch = self.epoch_manager.get_epoch()

        cdt_policy = PolicyState(
            subject_id=policy.subject_id,
            partner_id=policy.partner_id,
            purposes=tuple(p.value for p in policy.purposes),
            data_categories=tuple(d.value for d in policy.data_categories),
            retention_period_days=policy.retention_period_days,
            jurisdiction=policy.jurisdiction.value,
        )

        expected_cdt = self.cdt_generator.generate(cdt_policy, current_epoch)

        if presented_cdt and presented_cdt != expected_cdt.token_value:
            self._denied_count += 1
            return {
                "decision": GateDecision.REVOKED,
                "receipt": None,
                "trust_score": 0.0,
                "error_message": "CDT mismatch - consent may have been revoked",
                "latency_ms": (time.perf_counter() - start) * 1000,
            }

        if purpose not in policy.purposes:
            self._denied_count += 1
            return {
                "decision": GateDecision.DENY,
                "receipt": None,
                "trust_score": 0.0,
                "error_message": f"Purpose {purpose.value} not consented",
                "latency_ms": (time.perf_counter() - start) * 1000,
            }

        if data_category not in policy.data_categories:
            self._denied_count += 1
            return {
                "decision": GateDecision.DENY,
                "receipt": None,
                "trust_score": 0.0,
                "error_message": f"Data category {data_category.value} not consented",
                "latency_ms": (time.perf_counter() - start) * 1000,
            }

        receipt = self.receipt_generator.generate(operation, expected_cdt.token_value)
        self.penny_counter.record_operation(receipt.receipt_id, tenant_id, operation.action.value)
        self._allowed_count += 1

        return {
            "decision": GateDecision.ALLOW,
            "receipt": receipt,
            "trust_score": 1.0,
            "cdt": expected_cdt,
            "error_message": None,
            "latency_ms": (time.perf_counter() - start) * 1000,
        }

    def get_metrics(self) -> Dict[str, Any]:
        return {
            "total_requests": self._total_requests,
            "allowed": self._allowed_count,
            "denied": self._denied_count,
            "allow_rate": self._allowed_count / max(self._total_requests, 1),
        }


# ============================================================================
# APPLICATION STATE
# ============================================================================

class AppState:
    def __init__(self):
        self.epoch_manager = EpochManager()
        self.policy_store = PolicyStore()
        self.receipt_chain = ReceiptChain()
        self.penny_counter = PennyCounter()
        self.gate = GovernanceGate(
            epoch_manager=self.epoch_manager,
            policy_store=self.policy_store,
            penny_counter=self.penny_counter,
        )
        self.start_time = datetime.now(timezone.utc)


# Initialize app state on module load for serverless
app_state = AppState()


# Vercel Python handler
from http.server import BaseHTTPRequestHandler


class handler(BaseHTTPRequestHandler):
    """Vercel Python serverless handler for FastAPI."""

    def do_GET(self):
        self._handle_request("GET")

    def do_POST(self):
        self._handle_request("POST")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-API-Key")
        self.end_headers()

    def _handle_request(self, method):
        import urllib.parse

        path = urllib.parse.urlparse(self.path).path
        query = urllib.parse.urlparse(self.path).query

        # Get headers
        headers = {k.lower(): v for k, v in self.headers.items()}

        # Get body for POST
        body = None
        if method == "POST":
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length > 0:
                body = self.rfile.read(content_length).decode("utf-8")

        # Route handling
        response_data = None
        status_code = 200

        try:
            if path == "/health" or path == "/":
                uptime = (datetime.now(timezone.utc) - app_state.start_time).total_seconds()
                response_data = {
                    "status": "healthy",
                    "version": "1.0.0",
                    "epoch": app_state.epoch_manager.global_epoch.current,
                    "uptime_seconds": uptime,
                }

            elif path == "/public-key":
                response_data = {
                    "key_id": app_state.gate.receipt_generator.signer.key_id,
                    "algorithm": app_state.gate.receipt_generator.signer.algorithm,
                    "public_key_pem": app_state.gate.receipt_generator.signer.get_public_key_pem(),
                }

            elif path == "/metrics":
                api_key = headers.get("x-api-key", "")
                expected = os.environ.get("API_KEY", "dev-key-change-in-production")
                if api_key != expected:
                    status_code = 401
                    response_data = {"error": "Invalid API key"}
                else:
                    gate_metrics = app_state.gate.get_metrics()
                    usage = app_state.penny_counter.get_tenant_usage("default")
                    response_data = {
                        "gate": gate_metrics,
                        "epoch": {
                            "current": app_state.epoch_manager.global_epoch.current,
                            "history_length": len(app_state.epoch_manager.global_epoch.get_history()),
                        },
                        "receipts": {"total": len(app_state.receipt_chain.receipts)},
                        "billing": usage,
                    }

            elif path == "/receipts/verify":
                api_key = headers.get("x-api-key", "")
                expected = os.environ.get("API_KEY", "dev-key-change-in-production")
                if api_key != expected:
                    status_code = 401
                    response_data = {"error": "Invalid API key"}
                else:
                    is_valid, error = app_state.receipt_chain.verify_chain_integrity()
                    response_data = {
                        "valid": is_valid,
                        "error": error,
                        "chain_length": len(app_state.receipt_chain.receipts),
                        "merkle_root": app_state.receipt_chain.to_merkle_root(),
                    }

            elif path == "/gate" and method == "POST":
                api_key = headers.get("x-api-key", "")
                expected = os.environ.get("API_KEY", "dev-key-change-in-production")
                if api_key != expected:
                    status_code = 401
                    response_data = {"error": "Invalid API key"}
                else:
                    request_data = json.loads(body) if body else {}

                    try:
                        action = ReceiptAction[request_data.get("action", "INVOKE").upper()]
                    except KeyError:
                        action = ReceiptAction.INVOKE

                    try:
                        purpose = Purpose[request_data.get("purpose", "INFERENCE").upper()]
                    except KeyError:
                        purpose = Purpose.INFERENCE

                    try:
                        data_category = DataCategory[request_data.get("data_category", "TEXT").upper()]
                    except KeyError:
                        data_category = DataCategory.TEXT

                    agent_id = request_data.get("agent_id", "anonymous")
                    target_resource = request_data.get("target_resource", "default")

                    operation = OperationPayload(
                        action=action,
                        target_resource=target_resource,
                        parameters=request_data.get("parameters", {}),
                        agent_id=agent_id,
                    )

                    policy = app_state.policy_store.get_for_pair(agent_id, "default_partner")
                    if not policy:
                        policy = FullPolicyState(
                            subject_id=agent_id,
                            partner_id="default_partner",
                            purposes={Purpose.INFERENCE, Purpose.ANALYTICS},
                            data_categories={DataCategory.TEXT},
                            retention_period_days=365,
                            jurisdiction=Jurisdiction.GDPR_EU,
                        )
                        app_state.policy_store.store(policy)

                    result = app_state.gate.gate(
                        operation=operation,
                        policy=policy,
                        presented_cdt=request_data.get("cdt"),
                        purpose=purpose,
                        data_category=data_category,
                        tenant_id=agent_id,
                    )

                    if result["receipt"]:
                        app_state.receipt_chain.add(result["receipt"])

                    response_data = {
                        "decision": result["decision"].value,
                        "receipt_id": result["receipt"].receipt_id if result["receipt"] else None,
                        "cdt": result["cdt"].token_value if result.get("cdt") else None,
                        "trust_score": result["trust_score"],
                        "latency_ms": result["latency_ms"],
                        "error": result["error_message"],
                    }

            elif path == "/consent" and method == "POST":
                api_key = headers.get("x-api-key", "")
                expected = os.environ.get("API_KEY", "dev-key-change-in-production")
                if api_key != expected:
                    status_code = 401
                    response_data = {"error": "Invalid API key"}
                else:
                    request_data = json.loads(body) if body else {}

                    purposes = set()
                    for p in request_data.get("purposes", []):
                        try:
                            purposes.add(Purpose[p.upper()])
                        except KeyError:
                            pass

                    categories = set()
                    for c in request_data.get("data_categories", []):
                        try:
                            categories.add(DataCategory[c.upper()])
                        except KeyError:
                            pass

                    try:
                        jurisdiction = Jurisdiction[request_data.get("jurisdiction", "GLOBAL").upper()]
                    except KeyError:
                        jurisdiction = Jurisdiction.GLOBAL

                    policy = FullPolicyState(
                        subject_id=request_data.get("subject_id", ""),
                        partner_id=request_data.get("partner_id", ""),
                        purposes=purposes or {Purpose.INFERENCE},
                        data_categories=categories or {DataCategory.TEXT},
                        retention_period_days=request_data.get("retention_days", 365),
                        jurisdiction=jurisdiction,
                    )

                    policy_id = app_state.policy_store.store(policy)

                    cdt_policy = PolicyState(
                        subject_id=policy.subject_id,
                        partner_id=policy.partner_id,
                        purposes=tuple(p.value for p in policy.purposes),
                        data_categories=tuple(d.value for d in policy.data_categories),
                        retention_period_days=policy.retention_period_days,
                        jurisdiction=policy.jurisdiction.value,
                    )
                    cdt = app_state.gate.cdt_generator.generate(cdt_policy, app_state.epoch_manager.global_epoch.current)

                    response_data = {
                        "policy_id": policy_id,
                        "cdt": cdt.token_value,
                        "epoch": app_state.epoch_manager.global_epoch.current,
                        "created_at": datetime.now(timezone.utc).isoformat(),
                    }

            elif path == "/revoke" and method == "POST":
                api_key = headers.get("x-api-key", "")
                expected = os.environ.get("API_KEY", "dev-key-change-in-production")
                if api_key != expected:
                    status_code = 401
                    response_data = {"error": "Invalid API key"}
                else:
                    request_data = json.loads(body) if body else {}

                    subject_id = request_data.get("subject_id")
                    reason = request_data.get("reason", "USER_REQUEST")

                    if subject_id:
                        new_epoch = app_state.epoch_manager.revoke_subject(subject_id, reason)
                        scope = f"subject:{subject_id}"
                    else:
                        new_epoch = app_state.epoch_manager.revoke_global(reason)
                        scope = "global"

                    app_state.penny_counter.record_revocation("system", new_epoch)

                    response_data = {
                        "new_epoch": new_epoch,
                        "scope": scope,
                        "reason": reason,
                        "effect": "ALL_PRIOR_CDTS_INVALIDATED",
                        "revoked_at": datetime.now(timezone.utc).isoformat(),
                    }

            else:
                status_code = 404
                response_data = {"error": "Not found", "path": path}

        except Exception as e:
            status_code = 500
            response_data = {"error": str(e)}

        # Send response
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(response_data).encode("utf-8"))
