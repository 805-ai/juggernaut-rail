"""
Tests for FastAPI Endpoints

Integration tests for the governance API.
"""

import pytest
from fastapi.testclient import TestClient
import os

# Set test environment before imports
os.environ["API_KEY"] = "test-key-12345"
os.environ["DATABASE_URL"] = "sqlite:///:memory:"

from api.server import app


@pytest.fixture
def client():
    """Create test client."""
    return TestClient(app)


@pytest.fixture
def auth_headers():
    """Headers with valid API key."""
    return {"X-API-Key": "test-key-12345"}


class TestHealthEndpoint:
    """Test health check endpoint."""

    def test_health_no_auth_required(self, client):
        """Health check should not require authentication."""
        response = client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert "epoch" in data
        assert "uptime_seconds" in data


class TestGateEndpoint:
    """Test the gate endpoint (core governance)."""

    def test_gate_requires_auth(self, client):
        """Gate endpoint should require API key."""
        response = client.post("/gate", json={
            "action": "INVOKE",
            "target_resource": "/api/v1/test",
            "agent_id": "agent-123",
        })

        assert response.status_code == 422  # Missing header

    def test_gate_invalid_api_key(self, client):
        """Invalid API key should be rejected."""
        response = client.post(
            "/gate",
            json={
                "action": "INVOKE",
                "target_resource": "/api/v1/test",
                "agent_id": "agent-123",
            },
            headers={"X-API-Key": "wrong-key"},
        )

        assert response.status_code == 401

    def test_gate_valid_request(self, client, auth_headers):
        """Valid gate request should return decision."""
        response = client.post(
            "/gate",
            json={
                "action": "INVOKE",
                "target_resource": "/api/v1/generate",
                "agent_id": "agent-123",
                "purpose": "INFERENCE",
                "data_category": "TEXT",
            },
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert data["decision"] in ["ALLOW", "DENY", "VETO"]
        assert "receipt_id" in data
        assert "cdt" in data
        assert "trust_score" in data
        assert "latency_ms" in data

    def test_gate_with_pii_vetoed(self, client, auth_headers):
        """Content with PII should be vetoed."""
        response = client.post(
            "/gate",
            json={
                "action": "INVOKE",
                "target_resource": "/api/v1/generate",
                "agent_id": "agent-123",
                "content": "My SSN is 123-45-6789",
            },
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()
        # Should be denied or vetoed due to PII
        assert data["decision"] in ["DENY", "VETO"] or data["trust_score"] < 0.5


class TestConsentEndpoint:
    """Test consent management endpoints."""

    def test_create_consent(self, client, auth_headers):
        """Should create a consent policy."""
        response = client.post(
            "/consent",
            json={
                "subject_id": "user-123",
                "partner_id": "partner-456",
                "purposes": ["INFERENCE", "ANALYTICS"],
                "data_categories": ["TEXT"],
                "retention_days": 365,
                "jurisdiction": "GDPR_EU",
            },
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert "policy_id" in data
        assert "cdt" in data
        assert "epoch" in data

    def test_invalid_purpose_rejected(self, client, auth_headers):
        """Invalid purpose should be rejected."""
        response = client.post(
            "/consent",
            json={
                "subject_id": "user-123",
                "partner_id": "partner-456",
                "purposes": ["INVALID_PURPOSE"],
                "data_categories": ["TEXT"],
            },
            headers=auth_headers,
        )

        assert response.status_code == 400


class TestRevocationEndpoint:
    """Test consent revocation."""

    def test_revoke_consent(self, client, auth_headers):
        """Should revoke consent and increment epoch."""
        # Get initial epoch
        health = client.get("/health").json()
        initial_epoch = health["epoch"]

        # Revoke
        response = client.post(
            "/revoke",
            json={
                "subject_id": "user-123",
                "reason": "USER_REQUEST",
            },
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert data["new_epoch"] > initial_epoch
        assert data["effect"] == "ALL_PRIOR_CDTS_INVALIDATED"

    def test_global_revocation(self, client, auth_headers):
        """Global revocation should affect all CDTs."""
        response = client.post(
            "/revoke",
            json={
                "reason": "SECURITY_INCIDENT",
            },
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert data["scope"] == "global"


class TestReceiptsEndpoint:
    """Test receipt querying."""

    def test_get_receipts(self, client, auth_headers):
        """Should return receipts."""
        # First create some receipts via gate
        for i in range(3):
            client.post(
                "/gate",
                json={
                    "action": "INVOKE",
                    "target_resource": f"/api/v1/test-{i}",
                    "agent_id": "agent-123",
                },
                headers=auth_headers,
            )

        response = client.get("/receipts", headers=auth_headers)

        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "receipts" in data
        assert data["total"] >= 3

    def test_verify_receipt_chain(self, client, auth_headers):
        """Should verify receipt chain integrity."""
        response = client.get("/receipts/verify", headers=auth_headers)

        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
        assert "chain_length" in data
        assert "merkle_root" in data


class TestMetricsEndpoint:
    """Test metrics endpoint."""

    def test_get_metrics(self, client, auth_headers):
        """Should return governance metrics."""
        response = client.get("/metrics", headers=auth_headers)

        assert response.status_code == 200
        data = response.json()
        assert "gate" in data
        assert "epoch" in data
        assert "receipts" in data
        assert "billing" in data


class TestPublicKeyEndpoint:
    """Test public key endpoint."""

    def test_get_public_key(self, client):
        """Should return public key for verification."""
        response = client.get("/public-key")

        assert response.status_code == 200
        data = response.json()
        assert "key_id" in data
        assert "algorithm" in data
        assert "public_key_pem" in data
        assert "BEGIN PUBLIC KEY" in data["public_key_pem"]
