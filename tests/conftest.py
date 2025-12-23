"""
Pytest Configuration and Fixtures
"""

import os
import sys
import pytest
import tempfile

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), 'src'))

# Set test environment
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["API_KEY"] = "test-key-12345"
os.environ["KEY_MASTER_SECRET"] = "test-master-secret-for-tests"


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"

    yield db_path

    # Cleanup
    try:
        os.unlink(db_path)
    except:
        pass


@pytest.fixture
def temp_keys_dir():
    """Create a temporary directory for key storage."""
    with tempfile.TemporaryDirectory() as tmpdir:
        os.environ["KEY_STORAGE_PATH"] = tmpdir
        yield tmpdir


@pytest.fixture
def sample_policy_dict():
    """Sample policy as dictionary."""
    return {
        "subject_id": "user-123",
        "partner_id": "partner-456",
        "purposes": ["INFERENCE", "ANALYTICS"],
        "data_categories": ["TEXT", "METADATA"],
        "retention_period_days": 365,
        "jurisdiction": "GDPR_EU",
    }


@pytest.fixture
def sample_operation_dict():
    """Sample operation as dictionary."""
    return {
        "action": "INVOKE",
        "target_resource": "/api/v1/generate",
        "parameters": {"model": "gpt-4", "prompt": "Hello"},
        "agent_id": "agent-789",
    }
