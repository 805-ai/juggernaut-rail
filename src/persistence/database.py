"""
Database Connection Layer

Supports SQLite (dev) and PostgreSQL (production) with automatic schema migration.
"""

import os
import sqlite3
from contextlib import contextmanager
from typing import Optional, Generator, Any, Dict, List
from datetime import datetime, timezone
import threading
import structlog

logger = structlog.get_logger()

# Schema version for migrations
SCHEMA_VERSION = 1

SCHEMA_SQL = """
-- Epoch tracking
CREATE TABLE IF NOT EXISTS epochs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    epoch_number INTEGER NOT NULL UNIQUE,
    scope TEXT NOT NULL DEFAULT 'global',
    reason TEXT,
    created_at TEXT NOT NULL,
    created_by TEXT
);

-- Policies
CREATE TABLE IF NOT EXISTS policies (
    policy_id TEXT PRIMARY KEY,
    subject_id TEXT NOT NULL,
    partner_id TEXT NOT NULL,
    purposes TEXT NOT NULL,  -- JSON array
    data_categories TEXT NOT NULL,  -- JSON array
    retention_period_days INTEGER NOT NULL,
    jurisdiction TEXT NOT NULL,
    custom_terms TEXT,  -- JSON object
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    epoch_created INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Receipts (the core audit trail)
CREATE TABLE IF NOT EXISTS receipts (
    receipt_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    operation_hash TEXT NOT NULL,
    consent_token TEXT NOT NULL,
    action TEXT NOT NULL,
    target_resource TEXT NOT NULL,
    chain_sequence INTEGER NOT NULL,
    prev_hash TEXT NOT NULL,
    signature TEXT NOT NULL,
    signature_algorithm TEXT NOT NULL,
    key_id TEXT,
    veto_state TEXT,  -- JSON object
    broken_seal INTEGER NOT NULL DEFAULT 0,
    regulatory_mode TEXT,
    receipt_hash TEXT NOT NULL,
    FOREIGN KEY (policy_id) REFERENCES policies(policy_id)
);

-- Usage records for billing
CREATE TABLE IF NOT EXISTS usage_records (
    record_id TEXT PRIMARY KEY,
    receipt_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    operation_type TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    tokens_processed INTEGER NOT NULL DEFAULT 0,
    signature_verifications INTEGER NOT NULL DEFAULT 1,
    storage_bytes INTEGER NOT NULL DEFAULT 0,
    compute_ms REAL NOT NULL DEFAULT 0.0,
    unit_cost_cents REAL NOT NULL,
    total_cost_cents REAL NOT NULL,
    billing_tier TEXT NOT NULL,
    settled INTEGER NOT NULL DEFAULT 0,
    invoice_id TEXT,
    FOREIGN KEY (receipt_id) REFERENCES receipts(receipt_id)
);

-- CDT cache for fast validation
CREATE TABLE IF NOT EXISTS cdt_cache (
    cdt_hash TEXT PRIMARY KEY,
    policy_id TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    FOREIGN KEY (policy_id) REFERENCES policies(policy_id)
);

-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_receipts_timestamp ON receipts(timestamp);
CREATE INDEX IF NOT EXISTS idx_receipts_agent ON receipts(agent_id);
CREATE INDEX IF NOT EXISTS idx_receipts_policy ON receipts(policy_id);
CREATE INDEX IF NOT EXISTS idx_receipts_chain ON receipts(chain_sequence);
CREATE INDEX IF NOT EXISTS idx_policies_subject ON policies(subject_id);
CREATE INDEX IF NOT EXISTS idx_policies_partner ON policies(partner_id);
CREATE INDEX IF NOT EXISTS idx_policies_status ON policies(status);
CREATE INDEX IF NOT EXISTS idx_usage_tenant ON usage_records(tenant_id);
CREATE INDEX IF NOT EXISTS idx_usage_settled ON usage_records(settled);
CREATE INDEX IF NOT EXISTS idx_cdt_epoch ON cdt_cache(epoch);
"""

POSTGRES_SCHEMA_SQL = """
-- Epoch tracking
CREATE TABLE IF NOT EXISTS epochs (
    id SERIAL PRIMARY KEY,
    epoch_number INTEGER NOT NULL UNIQUE,
    scope TEXT NOT NULL DEFAULT 'global',
    reason TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    created_by TEXT
);

-- Policies
CREATE TABLE IF NOT EXISTS policies (
    policy_id TEXT PRIMARY KEY,
    subject_id TEXT NOT NULL,
    partner_id TEXT NOT NULL,
    purposes JSONB NOT NULL,
    data_categories JSONB NOT NULL,
    retention_period_days INTEGER NOT NULL,
    jurisdiction TEXT NOT NULL,
    custom_terms JSONB,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    epoch_created INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

-- Receipts
CREATE TABLE IF NOT EXISTS receipts (
    receipt_id TEXT PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    agent_id TEXT NOT NULL,
    policy_id TEXT NOT NULL REFERENCES policies(policy_id),
    operation_hash TEXT NOT NULL,
    consent_token TEXT NOT NULL,
    action TEXT NOT NULL,
    target_resource TEXT NOT NULL,
    chain_sequence INTEGER NOT NULL,
    prev_hash TEXT NOT NULL,
    signature TEXT NOT NULL,
    signature_algorithm TEXT NOT NULL,
    key_id TEXT,
    veto_state JSONB,
    broken_seal BOOLEAN NOT NULL DEFAULT FALSE,
    regulatory_mode TEXT,
    receipt_hash TEXT NOT NULL
);

-- Usage records
CREATE TABLE IF NOT EXISTS usage_records (
    record_id TEXT PRIMARY KEY,
    receipt_id TEXT NOT NULL REFERENCES receipts(receipt_id),
    timestamp TIMESTAMPTZ NOT NULL,
    tenant_id TEXT NOT NULL,
    operation_type TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    tokens_processed INTEGER NOT NULL DEFAULT 0,
    signature_verifications INTEGER NOT NULL DEFAULT 1,
    storage_bytes INTEGER NOT NULL DEFAULT 0,
    compute_ms REAL NOT NULL DEFAULT 0.0,
    unit_cost_cents REAL NOT NULL,
    total_cost_cents REAL NOT NULL,
    billing_tier TEXT NOT NULL,
    settled BOOLEAN NOT NULL DEFAULT FALSE,
    invoice_id TEXT
);

-- CDT cache
CREATE TABLE IF NOT EXISTS cdt_cache (
    cdt_hash TEXT PRIMARY KEY,
    policy_id TEXT NOT NULL REFERENCES policies(policy_id),
    epoch INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ
);

-- Schema version
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_receipts_timestamp ON receipts(timestamp);
CREATE INDEX IF NOT EXISTS idx_receipts_agent ON receipts(agent_id);
CREATE INDEX IF NOT EXISTS idx_receipts_policy ON receipts(policy_id);
CREATE INDEX IF NOT EXISTS idx_receipts_chain ON receipts(chain_sequence);
CREATE INDEX IF NOT EXISTS idx_policies_subject ON policies(subject_id);
CREATE INDEX IF NOT EXISTS idx_policies_partner ON policies(partner_id);
CREATE INDEX IF NOT EXISTS idx_policies_status ON policies(status);
CREATE INDEX IF NOT EXISTS idx_usage_tenant ON usage_records(tenant_id);
CREATE INDEX IF NOT EXISTS idx_usage_settled ON usage_records(settled);
CREATE INDEX IF NOT EXISTS idx_cdt_epoch ON cdt_cache(epoch);
"""


class Database:
    """
    Database connection manager with SQLite and PostgreSQL support.

    Usage:
        db = Database()  # Uses DATABASE_URL env or defaults to SQLite
        with db.connection() as conn:
            conn.execute("SELECT * FROM receipts")
    """

    _instance: Optional["Database"] = None
    _lock = threading.Lock()

    def __init__(self, database_url: Optional[str] = None):
        self.database_url = database_url or os.environ.get(
            "DATABASE_URL",
            "sqlite:///juggernaut.db"
        )
        self.is_postgres = self.database_url.startswith("postgres")
        self._local = threading.local()
        self._initialized = False

    @classmethod
    def get_instance(cls, database_url: Optional[str] = None) -> "Database":
        """Get singleton database instance."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls(database_url)
        return cls._instance

    def _get_sqlite_path(self) -> str:
        """Extract SQLite file path from URL."""
        if self.database_url.startswith("sqlite:///"):
            return self.database_url[10:]
        return "juggernaut.db"

    @contextmanager
    def connection(self) -> Generator[Any, None, None]:
        """Get a database connection (thread-safe)."""
        if self.is_postgres:
            yield from self._postgres_connection()
        else:
            yield from self._sqlite_connection()

    @contextmanager
    def _sqlite_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """SQLite connection with WAL mode for concurrency."""
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            db_path = self._get_sqlite_path()
            self._local.conn = sqlite3.connect(
                db_path,
                check_same_thread=False,
                timeout=30.0,
            )
            self._local.conn.row_factory = sqlite3.Row
            # Enable WAL mode for better concurrency
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA synchronous=NORMAL")
            self._local.conn.execute("PRAGMA foreign_keys=ON")

        try:
            yield self._local.conn
            self._local.conn.commit()
        except Exception:
            self._local.conn.rollback()
            raise

    @contextmanager
    def _postgres_connection(self) -> Generator[Any, None, None]:
        """PostgreSQL connection with connection pooling."""
        try:
            import psycopg2
            from psycopg2.extras import RealDictCursor
        except ImportError:
            raise ImportError("psycopg2 required for PostgreSQL. Install with: pip install psycopg2-binary")

        conn = psycopg2.connect(self.database_url, cursor_factory=RealDictCursor)
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def initialize(self) -> None:
        """Initialize database schema."""
        if self._initialized:
            return

        with self._lock:
            if self._initialized:
                return

            schema = POSTGRES_SCHEMA_SQL if self.is_postgres else SCHEMA_SQL

            with self.connection() as conn:
                if self.is_postgres:
                    cursor = conn.cursor()
                    cursor.execute(schema)
                else:
                    conn.executescript(schema)

                # Record schema version
                now = datetime.now(timezone.utc).isoformat()
                if self.is_postgres:
                    cursor.execute(
                        "INSERT INTO schema_version (version, applied_at) VALUES (%s, %s) ON CONFLICT (version) DO NOTHING",
                        (SCHEMA_VERSION, now)
                    )
                else:
                    conn.execute(
                        "INSERT OR IGNORE INTO schema_version (version, applied_at) VALUES (?, ?)",
                        (SCHEMA_VERSION, now)
                    )

            self._initialized = True
            logger.info("database_initialized", url=self.database_url[:20] + "...", is_postgres=self.is_postgres)

    def execute(self, query: str, params: tuple = ()) -> List[Dict[str, Any]]:
        """Execute a query and return results as list of dicts."""
        with self.connection() as conn:
            if self.is_postgres:
                cursor = conn.cursor()
                cursor.execute(query, params)
                if cursor.description:
                    return [dict(row) for row in cursor.fetchall()]
                return []
            else:
                cursor = conn.execute(query, params)
                if cursor.description:
                    return [dict(row) for row in cursor.fetchall()]
                return []

    def execute_many(self, query: str, params_list: List[tuple]) -> int:
        """Execute a query with multiple parameter sets."""
        with self.connection() as conn:
            if self.is_postgres:
                cursor = conn.cursor()
                cursor.executemany(query, params_list)
                return cursor.rowcount
            else:
                cursor = conn.executemany(query, params_list)
                return cursor.rowcount

    def close(self) -> None:
        """Close database connections."""
        if hasattr(self._local, 'conn') and self._local.conn:
            self._local.conn.close()
            self._local.conn = None


def get_database(database_url: Optional[str] = None) -> Database:
    """Get the database singleton instance."""
    db = Database.get_instance(database_url)
    db.initialize()
    return db
