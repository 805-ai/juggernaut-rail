# JUGGERNAUT RAIL - Production Docker Image
# Cryptographic AI Governance Infrastructure
# Multi-stage build for security and efficiency

# ==============================================================================
# Stage 1: Builder
# ==============================================================================
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy and install requirements
COPY requirements.txt .
RUN pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt

# ==============================================================================
# Stage 2: Production
# ==============================================================================
FROM python:3.12-slim AS production

# Labels
LABEL maintainer="abraham@finalbosstech.com"
LABEL org.opencontainers.image.title="Juggernaut Rail"
LABEL org.opencontainers.image.description="Cryptographic AI Governance Infrastructure"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.vendor="FinalBoss Tech"
LABEL org.opencontainers.image.licenses="Proprietary"

# Security: Don't run as root
RUN groupadd -r juggernaut && useradd -r -g juggernaut -s /sbin/nologin juggernaut

# Environment
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONFAULTHANDLER=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PORT=8000 \
    # Security: Disable debug in production
    DEBUG=false \
    # Database default (override in deployment)
    DATABASE_URL=sqlite:///data/juggernaut.db \
    # Key storage
    KEY_STORAGE_PATH=/data/keys

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # For healthcheck
    curl \
    # CA certificates for HTTPS
    ca-certificates \
    # Timezone data
    tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

WORKDIR /app

# Install Python packages from builder
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/* && rm -rf /wheels

# Copy application code
COPY --chown=juggernaut:juggernaut src/ /app/src/

# Create data directories
RUN mkdir -p /data/keys /data/receipts && \
    chown -R juggernaut:juggernaut /data

# Volume for persistent data
VOLUME ["/data"]

# Switch to non-root user
USER juggernaut

# Expose port
EXPOSE 8000

# Health check with proper timeout
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:${PORT}/health || exit 1

# Use exec form for proper signal handling
ENTRYPOINT ["python", "-m", "uvicorn"]
CMD ["src.api.server:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--access-log", "--proxy-headers"]
