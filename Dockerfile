# JUGGERNAUT RAIL - Production Docker Image
# Cryptographic AI Governance Infrastructure

FROM python:3.12-slim

# Labels
LABEL maintainer="abraham@finalbosstech.com"
LABEL description="Juggernaut Rail - Cryptographic AI Governance"
LABEL version="1.0.0"

# Environment
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PORT=8000

# Create app user
RUN groupadd -r juggernaut && useradd -r -g juggernaut juggernaut

# Install dependencies
WORKDIR /app

# Copy requirements first for caching
COPY pyproject.toml .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir hatch && \
    pip install --no-cache-dir \
        fastapi>=0.115.0 \
        uvicorn[standard]>=0.32.0 \
        pydantic>=2.10.0 \
        cryptography>=44.0.0 \
        httpx>=0.28.0 \
        structlog>=24.0.0 \
        prometheus-client>=0.21.0 \
        python-multipart>=0.0.17 \
        stripe>=11.0.0

# Copy application
COPY src/ /app/src/

# Set ownership
RUN chown -R juggernaut:juggernaut /app

# Switch to non-root user
USER juggernaut

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/health').raise_for_status()"

# Run
CMD ["python", "-m", "uvicorn", "src.api.server:app", "--host", "0.0.0.0", "--port", "8000"]
