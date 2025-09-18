FROM python:3.11-slim-bookworm

# Install security updates and system dependencies
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    git \
    ssh \
    gnupg \
    gnupg2 \
    libpq-dev \
    libssl-dev \
    libffi-dev \
    ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Upgrade pip and install Python dependencies
RUN python -m pip install --upgrade pip setuptools wheel \
    && pip install --no-cache-dir -r requirements.txt \
    && rm -rf ~/.cache/pip

# Create non-root user for security
RUN useradd -m -u 1000 catnet

# Copy application code
COPY src/ ./src/

# Create necessary directories
RUN mkdir -p logs configs migrations/versions

# Copy optional files if they exist
RUN touch alembic.ini || true

# Set ownership
RUN chown -R catnet:catnet /app

USER catnet

# Set environment variables for security
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PIP_NO_CACHE_DIR=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8080/health')" || exit 1

# Default command (can be overridden)
CMD ["python", "-m", "uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8080"]