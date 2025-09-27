# Multi-stage build for CatNet
FROM python:3.11-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libpq-dev \
    libssl-dev \
    libffi-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir wheel && \
    pip wheel --no-cache-dir --no-deps --wheel-dir /app/wheels -r requirements.txt

# Production image
FROM python:3.11-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libpq5 \
    netcat-traditional \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -g 1000 catnet && \
    useradd -r -u 1000 -g catnet -s /bin/bash -m catnet

# Set working directory
WORKDIR /app

# Copy wheels from builder
COPY --from=builder /app/wheels /wheels

# Install dependencies from wheels
RUN pip install --no-cache-dir /wheels/*

# Copy application code
COPY --chown=catnet:catnet . .

# Create necessary directories
RUN mkdir -p /var/log/catnet /var/log/catnet/sessions /etc/catnet/certs && \
    chown -R catnet:catnet /var/log/catnet /etc/catnet

# Switch to non-root user
USER catnet

# Set environment variables
ENV PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Expose ports for different services
EXPOSE 8000 8081 8082 8083 8084

# Default command
CMD ["python", "main.py", "--service", "main"]