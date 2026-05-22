FROM python:3.10-slim-bookworm

# Metadata
LABEL maintainer="secopsai"
LABEL description="OpenClaw Security Detection Pipeline - Production Container"
LABEL version="1.0.0"

# Set working directory
WORKDIR /opt/secopsai

# Install system dependencies and apply security updates
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# Create non-root user for security
RUN useradd -m -u 1000 secops && \
    chown -R secops:secops /opt/secopsai

# Switch to non-root user
USER secops

# Health check - verify detection pipeline works
HEALTHCHECK --interval=5m --timeout=1m --start-period=1m --retries=3 \
    CMD python -c "from detect import run_detection; print('ok')" || exit 1

# Default command: run live OpenClaw detection
CMD ["sh", "-c", "while true; do python -u run_openclaw_live.py; sleep \"${SECOPS_POLL_INTERVAL_SECONDS:-300}\"; done"]

# Allow override to run other commands:
# docker run secopsai python evaluate.py --mode benchmark
