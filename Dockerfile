FROM python:3.10-alpine

# Metadata
LABEL maintainer="secopsai"
LABEL description="OpenClaw Security Detection Pipeline - Production Container"
LABEL version="1.0.0"

# Set working directory
WORKDIR /opt/secopsai

# Install system dependencies and apply security updates
RUN apk update && apk upgrade && apk add --no-cache \
    git \
    curl \
    ca-certificates

# Copy project files
COPY . .

# Install Python dependencies (including build deps for compile-on-demand)
RUN apk add --no-cache --virtual .build-deps build-base linux-headers && \
    pip install --no-cache-dir --upgrade pip "setuptools>=78.1.1" wheel && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir --upgrade "setuptools>=78.1.1" && \
    python -c "import importlib.metadata as m; assert tuple(map(int, m.version('setuptools').split('.')[:3])) >= (78, 1, 1)" && \
    apk del .build-deps

# Fail the build if an OS or cached Python environment reintroduces either
# vulnerable distribution outside the active /usr/local Python environment.
RUN vulnerable="$(find / -type d \( \
      -name 'msgpack-1.1.2.dist-info' -o \
      -name 'setuptools-70.3.0.dist-info' \
    \) -print 2>/dev/null)" && \
    test -z "$vulnerable" || { printf 'Vulnerable Python metadata found:\n%s\n' "$vulnerable"; exit 1; }

# Create non-root user for security
RUN adduser -D -u 1000 secops && \
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
