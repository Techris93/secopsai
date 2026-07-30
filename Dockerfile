ARG PYTHON_IMAGE=python:3.13-alpine@sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0

FROM ${PYTHON_IMAGE} AS builder

WORKDIR /opt/secopsai

COPY requirements.txt .

RUN apk add --no-cache build-base linux-headers && \
    python -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade pip "setuptools>=78.1.1" wheel && \
    /opt/venv/bin/pip install --no-cache-dir -r requirements.txt && \
    /opt/venv/bin/python -c "import importlib.metadata as m; assert tuple(map(int, m.version('setuptools').split('.')[:3])) >= (78, 1, 1)"

FROM ${PYTHON_IMAGE}

# Metadata
LABEL maintainer="secopsai"
LABEL description="OpenClaw Security Detection Pipeline - Production Container"
LABEL version="1.0.0"

# Set working directory
WORKDIR /opt/secopsai

ENV PATH="/opt/venv/bin:$PATH"

# Install system dependencies and apply security updates
RUN apk update && apk upgrade && apk add --no-cache \
    git \
    curl \
    ca-certificates

# Create the unprivileged runtime owner before copying application content so
# the image does not need a later recursive ownership layer.
RUN adduser -D -u 1000 secops

# Copy only runtime files admitted by .dockerignore.
COPY --chown=secops:secops . .

# Copy only the resolved Python environment. Build tools and their transitive
# packages remain in the discarded builder stage.
COPY --from=builder --chown=secops:secops /opt/venv /opt/venv

# Apply exact PSF Python 3.13 security backports. PATCHES.json records the
# upstream commits and hashes used for the evidence-backed OpenVEX statement.
COPY container/stdlib/3.13/tarfile.py /usr/local/lib/python3.13/tarfile.py
COPY container/stdlib/3.13/html/parser.py /usr/local/lib/python3.13/html/parser.py
COPY container/stdlib/3.13/PATCHES.json /usr/local/share/secopsai/cpython-patches.json

# pip, setuptools, wheel, and ensurepip are installation tools. SecOpsAI has no
# runtime import of them, so remove both base-image and venv copies after the
# resolved environment has been assembled.
RUN rm -rf \
      /usr/local/lib/python3.13/ensurepip \
      /usr/local/lib/python3.13/site-packages/pip* \
      /usr/local/lib/python3.13/site-packages/setuptools* \
      /usr/local/lib/python3.13/site-packages/wheel* \
      /opt/venv/lib/python3.13/site-packages/pip* \
      /opt/venv/lib/python3.13/site-packages/setuptools* \
      /opt/venv/lib/python3.13/site-packages/wheel* \
      /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.13 \
      /opt/venv/bin/pip /opt/venv/bin/pip3 /opt/venv/bin/pip3.13 && \
    echo '9fedddf7e814c226cb7e1ac0aa603092eda40047367ec00ad740a81484a17d01  /usr/local/lib/python3.13/tarfile.py' | sha256sum -c - && \
    echo '4274e9112adf3fa57c7f9afa7c9b5c631456b18b7403cc627cc5027d02cdd2ae  /usr/local/lib/python3.13/html/parser.py' | sha256sum -c - && \
    python -c "import importlib.util as u; assert u.find_spec('pip') is None; assert u.find_spec('setuptools') is None; assert u.find_spec('wheel') is None" && \
    python -c "import html.parser, tarfile; from detect import run_detection; assert html.parser.__file__ == '/usr/local/lib/python3.13/html/parser.py'; assert tarfile.__file__ == '/usr/local/lib/python3.13/tarfile.py'; print('runtime-import-ok')" && \
    chmod 0755 /opt/secopsai/scripts/container-entrypoint.sh

# Switch to non-root user
USER secops

# Health check - verify detection pipeline works
HEALTHCHECK --interval=5m --timeout=1m --start-period=1m --retries=3 \
    CMD python -c "from detect import run_detection; print('ok')" || exit 1

# Default command: run live OpenClaw detection with graceful signal handling.
CMD ["sh", "scripts/container-entrypoint.sh"]

# Allow override to run other commands:
# docker run secopsai python evaluate.py --mode benchmark
