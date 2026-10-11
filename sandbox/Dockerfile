# Detonation sandbox: runs one package's install and import under strace.
# Containment is applied by the runner (secopsai/sandbox.py): --network none,
# no capabilities, no-new-privileges, read-only root, memory/pid/cpu limits,
# hard timeout. The image only provides the tools and the bait.
FROM node:22-bookworm-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-pip python3-setuptools strace ca-certificates coreutils \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 10001 analyst
# Bait: realistic-looking but fake credentials. Any read of these is recorded;
# none of them is valid anywhere.
COPY --chown=analyst:analyst bait/ /home/analyst/
COPY detonate.sh /usr/local/bin/detonate
COPY dnslog.py /usr/local/bin/dnslog.py
RUN chmod 0755 /usr/local/bin/detonate && chmod 0600 /home/analyst/.ssh/id_rsa
USER analyst
WORKDIR /home/analyst
ENTRYPOINT ["/usr/local/bin/detonate"]
