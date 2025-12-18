# Build
FROM rust:latest AS builder

WORKDIR /usr/src/app

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    clang \
    && rm -rf /var/lib/apt/lists/*

COPY . .

RUN cargo build --release

# Runtime
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    ca-certificates \
    openssl \
    curl \
    xxd \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user and group
RUN groupadd -g 1001 hyperscalers && useradd -m -u 1001 -g 1001 hyperscalers

USER 1001:1001
WORKDIR /home/hyperscalers

# Copy binaries from builder
COPY --from=builder --chown=1001:1001 /usr/src/app/target/release/hyperscale-validator /usr/local/bin/
COPY --from=builder --chown=1001:1001 /usr/src/app/target/release/hyperscale-keygen /usr/local/bin/
COPY --from=builder --chown=1001:1001 /usr/src/app/target/release/hyperscale-spammer /usr/local/bin/

# Copy launch script
COPY --chown=1001:1001 scripts/launch-cluster.sh /usr/local/bin/launch-cluster.sh
RUN chmod +x /usr/local/bin/launch-cluster.sh

# Environment variables
ENV VALIDATOR_BIN=/usr/local/bin/hyperscale-validator
ENV KEYGEN_BIN=/usr/local/bin/hyperscale-keygen
ENV SPAMMER_BIN=/usr/local/bin/hyperscale-spammer
ENV SKIP_BUILD=true
ENV NODE_HOSTNAME=localhost

# Expose ports
EXPOSE 9000-9500 8080-8099

ENTRYPOINT ["/usr/local/bin/launch-cluster.sh", "--clean", "--shards", "1", "--validators-per-shard", "7"]
