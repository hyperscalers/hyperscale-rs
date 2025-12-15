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
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user and group
RUN groupadd -g 1001 hyperscalers && useradd -m -u 1001 -g 1001 hyperscalers

USER 1001:1001
WORKDIR /home/hyperscalers

# Copy binary from builder and chown it
COPY --from=builder --chown=1001:1001 /usr/src/app/target/release/hyperscale-sim /usr/local/bin/

ENTRYPOINT ["/usr/local/bin/hyperscale-sim"]
