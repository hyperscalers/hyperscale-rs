# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM rust:latest AS builder

# import cross-compilation helpers
COPY --from=tonistiigi/xx:master / /

WORKDIR /usr/src/app
ARG TARGETPLATFORM
ARG HYPERSCALE_VERSION=localdev

# install dependencies
RUN apt-get update && apt-get install -y \
    clang \
    lld \
    pkg-config \
    protobuf-compiler \
    git \
    build-essential \
    && xx-apt-get install -y \
    gcc \
    g++ \
    libssl-dev \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . .

ENV PKG_CONFIG_ALLOW_CROSS=1

# build with xx-cargo to cross compile (github runners are linux/amd64, but we may want to build for arm64)
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/src/app/target \
    HYPERSCALE_VERSION=${HYPERSCALE_VERSION} xx-cargo build --release --target-dir ./target && \
    mkdir -p /out && \
    cp target/$(xx-cargo --print-target-triple)/release/hyperscale-validator /out/ && \
    cp target/$(xx-cargo --print-target-triple)/release/hyperscale-keygen /out/ && \
    cp target/$(xx-cargo --print-target-triple)/release/hyperscale-spammer /out/

FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    ca-certificates \
    openssl \
    curl \
    xxd \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# create a non-root user and group
RUN groupadd -g 1001 hyperscalers && useradd -m -u 1001 -g 1001 hyperscalers

USER 1001:1001
WORKDIR /home/hyperscalers

# copy binaries from the builder's specific output folder
COPY --from=builder --chown=1001:1001 /out/hyperscale-validator /usr/local/bin/
COPY --from=builder --chown=1001:1001 /out/hyperscale-keygen /usr/local/bin/
COPY --from=builder --chown=1001:1001 /out/hyperscale-spammer /usr/local/bin/

# copy launch script
COPY --chown=1001:1001 scripts/launch-cluster.sh /usr/local/bin/launch-cluster.sh
RUN chmod +x /usr/local/bin/launch-cluster.sh

# environment variables
ENV VALIDATOR_BIN=/usr/local/bin/hyperscale-validator
ENV KEYGEN_BIN=/usr/local/bin/hyperscale-keygen
ENV SPAMMER_BIN=/usr/local/bin/hyperscale-spammer
ENV SKIP_BUILD=true
ENV NODE_HOSTNAME=localhost

# expose ports used by hyperscale-node
EXPOSE 9000-9500 8080-8099

# NOTE: use --net=host for docker run! otherwise the nodes will be isolated from each other
ENTRYPOINT ["tail", "-f", "/dev/null"]
