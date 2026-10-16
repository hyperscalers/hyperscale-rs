# syntax=docker/dockerfile:1
#
# The iroh NAT testbeds: the path probe, the backend host of the seating
# run, a relay, and the tools that build one network namespace per host.
# Built from the workspace root by scripts/iroh-nat-testbed.sh and
# scripts/iroh-seating.sh.

FROM rust:latest AS builder

WORKDIR /usr/src/app

RUN apt-get update && apt-get install -y \
    clang \
    lld \
    pkg-config \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

COPY . .

# Overrides rust-toolchain.toml, which pins nightly for fmt and clippy.
ENV RUSTUP_TOOLCHAIN=stable

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/src/app/target \
    cargo build --release --package hyperscale-network-iroh --features test-utils \
        --example probe --example seat && \
    cargo install --locked --root /out iroh-relay@1.3.0 --features server && \
    cp target/release/examples/probe target/release/examples/seat /out/bin/

FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    ca-certificates \
    iproute2 \
    jq \
    nftables \
    openssl \
    procps \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/bin/probe /out/bin/seat /out/bin/iroh-relay /usr/local/bin/
COPY scripts/iroh-nat-testbed/netns.sh scripts/iroh-nat-testbed/testbed.sh \
    scripts/iroh-nat-testbed/seating.sh scripts/iroh-nat-testbed/seating-summary.jq \
    /usr/local/bin/
RUN chmod +x /usr/local/bin/testbed.sh /usr/local/bin/seating.sh

ENTRYPOINT ["/usr/local/bin/testbed.sh"]
