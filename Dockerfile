# ACE Chain public full-node image with self-contained build.
#
# This Dockerfile compiles the ACE Chain node from source and packages it
# into a minimal runtime image. The bundled config runs as a non-validator
# full node by default. Users can build with:
#
#   docker build -t acechain/ace-node:fullnode .
#   docker run -p 18545:18545 -p 31333:31333 acechain/ace-node:fullnode
#
# Multi-stage build: compile stage runs in a full Rust environment,
# then only the binary is copied to the minimal runtime image.

# Compilation stage.
# Pin the builder to bookworm so its glibc/libstdc++ match the bookworm-slim
# runtime below. `rust:latest` floats to newer Debian (trixie → glibc 2.39),
# producing a binary that fails on bookworm-slim with "GLIBC_2.39 not found".
FROM rust:bookworm AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
      clang libclang-dev pkg-config cmake \
    && rm -rf /var/lib/apt/lists/*

COPY . .

# Build the ace-node binary with required features
RUN cargo build --release --bin ace-node --features devnet,stark

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /data /config

COPY --from=builder /app/target/release/ace-node /usr/local/bin/ace-node
COPY --from=builder /app/networks/testnet/genesis.json /config/genesis.json
COPY --from=builder /app/networks/testnet/node.example.json /config/node.json
RUN chmod +x /usr/local/bin/ace-node

VOLUME ["/data"]

EXPOSE 18545 31333

ENTRYPOINT ["ace-node"]
CMD ["--config", "/config/node.json", "--log-level", "info"]
