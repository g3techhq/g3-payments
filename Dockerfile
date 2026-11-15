# g3-payments-server: Stripe Checkout and license keys for g3 apps without a
# server of their own. Build from a clean export of a pushed commit:
#   git archive --format=tar HEAD | docker build -t g3-payments-server -
FROM rust:1.95.0-trixie AS builder
WORKDIR /src
COPY . .
# The crate leaves Cargo.lock out, as libraries do; the server pins its own.
COPY ci/server.Cargo.lock Cargo.lock
RUN cargo build --release --locked --features standalone --bin g3-payments-server

FROM debian:trixie-slim
LABEL org.opencontainers.image.source="https://github.com/g3techhq/g3-payments" \
      org.opencontainers.image.description="g3-payments-server: Stripe Checkout and license keys for apps without a server" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/g3-payments-server /usr/local/bin/g3-payments-server
USER 65532:65532
ENV PORT=8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/g3-payments-server"]
