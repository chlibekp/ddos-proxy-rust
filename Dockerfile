# Build stage
FROM rust:1-bookworm AS builder

WORKDIR /app

# Copy the full source (includes Cargo.toml, Cargo.lock, src/, challenge.html,
# and the precompiled eBPF object used by the optional `xdp` feature).
COPY . .

# Optional cargo features. Pass `--build-arg FEATURES=xdp` to enable
# eBPF/XDP Layer-4 blocking (Linux only).
ARG FEATURES=""
RUN if [ -n "$FEATURES" ]; then \
        cargo build --release --features "$FEATURES"; \
    else \
        cargo build --release; \
    fi

# Runtime stage
FROM debian:bookworm-slim

# ca-certificates for outbound HTTPS (Turnstile verification, ACME, https backends).
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/ddos-proxy ./ddos-proxy
COPY challenge.html ./challenge.html

EXPOSE 8080

CMD ["./ddos-proxy"]
