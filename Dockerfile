# Build stage
FROM rust:1-bookworm AS builder

# clang + kernel UAPI headers are needed to compile the eBPF program
# (src/bpf/xdp.c) when building with the `xdp` feature.
RUN apt-get update \
    && apt-get install -y --no-install-recommends clang llvm libc6-dev linux-libc-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the full source (Cargo.toml, Cargo.lock, src/, build.rs, challenge.html).
COPY . .

# Optional cargo features. Pass `--build-arg FEATURES=xdp` to enable
# eBPF/XDP Layer-4 blocking (Linux only). build.rs compiles src/bpf/xdp.c with clang.
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
