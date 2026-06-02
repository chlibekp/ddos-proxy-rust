# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Rust reverse proxy with a WAF challenge layer for DDoS protection. It is a faithful port of the Go implementation kept under `old/` — when behaviour is ambiguous, `old/` is the reference of record. Same env-var config, same request lifecycle.

## Commands

```bash
cargo build --release                  # binary at target/release/ddos-proxy
cargo build --release --features xdp   # Linux only: compile in eBPF/XDP L4 blocking
cargo check                            # fast type-check
cargo run --release                    # needs PROXY_BACKEND_URL set; challenge.html in CWD

# Run against a backend:
PROXY_BACKEND_URL=http://127.0.0.1:8081 PORT=8080 cargo run --release
```

`PROXY_BACKEND_URL` is the only required env var (full list in `README.md`). The binary reads `challenge.html` from the working directory at startup. Docker: `docker build -t ddos-proxy .` (add `--build-arg FEATURES=xdp` for L4 blocking).

## Architecture

Request flow: `hyper server (main.rs) → route() → WAF Manager (waf) → Proxy (proxy.rs) → backend`. `/metrics` bypasses the WAF.

- **src/main.rs** — startup, config load, rustls provider install, JSON logging (`tracing`), the per-connection accept loop (`hyper_util auto::Builder` with upgrades), the 1s rate-reset ticker, `/metrics` routing, signal shutdown. Calls `tls::serve_tls` when `enable_ssl`, else `serve_plain`.
- **src/config.rs** — env parsing. Defaults and the Go-style duration parser (`5m`/`300s`, integer-seconds fallback) must match Go exactly.
- **src/limiter.rs** — `RateLimiter` (global atomic req/conn/whitelist counters, reset each second) and `IPLimiter` (1 req/s per IP, protects `/metrics`).
- **src/waf/** — the core. `Manager::handle` reproduces the Go middleware branch-for-branch: websocket bypass → whitelist UA → blocked fast-path → verified fast-path → mitigation eval → challenge/block → proxy. `ClientState` (`client.rs`) keeps lock-free atomic fast-path fields (`blocked_flag`, `verified_flag`, `verified_until`, `last_seen`) in sync with a `Mutex<Inner>`. Per-client state lives in a `DashMap` keyed `IP|Host`. PoW = SHA-256 over `salt+nonce` with `pow_difficulty` leading zero hex chars; verify at `POST /challenge/verify` rejects sub-2s solutions. Turnstile via reqwest. Challenge HTML rendered with **minijinja** from `challenge.html` (Go template directives converted to Jinja).
  - **Important invariant**: never hold a `std::sync::MutexGuard` across an `.await` — the `handle` future must stay `Send`. Compute a decision inside the locked scope, drop the guard, then await.
- **src/proxy.rs** — reverse proxy over a pooled `hyper_util` client with `hyper-rustls` (http+https backends). Header rewrite (preserve `Host`, append `X-Forwarded-For`, set `X-Forwarded-Host/Proto`, strip hop-by-hop, drop `Accept-Encoding` for HTML), `Server`→`ddos-proxy`, `Via`, `X-Ddos-Proxy-Cache` (HIT/MISS/DYNAMIC), redirect `Location` rewrite, and `<head>/<body>` JS injection (gzip-aware) using the byte-identical `JS_SNIPPET`. WebSocket upgrades are tunneled via a manual HTTP/1 handshake + `copy_bidirectional`.
- **src/cache.rs** — optional disk HTTP cache (`/tmp/ddos-mitigator-cache`), honours `Cache-Control: max-age`/`s-maxage`; stores raw upstream responses pre-modify, like the Go `httpcache` layer.
- **src/tls.rs** — on-demand ACME via **instant-acme** + **rcgen**. `OnDemandResolver` (rustls `ResolvesServerCert`) serves cached certs and triggers background issuance per SNI (with host-policy backend probe, disk cache under `certs/`, 24h renew-before, retry backoff). HTTP-01 served by the redirect server on `http_port`. Supports staging, custom directory, and EAB.
- **src/xdp.rs** + **build.rs** — `Blocker` trait. On Linux + `xdp` feature, `build.rs` compiles `src/bpf/xdp.c` (BTF maps, clang) to `$OUT_DIR/xdp.o`; `XdpBlocker` loads it via `aya` and attaches to the interface; elsewhere a no-op stub. `block_ip` writes IP→1 into the `blocklist` map using the Go key encoding. XDP init failure is non-fatal (logged, proxy continues without L4).
- **src/metrics.rs** — Prometheus collectors in a dedicated registry; `gather()` encodes text for `/metrics`.

## Conventions / gotchas

- The eBPF program lives at `src/bpf/xdp.c`; `build.rs` compiles it with clang at build time (feature `xdp`). Edit the C there — no checked-in `.o`. Maps must stay in BTF `.maps` style (legacy `bpf_map_def` won't load in aya).
- Body types unify on `body::BoxedBody`; use `body::empty()` / `body::full()`.
- Keep parity edits anchored to `old/` — diff the Go source when changing WAF/proxy logic.
- Known intentional deviations (documented in README): `close` block action returns an empty `403 Connection: close` instead of a raw socket close; the first TLS handshake for a new host fails while the cert issues in the background.
