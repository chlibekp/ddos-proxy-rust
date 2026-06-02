# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
make build         # go build -o proxy cmd/ddos-proxy/main.go
make run           # run with PROXY_BACKEND_URL=https://example.com PORT=8080
make test          # go test -v ./...
make docker-build  # docker build -t ddos-proxy .
make docker-run    # docker run with PROXY_BACKEND_URL set

go test -v ./internal/waf/        # single package
go test -run TestName ./internal/limiter/   # single test
go generate ./...  # regenerate eBPF bytecode (bpf_bpfel.go/.o etc) — needs clang/llvm/libbpf-dev/linux-headers (Linux only)
```

`PROXY_BACKEND_URL` is the only required env var. Full list of `PROXY_*` vars in README.md. Entry point: `cmd/ddos-proxy/main.go`. Binary expects `challenge.html` in working dir.

## Architecture

Reverse proxy that fronts a single backend and gates traffic through a WAF challenge layer. Request flow:

```
HTTP server (main.go) → WAF Middleware (internal/waf) → ReverseProxy (internal/proxy) → backend
```

**Two-tier rate limiting.** `internal/limiter`:
- `RateLimiter` (limiter.go): global atomic counters (req/conn/whitelist), reset every 1s by a ticker in main.go. Connection count incremented via `http.Server.ConnState`. Drives mitigation trigger.
- `IPLimiter` (ip_limiter.go): per-IP 1 req/s, used only to protect the `/metrics` endpoint.

**WAF state machine.** `internal/waf/waf.go` is the core. `Manager.Middleware` wraps the proxy and decides per request:
1. WebSocket upgrades bypass WAF entirely.
2. Whitelisted User-Agents bypass challenge but share a global `WhitelistRateLimit`.
3. Per-client state keyed by `IP|Host` in a `sync.Map` of `*ClientState` (client.go). States: verified → bypass; blocked → 403/close (+ L4 block); else evaluate mitigation.
4. **Mitigation mode** turns on when global req/conn rate exceeds thresholds, or `AlwaysOn`, or (optionally) too many slow/timed-out backend responses (`AutoMitigationOnTimeout`). `mitigationUntil` is a sticky atomic unix timestamp extended on each violation.
5. In mitigation, unverified clients get `challenge.html` (HTTP 418). Repeated unsolved challenges past `MaxFailedChallenges` → blocked.

**Challenge / verify.** Either Cloudflare Turnstile (if keys set) or native SHA-256 Proof-of-Work (default). PoW: server issues random `powSalt`; client finds nonce so `sha256(salt+nonce)` has `PoWDifficulty` leading zero hex chars. Verified at `POST /challenge/verify`; rejects solutions submitted <2s (bot guard). Success marks IP verified for `VerifyTime`. A background ticker (`cleanup`, every 1m) expires verification/blocks and prunes idle state.

**L4 blocking (eBPF/XDP).** `internal/xdp` drops packets at the NIC for repeat offenders. Only engaged when neither `CloudflareSupport` nor `UseForwardedFor` is set (otherwise RemoteAddr isn't the real client). `Blocker` is an interface; `xdpBlocker` is nil when `PROXY_XDP_INTERFACE` unset, so all `blockL4`/`unblockL4` calls no-op. `bpf_bpfel*.go`/`bpf_bpfeb*.go`/`*.o` are generated from `xdp.c` via `go generate` — edit `xdp.c`, not the generated files. Requires `NET_ADMIN`/`SYS_ADMIN`/`BPF` caps and host network mode (see docker-compose.yml).

**Reverse proxy layer.** `internal/proxy/reverse_proxy.go` wraps `httputil.NewSingleHostReverseProxy` with custom transports:
- `WebSocketAwareTransport` routes upgrades around the cache.
- Optional disk cache (`httpcache` + `diskcache` at `/tmp/ddos-mitigator-cache`) when `CacheEnabled`; `NormalizingTransport` merges/repairs malformed `Cache-Control` headers the cache lib mishandles.
- `Director` preserves the original `Host` header and sets `X-Forwarded-Host`/`X-Forwarded-Proto`.
- `ModifyResponse` rewrites `Server`→`ddos-proxy`, sets `X-Ddos-Proxy-Cache` (HIT/MISS/DYNAMIC), rewrites backend-host redirects to the client host, and injects a `<script>` into HTML that reloads the page when it sees an `X-Mitigation: challenge` response header (so SPA fetches surface the challenge).

**Client IP resolution** (`getClientIP`): `CF-Connecting-IP` if `CloudflareSupport`, else first `X-Forwarded-For` if `UseForwardedFor`, else `RemoteAddr`. This choice gates whether L4 blocking is safe to use.

**TLS/ACME** (main.go): optional Let's Encrypt/ACME via `autocert` when `EnableSSL`. `HostPolicy` only issues certs for hosts the backend answers 200 on. `certRequestCoordinator` dedupes concurrent cert requests and applies rate-limit backoff; `hostCertCache` caches leaf certs until 24h before expiry. Supports staging, custom directory URLs (ZeroSSL), and EAB. An HTTP server on `HTTPPort` (80) handles HTTP-01 challenges and redirects to HTTPS.

**Metrics.** `internal/metrics` defines Prometheus collectors (allowed/dropped/challenged requests, XDP packets). `/metrics` enabled by `PrometheusEnabled`, rate-limited 1 req/s/IP. Metric increments are guarded behind `cfg.PrometheusEnabled` checks throughout.
