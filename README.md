# DDoS Protection Proxy (Rust)

A high-performance Rust reverse proxy designed to protect backend services from DDoS attacks. It features global rate limiting, connection limiting, Cloudflare Turnstile, and a native Proof-of-Work (PoW) captcha to mitigate automated attacks.

This is a Rust implementation of a DDoS protection proxy.

## Features

- **Global Rate Limiting**: Triggers mitigation mode when request rate exceeds a threshold.
- **Connection Limiting**: Triggers mitigation mode when new connection rate exceeds a threshold.
- **Invisible Proof-of-Work (PoW)**: A native fallback challenge that forces malicious bots to expend CPU cycles without requiring user interaction.
- **Cloudflare Turnstile**: Optional CAPTCHA widget that can be enabled by supplying API keys.
- **IP Verification**: Validated IPs bypass challenges for a configurable duration.
- **Sticky Mitigation**: Mitigation mode stays active for a set duration after the attack subsides.
- **Always-On Mode**: Option to permanently enable the challenge for all requests.
- **Aggressive Blocking**: IPs that fail to solve the challenge and continue sending requests are blocked (`403 Forbidden` or connection close).
- **Hardware-Accelerated Layer 4 Blocking**: Uses eBPF/XDP to natively drop packets from malicious IPs at the NIC level. The same eBPF bytecode as the Go build is loaded at runtime via [`aya`](https://aya-rs.dev/) (Linux only, `xdp` feature).
- **User-Agent Whitelisting**: Allows trusted bots (e.g. Googlebot) to bypass challenges, subject to a separate global rate limit.
- **Disk Caching**: Built-in HTTP caching layer that respects standard `Cache-Control` headers.
- **Prometheus Metrics**: Exposes a `/metrics` endpoint, secured with a rate limit of 1 req/s per IP.

## Configuration

The proxy is configured via environment variables.

| Variable | Default | Description |
| :--- | :--- | :--- |
| `PROXY_BACKEND_URL` | **Required** | The full URL of the backend service (e.g. `http://localhost:3000`). |
| `PORT` | `8080` | The port the proxy listens on. |
| `PROXY_MAX_REQ` | `300` | Max global requests per second before triggering mitigation. |
| `PROXY_MAX_CONN` | `50` | Max global new connections per second before triggering mitigation. |
| `PROXY_MAX_REQ_PER_IP` | `0` (off) | Max requests per second from a single IP before that IP is served the WAF challenge. Unlike `PROXY_MAX_REQ`, exceeding this limit only challenges the offending IP and does not trigger a global mitigation window for all clients. Blocked and verified IPs are exempt. Set to `0` or omit to disable. |
| `PROXY_POW_DIFFICULTY` | `5` | Difficulty (number of leading zero hex chars) for the native Proof-of-Work challenge. |
| `PROXY_MITIGATION_TIME` | `5m` | Duration to keep mitigation active after thresholds are no longer exceeded (e.g. `5m`, `300s`). |
| `PROXY_VERIFY_TIME` | `10m` | Duration for which a user remains verified after solving a challenge. |
| `PROXY_ALWAYS_ON` | `false` | If `true`, the challenge is served for every request regardless of rate. |
| `PROXY_COOKIE_CHALLENGE` | `true` | If `true`, mitigation first serves a lightweight cookie challenge (set cookie + 307 redirect) and only escalates to the JS/PoW challenge once a flood is detected bypassing it. Set `false` to always serve the JS challenge. |
| `PROXY_USE_FORWARDED_FOR` | `false` | If `true`, the first `X-Forwarded-For` entry is used as the client IP. |
| `PROXY_CLOUDFLARE_SUPPORT` | `false` | If `true`, the `CF-Connecting-IP` header is used as the client IP. |
| `PROXY_TURNSTILE_PUBLIC_KEY` | `""` | Cloudflare Turnstile Site Key (optional; uses PoW if omitted). |
| `PROXY_TURNSTILE_PRIVATE_KEY` | `""` | Cloudflare Turnstile Secret Key (optional; uses PoW if omitted). |
| `PROXY_WHITELIST_UA` | `""` | Comma-separated list of User-Agent substrings to whitelist (e.g. `Googlebot,Bingbot`). |
| `PROXY_WHITELIST_RATE` | `10` | Global rate limit (req/s) for all whitelisted User-Agents combined. |
| `PROXY_MAX_FAILED_CHALLENGES` | `5` | Failed/unsolved challenges allowed before an IP is blocked. |
| `PROXY_PROMETHEUS_ENABLED` | `false` | If `true`, enables the `/metrics` endpoint. |
| `PROXY_BLOCK_ACTION` | `403` | Action when an IP is blocked (`403` or `close`). |
| `PROXY_AUTO_MITIGATION_ON_TIMEOUT` | `false` | If `true`, enables mitigation when multiple requests time out or take too long. |
| `PROXY_MAX_TIMEOUTS` | `5` | Number of timeouts/long requests allowed before triggering mitigation. |
| `PROXY_TIMEOUT_THRESHOLD` | `5s` | Duration threshold to consider a request "long" (e.g. `5s`, `10s`). |
| `PROXY_CACHE_ENABLED` | `false` | If `true` or `1`, enables disk-based HTTP caching. |
| `PROXY_ENABLE_SSL` | `false` | If `true`, enables automatic HTTPS using ACME/Let's Encrypt (set `PORT` to `443`). |
| `PROXY_ACME_STAGING` | `false` | If `true`, uses Let's Encrypt staging. Staging certs are not browser-trusted. |
| `PROXY_ACME_DIRECTORY_URL` | `""` | ACME directory URL override (e.g. ZeroSSL). Overrides `PROXY_ACME_STAGING` when set. |
| `PROXY_ACME_EMAIL` | `""` | ACME contact email used during account registration. |
| `PROXY_ACME_EAB_KEY_ID` | `""` | External Account Binding key ID (used with `PROXY_ACME_EAB_HMAC`). |
| `PROXY_ACME_EAB_HMAC` | `""` | External Account Binding HMAC key (base64 or base64url). |
| `PROXY_HTTP_PORT` | `80` | Port for the HTTP→HTTPS redirect server and ACME HTTP-01 challenges (SSL only). |
| `PROXY_XDP_INTERFACE` | `""` | Network interface to attach the XDP program to (e.g. `eth0`). Requires the `xdp` build feature plus `NET_ADMIN`, `SYS_ADMIN`, `BPF` capabilities. |
| `PROXY_MAX_IP_STATES` | `500000` | Cap on tracked client IP states (0 = unlimited) to bound memory under spoofed floods. |
| `PROXY_DISCORD_WEBHOOK_URL` | `""` | Discord incoming-webhook URL. When set, a rich embed is posted to this channel whenever mitigation mode is triggered by sustained traffic exceeding **500 req/min** (~8.3 req/s). Alerts are rate-limited to at most **one per minute** to prevent webhook spam. Leave empty to disable. |

## Usage

### Prerequisites

- **Rust 1.82+** (`cargo`).
- The `challenge.html` template must be present in the working directory.

### Running Locally

```bash
export PROXY_BACKEND_URL="http://localhost:3000"
cargo run --release
```

Access the proxy at `http://localhost:8080`.

### Building

```bash
cargo build --release          # binary at target/release/ddos-proxy
cargo build --release --features xdp   # Linux: include eBPF/XDP L4 blocking
```

### Docker

```bash
docker build -t ddos-proxy .
docker run -p 8080:8080 -e PROXY_BACKEND_URL=http://host.docker.internal:3000 ddos-proxy
```

To enable eBPF/XDP L4 blocking, build with the feature and run with the required capabilities and host networking (see `docker-compose.yml`):

```bash
docker build --build-arg FEATURES=xdp -t ddos-proxy .
```

## How it Works

1. **User-Agent Check**: Requests matching a whitelisted User-Agent bypass challenges, subject to a separate global rate limit. Exceeding it returns `429`.
2. **Normal Operation**: Other requests are proxied to `PROXY_BACKEND_URL`. The proxy tracks global request and connection rates.
3. **Mitigation Trigger**: If rates exceed `PROXY_MAX_REQ` or `PROXY_MAX_CONN`, the proxy enters **Mitigation Mode**.
4. **Disk Caching**: If enabled, GET requests may be served from disk; the `X-Ddos-Proxy-Cache` header indicates `HIT`/`MISS`/`DYNAMIC`.
5. **Cookie Challenge (tier 1)**: In Mitigation Mode, with `PROXY_COOKIE_CHALLENGE` enabled (the default), unverified requests first get a lightweight cookie challenge — a token cookie is set and the client is bounced back to the original URL with an `HTTP 307` redirect. Real browsers replay the request with the cookie and are let through; trivial floods that ignore `Set-Cookie`/redirects are dropped here cheaply.
6. **Escalation to JS Challenge (tier 2)**: If the flood keeps breaching the rate thresholds *while* the cookie challenge is active, the attack is solving the cookie challenge, so the proxy escalates every client to the heavier challenge below for `PROXY_MITIGATION_TIME`.
7. **Challenge**: When escalated (or with `PROXY_COOKIE_CHALLENGE=false`), unverified requests receive a lightweight HTML page (`HTTP 418`) running Turnstile (if keys set) or an invisible Proof-of-Work solver.
8. **Verification**: The browser submits the solution to `POST /challenge/verify`. On success the IP is marked **verified** for `PROXY_VERIFY_TIME` and redirected to the original URL. PoW solutions submitted in under 2 seconds are rejected.
9. **Bypass**: Verified IPs are proxied directly to the backend.
10. **Blocking**: IPs that receive challenges but keep sending unsolved requests (more than `PROXY_MAX_FAILED_CHALLENGES`) are blocked. With `PROXY_XDP_INTERFACE` configured (and the `xdp` feature), packets are additionally dropped at Layer 4.
11. **Recovery**: Mitigation Mode turns off after `PROXY_MITIGATION_TIME` without rate violations (unless `PROXY_ALWAYS_ON`).

## Notes on parity with the Go version

The Rust port reproduces the Go behaviour and configuration. A few platform-level details differ by necessity:

- **Connection close**: where Go hijacks and closes the TCP socket (block action `close`, and L4 escalation), the Rust port returns an empty `403` with `Connection: close` — hyper's nearest equivalent.
- **On-demand TLS**: rustls' certificate resolver is synchronous, so the first TLS handshake for a brand-new host triggers background issuance and fails; the client's retry succeeds once the cert is ready (Go blocks the first handshake instead). Issued certs are cached on disk under `certs/`.
- **eBPF/XDP**: the same C program (`src/bpf/xdp.c`, logic identical to the Go build) is compiled with clang by `build.rs` and loaded via `aya`. Gated behind the `xdp` cargo feature, Linux-only. A failed XDP attach is logged but **non-fatal** (the Go version exits) so the proxy keeps serving.

## eBPF/XDP Requirements (Docker)

When using `PROXY_XDP_INTERFACE`, the container requires:

1. **Host Network Mode**: `network_mode: "host"`.
2. **Capabilities**: `NET_ADMIN`, `SYS_ADMIN`, `BPF`.
3. The image built with `--build-arg FEATURES=xdp`.

## Discord DDoS Alerts

When `PROXY_DISCORD_WEBHOOK_URL` is set the proxy posts a rich embed to your Discord channel every time it detects a sustained attack:

```
PROXY_DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/<id>/<token>
```

**What triggers an alert**

- Mitigation mode is activated (global req/s or conn/s threshold breached), **and**
- The current rate exceeds **500 requests per minute** (~8.3 req/s).

Short traffic bursts below this threshold will not generate a notification, preventing alert fatigue from normal load spikes.

**Alert content (embed fields)**

| Field | Description |
| :--- | :--- |
| 📈 Current req/s | Observed rate at the moment mitigation triggered |
| 🔺 Peak req/s (session) | Highest req/s seen since the proxy started |
| ⚙️ Configured limit | Value of `PROXY_MAX_REQ` |
| 🌐 Tracked IPs | Number of client IP states currently tracked |
| 💥 5xx Responses | Cumulative backend 5xx errors since startup |

**Rate limiting**: at most one Discord alert is sent per 60-second window, regardless of how frequently mitigation fires during an attack.

**How to get a webhook URL**: in your Discord server go to *Channel Settings → Integrations → Webhooks → New Webhook*, copy the URL, and set it as `PROXY_DISCORD_WEBHOOK_URL`.

## Security Notes

- Keep Turnstile and EAB keys secret; do not commit them.
- The proxy preserves the original `Host` header from the client; ensure your backend handles it correctly.
