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
- **IP Allow/Deny Lists**: CIDR-based trusted ranges that bypass the WAF (`PROXY_TRUSTED_IPS`) and ranges that are always blocked (`PROXY_DENY_IPS`).
- **User-Agent Denylist**: Block known-bad scanners and scrapers by UA substring (`PROXY_BLOCKED_UA`).
- **Challenge-Exempt Paths**: Path prefixes (webhooks, payment callbacks) that are proxied without ever being challenged (`PROXY_EXEMPT_PATHS`).
- **Request Hygiene Filters**: HTTP method allowlist (`PROXY_ALLOWED_METHODS`) and a declared body-size cap (`PROXY_MAX_BODY_SIZE`).
- **Backend Timeout**: Bounded time-to-first-byte for the backend hop (`PROXY_BACKEND_TIMEOUT`) so a hung origin returns `504` instead of pinning connections open.
- **Security Headers**: Optional injection of standard security headers, including HSTS on TLS (`PROXY_SECURITY_HEADERS`).
- **Access Logging**: Optional structured JSON access log for every request (`PROXY_ACCESS_LOG`).
- **Maintenance Mode**: Toggle a `503` maintenance page for all traffic from the admin dashboard or via `POST`/`DELETE /ddos-proxy/admin/maintenance`; `/metrics`, `/healthz`, the admin API, and trusted IPs stay reachable.
- **Request Hygiene & WAF Rules**: blocked path prefixes, a regex rule over path+query, Host allowlist, required User-Agent, URI-length cap — all matched against a normalized path so `..`/`//` tricks don't bypass them.
- **Honeypot Paths & Scanner Auto-Block**: instantly block clients touching trap paths, and block IPs that rack up backend 404s probing for exploitable files.
- **Concurrency Caps**: global in-flight request cap (`503`) and per-IP concurrency cap (`429`) against slow-POST/connection-exhaustion attacks.
- **Backend Resilience**: bounded retries for idempotent requests, a circuit breaker that fails fast while the backend is down, and serve-stale-from-cache on backend errors.
- **Adaptive PoW Difficulty**: automatically issue a harder proof-of-work challenge while a mitigation window is active.
- **Per-Path Rate Limits**: protect expensive endpoints (`/login`, search) with their own req/s budgets, challenged independently of global mitigation.
- **Site-wide Basic Auth**: one env var turns the proxy into an authenticated staging gate.
- **Response Polish**: optional gzip compression, CORS headers, custom header add/remove, `X-Request-Id` correlation, `X-Real-IP` to the backend.
- **Runtime Admin API**: manage IP deny/trust lists, force mitigation on/off, clear tracked states, purge the cache, and inspect redacted config — all without a restart.

### Admin API

All endpoints live under `/ddos-proxy/admin` and require `Authorization: Bearer $PROXY_ADMIN_SECRET` (the API is invisible — requests with a wrong/missing token are proxied to the origin). `GET /ddos-proxy/admin/` serves an interactive dashboard.

| Method & path | Action |
| :--- | :--- |
| `GET /status` | Mitigation/maintenance state, tracked-IP count, uptime, version |
| `GET /config` | Redacted view of the running configuration |
| `GET /states`, `GET /states/{ip\|host}` | List / fetch tracked client states |
| `DELETE /states` | Clear all tracked states (releases L4 blocks) |
| `POST /block`, `DELETE /block` | Manually block / unblock `{"ip":"…","host":"…"}` |
| `GET\|POST\|DELETE /denylist`, `/trustlist` | Runtime IP/CIDR lists, body `{"entry":"10.0.0.0/8"}` |
| `POST\|DELETE /mitigation` | Force the mitigation window on / off |
| `POST\|DELETE /maintenance` | Maintenance mode on / off |
| `DELETE /cache` | Purge the disk cache |

## Configuration

The proxy is configured via environment variables.

| Variable | Default | Description |
| :--- | :--- | :--- |
| `PROXY_BACKEND_URL` | **Required** | The full URL of the backend service (e.g. `http://localhost:3000`). |
| `PORT` | `8080` (or `443` when `PROXY_ENABLE_SSL=true`) | The port the proxy listens on. |
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
| `PROXY_ACME_SKIP_HOST_POLICY` | `false` | If `true`, skips the backend probe that validates a hostname before issuing a cert. Useful when the backend is not directly reachable from the proxy (e.g. nginx→proxy→nginx chains) or when the probe URL differs from the public hostname. When `false` (default), a non-200 response blocks issuance; a connection error is treated as a transient failure and allows issuance. |
| `PROXY_HTTP_PORT` | `80` | Port for the HTTP→HTTPS redirect server and ACME HTTP-01 challenges (SSL only). |
| `PROXY_XDP_INTERFACE` | `""` | Network interface to attach the XDP program to (e.g. `eth0`). Requires the `xdp` build feature plus `NET_ADMIN`, `SYS_ADMIN`, `BPF` capabilities. |
| `PROXY_XDP_ALERT_PPS` | `1000` | Dropped-packets-per-second threshold (measured at the XDP/L4 layer) above which a Discord **L4-flood** alert fires. `0` or less disables L4 alerting. Only active when both `PROXY_XDP_INTERFACE` and `PROXY_DISCORD_WEBHOOK_URL` are set. |
| `PROXY_MAX_IP_STATES` | `500000` | Cap on tracked client IP states (0 = unlimited) to bound memory under spoofed floods. |
| `PROXY_DISCORD_WEBHOOK_URL` | `""` | Discord incoming-webhook URL. When set, a rich embed is posted to this channel whenever mitigation mode is triggered by sustained traffic exceeding **500 req/min** (~8.3 req/s). Alerts are rate-limited to at most **one per minute** to prevent webhook spam. Leave empty to disable. |
| `PROXY_TRUSTED_IPS` | `""` | Comma-separated IPs/CIDRs (IPv4 + IPv6) that bypass the WAF entirely (e.g. `10.0.0.0/8,192.168.1.5,2001:db8::/32`). Use for monitoring probes and internal infrastructure. |
| `PROXY_DENY_IPS` | `""` | Comma-separated IPs/CIDRs that are always blocked (served `PROXY_BLOCK_ACTION`) before any other processing. |
| `PROXY_BLOCKED_UA` | `""` | Comma-separated User-Agent substrings to block outright with `403` (case-insensitive, e.g. `sqlmap,nikto,masscan`). Checked before the UA whitelist. |
| `PROXY_EXEMPT_PATHS` | `""` | Comma-separated path prefixes that are never served a challenge (e.g. `/api/webhooks,/.well-known/`). For machine-to-machine endpoints that can't run JS or keep cookies. Blocked/denied IPs are still blocked on these paths. |
| `PROXY_BACKEND_TIMEOUT` | `30s` | Max time to wait for the backend to start responding before returning `504 Gateway Timeout`. `0` disables the timeout. |
| `PROXY_MAX_BODY_SIZE` | `0` (off) | Maximum request body size in bytes, checked against the declared `Content-Length`. Oversized requests get `413 Payload Too Large`. |
| `PROXY_ALLOWED_METHODS` | `""` (all) | Comma-separated HTTP methods to accept (e.g. `GET,POST,PUT,DELETE,HEAD,OPTIONS`). Other methods get `405 Method Not Allowed`. |
| `PROXY_SECURITY_HEADERS` | `false` | If `true`, adds `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` (and `Strict-Transport-Security` on TLS) to proxied responses unless the backend already set them. |
| `PROXY_ACCESS_LOG` | `false` | If `true`, logs every request as a structured JSON line (`method`, `path`, `status`, `duration_ms`, `ip`). |
| `PROXY_BLOCKED_PATHS` | `""` | Comma-separated path prefixes blocked outright with `403` (e.g. `/.env,/.git,/wp-admin`). Matched against the **normalized** path, so `/a/../.env` is caught. |
| `PROXY_BLOCK_REGEX` | `""` | Regex matched against the raw path+query; matching requests get `403` (e.g. `(?i)union.{0,6}select`). |
| `PROXY_ALLOWED_HOSTS` | `""` (all) | Comma-separated hostnames the proxy serves (port ignored). Exact (`example.com`) or wildcard (`*.example.com`, subdomains only). Others get `403`. |
| `PROXY_REQUIRE_UA` | `false` | If `true`, requests without a `User-Agent` header get `403`. |
| `PROXY_MAX_URI_LEN` | `0` (off) | Maximum path+query length in bytes; longer requests get `414`. |
| `PROXY_HONEYPOT_PATHS` | `""` | Comma-separated path prefixes that instantly block any client touching them (no legitimate user requests these). |
| `PROXY_MAX_404_PER_IP` | `0` (off) | Backend 404s a single IP may accumulate in 60 s before being blocked as a scanner. |
| `PROXY_BASIC_AUTH` | `""` (off) | `user:password` enabling a site-wide HTTP Basic auth gate (staging protection). Constant-time compared. |
| `PROXY_MAX_CONCURRENT_PER_IP` | `0` (off) | Max concurrent in-flight requests per client IP; excess gets `429`. |
| `PROXY_MAX_INFLIGHT` | `0` (off) | Global cap on concurrent in-flight requests; excess gets `503`. Also enables the `ddos_proxy_inflight_requests` gauge. |
| `PROXY_BACKEND_RETRIES` | `0` | Times an idempotent (GET/HEAD) request is retried against the backend after a transport error (max 5). |
| `PROXY_CB_THRESHOLD` | `0` (off) | Consecutive backend transport failures that trip the circuit breaker (instant `503` instead of waiting on a dead backend). |
| `PROXY_CB_COOLDOWN` | `30s` | How long the circuit stays open after tripping. |
| `PROXY_SERVE_STALE` | `false` | If `true` (with `PROXY_CACHE_ENABLED`), an expired cached copy is served when the backend errors, times out, returns 5xx, or the circuit is open. Marked `X-Ddos-Proxy-Cache: STALE`. |
| `PROXY_REQUEST_ID` | `false` | If `true`, an `X-Request-Id` is generated (or a valid inbound one kept), forwarded to the backend and returned on the response. |
| `PROXY_ADD_HEADERS` | `""` | Custom response headers, `Name=Value;Name2=Value2`. Overwrite backend values. |
| `PROXY_REMOVE_HEADERS` | `""` | Comma-separated response headers to strip (e.g. `X-Powered-By`). |
| `PROXY_CORS_ORIGIN` | `""` (off) | Adds `Access-Control-Allow-Origin` (plus `-Methods`/`-Headers`) to responses unless the backend set them. |
| `PROXY_COMPRESSION` | `false` | If `true`, gzip-compresses buffered text/JSON/JS/SVG responses ≥ 1 KiB when the client accepts gzip and the backend didn't encode. |
| `PROXY_POW_DIFFICULTY_ATTACK` | `""` (off) | PoW difficulty issued **while a mitigation window is active** (adaptive hardening; verification accepts the difficulty each client was actually issued). |
| `PROXY_PATH_RATE_LIMITS` | `""` | Per-path-prefix global req/s limits, e.g. `/login=5,/api=100`. An over-limit prefix is served the JS/PoW challenge without opening a global mitigation window. |

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

### L4 / XDP Flood Alerts

The alerts above are driven by the **L7** layer (HTTP request rate). A purely **volumetric L4 flood** — UDP floods, malformed-TCP storms, or raw junk hammering ports 80/443 — is absorbed by the XDP program and never reaches the request counter, so it would otherwise be invisible. When the `xdp` feature is built **and** an interface is attached (`PROXY_XDP_INTERFACE`), the per-second XDP stats loop additionally watches the **dropped-packets-per-second** rate and fires a separate set of alerts.

**What triggers an L4 alert**

- XDP-dropped packets/sec rises above `PROXY_XDP_ALERT_PPS` (default `1000`). A flood-start embed fires (with a 60 s cooldown between successive starts), progress updates every 3 minutes, and an all-clear once the rate stays below threshold for 5 s.

**Attack classification** — the eBPF program counts *why* each packet was dropped, and the alert names the dominant category:

| Type | Meaning |
| :--- | :--- |
| UDP flood | High volume of UDP packets to 80/443 (the proxy serves no UDP) |
| Non-HTTP junk flood (:80) | TCP payloads to :80 that aren't a valid HTTP request line |
| Non-TLS junk flood (:443) | TCP payloads to :443 that aren't a TLS ClientHello |
| Malformed-TCP flood | Truncated / crafted TCP segments |
| Blocklisted-IP flood | Packets from IPs already on the XDP blocklist |

**Payload fingerprint** — for payload-bearing drops the eBPF program samples the first 16 bytes of each dropped packet, FNV-1a–hashes them into an LRU map, and counts occurrences. Floods almost always replay an identical payload, so the highest-count fingerprint *is* the attack signature. The alert renders the top three as hex + printable-ASCII with their hit counts, e.g.:

```
#1 ×84213
hex 5c 78 39 30 5c 78 30 30 5c 78 39 30 5c 78 30 30
txt \x90\x00\x90\x00
```

The fingerprint set is cleared at each all-clear so every attack window starts fresh. A header-only/volumetric flood (e.g. spoofed SYNs with no payload) records no fingerprint, which the alert states explicitly.

**Prometheus** — the per-reason drop breakdown is also exported as `ddos_proxy_xdp_drops_total{reason="…"}` alongside the existing `ddos_proxy_xdp_packets_total`.

## Security Notes

- Keep Turnstile and EAB keys secret; do not commit them.
- The proxy preserves the original `Host` header from the client; ensure your backend handles it correctly.
