# DDoS Protection Proxy

A high-performance Go reverse proxy designed to protect backend services from DDoS attacks. It features global rate limiting, connection limiting, Cloudflare Turnstile, and a native Proof-of-Work (PoW) captcha to mitigate automated attacks.

## Features

- **Global Rate Limiting**: Triggers mitigation mode when request rate exceeds a threshold.
- **Connection Limiting**: Triggers mitigation mode when new connection rate exceeds a threshold.
- **Invisible Proof-of-Work (PoW)**: A native fallback challenge that forces malicious bots to expend CPU cycles without requiring user interaction.
- **Cloudflare Turnstile**: Optional CAPTCHA widget that can be enabled by supplying API keys.
- **IP Verification**: Validated IPs bypass challenges for a configurable duration.
- **Sticky Mitigation**: Mitigation mode stays active for a set duration after the attack subsides.
- **Always-On Mode**: Option to permanently enable the challenge for all requests.
- **Aggressive Blocking**: IPs that fail to solve the challenge and continue sending requests are blocked. The action is configurable (403 Forbidden or Close Connection).
- **Hardware-Accelerated Layer 4 Blocking**: Uses eBPF/XDP to natively drop packets from malicious IPs directly at the NIC level, drastically reducing CPU overhead during intense volumetric attacks.
- **User-Agent Whitelisting**: Allows trusted bots (e.g., Googlebot) to bypass challenges, subject to a separate global rate limit.
- **Disk Caching**: Built-in HTTP caching layer that respects standard `Cache-Control` headers, reducing load on the backend.
- **Prometheus Metrics**: Exposes a `/metrics` endpoint for monitoring, secured with a rate limit of 1 req/s per IP.

## Configuration

The proxy is configured via environment variables.

| Variable | Default | Description |
| :--- | :--- | :--- |
| `PROXY_BACKEND_URL` | **Required** | The full URL of the backend service (e.g., `http://localhost:3000`). |
| `PORT` | `8080` | The port the proxy listens on. |
| `PROXY_MAX_REQ` | `300` | Max global requests per second before triggering mitigation. |
| `PROXY_MAX_CONN` | `50` | Max global new connections per second before triggering mitigation. |
| `PROXY_POW_DIFFICULTY` | `5` | The difficulty level (number of leading zeros) for the native Proof-of-Work challenge. Higher values require more CPU power from the client. |
| `PROXY_MITIGATION_TIME` | `5m` | Duration to keep mitigation active after thresholds are no longer exceeded (e.g., `5m`, `300s`). |
| `PROXY_VERIFY_TIME` | `5m` | Duration for which a user remains verified after solving a CAPTCHA. |
| `PROXY_ALWAYS_ON` | `false` | If `true`, the challenge is served for every request regardless of rate. |
| `PROXY_CLOUDFLARE_SUPPORT` | `false` | If `true`, the `CF-Connecting-IP` header is used as the client IP. |
| `PROXY_TURNSTILE_PUBLIC_KEY` | `""` | Cloudflare Turnstile Site Key (Optional, uses PoW if omitted). |
| `PROXY_TURNSTILE_PRIVATE_KEY` | `""` | Cloudflare Turnstile Secret Key (Optional, uses PoW if omitted). |
| `PROXY_WHITELIST_UA` | `""` | Comma-separated list of User-Agent substrings to whitelist (e.g., `Googlebot,Bingbot`). |
| `PROXY_WHITELIST_RATE` | `10` | Global rate limit (requests/sec) for all whitelisted User-Agents combined. |
| `PROXY_PROMETHEUS_ENABLED` | `false` | If `true`, enables the `/metrics` endpoint. |
| `PROXY_BLOCK_ACTION` | `403` | Action to take when an IP is blocked (`403` or `close`). |
| `PROXY_AUTO_MITIGATION_ON_TIMEOUT` | `false` | If `true`, enables mitigation mode when multiple requests timeout or take too long. |
| `PROXY_MAX_TIMEOUTS` | `5` | Number of timeouts/long requests allowed before triggering mitigation mode. |
| `PROXY_TIMEOUT_THRESHOLD` | `5s` | Duration threshold to consider a request as "long" (e.g., `5s`, `10s`). |
| `PROXY_CACHE_ENABLED` | `false` | If `true` or `1`, enables disk-based HTTP caching for responses with valid `Cache-Control` headers. |
| `PROXY_ENABLE_SSL` | `false` | If `true`, enables automatic HTTPS using Let's Encrypt (requires `PORT` to be set to 443). |
| `PROXY_ACME_STAGING` | `false` | If `true`, uses Let's Encrypt staging instead of production for certificate issuance. Staging certificates are not trusted by browsers. |
| `PROXY_ACME_DIRECTORY_URL` | `""` | Optional ACME directory URL override for alternate providers such as ZeroSSL. Overrides `PROXY_ACME_STAGING` when set. |
| `PROXY_ACME_EMAIL` | `""` | Optional ACME contact email used during account registration. Recommended for providers that send expiry or account notices. |
| `PROXY_ACME_EAB_KEY_ID` | `""` | Optional External Account Binding key ID for ACME providers that require EAB. Must be used together with `PROXY_ACME_EAB_HMAC`. |
| `PROXY_ACME_EAB_HMAC` | `""` | Optional External Account Binding HMAC key for ACME providers that require EAB. Accepts base64 or base64url-encoded input. |
| `PROXY_HTTP_PORT` | `80` | The port for the HTTP-to-HTTPS redirect server and Let's Encrypt HTTP-01 challenges (only used when SSL is enabled). |
| `PROXY_XDP_INTERFACE` | `""` | Network interface to attach the XDP program to (e.g., `eth0`) for hardware-accelerated L4 blocking. Requires `NET_ADMIN`, `SYS_ADMIN`, and `BPF` capabilities in Docker. |

## Usage

### Prerequisites

1.  **Go 1.23+** installed.
2.  **(Optional) Cloudflare Turnstile Keys**: Obtain a Site Key and Secret Key from the [Cloudflare Dashboard](https://dash.cloudflare.com/?to=/:account/turnstile). If omitted, the proxy will default to using the native Proof-of-Work challenge.

### Running Locally

1.  Set the environment variables:

    ```bash
    export PROXY_BACKEND_URL="http://localhost:3000"
    
    # Optional tuning
    export PROXY_MAX_REQ=500
    export PROXY_MAX_CONN=100
    ```

2.  Run the proxy:

    ```bash
    go run main.go
    ```

3.  Access the proxy at `http://localhost:8080`.

### Alternate ACME Providers

To use another ACME-compatible CA instead of Let's Encrypt, set a custom directory URL. For providers that require External Account Binding, also set the EAB credentials:

```bash
export PROXY_ENABLE_SSL=true
export PROXY_ACME_DIRECTORY_URL="https://acme.zerossl.com/v2/DV90"
export PROXY_ACME_EMAIL="you@example.com"
export PROXY_ACME_EAB_KEY_ID="your-eab-kid"
export PROXY_ACME_EAB_HMAC="your-base64-or-base64url-hmac"
```

### Building for Production

Build the binary:

```bash
go build -o ddos-proxy main.go
```

Run the binary:

```bash
./ddos-proxy
```

## How it Works

1.  **User-Agent Check**: Requests matching a whitelisted User-Agent (via `PROXY_WHITELIST_UA`) bypass challenges and are subject to a separate global rate limit (`PROXY_WHITELIST_RATE`). If they exceed this limit, they receive a 429 error.
2.  **Normal Operation**: Other requests are proxied to `PROXY_BACKEND_URL`. The proxy tracks global request and connection rates.
3.  **Mitigation Trigger**: If rates exceed `PROXY_MAX_REQ` or `PROXY_MAX_CONN`, the proxy enters **Mitigation Mode**.
4.  **Disk Caching**: If enabled (`PROXY_CACHE_ENABLED`), the proxy will attempt to serve GET requests from disk if a valid cached copy exists, minimizing backend load. The `X-Ddos-Mitigator-Cache` response header indicates status (`HIT`, `MISS`, `DYNAMIC`).
5.  **Challenge**: In Mitigation Mode, all new requests (without a valid verification) are served a lightweight HTML page. If Turnstile keys are provided, it renders a CAPTCHA widget. If not, it runs an invisible Proof-of-Work solver using the browser's crypto API.
6.  **Verification**:
    -   The user solves the CAPTCHA or the browser completes the PoW challenge.
    -   The browser submits the solution to `/challenge/verify`.
    -   The proxy verifies the token with Cloudflare or validates the PoW hash.
    -   If valid, the IP address is marked as **verified** for `PROXY_VERIFY_TIME`.
    -   The user is redirected to their original URL.
7.  **Bypass**: Subsequent requests from a verified IP bypass the rate limiter and are proxied directly to the backend.
8.  **Blocking**: If an IP receives a challenge but continues to send requests without solving it (more than 5 times), the IP is **blocked**, and its TCP connection is forcibly closed. If `PROXY_XDP_INTERFACE` is configured, the proxy will additionally drop packets from this IP at Layer 4 natively using eBPF/XDP.
9.  **Recovery**: Mitigation Mode automatically turns off after `PROXY_MITIGATION_TIME` passes without rate violations (unless `PROXY_ALWAYS_ON` is set).

## eBPF/XDP Requirements (Docker)

If you are running `ddos-proxy` in Docker and want to utilize hardware-accelerated Layer 4 blocking with `PROXY_XDP_INTERFACE`, your container requires special privileges. Ensure your `docker-compose.yml` or `docker run` command is configured with:

1. **Host Network Mode**: `network_mode: "host"` so XDP attaches to the host's NIC.
2. **Capabilities**: `NET_ADMIN`, `SYS_ADMIN`, and `BPF`.

Example `docker-compose.yml` snippet:

```yaml
services:
  ddos-proxy:
    build: .
    network_mode: "host"
    cap_add:
      - NET_ADMIN
      - SYS_ADMIN
      - BPF
    environment:
      - PROXY_XDP_INTERFACE=eth0
      - PROXY_BACKEND_URL=http://localhost:8081
```

## Security Notes

-   **Turnstile Keys**: Ensure your Turnstile keys are kept secret and not committed to public repositories.
-   **Reverse Proxy Headers**: The proxy preserves the original `Host` header from the client. Ensure your backend is configured to handle the incoming Host header correctly.
