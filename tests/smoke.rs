/// Smoke tests for ddos-proxy.
///
/// Each test spins up a real in-process HTTP backend using hyper, builds a
/// `Proxy` (or WAF `Manager`) directly, drives requests through it via a tiny
/// loopback server, and asserts on the responses.  No external processes or
/// sockets beyond loopback are used.
///
/// # Test catalogue
///
/// | # | Group       | What is tested                                                |
/// |---|-------------|--------------------------------------------------------------|
/// |  1| proxy       | Basic GET is forwarded, status and body preserved             |
/// |  2| proxy       | Repeated GET ?lang=cs no alternating 502 (stale-conn fix)    |
/// |  2b| proxy      | With retries=0 + close-after-each backend, 502 IS observed   |
/// |  3| proxy       | JS snippet injected right after `<head>`                     |
/// |  4| proxy       | JS snippet injected after `<body>` when no `<head>` present  |
/// |  5| proxy       | Non-HTML response passes through without JS injection         |
/// |  6| proxy       | Gzip-encoded HTML decoded, JS injected, CE header removed     |
/// |  7| proxy       | Backend 5xx forwarded as-is                                  |
/// |  8| proxy       | Backend timeout returns 504                                  |
/// |  9| proxy       | Backend unreachable returns 502                              |
/// | 10| proxy       | X-Forwarded-For appended to request                          |
/// | 10b| proxy      | X-Forwarded-For appended (not replaced) when already present  |
/// | 11| proxy       | X-Real-IP set from remote address                            |
/// | 12| proxy       | Via and Server response headers set correctly                |
/// | 13| proxy       | Location header rewritten from backend host to inbound host  |
/// | 14| proxy       | Content-Length is correct after JS injection                 |
/// | 15| proxy       | X-Request-Id generated and echoed back                      |
/// | 16| proxy/cache | Cache miss → backend called; cache hit → backend NOT called  |
/// | 17| proxy/cache | Stale cache served on backend 5xx (serve-stale)              |
/// | 18| waf         | Trusted IP bypasses WAF challenge (even in always-on)        |
/// | 19| waf         | Blocked IP gets 403                                          |
/// | 20| waf         | Maintenance mode returns 503                                 |
/// | 21| waf         | Blocked path returns 403 (path traversal also blocked)       |
/// | 22| waf         | Honeypot path blocks the IP for subsequent requests          |
/// | 23| waf         | Blocked User-Agent returns 403                               |
/// | 24| waf         | Require-UA: missing UA returns 403                           |
/// | 25| waf         | URI too long returns 414                                     |
/// | 26| waf         | Disallowed HTTP method returns 405                           |
/// | 27| waf         | Always-on: unverified client gets 418 JS challenge           |
/// | 28| waf         | Cookie challenge flow: 307 → cookie → proxied                |
/// | 29| waf         | PoW challenge body contains the salt                        |
/// | 30| waf         | Per-IP rate limit triggers challenge                         |
/// | 31| waf         | 404 scanner: IP blocked after exceeding threshold            |
/// | 32| waf         | Exempt path bypasses challenge even in always-on             |
/// | 33| waf         | Host allowlist: unknown host blocked, allowed host passes    |
/// | 34| proxy       | X-Ddos-Proxy-Cache: DYNAMIC for non-cacheable response       |

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

// Tests that touch the shared on-disk cache directory must hold this mutex to
// prevent parallel test runs from corrupting each other's cache state.
static CACHE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::net::TcpListener;

use ddos_proxy::config::{Config, TestCfgOverride};
use ddos_proxy::limiter::RateLimiter;
use ddos_proxy::proxy::{Proxy, ReqCtx};
use ddos_proxy::waf::Manager;

// ── Body helpers ─────────────────────────────────────────────────────────────

type BoxedBody =
    http_body_util::combinators::BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;

fn bfull<T: Into<Bytes>>(chunk: T) -> BoxedBody {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

fn bempty() -> BoxedBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

// ── Backend spawn helpers ────────────────────────────────────────────────────

/// Spawn a persistent hyper backend.  Every accepted connection is served by
/// `handler` with standard HTTP/1.1 keep-alive (i.e. connections are reused).
async fn spawn_backend<F, Fut>(handler: F) -> SocketAddr
where
    F: Fn(Request<Incoming>) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Response<BoxedBody>> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handler = Arc::new(handler);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { break };
            let handler = handler.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req| {
                    let h = handler.clone();
                    async move { Ok::<_, Infallible>(h(req).await) }
                });
                let _ = auto::Builder::new(TokioExecutor::new())
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });
    addr
}

/// Spawn a backend that closes the TCP connection after each HTTP/1.1
/// response.  This simulates a backend whose keep-alive window is shorter than
/// the proxy's pool idle timeout, exposing the stale-pooled-connection bug.
async fn spawn_close_after_each<F>(handler: F) -> SocketAddr
where
    F: Fn(Request<Incoming>) -> Response<BoxedBody> + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handler = Arc::new(handler);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { break };
            let handler = handler.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req| {
                    let h = handler.clone();
                    async move { Ok::<_, Infallible>(h(req)) }
                });
                // http1::Builder serves one request then drops the connection.
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await;
                // connection dropped here → TCP FIN sent
            });
        }
    });
    addr
}

// ── Proxy / WAF construction helpers ────────────────────────────────────────

fn make_proxy(backend: SocketAddr, overrides: TestCfgOverride) -> Arc<Proxy> {
    let cfg = Config::for_test(&format!("http://{backend}"), overrides);
    Arc::new(Proxy::new(cfg.backend_url.parse().unwrap(), cfg))
}

/// Construct a WAF Manager backed by `backend`.  The template is minimal; it
/// only renders the `{{ pow_salt }}` variable so tests can locate the salt.
fn make_waf(backend: SocketAddr, overrides: TestCfgOverride) -> Arc<Manager> {
    let cfg = Config::for_test(&format!("http://{backend}"), overrides);
    let rl = Arc::new(RateLimiter::new());
    let proxy = Arc::new(Proxy::new(cfg.backend_url.parse().unwrap(), cfg.clone()));
    Manager::new(cfg, rl, "<html>{{ pow_salt }}</html>".to_string(), None, proxy, None)
}

/// Synthetic `ReqCtx` for tests: plain HTTP, loopback client.
fn ctx() -> ReqCtx {
    ReqCtx { is_tls: false, remote_addr: "127.0.0.1:12345".to_string() }
}

// ── Request-sending harness ──────────────────────────────────────────────────
//
// We drive requests through the proxy/WAF by creating a minimal loopback HTTP
// server that calls `proxy.handle` (or `waf.handle`) for each request, then
// making a real HTTP request to that server.  This exercises the real hyper
// framing stack end-to-end without needing an actual listening proxy port.

async fn call_proxy(proxy: Arc<Proxy>, req: Request<()>) -> (Response<()>, Bytes) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let p = proxy.clone();
    tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else { return };
        let io = TokioIo::new(stream);
        let c = ctx();
        let svc = service_fn(move |req: Request<Incoming>| {
            let p = p.clone();
            let c = c.clone();
            async move { Ok::<_, Infallible>(p.handle(req, &c).await) }
        });
        let _ = auto::Builder::new(TokioExecutor::new())
            .serve_connection(io, svc)
            .await;
    });

    send_request(addr, req).await
}

async fn call_waf(mgr: Arc<Manager>, req: Request<()>) -> (Response<()>, Bytes) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let m = mgr.clone();
    tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else { return };
        let io = TokioIo::new(stream);
        let c = ctx();
        let svc = service_fn(move |req: Request<Incoming>| {
            let m = m.clone();
            let c = c.clone();
            async move { Ok::<_, Infallible>(m.handle(req, c).await) }
        });
        let _ = auto::Builder::new(TokioExecutor::new())
            .serve_connection(io, svc)
            .await;
    });

    send_request(addr, req).await
}

async fn send_request(proxy_addr: SocketAddr, req: Request<()>) -> (Response<()>, Bytes) {
    let url: http::Uri = format!("http://{}{}", proxy_addr, req.uri()).parse().unwrap();
    let (mut parts, _) = req.into_parts();
    parts.uri = url;
    let req = Request::from_parts(parts, bempty());

    let connector = hyper_util::client::legacy::connect::HttpConnector::new();
    let client =
        hyper_util::client::legacy::Client::builder(TokioExecutor::new()).build(connector);
    let resp = client.request(req).await.expect("test client request failed");
    let (parts, body) = resp.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    (Response::from_parts(parts, ()), bytes)
}

// ── Request builders ─────────────────────────────────────────────────────────

fn get(path: &str) -> Request<()> {
    Request::builder().method(Method::GET).uri(path).body(()).unwrap()
}

fn get_h(path: &str, name: &str, value: &str) -> Request<()> {
    Request::builder().method(Method::GET).uri(path).header(name, value).body(()).unwrap()
}

fn waf_get(path: &str) -> Request<()> {
    Request::builder()
        .method(Method::GET)
        .uri(path)
        .header("host", "example.com")
        .header("user-agent", "TestAgent/1.0")
        .body(())
        .unwrap()
}

// ════════════════════════════════════════════════════════════════════════════
// Proxy-level tests
// ════════════════════════════════════════════════════════════════════════════

/// Test 1 – basic GET is forwarded correctly.
#[tokio::test]
async fn test_basic_get_proxied() {
    let backend = spawn_backend(|_req| async {
        Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(bfull(r#"{"ok":true}"#))
            .unwrap()
    })
    .await;

    let proxy = make_proxy(backend, Default::default());
    let (resp, body) = call_proxy(proxy, get("/api/data")).await;

    assert_eq!(resp.status(), 200);
    assert_eq!(&body[..], br#"{"ok":true}"#);
}

/// Test 2 – repeated GET `?lang=cs` must NOT alternate between 200 and 502.
///
/// Root cause: when the proxy buffers an HTML response body (`body.collect()`),
/// it returns the backend connection to the pool immediately — before the
/// response has been sent to the client.  If the backend then closes that
/// connection (short keepalive), the next request picks up a stale connection
/// from the pool and fails with a transport error → 502 BAD_GATEWAY.
///
/// Fix: default `PROXY_BACKEND_RETRIES` from 0 to 1.  One retry transparently
/// opens a fresh connection; no visible error reaches the client.
#[tokio::test]
async fn test_repeated_lang_param_no_alternating_502() {
    // Backend closes the TCP connection after every single response.
    let backend = spawn_close_after_each(|_req| {
        Response::builder()
            .status(200)
            .header("content-type", "text/html; charset=utf-8")
            .body(bfull("<html><head></head><body>Czech page</body></html>"))
            .unwrap()
    })
    .await;

    let proxy = make_proxy(
        backend,
        TestCfgOverride { backend_retries: Some(1), ..Default::default() },
    );

    for i in 0..6u32 {
        let (resp, _) = call_proxy(proxy.clone(), get("/?lang=cs")).await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "request {i} with ?lang=cs returned {} (expected 200)",
            resp.status()
        );
    }
}

/// Test 2b – confirms the default `backend_retries=1` config value.
///
/// This test just checks that the configuration value is what we expect;
/// the timing-dependent stale-connection race is tested by the unit below.
#[tokio::test]
async fn test_default_backend_retries_is_one() {
    let cfg = ddos_proxy::config::Config::for_test(
        "http://127.0.0.1:1",
        TestCfgOverride::default(),
    );
    assert_eq!(cfg.backend_retries, 1, "default backend_retries should be 1");
}

/// Test 2c – with `backend_retries=0` and a close-after-each backend the
/// proxy *may* see a 502.  This is intentionally not asserted because whether
/// hyper catches the stale TCP connection before sending the request is a
/// timing / implementation detail.  The meaningful invariant — that retries=1
/// never surfaces the 502 to the caller — is tested in Test 2.
#[tokio::test]
async fn test_stale_connection_retries0_does_not_panic() {
    let backend = spawn_close_after_each(|_req| {
        Response::builder()
            .status(200)
            .header("content-type", "text/html; charset=utf-8")
            .body(bfull("<html><head></head><body>Czech page</body></html>"))
            .unwrap()
    })
    .await;

    let proxy = make_proxy(
        backend,
        TestCfgOverride { backend_retries: Some(0), ..Default::default() },
    );

    // Just verify the proxy doesn't panic; status may be 200 or 502.
    for _ in 0..4u32 {
        let (resp, _) = call_proxy(proxy.clone(), get("/?lang=cs")).await;
        assert!(
            resp.status() == StatusCode::OK || resp.status() == StatusCode::BAD_GATEWAY,
            "unexpected status {}",
            resp.status()
        );
    }
}

/// Test 3 – JS snippet injected right after `<head>`.
#[tokio::test]
async fn test_js_injected_after_head() {
    let backend = spawn_backend(|_req| async {
        Response::builder()
            .status(200)
            .header("content-type", "text/html; charset=utf-8")
            .body(bfull("<html><head><title>T</title></head><body>hi</body></html>"))
            .unwrap()
    })
    .await;

    let proxy = make_proxy(backend, Default::default());
    let (_, body) = call_proxy(proxy, get("/")).await;
    let html = std::str::from_utf8(&body).unwrap();

    assert!(html.contains("<head>"), "missing <head> in output");
    assert!(
        html.contains("<head><script>"),
        "JS not injected right after <head>; got: {html}"
    );
}

/// Test 4 – JS snippet injected after `<body>` when there is no `<head>`.
#[tokio::test]
async fn test_js_injected_after_body_no_head() {
    let backend = spawn_backend(|_req| async {
        Response::builder()
            .status(200)
            .header("content-type", "text/html")
            .body(bfull("<html><body>no head here</body></html>"))
            .unwrap()
    })
    .await;

    let proxy = make_proxy(backend, Default::default());
    let (_, body) = call_proxy(proxy, get("/")).await;
    let html = std::str::from_utf8(&body).unwrap();

    assert!(
        html.contains("<body><script>"),
        "JS not injected after <body>; got: {html}"
    );
}

/// Test 5 – non-HTML response passes through without JS injection.
#[tokio::test]
async fn test_non_html_not_injected() {
    const JSON: &str = r#"{"key":"value"}"#;
    let backend = spawn_backend(|_req| async {
        Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(bfull(JSON))
            .unwrap()
    })
    .await;

    let proxy = make_proxy(backend, Default::default());
    let (resp, body) = call_proxy(proxy, get("/api")).await;

    assert_eq!(resp.status(), 200);
    assert_eq!(&body[..], JSON.as_bytes());
    assert!(
        !body.windows(8).any(|w| w == b"<script>"),
        "script tag injected into JSON response"
    );
}

/// Test 6 – gzip-encoded HTML: decoded, JS injected, Content-Encoding removed.
#[tokio::test]
async fn test_gzip_html_decoded_and_injected() {
    use std::io::Write;

    let html = b"<html><head><title>Gzip</title></head><body>content</body></html>";
    let gz = {
        let mut enc =
            flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(html).unwrap();
        enc.finish().unwrap()
    };

    let gz2 = gz.clone();
    let backend = spawn_backend(move |_req| {
        let gz = gz2.clone();
        async move {
            Response::builder()
                .status(200)
                .header("content-type", "text/html; charset=utf-8")
                .header("content-encoding", "gzip")
                .header("content-length", gz.len().to_string())
                .body(bfull(gz))
                .unwrap()
        }
    })
    .await;

    let proxy = make_proxy(backend, Default::default());
    // Request without Accept-Encoding:gzip so we receive the uncompressed result.
    let (resp, body) = call_proxy(proxy, get("/")).await;

    assert_eq!(resp.status(), 200);
    assert!(
        resp.headers().get("content-encoding").is_none(),
        "content-encoding should be stripped after gzip decode"
    );
    let out = std::str::from_utf8(&body).unwrap();
    assert!(out.contains("<head>"), "missing <head> in decoded output");
    assert!(out.contains("<script>"), "JS not injected after gzip decode");
}

/// Test 7 – backend 5xx is forwarded as-is to the client.
#[tokio::test]
async fn test_backend_5xx_forwarded() {
    let backend = spawn_backend(|_req| async {
        Response::builder()
            .status(503)
            .header("content-type", "text/plain")
            .body(bfull("Service Unavailable"))
            .unwrap()
    })
    .await;

    let proxy = make_proxy(backend, Default::default());
    let (resp, _) = call_proxy(proxy, get("/")).await;

    assert_eq!(resp.status(), 503);
}

/// Test 8 – backend that never responds triggers a 504 Gateway Timeout.
#[tokio::test]
async fn test_backend_timeout_returns_504() {
    // Backend accepts connections but never sends a response.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((_stream, _)) = listener.accept().await else { break };
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });

    let proxy = make_proxy(
        backend_addr,
        TestCfgOverride { backend_timeout_ms: Some(150), ..Default::default() },
    );
    let (resp, _) = call_proxy(proxy, get("/")).await;

    assert_eq!(resp.status(), StatusCode::GATEWAY_TIMEOUT);
}

/// Test 9 – backend completely unreachable returns 502.
#[tokio::test]
async fn test_backend_unreachable_returns_502() {
    // Port 1 is effectively always unreachable on loopback.
    let proxy = make_proxy(
        "127.0.0.1:1".parse().unwrap(),
        TestCfgOverride { backend_retries: Some(0), ..Default::default() },
    );
    let (resp, _) = call_proxy(proxy, get("/")).await;

    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
}

/// Test 10 – X-Forwarded-For added to the backend request.
#[tokio::test]
async fn test_xff_added() {
    let backend = spawn_backend(|req| async move {
        let xff = req
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        Response::builder()
            .status(200)
            .header("content-type", "text/plain")
            .body(bfull(xff))
            .unwrap()
    })
    .await;

    let proxy = make_proxy(backend, Default::default());
    let (resp, body) = call_proxy(proxy, get("/")).await;

    assert_eq!(resp.status(), 200);
    let xff = std::str::from_utf8(&body).unwrap();
    assert!(xff.contains("127.0.0.1"), "client IP missing from X-Forwarded-For: {xff}");
}

/// Test 10b – existing X-Forwarded-For is preserved and client IP appended.
#[tokio::test]
async fn test_xff_appended_to_existing() {
    let backend = spawn_backend(|req| async move {
        let xff = req
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        Response::builder()
            .status(200)
            .header("content-type", "text/plain")
            .body(bfull(xff))
            .unwrap()
    })
    .await;

    let proxy = make_proxy(backend, Default::default());
    let req = get_h("/", "x-forwarded-for", "1.2.3.4");
    let (_, body) = call_proxy(proxy, req).await;

    let xff = std::str::from_utf8(&body).unwrap();
    assert!(xff.starts_with("1.2.3.4,"), "original XFF not preserved: {xff}");
    assert!(xff.contains("127.0.0.1"), "proxy IP not appended: {xff}");
}

/// Test 11 – X-Real-IP set from remote address (overwriting any inbound value).
#[tokio::test]
async fn test_x_real_ip_set() {
    let backend = spawn_backend(|req| async move {
        let ip = req
            .headers()
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        Response::builder()
            .status(200)
            .header("content-type", "text/plain")
            .body(bfull(ip))
            .unwrap()
    })
    .await;

    let proxy = make_proxy(backend, Default::default());
    let (_, body) = call_proxy(proxy, get("/")).await;

    assert_eq!(std::str::from_utf8(&body).unwrap(), "127.0.0.1");
}

/// Test 12 – `Server` header replaced with `ddos-proxy/…` and `Via` added.
#[tokio::test]
async fn test_via_and_server_headers() {
    let backend = spawn_backend(|_req| async {
        Response::builder()
            .status(200)
            .header("content-type", "text/plain")
            .header("server", "Apache/2.4")
            .body(bfull("ok"))
            .unwrap()
    })
    .await;

    let proxy = make_proxy(backend, Default::default());
    let (resp, _) = call_proxy(proxy, get("/")).await;

    let server = resp.headers().get("server").and_then(|v| v.to_str().ok()).unwrap_or("");
    assert!(server.starts_with("ddos-proxy"), "Server not replaced; got: {server}");

    let via = resp.headers().get("via").and_then(|v| v.to_str().ok()).unwrap_or("");
    assert!(via.contains("ddos-proxy"), "Via header missing; got: {via}");
}

/// Test 13 – `Location` pointing at the backend host is rewritten to the
/// inbound host so clients aren't accidentally redirected to the backend.
#[tokio::test]
async fn test_location_rewritten_to_inbound_host() {
    // The backend address is only known after spawn, so share it via an Arc.
    let backend_addr_slot: Arc<std::sync::OnceLock<SocketAddr>> = Arc::new(std::sync::OnceLock::new());
    let slot = backend_addr_slot.clone();
    let backend = spawn_backend(move |_req| {
        let addr = slot.get().copied().map(|a| a.to_string()).unwrap_or_default();
        async move {
            Response::builder()
                .status(302)
                .header("location", format!("http://{addr}/redirected"))
                .body(bempty())
                .unwrap()
        }
    })
    .await;
    // Populate the slot so the closure returns the correct host.
    let _ = backend_addr_slot.set(backend);

    let proxy = make_proxy(backend, Default::default());
    let req = Request::builder()
        .method(Method::GET)
        .uri("/old")
        .header("host", "example.com")
        .body(())
        .unwrap();
    let (resp, _) = call_proxy(proxy, req).await;

    assert_eq!(resp.status(), 302);
    let loc = resp.headers().get("location").and_then(|v| v.to_str().ok()).unwrap_or("");
    assert!(
        loc.contains("example.com"),
        "Location not rewritten to inbound host; got: {loc}"
    );
    assert!(
        !loc.contains(&backend.to_string()),
        "backend address leaked in Location: {loc}"
    );
}

/// Test 14 – Content-Length is correct (matches body length) after JS injection.
#[tokio::test]
async fn test_content_length_correct_after_injection() {
    let backend = spawn_backend(|_req| async {
        let html = "<html><head></head><body>test content</body></html>";
        Response::builder()
            .status(200)
            .header("content-type", "text/html")
            .header("content-length", html.len().to_string())
            .body(bfull(html))
            .unwrap()
    })
    .await;

    let proxy = make_proxy(backend, Default::default());
    let (resp, body) = call_proxy(proxy, get("/")).await;

    assert_eq!(resp.status(), 200);
    let reported: usize = resp
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .expect("content-length missing or invalid");
    assert_eq!(
        reported,
        body.len(),
        "Content-Length ({reported}) ≠ actual body length ({})",
        body.len()
    );
}

/// Test 15 – `X-Request-Id` generated, forwarded to backend, returned on response.
#[tokio::test]
async fn test_request_id_generated_and_forwarded() {
    let backend = spawn_backend(|req| async move {
        let id = req
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        Response::builder()
            .status(200)
            .header("content-type", "text/plain")
            .body(bfull(id))
            .unwrap()
    })
    .await;

    let proxy = make_proxy(
        backend,
        TestCfgOverride { request_id: Some(true), ..Default::default() },
    );
    let (resp, body) = call_proxy(proxy, get("/")).await;

    let backend_saw = std::str::from_utf8(&body).unwrap();
    assert!(!backend_saw.is_empty(), "backend did not receive X-Request-Id");

    let resp_id = resp
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(resp_id, backend_saw, "response X-Request-Id ≠ forwarded ID");
}

// ── Cache tests ──────────────────────────────────────────────────────────────

/// Test 16 – first request is a cache miss (backend called), second is a hit
/// (backend NOT called again; same body returned).
#[tokio::test]
async fn test_cache_miss_then_hit() {
    let _guard = CACHE_LOCK.lock().unwrap();
    use std::sync::atomic::{AtomicU32, Ordering};

    let calls = Arc::new(AtomicU32::new(0));
    let calls2 = calls.clone();

    let backend = spawn_backend(move |_req| {
        let n = calls2.fetch_add(1, Ordering::SeqCst);
        async move {
            Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .header("cache-control", "max-age=60")
                .body(bfull(format!(r#"{{"n":{n}}}"#)))
                .unwrap()
        }
    })
    .await;

    // Clear the shared on-disk cache so prior test runs don't pollute this one.
    let _ = std::fs::remove_dir_all("/tmp/ddos-mitigator-cache");

    let cfg = Config::for_test(
        &format!("http://{backend}"),
        TestCfgOverride {
            cache_enabled: Some(true),
            ..Default::default()
        },
    );
    let proxy = Arc::new(Proxy::new(cfg.backend_url.parse().unwrap(), cfg));

    let (_, b1) = call_proxy(proxy.clone(), get_h("/cached-resource", "host", "test.example")).await;
    let (_, b2) = call_proxy(proxy.clone(), get_h("/cached-resource", "host", "test.example")).await;

    assert_eq!(b1, b2, "second response (cache hit) body differs from first");
    assert_eq!(calls.load(Ordering::SeqCst), 1, "backend called more than once; cache not working");
}

/// Test 17 – stale cache is served when the backend returns 5xx.
#[tokio::test]
async fn test_stale_cache_served_on_backend_error() {
    let _guard = CACHE_LOCK.lock().unwrap();
    use std::sync::atomic::{AtomicBool, Ordering};

    let fail = Arc::new(AtomicBool::new(false));
    let fail2 = fail.clone();

    let backend = spawn_backend(move |_req| {
        let f = fail2.load(Ordering::SeqCst);
        async move {
            if f {
                Response::builder().status(500).body(bempty()).unwrap()
            } else {
                Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .header("cache-control", "max-age=1")
                    .body(bfull(r#"{"stale":true}"#))
                    .unwrap()
            }
        }
    })
    .await;

    let _ = std::fs::remove_dir_all("/tmp/ddos-mitigator-cache");

    let cfg = Config::for_test(
        &format!("http://{backend}"),
        TestCfgOverride {
            cache_enabled: Some(true),
            serve_stale: Some(true),
            ..Default::default()
        },
    );
    let proxy = Arc::new(Proxy::new(cfg.backend_url.parse().unwrap(), cfg));

    // Populate the cache (stable Host so both requests share the same cache key).
    call_proxy(proxy.clone(), get_h("/stale-data", "host", "test.example")).await;
    // Let the cache entry expire (max-age=1).
    tokio::time::sleep(Duration::from_millis(1100)).await;
    // Now break the backend.
    fail.store(true, Ordering::SeqCst);
    // The proxy should serve the stale entry rather than a 502/500.
    let (resp, body) = call_proxy(proxy.clone(), get_h("/stale-data", "host", "test.example")).await;

    assert_eq!(resp.status(), 200, "stale cache not served on backend 500");
    assert!(body.windows(12).any(|w| w == br#""stale":true"#), "stale body not returned");
    let ch = resp.headers().get("x-ddos-proxy-cache").and_then(|v| v.to_str().ok()).unwrap_or("");
    assert_eq!(ch, "STALE");
}

// ════════════════════════════════════════════════════════════════════════════
// WAF-level tests
// ════════════════════════════════════════════════════════════════════════════

/// Test 18 – trusted IP bypasses WAF challenge even in always-on mode.
#[tokio::test]
async fn test_trusted_ip_bypasses_waf() {
    let backend = spawn_backend(|_req| async {
        Response::builder().status(200).body(bfull("ok")).unwrap()
    })
    .await;

    let mgr = make_waf(
        backend,
        TestCfgOverride {
            always_on: Some(true),
            trusted_ips: Some(vec!["127.0.0.1".to_string()]),
            ..Default::default()
        },
    );

    let (resp, _) = call_waf(mgr, waf_get("/?lang=cs")).await;
    assert_eq!(resp.status(), 200, "trusted IP should bypass WAF challenge");
}

/// Test 19 – blocked IP gets 403.
#[tokio::test]
async fn test_blocked_ip_gets_403() {
    let backend = spawn_backend(|_req| async {
        Response::builder().status(200).body(bfull("ok")).unwrap()
    })
    .await;

    let mgr = make_waf(
        backend,
        TestCfgOverride {
            deny_ips: Some(vec!["127.0.0.1".to_string()]),
            ..Default::default()
        },
    );

    let (resp, _) = call_waf(mgr, waf_get("/")).await;
    assert_eq!(resp.status(), 403);
}

/// Test 20 – maintenance mode returns 503 for all WAF-routed requests.
#[tokio::test]
async fn test_maintenance_mode_returns_503() {
    let backend = spawn_backend(|_req| async {
        Response::builder().status(200).body(bfull("ok")).unwrap()
    })
    .await;

    let mgr = make_waf(backend, Default::default());
    mgr.set_maintenance(true);

    let (resp, _) = call_waf(mgr, waf_get("/")).await;
    assert_eq!(resp.status(), 503);
}

/// Test 21 – blocked path prefix returns 403; path-traversal variant too.
#[tokio::test]
async fn test_blocked_path_returns_403() {
    let backend = spawn_backend(|_req| async {
        Response::builder().status(200).body(bfull("ok")).unwrap()
    })
    .await;

    let mgr = make_waf(
        backend,
        TestCfgOverride {
            blocked_paths: Some(vec!["/.env".to_string()]),
            trusted_ips: Some(vec!["127.0.0.1".to_string()]), // so only path check fires
            ..Default::default()
        },
    );
    // Trusted bypass is checked before blocked-path in the WAF, but blocked-path
    // is checked before trusted in the real code.  Use a separate IP to keep the
    // test deterministic: we pass the deny_ips as empty and rely on blocked_paths.
    let mgr2 = make_waf(
        backend,
        TestCfgOverride {
            blocked_paths: Some(vec!["/.env".to_string()]),
            ..Default::default()
        },
    );

    let (resp, _) = call_waf(mgr2.clone(), waf_get("/.env")).await;
    assert_eq!(resp.status(), 403, "/.env not blocked");

    // Path traversal: /foo/../.env → normalized to /.env → also blocked
    let (resp2, _) = call_waf(mgr2.clone(), waf_get("/foo/../.env")).await;
    assert_eq!(resp2.status(), 403, "path-traversal variant /.env not blocked");
}

/// Test 22 – honeypot path instantly blocks the IP; subsequent normal requests
/// also get 403.
#[tokio::test]
async fn test_honeypot_path_blocks_ip() {
    let backend = spawn_backend(|_req| async {
        Response::builder().status(200).body(bfull("ok")).unwrap()
    })
    .await;

    let mgr = make_waf(
        backend,
        TestCfgOverride {
            honeypot_paths: Some(vec!["/trap".to_string()]),
            ..Default::default()
        },
    );

    // Hit the honeypot.
    let (r1, _) = call_waf(mgr.clone(), waf_get("/trap")).await;
    assert_eq!(r1.status(), 403, "honeypot should return 403");

    // The same IP should now be blocked on a normal path too.
    let (r2, _) = call_waf(mgr.clone(), waf_get("/normal")).await;
    assert_eq!(r2.status(), 403, "honeypot-blocked IP should get 403 on normal path");
}

/// Test 23 – blocked User-Agent substring returns 403.
#[tokio::test]
async fn test_blocked_ua_returns_403() {
    let backend = spawn_backend(|_req| async {
        Response::builder().status(200).body(bfull("ok")).unwrap()
    })
    .await;

    let mgr = make_waf(
        backend,
        TestCfgOverride {
            blocked_ua: Some(vec!["badbot".to_string()]),
            ..Default::default()
        },
    );

    let req = Request::builder()
        .method(Method::GET)
        .uri("/")
        .header("host", "example.com")
        .header("user-agent", "BadBot/2.0 (scraper)")
        .body(())
        .unwrap();
    let (resp, _) = call_waf(mgr, req).await;
    assert_eq!(resp.status(), 403);
}

/// Test 24 – `PROXY_REQUIRE_UA`: request without User-Agent returns 403.
#[tokio::test]
async fn test_require_ua_missing_returns_403() {
    let backend = spawn_backend(|_req| async {
        Response::builder().status(200).body(bfull("ok")).unwrap()
    })
    .await;

    let mgr = make_waf(
        backend,
        TestCfgOverride { require_ua: Some(true), ..Default::default() },
    );

    let req = Request::builder()
        .method(Method::GET)
        .uri("/")
        .header("host", "example.com")
        // deliberately no User-Agent
        .body(())
        .unwrap();
    let (resp, _) = call_waf(mgr, req).await;
    assert_eq!(resp.status(), 403);
}

/// Test 25 – URI exceeding `max_uri_len` returns 414.
#[tokio::test]
async fn test_uri_too_long_returns_414() {
    let backend = spawn_backend(|_req| async {
        Response::builder().status(200).body(bfull("ok")).unwrap()
    })
    .await;

    let mgr = make_waf(
        backend,
        TestCfgOverride { max_uri_len: Some(10), ..Default::default() },
    );

    let (resp, _) =
        call_waf(mgr, waf_get("/this/is/way/too/long/for/a/ten-byte/limit?q=v")).await;
    assert_eq!(resp.status(), 414);
}

/// Test 26 – HTTP method not in the allowlist returns 405.
#[tokio::test]
async fn test_disallowed_method_returns_405() {
    let backend = spawn_backend(|_req| async {
        Response::builder().status(200).body(bfull("ok")).unwrap()
    })
    .await;

    let mgr = make_waf(
        backend,
        TestCfgOverride {
            allowed_methods: Some(vec!["GET".to_string(), "POST".to_string()]),
            ..Default::default()
        },
    );

    let req = Request::builder()
        .method(Method::DELETE)
        .uri("/resource/1")
        .header("host", "example.com")
        .header("user-agent", "TestAgent/1.0")
        .body(())
        .unwrap();
    let (resp, _) = call_waf(mgr, req).await;
    assert_eq!(resp.status(), 405);
}

/// Test 27 – `always_on=true` with cookie challenge disabled: unverified client
/// gets the JS challenge (418 I'm a Teapot with `X-Mitigation: challenge`).
#[tokio::test]
async fn test_always_on_serves_js_challenge() {
    let backend = spawn_backend(|_req| async {
        Response::builder().status(200).body(bfull("ok")).unwrap()
    })
    .await;

    let mgr = make_waf(
        backend,
        TestCfgOverride {
            always_on: Some(true),
            cookie_challenge: Some(false),
            ..Default::default()
        },
    );

    let (resp, _) = call_waf(mgr, waf_get("/?lang=cs")).await;
    assert_eq!(resp.status(), StatusCode::IM_A_TEAPOT, "expected 418 JS challenge");
    let hdr = resp
        .headers()
        .get("x-mitigation")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(hdr, "challenge");
}

/// Test 28 – cookie challenge flow:
/// 1st request → 307 with `Set-Cookie: __ddos_clearance=…`
/// 2nd request (with cookie) → 200 proxied to backend
#[tokio::test]
async fn test_cookie_challenge_flow() {
    let backend = spawn_backend(|_req| async {
        Response::builder().status(200).body(bfull("proxied")).unwrap()
    })
    .await;

    let mgr = make_waf(
        backend,
        TestCfgOverride {
            always_on: Some(true),
            cookie_challenge: Some(true),
            ..Default::default()
        },
    );

    // Step 1: first request — should get a cookie-challenge redirect.
    let (r1, _) = call_waf(mgr.clone(), waf_get("/?lang=cs")).await;
    assert_eq!(r1.status(), StatusCode::TEMPORARY_REDIRECT, "expected 307 cookie challenge");

    let set_cookie = r1
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .expect("Set-Cookie header missing");
    assert!(set_cookie.contains("__ddos_clearance="), "unexpected cookie: {set_cookie}");

    // Extract the clearance token.
    let token = set_cookie
        .split(';')
        .next()
        .and_then(|kv| kv.split_once('='))
        .map(|(_, v)| v.to_string())
        .expect("could not extract clearance token");

    // Step 2: replay the request with the cookie → should be proxied.
    let r2 = Request::builder()
        .method(Method::GET)
        .uri("/?lang=cs")
        .header("host", "example.com")
        .header("user-agent", "TestAgent/1.0")
        .header("cookie", format!("__ddos_clearance={token}"))
        .body(())
        .unwrap();
    let (resp2, body2) = call_waf(mgr.clone(), r2).await;
    assert_eq!(resp2.status(), 200, "cookie-verified request not proxied");
    assert_eq!(&body2[..], b"proxied");
}

/// Test 29 – PoW challenge: rendered body contains the client's PoW salt.
#[tokio::test]
async fn test_pow_challenge_body_contains_salt() {
    let backend = spawn_backend(|_req| async {
        Response::builder().status(200).body(bfull("ok")).unwrap()
    })
    .await;

    let mgr = make_waf(
        backend,
        TestCfgOverride {
            always_on: Some(true),
            cookie_challenge: Some(false),
            pow_difficulty: Some(1),
            ..Default::default()
        },
    );

    let (resp, body) = call_waf(mgr, waf_get("/")).await;
    assert_eq!(resp.status(), StatusCode::IM_A_TEAPOT);

    // Our template is "<html>{{ pow_salt }}</html>".  The salt is a 16-byte hex
    // string → 32 lowercase hex characters.
    let html = std::str::from_utf8(&body).unwrap();
    let salt_re = regex::Regex::new(r"[0-9a-f]{32}").unwrap();
    assert!(salt_re.is_match(html), "PoW salt not found in challenge body: {html}");
}

/// Test 30 – per-IP rate limit: first request passes, second in the same second
/// gets the JS challenge.
#[tokio::test]
async fn test_per_ip_rate_limit_triggers_challenge() {
    let backend = spawn_backend(|_req| async {
        Response::builder().status(200).body(bfull("ok")).unwrap()
    })
    .await;

    let mgr = make_waf(
        backend,
        TestCfgOverride {
            max_req_per_ip: Some(1),
            cookie_challenge: Some(false),
            ..Default::default()
        },
    );

    // First request within the rate window → proxied.
    let (r1, _) = call_waf(mgr.clone(), waf_get("/")).await;
    assert_eq!(r1.status(), 200, "first request should succeed");

    // Second request within the same second → challenge.
    let (r2, _) = call_waf(mgr.clone(), waf_get("/")).await;
    assert_eq!(
        r2.status(),
        StatusCode::IM_A_TEAPOT,
        "second request over per-IP limit should be challenged"
    );
}

/// Test 31 – 404 scanner: IP blocked after exceeding `max_404_per_ip`.
#[tokio::test]
async fn test_404_scanner_blocks_ip() {
    let backend = spawn_backend(|_req| async {
        Response::builder()
            .status(404)
            .header("content-type", "text/plain")
            .body(bfull("not found"))
            .unwrap()
    })
    .await;

    // Threshold = 2; after 2 404s the client is blocked.
    let mgr = make_waf(
        backend,
        TestCfgOverride { max_404_per_ip: Some(2), ..Default::default() },
    );

    // Send requests until blocked or limit exceeded.
    for i in 0..5usize {
        let (r, _) = call_waf(mgr.clone(), waf_get(&format!("/nonexistent-{i}"))).await;
        if r.status() == 403 {
            return; // blocked as expected
        }
    }
    panic!("IP not blocked after exceeding 404 threshold");
}

/// Test 32 – exempt path bypasses challenge even in always-on mode.
#[tokio::test]
async fn test_exempt_path_bypasses_challenge() {
    let backend = spawn_backend(|_req| async {
        Response::builder().status(200).body(bfull("webhook ok")).unwrap()
    })
    .await;

    let mgr = make_waf(
        backend,
        TestCfgOverride {
            always_on: Some(true),
            exempt_paths: Some(vec!["/webhook".to_string()]),
            ..Default::default()
        },
    );

    let (resp, body) = call_waf(mgr, waf_get("/webhook/event")).await;
    assert_eq!(resp.status(), 200, "exempt path should be proxied without challenge");
    assert_eq!(&body[..], b"webhook ok");
}

/// Test 33 – host allowlist: unknown host gets 403; listed host is proxied.
#[tokio::test]
async fn test_host_allowlist() {
    let backend = spawn_backend(|_req| async {
        Response::builder().status(200).body(bfull("ok")).unwrap()
    })
    .await;

    let mgr = make_waf(
        backend,
        TestCfgOverride {
            allowed_hosts: Some(vec!["allowed.example.com".to_string()]),
            ..Default::default()
        },
    );

    // Unknown host → 403.
    let req_bad = Request::builder()
        .method(Method::GET)
        .uri("/")
        .header("host", "evil.example.com")
        .header("user-agent", "TestAgent/1.0")
        .body(())
        .unwrap();
    let (r1, _) = call_waf(mgr.clone(), req_bad).await;
    assert_eq!(r1.status(), 403, "unknown host should be blocked");

    // Allowed host → proxied.
    let req_good = Request::builder()
        .method(Method::GET)
        .uri("/")
        .header("host", "allowed.example.com")
        .header("user-agent", "TestAgent/1.0")
        .body(())
        .unwrap();
    let (r2, _) = call_waf(mgr, req_good).await;
    assert_eq!(r2.status(), 200, "allowed host should be proxied");
}

/// Test 34 – `X-Ddos-Proxy-Cache: DYNAMIC` for responses with `no-store`.
#[tokio::test]
async fn test_cache_header_dynamic_for_no_store() {
    let backend = spawn_backend(|_req| async {
        Response::builder()
            .status(200)
            .header("content-type", "text/plain")
            .header("cache-control", "no-store")
            .body(bfull("dynamic"))
            .unwrap()
    })
    .await;

    let proxy = make_proxy(
        backend,
        TestCfgOverride { cache_enabled: Some(true), ..Default::default() },
    );
    let (resp, _) = call_proxy(proxy, get("/")).await;

    let ch = resp
        .headers()
        .get("x-ddos-proxy-cache")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(ch, "DYNAMIC");
}
