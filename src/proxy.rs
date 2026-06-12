use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::header::{HeaderName, HeaderValue};
use http::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Limited};
use hyper::body::Incoming;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use once_cell::sync::Lazy;
use regex::Regex;

use crate::body::{empty, full, BoxedBody};
use crate::config::Config;
use crate::util::is_websocket_upgrade;

/// Mitigation-detection script injected into HTML responses. Byte-identical to Go.
const JS_SNIPPET: &[u8] = br#"<script>(function(){var r=function(){window.location.reload()};var c=function(h){if(h==='challenge')r()};var f=window.fetch;if(f){window.fetch=function(){return f.apply(this,arguments).then(function(res){if(res&&res.headers&&res.headers.get){c(res.headers.get('X-Mitigation'))}return res})}}var x=XMLHttpRequest.prototype;var o=x.open;x.open=function(){this.addEventListener('load',function(){if(this.getResponseHeader){c(this.getResponseHeader('X-Mitigation'))}});return o.apply(this,arguments)};if(window.fetch){document.addEventListener('error',function(e){var t=e.target;if(t&&t.tagName&&(t.src||t.href)){var g=t.tagName;if(g==='IMG'||g==='SCRIPT'||g==='LINK'||g==='IFRAME'||g==='VIDEO'||g==='AUDIO'){var u=t.src||t.href;if(u&&u.indexOf('data:')!==0){window.fetch(u,{method:'HEAD'}).catch(function(){})}}}},true)}})();</script>"#;

static CC_NORMALIZE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(max-age|s-maxage)\s*=?\s*(\d+)").unwrap());

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

const SERVER_BANNER: &str = concat!("ddos-proxy/", env!("CARGO_PKG_VERSION"));
const VIA_BANNER: &str = concat!(
    "ddos-proxy/",
    env!("CARGO_PKG_VERSION"),
    " https://github.com/chlibekp/ddos-proxy-rust"
);

type ProxyClient = Client<HttpsConnector<HttpConnector>, BoxedBody>;

/// Per-request context that the WAF/server thread provides.
#[derive(Clone)]
pub struct ReqCtx {
    /// True when the inbound connection terminated TLS at the proxy.
    pub is_tls: bool,
    /// Inbound client remote address (host:port or host).
    pub remote_addr: String,
    /// When the request entered the service (start of routing/WAF processing).
    pub start: std::time::Instant,
    /// Connection-scoped metadata (proxy-side address, accept time, socket fd)
    /// backing the `X-Tcp` header and the `tls` Server-Timing component.
    pub conn: Option<Arc<crate::conninfo::ConnInfo>>,
}

impl ReqCtx {
    pub fn new(
        is_tls: bool,
        remote_addr: String,
        conn: Option<Arc<crate::conninfo::ConnInfo>>,
    ) -> Self {
        ReqCtx {
            is_tls,
            remote_addr,
            start: std::time::Instant::now(),
            conn,
        }
    }
}

/// Per-request timing breakdown filled in by `handle_inner` and rendered as
/// the proxy's `Server-Timing` components.
#[derive(Default)]
struct Timing {
    /// Disk-cache lookup.
    cache_lookup: Option<Duration>,
    /// Backend time to first response headers (includes retries).
    backend: Option<Duration>,
    /// Reading the upstream response body (buffered HTML/cacheable path).
    body: Option<Duration>,
    /// Response modification (header rewrite, JS injection, compression).
    process: Option<Duration>,
}

/// Cached outcome of a backend health probe (clonable so it can be stored).
#[derive(Clone)]
enum HealthOutcome {
    Ok(StatusCode),
    Err(String),
}

pub struct Proxy {
    target: Uri,
    target_host: String,
    target_scheme: String,
    cfg: Arc<Config>,
    client: ProxyClient,
    cache: Option<crate::cache::DiskCache>,
    /// Last health-probe result, reused for up to 1s so that flooding `/healthz`
    /// (which is unauthenticated and WAF-exempt) can't amplify into a flood of
    /// backend probes.
    health_cache: std::sync::Mutex<Option<(std::time::Instant, HealthOutcome)>>,
    /// Circuit breaker: consecutive backend transport failures (reset on any
    /// successful response) and the unix second until which the circuit is open.
    cb_failures: std::sync::atomic::AtomicI64,
    cb_open_until: std::sync::atomic::AtomicI64,
}

impl Proxy {
    pub fn new(target: Uri, cfg: Arc<Config>) -> Self {
        // Talk HTTP/1.1 to the backend (the inbound side may be HTTP/2 via ALPN,
        // but the backend hop is negotiated independently). Negotiating only
        // http/1.1 keeps outbound requests and the connection in sync.
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots()
            .expect("native roots")
            .https_or_http()
            .enable_http1()
            .build();

        let client: ProxyClient = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(256)
            .build(https);

        let target_host = target.authority().map(|a| a.as_str().to_string()).unwrap_or_default();
        let target_scheme = target.scheme_str().unwrap_or("http").to_string();

        let cache = if cfg.cache_enabled {
            let dir = "/tmp/ddos-mitigator-cache";
            tracing::info!(dir = dir, "Enabling disk cache");
            Some(crate::cache::DiskCache::new(dir))
        } else {
            None
        };

        Proxy {
            target,
            target_host,
            target_scheme,
            cfg,
            client,
            cache,
            health_cache: std::sync::Mutex::new(None),
            cb_failures: std::sync::atomic::AtomicI64::new(0),
            cb_open_until: std::sync::atomic::AtomicI64::new(0),
        }
    }

    /// Wipe the disk cache. Returns the number of entries removed, or `None`
    /// when caching is disabled.
    pub fn purge_cache(&self) -> Option<usize> {
        self.cache.as_ref().map(|c| c.purge())
    }

    /// Record a backend transport failure for the circuit breaker; trips the
    /// circuit (fail-fast 503s) once `cb_threshold` consecutive failures accrue.
    fn cb_record_failure(&self) {
        if self.cfg.cb_threshold <= 0 {
            return;
        }
        use std::sync::atomic::Ordering;
        let failures = self.cb_failures.fetch_add(1, Ordering::SeqCst) + 1;
        if failures >= self.cfg.cb_threshold {
            let open_until = unix_now() + self.cfg.cb_cooldown.as_secs() as i64;
            self.cb_open_until.store(open_until, Ordering::SeqCst);
            self.cb_failures.store(0, Ordering::SeqCst);
            tracing::warn!(
                failures = failures,
                cooldown_secs = self.cfg.cb_cooldown.as_secs(),
                "Circuit breaker opened: failing fast on backend requests"
            );
        }
    }

    fn cb_record_success(&self) {
        if self.cfg.cb_threshold > 0 {
            self.cb_failures.store(0, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// Whether the circuit breaker is currently open (backend known bad).
    fn cb_is_open(&self) -> bool {
        self.cfg.cb_threshold > 0
            && unix_now() < self.cb_open_until.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Probes the backend by sending a HEAD request to `path` with a 5-second
    /// timeout. Returns the HTTP status code on success or an error on failure.
    pub async fn health_check(
        &self,
        path: &str,
    ) -> Result<StatusCode, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}://{}{}", self.target_scheme, self.target_host, path);
        let uri: Uri = url.parse()?;

        let req = Request::builder()
            .method(Method::HEAD)
            .uri(uri)
            .header(http::header::HOST, &self.target_host)
            .body(empty())?;

        let resp = tokio::time::timeout(Duration::from_secs(5), self.client.request(req))
            .await
            .map_err(|_| "backend health check timed out")?
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

        Ok(resp.status())
    }

    /// Health probe with a 1-second result cache. Returns `Ok(status)` on a
    /// successful probe or `Err(message)` on failure. The cache bounds backend
    /// load to at most one probe per second regardless of inbound `/healthz` rate.
    pub async fn cached_health_check(&self, path: &str) -> Result<StatusCode, String> {
        const TTL: Duration = Duration::from_secs(1);
        if let Ok(guard) = self.health_cache.lock() {
            if let Some((at, outcome)) = guard.as_ref() {
                if at.elapsed() < TTL {
                    return match outcome {
                        HealthOutcome::Ok(s) => Ok(*s),
                        HealthOutcome::Err(e) => Err(e.clone()),
                    };
                }
            }
        }

        let result = self.health_check(path).await.map_err(|e| e.to_string());
        let outcome = match &result {
            Ok(s) => HealthOutcome::Ok(*s),
            Err(e) => HealthOutcome::Err(e.clone()),
        };
        if let Ok(mut guard) = self.health_cache.lock() {
            *guard = Some((std::time::Instant::now(), outcome));
        }
        result
    }

    /// Main proxy entry point. Handles `X-Request-Id` generation/propagation
    /// (inserted into the inbound headers so it is forwarded upstream, and set
    /// on whatever response is produced), then delegates to `handle_inner`.
    pub async fn handle(&self, mut req: Request<Incoming>, ctx: &ReqCtx) -> Response<BoxedBody> {
        let req_id = if self.cfg.request_id {
            let inbound = req
                .headers()
                .get("x-request-id")
                .and_then(|v| v.to_str().ok())
                .filter(|s| {
                    !s.is_empty()
                        && s.len() <= 128
                        && s.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
                })
                .map(|s| s.to_string());
            let id = inbound.unwrap_or_else(random_request_id);
            if let Ok(hv) = HeaderValue::from_str(&id) {
                req.headers_mut()
                    .insert(HeaderName::from_static("x-request-id"), hv);
            }
            Some(id)
        } else {
            None
        };

        // Time spent before the proxy: routing + the whole WAF pipeline.
        let waf_time = ctx.start.elapsed();
        let mut timing = Timing::default();
        let mut resp = self.handle_inner(req, ctx, &mut timing).await;

        if let Some(id) = req_id {
            if let Ok(hv) = HeaderValue::from_str(&id) {
                resp.headers_mut()
                    .insert(HeaderName::from_static("x-request-id"), hv);
            }
        }

        if self.cfg.server_timing && resp.status() != StatusCode::SWITCHING_PROTOCOLS {
            let cache_desc = resp
                .headers()
                .get("x-ddos-proxy-cache")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let value = server_timing_value(waf_time, &timing, cache_desc.as_deref());
            if let Ok(hv) = HeaderValue::from_str(&value) {
                // Append: a backend-supplied Server-Timing must survive.
                resp.headers_mut()
                    .append(HeaderName::from_static("server-timing"), hv);
            }
        }
        resp
    }

    /// Forwards `req` to the backend, applying the same header manipulation,
    /// JS injection and caching behaviour as the Go proxy.
    async fn handle_inner(
        &self,
        req: Request<Incoming>,
        ctx: &ReqCtx,
        timing: &mut Timing,
    ) -> Response<BoxedBody> {
        if is_websocket_upgrade(&req) {
            return self.handle_websocket(req, ctx).await;
        }

        let method = req.method().clone();
        let cacheable_req = method == Method::GET && self.cache.is_some();
        let cache_key = if cacheable_req {
            Some(self.cache_key(&req))
        } else {
            None
        };
        let accept_gzip = req
            .headers()
            .get(http::header::ACCEPT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.contains("gzip"))
            .unwrap_or(false);

        // Cache hit fast-path.
        if let (Some(cache), Some(key)) = (self.cache.as_ref(), cache_key.as_ref()) {
            let lookup_start = std::time::Instant::now();
            let stored = cache.get_fresh(key);
            timing.cache_lookup = Some(lookup_start.elapsed());
            if let Some(stored) = stored {
                if self.cfg.prometheus_enabled {
                    crate::metrics::cache_result("hit");
                }
                let resp = stored.into_response();
                let meta = InboundMeta {
                    host: String::new(),
                    accept_gzip,
                };
                let process_start = std::time::Instant::now();
                let resp = self
                    .modify_response_buffered(resp, &meta, ctx, CacheStatus::Hit)
                    .await;
                timing.process = Some(process_start.elapsed());
                return resp;
            }
            if self.cfg.prometheus_enabled {
                crate::metrics::cache_result("miss");
            }
        }

        // Circuit breaker: while open, fail fast instead of hammering a backend
        // that is known to be down (serving stale cache if allowed).
        if self.cb_is_open() {
            if self.cfg.prometheus_enabled {
                crate::metrics::dropped("circuit_open");
            }
            if let Some(resp) = self.try_serve_stale(&cache_key, ctx, accept_gzip).await {
                return resp;
            }
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "Service Temporarily Unavailable");
        }

        // Build the outbound request.
        // Body-regex inspection and boxing happen here: the body is collected
        // from Incoming (using Limited<Incoming>, not Limited<BoxedBody>) so the
        // async state machine in the public `handle()` never holds a BoxedBody,
        // keeping hyper's `serve_connection_with_upgrades` lifetime constraints satisfied.
        let original_host = host_header(&req).unwrap_or_default();
        let req = match self.inspect_and_box_body(req).await {
            Ok(r) => r,
            Err(resp) => return resp,
        };
        let outbound = match self.build_outbound(req, ctx, &original_host) {
            Ok(r) => r,
            Err(resp) => return resp,
        };
        let inbound_meta = InboundMeta {
            host: original_host,
            accept_gzip,
        };

        // Retry support: GET/HEAD are idempotent, so a transport error (likely a
        // dead pooled connection or a momentary backend blip) can be retried with
        // a rebuilt request. The retry uses an empty body — bodies on GET/HEAD
        // are vanishingly rare and not forwarded on retry.
        let retriable = self.cfg.backend_retries > 0
            && (method == Method::GET || method == Method::HEAD);
        let (out_parts, out_body) = outbound.into_parts();
        let saved_parts = if retriable { Some(out_parts.clone()) } else { None };
        let mut current = Request::from_parts(out_parts, out_body);

        // Send to backend, bounded by PROXY_BACKEND_TIMEOUT (time to first
        // response headers). A hung backend otherwise pins request tasks open
        // indefinitely, which is itself a DoS amplifier.
        let req_start = std::time::Instant::now();
        let mut attempt: u32 = 0;
        let upstream = loop {
            let upstream_result = if self.cfg.backend_timeout.is_zero() {
                Ok(self.client.request(current).await)
            } else {
                tokio::time::timeout(self.cfg.backend_timeout, self.client.request(current)).await
            };
            match upstream_result {
                Err(_) => {
                    timing.backend = Some(req_start.elapsed());
                    tracing::error!(
                        timeout_secs = self.cfg.backend_timeout.as_secs(),
                        "Backend request timed out"
                    );
                    self.cb_record_failure();
                    if self.cfg.prometheus_enabled {
                        crate::metrics::backend_response("timeout");
                        crate::metrics::backend_duration(req_start.elapsed().as_secs_f64());
                    }
                    if let Some(resp) = self.try_serve_stale(&cache_key, ctx, accept_gzip).await {
                        return resp;
                    }
                    return error_response(StatusCode::GATEWAY_TIMEOUT, "Gateway Timeout");
                }
                Ok(Err(e)) => {
                    if let Some(parts) = &saved_parts {
                        if attempt < self.cfg.backend_retries {
                            attempt += 1;
                            tracing::warn!(error = %e, attempt = attempt, "Retrying backend request");
                            if self.cfg.prometheus_enabled {
                                crate::metrics::backend_retry();
                            }
                            current = Request::from_parts(parts.clone(), empty());
                            continue;
                        }
                    }
                    timing.backend = Some(req_start.elapsed());
                    tracing::error!(error = %e, "Proxy error");
                    self.cb_record_failure();
                    if self.cfg.prometheus_enabled {
                        crate::metrics::backend_response("error");
                        crate::metrics::backend_duration(req_start.elapsed().as_secs_f64());
                    }
                    if let Some(resp) = self.try_serve_stale(&cache_key, ctx, accept_gzip).await {
                        return resp;
                    }
                    return error_response(StatusCode::BAD_GATEWAY, "Bad Gateway");
                }
                Ok(Ok(r)) => {
                    self.cb_record_success();
                    timing.backend = Some(req_start.elapsed());
                    break r;
                }
            }
        };

        // Serve-stale on backend 5xx: a stale cached page beats an error page.
        if self.cfg.serve_stale && upstream.status().is_server_error() {
            if let Some(resp) = self.try_serve_stale(&cache_key, ctx, accept_gzip).await {
                if self.cfg.prometheus_enabled {
                    crate::metrics::backend_response(crate::metrics::status_class(
                        upstream.status().as_u16(),
                    ));
                    crate::metrics::backend_duration(req_start.elapsed().as_secs_f64());
                }
                return resp;
            }
        }

        // Convert to buffered form when we may store or inject; otherwise stream.
        let status = upstream.status();
        if self.cfg.prometheus_enabled {
            crate::metrics::backend_response(crate::metrics::status_class(status.as_u16()));
            crate::metrics::backend_duration(req_start.elapsed().as_secs_f64());
        }
        let (parts, body) = upstream.into_parts();
        let content_type = parts
            .headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let is_html = content_type.starts_with("text/html");

        let storable = cacheable_req && status == StatusCode::OK && response_cacheable(&parts.headers);

        if is_html || storable {
            // Buffer the body.
            let body_start = std::time::Instant::now();
            let collected = match body.collect().await {
                Ok(c) => c.to_bytes(),
                Err(e) => {
                    timing.body = Some(body_start.elapsed());
                    tracing::error!(error = %e, "Proxy error reading body");
                    return error_response(StatusCode::BAD_GATEWAY, "Bad Gateway");
                }
            };
            timing.body = Some(body_start.elapsed());

            // Store raw (pre-modify) upstream response in the cache.
            if storable {
                if let (Some(cache), Some(key)) = (self.cache.as_ref(), cache_key.as_ref()) {
                    cache.put(key, status, &parts.headers, &collected);
                    if self.cfg.prometheus_enabled {
                        crate::metrics::cache_result("store");
                    }
                }
            }

            let resp = Response::from_parts(parts, full(collected));
            let cache_status = if self.cfg.cache_enabled {
                CacheStatus::FreshFetch
            } else {
                CacheStatus::Disabled
            };
            let process_start = std::time::Instant::now();
            let resp = self
                .modify_response_buffered(resp, &inbound_meta, ctx, cache_status)
                .await;
            timing.process = Some(process_start.elapsed());
            resp
        } else {
            // Stream straight through, only adjusting headers.
            let resp = Response::from_parts(parts, body.map_err(|e| Box::new(e) as _).boxed());
            let cache_status = if self.cfg.cache_enabled {
                CacheStatus::FreshFetch
            } else {
                CacheStatus::Disabled
            };
            let process_start = std::time::Instant::now();
            let resp = self.modify_response_stream(resp, &inbound_meta, ctx, cache_status);
            timing.process = Some(process_start.elapsed());
            resp
        }
    }

    /// Cache key for a GET request. Includes the inbound `Host` so responses for
    /// different inbound hosts proxied to the same backend can't collide and serve
    /// one host's content to another (the Host is forwarded upstream, so the
    /// backend may produce different bodies per host).
    fn cache_key<B>(&self, req: &Request<B>) -> String {
        let pq = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
        let joined = join_path(self.target.path(), pq);
        let host = host_header(req).unwrap_or_default();
        format!("{}://{}{}|host={}", self.target_scheme, self.target_host, joined, host)
    }

    /// Inspect the request body for `PROXY_BLOCK_BODY_REGEX` and box it.
    ///
    /// Uses `Limited<Incoming>` (the native hyper body type) rather than
    /// `Limited<BoxedBody>` so the caller's async state machine doesn't hold a
    /// `Box<dyn Error + 'static>` trait-object across an await point — which
    /// would trigger an unsatisfiable HRTB constraint in hyper's upgrade machinery.
    async fn inspect_and_box_body(
        &self,
        req: Request<Incoming>,
    ) -> Result<Request<BoxedBody>, Response<BoxedBody>> {
        if let Some(re) = &self.cfg.block_body_regex {
            if matches!(req.method(), &Method::POST | &Method::PUT | &Method::PATCH) {
                let limit = self.cfg.max_body_size.map(|n| n as usize).unwrap_or(1024 * 1024);
                let (parts, body) = req.into_parts();
                return match Limited::new(body, limit).collect().await {
                    Ok(collected) => {
                        let bytes = collected.to_bytes();
                        if re.is_match(&String::from_utf8_lossy(&bytes)) {
                            if self.cfg.prometheus_enabled {
                                crate::metrics::dropped("body_regex");
                            }
                            Err(error_response(StatusCode::FORBIDDEN, "Forbidden"))
                        } else {
                            Ok(Request::from_parts(parts, full(bytes)))
                        }
                    }
                    Err(_) => {
                        if self.cfg.prometheus_enabled {
                            crate::metrics::dropped("body_too_large");
                        }
                        Err(error_response(StatusCode::PAYLOAD_TOO_LARGE, "Payload Too Large"))
                    }
                };
            }
        }
        let (parts, body) = req.into_parts();
        Ok(Request::from_parts(parts, body.map_err(|e| Box::new(e) as _).boxed()))
    }

    /// Build the outbound request from the inbound one (non-websocket path).
    fn build_outbound(
        &self,
        req: Request<BoxedBody>,
        ctx: &ReqCtx,
        original_host: &str,
    ) -> Result<Request<BoxedBody>, Response<BoxedBody>> {
        let (mut parts, body) = req.into_parts();

        // Force HTTP/1.1 for the backend hop (inbound may be HTTP/2 via ALPN).
        parts.version = http::Version::HTTP_11;

        // Compose target URI: backend scheme/authority + inbound path&query.
        let path_and_query = parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        let joined = join_path(self.target.path(), path_and_query);
        let uri_str = format!("{}://{}{}", self.target_scheme, self.target_host, joined);
        let new_uri: Uri = match uri_str.parse() {
            Ok(u) => u,
            Err(_) => return Err(error_response(StatusCode::BAD_GATEWAY, "Bad Gateway")),
        };
        parts.uri = new_uri;

        // Strip hop-by-hop headers.
        strip_hop_by_hop(&mut parts.headers);

        // Accept-Encoding stripped for HTML requests (so we can inject).
        let accept_html = parts
            .headers
            .get(http::header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.contains("text/html"))
            .unwrap_or(false);
        if accept_html {
            parts.headers.remove(http::header::ACCEPT_ENCODING);
        }

        // Preserve original Host.
        if let Ok(hv) = HeaderValue::from_str(original_host) {
            parts.headers.insert(http::header::HOST, hv);
        }

        // X-Forwarded-For append (client IP).
        let client_ip = ctx
            .remote_addr
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(&ctx.remote_addr)
            .trim_matches(|c| c == '[' || c == ']');
        append_xff(&mut parts.headers, client_ip);

        // X-Real-IP: always set (overwriting any inbound value, which would
        // otherwise let clients spoof their address to the backend).
        if let Ok(hv) = HeaderValue::from_str(client_ip) {
            parts.headers.insert(HeaderName::from_static("x-real-ip"), hv);
        }

        // X-Forwarded-Host / X-Forwarded-Proto if absent.
        if !parts.headers.contains_key("x-forwarded-host") {
            if let Ok(hv) = HeaderValue::from_str(original_host) {
                parts.headers.insert(
                    HeaderName::from_static("x-forwarded-host"),
                    hv,
                );
            }
        }
        if !parts.headers.contains_key("x-forwarded-proto") {
            let scheme = if ctx.is_tls { "https" } else { "http" };
            parts.headers.insert(
                HeaderName::from_static("x-forwarded-proto"),
                HeaderValue::from_static(if scheme == "https" { "https" } else { "http" }),
            );
        }

        Ok(Request::from_parts(parts, body))
    }

    /// Serve a stale cached copy of `cache_key` if serve-stale is enabled and an
    /// entry (fresh or expired) exists. Returns `None` when not applicable.
    async fn try_serve_stale(
        &self,
        cache_key: &Option<String>,
        ctx: &ReqCtx,
        accept_gzip: bool,
    ) -> Option<Response<BoxedBody>> {
        if !self.cfg.serve_stale {
            return None;
        }
        let (cache, key) = (self.cache.as_ref()?, cache_key.as_ref()?);
        let stored = cache.get_any(key)?;
        tracing::warn!("Backend unavailable; serving stale cached response");
        if self.cfg.prometheus_enabled {
            crate::metrics::cache_result("stale");
        }
        let meta = InboundMeta {
            host: String::new(),
            accept_gzip,
        };
        Some(
            self.modify_response_buffered(stored.into_response(), &meta, ctx, CacheStatus::Stale)
                .await,
        )
    }

    /// Apply response transforms when the body is already buffered (HTML/cache).
    async fn modify_response_buffered(
        &self,
        resp: Response<BoxedBody>,
        meta: &InboundMeta,
        ctx: &ReqCtx,
        cache_status: CacheStatus,
    ) -> Response<BoxedBody> {
        let (mut parts, body) = resp.into_parts();

        if parts.status == StatusCode::SWITCHING_PROTOCOLS {
            return Response::from_parts(parts, body);
        }

        self.apply_common_headers(&mut parts.headers, cache_status, ctx.is_tls);
        self.rewrite_location(&mut parts.headers, meta, ctx);

        // Collect the buffered body.
        let bytes = body.collect().await.map(|c| c.to_bytes()).unwrap_or_default();

        let content_type = parts
            .headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        if content_type.starts_with("text/html") {
            let ce = parts
                .headers
                .get(http::header::CONTENT_ENCODING)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();

            if !ce.is_empty() && ce != "identity" && ce != "gzip" {
                // Unsupported encoding — skip injection.
                strip_hop_by_hop(&mut parts.headers);
                return Response::from_parts(parts, full(bytes));
            }

            let decoded: Vec<u8> = if ce == "gzip" {
                match decode_gzip(&bytes) {
                    Some(d) => d,
                    None => {
                        // Gzip decode failed — skip injection, return original response.
                        strip_hop_by_hop(&mut parts.headers);
                        return Response::from_parts(parts, full(bytes));
                    }
                }
            } else {
                bytes.to_vec()
            };

            let injected = inject_js(&decoded);

            if ce == "gzip" {
                parts.headers.remove(http::header::CONTENT_ENCODING);
            }
            let len = injected.len();
            parts.headers.remove(http::header::CONTENT_LENGTH);
            parts.headers.insert(
                http::header::CONTENT_LENGTH,
                HeaderValue::from_str(&len.to_string()).unwrap(),
            );
            strip_hop_by_hop(&mut parts.headers);
            let body = self.maybe_compress(&mut parts.headers, &content_type, meta, Bytes::from(injected));
            return Response::from_parts(parts, full(body));
        }

        strip_hop_by_hop(&mut parts.headers);
        let body = self.maybe_compress(&mut parts.headers, &content_type, meta, bytes);
        Response::from_parts(parts, full(body))
    }

    /// Optionally gzip a buffered response body: only when compression is
    /// enabled, the client accepts gzip, the content type is compressible, the
    /// body is ≥ 1 KiB, the backend didn't already encode it, and compressing
    /// actually shrinks it. Updates Content-Encoding/Content-Length/Vary.
    fn maybe_compress(
        &self,
        headers: &mut HeaderMap,
        content_type: &str,
        meta: &InboundMeta,
        body: Bytes,
    ) -> Bytes {
        const MIN_COMPRESS_LEN: usize = 1024;
        if !self.cfg.compression
            || !meta.accept_gzip
            || body.len() < MIN_COMPRESS_LEN
            || !compressible_content_type(content_type)
            || headers.contains_key(http::header::CONTENT_ENCODING)
        {
            return body;
        }
        let Some(gz) = encode_gzip(&body) else {
            return body;
        };
        if gz.len() >= body.len() {
            return body;
        }
        headers.insert(
            http::header::CONTENT_ENCODING,
            HeaderValue::from_static("gzip"),
        );
        headers.insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_str(&gz.len().to_string()).unwrap(),
        );
        headers.append(http::header::VARY, HeaderValue::from_static("Accept-Encoding"));
        Bytes::from(gz)
    }

    /// Apply response transforms for the streaming (non-HTML, non-cached) path.
    fn modify_response_stream(
        &self,
        resp: Response<BoxedBody>,
        meta: &InboundMeta,
        ctx: &ReqCtx,
        cache_status: CacheStatus,
    ) -> Response<BoxedBody> {
        let (mut parts, body) = resp.into_parts();
        if parts.status == StatusCode::SWITCHING_PROTOCOLS {
            return Response::from_parts(parts, body);
        }
        self.apply_common_headers(&mut parts.headers, cache_status, ctx.is_tls);
        self.rewrite_location(&mut parts.headers, meta, ctx);
        strip_hop_by_hop(&mut parts.headers);
        Response::from_parts(parts, body)
    }

    fn apply_common_headers(&self, headers: &mut HeaderMap, cache_status: CacheStatus, is_tls: bool) {
        headers.insert(HeaderName::from_static("via"), HeaderValue::from_static(VIA_BANNER));
        headers.remove(http::header::SERVER);
        headers.insert(http::header::SERVER, HeaderValue::from_static(SERVER_BANNER));

        // Optional security headers; backend-set values always win.
        if self.cfg.security_headers {
            for (name, value) in [
                ("x-content-type-options", "nosniff"),
                ("x-frame-options", "SAMEORIGIN"),
                ("referrer-policy", "strict-origin-when-cross-origin"),
            ] {
                let name = HeaderName::from_static(name);
                if !headers.contains_key(&name) {
                    headers.insert(name, HeaderValue::from_static(value));
                }
            }
            // HSTS only makes sense on TLS responses (browsers ignore it on
            // plain HTTP, and setting it there can mask misconfiguration).
            if is_tls && !headers.contains_key(http::header::STRICT_TRANSPORT_SECURITY) {
                headers.insert(
                    http::header::STRICT_TRANSPORT_SECURITY,
                    HeaderValue::from_static("max-age=31536000; includeSubDomains"),
                );
            }
        }

        let value = match cache_status {
            CacheStatus::Hit => {
                headers.remove("x-from-cache");
                "HIT"
            }
            CacheStatus::FreshFetch => {
                // X-From-Cache would be present only on a hit; here it's a fetch.
                let cc = headers
                    .get(http::header::CACHE_CONTROL)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                if !cc.is_empty()
                    && !cc.contains("no-cache")
                    && !cc.contains("no-store")
                    && !cc.contains("private")
                {
                    "MISS"
                } else {
                    "DYNAMIC"
                }
            }
            CacheStatus::Disabled => "DYNAMIC",
            CacheStatus::Stale => "STALE",
        };
        headers.insert(
            HeaderName::from_static("x-ddos-proxy-cache"),
            HeaderValue::from_static(value),
        );

        // CORS injection: only when configured and the backend didn't set it.
        if let Some(origin) = &self.cfg.cors_origin {
            if !headers.contains_key(http::header::ACCESS_CONTROL_ALLOW_ORIGIN) {
                if let Ok(hv) = HeaderValue::from_str(origin) {
                    headers.insert(http::header::ACCESS_CONTROL_ALLOW_ORIGIN, hv);
                    headers.insert(
                        http::header::ACCESS_CONTROL_ALLOW_METHODS,
                        HeaderValue::from_static("GET, POST, PUT, DELETE, PATCH, OPTIONS"),
                    );
                    headers.insert(
                        http::header::ACCESS_CONTROL_ALLOW_HEADERS,
                        HeaderValue::from_static("Content-Type, Authorization"),
                    );
                    if origin != "*" {
                        headers.append(http::header::VARY, HeaderValue::from_static("Origin"));
                    }
                }
            }
        }

        // Operator-configured header stripping (e.g. hide X-Powered-By) and
        // custom additions; additions overwrite backend values by design.
        for name in &self.cfg.remove_headers {
            headers.remove(name.as_str());
        }
        for (name, value) in &self.cfg.add_headers {
            if let (Ok(n), Ok(v)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers.insert(n, v);
            }
        }
    }

    fn rewrite_location(&self, headers: &mut HeaderMap, meta: &InboundMeta, ctx: &ReqCtx) {
        let location = match headers.get(http::header::LOCATION).and_then(|v| v.to_str().ok()) {
            Some(l) if !l.is_empty() => l.to_string(),
            _ => return,
        };
        let parsed = match url::Url::parse(&location) {
            Ok(u) => u,
            Err(_) => return,
        };
        let loc_host = match parsed.host_str() {
            Some(h) => {
                if let Some(port) = parsed.port() {
                    format!("{h}:{port}")
                } else {
                    h.to_string()
                }
            }
            None => return,
        };
        if loc_host == self.target_host {
            let scheme = if ctx.is_tls { "https" } else { "http" };
            let mut new_url = parsed.clone();
            let _ = new_url.set_scheme(scheme);
            // set host to inbound host (may include port)
            if let Some((h, p)) = meta.host.rsplit_once(':') {
                let _ = new_url.set_host(Some(h));
                let _ = new_url.set_port(p.parse::<u16>().ok());
            } else {
                let _ = new_url.set_host(Some(&meta.host));
                let _ = new_url.set_port(None);
            }
            if let Ok(hv) = HeaderValue::from_str(new_url.as_str()) {
                headers.insert(http::header::LOCATION, hv);
            }
        }
    }

    /// WebSocket upgrade tunneling: bypasses cache, pipes bytes both ways.
    async fn handle_websocket(&self, req: Request<Incoming>, ctx: &ReqCtx) -> Response<BoxedBody> {
        use tokio::io::copy_bidirectional;

        let original_host = host_header(&req).unwrap_or_default();
        let (mut parts, _body) = req.into_parts();

        // Take the inbound upgrade future before we consume the request parts.
        // Reconstruct a request to get OnUpgrade.
        let mut inbound_req = Request::from_parts(parts.clone(), empty());
        let inbound_upgrade = hyper::upgrade::on(&mut inbound_req);

        // Build outbound request (keep upgrade headers).
        let path_and_query = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        let joined = join_path(self.target.path(), path_and_query);

        // Connect to backend (TCP, optional TLS).
        let host_only = self
            .target_host
            .rsplit_once(':')
            .map(|(h, _)| h.to_string())
            .unwrap_or_else(|| self.target_host.clone());
        let port: u16 = self
            .target_host
            .rsplit_once(':')
            .and_then(|(_, p)| p.parse().ok())
            .unwrap_or(if self.target_scheme == "https" { 443 } else { 80 });

        let tcp = match tokio::net::TcpStream::connect((host_only.as_str(), port)).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "WebSocket backend connect failed");
                return error_response(StatusCode::BAD_GATEWAY, "Bad Gateway");
            }
        };

        if let Ok(hv) = HeaderValue::from_str(&original_host) {
            parts.headers.insert(http::header::HOST, hv);
        }
        let client_ip = ctx
            .remote_addr
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(&ctx.remote_addr);
        append_xff(&mut parts.headers, client_ip);
        if let Ok(hv) = HeaderValue::from_str(client_ip.trim_matches(|c| c == '[' || c == ']')) {
            parts.headers.insert(HeaderName::from_static("x-real-ip"), hv);
        }

        let out_uri: Uri = match joined.parse() {
            Ok(u) => u,
            Err(_) => return error_response(StatusCode::BAD_GATEWAY, "Bad Gateway"),
        };
        let mut out_parts = parts;
        out_parts.uri = out_uri;
        out_parts.version = http::Version::HTTP_11;
        let outbound = Request::from_parts(out_parts, empty());

        // Note: TLS to backend (wss) not implemented; ws:// supported.
        let io = TokioIo::new(tcp);
        let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::error!(error = %e, "WebSocket handshake failed");
                return error_response(StatusCode::BAD_GATEWAY, "Bad Gateway");
            }
        };
        tokio::spawn(async move {
            let _ = conn.with_upgrades().await;
        });

        let upstream = match sender.send_request(outbound).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(error = %e, "WebSocket upstream request failed");
                return error_response(StatusCode::BAD_GATEWAY, "Bad Gateway");
            }
        };

        if upstream.status() != StatusCode::SWITCHING_PROTOCOLS {
            // Not an upgrade — relay the response as-is (buffered).
            let (p, b) = upstream.into_parts();
            let bytes = b.collect().await.map(|c| c.to_bytes()).unwrap_or_default();
            return Response::from_parts(p, full(bytes));
        }

        // Build the 101 response to send back to the client.
        let (up_parts, _up_body) = upstream.into_parts();
        let backend_upgrade = {
            // Re-wrap to take upgrade; hyper::upgrade::on needs the response.
            let mut up_resp = Response::from_parts(up_parts.clone(), empty());
            hyper::upgrade::on(&mut up_resp)
        };

        // Spawn the bidirectional pipe.
        tokio::spawn(async move {
            let (client_io, server_io) = match tokio::join!(inbound_upgrade, backend_upgrade) {
                (Ok(c), Ok(s)) => (c, s),
                _ => {
                    tracing::error!("WebSocket upgrade failed on one side");
                    return;
                }
            };
            let mut client_io = TokioIo::new(client_io);
            let mut server_io = TokioIo::new(server_io);
            let _ = copy_bidirectional(&mut client_io, &mut server_io).await;
        });

        let mut resp = Response::new(empty());
        *resp.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
        *resp.headers_mut() = up_parts.headers;
        resp
    }
}

struct InboundMeta {
    host: String,
    /// Whether the inbound request advertised `Accept-Encoding: gzip` (used by
    /// the optional response-compression feature).
    accept_gzip: bool,
}

#[derive(Clone, Copy)]
enum CacheStatus {
    Hit,
    FreshFetch,
    Disabled,
    /// Expired cache entry served because the backend failed (serve-stale).
    Stale,
}

fn host_header<B>(req: &Request<B>) -> Option<String> {
    req.headers()
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .or_else(|| req.uri().authority().map(|a| a.as_str().to_string()))
}

fn join_path(base: &str, req_path: &str) -> String {
    // Mirror Go's singleJoiningSlash.
    let a = base;
    let b = req_path;
    let a_slash = a.ends_with('/');
    let b_slash = b.starts_with('/');
    if a_slash && b_slash {
        format!("{}{}", a, &b[1..])
    } else if !a_slash && !b_slash {
        if a.is_empty() {
            b.to_string()
        } else {
            format!("{}/{}", a, b)
        }
    } else {
        format!("{}{}", a, b)
    }
}

fn strip_hop_by_hop(headers: &mut HeaderMap) {
    for h in HOP_BY_HOP {
        headers.remove(*h);
    }
}

fn append_xff(headers: &mut HeaderMap, client_ip: &str) {
    let existing = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let new_val = match existing {
        Some(prev) if !prev.is_empty() => format!("{prev}, {client_ip}"),
        _ => client_ip.to_string(),
    };
    if let Ok(hv) = HeaderValue::from_str(&new_val) {
        headers.insert(HeaderName::from_static("x-forwarded-for"), hv);
    }
}

fn inject_js(body: &[u8]) -> Vec<u8> {
    let head = b"<head>";
    let body_tag = b"<body>";
    if let Some(idx) = find_subslice(body, head) {
        let mut out = Vec::with_capacity(body.len() + JS_SNIPPET.len());
        out.extend_from_slice(&body[..idx + head.len()]);
        out.extend_from_slice(JS_SNIPPET);
        out.extend_from_slice(&body[idx + head.len()..]);
        out
    } else if let Some(idx) = find_subslice(body, body_tag) {
        let mut out = Vec::with_capacity(body.len() + JS_SNIPPET.len());
        out.extend_from_slice(&body[..idx + body_tag.len()]);
        out.extend_from_slice(JS_SNIPPET);
        out.extend_from_slice(&body[idx + body_tag.len()..]);
        out
    } else {
        let mut out = Vec::with_capacity(body.len() + JS_SNIPPET.len());
        out.extend_from_slice(JS_SNIPPET);
        out.extend_from_slice(body);
        out
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

fn decode_gzip(data: &[u8]) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut decoder = flate2::read::GzDecoder::new(data);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).ok().map(|_| out)
}

fn encode_gzip(data: &[u8]) -> Option<Vec<u8>> {
    use std::io::Write;
    let mut encoder =
        flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).ok()?;
    encoder.finish().ok()
}

/// Content types worth gzip-compressing (text-like payloads).
fn compressible_content_type(ct: &str) -> bool {
    ct.starts_with("text/")
        || ct.starts_with("application/json")
        || ct.starts_with("application/javascript")
        || ct.starts_with("application/xml")
        || ct.starts_with("image/svg")
}

/// Render the proxy's `Server-Timing` components (durations in milliseconds).
/// The server in `lib.rs` appends the request-level `tls`/`total` components.
fn server_timing_value(waf: Duration, t: &Timing, cache_desc: Option<&str>) -> String {
    fn ms(d: Duration) -> f64 {
        d.as_secs_f64() * 1000.0
    }
    let mut parts = vec![format!("waf;dur={:.2}", ms(waf))];
    if let Some(d) = t.cache_lookup {
        match cache_desc {
            Some(desc) => parts.push(format!("cache;desc=\"{desc}\";dur={:.2}", ms(d))),
            None => parts.push(format!("cache;dur={:.2}", ms(d))),
        }
    }
    if let Some(d) = t.backend {
        parts.push(format!("backend;desc=\"ttfb\";dur={:.2}", ms(d)));
    }
    if let Some(d) = t.body {
        parts.push(format!("body;desc=\"read\";dur={:.2}", ms(d)));
    }
    if let Some(d) = t.process {
        parts.push(format!("proc;desc=\"modify\";dur={:.2}", ms(d)));
    }
    parts.join(", ")
}

/// Random 16-byte hex request ID.
fn random_request_id() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

pub fn normalize_cache_control(value: &str) -> String {
    CC_NORMALIZE_RE.replace_all(value, "$1=$2").to_string()
}

fn response_cacheable(headers: &HeaderMap) -> bool {
    // Merge potentially-multiple Cache-Control headers (Go NormalizingTransport).
    let merged: Vec<String> = headers
        .get_all(http::header::CACHE_CONTROL)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .collect();
    if merged.is_empty() {
        return false;
    }
    let cc = normalize_cache_control(&merged.join(", "));
    if cc.contains("no-store") || cc.contains("no-cache") || cc.contains("private") {
        return false;
    }
    // Require a positive max-age or s-maxage.
    max_age(&cc).map(|m| m > 0).unwrap_or(false)
}

pub fn max_age(cc: &str) -> Option<i64> {
    for part in cc.split(',') {
        let p = part.trim();
        for key in ["s-maxage=", "max-age="] {
            if let Some(rest) = p.strip_prefix(key) {
                if let Ok(v) = rest.trim().parse::<i64>() {
                    return Some(v);
                }
            }
        }
    }
    None
}

pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn error_response(status: StatusCode, msg: &str) -> Response<BoxedBody> {
    let mut resp = Response::new(full(format!("{msg}\n")));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp
}
