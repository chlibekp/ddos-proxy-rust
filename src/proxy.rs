use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::header::{HeaderName, HeaderValue};
use http::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use http_body_util::BodyExt;
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
    Lazy::new(|| Regex::new(r"(max-age|s-maxage)\s+(\d+)").unwrap());

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
}

pub struct Proxy {
    target: Uri,
    target_host: String,
    target_scheme: String,
    cfg: Arc<Config>,
    client: ProxyClient,
    cache: Option<crate::cache::DiskCache>,
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
        }
    }

    /// Main proxy entry point. Forwards `req` to the backend, applying the same
    /// header manipulation, JS injection and caching behaviour as the Go proxy.
    pub async fn handle(&self, req: Request<Incoming>, ctx: &ReqCtx) -> Response<BoxedBody> {
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

        // Cache hit fast-path.
        if let (Some(cache), Some(key)) = (self.cache.as_ref(), cache_key.as_ref()) {
            if let Some(stored) = cache.get_fresh(key) {
                let resp = stored.into_response();
                return self.modify_response(resp, &req, ctx, CacheStatus::Hit).await;
            }
        }

        // Build the outbound request.
        let original_host = host_header(&req).unwrap_or_default();
        let outbound = match self.build_outbound(req, ctx, &original_host) {
            Ok(r) => r,
            Err(resp) => return resp,
        };
        let inbound_meta = InboundMeta {
            host: original_host,
        };

        // Send to backend.
        let req_start = std::time::Instant::now();
        let upstream = match self.client.request(outbound).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(error = %e, "Proxy error");
                if self.cfg.prometheus_enabled {
                    crate::metrics::backend_response("error");
                    crate::metrics::backend_duration(req_start.elapsed().as_secs_f64());
                }
                return error_response(StatusCode::BAD_GATEWAY, "Bad Gateway");
            }
        };

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
            let collected = match body.collect().await {
                Ok(c) => c.to_bytes(),
                Err(e) => {
                    tracing::error!(error = %e, "Proxy error reading body");
                    return error_response(StatusCode::BAD_GATEWAY, "Bad Gateway");
                }
            };

            // Store raw (pre-modify) upstream response in the cache.
            if storable {
                if let (Some(cache), Some(key)) = (self.cache.as_ref(), cache_key.as_ref()) {
                    cache.put(key, status, &parts.headers, &collected);
                }
            }

            let resp = Response::from_parts(parts, full(collected));
            let cache_status = if self.cfg.cache_enabled {
                CacheStatus::FreshFetch
            } else {
                CacheStatus::Disabled
            };
            self.modify_response_buffered(resp, &inbound_meta, ctx, cache_status)
                .await
        } else {
            // Stream straight through, only adjusting headers.
            let resp = Response::from_parts(parts, body.map_err(|e| Box::new(e) as _).boxed());
            let cache_status = if self.cfg.cache_enabled {
                CacheStatus::FreshFetch
            } else {
                CacheStatus::Disabled
            };
            self.modify_response_stream(resp, &inbound_meta, ctx, cache_status)
        }
    }

    /// Cache key mirroring Go's httpcache: GET uses the (backend) URL string.
    fn cache_key<B>(&self, req: &Request<B>) -> String {
        let pq = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
        let joined = join_path(self.target.path(), pq);
        format!("{}://{}{}", self.target_scheme, self.target_host, joined)
    }

    /// Build the outbound request from the inbound one (non-websocket path).
    fn build_outbound(
        &self,
        req: Request<Incoming>,
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

        let boxed = body.map_err(|e| Box::new(e) as _).boxed();
        Ok(Request::from_parts(parts, boxed))
    }

    async fn modify_response(
        &self,
        resp: Response<BoxedBody>,
        _req: &Request<Incoming>,
        ctx: &ReqCtx,
        cache_status: CacheStatus,
    ) -> Response<BoxedBody> {
        // Used for cache-hit path: body already buffered inside resp.
        let host = ctx.remote_addr.clone(); // not used for location here
        let _ = host;
        let meta = InboundMeta {
            host: String::new(),
        };
        self.modify_response_buffered(resp, &meta, ctx, cache_status)
            .await
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

        self.apply_common_headers(&mut parts.headers, cache_status);
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
                decode_gzip(&bytes).unwrap_or_else(|| bytes.to_vec())
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
            return Response::from_parts(parts, full(Bytes::from(injected)));
        }

        strip_hop_by_hop(&mut parts.headers);
        Response::from_parts(parts, full(bytes))
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
        self.apply_common_headers(&mut parts.headers, cache_status);
        self.rewrite_location(&mut parts.headers, meta, ctx);
        strip_hop_by_hop(&mut parts.headers);
        Response::from_parts(parts, body)
    }

    fn apply_common_headers(&self, headers: &mut HeaderMap, cache_status: CacheStatus) {
        headers.insert(HeaderName::from_static("via"), HeaderValue::from_static(VIA_BANNER));
        headers.remove(http::header::SERVER);
        headers.insert(http::header::SERVER, HeaderValue::from_static(SERVER_BANNER));

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
        };
        headers.insert(
            HeaderName::from_static("x-ddos-proxy-cache"),
            HeaderValue::from_static(value),
        );
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
}

#[derive(Clone, Copy)]
enum CacheStatus {
    Hit,
    FreshFetch,
    Disabled,
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
