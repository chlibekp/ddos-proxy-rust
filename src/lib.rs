// Needed by the large serde_json::json! literal in admin::config_json.
#![recursion_limit = "256"]

pub mod admin;
pub mod audit;
pub mod body;
pub mod cache;
pub mod config;
pub mod conninfo;
pub mod discord;
pub mod health;
pub mod limiter;
pub mod metrics;
pub mod netmatch;
pub mod proxy;
pub mod tls;
pub mod util;
pub mod waf;
pub mod xdp;

use std::convert::Infallible;
use std::sync::Arc;

use http::{Request, Response, StatusCode};
use hyper::body::Incoming;

use crate::body::{full, BoxedBody};
use crate::limiter::IPLimiter;
use crate::proxy::ReqCtx;
use crate::waf::Manager;

/// Route a request: `/metrics`, `/healthz`, and `/admin/` bypass the WAF;
/// everything else goes through the WAF middleware.  Used by both the plain-
/// HTTP server in `main.rs` and the TLS server in `tls.rs`.
pub async fn route(
    req: Request<Incoming>,
    ctx: ReqCtx,
    manager: Arc<Manager>,
    ip_limiter: Option<Arc<IPLimiter>>,
) -> Result<Response<BoxedBody>, Infallible> {
    let cfg = manager.config().clone();
    let start = ctx.start;
    let conn = ctx.conn.clone();
    let remote_addr = ctx.remote_addr.clone();

    let access_meta = cfg.access_log.then(|| {
        let method = req.method().to_string();
        let path = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
        let ip = remote_addr
            .rsplit_once(':')
            .map(|(h, _)| h.trim_matches(|c| c == '[' || c == ']').to_string())
            .unwrap_or_else(|| remote_addr.clone());
        (method, path, ip)
    });

    let mut resp = dispatch(req, ctx, manager, ip_limiter).await;

    if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
        if cfg.server_timing {
            // Request-level components; the proxy contributes its own detailed
            // Server-Timing header (waf/cache/backend/body/proc) — multiple
            // Server-Timing headers are merged by clients per the spec.
            let mut value = String::new();
            if let Some(hs) = conn.as_ref().and_then(|c| c.tls_handshake) {
                value.push_str(&format!(
                    "tls;desc=\"handshake\";dur={:.2}, ",
                    hs.as_secs_f64() * 1000.0
                ));
            }
            value.push_str(&format!(
                "total;dur={:.2}",
                start.elapsed().as_secs_f64() * 1000.0
            ));
            if let Ok(hv) = http::HeaderValue::from_str(&value) {
                resp.headers_mut()
                    .append(http::header::HeaderName::from_static("server-timing"), hv);
            }
        }
        if cfg.tcp_header {
            let value = conninfo::x_tcp_value(conn.as_deref(), &remote_addr);
            if let Ok(hv) = http::HeaderValue::from_str(&value) {
                resp.headers_mut()
                    .insert(http::header::HeaderName::from_static("x-tcp"), hv);
            }
        }
    }

    if let Some((method, path, ip)) = access_meta {
        tracing::info!(
            target: "access",
            method = %method,
            path = %path,
            status = resp.status().as_u16(),
            duration_ms = start.elapsed().as_millis() as u64,
            ip = %ip,
            "request",
        );
    }
    Ok(resp)
}

async fn dispatch(
    req: Request<Incoming>,
    ctx: ReqCtx,
    manager: Arc<Manager>,
    ip_limiter: Option<Arc<IPLimiter>>,
) -> Response<BoxedBody> {
    if manager.config().prometheus_enabled && req.uri().path() == "/metrics" {
        return metrics_endpoint(&ctx, ip_limiter.as_deref());
    }
    let path = req.uri().path();
    if path.starts_with("/ddos-proxy/admin") {
        return admin::handle(req, ctx, manager).await;
    }
    let cfg = manager.config();
    if cfg.healthz_enabled && path == cfg.healthz_path {
        return health::handle(manager.proxy(), &cfg.healthz_backend_path.clone()).await;
    }
    manager.handle(req, ctx).await
}

fn metrics_endpoint(ctx: &ReqCtx, ip_limiter: Option<&IPLimiter>) -> Response<BoxedBody> {
    let ip = ctx
        .remote_addr
        .rsplit_once(':')
        .map(|(h, _)| h.trim_matches(|c| c == '[' || c == ']').to_string())
        .unwrap_or_else(|| ctx.remote_addr.clone());

    if let Some(limiter) = ip_limiter {
        if !limiter.allow(&ip) {
            metrics::dropped("metrics_rate_limit");
            let mut resp = Response::new(full("Too Many Requests\n"));
            *resp.status_mut() = StatusCode::TOO_MANY_REQUESTS;
            return resp;
        }
    }

    let (buf, content_type) = metrics::gather();
    let mut resp = Response::new(full(buf));
    resp.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_str(&content_type).unwrap(),
    );
    resp
}

/// Future that resolves on SIGINT or SIGTERM.  Used by both the plain-HTTP and
/// TLS servers so they share the same shutdown mechanism.
pub fn signal_future() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
    Box::pin(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigterm = signal(SignalKind::terminate()).unwrap();
            let mut sigint = signal(SignalKind::interrupt()).unwrap();
            tokio::select! {
                _ = sigterm.recv() => {}
                _ = sigint.recv() => {}
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
    })
}
