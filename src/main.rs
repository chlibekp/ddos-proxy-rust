mod admin;
mod body;
mod cache;
mod config;
mod discord;
mod health;
mod limiter;
mod metrics;
mod proxy;
mod tls;
mod util;
mod waf;
mod xdp;

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use http::{Request, Response, StatusCode};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::net::TcpListener;

use crate::body::{full, BoxedBody};
use crate::config::Config;
use crate::limiter::{IPLimiter, RateLimiter};
use crate::proxy::{Proxy, ReqCtx};
use crate::waf::Manager;

#[tokio::main]
async fn main() {
    // JSON structured logging (mirrors Go slog JSON handler).
    tracing_subscriber::fmt()
        .json()
        .with_current_span(false)
        .with_span_list(false)
        .init();

    // Install the default rustls crypto provider (ring).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cfg = match Config::load() {
        Ok(c) => Arc::new(c),
        Err(_) => {
            tracing::error!(error = "PROXY_BACKEND_URL is required", "Failed to load configuration");
            std::process::exit(1);
        }
    };

    // Parse backend URL.
    let target: http::Uri = match cfg.backend_url.parse() {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(url = %cfg.backend_url, error = %e, "Invalid backend URL");
            std::process::exit(1);
        }
    };

    // Load challenge template.
    let template_src = match std::fs::read_to_string("challenge.html") {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "Failed to load templates");
            std::process::exit(1);
        }
    };

    metrics::init();

    let rl = Arc::new(RateLimiter::new());

    // Discord alerter (optional). Created before the XDP blocker so the L4 stats
    // loop can drive flood alerts through it.
    let alerter = cfg
        .discord_webhook_url
        .as_deref()
        .filter(|u| !u.is_empty())
        .map(|u| {
            tracing::info!(webhook = "<redacted>", "Discord DDoS alerting enabled");
            discord::DiscordAlerter::new(u.to_string(), cfg.max_req_per_sec, rl.clone())
        });

    // XDP blocker (optional, Linux + feature `xdp`).
    let xdp_blocker: Option<Arc<dyn xdp::Blocker>> = if !cfg.xdp_interface.is_empty() {
        #[cfg(all(target_os = "linux", feature = "xdp"))]
        {
            tracing::info!(interface = %cfg.xdp_interface, "Initializing XDP blocker");
            match xdp::init_xdp(&cfg.xdp_interface) {
                Ok(b) => {
                    let blocker: Arc<dyn xdp::Blocker> = Arc::new(b);
                    spawn_xdp_stats(blocker.clone(), cfg.clone(), alerter.clone());
                    Some(blocker)
                }
                Err(e) => {
                    // Non-fatal (unlike the Go version, which exits): the proxy
                    // is fully functional without L4 acceleration, so a failed
                    // XDP attach must not take the service down.
                    tracing::error!(error = %e, "Failed to initialize XDP; continuing without L4 blocking");
                    None
                }
            }
        }
        #[cfg(not(all(target_os = "linux", feature = "xdp")))]
        {
            tracing::warn!(
                interface = %cfg.xdp_interface,
                "PROXY_XDP_INTERFACE is set but this build has no XDP support \
                 (build with --features xdp on Linux); continuing without L4 blocking"
            );
            None
        }
    } else {
        tracing::info!("XDP blocking is disabled (PROXY_XDP_INTERFACE not set)");
        None
    };

    let proxy = Arc::new(Proxy::new(target.clone(), cfg.clone()));

    let manager = Manager::new(cfg.clone(), rl.clone(), template_src, xdp_blocker, proxy, alerter);

    // Rate limiter reset ticker (every second).
    {
        let rl = rl.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(1));
            ticker.tick().await;
            loop {
                ticker.tick().await;
                rl.reset();
            }
        });
    }

    let ip_limiter = if cfg.prometheus_enabled {
        tracing::info!(endpoint = "/metrics", "Prometheus metrics enabled");
        Some(IPLimiter::new())
    } else {
        None
    };

    tracing::info!(
        port = %cfg.port,
        backend = %cfg.backend_url,
        max_req_per_sec = cfg.max_req_per_sec,
        max_conn_per_sec = cfg.max_conn_per_sec,
        always_on = cfg.always_on,
        prometheus_enabled = cfg.prometheus_enabled,
        ssl_enabled = cfg.enable_ssl,
        "Starting proxy server",
    );

    if cfg.enable_ssl {
        tls::serve_tls(cfg.clone(), manager.clone(), rl.clone(), ip_limiter.clone(), target).await;
    } else {
        serve_plain(cfg.clone(), manager.clone(), rl.clone(), ip_limiter.clone()).await;
    }
}

/// Plain HTTP server on `cfg.port`.
async fn serve_plain(
    cfg: Arc<Config>,
    manager: Arc<Manager>,
    rl: Arc<RateLimiter>,
    ip_limiter: Option<Arc<IPLimiter>>,
) {
    let addr = format!("0.0.0.0:{}", cfg.port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(error = %e, addr = %addr, "Server failed");
            std::process::exit(1);
        }
    };

    let mut sigint = signal_future();

    loop {
        tokio::select! {
            _ = &mut sigint => {
                tracing::info!("Shutting down server...");
                break;
            }
            accept = listener.accept() => {
                let (stream, peer) = match accept {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                rl.inc_conn();
                let manager = manager.clone();
                let ip_limiter = ip_limiter.clone();
                let remote = peer.to_string();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let service = service_fn(move |req: Request<Incoming>| {
                        let manager = manager.clone();
                        let ip_limiter = ip_limiter.clone();
                        let ctx = ReqCtx { is_tls: false, remote_addr: remote.clone() };
                        async move { route(req, ctx, manager, ip_limiter).await }
                    });
                    let _ = auto::Builder::new(TokioExecutor::new())
                        .serve_connection_with_upgrades(io, service)
                        .await;
                });
            }
        }
    }

    tracing::info!("Server exited properly");
}

/// Route a request: `/metrics`, `/healthz`, and `/admin/` bypass the WAF;
/// everything else goes through the WAF middleware.
pub async fn route(
    req: Request<Incoming>,
    ctx: ReqCtx,
    manager: Arc<Manager>,
    ip_limiter: Option<Arc<IPLimiter>>,
) -> Result<Response<BoxedBody>, Infallible> {
    if manager.config().prometheus_enabled && req.uri().path() == "/metrics" {
        return Ok(metrics_endpoint(&ctx, ip_limiter.as_deref()));
    }
    let path = req.uri().path();
    if path.starts_with("/ddos-proxy/admin") {
        return Ok(admin::handle(req, ctx, manager).await);
    }
    let cfg = manager.config();
    if cfg.healthz_enabled && path == cfg.healthz_path {
        return Ok(health::handle(manager.proxy(), &cfg.healthz_backend_path.clone()).await);
    }
    Ok(manager.handle(req, ctx).await)
}

fn metrics_endpoint(ctx: &ReqCtx, ip_limiter: Option<&IPLimiter>) -> Response<BoxedBody> {
    let ip = ctx
        .remote_addr
        .rsplit_once(':')
        .map(|(h, _)| h.to_string())
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

/// Future that resolves on SIGINT or SIGTERM.
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

/// Per-second XDP stats logging + metrics, mirroring the Go goroutine, plus the
/// L4-flood detection state machine that drives Discord alerts.
#[cfg(all(target_os = "linux", feature = "xdp"))]
fn spawn_xdp_stats(
    blocker: Arc<dyn xdp::Blocker>,
    cfg: Arc<Config>,
    alerter: Option<Arc<discord::DiscordAlerter>>,
) {
    use crate::discord::{L4Event, L4Reasons};

    // Seconds between progress updates while a flood is ongoing.
    const L4_UPDATE_INTERVAL: i64 = 180;
    // Minimum gap between successive flood-start alerts (avoids flap-spam).
    const L4_INITIAL_COOLDOWN: i64 = 60;
    // Consecutive sub-threshold seconds required before declaring all-clear.
    const L4_CLEAR_GRACE: u32 = 5;

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        let mut prev = blocker.get_stats().unwrap_or_default();

        let threshold = cfg.xdp_alert_pps;
        let l4_enabled = alerter.is_some() && threshold > 0;
        let mut l4_active = false;
        let mut l4_started_at: i64 = 0;
        let mut l4_last_sent_at: i64 = 0;
        let mut l4_peak_pps: u64 = 0;
        let mut below_count: u32 = 0;

        // Saturating per-second delta that tolerates counter resets/wraps.
        let delta = |cur: u64, prev: u64| if cur >= prev { cur - prev } else { cur };

        ticker.tick().await;
        loop {
            ticker.tick().await;
            let stats = match blocker.get_stats() {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to get XDP stats");
                    continue;
                }
            };

            let delta_allowed = delta(stats.allowed, prev.allowed);
            let delta_blocked = delta(stats.blocked, prev.blocked);
            let reasons = L4Reasons {
                blocklist:    delta(stats.drop_blocklist,     prev.drop_blocklist),
                udp:          delta(stats.drop_udp,           prev.drop_udp),
                tcp_malformed:delta(stats.drop_tcp_malformed, prev.drop_tcp_malformed),
                http_invalid: delta(stats.drop_http_invalid,  prev.drop_http_invalid),
                tls_invalid:  delta(stats.drop_tls_invalid,   prev.drop_tls_invalid),
                icmp:         delta(stats.drop_icmp,          prev.drop_icmp),
                bad_flags:    delta(stats.drop_bad_flags,     prev.drop_bad_flags),
                fragment:     delta(stats.drop_fragment,      prev.drop_fragment),
                amplify:      delta(stats.drop_amplify,       prev.drop_amplify),
                syn_flood:    delta(stats.drop_syn_flood,     prev.drop_syn_flood),
            };

            if delta_allowed > 0 || delta_blocked > 0 {
                tracing::info!(allowed = delta_allowed, blocked = delta_blocked, "XDP Stats (per sec)");
            }

            if cfg.prometheus_enabled {
                if delta_allowed > 0 {
                    metrics::XDP_PACKETS.with_label_values(&["allowed"]).inc_by(delta_allowed);
                }
                if delta_blocked > 0 {
                    metrics::XDP_PACKETS.with_label_values(&["blocked"]).inc_by(delta_blocked);
                }
                for (reason, n) in [
                    ("blocklist",     reasons.blocklist),
                    ("udp",           reasons.udp),
                    ("tcp_malformed", reasons.tcp_malformed),
                    ("http_invalid",  reasons.http_invalid),
                    ("tls_invalid",   reasons.tls_invalid),
                    ("icmp",          reasons.icmp),
                    ("bad_flags",     reasons.bad_flags),
                    ("fragment",      reasons.fragment),
                    ("amplify",       reasons.amplify),
                    ("syn_flood",     reasons.syn_flood),
                ] {
                    if n > 0 {
                        metrics::XDP_DROPS.with_label_values(&[reason]).inc_by(n);
                    }
                }
            }

            // ── L4 flood alert state machine ──────────────────────────────────
            let pps = delta_blocked;
            let (dominant_type, _) = discord::classify_l4_reasons(&reasons);

            if cfg.prometheus_enabled {
                metrics::xdp_l4_flood_state(
                    if l4_active { Some(dominant_type) } else { None },
                    pps as i64,
                );
            }

            if l4_enabled {
                let now = unix_secs();
                if pps >= threshold as u64 {
                    below_count = 0;
                    if pps > l4_peak_pps {
                        l4_peak_pps = pps;
                    }
                    if !l4_active {
                        if now - l4_last_sent_at >= L4_INITIAL_COOLDOWN {
                            l4_active = true;
                            l4_started_at = now;
                            l4_last_sent_at = now;
                            let fps = blocker.top_fingerprints(3).unwrap_or_default();
                            if let Some(a) = &alerter {
                                a.notify_l4(L4Event::Start, pps, l4_peak_pps, reasons, fps).await;
                            }
                        }
                    } else if now - l4_last_sent_at >= L4_UPDATE_INTERVAL {
                        l4_last_sent_at = now;
                        let fps = blocker.top_fingerprints(3).unwrap_or_default();
                        if let Some(a) = &alerter {
                            a.notify_l4(L4Event::Update, pps, l4_peak_pps, reasons, fps).await;
                        }
                    }
                } else if l4_active {
                    below_count += 1;
                    if below_count >= L4_CLEAR_GRACE {
                        let duration_secs = now - l4_started_at;
                        if let Some(a) = &alerter {
                            a.notify_l4(
                                L4Event::Clear { duration_secs },
                                pps,
                                l4_peak_pps,
                                reasons,
                                Vec::new(),
                            )
                            .await;
                        }
                        let _ = blocker.clear_fingerprints();
                        l4_active = false;
                        l4_last_sent_at = now;
                        l4_peak_pps = 0;
                        below_count = 0;
                    }
                }
            }

            prev = stats;
        }
    });
}

/// Current Unix time in seconds.
#[cfg(all(target_os = "linux", feature = "xdp"))]
fn unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
