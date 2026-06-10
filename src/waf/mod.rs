mod client;

pub use client::ClientState;

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use http::header::{HeaderName, HeaderValue};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Limited};
use hyper::body::Incoming;
use minijinja::{context, Environment};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::body::{empty, full, BoxedBody};
use crate::config::Config;
use crate::discord::DiscordAlerter;
use crate::limiter::RateLimiter;
use crate::metrics;
use crate::netmatch::IpCidr;
use crate::proxy::{Proxy, ReqCtx};
use crate::util::{ct_eq, is_websocket_upgrade, normalize_path, now_millis, now_unix};
use crate::xdp::Blocker;

pub struct Manager {
    cfg: Arc<Config>,
    rl: Arc<RateLimiter>,
    env: Environment<'static>,
    xdp: Option<Arc<dyn Blocker>>,
    proxy: Arc<Proxy>,
    alerter: Option<Arc<DiscordAlerter>>,
    mitigation_until: AtomicI64,   // unix seconds
    mitigation_started_at: AtomicI64, // unix seconds; when the current mitigation window began
    js_challenge_until: AtomicI64, // unix seconds; while set, escalate cookie→JS challenge
    /// Admin-toggled maintenance mode: while set, all WAF-routed traffic gets a
    /// 503 maintenance page (the admin API itself is routed before the WAF and
    /// stays reachable to turn it back off).
    maintenance_mode: AtomicBool,
    timeout_count: AtomicI64,
    ip_states: DashMap<String, Arc<ClientState>>,
    ip_state_count: AtomicI64,
    /// Requests currently in flight through the WAF (tracked when
    /// `PROXY_MAX_INFLIGHT` is set; drives the inflight gauge and global cap).
    inflight: Arc<AtomicI64>,
    /// Runtime-managed IP deny/trust lists (admin API), checked alongside the
    /// static `PROXY_DENY_IPS` / `PROXY_TRUSTED_IPS` config lists. Entries keep
    /// their original string form for listing and removal.
    dyn_deny: std::sync::RwLock<Vec<(String, IpCidr)>>,
    dyn_trust: std::sync::RwLock<Vec<(String, IpCidr)>>,
    /// Per-path rate-limit counters, aligned with `cfg.path_rate_limits`.
    path_rates: Vec<PathRate>,
    /// Unix second the manager started (for uptime reporting).
    started_at_unix: i64,
    /// Shared HTTP client for Turnstile siteverify calls. Built once and reused so
    /// every challenge verification doesn't spin up a fresh connection pool, and a
    /// bounded timeout keeps a slow/hung Turnstile endpoint from pinning request
    /// handler tasks open under load.
    http_client: reqwest::Client,
}

/// Maximum accepted body size for the `POST /challenge/verify` form. The form
/// carries only a nonce/token plus a short URL, so anything larger is abuse;
/// capping it stops an attacker from forcing the proxy to buffer huge bodies.
const MAX_VERIFY_BODY: usize = 64 * 1024;

/// Per-second counter for one `PROXY_PATH_RATE_LIMITS` prefix.
struct PathRate {
    prefix: String,
    limit: i64,
    window: AtomicI64,
    count: AtomicI64,
}

/// Decrements the wrapped counter on drop and refreshes the inflight gauge.
/// Held for the lifetime of a request to track global in-flight count.
struct CounterGuard(Arc<AtomicI64>);

impl Drop for CounterGuard {
    fn drop(&mut self) {
        let v = self.0.fetch_sub(1, Ordering::SeqCst) - 1;
        metrics::set_inflight(v);
    }
}

/// Decrements the per-client in-flight counter on drop
/// (`PROXY_MAX_CONCURRENT_PER_IP`).
struct StateInflightGuard(Arc<ClientState>);

impl Drop for StateInflightGuard {
    fn drop(&mut self) {
        self.0.inflight.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Manager {
    pub fn new(
        cfg: Arc<Config>,
        rl: Arc<RateLimiter>,
        template_src: String,
        xdp: Option<Arc<dyn Blocker>>,
        proxy: Arc<Proxy>,
        alerter: Option<Arc<DiscordAlerter>>,
    ) -> Arc<Self> {
        let mut env = Environment::new();
        env.add_template_owned("challenge.html", template_src)
            .expect("invalid challenge template");

        let path_rates = cfg
            .path_rate_limits
            .iter()
            .map(|(prefix, limit)| PathRate {
                prefix: prefix.clone(),
                limit: *limit,
                window: AtomicI64::new(0),
                count: AtomicI64::new(0),
            })
            .collect();

        let manager = Arc::new(Manager {
            cfg,
            rl,
            env,
            xdp,
            proxy,
            alerter,
            inflight: Arc::new(AtomicI64::new(0)),
            dyn_deny: std::sync::RwLock::new(Vec::new()),
            dyn_trust: std::sync::RwLock::new(Vec::new()),
            path_rates,
            started_at_unix: now_unix(),
            mitigation_until: AtomicI64::new(0),
            mitigation_started_at: AtomicI64::new(0),
            js_challenge_until: AtomicI64::new(0),
            maintenance_mode: AtomicBool::new(false),
            timeout_count: AtomicI64::new(0),
            ip_states: DashMap::new(),
            ip_state_count: AtomicI64::new(0),
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
        });

        // Cleanup ticker (10s cadence), mirroring Go.
        let weak = Arc::downgrade(&manager);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(10));
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let Some(m) = weak.upgrade() else { break };
                m.cleanup();
            }
        });

        manager
    }

    fn prom(&self) -> bool {
        self.cfg.prometheus_enabled
    }

    pub fn proxy(&self) -> Arc<crate::proxy::Proxy> {
        self.proxy.clone()
    }

    pub fn config(&self) -> &Arc<Config> {
        &self.cfg
    }

    fn get_client_ip<B>(&self, req: &Request<B>, ctx: &ReqCtx) -> String {
        if self.cfg.cloudflare_support {
            if let Some(cf) = req
                .headers()
                .get("cf-connecting-ip")
                .and_then(|v| v.to_str().ok())
            {
                if !cf.is_empty() {
                    return cf.to_string();
                }
            }
        }
        if self.cfg.use_forwarded_for {
            if let Some(fwd) = req
                .headers()
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
            {
                if !fwd.is_empty() {
                    let first = fwd.split(',').next().unwrap_or("").trim();
                    if !first.is_empty() {
                        return first.to_string();
                    }
                }
            }
        }
        // RemoteAddr → strip port.
        strip_port(&ctx.remote_addr)
    }

    fn get_client_state(&self, ip: &str, host: &str) -> Option<Arc<ClientState>> {
        let h = strip_port(host);
        let key = format!("{ip}|{h}");

        if let Some(existing) = self.ip_states.get(&key) {
            return Some(existing.clone());
        }

        if self.cfg.max_ip_states > 0
            && self.ip_state_count.load(Ordering::SeqCst) >= self.cfg.max_ip_states
        {
            if self.prom() {
                metrics::ip_states_cap_hit();
            }
            return None;
        }

        let state = Arc::new(ClientState::default());
        state.last_seen.store(now_unix(), Ordering::SeqCst);
        match self.ip_states.entry(key) {
            dashmap::mapref::entry::Entry::Occupied(e) => Some(e.get().clone()),
            dashmap::mapref::entry::Entry::Vacant(e) => {
                let arc = state.clone();
                e.insert(state);
                self.ip_state_count.fetch_add(1, Ordering::SeqCst);
                Some(arc)
            }
        }
    }

    fn block_l4(&self, ip: &str) {
        if let Some(x) = &self.xdp {
            tracing::info!(ip = ip, "Blocking IP on L4 via XDP");
            if let Err(e) = x.block_ip(ip) {
                tracing::error!(ip = ip, error = %e, "Failed to add XDP block rule");
            }
        }
    }

    fn unblock_l4(&self, ip: &str) {
        if let Some(x) = &self.xdp {
            tracing::info!(ip = ip, "Unblocking IP on L4 via XDP");
            if let Err(e) = x.unblock_ip(ip) {
                tracing::error!(ip = ip, error = %e, "Failed to remove XDP block rule");
            }
        }
    }

    fn cleanup(&self) {
        let now_s = now_unix();
        let now_ms = now_millis();
        let mitigation_end = self.mitigation_until.load(Ordering::SeqCst);
        let attack_ended = now_s > mitigation_end;
        let verify_ms = self.cfg.verify_time.as_millis() as i64;

        self.timeout_count.store(0, Ordering::SeqCst);

        let mut to_delete: Vec<String> = Vec::new();
        let mut to_unblock: Vec<String> = Vec::new();
        // Count challenges that were issued but never solved before eviction.
        let mut abandoned: u64 = 0;
        // Eviction reason counters for Prometheus.
        let mut evicted_mitigation_ended: u64 = 0;
        let mut evicted_idle: u64 = 0;
        let mut verified_count: i64 = 0;

        for entry in self.ip_states.iter() {
            let key = entry.key().clone();
            let state = entry.value();
            let mut inner = state.inner.lock().unwrap();

            // Expire verification.
            if inner.verified && now_ms - inner.verified_at_ms > verify_ms {
                inner.verified = false;
                state.verified_flag.store(false, Ordering::SeqCst);
            }
            if inner.verified {
                verified_count += 1;
            }

            if attack_ended && !self.cfg.always_on && !inner.verified {
                if inner.challenge_served {
                    abandoned += 1;
                }
                evicted_mitigation_ended += 1;
                to_delete.push(key);
                continue;
            }

            // Unblock after 5 minutes.
            if inner.blocked && now_ms - inner.blocked_at_ms > 5 * 60 * 1000 {
                inner.blocked = false;
                state.blocked_flag.store(false, Ordering::SeqCst);
                inner.violation_count = 0;
                inner.challenge_served = false;
                inner.error_count = 0;
                if inner.l4_blocked {
                    inner.l4_blocked = false;
                    if let Some(ip) = key.split('|').next() {
                        to_unblock.push(ip.to_string());
                    }
                }
            }

            // Evict idle unverified entries.
            if !inner.verified && now_s - state.last_seen.load(Ordering::SeqCst) > 10 * 60 {
                if inner.challenge_served {
                    abandoned += 1;
                }
                evicted_idle += 1;
                to_delete.push(key.clone());
            }
        }

        for key in to_delete {
            if self.ip_states.remove(&key).is_some() {
                self.ip_state_count.fetch_sub(1, Ordering::SeqCst);
            }
        }
        for ip in to_unblock {
            self.unblock_l4(&ip);
        }

        if self.prom() {
            metrics::set_ip_states(self.ip_state_count.load(Ordering::SeqCst));
            metrics::set_verified_clients(verified_count);
            if abandoned > 0 {
                metrics::challenge_abandoned(abandoned);
            }
            if evicted_mitigation_ended > 0 {
                metrics::ip_states_evicted("mitigation_ended", evicted_mitigation_ended);
            }
            if evicted_idle > 0 {
                metrics::ip_states_evicted("idle", evicted_idle);
            }
        }
    }

    /// Count this request toward the per-IP rate window and return `true` if the
    /// configured limit is exceeded for the current second.
    ///
    /// Uses Relaxed ordering throughout — minor inaccuracies at second boundaries
    /// are acceptable for rate limiting.
    fn check_per_ip_rate(&self, state: &Arc<ClientState>, now_s: i64) -> bool {
        let Some(max) = self.cfg.max_req_per_ip else {
            return false;
        };
        let window = state.ip_req_window.load(Ordering::Relaxed);
        let count = if now_s > window {
            // New second: reset the window. Concurrent resets (race) are harmless —
            // at worst we lose one or two counts at the boundary, which is fine.
            state.ip_req_window.store(now_s, Ordering::Relaxed);
            state.ip_req_count.store(1, Ordering::Relaxed);
            1
        } else {
            state.ip_req_count.fetch_add(1, Ordering::Relaxed) + 1
        };
        count > max
    }

    /// Whether `ip` is denied by the static config list or the runtime list.
    fn ip_denied(&self, ip: &str) -> bool {
        if crate::netmatch::ip_in_list(ip, &self.cfg.deny_ips) {
            return true;
        }
        let list = self.dyn_deny.read().unwrap();
        if list.is_empty() {
            return false;
        }
        let Ok(addr) = ip.parse::<std::net::IpAddr>() else {
            return false;
        };
        list.iter().any(|(_, c)| c.contains(addr))
    }

    /// Whether `ip` is trusted by the static config list or the runtime list.
    fn ip_trusted(&self, ip: &str) -> bool {
        if crate::netmatch::ip_in_list(ip, &self.cfg.trusted_ips) {
            return true;
        }
        let list = self.dyn_trust.read().unwrap();
        if list.is_empty() {
            return false;
        }
        let Ok(addr) = ip.parse::<std::net::IpAddr>() else {
            return false;
        };
        list.iter().any(|(_, c)| c.contains(addr))
    }

    /// Count this request toward the first matching per-path rate window and
    /// return `true` when that prefix is over its configured req/s limit.
    fn check_path_rate(&self, norm_path: &str, now_s: i64) -> bool {
        for pr in &self.path_rates {
            if norm_path.starts_with(pr.prefix.as_str()) {
                let window = pr.window.load(Ordering::Relaxed);
                let count = if now_s > window {
                    pr.window.store(now_s, Ordering::Relaxed);
                    pr.count.store(1, Ordering::Relaxed);
                    1
                } else {
                    pr.count.fetch_add(1, Ordering::Relaxed) + 1
                };
                return count > pr.limit;
            }
        }
        false
    }

    /// PoW difficulty to issue right now: the harder attack difficulty while a
    /// mitigation window is active (when configured), else the base difficulty.
    fn effective_pow_difficulty(&self, now_s: i64) -> usize {
        match self.cfg.pow_difficulty_attack {
            Some(d) if now_s < self.mitigation_until.load(Ordering::SeqCst) => d,
            _ => self.cfg.pow_difficulty,
        }
    }

    /// Record a backend 404 for scanner detection; blocks the client once it
    /// exceeds `max` 404s within a 60-second window.
    fn note_404(&self, state: &Arc<ClientState>, max: i64) {
        let now_s = now_unix();
        let should_block = {
            let mut inner = state.inner.lock().unwrap();
            if now_s - inner.not_found_window_s >= 60 {
                inner.not_found_window_s = now_s;
                inner.not_found_count = 0;
            }
            inner.not_found_count += 1;
            if inner.not_found_count > max && !inner.blocked {
                inner.blocked = true;
                inner.blocked_at_ms = now_millis();
                true
            } else {
                false
            }
        };
        if should_block {
            state.blocked_flag.store(true, Ordering::SeqCst);
            if self.prom() {
                metrics::dropped("scanner_404");
            }
            tracing::info!("Blocking client after excessive 404s (scanner behaviour)");
        }
    }

    fn render_challenge(
        &self,
        err: &str,
        site_key: &str,
        original_url: &str,
        salt: &str,
        difficulty: usize,
    ) -> String {
        let tmpl = self.env.get_template("challenge.html").unwrap();
        tmpl.render(context! {
            error => err,
            site_key => site_key,
            original_url => original_url,
            pow_salt => salt,
            pow_difficulty => difficulty,
        })
        .unwrap_or_default()
    }

    fn serve_challenge(&self, ip: &str, host: &str, original_url: &str, err: &str) -> Response<BoxedBody> {
        // Adaptive PoW: issue the harder attack difficulty during mitigation.
        // The issued difficulty is remembered per client so verification accepts
        // exactly what the client was asked to solve.
        let difficulty = self.effective_pow_difficulty(now_unix());
        let salt = match self.get_client_state(ip, host) {
            Some(state) => {
                let mut inner = state.inner.lock().unwrap();
                if inner.pow_salt.is_empty() {
                    inner.pow_salt = random_hex_16();
                }
                inner.challenge_served_at_ms = now_millis();
                inner.pow_difficulty_issued = difficulty;
                inner.pow_salt.clone()
            }
            None => random_hex_16(),
        };

        let body = self.render_challenge(
            err,
            &self.cfg.turnstile_site_key,
            original_url,
            &salt,
            difficulty,
        );

        if self.prom() {
            metrics::challenged();
        }

        let mut resp = Response::new(full(body));
        *resp.status_mut() = StatusCode::IM_A_TEAPOT;
        let h = resp.headers_mut();
        h.insert(HeaderName::from_static("x-mitigation"), HeaderValue::from_static("challenge"));
        h.insert(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("no-cache, no-store, must-revalidate"),
        );
        h.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        );
        resp
    }

    /// Check whether the request carries a valid cookie-challenge cookie matching
    /// the token we issued to this client.
    fn cookie_valid<B>(&self, req: &Request<B>, state: &Arc<ClientState>) -> bool {
        let token = {
            let inner = state.inner.lock().unwrap();
            inner.cookie_token.clone()
        };
        if token.is_empty() {
            return false;
        }
        for hv in req.headers().get_all(http::header::COOKIE) {
            if let Ok(s) = hv.to_str() {
                for pair in s.split(';') {
                    let pair = pair.trim();
                    if let Some(val) = pair.strip_prefix(&format!("{COOKIE_NAME}=")) {
                        if val == token {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Serve the lightweight cookie challenge: issue a token cookie and bounce the
    /// client back to the original URL with a 307 redirect. Browsers replay the
    /// request with the cookie set; trivial floods that ignore Set-Cookie/redirects
    /// are filtered out here without the cost of the JS challenge.
    fn serve_cookie_challenge(&self, state: &Arc<ClientState>, original_url: &str, is_tls: bool) -> Response<BoxedBody> {
        let token = {
            let mut inner = state.inner.lock().unwrap();
            if inner.cookie_token.is_empty() {
                inner.cookie_token = random_hex_16();
            }
            inner.cookie_token.clone()
        };

        let max_age = self.cfg.verify_time.as_secs().max(1);
        // SameSite=None; Secure is required for cross-site contexts (e.g. subrequests,
        // iframes) — SameSite=Lax is blocked by browsers in those cases. SameSite=None
        // requires the Secure attribute, so fall back to no SameSite on plain HTTP.
        let samesite = if is_tls { "; SameSite=None; Secure" } else { "" };
        let cookie = format!(
            "{COOKIE_NAME}={token}; Path=/; Max-Age={max_age}; HttpOnly{samesite}"
        );

        let mut resp = Response::new(empty());
        *resp.status_mut() = StatusCode::TEMPORARY_REDIRECT;
        let h = resp.headers_mut();
        if let Ok(hv) = HeaderValue::from_str(&cookie) {
            h.insert(http::header::SET_COOKIE, hv);
        }
        let loc = safe_redirect_path(original_url);
        if let Ok(hv) = HeaderValue::from_str(&loc) {
            h.insert(http::header::LOCATION, hv);
        }
        h.insert(HeaderName::from_static("x-mitigation"), HeaderValue::from_static("cookie"));
        h.insert(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("no-cache, no-store, must-revalidate"),
        );
        resp
    }

    /// Main WAF entry point.
    pub async fn handle(self: &Arc<Self>, req: Request<Incoming>, ctx: ReqCtx) -> Response<BoxedBody> {
        // Count every incoming request (allowed, challenged, or blocked) so the
        // alerter can report true incoming traffic rate, not just proxied requests.
        self.rl.inc_total();

        // ── Global in-flight cap ─────────────────────────────────────────
        // The guard decrements on drop, covering every return path below.
        let _global_inflight = if let Some(max) = self.cfg.max_inflight {
            let cur = self.inflight.fetch_add(1, Ordering::SeqCst) + 1;
            let guard = CounterGuard(self.inflight.clone());
            metrics::set_inflight(cur);
            if cur > max {
                if self.prom() {
                    metrics::dropped("inflight_cap");
                }
                return text_response(StatusCode::SERVICE_UNAVAILABLE, "Server Busy");
            }
            Some(guard)
        } else {
            None
        };

        let ip = self.get_client_ip(&req, &ctx);

        // ── IP denylist (config + runtime): always blocked, first ────────
        if self.ip_denied(&ip) {
            if self.prom() {
                metrics::dropped("ip_denylist");
            }
            if self.cfg.block_action == "close" {
                return close_response();
            }
            return forbidden_response();
        }

        // ── Trusted IPs (config + runtime) bypass the WAF entirely ───────
        // Including maintenance mode, so operators can verify the site while
        // it is closed to the public.
        if self.ip_trusted(&ip) {
            if self.prom() {
                metrics::allowed("trusted_ip");
            }
            return self.proxy.handle(req, &ctx).await;
        }

        // ── Maintenance mode ─────────────────────────────────────────────
        if self.maintenance_mode.load(Ordering::SeqCst) {
            if self.prom() {
                metrics::dropped("maintenance");
            }
            return maintenance_response();
        }

        // ── HTTP method allowlist ────────────────────────────────────────
        if !self.cfg.allowed_methods.is_empty()
            && !self
                .cfg
                .allowed_methods
                .iter()
                .any(|m| m == req.method().as_str())
        {
            if self.prom() {
                metrics::dropped("method_not_allowed");
            }
            return text_response(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
        }

        // ── URI length cap ───────────────────────────────────────────────
        if let Some(max) = self.cfg.max_uri_len {
            let uri_len = req
                .uri()
                .path_and_query()
                .map(|p| p.as_str().len())
                .unwrap_or(0);
            if uri_len > max {
                if self.prom() {
                    metrics::dropped("uri_too_long");
                }
                return text_response(StatusCode::URI_TOO_LONG, "URI Too Long");
            }
        }

        // ── Declared body-size cap ───────────────────────────────────────
        // Checked against Content-Length only: the proxy streams bodies, so this
        // rejects declared oversized uploads cheaply before they hit the backend.
        if let Some(max) = self.cfg.max_body_size {
            let declared = req
                .headers()
                .get(http::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok());
            if declared.is_some_and(|len| len > max) {
                if self.prom() {
                    metrics::dropped("body_too_large");
                }
                return text_response(StatusCode::PAYLOAD_TOO_LARGE, "Payload Too Large");
            }
        }

        let host = req
            .headers()
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_default();

        // ── Host allowlist ───────────────────────────────────────────────
        if !self.cfg.allowed_hosts.is_empty() {
            let h = strip_port(&host).to_lowercase();
            if !self.cfg.allowed_hosts.iter().any(|a| host_matches(a, &h)) {
                if self.prom() {
                    metrics::dropped("host_not_allowed");
                }
                return forbidden_response();
            }
        }

        // Normalized path (dot segments resolved, duplicate slashes collapsed)
        // used for all path-based security matching below; the original path is
        // forwarded upstream untouched.
        let norm_path = normalize_path(req.uri().path());

        // ── Blocked path prefixes ────────────────────────────────────────
        if self
            .cfg
            .blocked_paths
            .iter()
            .any(|p| norm_path.starts_with(p.as_str()))
        {
            if self.prom() {
                metrics::dropped("blocked_path");
            }
            return forbidden_response();
        }

        // ── Regex WAF rule (raw path + query) ────────────────────────────
        if let Some(re) = &self.cfg.block_regex {
            let pq = req
                .uri()
                .path_and_query()
                .map(|p| p.as_str())
                .unwrap_or("/");
            if re.is_match(pq) {
                if self.prom() {
                    metrics::dropped("block_regex");
                }
                return forbidden_response();
            }
        }

        if is_websocket_upgrade(&req) {
            return self.proxy.handle(req, &ctx).await;
        }

        let ua = req
            .headers()
            .get(http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        // ── Require a User-Agent ─────────────────────────────────────────
        if self.cfg.require_ua && ua.is_empty() {
            if self.prom() {
                metrics::dropped("no_user_agent");
            }
            return forbidden_response();
        }

        // Blocked UA check (known-bad bots / scrapers).
        if !self.cfg.blocked_ua.is_empty() {
            let ua_lower = ua.to_lowercase();
            if self.cfg.blocked_ua.iter().any(|bad| ua_lower.contains(bad.as_str())) {
                if self.prom() {
                    metrics::dropped("ua_denylist");
                }
                return forbidden_response();
            }
        }

        // Whitelisted UA check.
        if !self.cfg.whitelisted_ua.is_empty() {
            for wua in &self.cfg.whitelisted_ua {
                if ua.contains(wua.as_str()) {
                    if self.rl.get_whitelist_req_count() >= self.cfg.whitelist_rate_limit {
                        if self.prom() {
                            metrics::dropped("whitelist_rate_limit");
                        }
                        return text_response(StatusCode::TOO_MANY_REQUESTS, "Rate Limit Exceeded");
                    }
                    self.rl.inc_whitelist_req();
                    if self.prom() {
                        metrics::allowed("whitelist");
                    }
                    return self.proxy.handle(req, &ctx).await;
                }
            }
        }

        // ── Site-wide Basic auth gate (staging protection) ───────────────
        if let Some(expected) = &self.cfg.basic_auth {
            let provided = req
                .headers()
                .get(http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if !ct_eq(provided.as_bytes(), expected.as_bytes()) {
                if self.prom() {
                    metrics::dropped("basic_auth");
                }
                let mut resp = text_response(StatusCode::UNAUTHORIZED, "Unauthorized");
                resp.headers_mut().insert(
                    http::header::WWW_AUTHENTICATE,
                    HeaderValue::from_static("Basic realm=\"restricted\""),
                );
                return resp;
            }
        }

        let original_url = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
        let path = req.uri().path().to_string();

        let now_s = now_unix();
        let now_ms = now_millis();

        let state = match self.get_client_state(&ip, &host) {
            Some(s) => s,
            None => {
                // ipStates cap hit — serve challenge without tracking.
                return self.serve_challenge(&ip, &host, &original_url, "");
            }
        };
        state.last_seen.store(now_s, Ordering::SeqCst);

        // ── Honeypot paths: instant block ────────────────────────────────
        // No legitimate user requests these; anything touching them is hostile.
        if self
            .cfg
            .honeypot_paths
            .iter()
            .any(|p| norm_path.starts_with(p.as_str()))
        {
            {
                let mut inner = state.inner.lock().unwrap();
                inner.blocked = true;
                inner.blocked_at_ms = now_ms;
            }
            state.blocked_flag.store(true, Ordering::SeqCst);
            if self.prom() {
                metrics::dropped("honeypot");
            }
            tracing::info!(ip = %ip, path = %norm_path, "Honeypot path hit; blocking client");
            if self.cfg.block_action == "close" {
                return close_response();
            }
            return forbidden_response();
        }

        // ── Per-IP concurrency cap ───────────────────────────────────────
        // The guard decrements on drop, covering every return path below.
        let _ip_inflight = if let Some(max) = self.cfg.max_concurrent_per_ip {
            let cur = state.inflight.fetch_add(1, Ordering::SeqCst) + 1;
            let guard = StateInflightGuard(state.clone());
            if cur > max {
                if self.prom() {
                    metrics::dropped("per_ip_concurrency");
                }
                return text_response(StatusCode::TOO_MANY_REQUESTS, "Too Many Concurrent Requests");
            }
            Some(guard)
        } else {
            None
        };

        // ── Blocked fast-path ────────────────────────────────────────────
        if state.blocked_flag.load(Ordering::SeqCst) {
            let mut inner = state.inner.lock().unwrap();
            if inner.blocked {
                if !self.cfg.cloudflare_support && !self.cfg.use_forwarded_for {
                    if !inner.l4_blocked {
                        inner.error_count += 1;
                        if inner.error_count > 5 {
                            inner.l4_blocked = true;
                            drop(inner);
                            self.block_l4(&ip);
                            return close_response();
                        }
                        // else fall through to block action
                    } else {
                        drop(inner);
                        return close_response();
                    }
                }
                drop(inner);
                if self.prom() {
                    metrics::dropped("blocked_ip");
                }
                if self.cfg.block_action == "close" {
                    return close_response();
                }
                return forbidden_response();
            }
        }

        // ── Challenge-exempt paths ───────────────────────────────────────
        // Webhooks / machine-to-machine endpoints that can't solve challenges.
        // Placed after the blocked fast-path so blocked IPs stay blocked here,
        // but before any challenge logic so these paths are never challenged.
        // Matched on the normalized path so `/api/../admin` can't slip through.
        if self
            .cfg
            .exempt_paths
            .iter()
            .any(|prefix| norm_path.starts_with(prefix.as_str()))
        {
            self.rl.inc_req();
            if self.prom() {
                metrics::allowed("exempt_path");
            }
            return self.proxy.handle(req, &ctx).await;
        }

        // ── Verified fast-path ───────────────────────────────────────────
        if state.verified_flag.load(Ordering::SeqCst)
            && now_s < state.verified_until.load(Ordering::SeqCst)
        {
            if self.prom() {
                metrics::allowed("verified");
            }
            return self.proxy.handle(req, &ctx).await;
        }

        // Expire stale verified state under lock (no await while holding the guard).
        let serve_verified = {
            let mut inner = state.inner.lock().unwrap();
            if inner.verified {
                if now_ms - inner.verified_at_ms < self.cfg.verify_time.as_millis() as i64 {
                    true
                } else {
                    inner.verified = false;
                    state.verified_flag.store(false, Ordering::SeqCst);
                    false
                }
            } else {
                false
            }
        };
        if serve_verified {
            if self.prom() {
                metrics::allowed("verified");
            }
            return self.proxy.handle(req, &ctx).await;
        }

        if path == "/challenge/verify" {
            return self.verify_challenge(req, &ctx).await;
        }

        // Per-IP rate limit: if this IP exceeds PROXY_MAX_REQ_PER_IP req/s,
        // challenge it directly without touching the global mitigation window.
        // This lets the proxy stay open for all other clients while the single
        // fast IP is challenged.
        let per_ip_over_limit = self.check_per_ip_rate(&state, now_s);
        if per_ip_over_limit {
            tracing::debug!(ip = %ip, "per-IP rate limit exceeded; serving challenge");
            if self.prom() {
                metrics::per_ip_rate_limited();
            }
        }

        // Per-path rate limit: an over-limit prefix (e.g. /login) is served the
        // challenge without opening a global mitigation window. Folded into the
        // same escalation path as the per-IP limit (straight to JS/PoW).
        let path_over_limit = self.check_path_rate(&norm_path, now_s);
        if path_over_limit {
            tracing::debug!(path = %norm_path, "per-path rate limit exceeded; serving challenge");
            if self.prom() {
                metrics::path_rate_limited();
            }
        }
        let per_ip_over_limit = per_ip_over_limit || path_over_limit;

        // Global rate-limit / mitigation evaluation.
        let (req_rate, conn_rate) = self.rl.get_counts();
        let mitigation_until = self.mitigation_until.load(Ordering::SeqCst);
        let mitigation_secs = self.cfg.mitigation_time.as_secs() as i64;
        let mut should_serve_challenge = self.cfg.always_on || per_ip_over_limit;

        if req_rate >= self.cfg.max_req_per_sec || conn_rate >= self.cfg.max_conn_per_sec {
            let already_mitigating = now_s < mitigation_until;
            if already_mitigating {
                // Still under attack while mitigation is active. Escalate to JS
                // challenge only after the cookie challenge has had 30 seconds to
                // filter the attack — if the attack is still bypassing after that
                // window, the cookie challenge isn't enough.
                let started_at = self.mitigation_started_at.load(Ordering::SeqCst);
                if self.cfg.cookie_challenge && now_s >= started_at + 30 {
                    self.js_challenge_until
                        .store(now_s + mitigation_secs, Ordering::SeqCst);
                    tracing::info!("DDoS attack bypassing cookie challenge after 30s; escalating to JS challenge");
                }
            } else {
                // New mitigation window — start with cookie challenge.
                self.mitigation_started_at.store(now_s, Ordering::SeqCst);
                // Clear any leftover JS-challenge window from a previous attack.
                self.js_challenge_until.store(0, Ordering::SeqCst);
                tracing::info!("DDoS mitigation started; serving cookie challenge");
            }
            self.mitigation_until
                .store(now_s + mitigation_secs, Ordering::SeqCst);
            should_serve_challenge = true;

            // Notify the Discord alerter of the new/extended mitigation window.
            if let Some(alerter) = &self.alerter {
                let alerter = alerter.clone();
                let mitigation_end = now_s + mitigation_secs;
                let tracked = self.ip_state_count.load(Ordering::SeqCst);
                tokio::spawn(async move {
                    alerter.notify_mitigation_active(mitigation_end, tracked).await;
                });
            }
        } else if now_s < mitigation_until {
            should_serve_challenge = true;
            // Keep the alerter's IP count fresh while the attack is ongoing.
            if let Some(alerter) = &self.alerter {
                alerter.update_ips(self.ip_state_count.load(Ordering::SeqCst));
            }
        } else if self.cfg.auto_mitigation_on_timeout
            && self.timeout_count.load(Ordering::SeqCst) >= self.cfg.max_timeouts
        {
            self.mitigation_until
                .store(now_s + mitigation_secs, Ordering::SeqCst);
            should_serve_challenge = true;
        }

        if should_serve_challenge {
            // Tier 1: cookie challenge. Only fall through to the heavier JS
            // challenge once we've detected the cookie challenge is being bypassed
            // (js_challenge_until in the future) or it's disabled entirely.
            // Per-IP rate-limited requests skip tier-1 entirely: a fast single IP
            // can trivially solve a cookie redirect, so we go straight to JS/PoW.
            let js_mode = per_ip_over_limit
                || !self.cfg.cookie_challenge
                || now_s < self.js_challenge_until.load(Ordering::SeqCst);

            if !js_mode {
                if self.cookie_valid(&req, &state) {
                    // Passed the cookie challenge — promote this IP to the verified
                    // allow-list so subsequent requests skip cookie re-checking entirely.
                    {
                        let mut inner = state.inner.lock().unwrap();
                        inner.verified = true;
                        inner.verified_at_ms = now_ms;
                        inner.violation_count = 0;
                        inner.challenge_served = false;
                    }
                    state.verified_flag.store(true, Ordering::SeqCst);
                    state.verified_until.store(
                        now_s + self.cfg.verify_time.as_secs() as i64,
                        Ordering::SeqCst,
                    );
                    self.rl.inc_req();
                    if self.prom() {
                        metrics::allowed("cookie");
                    }
                    return self.proxy.handle(req, &ctx).await;
                }
                if self.prom() {
                    metrics::challenged();
                }
                return self.serve_cookie_challenge(&state, &original_url, ctx.is_tls);
            }

            let mut inner = state.inner.lock().unwrap();
            if !inner.challenge_served {
                inner.challenge_served = true;
                inner.violation_count = 0;
            } else {
                inner.violation_count += 1;
                if inner.violation_count > self.cfg.max_failed_challenges {
                    inner.blocked = true;
                    inner.blocked_at_ms = now_ms;
                    state.blocked_flag.store(true, Ordering::SeqCst);
                    drop(inner);
                    if self.prom() {
                        metrics::dropped("challenge_violation");
                    }
                    if self.cfg.block_action == "close" {
                        return close_response();
                    }
                    return forbidden_response();
                }
            }
            drop(inner);
            return self.serve_challenge(&ip, &host, &original_url, "");
        }

        self.rl.inc_req();
        if self.prom() {
            metrics::allowed("normal");
        }

        let resp = if self.cfg.auto_mitigation_on_timeout {
            let start = Instant::now();
            let resp = self.proxy.handle(req, &ctx).await;
            let duration = start.elapsed();
            let status = resp.status();
            if duration >= self.cfg.timeout_threshold
                || status == StatusCode::GATEWAY_TIMEOUT
                || status == StatusCode::BAD_GATEWAY
            {
                let count = self.timeout_count.fetch_add(1, Ordering::SeqCst) + 1;
                if count >= self.cfg.max_timeouts {
                    self.mitigation_until
                        .store(now_unix() + mitigation_secs, Ordering::SeqCst);
                }
            }
            resp
        } else {
            self.proxy.handle(req, &ctx).await
        };

        // Scanner detection: clients racking up backend 404s are probing for
        // exploitable files; block them once they exceed the configured budget.
        if let Some(max) = self.cfg.max_404_per_ip {
            if resp.status() == StatusCode::NOT_FOUND {
                self.note_404(&state, max);
            }
        }

        resp
    }

    async fn verify_challenge(&self, req: Request<Incoming>, ctx: &ReqCtx) -> Response<BoxedBody> {
        if req.method() != http::Method::POST {
            return text_response(StatusCode::METHOD_NOT_ALLOWED, "Method not allowed");
        }

        let ip = self.get_client_ip(&req, ctx);
        let host = req
            .headers()
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_default();

        // Rate-limit /challenge/verify to at most PROXY_MAX_VERIFY_ATTEMPTS failed
        // submissions per IP per 60-second window. This prevents brute-forcing the PoW
        // nonce: without this guard an attacker can POST garbage indefinitely because
        // failed verifications don't increment the violation counter.
        if let Some(state) = self.get_client_state(&ip, &host) {
            let now_s = now_unix();
            let over_limit = {
                let mut inner = state.inner.lock().unwrap();
                // Reset the window if it started more than 60 seconds ago.
                if now_s - inner.verify_fail_window_s >= 60 {
                    inner.verify_fail_window_s = now_s;
                    inner.verify_fail_count = 0;
                }
                inner.verify_fail_count += 1;
                inner.verify_fail_count > self.cfg.max_verify_attempts
            };
            if over_limit {
                tracing::debug!(ip = %ip, "verify rate limit exceeded");
                if self.prom() {
                    metrics::verify_rate_limited();
                }
                return text_response(StatusCode::TOO_MANY_REQUESTS, "Too many verification attempts, please wait");
            }
        }

        // Read and parse form body, capping the size so a malicious client can't
        // make us buffer an arbitrarily large body.
        let body_bytes = match Limited::new(req.into_body(), MAX_VERIFY_BODY).collect().await {
            Ok(c) => c.to_bytes(),
            Err(_) => {
                if self.prom() {
                    metrics::dropped("challenge_invalid_form");
                }
                return self.serve_challenge(&ip, &host, "", "Invalid form data");
            }
        };
        let form = parse_form(&body_bytes);
        let get = |k: &str| form.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());

        if !self.cfg.turnstile_site_key.is_empty() {
            let token = get("cf-turnstile-response").unwrap_or_default();
            if token.is_empty() {
                if self.prom() {
                    metrics::dropped("challenge_empty_token");
                }
                return self.serve_challenge(&ip, &host, "", "Please complete the CAPTCHA");
            }
            if !self.verify_turnstile(&token, &ip).await {
                if self.prom() {
                    metrics::dropped("challenge_verification_failed");
                }
                return self.serve_challenge(&ip, &host, "", "CAPTCHA verification failed");
            }
        } else {
            let nonce = get("pow_nonce").unwrap_or_default();
            if nonce.is_empty() {
                if self.prom() {
                    metrics::dropped("challenge_empty_pow");
                }
                return self.serve_challenge(&ip, &host, "", "Please complete the PoW");
            }
            let state = match self.get_client_state(&ip, &host) {
                Some(s) => s,
                None => return self.serve_challenge(&ip, &host, "", "Invalid challenge session"),
            };
            let (salt, served_at, issued_difficulty) = {
                let inner = state.inner.lock().unwrap();
                (
                    inner.pow_salt.clone(),
                    inner.challenge_served_at_ms,
                    inner.pow_difficulty_issued,
                )
            };
            if salt.is_empty() {
                return self.serve_challenge(&ip, &host, "", "Invalid challenge session");
            }
            if now_millis() - served_at < 2000 {
                if self.prom() {
                    metrics::dropped("challenge_too_fast");
                }
                return self.serve_challenge(
                    &ip,
                    &host,
                    "",
                    "Challenge solved too quickly, please try again",
                );
            }
            let mut hasher = Sha256::new();
            hasher.update(format!("{salt}{nonce}").as_bytes());
            let hash_hex = hex::encode(hasher.finalize());
            // Verify against the difficulty this client was actually issued
            // (adaptive difficulty may differ from the current base setting).
            let difficulty = if issued_difficulty > 0 {
                issued_difficulty
            } else {
                self.cfg.pow_difficulty
            };
            let target_prefix = "0".repeat(difficulty);
            if !hash_hex.starts_with(&target_prefix) {
                if self.prom() {
                    metrics::dropped("challenge_pow_failed");
                }
                return self.serve_challenge(&ip, &host, "", "PoW verification failed");
            }
        }

        // Mark IP as verified.
        if let Some(state) = self.get_client_state(&ip, &host) {
            let now_ms = now_millis();
            // Capture the timestamp before clearing it so we can record solve latency.
            let challenge_issued_ms = {
                let mut inner = state.inner.lock().unwrap();
                let issued = inner.challenge_served_at_ms;
                inner.violation_count = 0;
                inner.challenge_served = false;
                inner.blocked = false;
                inner.verified = true;
                inner.verified_at_ms = now_ms;
                inner.pow_salt = String::new();
                inner.verify_fail_count = 0;
                issued
            };
            state.blocked_flag.store(false, Ordering::SeqCst);
            state.verified_flag.store(true, Ordering::SeqCst);
            state.verified_until.store(
                now_unix() + self.cfg.verify_time.as_secs() as i64,
                Ordering::SeqCst,
            );

            // Record how long the client took to solve the challenge.
            if self.prom() && challenge_issued_ms > 0 {
                let challenge_type = if self.cfg.turnstile_site_key.is_empty() {
                    "pow"
                } else {
                    "turnstile"
                };
                let elapsed_secs = (now_ms - challenge_issued_ms).max(0) as f64 / 1000.0;
                metrics::challenge_solved(challenge_type, elapsed_secs);
            }
        }

        // `original_url` is attacker-controlled here (it's just a hidden form
        // field, and the endpoint can be POSTed to directly), so it must be
        // validated to a same-origin path before being used as a redirect target.
        // Otherwise it's an open redirect: solve the challenge, get bounced to
        // any external site.
        let original_url = safe_redirect_path(&get("original_url").unwrap_or_default());

        if self.prom() {
            metrics::allowed("challenge_solved");
        }

        redirect_found(&original_url)
    }

    async fn verify_turnstile(&self, token: &str, remote_ip: &str) -> bool {
        let params = [
            ("secret", self.cfg.turnstile_secret_key.as_str()),
            ("response", token),
            ("remoteip", remote_ip),
        ];
        let resp = match self
            .http_client
            .post("https://challenges.cloudflare.com/turnstile/v0/siteverify")
            .form(&params)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(error = %e, "Turnstile verification failed");
                return false;
            }
        };
        #[derive(serde::Deserialize)]
        struct Tr {
            success: bool,
        }
        match resp.json::<Tr>().await {
            Ok(t) => t.success,
            Err(e) => {
                tracing::error!(error = %e, "Failed to decode Turnstile response");
                false
            }
        }
    }
}

// ── Admin API types and methods ──────────────────────────────────────────────

/// Snapshot of a single tracked IP|Host state, returned by the admin API.
#[derive(serde::Serialize)]
pub struct StateInfo {
    pub key: String,
    pub blocked: bool,
    pub verified: bool,
    pub verified_until_unix: i64,
    pub last_seen_unix: i64,
    pub violation_count: i64,
    pub challenge_served: bool,
    pub l4_blocked: bool,
    pub error_count: i64,
}

/// Current mitigation / rate-limiting status, returned by GET /admin/status.
#[derive(serde::Serialize)]
pub struct MitigationStatus {
    pub mitigation_active: bool,
    pub mitigation_until_unix: i64,
    pub mitigation_started_at_unix: i64,
    pub js_challenge_active: bool,
    pub js_challenge_until_unix: i64,
    pub ip_state_count: i64,
    pub maintenance_active: bool,
    pub uptime_secs: i64,
    pub version: String,
}

impl Manager {
    /// Return a snapshot of every tracked IP|Host state.
    pub fn list_states(&self) -> Vec<StateInfo> {
        self.ip_states
            .iter()
            .map(|entry| {
                let key = entry.key().clone();
                let state = entry.value();
                let inner = state.inner.lock().unwrap();
                StateInfo {
                    key,
                    blocked: inner.blocked,
                    verified: inner.verified,
                    verified_until_unix: state.verified_until.load(Ordering::SeqCst),
                    last_seen_unix: state.last_seen.load(Ordering::SeqCst),
                    violation_count: inner.violation_count,
                    challenge_served: inner.challenge_served,
                    l4_blocked: inner.l4_blocked,
                    error_count: inner.error_count,
                }
            })
            .collect()
    }

    /// Look up a single state by its canonical `ip|host` key.
    pub fn get_state_by_key(&self, key: &str) -> Option<StateInfo> {
        let entry = self.ip_states.get(key)?;
        let state = entry.value();
        let inner = state.inner.lock().unwrap();
        Some(StateInfo {
            key: key.to_string(),
            blocked: inner.blocked,
            verified: inner.verified,
            verified_until_unix: state.verified_until.load(Ordering::SeqCst),
            last_seen_unix: state.last_seen.load(Ordering::SeqCst),
            violation_count: inner.violation_count,
            challenge_served: inner.challenge_served,
            l4_blocked: inner.l4_blocked,
            error_count: inner.error_count,
        })
    }

    /// Snapshot of current mitigation state and tracked IP count.
    pub fn get_status(&self) -> MitigationStatus {
        let now_s = now_unix();
        let mitigation_until = self.mitigation_until.load(Ordering::SeqCst);
        let js_challenge_until = self.js_challenge_until.load(Ordering::SeqCst);
        MitigationStatus {
            mitigation_active: now_s < mitigation_until,
            mitigation_until_unix: mitigation_until,
            mitigation_started_at_unix: self.mitigation_started_at.load(Ordering::SeqCst),
            js_challenge_active: now_s < js_challenge_until,
            js_challenge_until_unix: js_challenge_until,
            ip_state_count: self.ip_state_count.load(Ordering::SeqCst),
            maintenance_active: self.maintenance_active(),
            uptime_secs: now_s - self.started_at_unix,
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// Remove every tracked client state (admin). L4 blocks held by tracked
    /// states are released. Returns the number of states cleared.
    pub fn clear_states(&self) -> i64 {
        let mut l4_ips: Vec<String> = Vec::new();
        for entry in self.ip_states.iter() {
            let inner = entry.value().inner.lock().unwrap();
            if inner.l4_blocked {
                if let Some(ip) = entry.key().split('|').next() {
                    l4_ips.push(ip.to_string());
                }
            }
        }
        self.ip_states.clear();
        let cleared = self.ip_state_count.swap(0, Ordering::SeqCst);
        for ip in l4_ips {
            self.unblock_l4(&ip);
        }
        tracing::info!(cleared = cleared, "Admin: cleared all IP states");
        cleared
    }

    /// Force the global mitigation window on (for `mitigation_time`) or off.
    pub fn set_mitigation(&self, on: bool) {
        let now_s = now_unix();
        if on {
            self.mitigation_started_at.store(now_s, Ordering::SeqCst);
            self.mitigation_until.store(
                now_s + self.cfg.mitigation_time.as_secs() as i64,
                Ordering::SeqCst,
            );
        } else {
            self.mitigation_until.store(0, Ordering::SeqCst);
            self.js_challenge_until.store(0, Ordering::SeqCst);
        }
        tracing::info!(enabled = on, "Admin: mitigation window toggled");
    }

    /// List runtime deny- or trust-list entries (admin).
    pub fn list_dyn_ips(&self, deny: bool) -> Vec<String> {
        let list = if deny { &self.dyn_deny } else { &self.dyn_trust };
        list.read().unwrap().iter().map(|(s, _)| s.clone()).collect()
    }

    /// Add an IP/CIDR to the runtime deny- or trust-list (admin).
    /// Returns false when the entry is invalid; duplicates are no-ops.
    pub fn add_dyn_ip(&self, deny: bool, entry: &str) -> bool {
        let entry = entry.trim();
        let Some(cidr) = IpCidr::parse(entry) else {
            return false;
        };
        let list = if deny { &self.dyn_deny } else { &self.dyn_trust };
        let mut guard = list.write().unwrap();
        if !guard.iter().any(|(s, _)| s == entry) {
            guard.push((entry.to_string(), cidr));
        }
        tracing::info!(entry = entry, deny = deny, "Admin: runtime IP list entry added");
        true
    }

    /// Remove an entry from the runtime deny- or trust-list (admin).
    /// Returns true when an entry was actually removed.
    pub fn remove_dyn_ip(&self, deny: bool, entry: &str) -> bool {
        let entry = entry.trim();
        let list = if deny { &self.dyn_deny } else { &self.dyn_trust };
        let mut guard = list.write().unwrap();
        let before = guard.len();
        guard.retain(|(s, _)| s != entry);
        let removed = guard.len() < before;
        if removed {
            tracing::info!(entry = entry, deny = deny, "Admin: runtime IP list entry removed");
        }
        removed
    }

    /// Wipe the proxy disk cache (admin). `None` when caching is disabled.
    pub fn purge_cache(&self) -> Option<usize> {
        self.proxy.purge_cache()
    }

    /// Whether admin-toggled maintenance mode is currently on.
    pub fn maintenance_active(&self) -> bool {
        self.maintenance_mode.load(Ordering::SeqCst)
    }

    /// Toggle maintenance mode. While on, every WAF-routed request receives a
    /// 503 maintenance page; `/metrics`, `/healthz` and the admin API stay up.
    pub fn set_maintenance(&self, on: bool) {
        self.maintenance_mode.store(on, Ordering::SeqCst);
        tracing::info!(enabled = on, "Admin: maintenance mode toggled");
    }

    /// Administratively block an IP+host. Creates the client state if needed.
    pub fn manual_block(&self, ip: &str, host: &str) {
        let state = match self.get_client_state(ip, host) {
            Some(s) => s,
            None => return,
        };
        let now_ms = crate::util::now_millis();
        let mut inner = state.inner.lock().unwrap();
        inner.blocked = true;
        inner.blocked_at_ms = now_ms;
        drop(inner);
        state.blocked_flag.store(true, Ordering::SeqCst);
        tracing::info!(ip = ip, host = host, "Admin: manually blocked IP");
    }

    /// Administratively unblock an IP+host, clearing violation counts.
    /// Also removes the XDP L4 block if one was active.
    pub fn manual_unblock(&self, ip: &str, host: &str) {
        let h = strip_port(host);
        let key = format!("{ip}|{h}");
        let needs_l4_unblock = if let Some(entry) = self.ip_states.get(&key) {
            let state = entry.value();
            let mut inner = state.inner.lock().unwrap();
            let was_l4 = inner.l4_blocked;
            inner.blocked = false;
            inner.blocked_at_ms = 0;
            inner.violation_count = 0;
            inner.l4_blocked = false;
            drop(inner);
            state.blocked_flag.store(false, Ordering::SeqCst);
            was_l4
        } else {
            false
        };
        if needs_l4_unblock {
            self.unblock_l4(ip);
        }
        tracing::info!(ip = ip, host = host, "Admin: manually unblocked IP");
    }
}

/// Name of the cookie issued by the tier-1 cookie challenge.
const COOKIE_NAME: &str = "__ddos_clearance";

fn strip_port(addr: &str) -> String {
    // Strip a trailing ":port" if present (handles host:port and ip:port).
    match addr.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) && !port.is_empty() => {
            host.trim_matches(|c| c == '[' || c == ']').to_string()
        }
        _ => addr.to_string(),
    }
}

/// Match a lowercase, port-stripped host against an allowlist entry: exact
/// match, or `*.example.com` matching any subdomain (but not the apex).
fn host_matches(entry: &str, host: &str) -> bool {
    if let Some(suffix) = entry.strip_prefix("*.") {
        host.len() > suffix.len() + 1 && host.ends_with(suffix)
            && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
    } else {
        entry == host
    }
}

fn parse_form(body: &[u8]) -> Vec<(String, String)> {
    url::form_urlencoded::parse(body)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

/// Validate a redirect target so it can only point back at this origin.
///
/// Returns the URL unchanged when it is a safe same-origin absolute path, else
/// falls back to `/`. This blocks open redirects: a value must start with a
/// single `/` and must not be a scheme-relative (`//host`) or backslash-tricked
/// (`/\host`) URL, and must not contain control characters that could smuggle
/// extra header content.
fn safe_redirect_path(url: &str) -> String {
    let ok = url.starts_with('/')
        && !url.starts_with("//")
        && !url.starts_with("/\\")
        && !url.bytes().any(|b| b < 0x20 || b == 0x7f);
    if ok {
        url.to_string()
    } else {
        "/".to_string()
    }
}

fn random_hex_16() -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

fn text_response(status: StatusCode, msg: &str) -> Response<BoxedBody> {
    let mut resp = Response::new(full(format!("{msg}\n")));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp
}

fn forbidden_response() -> Response<BoxedBody> {
    text_response(StatusCode::FORBIDDEN, "Forbidden")
}

/// Equivalent of hijack-and-close: an empty 403 that closes the connection.
/// (Go closes the TCP connection directly; hyper's nearest equivalent is an
/// empty response with `Connection: close`.)
fn close_response() -> Response<BoxedBody> {
    let mut resp = Response::new(empty());
    *resp.status_mut() = StatusCode::FORBIDDEN;
    resp.headers_mut()
        .insert(http::header::CONNECTION, HeaderValue::from_static("close"));
    resp
}

/// 503 page served while maintenance mode is on.
fn maintenance_response() -> Response<BoxedBody> {
    const MAINTENANCE_HTML: &str = "<!DOCTYPE html>\
<html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<title>Maintenance</title>\
<style>body{font-family:system-ui,sans-serif;background:#0f1117;color:#e2e8f0;\
display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}\
div{text-align:center}h1{font-size:1.6rem;margin-bottom:8px}p{color:#94a3b8}</style>\
</head><body><div><h1>We&rsquo;ll be right back</h1>\
<p>This site is undergoing scheduled maintenance. Please try again shortly.</p>\
</div></body></html>";

    let mut resp = Response::new(full(MAINTENANCE_HTML));
    *resp.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
    let h = resp.headers_mut();
    h.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    h.insert(http::header::RETRY_AFTER, HeaderValue::from_static("300"));
    h.insert(
        http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache, no-store, must-revalidate"),
    );
    resp
}

fn redirect_found(location: &str) -> Response<BoxedBody> {
    let mut resp = Response::new(empty());
    *resp.status_mut() = StatusCode::FOUND;
    if let Ok(hv) = HeaderValue::from_str(location) {
        resp.headers_mut().insert(http::header::LOCATION, hv);
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::{host_matches, safe_redirect_path, strip_port};

    #[test]
    fn host_matches_exact_and_wildcard() {
        assert!(host_matches("example.com", "example.com"));
        assert!(!host_matches("example.com", "www.example.com"));
        assert!(host_matches("*.example.com", "www.example.com"));
        assert!(host_matches("*.example.com", "a.b.example.com"));
        // Wildcard does not match the apex or unrelated suffixes.
        assert!(!host_matches("*.example.com", "example.com"));
        assert!(!host_matches("*.example.com", "evilexample.com"));
        assert!(!host_matches("*.example.com", "other.com"));
    }

    #[test]
    fn safe_redirect_allows_local_paths() {
        assert_eq!(safe_redirect_path("/"), "/");
        assert_eq!(safe_redirect_path("/dashboard"), "/dashboard");
        assert_eq!(safe_redirect_path("/a/b?c=d&e=f"), "/a/b?c=d&e=f");
    }

    #[test]
    fn safe_redirect_blocks_open_redirects() {
        // Scheme-relative and absolute URLs must collapse to "/".
        assert_eq!(safe_redirect_path("//evil.com"), "/");
        assert_eq!(safe_redirect_path("https://evil.com"), "/");
        assert_eq!(safe_redirect_path("http://evil.com/path"), "/");
        // Backslash trick some browsers normalise to "//".
        assert_eq!(safe_redirect_path("/\\evil.com"), "/");
        // Empty / non-rooted values.
        assert_eq!(safe_redirect_path(""), "/");
        assert_eq!(safe_redirect_path("evil.com"), "/");
    }

    #[test]
    fn safe_redirect_blocks_control_chars() {
        // CR/LF (header smuggling) and other control bytes are rejected.
        assert_eq!(safe_redirect_path("/foo\r\nSet-Cookie: x=1"), "/");
        assert_eq!(safe_redirect_path("/foo\nbar"), "/");
    }

    #[test]
    fn strip_port_handles_plain_and_bracketed() {
        assert_eq!(strip_port("1.2.3.4:8080"), "1.2.3.4");
        assert_eq!(strip_port("example.com"), "example.com");
        assert_eq!(strip_port("[::1]:443"), "::1");
    }
}
