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
use crate::proxy::{Proxy, ReqCtx};
use crate::util::{is_websocket_upgrade, now_millis, now_unix};
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

        let manager = Arc::new(Manager {
            cfg,
            rl,
            env,
            xdp,
            proxy,
            alerter,
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

        for entry in self.ip_states.iter() {
            let key = entry.key().clone();
            let state = entry.value();
            let mut inner = state.inner.lock().unwrap();

            // Expire verification.
            if inner.verified && now_ms - inner.verified_at_ms > verify_ms {
                inner.verified = false;
                state.verified_flag.store(false, Ordering::SeqCst);
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

    fn render_challenge(&self, err: &str, site_key: &str, original_url: &str, salt: &str) -> String {
        let tmpl = self.env.get_template("challenge.html").unwrap();
        tmpl.render(context! {
            error => err,
            site_key => site_key,
            original_url => original_url,
            pow_salt => salt,
            pow_difficulty => self.cfg.pow_difficulty,
        })
        .unwrap_or_default()
    }

    fn serve_challenge(&self, ip: &str, host: &str, original_url: &str, err: &str) -> Response<BoxedBody> {
        let salt = match self.get_client_state(ip, host) {
            Some(state) => {
                let mut inner = state.inner.lock().unwrap();
                if inner.pow_salt.is_empty() {
                    inner.pow_salt = random_hex_16();
                }
                inner.challenge_served_at_ms = now_millis();
                inner.pow_salt.clone()
            }
            None => random_hex_16(),
        };

        let body = self.render_challenge(err, &self.cfg.turnstile_site_key, original_url, &salt);

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

        let ip = self.get_client_ip(&req, &ctx);

        // ── IP denylist: always blocked, before anything else ────────────
        if crate::netmatch::ip_in_list(&ip, &self.cfg.deny_ips) {
            if self.prom() {
                metrics::dropped("ip_denylist");
            }
            if self.cfg.block_action == "close" {
                return close_response();
            }
            return forbidden_response();
        }

        // ── Trusted IPs bypass the WAF entirely ──────────────────────────
        if crate::netmatch::ip_in_list(&ip, &self.cfg.trusted_ips) {
            if self.prom() {
                metrics::allowed("trusted_ip");
            }
            return self.proxy.handle(req, &ctx).await;
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

        let host = req
            .headers()
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_default();
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
        if self
            .cfg
            .exempt_paths
            .iter()
            .any(|prefix| path.starts_with(prefix.as_str()))
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

        if self.cfg.auto_mitigation_on_timeout {
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
        }
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
            let (salt, served_at) = {
                let inner = state.inner.lock().unwrap();
                (inner.pow_salt.clone(), inner.challenge_served_at_ms)
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
            let target_prefix = "0".repeat(self.cfg.pow_difficulty);
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
        }
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
    use super::{safe_redirect_path, strip_port};

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
