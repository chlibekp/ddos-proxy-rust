use std::sync::atomic::{AtomicBool, AtomicI64};
use std::sync::Mutex;

/// Tracks the state of a single client IP (keyed by `IP|Host`).
///
/// The atomic fields form the lock-free fast path (read on every request); they
/// are always kept in sync with the mutex-protected canonical fields below.
pub struct ClientState {
    pub last_seen: AtomicI64,       // unix seconds
    pub blocked_flag: AtomicBool,
    pub verified_flag: AtomicBool,
    pub verified_until: AtomicI64,  // unix seconds when verification expires
    pub inner: Mutex<Inner>,
    /// Per-IP rate-limit window: the unix second of the last token refill.
    pub ip_req_window: AtomicI64,
    /// Token bucket for per-IP rate limiting (PROXY_MAX_REQ_PER_IP /
    /// PROXY_MAX_REQ_PER_IP_BURST). Starts at 0; the first request triggers a
    /// refill to the burst capacity, then each request consumes one token.
    /// Negative values mean the bucket is overdrawn.
    pub ip_tokens: AtomicI64,
    /// Requests from this client currently being proxied (in flight). Used by
    /// the PROXY_MAX_CONCURRENT_PER_IP cap.
    pub inflight: AtomicI64,
}

#[derive(Default)]
pub struct Inner {
    pub blocked: bool,
    pub blocked_at_ms: i64,
    pub violation_count: i64,
    pub challenge_served: bool,
    pub challenge_served_at_ms: i64,
    pub verified: bool,
    pub verified_at_ms: i64,
    pub pow_salt: String,
    pub error_count: i64,
    pub l4_blocked: bool,
    /// Token expected back in the cookie-challenge cookie for this client.
    pub cookie_token: String,
    /// Unix second at which the current verify-attempt window started.
    pub verify_fail_window_s: i64,
    /// Number of failed /challenge/verify submissions in the current window.
    pub verify_fail_count: i64,
    /// PoW difficulty the last served challenge was rendered with (0 = use the
    /// configured base difficulty). Lets verification accept the difficulty the
    /// client was actually given when adaptive difficulty changes mid-flight.
    pub pow_difficulty_issued: usize,
    /// Unix second at which the current 404-counting window started.
    pub not_found_window_s: i64,
    /// Backend 404 responses served to this client in the current window.
    pub not_found_count: i64,
}

impl Default for ClientState {
    fn default() -> Self {
        ClientState {
            last_seen: AtomicI64::new(0),
            blocked_flag: AtomicBool::new(false),
            verified_flag: AtomicBool::new(false),
            verified_until: AtomicI64::new(0),
            inner: Mutex::new(Inner::default()),
            ip_req_window: AtomicI64::new(0),
            ip_tokens: AtomicI64::new(0),
            inflight: AtomicI64::new(0),
        }
    }
}
