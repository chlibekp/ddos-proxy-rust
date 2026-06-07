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
    /// Per-IP rate-limit window: the unix second in which ip_req_count started.
    pub ip_req_window: AtomicI64,
    /// Requests counted in the current ip_req_window second.
    pub ip_req_count: AtomicI64,
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
            ip_req_count: AtomicI64::new(0),
        }
    }
}
