use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Tracks global request and connection rates. Safe for concurrent use.
/// Counters are reset every second by a ticker (see main).
#[derive(Default)]
pub struct RateLimiter {
    req_count: AtomicI64,
    conn_count: AtomicI64,
    whitelist_req_count: AtomicI64,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset the request, connection and whitelist counts to zero.
    pub fn reset(&self) {
        self.req_count.store(0, Ordering::SeqCst);
        self.conn_count.store(0, Ordering::SeqCst);
        self.whitelist_req_count.store(0, Ordering::SeqCst);
    }

    pub fn inc_req(&self) {
        self.req_count.fetch_add(1, Ordering::SeqCst);
    }

    pub fn inc_conn(&self) {
        self.conn_count.fetch_add(1, Ordering::SeqCst);
    }

    pub fn inc_whitelist_req(&self) {
        self.whitelist_req_count.fetch_add(1, Ordering::SeqCst);
    }

    /// Returns (request_count, connection_count).
    pub fn get_counts(&self) -> (i64, i64) {
        (
            self.req_count.load(Ordering::SeqCst),
            self.conn_count.load(Ordering::SeqCst),
        )
    }

    pub fn get_whitelist_req_count(&self) -> i64 {
        self.whitelist_req_count.load(Ordering::SeqCst)
    }
}

/// Limits requests per IP address: allows 1 request per second per IP.
/// Used only to protect the /metrics endpoint.
pub struct IPLimiter {
    visitors: Mutex<HashMap<String, Instant>>,
}

impl IPLimiter {
    pub fn new() -> std::sync::Arc<Self> {
        let limiter = std::sync::Arc::new(IPLimiter {
            visitors: Mutex::new(HashMap::new()),
        });
        // Background cleanup of stale entries, mirroring the Go goroutine.
        let weak = std::sync::Arc::downgrade(&limiter);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(60));
            ticker.tick().await; // consume immediate first tick
            loop {
                ticker.tick().await;
                let Some(l) = weak.upgrade() else { break };
                let now = Instant::now();
                let mut map = l.visitors.lock().unwrap();
                map.retain(|_, t| now.duration_since(*t) <= Duration::from_secs(60));
            }
        });
        limiter
    }

    /// Returns true if the request from `ip` is allowed (1 req/s).
    pub fn allow(&self, ip: &str) -> bool {
        let now = Instant::now();
        let mut map = self.visitors.lock().unwrap();
        if let Some(last) = map.get(ip) {
            if now.duration_since(*last) < Duration::from_secs(1) {
                return false;
            }
        }
        map.insert(ip.to_string(), now);
        true
    }
}
