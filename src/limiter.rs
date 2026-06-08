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
    /// Every incoming request entering the WAF (allowed OR challenged/blocked),
    /// counted within the current 1-second window.
    total_req_count: AtomicI64,
    /// Snapshot of `total_req_count` for the previous *complete* second, taken at
    /// reset. Reading this always yields a full-second figure (true req/s) rather
    /// than a partial in-progress count.
    last_second_total: AtomicI64,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset the request, connection and whitelist counts to zero.
    /// The total-incoming counter is snapshotted into `last_second_total` first
    /// so consumers can read an accurate full-second req/s.
    pub fn reset(&self) {
        let total = self.total_req_count.swap(0, Ordering::SeqCst);
        self.last_second_total.store(total, Ordering::SeqCst);
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

    /// Count one incoming request (regardless of whether it is allowed, challenged
    /// or blocked). Used to measure true incoming traffic rate for alerting.
    pub fn inc_total(&self) {
        self.total_req_count.fetch_add(1, Ordering::SeqCst);
    }

    /// Total incoming requests over the previous complete second (true req/s).
    pub fn get_last_second_total(&self) -> i64 {
        self.last_second_total.load(Ordering::SeqCst)
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
