use once_cell::sync::Lazy;
use prometheus::{Encoder, IntCounter, IntCounterVec, Opts, Registry, TextEncoder};

/// Dedicated registry (equivalent to Go's promauto default registry).
pub static REGISTRY: Lazy<Registry> = Lazy::new(Registry::new);

pub static DROPPED_REQUESTS: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new(
            "ddos_proxy_dropped_requests_total",
            "The total number of dropped requests",
        ),
        &["reason"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

pub static CHALLENGED_REQUESTS: Lazy<IntCounter> = Lazy::new(|| {
    let c = IntCounter::new(
        "ddos_proxy_challenged_requests_total",
        "The total number of challenged requests",
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

pub static ALLOWED_REQUESTS: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new(
            "ddos_proxy_allowed_requests_total",
            "The total number of allowed requests",
        ),
        &["reason"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

pub static XDP_PACKETS: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new(
            "ddos_proxy_xdp_packets_total",
            "The total number of packets processed by XDP",
        ),
        &["action"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

/// Initialise counters to 0 so they appear in metrics output immediately,
/// matching the Go `init()` behaviour.
pub fn init() {
    DROPPED_REQUESTS.with_label_values(&["blocked_ip"]).inc_by(0);
    DROPPED_REQUESTS
        .with_label_values(&["challenge_violation"])
        .inc_by(0);
    DROPPED_REQUESTS
        .with_label_values(&["whitelist_rate_limit"])
        .inc_by(0);
    DROPPED_REQUESTS
        .with_label_values(&["metrics_rate_limit"])
        .inc_by(0);
    XDP_PACKETS.with_label_values(&["allowed"]).inc_by(0);
    XDP_PACKETS.with_label_values(&["blocked"]).inc_by(0);
}

/// Convenience helpers (only meaningful when prometheus is enabled; callers gate).
pub fn dropped(reason: &str) {
    DROPPED_REQUESTS.with_label_values(&[reason]).inc();
}

pub fn allowed(reason: &str) {
    ALLOWED_REQUESTS.with_label_values(&[reason]).inc();
}

pub fn challenged() {
    CHALLENGED_REQUESTS.inc();
}

/// Gather and encode metrics in Prometheus text format.
pub fn gather() -> (Vec<u8>, String) {
    let encoder = TextEncoder::new();
    let metric_families = REGISTRY.gather();
    let mut buf = Vec::new();
    encoder.encode(&metric_families, &mut buf).unwrap();
    (buf, encoder.format_type().to_string())
}
