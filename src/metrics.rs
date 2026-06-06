use once_cell::sync::Lazy;
use prometheus::{Encoder, Histogram, HistogramOpts, IntCounter, IntCounterVec, IntGauge, Opts, Registry, TextEncoder};

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

/// Backend HTTP response counter, labelled by status class: 2xx, 3xx, 4xx, 5xx, or error.
pub static BACKEND_RESPONSES: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new(
            "ddos_proxy_backend_responses_total",
            "Total responses received from the backend, by HTTP status class",
        ),
        &["status_class"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

/// Backend request round-trip duration histogram (time to first response headers).
pub static BACKEND_REQUEST_DURATION: Lazy<Histogram> = Lazy::new(|| {
    let h = Histogram::with_opts(
        HistogramOpts::new(
            "ddos_proxy_backend_request_duration_seconds",
            "Backend request duration in seconds (time to first response headers)",
        )
        .buckets(vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]),
    )
    .unwrap();
    REGISTRY.register(Box::new(h.clone())).unwrap();
    h
});

/// Current number of tracked per-IP client states. Updated every 10 s by the cleanup ticker.
pub static IP_STATES: Lazy<IntGauge> = Lazy::new(|| {
    let g = IntGauge::new(
        "ddos_proxy_ip_states_current",
        "Current number of tracked per-IP client states",
    )
    .unwrap();
    REGISTRY.register(Box::new(g.clone())).unwrap();
    g
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
    BACKEND_RESPONSES.with_label_values(&["2xx"]).inc_by(0);
    BACKEND_RESPONSES.with_label_values(&["3xx"]).inc_by(0);
    BACKEND_RESPONSES.with_label_values(&["4xx"]).inc_by(0);
    BACKEND_RESPONSES.with_label_values(&["5xx"]).inc_by(0);
    BACKEND_RESPONSES.with_label_values(&["error"]).inc_by(0);
    // Force Lazy initialisation so the histogram and gauge appear on the first scrape.
    let _ = &*BACKEND_REQUEST_DURATION;
    let _ = &*IP_STATES;
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

pub fn backend_response(status_class: &str) {
    BACKEND_RESPONSES.with_label_values(&[status_class]).inc();
}

pub fn backend_duration(secs: f64) {
    BACKEND_REQUEST_DURATION.observe(secs);
}

pub fn set_ip_states(count: i64) {
    IP_STATES.set(count);
}

/// Map an HTTP status code to its class label: "2xx", "3xx", "4xx", "5xx".
/// Any code outside the 100–599 range returns "other".
pub fn status_class(code: u16) -> &'static str {
    match code {
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "other",
    }
}

/// Gather and encode metrics in Prometheus text format.
pub fn gather() -> (Vec<u8>, String) {
    let encoder = TextEncoder::new();
    let metric_families = REGISTRY.gather();
    let mut buf = Vec::new();
    encoder.encode(&metric_families, &mut buf).unwrap();
    (buf, encoder.format_type().to_string())
}

#[cfg(test)]
mod tests {
    use super::status_class;

    #[test]
    fn status_class_maps_correctly() {
        assert_eq!(status_class(200), "2xx");
        assert_eq!(status_class(201), "2xx");
        assert_eq!(status_class(204), "2xx");
        assert_eq!(status_class(299), "2xx");
        assert_eq!(status_class(301), "3xx");
        assert_eq!(status_class(304), "3xx");
        assert_eq!(status_class(307), "3xx");
        assert_eq!(status_class(400), "4xx");
        assert_eq!(status_class(403), "4xx");
        assert_eq!(status_class(404), "4xx");
        assert_eq!(status_class(429), "4xx");
        assert_eq!(status_class(500), "5xx");
        assert_eq!(status_class(502), "5xx");
        assert_eq!(status_class(503), "5xx");
        assert_eq!(status_class(100), "other");
        assert_eq!(status_class(600), "other");
    }
}
