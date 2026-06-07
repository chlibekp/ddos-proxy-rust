use once_cell::sync::Lazy;
use prometheus::{Encoder, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, Opts, Registry, TextEncoder};

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

/// How long it takes a client to solve a challenge (issue → successful verify).
/// Labelled by challenge_type: "pow" or "turnstile".
/// Buckets tuned so the bot-speed range (< 5 s) and typical human range (5–120 s) are
/// both visible, making automated solvers detectable as a spike in the lowest buckets.
pub static CHALLENGE_SOLVE_DURATION: Lazy<HistogramVec> = Lazy::new(|| {
    let h = HistogramVec::new(
        HistogramOpts::new(
            "ddos_proxy_challenge_solve_duration_seconds",
            "Time from challenge issue to successful verification, by challenge type",
        )
        .buckets(vec![2.0, 5.0, 10.0, 20.0, 30.0, 60.0, 120.0, 300.0]),
        &["challenge_type"],
    )
    .unwrap();
    REGISTRY.register(Box::new(h.clone())).unwrap();
    h
});

/// Challenges that were issued but the client state was evicted (idle timeout or end of
/// mitigation window) before the challenge was ever solved.
pub static CHALLENGE_ABANDONED: Lazy<IntCounter> = Lazy::new(|| {
    let c = IntCounter::new(
        "ddos_proxy_challenges_abandoned_total",
        "Challenges issued but never solved before the client state was evicted",
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

/// Requests that triggered the per-IP rate limit and were served a WAF challenge.
/// Only incremented when PROXY_MAX_REQ_PER_IP is configured.
pub static PER_IP_RATE_LIMITED: Lazy<IntCounter> = Lazy::new(|| {
    let c = IntCounter::new(
        "ddos_proxy_per_ip_rate_limited_total",
        "Requests served a WAF challenge because their source IP exceeded PROXY_MAX_REQ_PER_IP",
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
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
    // Force Lazy initialisation so histograms, vecs, and gauge appear on the first scrape.
    let _ = &*BACKEND_REQUEST_DURATION;
    let _ = &*IP_STATES;
    let _ = &*PER_IP_RATE_LIMITED;
    let _ = &*CHALLENGE_ABANDONED;
    // Touch both challenge_type label values so the series appear on the first scrape
    // (no observation is recorded — just ensures the label combination is initialised).
    let _ = CHALLENGE_SOLVE_DURATION.with_label_values(&["pow"]);
    let _ = CHALLENGE_SOLVE_DURATION.with_label_values(&["turnstile"]);
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

/// Record a successfully solved challenge.
/// `challenge_type` is `"pow"` or `"turnstile"`.
/// `elapsed_secs` is the wall-clock time from challenge issue to successful verification.
pub fn challenge_solved(challenge_type: &str, elapsed_secs: f64) {
    CHALLENGE_SOLVE_DURATION
        .with_label_values(&[challenge_type])
        .observe(elapsed_secs);
}

/// Increment the per-IP rate limit counter.
pub fn per_ip_rate_limited() {
    PER_IP_RATE_LIMITED.inc();
}

/// Record `count` challenges that were abandoned (client state evicted before solve).
pub fn challenge_abandoned(count: u64) {
    CHALLENGE_ABANDONED.inc_by(count);
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
    use super::*;

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

    #[test]
    fn challenge_solve_duration_records_observation() {
        // Record a solve time for each challenge type and verify the histogram sample
        // count increments (we read via gather() since the registry is global).
        let before = CHALLENGE_SOLVE_DURATION
            .with_label_values(&["pow"])
            .get_sample_count();
        challenge_solved("pow", 12.5);
        let after = CHALLENGE_SOLVE_DURATION
            .with_label_values(&["pow"])
            .get_sample_count();
        assert_eq!(after, before + 1);
    }

    #[test]
    fn challenge_abandoned_increments_counter() {
        let before = CHALLENGE_ABANDONED.get();
        challenge_abandoned(3);
        assert_eq!(CHALLENGE_ABANDONED.get(), before + 3);
    }

    #[test]
    fn per_ip_rate_limited_increments_counter() {
        let before = PER_IP_RATE_LIMITED.get();
        per_ip_rate_limited();
        per_ip_rate_limited();
        assert_eq!(PER_IP_RATE_LIMITED.get(), before + 2);
    }

    #[test]
    fn challenge_solve_duration_turnstile_independent_of_pow() {
        let pow_before = CHALLENGE_SOLVE_DURATION
            .with_label_values(&["pow"])
            .get_sample_count();
        challenge_solved("turnstile", 8.0);
        let pow_after = CHALLENGE_SOLVE_DURATION
            .with_label_values(&["pow"])
            .get_sample_count();
        // recording a "turnstile" observation must not affect the "pow" series
        assert_eq!(pow_before, pow_after);
    }
}
