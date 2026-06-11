use once_cell::sync::Lazy;
use prometheus::{Encoder, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry, TextEncoder};

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

/// XDP-dropped packets broken down by drop reason (blocklist, udp, tcp_malformed,
/// http_invalid, tls_invalid). Complements `XDP_PACKETS{action="blocked"}` with
/// the *why*, so the dominant attack vector is visible in Prometheus/Grafana.
pub static XDP_DROPS: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new(
            "ddos_proxy_xdp_drops_total",
            "Total packets dropped by XDP, broken down by drop reason",
        ),
        &["reason"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

/// XDP SYN-cookie (RST-cookie) authentication events, labelled by `event`:
/// `challenged` (a bogus SYN-ACK was emitted) and `validated` (a returning RST
/// proved the source genuine and whitelisted it). The ratio shows how many
/// challenged sources were real clients versus spoofed flood traffic.
pub static XDP_SYN_AUTH: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new(
            "ddos_proxy_xdp_syn_auth_total",
            "XDP SYN-cookie authentication events (challenged/validated)",
        ),
        &["event"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

/// Whether an L4/XDP flood is currently in progress, labelled by `attack_type`.
/// The gauge is 1 while the flood is active and 0 once it clears. Having the
/// attack type as a label means you can alert on a specific class (e.g. SYN flood)
/// directly in Prometheus/Grafana without parsing log lines.
pub static XDP_L4_FLOOD_ACTIVE: Lazy<IntGaugeVec> = Lazy::new(|| {
    let g = IntGaugeVec::new(
        Opts::new(
            "ddos_proxy_xdp_l4_flood_active",
            "1 while an L4/XDP flood is in progress, labelled by the dominant attack type",
        ),
        &["attack_type"],
    )
    .unwrap();
    REGISTRY.register(Box::new(g.clone())).unwrap();
    g
});

/// Total seconds spent under an active L4/XDP flood. Incremented every second
/// while `xdp_l4_flood_active > 0`. Useful for computing flood-time percentage
/// over an interval and for SLO burn-rate calculations.
pub static XDP_FLOOD_SECONDS: Lazy<IntCounter> = Lazy::new(|| {
    let c = IntCounter::new(
        "ddos_proxy_xdp_flood_seconds_total",
        "Total seconds the proxy has spent under an active L4/XDP flood",
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

/// Current dropped-packets-per-second rate as seen by the XDP stats loop.
/// Updated every second; gives Grafana a live pkt/s gauge without needing
/// Prometheus rate() over a counter.
pub static XDP_DROP_RATE: Lazy<IntGauge> = Lazy::new(|| {
    let g = IntGauge::new(
        "ddos_proxy_xdp_drop_rate_pps",
        "Current dropped-packets-per-second rate at the XDP layer (updated every second)",
    )
    .unwrap();
    REGISTRY.register(Box::new(g.clone())).unwrap();
    g
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

/// Health check results counter, labelled by `result`: `"ok"` or `"error"`.
/// Incremented on every request to the `/healthz` endpoint.
pub static HEALTHZ_CHECKS: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new(
            "ddos_proxy_healthz_checks_total",
            "Total health check requests, by result (ok or error)",
        ),
        &["result"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

/// IPs that exceeded the per-IP /challenge/verify rate limit (PROXY_MAX_VERIFY_ATTEMPTS).
pub static VERIFY_RATE_LIMITED: Lazy<IntCounter> = Lazy::new(|| {
    let c = IntCounter::new(
        "ddos_proxy_verify_rate_limited_total",
        "Requests to /challenge/verify rejected because the IP exceeded PROXY_MAX_VERIFY_ATTEMPTS",
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

/// Per-IP client states removed from the tracking map, broken down by eviction reason.
///
/// `idle`             — state evicted because the IP was inactive for 10 minutes.
/// `mitigation_ended` — state evicted because the mitigation window closed and the
///                      IP had not been verified (unverified bots cleared en-masse).
pub static IP_STATES_EVICTED: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new(
            "ddos_proxy_ip_states_evicted_total",
            "Total per-IP client states evicted from the tracking map, by reason",
        ),
        &["reason"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

/// Requests for which no per-IP state could be allocated because the
/// `PROXY_MAX_IP_STATES` cap was already full. Incremented on every request
/// that finds the map at capacity. A sustained non-zero rate here means the cap
/// should be raised or the attack volume is generating too many unique IPs.
pub static IP_STATES_CAP_HITS: Lazy<IntCounter> = Lazy::new(|| {
    let c = IntCounter::new(
        "ddos_proxy_ip_states_cap_hits_total",
        "Requests served without state tracking because PROXY_MAX_IP_STATES was full",
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

/// Requests currently being handled (incremented at WAF entry, decremented when
/// the response is produced). Only tracked when `PROXY_MAX_INFLIGHT` is set.
pub static INFLIGHT_REQUESTS: Lazy<IntGauge> = Lazy::new(|| {
    let g = IntGauge::new(
        "ddos_proxy_inflight_requests",
        "Requests currently in flight through the proxy (tracked when PROXY_MAX_INFLIGHT is set)",
    )
    .unwrap();
    REGISTRY.register(Box::new(g.clone())).unwrap();
    g
});

/// Currently verified client states, updated every 10 s by the cleanup ticker.
pub static VERIFIED_CLIENTS: Lazy<IntGauge> = Lazy::new(|| {
    let g = IntGauge::new(
        "ddos_proxy_verified_clients_current",
        "Currently verified client states (challenge solved, within verify window)",
    )
    .unwrap();
    REGISTRY.register(Box::new(g.clone())).unwrap();
    g
});

/// Disk-cache outcomes: `hit` (fresh entry served), `miss` (cacheable GET with
/// no fresh entry), `store` (response written to cache), `stale` (expired entry
/// served because the backend failed).
pub static CACHE_REQUESTS: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        Opts::new(
            "ddos_proxy_cache_requests_total",
            "Disk cache outcomes, by result (hit, miss, store, stale)",
        ),
        &["result"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

/// Idempotent backend requests retried after a transport error.
pub static BACKEND_RETRIES: Lazy<IntCounter> = Lazy::new(|| {
    let c = IntCounter::new(
        "ddos_proxy_backend_retries_total",
        "Idempotent (GET/HEAD) backend requests retried after a transport error",
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

/// Requests served the challenge because a per-path rate limit was exceeded.
pub static PATH_RATE_LIMITED: Lazy<IntCounter> = Lazy::new(|| {
    let c = IntCounter::new(
        "ddos_proxy_path_rate_limited_total",
        "Requests served a WAF challenge because a PROXY_PATH_RATE_LIMITS prefix was over its limit",
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
    for reason in [
        "ip_denylist",
        "ua_denylist",
        "method_not_allowed",
        "body_too_large",
        "maintenance",
        "blocked_path",
        "block_regex",
        "host_not_allowed",
        "no_user_agent",
        "uri_too_long",
        "honeypot",
        "basic_auth",
        "inflight_cap",
        "per_ip_concurrency",
        "scanner_404",
        "circuit_open",
    ] {
        DROPPED_REQUESTS.with_label_values(&[reason]).inc_by(0);
    }
    for reason in ["trusted_ip", "exempt_path"] {
        ALLOWED_REQUESTS.with_label_values(&[reason]).inc_by(0);
    }
    for result in ["hit", "miss", "store", "stale"] {
        CACHE_REQUESTS.with_label_values(&[result]).inc_by(0);
    }
    let _ = &*INFLIGHT_REQUESTS;
    let _ = &*VERIFIED_CLIENTS;
    let _ = &*BACKEND_RETRIES;
    let _ = &*PATH_RATE_LIMITED;
    XDP_PACKETS.with_label_values(&["allowed"]).inc_by(0);
    XDP_PACKETS.with_label_values(&["blocked"]).inc_by(0);
    for reason in [
        "blocklist", "udp", "tcp_malformed", "http_invalid", "tls_invalid",
        "icmp", "bad_flags", "fragment", "amplify", "syn_flood",
    ] {
        XDP_DROPS.with_label_values(&[reason]).inc_by(0);
    }
    for event in ["challenged", "validated"] {
        XDP_SYN_AUTH.with_label_values(&[event]).inc_by(0);
    }
    // Touch the L4-flood gauges so all label combinations appear on first scrape.
    for attack_type in [
        "syn_flood", "udp_flood", "amplification", "icmp_flood",
        "ip_fragmentation", "bad_tcp_flags", "http_junk", "tls_junk",
        "malformed_tcp", "blocklist_flood", "mixed",
    ] {
        XDP_L4_FLOOD_ACTIVE.with_label_values(&[attack_type]).set(0);
    }
    let _ = &*XDP_FLOOD_SECONDS;
    let _ = &*XDP_DROP_RATE;
    BACKEND_RESPONSES.with_label_values(&["2xx"]).inc_by(0);
    BACKEND_RESPONSES.with_label_values(&["3xx"]).inc_by(0);
    BACKEND_RESPONSES.with_label_values(&["4xx"]).inc_by(0);
    BACKEND_RESPONSES.with_label_values(&["5xx"]).inc_by(0);
    BACKEND_RESPONSES.with_label_values(&["error"]).inc_by(0);
    BACKEND_RESPONSES.with_label_values(&["timeout"]).inc_by(0);
    // Force Lazy initialisation so histograms, vecs, and gauge appear on the first scrape.
    let _ = &*BACKEND_REQUEST_DURATION;
    let _ = &*IP_STATES;
    IP_STATES_EVICTED.with_label_values(&["idle"]).inc_by(0);
    IP_STATES_EVICTED
        .with_label_values(&["mitigation_ended"])
        .inc_by(0);
    let _ = &*IP_STATES_CAP_HITS;
    let _ = &*PER_IP_RATE_LIMITED;
    let _ = &*VERIFY_RATE_LIMITED;
    let _ = &*CHALLENGE_ABANDONED;
    HEALTHZ_CHECKS.with_label_values(&["ok"]).inc_by(0);
    HEALTHZ_CHECKS.with_label_values(&["error"]).inc_by(0);
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

/// Record `count` states evicted for the given reason (`"idle"` or `"mitigation_ended"`).
pub fn ip_states_evicted(reason: &str, count: u64) {
    IP_STATES_EVICTED.with_label_values(&[reason]).inc_by(count);
}

/// Record one request that could not be assigned a tracking state because the cap was full.
pub fn ip_states_cap_hit() {
    IP_STATES_CAP_HITS.inc();
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

/// Increment the verify-endpoint rate limit counter.
pub fn verify_rate_limited() {
    VERIFY_RATE_LIMITED.inc();
}

/// Update the in-flight requests gauge.
pub fn set_inflight(count: i64) {
    INFLIGHT_REQUESTS.set(count.max(0));
}

/// Update the verified-clients gauge (computed by the cleanup ticker).
pub fn set_verified_clients(count: i64) {
    VERIFIED_CLIENTS.set(count.max(0));
}

/// Record a cache outcome: `"hit"`, `"miss"`, `"store"`, or `"stale"`.
pub fn cache_result(result: &str) {
    CACHE_REQUESTS.with_label_values(&[result]).inc();
}

/// Record one retried backend request.
pub fn backend_retry() {
    BACKEND_RETRIES.inc();
}

/// Increment the per-path rate limit counter.
pub fn path_rate_limited() {
    PATH_RATE_LIMITED.inc();
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

/// Update L4-flood state metrics. Call every second from the XDP stats loop.
///
/// `active_type` is `Some("syn_flood")` etc. while a flood is in progress, or
/// `None` when no flood is active. `drop_pps` is the current dropped pkt/s.
pub fn xdp_l4_flood_state(active_type: Option<&str>, drop_pps: i64) {
    XDP_DROP_RATE.set(drop_pps);
    let canonical_type = active_type.map(attack_type_label).unwrap_or("mixed");
    if active_type.is_some() {
        // Set the active label to 1, all others to 0.
        for label in [
            "syn_flood", "udp_flood", "amplification", "icmp_flood",
            "ip_fragmentation", "bad_tcp_flags", "http_junk", "tls_junk",
            "malformed_tcp", "blocklist_flood", "mixed",
        ] {
            XDP_L4_FLOOD_ACTIVE
                .with_label_values(&[label])
                .set(if label == canonical_type { 1 } else { 0 });
        }
        XDP_FLOOD_SECONDS.inc();
    } else {
        // No flood: zero all labels.
        for label in [
            "syn_flood", "udp_flood", "amplification", "icmp_flood",
            "ip_fragmentation", "bad_tcp_flags", "http_junk", "tls_junk",
            "malformed_tcp", "blocklist_flood", "mixed",
        ] {
            XDP_L4_FLOOD_ACTIVE.with_label_values(&[label]).set(0);
        }
    }
}

/// Map a classify_l4 label string to a Prometheus-safe attack_type label value.
fn attack_type_label(classify_label: &str) -> &'static str {
    match classify_label {
        s if s.starts_with("SYN")           => "syn_flood",
        s if s.starts_with("UDP")           => "udp_flood",
        s if s.starts_with("Amplification") => "amplification",
        s if s.starts_with("ICMP")          => "icmp_flood",
        s if s.starts_with("IP frag")       => "ip_fragmentation",
        s if s.starts_with("Malformed TCP") => "bad_tcp_flags",
        s if s.starts_with("Non-HTTP")      => "http_junk",
        s if s.starts_with("Non-TLS")       => "tls_junk",
        s if s.starts_with("Malformed-TCP") => "malformed_tcp",
        s if s.starts_with("Blocklisted")   => "blocklist_flood",
        _                                   => "mixed",
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
    fn verify_rate_limited_increments_counter() {
        let before = VERIFY_RATE_LIMITED.get();
        verify_rate_limited();
        verify_rate_limited();
        assert_eq!(VERIFY_RATE_LIMITED.get(), before + 2);
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

    #[test]
    fn ip_states_evicted_increments_by_reason() {
        let idle_before = IP_STATES_EVICTED.with_label_values(&["idle"]).get();
        let mit_before = IP_STATES_EVICTED
            .with_label_values(&["mitigation_ended"])
            .get();

        ip_states_evicted("idle", 5);
        ip_states_evicted("mitigation_ended", 3);

        assert_eq!(IP_STATES_EVICTED.with_label_values(&["idle"]).get(), idle_before + 5);
        assert_eq!(
            IP_STATES_EVICTED.with_label_values(&["mitigation_ended"]).get(),
            mit_before + 3
        );
    }

    #[test]
    fn ip_states_evicted_reasons_are_independent() {
        let idle_before = IP_STATES_EVICTED.with_label_values(&["idle"]).get();
        ip_states_evicted("mitigation_ended", 10);
        // idle counter must not be affected by a mitigation_ended increment
        assert_eq!(IP_STATES_EVICTED.with_label_values(&["idle"]).get(), idle_before);
    }

    #[test]
    fn ip_states_cap_hits_increments() {
        let before = IP_STATES_CAP_HITS.get();
        ip_states_cap_hit();
        ip_states_cap_hit();
        ip_states_cap_hit();
        assert_eq!(IP_STATES_CAP_HITS.get(), before + 3);
    }
}
