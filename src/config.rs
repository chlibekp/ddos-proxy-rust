use std::env;
use std::time::Duration;

use crate::netmatch::IpCidr;

/// Application configuration loaded from environment variables.
/// Field defaults and parsing semantics mirror the Go implementation exactly.
#[derive(Clone, Debug)]
pub struct Config {
    pub backend_url: String,
    pub port: String,
    pub http_port: String,
    pub max_req_per_sec: i64,
    pub max_conn_per_sec: i64,
    pub verify_time: Duration,
    pub mitigation_time: Duration,
    pub turnstile_site_key: String,
    pub turnstile_secret_key: String,
    pub always_on: bool,
    pub use_forwarded_for: bool,
    pub cloudflare_support: bool,
    pub whitelisted_ua: Vec<String>,
    pub whitelist_rate_limit: i64,
    pub max_failed_challenges: i64,
    pub prometheus_enabled: bool,
    pub block_action: String,
    pub auto_mitigation_on_timeout: bool,
    pub max_timeouts: i64,
    pub timeout_threshold: Duration,
    pub cache_enabled: bool,
    pub enable_ssl: bool,
    pub acme_staging: bool,
    pub acme_directory_url: String,
    pub acme_email: String,
    pub acme_eab_key_id: String,
    pub acme_eab_hmac: String,
    pub xdp_interface: String,
    pub pow_difficulty: usize,
    pub max_ip_states: i64,
    pub cookie_challenge: bool,
    /// Optional per-IP request rate cap (req/s). `None` means disabled.
    /// When an unverified IP exceeds this limit it is served the WAF challenge
    /// instead of being proxied, without triggering a global mitigation window.
    pub max_req_per_ip: Option<i64>,
    /// Bearer token that protects the `/ddos-proxy/admin/` endpoints. `None` disables the admin API.
    pub admin_secret: Option<String>,

    /// Whether the `/healthz` endpoint is enabled (default: true).
    pub healthz_enabled: bool,
    /// Path on which the health check endpoint is served (default: `/healthz`).
    pub healthz_path: String,
    /// Path to probe on the backend when performing a health check (default: `/`).
    pub healthz_backend_path: String,

    /// Optional Discord incoming-webhook URL for DDoS/suspicious-traffic alerts.
    /// Alerts are suppressed for bursts ≤ 500 req/min and rate-limited to one per minute.
    /// `None` disables alerting.
    pub discord_webhook_url: Option<String>,

    /// Maximum number of failed `/challenge/verify` submissions an IP may make in a
    /// 60-second window before the endpoint returns 429.  Default: 5.
    /// Set via `PROXY_MAX_VERIFY_ATTEMPTS`.
    pub max_verify_attempts: i64,

    /// Dropped-packets-per-second threshold (measured at the XDP/L4 layer) above
    /// which a Discord L4-flood alert is fired. `<= 0` disables L4 alerting.
    /// Default: 1000. Set via `PROXY_XDP_ALERT_PPS`. Only meaningful when both
    /// `PROXY_XDP_INTERFACE` and `PROXY_DISCORD_WEBHOOK_URL` are configured.
    pub xdp_alert_pps: i64,

    /// IPs/CIDRs that bypass the WAF entirely (monitoring probes, internal
    /// infrastructure, office ranges). Set via `PROXY_TRUSTED_IPS`
    /// (comma-separated, e.g. `10.0.0.0/8,192.168.1.5,2001:db8::/32`).
    pub trusted_ips: Vec<IpCidr>,
    /// IPs/CIDRs that are always blocked (served the configured block action)
    /// before any other processing. Set via `PROXY_DENY_IPS`.
    pub deny_ips: Vec<IpCidr>,
    /// User-Agent substrings that are blocked outright with 403.
    /// Set via `PROXY_BLOCKED_UA` (comma-separated, case-insensitive match).
    pub blocked_ua: Vec<String>,
    /// Path prefixes that are never served a challenge (webhooks, payment
    /// callbacks, machine-to-machine APIs that can't run JS or keep cookies).
    /// Blocked IPs are still blocked on these paths. Set via
    /// `PROXY_EXEMPT_PATHS` (comma-separated, each must start with `/`).
    pub exempt_paths: Vec<String>,
    /// Maximum time to wait for the backend to start responding before
    /// returning 504. Set via `PROXY_BACKEND_TIMEOUT` (default `30s`,
    /// `0` disables the timeout).
    pub backend_timeout: Duration,
    /// Maximum declared request body size in bytes (checked against
    /// `Content-Length`). Oversized requests get 413. Set via
    /// `PROXY_MAX_BODY_SIZE`; `0` or absent disables the check.
    pub max_body_size: Option<u64>,
    /// HTTP methods accepted by the proxy (uppercase). Empty means all methods
    /// are allowed. Set via `PROXY_ALLOWED_METHODS`
    /// (e.g. `GET,POST,PUT,DELETE,HEAD,OPTIONS,PATCH`).
    pub allowed_methods: Vec<String>,
    /// When true, standard security headers (HSTS on TLS, nosniff,
    /// X-Frame-Options, Referrer-Policy) are added to proxied responses
    /// unless the backend already set them. Set via `PROXY_SECURITY_HEADERS`.
    pub security_headers: bool,
    /// When true, every request is logged as a structured JSON line
    /// (method, path, status, duration, client IP). Set via `PROXY_ACCESS_LOG`.
    pub access_log: bool,
}

/// Error returned when required configuration is missing.
#[derive(Debug)]
pub struct MissingBackendURL;

fn env_nonempty(key: &str) -> Option<String> {
    match env::var(key) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}

fn parse_bool(key: &str) -> bool {
    matches!(env::var(key).as_deref(), Ok("true") | Ok("1"))
}

/// Parse a duration the way Go's config does: first try Go's `time.ParseDuration`
/// format (e.g. "5m", "300s", "1h30m"), then fall back to a bare integer as seconds.
fn parse_duration_env(key: &str, default: Duration) -> Duration {
    match env_nonempty(key) {
        None => default,
        Some(s) => {
            if let Some(d) = parse_go_duration(&s) {
                d
            } else if let Ok(secs) = s.parse::<i64>() {
                Duration::from_secs(secs.max(0) as u64)
            } else {
                default
            }
        }
    }
}

impl Config {
    /// Load configuration from environment variables.
    pub fn load() -> Result<Config, MissingBackendURL> {
        let backend_url = env_nonempty("PROXY_BACKEND_URL").ok_or(MissingBackendURL)?;

        let port = env_nonempty("PORT").unwrap_or_else(|| "8080".to_string());
        let http_port = env_nonempty("PROXY_HTTP_PORT").unwrap_or_else(|| "80".to_string());

        let max_req = env_nonempty("PROXY_MAX_REQ")
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(300);
        let max_conn = env_nonempty("PROXY_MAX_CONN")
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(50);

        let verify_time = parse_duration_env("PROXY_VERIFY_TIME", Duration::from_secs(10 * 60));
        let mitigation_time =
            parse_duration_env("PROXY_MITIGATION_TIME", Duration::from_secs(5 * 60));

        let always_on = parse_bool("PROXY_ALWAYS_ON");
        let use_forwarded_for = parse_bool("PROXY_USE_FORWARDED_FOR");
        let cloudflare_support = parse_bool("PROXY_CLOUDFLARE_SUPPORT");

        let whitelisted_ua = env_nonempty("PROXY_WHITELIST_UA")
            .map(|s| {
                s.split(',')
                    .map(|p| p.trim().to_string())
                    .filter(|p| !p.is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let whitelist_rate_limit = env_nonempty("PROXY_WHITELIST_RATE")
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(10);

        let prometheus_enabled = parse_bool("PROXY_PROMETHEUS_ENABLED");

        let max_failed_challenges = env_nonempty("PROXY_MAX_FAILED_CHALLENGES")
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(5);

        let block_action = match env::var("PROXY_BLOCK_ACTION").as_deref() {
            Ok("close") => "close".to_string(),
            _ => "403".to_string(),
        };

        let auto_mitigation_on_timeout = parse_bool("PROXY_AUTO_MITIGATION_ON_TIMEOUT");
        let max_timeouts = env_nonempty("PROXY_MAX_TIMEOUTS")
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(5);
        let timeout_threshold =
            parse_duration_env("PROXY_TIMEOUT_THRESHOLD", Duration::from_secs(5));

        let cache_enabled = parse_bool("PROXY_CACHE_ENABLED");
        let enable_ssl = parse_bool("PROXY_ENABLE_SSL");
        let acme_staging = parse_bool("PROXY_ACME_STAGING");
        let acme_directory_url = env::var("PROXY_ACME_DIRECTORY_URL")
            .unwrap_or_default()
            .trim()
            .to_string();
        let acme_email = env::var("PROXY_ACME_EMAIL")
            .unwrap_or_default()
            .trim()
            .to_string();
        let acme_eab_key_id = env::var("PROXY_ACME_EAB_KEY_ID")
            .unwrap_or_default()
            .trim()
            .to_string();
        let acme_eab_hmac = env::var("PROXY_ACME_EAB_HMAC")
            .unwrap_or_default()
            .trim()
            .to_string();

        let pow_difficulty = env_nonempty("PROXY_POW_DIFFICULTY")
            .and_then(|s| s.parse::<i64>().ok())
            .filter(|&v| v > 0)
            .map(|v| v as usize)
            .unwrap_or(5);

        let xdp_interface = env::var("PROXY_XDP_INTERFACE").unwrap_or_default();

        // Cookie challenge is the lightweight first tier; enabled by default.
        // Disable explicitly with PROXY_COOKIE_CHALLENGE=false.
        let cookie_challenge = !matches!(env::var("PROXY_COOKIE_CHALLENGE").as_deref(), Ok("false") | Ok("0"));

        // Per-IP rate cap: 0 or absent disables the feature.
        let max_req_per_ip = env_nonempty("PROXY_MAX_REQ_PER_IP")
            .and_then(|s| s.parse::<i64>().ok())
            .filter(|&v| v > 0);

        let max_ip_states = env_nonempty("PROXY_MAX_IP_STATES")
            .and_then(|s| s.parse::<i64>().ok())
            .filter(|&v| v > 0)
            .unwrap_or(500_000);

        let admin_secret = env_nonempty("PROXY_ADMIN_SECRET");

        // Health check endpoint configuration.
        // PROXY_HEALTHZ_ENABLED defaults to true; set to "false" or "0" to disable.
        let healthz_enabled = !matches!(env::var("PROXY_HEALTHZ_ENABLED").as_deref(), Ok("false") | Ok("0"));
        let healthz_path = env_nonempty("PROXY_HEALTHZ_PATH").unwrap_or_else(|| "/healthz".to_string());
        let healthz_backend_path = env_nonempty("PROXY_HEALTHZ_BACKEND_PATH").unwrap_or_else(|| "/".to_string());

        let discord_webhook_url = env_nonempty("PROXY_DISCORD_WEBHOOK_URL");

        let max_verify_attempts = env_nonempty("PROXY_MAX_VERIFY_ATTEMPTS")
            .and_then(|s| s.parse::<i64>().ok())
            .filter(|&v| v > 0)
            .unwrap_or(5);

        let xdp_alert_pps = env_nonempty("PROXY_XDP_ALERT_PPS")
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(1000);

        let trusted_ips = env_nonempty("PROXY_TRUSTED_IPS")
            .map(|s| crate::netmatch::parse_cidr_list(&s))
            .unwrap_or_default();
        let deny_ips = env_nonempty("PROXY_DENY_IPS")
            .map(|s| crate::netmatch::parse_cidr_list(&s))
            .unwrap_or_default();

        let blocked_ua = env_nonempty("PROXY_BLOCKED_UA")
            .map(|s| {
                s.split(',')
                    .map(|p| p.trim().to_lowercase())
                    .filter(|p| !p.is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        // Only rooted prefixes make sense; anything else is silently dropped.
        let exempt_paths = env_nonempty("PROXY_EXEMPT_PATHS")
            .map(|s| {
                s.split(',')
                    .map(|p| p.trim().to_string())
                    .filter(|p| p.starts_with('/'))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let backend_timeout = parse_duration_env("PROXY_BACKEND_TIMEOUT", Duration::from_secs(30));

        let max_body_size = env_nonempty("PROXY_MAX_BODY_SIZE")
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|&v| v > 0);

        let allowed_methods = env_nonempty("PROXY_ALLOWED_METHODS")
            .map(|s| {
                s.split(',')
                    .map(|p| p.trim().to_uppercase())
                    .filter(|p| !p.is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let security_headers = parse_bool("PROXY_SECURITY_HEADERS");
        let access_log = parse_bool("PROXY_ACCESS_LOG");

        Ok(Config {
            backend_url,
            port,
            http_port,
            max_req_per_sec: max_req,
            max_conn_per_sec: max_conn,
            verify_time,
            mitigation_time,
            turnstile_site_key: env::var("PROXY_TURNSTILE_PUBLIC_KEY").unwrap_or_default(),
            turnstile_secret_key: env::var("PROXY_TURNSTILE_PRIVATE_KEY").unwrap_or_default(),
            always_on,
            use_forwarded_for,
            cloudflare_support,
            whitelisted_ua,
            whitelist_rate_limit,
            max_failed_challenges,
            prometheus_enabled,
            block_action,
            auto_mitigation_on_timeout,
            max_timeouts,
            timeout_threshold,
            cache_enabled,
            enable_ssl,
            acme_staging,
            acme_directory_url,
            acme_email,
            acme_eab_key_id,
            acme_eab_hmac,
            xdp_interface,
            pow_difficulty,
            max_ip_states,
            cookie_challenge,
            max_req_per_ip,
            admin_secret,
            healthz_enabled,
            healthz_path,
            healthz_backend_path,
            discord_webhook_url,
            max_verify_attempts,
            xdp_alert_pps,
            trusted_ips,
            deny_ips,
            blocked_ua,
            exempt_paths,
            backend_timeout,
            max_body_size,
            allowed_methods,
            security_headers,
            access_log,
        })
    }
}

/// Parse a Go `time.ParseDuration`-style string: a possibly-signed sequence of
/// decimal numbers, each with an optional fraction and a required unit suffix
/// (ns, us/µs, ms, s, m, h). Returns None on any parse error (caller falls back).
fn parse_go_duration(input: &str) -> Option<Duration> {
    let s = input;
    if s.is_empty() {
        return None;
    }
    // Special-case "0" like Go does.
    if s == "0" {
        return Some(Duration::ZERO);
    }

    let bytes = s.as_bytes();
    let mut i = 0;
    let mut neg = false;
    if bytes[i] == b'+' || bytes[i] == b'-' {
        neg = bytes[i] == b'-';
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }

    let mut total_nanos: f64 = 0.0;
    let mut saw_unit = false;

    while i < bytes.len() {
        // Parse leading number (integer + optional fraction).
        let start = i;
        while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
            i += 1;
        }
        if i == start {
            return None;
        }
        let num: f64 = s[start..i].parse().ok()?;

        // Parse unit.
        let unit_start = i;
        // unit is non-digit, non-dot characters
        while i < bytes.len() && !bytes[i].is_ascii_digit() && bytes[i] != b'.' {
            i += 1;
        }
        if i == unit_start {
            return None; // missing unit
        }
        let unit = &s[unit_start..i];
        let mult = match unit {
            "ns" => 1.0,
            "us" | "µs" => 1_000.0,
            "ms" => 1_000_000.0,
            "s" => 1_000_000_000.0,
            "m" => 60.0 * 1_000_000_000.0,
            "h" => 3600.0 * 1_000_000_000.0,
            _ => return None,
        };
        total_nanos += num * mult;
        saw_unit = true;
    }

    if !saw_unit {
        return None;
    }
    if neg {
        // Negative durations clamp to zero (Go would keep negative, but our
        // config never uses negatives meaningfully; downstream treats as 0).
        return Some(Duration::ZERO);
    }
    Some(Duration::from_nanos(total_nanos as u64))
}
