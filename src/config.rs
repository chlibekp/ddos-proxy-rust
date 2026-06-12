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

    /// Path prefixes that are blocked outright with 403 (matched against the
    /// normalized path). Set via `PROXY_BLOCKED_PATHS` (e.g. `/.env,/.git,/wp-admin`).
    pub blocked_paths: Vec<String>,
    /// Regex matched against the raw path+query; matching requests get 403.
    /// Set via `PROXY_BLOCK_REGEX` (e.g. `(?i)(union\s+select|\.\./\.\./)`).
    pub block_regex: Option<regex::Regex>,
    /// Regex applied to the raw request body of POST/PUT/PATCH requests;
    /// matching requests get 403 before reaching the backend.  The body is
    /// buffered (up to `max_body_size`, default 1 MiB) for inspection.  Use this
    /// to block SQL-injection payloads, command-injection strings, or other
    /// patterns that appear in form fields or JSON bodies.
    /// Set via `PROXY_BLOCK_BODY_REGEX` (e.g. `(?i)(union\s+select|exec\s*\()`).
    pub block_body_regex: Option<regex::Regex>,
    /// Hostnames the proxy will serve (lowercase, port stripped). Entries may be
    /// exact (`example.com`) or wildcard (`*.example.com`). Empty = all hosts.
    /// Set via `PROXY_ALLOWED_HOSTS`.
    pub allowed_hosts: Vec<String>,
    /// When true, requests without a User-Agent header are rejected with 403.
    /// Set via `PROXY_REQUIRE_UA`.
    pub require_ua: bool,
    /// Maximum length of the request path+query in bytes; longer requests get
    /// 414. Set via `PROXY_MAX_URI_LEN`; `0` or absent disables.
    pub max_uri_len: Option<usize>,
    /// Honeypot path prefixes: any client touching one is immediately blocked
    /// (real users have no reason to request them). Set via `PROXY_HONEYPOT_PATHS`.
    pub honeypot_paths: Vec<String>,
    /// Backend 404 responses a single IP may receive in a 60-second window
    /// before being blocked as a scanner. Set via `PROXY_MAX_404_PER_IP`;
    /// `0` or absent disables.
    pub max_404_per_ip: Option<i64>,
    /// Site-wide HTTP Basic auth gate (e.g. for staging environments). Stores
    /// the full expected `Authorization` header value. Set via
    /// `PROXY_BASIC_AUTH=user:password`; absent disables.
    pub basic_auth: Option<String>,
    /// Maximum concurrent in-flight requests per client IP; excess gets 429.
    /// Set via `PROXY_MAX_CONCURRENT_PER_IP`; `0` or absent disables.
    pub max_concurrent_per_ip: Option<i64>,
    /// Global cap on concurrent in-flight requests; excess gets 503. Bounds
    /// memory/FDs under extreme load. Set via `PROXY_MAX_INFLIGHT`.
    pub max_inflight: Option<i64>,
    /// Number of times an idempotent (GET/HEAD) request is retried against the
    /// backend after a transport error. Set via `PROXY_BACKEND_RETRIES` (default 0).
    pub backend_retries: u32,
    /// Consecutive backend transport failures that trip the circuit breaker
    /// (fail-fast 503 for `cb_cooldown`). Set via `PROXY_CB_THRESHOLD`; `0` disables.
    pub cb_threshold: i64,
    /// How long the circuit stays open after tripping. Set via
    /// `PROXY_CB_COOLDOWN` (default `30s`).
    pub cb_cooldown: Duration,
    /// When true and the backend errors/times out (or returns 5xx) on a GET,
    /// a stale cached copy is served instead if one exists (requires
    /// `PROXY_CACHE_ENABLED`). Set via `PROXY_SERVE_STALE`.
    pub serve_stale: bool,
    /// When true, an `X-Request-Id` is generated (or a valid inbound one kept),
    /// forwarded to the backend and returned on the response. Set via
    /// `PROXY_REQUEST_ID`.
    pub request_id: bool,
    /// Extra response headers, applied after the backend response (overwrite).
    /// Set via `PROXY_ADD_HEADERS` (`Name=Value;Name2=Value2`).
    pub add_headers: Vec<(String, String)>,
    /// Response headers stripped before returning to the client (e.g. hide
    /// `X-Powered-By`). Set via `PROXY_REMOVE_HEADERS` (comma-separated).
    pub remove_headers: Vec<String>,
    /// When set, CORS headers are added to responses unless the backend set
    /// them. Set via `PROXY_CORS_ORIGIN` (e.g. `*` or `https://app.example.com`).
    pub cors_origin: Option<String>,
    /// When true, compressible (text/JSON/JS/SVG) buffered responses ≥ 1 KiB are
    /// gzip-compressed if the client accepts gzip and the backend didn't already
    /// encode. Set via `PROXY_COMPRESSION`.
    pub compression: bool,
    /// PoW difficulty used while a mitigation window is active (adaptive
    /// hardening under attack). Set via `PROXY_POW_DIFFICULTY_ATTACK`;
    /// absent keeps the base difficulty always.
    pub pow_difficulty_attack: Option<usize>,
    /// Per-path-prefix global rate limits: requests/second to a prefix above
    /// which that path is served the challenge (protects expensive endpoints
    /// like `/login` without global mitigation). Set via
    /// `PROXY_PATH_RATE_LIMITS` (e.g. `/login=5,/api=100`).
    pub path_rate_limits: Vec<(String, i64)>,
    /// When true (default), every response carries a `Server-Timing` header
    /// with the proxy's internal timing breakdown (`waf`, `cache`, `backend`,
    /// `body`, `proc`, `tls` handshake, `total`), in milliseconds.
    /// Disable with `PROXY_SERVER_TIMING=false`.
    pub server_timing: bool,
    /// When true (default), every response carries an `X-Tcp` header describing
    /// the client TCP connection: peer/local address, connection age, and on
    /// Linux live kernel `TCP_INFO` stats (RTT, cwnd, MSS, retransmits, ...).
    /// Disable with `PROXY_TCP_HEADER=false`.
    pub tcp_header: bool,
}

/// Error returned when required configuration is missing.
#[derive(Debug)]
pub struct MissingBackendURL;

/// Override bag for `Config::for_test`.  Every field is `Option<T>`; `None`
/// means "use the test default".  Only used in `#[cfg(test)]` / test helpers.
#[cfg(any(test, feature = "testing"))]
#[derive(Default)]
pub struct TestCfgOverride {
    pub backend_retries: Option<u32>,
    pub backend_timeout_ms: Option<u64>,
    pub always_on: Option<bool>,
    pub trusted_ips: Option<Vec<String>>,
    pub deny_ips: Option<Vec<String>>,
    pub blocked_paths: Option<Vec<String>>,
    pub honeypot_paths: Option<Vec<String>>,
    pub blocked_ua: Option<Vec<String>>,
    pub require_ua: Option<bool>,
    pub max_uri_len: Option<usize>,
    pub allowed_methods: Option<Vec<String>>,
    pub allowed_hosts: Option<Vec<String>>,
    pub cookie_challenge: Option<bool>,
    pub pow_difficulty: Option<usize>,
    pub max_req_per_ip: Option<i64>,
    pub max_404_per_ip: Option<i64>,
    pub exempt_paths: Option<Vec<String>>,
    pub cache_enabled: Option<bool>,
    pub serve_stale: Option<bool>,
    pub request_id: Option<bool>,
    pub block_body_regex: Option<regex::Regex>,
}

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

        // SSL mode listens for HTTPS, so when PORT is left unset default it to
        // 443 (the port browsers use) instead of the plain-HTTP default of 8080.
        let enable_ssl = parse_bool("PROXY_ENABLE_SSL");
        let port = env_nonempty("PORT").unwrap_or_else(|| {
            if enable_ssl {
                "443".to_string()
            } else {
                "8080".to_string()
            }
        });
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

        let blocked_paths = parse_path_list("PROXY_BLOCKED_PATHS");
        let honeypot_paths = parse_path_list("PROXY_HONEYPOT_PATHS");

        let block_regex = env_nonempty("PROXY_BLOCK_REGEX").and_then(|s| {
            match regex::Regex::new(&s) {
                Ok(re) => Some(re),
                Err(e) => {
                    tracing::warn!(error = %e, "Ignoring invalid PROXY_BLOCK_REGEX");
                    None
                }
            }
        });

        let block_body_regex = env_nonempty("PROXY_BLOCK_BODY_REGEX").and_then(|s| {
            match regex::Regex::new(&s) {
                Ok(re) => Some(re),
                Err(e) => {
                    tracing::warn!(error = %e, "Ignoring invalid PROXY_BLOCK_BODY_REGEX");
                    None
                }
            }
        });

        let allowed_hosts = env_nonempty("PROXY_ALLOWED_HOSTS")
            .map(|s| {
                s.split(',')
                    .map(|p| p.trim().to_lowercase())
                    .filter(|p| !p.is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let require_ua = parse_bool("PROXY_REQUIRE_UA");

        let max_uri_len = env_nonempty("PROXY_MAX_URI_LEN")
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|&v| v > 0);

        let max_404_per_ip = env_nonempty("PROXY_MAX_404_PER_IP")
            .and_then(|s| s.parse::<i64>().ok())
            .filter(|&v| v > 0);

        // Stored as the full expected Authorization header value so the hot
        // path is a single constant-time compare.
        let basic_auth = env_nonempty("PROXY_BASIC_AUTH").map(|creds| {
            use base64::Engine as _;
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(creds.as_bytes())
            )
        });

        let max_concurrent_per_ip = env_nonempty("PROXY_MAX_CONCURRENT_PER_IP")
            .and_then(|s| s.parse::<i64>().ok())
            .filter(|&v| v > 0);
        let max_inflight = env_nonempty("PROXY_MAX_INFLIGHT")
            .and_then(|s| s.parse::<i64>().ok())
            .filter(|&v| v > 0);

        // Default 1 retry: transparently recovers from a stale pooled connection
        // (the most common cause of alternating 502s on HTML responses, where the
        // body is buffered and the connection is returned to the pool early).
        let backend_retries = env_nonempty("PROXY_BACKEND_RETRIES")
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(1)
            .min(5);

        let cb_threshold = env_nonempty("PROXY_CB_THRESHOLD")
            .and_then(|s| s.parse::<i64>().ok())
            .filter(|&v| v > 0)
            .unwrap_or(0);
        let cb_cooldown = parse_duration_env("PROXY_CB_COOLDOWN", Duration::from_secs(30));

        let serve_stale = parse_bool("PROXY_SERVE_STALE");
        let request_id = parse_bool("PROXY_REQUEST_ID");

        let add_headers = env_nonempty("PROXY_ADD_HEADERS")
            .map(|s| {
                s.split(';')
                    .filter_map(|pair| {
                        let (name, value) = pair.split_once('=')?;
                        let (name, value) = (name.trim(), value.trim());
                        if name.is_empty() {
                            return None;
                        }
                        Some((name.to_lowercase(), value.to_string()))
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let remove_headers = env_nonempty("PROXY_REMOVE_HEADERS")
            .map(|s| {
                s.split(',')
                    .map(|p| p.trim().to_lowercase())
                    .filter(|p| !p.is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let cors_origin = env_nonempty("PROXY_CORS_ORIGIN");
        let compression = parse_bool("PROXY_COMPRESSION");

        let pow_difficulty_attack = env_nonempty("PROXY_POW_DIFFICULTY_ATTACK")
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|&v| v > 0);

        // Timing/TCP introspection headers are enabled by default; disable
        // explicitly with PROXY_SERVER_TIMING=false / PROXY_TCP_HEADER=false.
        let server_timing =
            !matches!(env::var("PROXY_SERVER_TIMING").as_deref(), Ok("false") | Ok("0"));
        let tcp_header =
            !matches!(env::var("PROXY_TCP_HEADER").as_deref(), Ok("false") | Ok("0"));

        let path_rate_limits = env_nonempty("PROXY_PATH_RATE_LIMITS")
            .map(|s| {
                s.split(',')
                    .filter_map(|pair| {
                        let (prefix, limit) = pair.split_once('=')?;
                        let prefix = prefix.trim();
                        let limit: i64 = limit.trim().parse().ok()?;
                        if !prefix.starts_with('/') || limit <= 0 {
                            return None;
                        }
                        Some((prefix.to_string(), limit))
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

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
            blocked_paths,
            block_regex,
            block_body_regex,
            allowed_hosts,
            require_ua,
            max_uri_len,
            honeypot_paths,
            max_404_per_ip,
            basic_auth,
            max_concurrent_per_ip,
            max_inflight,
            backend_retries,
            cb_threshold,
            cb_cooldown,
            serve_stale,
            request_id,
            add_headers,
            remove_headers,
            cors_origin,
            compression,
            pow_difficulty_attack,
            path_rate_limits,
            server_timing,
            tcp_header,
        })
    }

    /// Construct a `Config` with safe test defaults, pointing at `backend_url`.
    /// All rate limits are effectively disabled; no challenges, no TLS.
    /// Only fields present in `overrides` differ from the defaults.
    #[cfg(any(test, feature = "testing"))]
    pub fn for_test(backend_url: &str, overrides: crate::config::TestCfgOverride) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Config {
            backend_url: backend_url.to_string(),
            port: "0".to_string(),
            http_port: "0".to_string(),
            max_req_per_sec: 1_000_000,
            max_conn_per_sec: 1_000_000,
            verify_time: Duration::from_secs(3600),
            mitigation_time: Duration::from_secs(300),
            turnstile_site_key: String::new(),
            turnstile_secret_key: String::new(),
            always_on: overrides.always_on.unwrap_or(false),
            use_forwarded_for: false,
            cloudflare_support: false,
            whitelisted_ua: Vec::new(),
            whitelist_rate_limit: 1_000_000,
            max_failed_challenges: 100,
            prometheus_enabled: false,
            block_action: "403".to_string(),
            auto_mitigation_on_timeout: false,
            max_timeouts: 100,
            timeout_threshold: Duration::from_secs(30),
            cache_enabled: overrides.cache_enabled.unwrap_or(false),
            enable_ssl: false,
            acme_staging: false,
            acme_directory_url: String::new(),
            acme_email: String::new(),
            acme_eab_key_id: String::new(),
            acme_eab_hmac: String::new(),
            xdp_interface: String::new(),
            pow_difficulty: overrides.pow_difficulty.unwrap_or(1),
            max_ip_states: 100_000,
            cookie_challenge: overrides.cookie_challenge.unwrap_or(true),
            max_req_per_ip: overrides.max_req_per_ip,
            admin_secret: None,
            healthz_enabled: true,
            healthz_path: "/healthz".to_string(),
            healthz_backend_path: "/".to_string(),
            discord_webhook_url: None,
            max_verify_attempts: 100,
            xdp_alert_pps: 0,
            trusted_ips: overrides
                .trusted_ips
                .unwrap_or_default()
                .iter()
                .filter_map(|s| crate::netmatch::IpCidr::parse(s))
                .collect(),
            deny_ips: overrides
                .deny_ips
                .unwrap_or_default()
                .iter()
                .filter_map(|s| crate::netmatch::IpCidr::parse(s))
                .collect(),
            blocked_ua: overrides
                .blocked_ua
                .unwrap_or_default()
                .into_iter()
                .map(|s| s.to_lowercase())
                .collect(),
            exempt_paths: overrides.exempt_paths.unwrap_or_default(),
            backend_timeout: Duration::from_millis(
                overrides.backend_timeout_ms.unwrap_or(5_000),
            ),
            max_body_size: None,
            allowed_methods: overrides.allowed_methods.unwrap_or_default(),
            security_headers: false,
            access_log: false,
            blocked_paths: overrides.blocked_paths.unwrap_or_default(),
            block_regex: None,
            block_body_regex: overrides.block_body_regex,
            allowed_hosts: overrides
                .allowed_hosts
                .unwrap_or_default()
                .into_iter()
                .map(|s| s.to_lowercase())
                .collect(),
            require_ua: overrides.require_ua.unwrap_or(false),
            max_uri_len: overrides.max_uri_len,
            honeypot_paths: overrides.honeypot_paths.unwrap_or_default(),
            max_404_per_ip: overrides.max_404_per_ip,
            basic_auth: None,
            max_concurrent_per_ip: None,
            max_inflight: None,
            backend_retries: overrides.backend_retries.unwrap_or(1),
            cb_threshold: 0,
            cb_cooldown: Duration::from_secs(30),
            serve_stale: overrides.serve_stale.unwrap_or(false),
            request_id: overrides.request_id.unwrap_or(false),
            add_headers: Vec::new(),
            remove_headers: Vec::new(),
            cors_origin: None,
            compression: false,
            pow_difficulty_attack: None,
            path_rate_limits: Vec::new(),
            server_timing: true,
            tcp_header: true,
        })
    }
}

/// Parse a comma-separated list of rooted path prefixes from `key`,
/// dropping entries that don't start with `/`.
fn parse_path_list(key: &str) -> Vec<String> {
    env_nonempty(key)
        .map(|s| {
            s.split(',')
                .map(|p| p.trim().to_string())
                .filter(|p| p.starts_with('/'))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
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
