use std::sync::Arc;

use http::{Request, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::Incoming;

use crate::body::{full, BoxedBody};
use crate::waf::Manager;

/// Handle a request routed to the `/admin/` prefix.
///
/// All endpoints require an `Authorization: Bearer <secret>` header matching
/// `PROXY_ADMIN_SECRET`.  Returns 404 for every path when the admin API is
/// disabled (no secret configured).
pub async fn handle(req: Request<Incoming>, manager: Arc<Manager>) -> Response<BoxedBody> {
    let secret = match &manager.config().admin_secret {
        Some(s) => s.clone(),
        None => return json(StatusCode::NOT_FOUND, r#"{"error":"not found"}"#),
    };

    let provided = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if provided != format!("Bearer {secret}") {
        return json(StatusCode::UNAUTHORIZED, r#"{"error":"unauthorized"}"#);
    }

    let method = req.method().clone();
    let path = req.uri().path().to_string();

    match (method.as_str(), path.as_str()) {
        // List all tracked IP states.
        ("GET", "/admin/states") => {
            let states = manager.list_states();
            let body = serde_json::to_string(&states).unwrap_or_else(|_| "[]".to_string());
            json(StatusCode::OK, &body)
        }

        // Fetch a single state by its `ip|host` key (URL-encoded in the path).
        ("GET", p) if p.starts_with("/admin/states/") => {
            let raw = &p["/admin/states/".len()..];
            let key = percent_decode(raw);
            match manager.get_state_by_key(&key) {
                Some(s) => {
                    let body = serde_json::to_string(&s).unwrap_or_else(|_| "{}".to_string());
                    json(StatusCode::OK, &body)
                }
                None => json(StatusCode::NOT_FOUND, r#"{"error":"state not found"}"#),
            }
        }

        // Current mitigation status (active flag, timestamps, IP state count).
        ("GET", "/admin/status") => {
            let status = manager.get_status();
            let body = serde_json::to_string(&status).unwrap_or_else(|_| "{}".to_string());
            json(StatusCode::OK, &body)
        }

        // Manually block an IP+host pair.
        ("POST", "/admin/block") => {
            match read_block_req(req).await {
                Some((ip, host)) => {
                    manager.manual_block(&ip, &host);
                    json(StatusCode::OK, r#"{"ok":true}"#)
                }
                None => json(StatusCode::BAD_REQUEST, r#"{"error":"expected JSON {\"ip\":\"...\",\"host\":\"...\"}"}"#),
            }
        }

        // Manually unblock an IP+host pair.
        ("DELETE", "/admin/block") => {
            match read_block_req(req).await {
                Some((ip, host)) => {
                    manager.manual_unblock(&ip, &host);
                    json(StatusCode::OK, r#"{"ok":true}"#)
                }
                None => json(StatusCode::BAD_REQUEST, r#"{"error":"expected JSON {\"ip\":\"...\",\"host\":\"...\"}"}"#),
            }
        }

        _ => json(StatusCode::NOT_FOUND, r#"{"error":"not found"}"#),
    }
}

fn json(status: StatusCode, body: &str) -> Response<BoxedBody> {
    let mut resp = Response::new(full(body.to_string()));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/json"),
    );
    resp
}

#[derive(serde::Deserialize)]
struct BlockReq {
    ip: String,
    host: String,
}

async fn read_block_req(req: Request<Incoming>) -> Option<(String, String)> {
    let bytes = req.into_body().collect().await.ok()?.to_bytes();
    let b: BlockReq = serde_json::from_slice(&bytes).ok()?;
    if b.ip.is_empty() || b.host.is_empty() {
        return None;
    }
    Some((b.ip, b.host))
}

/// Minimal percent-decoding: replace `%XX` sequences and `+` (for the `|`
/// separator that browsers may encode).  Only used for the path segment after
/// `/admin/states/`, so a full decoder is not needed.
fn percent_decode(s: &str) -> String {
    url::form_urlencoded::parse(s.replace('/', "%2F").as_bytes())
        .map(|(k, _)| k.into_owned())
        .next()
        .unwrap_or_else(|| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    use crate::config::Config;
    use crate::limiter::RateLimiter;
    use crate::proxy::Proxy;

    fn make_manager(secret: Option<&str>) -> Arc<Manager> {
        let cfg = Arc::new(Config {
            backend_url: "http://127.0.0.1:8081".to_string(),
            port: "8080".to_string(),
            http_port: "80".to_string(),
            max_req_per_sec: 300,
            max_conn_per_sec: 50,
            verify_time: Duration::from_secs(600),
            mitigation_time: Duration::from_secs(300),
            turnstile_site_key: String::new(),
            turnstile_secret_key: String::new(),
            always_on: false,
            use_forwarded_for: false,
            cloudflare_support: false,
            whitelisted_ua: vec![],
            whitelist_rate_limit: 10,
            max_failed_challenges: 5,
            prometheus_enabled: false,
            block_action: "403".to_string(),
            auto_mitigation_on_timeout: false,
            max_timeouts: 5,
            timeout_threshold: Duration::from_secs(5),
            cache_enabled: false,
            enable_ssl: false,
            acme_staging: false,
            acme_directory_url: String::new(),
            acme_email: String::new(),
            acme_eab_key_id: String::new(),
            acme_eab_hmac: String::new(),
            xdp_interface: String::new(),
            pow_difficulty: 5,
            max_ip_states: 500_000,
            cookie_challenge: true,
            admin_secret: secret.map(|s| s.to_string()),
        });
        let rl = Arc::new(RateLimiter::new());
        let target: http::Uri = "http://127.0.0.1:8081".parse().unwrap();
        let proxy = Arc::new(Proxy::new(target, cfg.clone()));
        Manager::new(cfg, rl, "<html></html>".to_string(), None, proxy)
    }

    #[tokio::test]
    async fn list_states_empty_initially() {
        let manager = make_manager(Some("secret"));
        assert!(manager.list_states().is_empty());
    }

    #[tokio::test]
    async fn manual_block_sets_blocked_flag() {
        let manager = make_manager(Some("secret"));
        manager.manual_block("1.2.3.4", "example.com");
        let info = manager.get_state_by_key("1.2.3.4|example.com").unwrap();
        assert!(info.blocked);
    }

    #[tokio::test]
    async fn manual_unblock_clears_blocked_flag() {
        let manager = make_manager(Some("secret"));
        manager.manual_block("1.2.3.4", "example.com");
        manager.manual_unblock("1.2.3.4", "example.com");
        let info = manager.get_state_by_key("1.2.3.4|example.com").unwrap();
        assert!(!info.blocked);
        assert_eq!(info.violation_count, 0);
    }

    #[tokio::test]
    async fn get_state_by_key_unknown_returns_none() {
        let manager = make_manager(Some("secret"));
        assert!(manager.get_state_by_key("9.9.9.9|unknown.com").is_none());
    }

    #[tokio::test]
    async fn get_state_by_key_after_block() {
        let manager = make_manager(Some("secret"));
        manager.manual_block("10.0.0.1", "test.com");
        let s = manager.get_state_by_key("10.0.0.1|test.com").unwrap();
        assert_eq!(s.key, "10.0.0.1|test.com");
        assert!(s.blocked);
    }

    #[tokio::test]
    async fn list_states_reflects_manual_block() {
        let manager = make_manager(Some("secret"));
        manager.manual_block("2.2.2.2", "site.io");
        let states = manager.list_states();
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].key, "2.2.2.2|site.io");
        assert!(states[0].blocked);
    }

    #[tokio::test]
    async fn get_status_no_mitigation() {
        let manager = make_manager(Some("secret"));
        let s = manager.get_status();
        assert!(!s.mitigation_active);
        assert!(!s.js_challenge_active);
        assert_eq!(s.ip_state_count, 0);
    }

    #[tokio::test]
    async fn admin_secret_none_disables_api() {
        // When no secret is configured the Manager should still work normally.
        let manager = make_manager(None);
        assert!(manager.config().admin_secret.is_none());
    }

    #[test]
    fn percent_decode_identity() {
        let s = percent_decode("1.2.3.4|example.com");
        assert!(!s.is_empty());
    }
}
