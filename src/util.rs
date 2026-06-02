use std::time::{SystemTime, UNIX_EPOCH};

/// Current unix timestamp in seconds.
pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Current unix timestamp in milliseconds.
pub fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Detect a WebSocket upgrade request: `Connection` contains "upgrade"
/// (case-insensitive) and `Upgrade` equals "websocket" (case-insensitive).
pub fn is_websocket_upgrade<B>(req: &http::Request<B>) -> bool {
    let conn = req
        .headers()
        .get(http::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let upgrade = req
        .headers()
        .get(http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    conn.to_ascii_lowercase().contains("upgrade") && upgrade.eq_ignore_ascii_case("websocket")
}
