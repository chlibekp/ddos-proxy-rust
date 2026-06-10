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

/// Constant-time byte-slice equality. Returns false fast on length mismatch
/// (lengths are not secret), otherwise compares every byte.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Normalize a URL path for security checks: resolves `.` and `..` segments
/// and collapses duplicate slashes, so `/api/../admin//x` becomes `/admin/x`.
/// Used for path-based matching only — the original path is forwarded upstream
/// untouched.
pub fn normalize_path(p: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    let mut s = String::with_capacity(p.len());
    s.push('/');
    s.push_str(&out.join("/"));
    if p.ends_with('/') && s != "/" {
        s.push('/');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::{ct_eq, normalize_path};

    #[test]
    fn normalize_resolves_dot_segments() {
        assert_eq!(normalize_path("/a/b/c"), "/a/b/c");
        assert_eq!(normalize_path("/a/./b"), "/a/b");
        assert_eq!(normalize_path("/a/../b"), "/b");
        assert_eq!(normalize_path("/api/../admin//x"), "/admin/x");
        assert_eq!(normalize_path("/../../etc/passwd"), "/etc/passwd");
        assert_eq!(normalize_path("//a///b"), "/a/b");
        assert_eq!(normalize_path("/"), "/");
        assert_eq!(normalize_path(""), "/");
    }

    #[test]
    fn normalize_preserves_trailing_slash() {
        assert_eq!(normalize_path("/a/b/"), "/a/b/");
        assert_eq!(normalize_path("/a/../"), "/");
    }

    #[test]
    fn ct_eq_basic() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
        assert!(ct_eq(b"", b""));
    }
}
