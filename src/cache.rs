use std::path::PathBuf;

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Response, StatusCode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::body::{full, BoxedBody};
use crate::proxy::{max_age, normalize_cache_control, unix_now};

/// Simple disk-backed HTTP cache, the Rust analogue of the Go
/// `httpcache` + `diskcache` layer. Stores cacheable GET responses on disk and
/// serves them while fresh per `Cache-Control: max-age` / `s-maxage`.
pub struct DiskCache {
    dir: PathBuf,
}

#[derive(Serialize, Deserialize)]
struct Meta {
    status: u16,
    headers: Vec<(String, String)>,
    expires_at: i64,
}

pub struct StoredResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Bytes,
}

impl DiskCache {
    pub fn new(dir: &str) -> Self {
        let _ = std::fs::create_dir_all(dir);
        DiskCache {
            dir: PathBuf::from(dir),
        }
    }

    fn path_for(&self, key: &str) -> PathBuf {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        let name = hex::encode(hasher.finalize());
        self.dir.join(name)
    }

    pub fn get_fresh(&self, key: &str) -> Option<StoredResponse> {
        let path = self.path_for(key);
        let data = std::fs::read(&path).ok()?;
        if data.len() < 8 {
            return None;
        }
        let meta_len = u64::from_le_bytes(data[..8].try_into().ok()?) as usize;
        if data.len() < 8 + meta_len {
            return None;
        }
        let meta: Meta = serde_json::from_slice(&data[8..8 + meta_len]).ok()?;
        if unix_now() >= meta.expires_at {
            // Stale — drop it.
            let _ = std::fs::remove_file(&path);
            return None;
        }
        let body = Bytes::copy_from_slice(&data[8 + meta_len..]);
        Some(StoredResponse {
            status: meta.status,
            headers: meta.headers,
            body,
        })
    }

    /// Like `get_fresh` but ignores the freshness deadline and never deletes the
    /// entry. Used for serve-stale-on-error: a stale page beats a 502.
    pub fn get_any(&self, key: &str) -> Option<StoredResponse> {
        let path = self.path_for(key);
        let data = std::fs::read(&path).ok()?;
        if data.len() < 8 {
            return None;
        }
        let meta_len = u64::from_le_bytes(data[..8].try_into().ok()?) as usize;
        if data.len() < 8 + meta_len {
            return None;
        }
        let meta: Meta = serde_json::from_slice(&data[8..8 + meta_len]).ok()?;
        let body = Bytes::copy_from_slice(&data[8 + meta_len..]);
        Some(StoredResponse {
            status: meta.status,
            headers: meta.headers,
            body,
        })
    }

    /// Remove every cached entry. Returns the number of files deleted.
    pub fn purge(&self) -> usize {
        let mut removed = 0;
        if let Ok(entries) = std::fs::read_dir(&self.dir) {
            for entry in entries.flatten() {
                if entry.path().is_file() && std::fs::remove_file(entry.path()).is_ok() {
                    removed += 1;
                }
            }
        }
        removed
    }

    pub fn put(&self, key: &str, status: StatusCode, headers: &HeaderMap, body: &[u8]) {
        // Compute freshness lifetime from Cache-Control.
        let merged: Vec<String> = headers
            .get_all(http::header::CACHE_CONTROL)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .collect();
        if merged.is_empty() {
            return;
        }
        let cc = normalize_cache_control(&merged.join(", "));
        let ttl = match max_age(&cc) {
            Some(v) if v > 0 => v,
            _ => return,
        };

        let mut header_vec = Vec::new();
        for (name, value) in headers.iter() {
            if let Ok(v) = value.to_str() {
                header_vec.push((name.as_str().to_string(), v.to_string()));
            }
        }

        let meta = Meta {
            status: status.as_u16(),
            headers: header_vec,
            expires_at: unix_now() + ttl,
        };
        let meta_json = match serde_json::to_vec(&meta) {
            Ok(j) => j,
            Err(_) => return,
        };

        let mut out = Vec::with_capacity(8 + meta_json.len() + body.len());
        out.extend_from_slice(&(meta_json.len() as u64).to_le_bytes());
        out.extend_from_slice(&meta_json);
        out.extend_from_slice(body);
        let _ = std::fs::write(self.path_for(key), out);
    }
}

impl StoredResponse {
    pub fn into_response(self) -> Response<BoxedBody> {
        let mut builder = Response::builder().status(self.status);
        if let Some(map) = builder.headers_mut() {
            for (name, value) in self.headers {
                if let (Ok(n), Ok(v)) = (
                    HeaderName::from_bytes(name.as_bytes()),
                    HeaderValue::from_str(&value),
                ) {
                    map.append(n, v);
                }
            }
        }
        builder.body(full(self.body)).unwrap()
    }
}
