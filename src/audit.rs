use std::collections::VecDeque;
use std::sync::Mutex;

use crate::util::now_unix;

/// Maximum audit entries retained in the ring buffer. Oldest entries are
/// evicted when the ring is full so memory usage stays bounded.
pub const AUDIT_LOG_CAPACITY: usize = 500;

/// A single recorded admin API action.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct AuditEntry {
    pub timestamp_unix: i64,
    /// Short label for the action taken (e.g. `"block"`, `"mitigation_on"`).
    pub action: String,
    /// Remote address of the admin API caller, in `ip:port` form.
    pub operator_ip: String,
    /// Optional free-form context: blocked IP+host, CIDR entry, etc.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Bounded in-memory ring buffer of admin API actions.
///
/// Entries are keyed by insertion order; the `capacity` newest are retained and
/// older entries are evicted automatically. Lock contention is negligible because
/// recording happens only on authenticated admin API calls.
pub struct AuditLog {
    capacity: usize,
    entries: Mutex<VecDeque<AuditEntry>>,
}

impl AuditLog {
    pub fn new(capacity: usize) -> Self {
        AuditLog {
            capacity,
            entries: Mutex::new(VecDeque::with_capacity(capacity.min(AUDIT_LOG_CAPACITY))),
        }
    }

    /// Append a new entry. If the ring is at capacity, the oldest entry is
    /// discarded to make room.
    pub fn record(
        &self,
        action: impl Into<String>,
        operator_ip: impl Into<String>,
        detail: Option<String>,
    ) {
        let entry = AuditEntry {
            timestamp_unix: now_unix(),
            action: action.into(),
            operator_ip: operator_ip.into(),
            detail,
        };
        let mut ring = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if ring.len() >= self.capacity {
            ring.pop_front();
        }
        ring.push_back(entry);
    }

    /// Return all retained entries, newest first.
    pub fn list(&self) -> Vec<AuditEntry> {
        let ring = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        ring.iter().rev().cloned().collect()
    }

    /// Number of entries currently retained.
    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_on_creation() {
        let log = AuditLog::new(10);
        assert!(log.is_empty());
        assert_eq!(log.list(), vec![]);
    }

    #[test]
    fn records_entry_and_lists_newest_first() {
        let log = AuditLog::new(10);
        log.record("block", "1.2.3.4:9999", Some("5.6.7.8|example.com".to_string()));
        log.record("mitigation_on", "1.2.3.4:9999", None);

        let entries = log.list();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].action, "mitigation_on");
        assert_eq!(entries[1].action, "block");
        assert_eq!(entries[1].detail.as_deref(), Some("5.6.7.8|example.com"));
    }

    #[test]
    fn evicts_oldest_when_full() {
        let log = AuditLog::new(3);
        log.record("a", "127.0.0.1:1", None);
        log.record("b", "127.0.0.1:1", None);
        log.record("c", "127.0.0.1:1", None);
        // Fourth entry must evict "a".
        log.record("d", "127.0.0.1:1", None);

        let entries = log.list();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].action, "d");
        assert_eq!(entries[2].action, "b");
        assert!(!entries.iter().any(|e| e.action == "a"));
    }

    #[test]
    fn len_tracks_entry_count() {
        let log = AuditLog::new(5);
        assert_eq!(log.len(), 0);
        log.record("x", "::1:0", None);
        assert_eq!(log.len(), 1);
        log.record("y", "::1:0", None);
        assert_eq!(log.len(), 2);
    }

    #[test]
    fn operator_ip_and_detail_stored_correctly() {
        let log = AuditLog::new(5);
        log.record("denylist_add", "10.0.0.1:8080", Some("192.168.0.0/16".to_string()));
        let e = &log.list()[0];
        assert_eq!(e.action, "denylist_add");
        assert_eq!(e.operator_ip, "10.0.0.1:8080");
        assert_eq!(e.detail.as_deref(), Some("192.168.0.0/16"));
    }

    #[test]
    fn serializes_to_json_without_null_detail() {
        let log = AuditLog::new(5);
        log.record("maintenance_on", "1.1.1.1:443", None);
        let e = &log.list()[0];
        let json = serde_json::to_string(e).unwrap();
        assert!(json.contains("\"action\":\"maintenance_on\""));
        assert!(!json.contains("\"detail\""), "null detail must be omitted");
    }
}
