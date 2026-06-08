use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

/// Rate below which an attack is considered resolved (≤ 500 req/min).
pub const ALERT_THRESHOLD_RPS: i64 = 9;

/// How often the background loop posts a progress update during an ongoing attack.
const UPDATE_INTERVAL_SECS: u64 = 180; // 3 minutes

/// Minimum gap between initial alerts for back-to-back mitigation windows.
const INITIAL_COOLDOWN_SECS: i64 = 60;

/// Snapshot of stats captured at the time of the last Discord message.
#[derive(Clone)]
struct Snapshot {
    rps: i64,
    ips: i64,
    err_5xx: u64,
}

/// Shared state for the background update loop.
struct Inner {
    /// Unix timestamp (seconds) until which mitigation is active; 0 = not active.
    mitigation_until: AtomicI64,
    /// Stats provider: latest (req_per_sec, tracked_ips, 5xx_total).
    latest_rps: AtomicI64,
    latest_ips: AtomicI64,
    latest_5xx: AtomicU64,
    /// Running peak req/s seen during the current session.
    peak_rps: AtomicU64,
    /// Unix timestamp of the first alert for the current attack window.
    attack_started_at: AtomicI64,
    /// Last time any Discord message was sent (initial or update).
    last_sent_at: AtomicI64,
    /// True while the background loop considers an attack in progress.
    attack_active: AtomicBool,
    /// Stats at the time of the previous Discord message (for trend comparison).
    prev_snapshot: Mutex<Option<Snapshot>>,
    /// Max req/s configured in the proxy (used for embed context).
    max_req_per_sec: i64,
}

/// Sends DDoS/suspicious-activity alerts to a Discord webhook.
/// Fires an initial embed on attack detection, periodic update embeds every
/// [`UPDATE_INTERVAL_SECS`] while mitigation remains active, and an all-clear
/// embed once the attack subsides.
pub struct DiscordAlerter {
    webhook_url: String,
    client: reqwest::Client,
    inner: Arc<Inner>,
}

impl DiscordAlerter {
    pub fn new(webhook_url: String, max_req_per_sec: i64) -> Arc<Self> {
        let inner = Arc::new(Inner {
            mitigation_until: AtomicI64::new(0),
            latest_rps: AtomicI64::new(0),
            latest_ips: AtomicI64::new(0),
            latest_5xx: AtomicU64::new(0),
            peak_rps: AtomicU64::new(0),
            attack_started_at: AtomicI64::new(0),
            last_sent_at: AtomicI64::new(0),
            attack_active: AtomicBool::new(false),
            prev_snapshot: Mutex::new(None),
            max_req_per_sec,
        });

        let alerter = Arc::new(DiscordAlerter {
            webhook_url,
            client: reqwest::Client::new(),
            inner: inner.clone(),
        });

        // Background task: periodic update + all-clear.
        let weak = Arc::downgrade(&alerter);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(UPDATE_INTERVAL_SECS));
            ticker.tick().await; // discard immediate first tick
            loop {
                ticker.tick().await;
                let Some(a) = weak.upgrade() else { break };
                a.background_tick().await;
            }
        });

        alerter
    }

    /// Called by the WAF every time mitigation mode is (re)activated.
    /// Fires the initial alert embed if this is the start of a new attack window,
    /// and updates the shared stats so the background loop can track progress.
    pub async fn notify_mitigation_active(
        &self,
        mitigation_until_unix: i64,
        req_per_sec: i64,
        tracked_ips: i64,
        error_5xx: u64,
    ) {
        // Always keep the shared stats fresh.
        self.inner.mitigation_until.store(mitigation_until_unix, Ordering::SeqCst);
        self.inner.latest_rps.store(req_per_sec, Ordering::Relaxed);
        self.inner.latest_ips.store(tracked_ips, Ordering::Relaxed);
        self.inner.latest_5xx.store(error_5xx, Ordering::Relaxed);
        self.update_peak(req_per_sec);

        // Below threshold → suppress alert (short burst ≤ 500 req/min).
        if req_per_sec < ALERT_THRESHOLD_RPS {
            return;
        }

        let now = unix_now();

        // If an attack window is already tracked, nothing to do here — the
        // background loop handles updates.
        if self.inner.attack_active.load(Ordering::SeqCst) {
            return;
        }

        // Cooldown: don't re-alert if we just sent one.
        let last = self.inner.last_sent_at.load(Ordering::SeqCst);
        if now - last < INITIAL_COOLDOWN_SECS {
            return;
        }

        // Claim the attack slot.
        if self
            .inner
            .attack_active
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }

        self.inner.attack_started_at.store(now, Ordering::SeqCst);
        let peak = self.inner.peak_rps.load(Ordering::Relaxed) as i64;

        let payload = build_initial_embed(
            req_per_sec,
            peak,
            self.inner.max_req_per_sec,
            tracked_ips,
            error_5xx,
        );
        self.send(&payload, req_per_sec, tracked_ips, error_5xx).await;
    }

    /// Fired every [`UPDATE_INTERVAL_SECS`] by the background task.
    async fn background_tick(&self) {
        let now = unix_now();
        let mitigation_until = self.inner.mitigation_until.load(Ordering::SeqCst);
        let attack_active = self.inner.attack_active.load(Ordering::SeqCst);

        if !attack_active {
            return;
        }

        let rps = self.inner.latest_rps.load(Ordering::Relaxed);
        let ips = self.inner.latest_ips.load(Ordering::Relaxed);
        let err_5xx = self.inner.latest_5xx.load(Ordering::Relaxed);
        let peak = self.inner.peak_rps.load(Ordering::Relaxed) as i64;
        let started_at = self.inner.attack_started_at.load(Ordering::SeqCst);
        let duration_secs = now - started_at;

        if now >= mitigation_until {
            // Attack ended — send all-clear and reset state.
            self.inner.attack_active.store(false, Ordering::SeqCst);
            let prev = self.inner.prev_snapshot.lock().unwrap().clone();
            let payload = build_allclear_embed(rps, peak, ips, err_5xx, duration_secs, prev);
            self.send(&payload, rps, ips, err_5xx).await;
            // Reset peak for the next attack window.
            self.inner.peak_rps.store(0, Ordering::Relaxed);
            *self.inner.prev_snapshot.lock().unwrap() = None;
        } else {
            // Still under attack — send an update with trend commentary.
            let prev = self.inner.prev_snapshot.lock().unwrap().clone();
            let payload = build_update_embed(
                rps,
                peak,
                self.inner.max_req_per_sec,
                ips,
                err_5xx,
                duration_secs,
                prev.as_ref(),
            );
            self.send(&payload, rps, ips, err_5xx).await;
        }
    }

    /// Send a webhook payload and record the snapshot.
    async fn send(&self, payload: &Value, rps: i64, ips: i64, err_5xx: u64) {
        match self.client.post(&self.webhook_url).json(payload).send().await {
            Ok(_) => {
                let now = unix_now();
                self.inner.last_sent_at.store(now, Ordering::SeqCst);
                *self.inner.prev_snapshot.lock().unwrap() = Some(Snapshot { rps, ips, err_5xx });
                tracing::info!(rps, ips, err_5xx, "Sent Discord DDoS alert");
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to send Discord DDoS alert");
            }
        }
    }

    fn update_peak(&self, rps: i64) {
        let rps_u = rps as u64;
        let mut cur = self.inner.peak_rps.load(Ordering::Relaxed);
        while rps_u > cur {
            match self.inner.peak_rps.compare_exchange_weak(
                cur,
                rps_u,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(x) => cur = x,
            }
        }
    }
}

// ─── Embed builders ─────────────────────────────────────────────────────────

fn build_initial_embed(
    rps: i64,
    peak_rps: i64,
    max_rps: i64,
    ips: i64,
    err_5xx: u64,
) -> Value {
    json!({
        "embeds": [{
            "title": "🚨 DDoS / Suspicious Traffic Detected",
            "description": format!(
                "Mitigation mode **activated**. Incoming traffic has spiked to `{rps}` req/s \
                 (limit: `{max_rps}` req/s). All unverified clients are now being challenged."
            ),
            "color": 0xE74C3C,
            "fields": rps_fields(rps, peak_rps, max_rps, ips, err_5xx, None),
            "footer": { "text": "ddos-proxy  •  attack started" },
            "timestamp": iso8601_now()
        }]
    })
}

fn build_update_embed(
    rps: i64,
    peak_rps: i64,
    max_rps: i64,
    ips: i64,
    err_5xx: u64,
    duration_secs: i64,
    prev: Option<&Snapshot>,
) -> Value {
    let trend = trend_description(rps, ips, err_5xx, prev);
    let duration_str = format_duration(duration_secs);

    json!({
        "embeds": [{
            "title": "⚠️ Attack In Progress — Update",
            "description": format!(
                "Mitigation is still **active** after {duration_str}. {trend}"
            ),
            "color": 0xE67E22,   // orange
            "fields": rps_fields(rps, peak_rps, max_rps, ips, err_5xx, prev),
            "footer": { "text": "ddos-proxy  •  mitigation ongoing" },
            "timestamp": iso8601_now()
        }]
    })
}

fn build_allclear_embed(
    rps: i64,
    peak_rps: i64,
    ips: i64,
    err_5xx: u64,
    duration_secs: i64,
    _prev: Option<Snapshot>,
) -> Value {
    let duration_str = format_duration(duration_secs);

    json!({
        "embeds": [{
            "title": "✅ Attack Subsided — All Clear",
            "description": format!(
                "Traffic has dropped below the alert threshold. Mitigation mode \
                 **deactivated** after {duration_str}. Normal proxying resumed."
            ),
            "color": 0x2ECC71,   // green
            "fields": [
                {
                    "name": "⏱️ Attack Duration",
                    "value": format!("`{duration_str}`"),
                    "inline": true
                },
                {
                    "name": "🔺 Peak req/s",
                    "value": format!("`{peak_rps}` req/s"),
                    "inline": true
                },
                {
                    "name": "🌐 Final Tracked IPs",
                    "value": format!("`{ips}`"),
                    "inline": true
                },
                {
                    "name": "💥 Total 5xx Responses",
                    "value": format!("`{err_5xx}`"),
                    "inline": true
                },
                {
                    "name": "📉 Current req/s",
                    "value": format!("`{rps}` req/s"),
                    "inline": true
                }
            ],
            "footer": { "text": "ddos-proxy  •  attack resolved" },
            "timestamp": iso8601_now()
        }]
    })
}

/// Common embed fields for initial + update messages.
fn rps_fields(
    rps: i64,
    peak_rps: i64,
    max_rps: i64,
    ips: i64,
    err_5xx: u64,
    prev: Option<&Snapshot>,
) -> Value {
    let rps_delta = prev.map(|p| rps - p.rps);
    let ips_delta = prev.map(|p| ips - p.ips);

    let rps_display = match rps_delta {
        Some(d) if d > 0 => format!("`{rps}` req/s  ▲ `+{d}`"),
        Some(d) if d < 0 => format!("`{rps}` req/s  ▼ `{d}`"),
        _ => format!("`{rps}` req/s"),
    };
    let ips_display = match ips_delta {
        Some(d) if d > 0 => format!("`{ips}`  ▲ `+{d}` new"),
        Some(d) if d < 0 => format!("`{ips}`  ▼ `{d}` cleared"),
        _ => format!("`{ips}`"),
    };

    json!([
        { "name": "📈 Current req/s",        "value": rps_display,                              "inline": true  },
        { "name": "🔺 Peak req/s (session)", "value": format!("`{peak_rps}` req/s"),            "inline": true  },
        { "name": "⚙️ Configured limit",     "value": format!("`{max_rps}` req/s"),             "inline": true  },
        { "name": "🌐 Tracked IPs",           "value": ips_display,                              "inline": true  },
        { "name": "💥 5xx Responses",         "value": format!("`{err_5xx}` total"),             "inline": true  }
    ])
}

/// Returns a short human-readable sentence describing the traffic trend.
fn trend_description(rps: i64, ips: i64, err_5xx: u64, prev: Option<&Snapshot>) -> &'static str {
    let Some(p) = prev else {
        return "Traffic is ongoing.";
    };
    let rps_diff = rps - p.rps;
    let ips_diff = ips - p.ips;
    let err_diff = err_5xx as i64 - p.err_5xx as i64;

    match (rps_diff, ips_diff, err_diff) {
        (r, _, _) if r > 50 => "🔥 Attack is **intensifying** — request rate has risen significantly.",
        (r, _, _) if r < -50 => "📉 Traffic is **easing off** — request rate has dropped since the last update.",
        (_, i, _) if i > 100 => "🌐 The **number of attacking IPs is growing** — possible distributed flood.",
        (_, i, _) if i < -100 => "🌐 The **number of active IPs is shrinking** — possible targeted flood winding down.",
        (_, _, e) if e > 500 => "💥 **Elevated backend errors** — the origin may be under stress.",
        _ => "⚖️ Traffic levels are **holding steady** — mitigation is actively blocking requests.",
    }
}

fn format_duration(secs: i64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// ISO-8601 timestamp for Discord embeds: `YYYY-MM-DDTHH:MM:SS.000Z`
fn iso8601_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;
    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}.000Z")
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let mut year = 1970u64;
    loop {
        let dy = if is_leap(year) { 366 } else { 365 };
        if days < dy {
            break;
        }
        days -= dy;
        year += 1;
    }
    let months = if is_leap(year) {
        [31u64, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31u64, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 1u64;
    for dm in months {
        if days < dm {
            break;
        }
        days -= dm;
        month += 1;
    }
    (year, month, days + 1)
}

fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}
