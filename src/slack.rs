use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use crate::discord::{L4Event, L4Reasons, classify_l4_reasons};
use crate::limiter::RateLimiter;
use crate::metrics;
use crate::xdp::Fingerprint;

/// Burst threshold: only alert when req/s exceeds this.
const ALERT_THRESHOLD_RPS: i64 = 9;

/// How often the background loop posts a progress update during an ongoing attack.
const UPDATE_INTERVAL_SECS: u64 = 180;

/// Seconds to wait after the first trigger before reading "real" req/s for the initial alert.
const WARMUP_SECS: u64 = 5;

/// Minimum gap between two successive initial alerts.
const INITIAL_COOLDOWN_SECS: i64 = 300;

#[derive(Clone)]
struct Snapshot {
    rps: i64,
    ips: i64,
    err_5xx: u64,
}

struct Inner {
    mitigation_until: AtomicI64,
    latest_ips: AtomicI64,
    peak_rps: AtomicU64,
    attack_started_at: AtomicI64,
    last_sent_at: AtomicI64,
    attack_active: AtomicBool,
    prev_snapshot: Mutex<Option<Snapshot>>,
    max_req_per_sec: i64,
}

/// Sends DDoS/suspicious-activity alerts to a Slack incoming webhook.
///
/// Lifecycle mirrors DiscordAlerter:
///  1. **Initial message** (red)    — fires ~5 s after mitigation activates.
///  2. **Update messages** (orange) — every 3 minutes while mitigation is still active.
///  3. **All-clear message** (green) — once the mitigation window expires.
pub struct SlackAlerter {
    webhook_url: String,
    client: reqwest::Client,
    rl: Arc<RateLimiter>,
    inner: Arc<Inner>,
}

impl SlackAlerter {
    pub fn new(webhook_url: String, max_req_per_sec: i64, rl: Arc<RateLimiter>) -> Arc<Self> {
        let inner = Arc::new(Inner {
            mitigation_until: AtomicI64::new(0),
            latest_ips: AtomicI64::new(0),
            peak_rps: AtomicU64::new(0),
            attack_started_at: AtomicI64::new(0),
            last_sent_at: AtomicI64::new(0),
            attack_active: AtomicBool::new(false),
            prev_snapshot: Mutex::new(None),
            max_req_per_sec,
        });

        let alerter = Arc::new(SlackAlerter {
            webhook_url,
            client: reqwest::Client::new(),
            rl,
            inner: inner.clone(),
        });

        let weak = Arc::downgrade(&alerter);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(UPDATE_INTERVAL_SECS));
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let Some(a) = weak.upgrade() else { break };
                a.background_tick().await;
            }
        });

        alerter
    }

    /// Called by the WAF on every request where mitigation is (re)activated.
    pub async fn notify_mitigation_active(&self, mitigation_until_unix: i64, tracked_ips: i64) {
        self.inner
            .mitigation_until
            .store(mitigation_until_unix, Ordering::SeqCst);
        self.inner.latest_ips.store(tracked_ips, Ordering::Relaxed);

        let rps = self.rl.get_last_second_total();
        self.update_peak(rps);

        if rps < ALERT_THRESHOLD_RPS {
            return;
        }

        if self.inner.attack_active.load(Ordering::SeqCst) {
            return;
        }

        let now = unix_now();
        let last = self.inner.last_sent_at.load(Ordering::SeqCst);
        if now - last < INITIAL_COOLDOWN_SECS {
            return;
        }

        if self
            .inner
            .attack_active
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }

        self.inner.attack_started_at.store(now, Ordering::SeqCst);

        let weak_inner = Arc::downgrade(&self.inner);
        let webhook = self.webhook_url.clone();
        let client = self.client.clone();
        let rl = self.rl.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(WARMUP_SECS)).await;
            let Some(inner) = weak_inner.upgrade() else { return };
            let live_rps = rl.get_last_second_total();
            let ips = inner.latest_ips.load(Ordering::Relaxed);
            let err_5xx = backend_5xx();
            let peak = inner.peak_rps.load(Ordering::Relaxed) as i64;

            let rps_u = live_rps as u64;
            let mut cur = inner.peak_rps.load(Ordering::Relaxed);
            while rps_u > cur {
                match inner.peak_rps.compare_exchange_weak(
                    cur, rps_u, Ordering::Relaxed, Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(x) => cur = x,
                }
            }

            let payload = build_initial_blocks(live_rps, peak, inner.max_req_per_sec, ips, err_5xx);
            send_message(&client, &webhook, &payload, live_rps, ips, err_5xx, &inner).await;
        });
    }

    async fn background_tick(&self) {
        if !self.inner.attack_active.load(Ordering::SeqCst) {
            return;
        }

        let now = unix_now();
        let mitigation_until = self.inner.mitigation_until.load(Ordering::SeqCst);

        let rps = self.rl.get_last_second_total();
        self.update_peak(rps);
        let ips = self.inner.latest_ips.load(Ordering::Relaxed);
        let err_5xx = backend_5xx();
        let peak = self.inner.peak_rps.load(Ordering::Relaxed) as i64;
        let started_at = self.inner.attack_started_at.load(Ordering::SeqCst);
        let duration_secs = now - started_at;

        if now >= mitigation_until {
            self.inner.attack_active.store(false, Ordering::SeqCst);
            let prev = self.inner.prev_snapshot.lock().unwrap().clone();
            let payload = build_allclear_blocks(rps, peak, ips, err_5xx, duration_secs, prev);
            send_message(
                &self.client, &self.webhook_url, &payload, rps, ips, err_5xx, &self.inner,
            )
            .await;
            self.inner.peak_rps.store(0, Ordering::Relaxed);
            *self.inner.prev_snapshot.lock().unwrap() = None;
        } else {
            let prev = self.inner.prev_snapshot.lock().unwrap().clone();
            let payload = build_update_blocks(
                rps,
                peak,
                self.inner.max_req_per_sec,
                ips,
                err_5xx,
                duration_secs,
                prev.as_ref(),
            );
            send_message(
                &self.client, &self.webhook_url, &payload, rps, ips, err_5xx, &self.inner,
            )
            .await;
        }
    }

    pub fn update_ips(&self, count: i64) {
        self.inner.latest_ips.store(count, Ordering::Relaxed);
    }

    fn update_peak(&self, rps: i64) {
        let rps_u = rps as u64;
        let mut cur = self.inner.peak_rps.load(Ordering::Relaxed);
        while rps_u > cur {
            match self.inner.peak_rps.compare_exchange_weak(
                cur, rps_u, Ordering::Relaxed, Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(x) => cur = x,
            }
        }
    }

    /// Send an L4 (XDP layer) flood alert.
    pub async fn notify_l4(
        &self,
        event: L4Event,
        pps: u64,
        peak_pps: u64,
        reasons: L4Reasons,
        fingerprints: Vec<Fingerprint>,
    ) {
        let payload = match event {
            L4Event::Start => build_l4_initial_blocks(pps, peak_pps, &reasons, &fingerprints),
            L4Event::Update => build_l4_update_blocks(pps, peak_pps, &reasons, &fingerprints),
            L4Event::Clear { duration_secs } => {
                build_l4_clear_blocks(peak_pps, duration_secs, &reasons)
            }
        };
        match self.client.post(&self.webhook_url).json(&payload).send().await {
            Ok(_) => tracing::info!(pps, peak_pps, "Sent Slack L4/XDP flood alert"),
            Err(e) => tracing::warn!(error = %e, "Failed to send Slack L4/XDP flood alert"),
        }
    }
}

// ─── HTTP send helper ────────────────────────────────────────────────────────

async fn send_message(
    client: &reqwest::Client,
    url: &str,
    payload: &Value,
    rps: i64,
    ips: i64,
    err_5xx: u64,
    inner: &Arc<Inner>,
) {
    match client.post(url).json(payload).send().await {
        Ok(_) => {
            inner.last_sent_at.store(unix_now(), Ordering::SeqCst);
            *inner.prev_snapshot.lock().unwrap() = Some(Snapshot { rps, ips, err_5xx });
            tracing::info!(rps, ips, err_5xx, "Sent Slack DDoS alert");
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to send Slack DDoS alert");
        }
    }
}

// ─── Slack Block Kit payload builders ────────────────────────────────────────

/// Builds the Slack attachment JSON for an L7 (HTTP) alert.
/// Uses the legacy `attachments` format for the colored left border,
/// with Block Kit `blocks` inside the attachment for rich layout.
fn build_initial_blocks(rps: i64, peak: i64, max_rps: i64, ips: i64, err_5xx: u64) -> Value {
    let text = format!(
        "Mitigation mode *activated*. Incoming traffic has spiked to `{rps}` req/s \
         (limit: `{max_rps}` req/s). All unverified clients are now being challenged."
    );
    json!({
        "attachments": [{
            "color": "#E74C3C",
            "blocks": [
                header_block(":rotating_light: DDoS / Suspicious Traffic Detected"),
                section_block(&text),
                fields_block(&rps_fields(rps, peak, max_rps, ips, err_5xx, None)),
                context_block("ddos-proxy  •  attack started", &slack_ts())
            ]
        }]
    })
}

fn build_update_blocks(
    rps: i64,
    peak: i64,
    max_rps: i64,
    ips: i64,
    err_5xx: u64,
    duration_secs: i64,
    prev: Option<&Snapshot>,
) -> Value {
    let trend = trend_description(rps, ips, err_5xx, prev);
    let duration_str = format_duration(duration_secs);
    let text = format!("Mitigation is still *active* after {duration_str}. {trend}");
    json!({
        "attachments": [{
            "color": "#E67E22",
            "blocks": [
                header_block(":warning: Attack In Progress — Update"),
                section_block(&text),
                fields_block(&rps_fields(rps, peak, max_rps, ips, err_5xx, prev)),
                context_block("ddos-proxy  •  mitigation ongoing", &slack_ts())
            ]
        }]
    })
}

fn build_allclear_blocks(
    rps: i64,
    peak: i64,
    ips: i64,
    err_5xx: u64,
    duration_secs: i64,
    prev: Option<Snapshot>,
) -> Value {
    let duration_str = format_duration(duration_secs);
    let prev_5xx = prev.as_ref().map(|p| p.err_5xx).unwrap_or(0);
    let new_5xx = err_5xx.saturating_sub(prev_5xx);
    let text = format!(
        "Traffic has dropped below the alert threshold. Mitigation mode \
         *deactivated* after {duration_str}. Normal proxying resumed."
    );
    let fields = vec![
        field(":timer_clock: Attack Duration", &format!("`{duration_str}`")),
        field(":chart_with_upwards_trend: Peak req/s", &format!("`{peak}` req/s")),
        field(":chart_with_downwards_trend: Current req/s", &format!("`{rps}` req/s")),
        field(":globe_with_meridians: Final Tracked IPs", &format!("`{ips}`")),
        field(":boom: 5xx During Attack", &format!("`{new_5xx}` new")),
        field(":boom: 5xx Total (session)", &format!("`{err_5xx}` total")),
    ];
    json!({
        "attachments": [{
            "color": "#2ECC71",
            "blocks": [
                header_block(":white_check_mark: Attack Subsided — All Clear"),
                section_block(&text),
                fields_block(&fields),
                context_block("ddos-proxy  •  attack resolved", &slack_ts())
            ]
        }]
    })
}

// ─── L4 / XDP flood alert builders ───────────────────────────────────────────

fn build_l4_initial_blocks(pps: u64, peak: u64, reasons: &L4Reasons, fps: &[Fingerprint]) -> Value {
    let (label, desc) = classify_l4_reasons(reasons);
    let text = format!(
        "The XDP layer is dropping *`{pps}` packets/sec*.\nSuspected attack type: *{label}* — {desc}"
    );
    json!({
        "attachments": [{
            "color": "#992D22",
            "blocks": [
                header_block(":octagonal_sign: L4 Flood Detected (XDP)"),
                section_block(&text),
                fields_block(&[
                    field(":package: Dropped pkt/s",     &format!("`{pps}` pkt/s")),
                    field(":small_red_triangle: Peak dropped pkt/s", &format!("`{peak}` pkt/s")),
                ]),
                text_block("*:dna: Drop breakdown (last sec)*"),
                text_block(&format!("`{}`", l4_breakdown(reasons))),
                text_block("*:mag: Payload fingerprint*"),
                text_block(&render_fingerprints(fps)),
                context_block("ddos-proxy  •  L4/XDP layer  •  flood started", &slack_ts())
            ]
        }]
    })
}

fn build_l4_update_blocks(pps: u64, peak: u64, reasons: &L4Reasons, fps: &[Fingerprint]) -> Value {
    let (label, desc) = classify_l4_reasons(reasons);
    let text = format!(
        "XDP is still dropping *`{pps}` packets/sec*.\nDominant type: *{label}* — {desc}"
    );
    json!({
        "attachments": [{
            "color": "#E67E22",
            "blocks": [
                header_block(":warning: L4 Flood — Update"),
                section_block(&text),
                fields_block(&[
                    field(":package: Dropped pkt/s",     &format!("`{pps}` pkt/s")),
                    field(":small_red_triangle: Peak dropped pkt/s", &format!("`{peak}` pkt/s")),
                ]),
                text_block("*:dna: Drop breakdown (last sec)*"),
                text_block(&format!("`{}`", l4_breakdown(reasons))),
                text_block("*:mag: Payload fingerprint*"),
                text_block(&render_fingerprints(fps)),
                context_block("ddos-proxy  •  L4/XDP layer  •  flood ongoing", &slack_ts())
            ]
        }]
    })
}

fn build_l4_clear_blocks(peak: u64, duration_secs: i64, reasons: &L4Reasons) -> Value {
    let duration_str = format_duration(duration_secs);
    let (label, _) = classify_l4_reasons(reasons);
    let text = format!(
        "Dropped-packet rate fell back below the alert threshold after {duration_str}. \
         Last dominant type: *{label}*."
    );
    json!({
        "attachments": [{
            "color": "#2ECC71",
            "blocks": [
                header_block(":white_check_mark: L4 Flood Subsided (XDP)"),
                section_block(&text),
                fields_block(&[
                    field(":timer_clock: Flood Duration",       &format!("`{duration_str}`")),
                    field(":small_red_triangle: Peak dropped pkt/s", &format!("`{peak}` pkt/s")),
                ]),
                context_block("ddos-proxy  •  L4/XDP layer  •  flood resolved", &slack_ts())
            ]
        }]
    })
}

// ─── Block Kit element helpers ────────────────────────────────────────────────

fn header_block(text: &str) -> Value {
    json!({
        "type": "header",
        "text": { "type": "plain_text", "text": text, "emoji": true }
    })
}

fn section_block(text: &str) -> Value {
    json!({
        "type": "section",
        "text": { "type": "mrkdwn", "text": text }
    })
}

fn text_block(text: &str) -> Value {
    json!({
        "type": "section",
        "text": { "type": "mrkdwn", "text": text }
    })
}

fn fields_block(fields: &[Value]) -> Value {
    json!({
        "type": "section",
        "fields": fields
    })
}

fn field(label: &str, value: &str) -> Value {
    json!({ "type": "mrkdwn", "text": format!("*{label}*\n{value}") })
}

fn context_block(footer: &str, ts: &str) -> Value {
    json!({
        "type": "context",
        "elements": [{
            "type": "mrkdwn",
            "text": format!("{footer}  •  {ts}")
        }]
    })
}

// ─── Field set helpers ────────────────────────────────────────────────────────

fn rps_fields(
    rps: i64,
    peak: i64,
    max_rps: i64,
    ips: i64,
    err_5xx: u64,
    prev: Option<&Snapshot>,
) -> Vec<Value> {
    let rps_delta = prev.map(|p| rps - p.rps);
    let ips_delta = prev.map(|p| ips - p.ips);
    let err_delta = prev.map(|p| err_5xx.saturating_sub(p.err_5xx));

    let rps_display = match rps_delta {
        Some(d) if d > 0 => format!("`{rps}` req/s  ▲ `+{d}`"),
        Some(d) if d < 0 => format!("`{rps}` req/s  ▼ `{d}`"),
        _ => format!("`{rps}` req/s"),
    };
    let ips_display = match ips_delta {
        Some(d) if d > 0 => format!("`{ips}`  ▲ `+{d}` new"),
        Some(d) if d < 0 => format!("`{ips}`  ▼ `{}` cleared", d.abs()),
        _ => format!("`{ips}`"),
    };
    let err_display = match err_delta {
        Some(d) if d > 0 => format!("`{err_5xx}` total  (+`{d}` since last update)"),
        _ => format!("`{err_5xx}` total"),
    };

    vec![
        field(":chart_with_upwards_trend: Current req/s",        &rps_display),
        field(":small_red_triangle: Peak req/s (session)",        &format!("`{peak}` req/s")),
        field(":gear: Configured limit",                           &format!("`{max_rps}` req/s")),
        field(":globe_with_meridians: Tracked IPs",                &ips_display),
        field(":boom: 5xx Responses",                              &err_display),
    ]
}

fn trend_description(rps: i64, ips: i64, err_5xx: u64, prev: Option<&Snapshot>) -> &'static str {
    let Some(p) = prev else {
        return "Traffic is ongoing.";
    };
    let rps_diff = rps - p.rps;
    let ips_diff = ips - p.ips;
    let err_diff = err_5xx as i64 - p.err_5xx as i64;

    match (rps_diff, ips_diff, err_diff) {
        (r, _, _) if r > 50 =>
            ":fire: Attack is *intensifying* — request rate has risen significantly.",
        (r, _, _) if r < -50 =>
            ":chart_with_downwards_trend: Traffic is *easing off* — request rate has dropped since the last update.",
        (_, i, _) if i > 100 =>
            ":globe_with_meridians: The *number of attacking IPs is growing* — possible distributed flood.",
        (_, i, _) if i < -100 =>
            ":globe_with_meridians: The *number of active IPs is shrinking* — flood may be winding down.",
        (_, _, e) if e > 500 =>
            ":boom: *Elevated backend errors* — the origin may be under stress.",
        _ =>
            ":scales: Traffic levels are *holding steady* — mitigation is actively blocking requests.",
    }
}

fn l4_breakdown(r: &L4Reasons) -> String {
    format!(
        "SYN flood {} • UDP {} • amplify {} • ICMP {} • fragment {} • bad flags {} • :80 junk {} • :443 junk {} • bad TCP {} • blocklist {}",
        r.syn_flood, r.udp, r.amplify, r.icmp, r.fragment,
        r.bad_flags, r.http_invalid, r.tls_invalid, r.tcp_malformed, r.blocklist
    )
}

fn render_fingerprints(fps: &[Fingerprint]) -> String {
    if fps.is_empty() {
        return "_No payload sample captured — likely a header-only / volumetric flood (e.g. SYN or spoofed packets)._".to_string();
    }
    let mut out = String::new();
    for (i, fp) in fps.iter().take(3).enumerate() {
        let hex = fp
            .bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        let ascii: String = fp
            .bytes
            .iter()
            .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
            .collect();
        out.push_str(&format!(
            "*#{}* ×`{}`\nhex `{hex}`\ntxt `{ascii}`\n",
            i + 1,
            fp.count,
        ));
    }
    out
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn backend_5xx() -> u64 {
    metrics::BACKEND_RESPONSES
        .with_label_values(&["5xx"])
        .get() as u64
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

/// Human-readable timestamp for the Slack context block footer.
fn slack_ts() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let (year, month, day) = days_to_ymd(secs / 86400);
    format!("{year:04}-{month:02}-{day:02} {h:02}:{m:02}:{s:02} UTC")
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let mut year = 1970u64;
    loop {
        let dy = if is_leap(year) { 366 } else { 365 };
        if days < dy { break; }
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
        if days < dm { break; }
        days -= dm;
        month += 1;
    }
    (year, month, days + 1)
}

fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}
