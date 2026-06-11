use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use crate::limiter::RateLimiter;
use crate::metrics;
use crate::xdp::Fingerprint;

/// Burst threshold: only alert when req/s exceeds 500 req/min (~8.3 req/s).
pub const ALERT_THRESHOLD_RPS: i64 = 9;

/// How often the background loop posts a progress update during an ongoing attack.
const UPDATE_INTERVAL_SECS: u64 = 180; // 3 minutes

/// Seconds to wait after the first trigger before reading "real" req/s for the initial alert.
const WARMUP_SECS: u64 = 5;

/// Minimum gap between two successive initial alerts (Start embeds).
/// Applies after both a fresh start and after an all-clear, so a burst/pause/burst
/// pattern doesn't generate a Start→Clear→Start→Clear spam cycle.
const INITIAL_COOLDOWN_SECS: i64 = 300; // 5 minutes

/// Snapshot of stats captured at the time of the last Discord message.
#[derive(Clone)]
struct Snapshot {
    rps: i64,
    ips: i64,
    err_5xx: u64,
}

struct Inner {
    /// Unix timestamp (seconds) until which mitigation is active; 0 = not active.
    mitigation_until: AtomicI64,
    /// Latest tracked-IP count pushed by the WAF.
    latest_ips: AtomicI64,
    /// Running peak req/s seen during the current attack window.
    peak_rps: AtomicU64,
    /// Unix timestamp when the current attack window started.
    attack_started_at: AtomicI64,
    /// Last time any Discord message was sent (initial or update).
    last_sent_at: AtomicI64,
    /// True while the background loop considers an attack in progress.
    attack_active: AtomicBool,
    /// Stats at the time of the previous Discord message (for trend comparison).
    prev_snapshot: Mutex<Option<Snapshot>>,
    /// PROXY_MAX_REQ — shown in embeds for context.
    max_req_per_sec: i64,
}

/// Sends DDoS/suspicious-activity alerts to a Discord webhook.
///
/// Lifecycle:
///  1. **Initial embed** (red)   — fires ~5 s after mitigation activates (to read stable req/s).
///  2. **Update embeds** (orange) — every 3 minutes while mitigation is still active.
///  3. **All-clear embed** (green) — once the mitigation window expires.
pub struct DiscordAlerter {
    webhook_url: String,
    client: reqwest::Client,
    /// Live source of current req/s (reset every second by main's ticker).
    rl: Arc<RateLimiter>,
    inner: Arc<Inner>,
}

impl DiscordAlerter {
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

        let alerter = Arc::new(DiscordAlerter {
            webhook_url,
            client: reqwest::Client::new(),
            rl,
            inner: inner.clone(),
        });

        // Background task: periodic update + all-clear detection.
        let weak = Arc::downgrade(&alerter);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(UPDATE_INTERVAL_SECS));
            ticker.tick().await; // discard the immediate first tick
            loop {
                ticker.tick().await;
                let Some(a) = weak.upgrade() else { break };
                a.background_tick().await;
            }
        });

        alerter
    }

    /// Called by the WAF on every request where mitigation is (re)activated.
    /// Updates live stats and fires the initial alert if this is a new attack window.
    pub async fn notify_mitigation_active(&self, mitigation_until_unix: i64, tracked_ips: i64) {
        self.inner
            .mitigation_until
            .store(mitigation_until_unix, Ordering::SeqCst);
        self.inner.latest_ips.store(tracked_ips, Ordering::Relaxed);

        // True incoming req/s over the last complete second (counts challenged
        // and blocked requests too, unlike the proxied-only req_count).
        let rps = self.rl.get_last_second_total();
        self.update_peak(rps);

        // Below burst threshold — suppress.
        if rps < ALERT_THRESHOLD_RPS {
            return;
        }

        // Already tracking an active attack window — background loop handles updates.
        if self.inner.attack_active.load(Ordering::SeqCst) {
            return;
        }

        // Cooldown between successive attack windows.
        let now = unix_now();
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

        // Spawn a task that waits WARMUP_SECS so the rate-limiter accumulates a
        // stable full-second reading before we read the "real" req/s and post the
        // initial embed.
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

            // Update peak with the post-warmup reading.
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

            let payload = build_initial_embed(live_rps, peak, inner.max_req_per_sec, ips, err_5xx);
            send_embed(&client, &webhook, &payload, live_rps, ips, err_5xx, &inner).await;
        });
    }

    /// Fired every [`UPDATE_INTERVAL_SECS`] — posts an update or all-clear.
    async fn background_tick(&self) {
        if !self.inner.attack_active.load(Ordering::SeqCst) {
            return;
        }

        let now = unix_now();
        let mitigation_until = self.inner.mitigation_until.load(Ordering::SeqCst);

        // Read live stats — true incoming req/s over the last complete second.
        let rps = self.rl.get_last_second_total();
        self.update_peak(rps);
        let ips = self.inner.latest_ips.load(Ordering::Relaxed);
        let err_5xx = backend_5xx();
        let peak = self.inner.peak_rps.load(Ordering::Relaxed) as i64;
        let started_at = self.inner.attack_started_at.load(Ordering::SeqCst);
        let duration_secs = now - started_at;

        if now >= mitigation_until {
            // Attack ended — send all-clear and reset.
            self.inner.attack_active.store(false, Ordering::SeqCst);
            let prev = self.inner.prev_snapshot.lock().unwrap().clone();
            let payload = build_allclear_embed(rps, peak, ips, err_5xx, duration_secs, prev);
            send_embed(
                &self.client, &self.webhook_url, &payload, rps, ips, err_5xx, &self.inner,
            )
            .await;
            self.inner.peak_rps.store(0, Ordering::Relaxed);
            *self.inner.prev_snapshot.lock().unwrap() = None;
        } else {
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
            send_embed(
                &self.client, &self.webhook_url, &payload, rps, ips, err_5xx, &self.inner,
            )
            .await;
        }
    }

    /// Cheaply update the tracked-IP counter. Called by the WAF on every request
    /// during an active mitigation window so the background loop always has fresh data.
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

    /// Send an L4 (XDP layer) flood alert. Driven by the per-second XDP stats
    /// loop, which owns the detection state machine; this method only classifies
    /// the attack from the per-reason drop breakdown, renders the captured byte
    /// fingerprint, and posts the appropriate embed.
    ///
    /// `reasons` are the per-second *deltas* of each drop category, `pps`/`peak`
    /// are dropped packets-per-second, and `fingerprints` are the top recurring
    /// dropped-payload signatures (highest count first).
    pub async fn notify_l4(
        &self,
        event: L4Event,
        pps: u64,
        peak_pps: u64,
        reasons: L4Reasons,
        fingerprints: Vec<Fingerprint>,
    ) {
        let payload = match event {
            L4Event::Start => build_l4_initial(pps, peak_pps, &reasons, &fingerprints),
            L4Event::Update => build_l4_update(pps, peak_pps, &reasons, &fingerprints),
            L4Event::Clear { duration_secs } => {
                build_l4_clear(peak_pps, duration_secs, &reasons)
            }
        };
        match self.client.post(&self.webhook_url).json(&payload).send().await {
            Ok(_) => tracing::info!(pps, peak_pps, "Sent Discord L4/XDP flood alert"),
            Err(e) => tracing::warn!(error = %e, "Failed to send Discord L4/XDP flood alert"),
        }
    }
}

// ─── L4 / XDP flood alerting ──────────────────────────────────────────────────

/// Which point in the L4-flood lifecycle an alert represents.
#[derive(Clone)]
pub enum L4Event {
    /// First detection — packets/sec crossed the alert threshold.
    Start,
    /// Periodic update while the flood is still in progress.
    Update,
    /// Flood subsided — dropped rate fell back below the threshold.
    Clear { duration_secs: i64 },
}

/// Per-second deltas of each XDP drop category, used to classify the attack.
#[derive(Clone, Copy, Default)]
pub struct L4Reasons {
    pub blocklist: u64,
    pub udp: u64,
    pub tcp_malformed: u64,
    pub http_invalid: u64,
    pub tls_invalid: u64,
    pub icmp: u64,
    pub bad_flags: u64,
    pub fragment: u64,
    pub amplify: u64,
    pub syn_flood: u64,
}

/// Pick the dominant drop category and return a (short label, description) pair.
/// Public so `main::spawn_xdp_stats` can pass the type label to Prometheus.
pub fn classify_l4_reasons(r: &L4Reasons) -> (&'static str, &'static str) {
    let candidates: &[(u64, &'static str, &'static str)] = &[
        (r.syn_flood,    "SYN flood",
         "Per-source-IP SYN rate exceeded — TCP SYN flood targeting the kernel connection table."),
        (r.udp,          "UDP flood",
         "High volume of UDP to ports 80/443 — no UDP service runs there; pure volumetric junk."),
        (r.amplify,      "Amplification/reflection attack",
         "UDP from known reflection ports (DNS :53, NTP :123, SSDP :1900, Memcached :11211, LDAP :389 …) — attacker spoofed victim's IP to reflectors; amplified responses are landing here."),
        (r.icmp,         "ICMP echo (ping) flood",
         "High volume of ICMP echo requests — classic ping flood or ICMP amplification."),
        (r.fragment,     "IP fragmentation flood",
         "Fragmented IPv4 packets (MF bit or non-zero offset) — fragmentation attack or evasion attempt; legitimate HTTP/TLS is never fragmented."),
        (r.bad_flags,    "Malformed TCP flags (Xmas/NULL/SYN+FIN)",
         "TCP packets with impossible or abusive flag combinations (NULL scan, Xmas tree, SYN+FIN, RST+SYN) — crafted packet flood / scanner storm."),
        (r.http_invalid, "Non-HTTP junk flood (:80)",
         "TCP payloads to :80 whose first bytes are not a valid HTTP request line — raw garbage/replay flood."),
        (r.tls_invalid,  "Non-TLS junk flood (:443)",
         "TCP payloads to :443 that are not a TLS ClientHello — malformed/replayed junk flood."),
        (r.tcp_malformed,"Malformed-TCP flood",
         "Truncated or header-level malformed TCP segments — crafted-packet flood or spoofed-header storm."),
        (r.blocklist,    "Blocklisted-IP flood",
         "Packets from source IPs already on the XDP blocklist — repeat-offender flood."),
    ];
    let mut best: (u64, &'static str, &'static str) = (
        0,
        "Mixed L4 flood",
        "Multiple drop categories with no single dominant type.",
    );
    for &(n, label, desc) in candidates {
        if n > best.0 {
            best = (n, label, desc);
        }
    }
    (best.1, best.2)
}

/// Render the top dropped-payload fingerprints as hex + printable-ASCII so the
/// operator can see the literal bytes being replayed. Bounded to fit a Discord
/// embed field (1024 chars).
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
            "**#{}** ×`{}`\nhex `{hex}`\ntxt `{ascii}`\n",
            i + 1,
            fp.count,
        ));
    }
    out
}

fn l4_breakdown(r: &L4Reasons) -> String {
    format!(
        "SYN flood `{}` • UDP `{}` • amplify `{}` • ICMP `{}` • fragment `{}` • bad flags `{}` • :80 junk `{}` • :443 junk `{}` • bad TCP `{}` • blocklist `{}`",
        r.syn_flood, r.udp, r.amplify, r.icmp, r.fragment,
        r.bad_flags, r.http_invalid, r.tls_invalid, r.tcp_malformed, r.blocklist
    )
}

fn build_l4_initial(pps: u64, peak: u64, reasons: &L4Reasons, fps: &[Fingerprint]) -> Value {
    let (label, desc) = classify_l4_reasons(reasons);
    json!({
        "embeds": [{
            "title": "🛑 L4 Flood Detected (XDP)",
            "description": format!(
                "The XDP layer is dropping **`{pps}` packets/sec**.\nSuspected attack type: **{label}** — {desc}"
            ),
            "color": 0x992D22,
            "fields": [
                { "name": "📦 Dropped pkt/s",     "value": format!("`{pps}` pkt/s"),  "inline": true },
                { "name": "🔺 Peak dropped pkt/s", "value": format!("`{peak}` pkt/s"), "inline": true },
                { "name": "🧬 Drop breakdown (last sec)", "value": l4_breakdown(reasons), "inline": false },
                { "name": "🔎 Payload fingerprint", "value": render_fingerprints(fps), "inline": false }
            ],
            "footer": { "text": "ddos-proxy  •  L4/XDP layer  •  flood started" },
            "timestamp": iso8601_now()
        }]
    })
}

fn build_l4_update(pps: u64, peak: u64, reasons: &L4Reasons, fps: &[Fingerprint]) -> Value {
    let (label, desc) = classify_l4_reasons(reasons);
    json!({
        "embeds": [{
            "title": "⚠️ L4 Flood — Update",
            "description": format!(
                "XDP is still dropping **`{pps}` packets/sec**.\nDominant type: **{label}** — {desc}"
            ),
            "color": 0xE67E22,
            "fields": [
                { "name": "📦 Dropped pkt/s",     "value": format!("`{pps}` pkt/s"),  "inline": true },
                { "name": "🔺 Peak dropped pkt/s", "value": format!("`{peak}` pkt/s"), "inline": true },
                { "name": "🧬 Drop breakdown (last sec)", "value": l4_breakdown(reasons), "inline": false },
                { "name": "🔎 Payload fingerprint", "value": render_fingerprints(fps), "inline": false }
            ],
            "footer": { "text": "ddos-proxy  •  L4/XDP layer  •  flood ongoing" },
            "timestamp": iso8601_now()
        }]
    })
}

fn build_l4_clear(peak: u64, duration_secs: i64, reasons: &L4Reasons) -> Value {
    let duration_str = format_duration(duration_secs);
    let (label, _) = classify_l4_reasons(reasons);
    json!({
        "embeds": [{
            "title": "✅ L4 Flood Subsided (XDP)",
            "description": format!(
                "Dropped-packet rate fell back below the alert threshold after {duration_str}. \
                 Last dominant type: **{label}**."
            ),
            "color": 0x2ECC71,
            "fields": [
                { "name": "⏱️ Flood Duration",      "value": format!("`{duration_str}`"),  "inline": true },
                { "name": "🔺 Peak dropped pkt/s",   "value": format!("`{peak}` pkt/s"),    "inline": true }
            ],
            "footer": { "text": "ddos-proxy  •  L4/XDP layer  •  flood resolved" },
            "timestamp": iso8601_now()
        }]
    })
}

// ─── HTTP send helper ────────────────────────────────────────────────────────

async fn send_embed(
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
            tracing::info!(rps, ips, err_5xx, "Sent Discord DDoS alert");
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to send Discord DDoS alert");
        }
    }
}

// ─── Embed builders ──────────────────────────────────────────────────────────

fn build_initial_embed(rps: i64, peak: i64, max_rps: i64, ips: i64, err_5xx: u64) -> Value {
    json!({
        "embeds": [{
            "title": "🚨 DDoS / Suspicious Traffic Detected",
            "description": format!(
                "Mitigation mode **activated**. Incoming traffic has spiked to `{rps}` req/s \
                 (limit: `{max_rps}` req/s). All unverified clients are now being challenged."
            ),
            "color": 0xE74C3C,
            "fields": rps_fields(rps, peak, max_rps, ips, err_5xx, None),
            "footer": { "text": "ddos-proxy  •  attack started" },
            "timestamp": iso8601_now()
        }]
    })
}

fn build_update_embed(
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

    json!({
        "embeds": [{
            "title": "⚠️ Attack In Progress — Update",
            "description": format!(
                "Mitigation is still **active** after {duration_str}. {trend}"
            ),
            "color": 0xE67E22,
            "fields": rps_fields(rps, peak, max_rps, ips, err_5xx, prev),
            "footer": { "text": "ddos-proxy  •  mitigation ongoing" },
            "timestamp": iso8601_now()
        }]
    })
}

fn build_allclear_embed(
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

    json!({
        "embeds": [{
            "title": "✅ Attack Subsided — All Clear",
            "description": format!(
                "Traffic has dropped below the alert threshold. Mitigation mode \
                 **deactivated** after {duration_str}. Normal proxying resumed."
            ),
            "color": 0x2ECC71,
            "fields": [
                { "name": "⏱️ Attack Duration",      "value": format!("`{duration_str}`"),   "inline": true },
                { "name": "🔺 Peak req/s",           "value": format!("`{peak}` req/s"),     "inline": true },
                { "name": "📉 Current req/s",        "value": format!("`{rps}` req/s"),      "inline": true },
                { "name": "🌐 Final Tracked IPs",    "value": format!("`{ips}`"),            "inline": true },
                { "name": "💥 5xx During Attack",    "value": format!("`{new_5xx}` new"),    "inline": true },
                { "name": "💥 5xx Total (session)",  "value": format!("`{err_5xx}` total"),  "inline": true },
            ],
            "footer": { "text": "ddos-proxy  •  attack resolved" },
            "timestamp": iso8601_now()
        }]
    })
}

fn rps_fields(
    rps: i64,
    peak: i64,
    max_rps: i64,
    ips: i64,
    err_5xx: u64,
    prev: Option<&Snapshot>,
) -> Value {
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

    json!([
        { "name": "📈 Current req/s",        "value": rps_display,                   "inline": true },
        { "name": "🔺 Peak req/s (session)", "value": format!("`{peak}` req/s"),     "inline": true },
        { "name": "⚙️ Configured limit",     "value": format!("`{max_rps}` req/s"),  "inline": true },
        { "name": "🌐 Tracked IPs",           "value": ips_display,                   "inline": true },
        { "name": "💥 5xx Responses",         "value": err_display,                   "inline": true }
    ])
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
            "🔥 Attack is **intensifying** — request rate has risen significantly.",
        (r, _, _) if r < -50 =>
            "📉 Traffic is **easing off** — request rate has dropped since the last update.",
        (_, i, _) if i > 100 =>
            "🌐 The **number of attacking IPs is growing** — possible distributed flood.",
        (_, i, _) if i < -100 =>
            "🌐 The **number of active IPs is shrinking** — flood may be winding down.",
        (_, _, e) if e > 500 =>
            "💥 **Elevated backend errors** — the origin may be under stress.",
        _ =>
            "⚖️ Traffic levels are **holding steady** — mitigation is actively blocking requests.",
    }
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

fn iso8601_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let (year, month, day) = days_to_ymd(secs / 86400);
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}.000Z")
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
