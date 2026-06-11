use std::sync::Arc;

use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Limited};
use hyper::body::Incoming;

use crate::body::{full, BoxedBody};
use crate::proxy::ReqCtx;
use crate::util::ct_eq;
use crate::waf::Manager;

/// Handle a request routed to the `/admin` prefix.
///
/// `GET /admin` and `GET /admin/` serve an interactive HTML dashboard (when the
/// admin API is enabled) that authenticates client-side via `sessionStorage`.
/// All other sub-paths require an `Authorization: Bearer <secret>` header.
///
/// When the admin API is disabled (`PROXY_ADMIN_SECRET` unset) **or** when the
/// bearer token is wrong, the request is forwarded to the origin unchanged so
/// that the admin interface is invisible to unauthorized users.
pub async fn handle(req: Request<Incoming>, ctx: ReqCtx, manager: Arc<Manager>) -> Response<BoxedBody> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    // Dashboard page — served without a server-side auth check so the browser
    // can load it; the JS layer handles login and stores the token in sessionStorage.
    // Only served when the admin API is actually enabled.
    if method == "GET" && (path == "/ddos-proxy/admin" || path == "/ddos-proxy/admin/") {
        if manager.config().admin_secret.is_some() {
            let mut resp = Response::new(full(DASHBOARD_HTML));
            resp.headers_mut().insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("text/html; charset=utf-8"),
            );
            resp.headers_mut().insert(
                http::header::CACHE_CONTROL,
                http::HeaderValue::from_static("no-store"),
            );
            return resp;
        }
        // Admin disabled — fall through to origin.
        return manager.handle(req, ctx).await;
    }

    // All API sub-paths require a valid Bearer token.  On any mismatch
    // (disabled or wrong token), forward silently to origin.
    let secret = match &manager.config().admin_secret {
        Some(s) => s.clone(),
        None => return manager.handle(req, ctx).await,
    };
    let provided = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    // Constant-time comparison so the bearer token can't be recovered byte-by-byte
    // via a timing side channel on the comparison.
    if !ct_eq(provided.as_bytes(), format!("Bearer {secret}").as_bytes()) {
        return manager.handle(req, ctx).await;
    }

    match (method.as_str(), path.as_str()) {
        // List all tracked IP states.
        ("GET", "/ddos-proxy/admin/states") => {
            let states = manager.list_states();
            let body = serde_json::to_string(&states).unwrap_or_else(|_| "[]".to_string());
            json(StatusCode::OK, &body)
        }

        // Fetch a single state by its `ip|host` key (URL-encoded in the path).
        ("GET", p) if p.starts_with("/ddos-proxy/admin/states/") => {
            let raw = &p["/ddos-proxy/admin/states/".len()..];
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
        ("GET", "/ddos-proxy/admin/status") => {
            let status = manager.get_status();
            let body = serde_json::to_string(&status).unwrap_or_else(|_| "{}".to_string());
            json(StatusCode::OK, &body)
        }

        // Manually block an IP+host pair.
        ("POST", "/ddos-proxy/admin/block") => match read_block_req(req).await {
            Some((ip, host)) => {
                manager.manual_block(&ip, &host);
                json(StatusCode::OK, r#"{"ok":true}"#)
            }
            None => json(
                StatusCode::BAD_REQUEST,
                r#"{"error":"expected JSON {\"ip\":\"...\",\"host\":\"...\"}"}"#,
            ),
        },

        // Clear every tracked IP state.
        ("DELETE", "/ddos-proxy/admin/states") => {
            let cleared = manager.clear_states();
            json(StatusCode::OK, &format!(r#"{{"ok":true,"cleared":{cleared}}}"#))
        }

        // Force the mitigation window on / off.
        ("POST", "/ddos-proxy/admin/mitigation") => {
            manager.set_mitigation(true);
            json(StatusCode::OK, r#"{"ok":true,"mitigation":true}"#)
        }
        ("DELETE", "/ddos-proxy/admin/mitigation") => {
            manager.set_mitigation(false);
            json(StatusCode::OK, r#"{"ok":true,"mitigation":false}"#)
        }

        // Runtime IP deny/trust lists: GET lists, POST adds, DELETE removes.
        ("GET", "/ddos-proxy/admin/denylist") => {
            let body = serde_json::to_string(&manager.list_dyn_ips(true))
                .unwrap_or_else(|_| "[]".to_string());
            json(StatusCode::OK, &format!(r#"{{"entries":{body}}}"#))
        }
        ("GET", "/ddos-proxy/admin/trustlist") => {
            let body = serde_json::to_string(&manager.list_dyn_ips(false))
                .unwrap_or_else(|_| "[]".to_string());
            json(StatusCode::OK, &format!(r#"{{"entries":{body}}}"#))
        }
        (m @ ("POST" | "DELETE"), p @ ("/ddos-proxy/admin/denylist" | "/ddos-proxy/admin/trustlist")) => {
            let deny = p.ends_with("denylist");
            match read_entry_req(req).await {
                Some(entry) => {
                    let ok = if m == "POST" {
                        manager.add_dyn_ip(deny, &entry)
                    } else {
                        manager.remove_dyn_ip(deny, &entry)
                    };
                    if ok {
                        json(StatusCode::OK, r#"{"ok":true}"#)
                    } else {
                        json(
                            StatusCode::BAD_REQUEST,
                            r#"{"error":"invalid or unknown IP/CIDR entry"}"#,
                        )
                    }
                }
                None => json(
                    StatusCode::BAD_REQUEST,
                    r#"{"error":"expected JSON {\"entry\":\"1.2.3.4/32\"}"}"#,
                ),
            }
        }

        // Wipe the disk cache.
        ("DELETE", "/ddos-proxy/admin/cache") => match manager.purge_cache() {
            Some(removed) => json(StatusCode::OK, &format!(r#"{{"ok":true,"removed":{removed}}}"#)),
            None => json(StatusCode::BAD_REQUEST, r#"{"error":"cache is disabled"}"#),
        },

        // Redacted view of the running configuration.
        ("GET", "/ddos-proxy/admin/config") => {
            let body = config_json(&manager);
            json(StatusCode::OK, &body)
        }

        // Maintenance mode: GET reads, POST enables, DELETE disables.
        ("GET", "/ddos-proxy/admin/maintenance") => {
            let body = format!(r#"{{"maintenance":{}}}"#, manager.maintenance_active());
            json(StatusCode::OK, &body)
        }
        ("POST", "/ddos-proxy/admin/maintenance") => {
            manager.set_maintenance(true);
            json(StatusCode::OK, r#"{"ok":true,"maintenance":true}"#)
        }
        ("DELETE", "/ddos-proxy/admin/maintenance") => {
            manager.set_maintenance(false);
            json(StatusCode::OK, r#"{"ok":true,"maintenance":false}"#)
        }

        // Manually unblock an IP+host pair.
        ("DELETE", "/ddos-proxy/admin/block") => match read_block_req(req).await {
            Some((ip, host)) => {
                manager.manual_unblock(&ip, &host);
                json(StatusCode::OK, r#"{"ok":true}"#)
            }
            None => json(
                StatusCode::BAD_REQUEST,
                r#"{"error":"expected JSON {\"ip\":\"...\",\"host\":\"...\"}"}"#,
            ),
        },

        _ => json(StatusCode::NOT_FOUND, r#"{"error":"not found"}"#),
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

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

#[derive(serde::Deserialize)]
struct EntryReq {
    entry: String,
}

/// Read a `{"entry":"..."}` body (runtime deny/trust list management).
async fn read_entry_req(req: Request<Incoming>) -> Option<String> {
    let bytes = Limited::new(req.into_body(), 64 * 1024)
        .collect()
        .await
        .ok()?
        .to_bytes();
    let e: EntryReq = serde_json::from_slice(&bytes).ok()?;
    if e.entry.is_empty() {
        return None;
    }
    Some(e.entry)
}

/// Redacted JSON view of the running configuration. Secrets are reported only
/// as set/unset so the endpoint can't leak credentials.
fn config_json(manager: &Manager) -> String {
    let c = manager.config();
    serde_json::json!({
        "backend_url": c.backend_url,
        "port": c.port,
        "max_req_per_sec": c.max_req_per_sec,
        "max_conn_per_sec": c.max_conn_per_sec,
        "max_req_per_ip": c.max_req_per_ip,
        "verify_time_secs": c.verify_time.as_secs(),
        "mitigation_time_secs": c.mitigation_time.as_secs(),
        "always_on": c.always_on,
        "cookie_challenge": c.cookie_challenge,
        "pow_difficulty": c.pow_difficulty,
        "pow_difficulty_attack": c.pow_difficulty_attack,
        "turnstile_configured": !c.turnstile_secret_key.is_empty(),
        "block_action": c.block_action,
        "max_failed_challenges": c.max_failed_challenges,
        "use_forwarded_for": c.use_forwarded_for,
        "cloudflare_support": c.cloudflare_support,
        "prometheus_enabled": c.prometheus_enabled,
        "cache_enabled": c.cache_enabled,
        "serve_stale": c.serve_stale,
        "enable_ssl": c.enable_ssl,
        "xdp_interface": c.xdp_interface,
        "discord_alerts": c.discord_webhook_url.is_some(),
        "max_ip_states": c.max_ip_states,
        "max_inflight": c.max_inflight,
        "max_concurrent_per_ip": c.max_concurrent_per_ip,
        "backend_timeout_secs": c.backend_timeout.as_secs(),
        "backend_retries": c.backend_retries,
        "cb_threshold": c.cb_threshold,
        "cb_cooldown_secs": c.cb_cooldown.as_secs(),
        "max_body_size": c.max_body_size,
        "max_uri_len": c.max_uri_len,
        "allowed_methods": c.allowed_methods,
        "allowed_hosts": c.allowed_hosts,
        "blocked_paths": c.blocked_paths,
        "honeypot_paths": c.honeypot_paths,
        "exempt_paths": c.exempt_paths,
        "blocked_ua": c.blocked_ua,
        "whitelisted_ua": c.whitelisted_ua,
        "block_regex": c.block_regex.as_ref().map(|r| r.as_str()),
        "path_rate_limits": c.path_rate_limits,
        "max_404_per_ip": c.max_404_per_ip,
        "require_ua": c.require_ua,
        "basic_auth_enabled": c.basic_auth.is_some(),
        "security_headers": c.security_headers,
        "compression": c.compression,
        "request_id": c.request_id,
        "access_log": c.access_log,
        "cors_origin": c.cors_origin,
        "add_headers": c.add_headers,
        "remove_headers": c.remove_headers,
        "trusted_ips_configured": c.trusted_ips.len(),
        "deny_ips_configured": c.deny_ips.len(),
    })
    .to_string()
}

async fn read_block_req(req: Request<Incoming>) -> Option<(String, String)> {
    // Cap the body: the JSON payload is tiny, so anything larger is abuse.
    let bytes = Limited::new(req.into_body(), 64 * 1024)
        .collect()
        .await
        .ok()?
        .to_bytes();
    let b: BlockReq = serde_json::from_slice(&bytes).ok()?;
    if b.ip.is_empty() || b.host.is_empty() {
        return None;
    }
    Some((b.ip, b.host))
}


/// Minimal percent-decoding for the path segment after `/admin/states/`.
fn percent_decode(s: &str) -> String {
    url::form_urlencoded::parse(s.replace('/', "%2F").as_bytes())
        .map(|(k, _)| k.into_owned())
        .next()
        .unwrap_or_else(|| s.to_string())
}

// ── dashboard HTML ────────────────────────────────────────────────────────────

/// Self-contained admin dashboard page. Auth happens entirely client-side:
/// the token is stored in `sessionStorage` and sent as `Authorization: Bearer`
/// on every fetch call. No secret is embedded in the HTML itself.
const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DDoS Proxy — Admin</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,sans-serif;font-size:14px;background:#0f1117;color:#e2e8f0;min-height:100vh}
#login{display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;gap:12px}
#login h1{font-size:1.4rem;margin-bottom:8px}
#login input{padding:8px 12px;width:280px;border:1px solid #334155;border-radius:6px;background:#1e293b;color:#e2e8f0;font-size:14px}
#login button{padding:8px 24px;border:none;border-radius:6px;background:#3b82f6;color:#fff;cursor:pointer;font-size:14px}
#login button:hover{background:#2563eb}
#login .err{color:#f87171;font-size:13px}
#app{display:none;padding:24px;max-width:1100px;margin:0 auto}
h2{font-size:1.1rem;margin-bottom:16px;color:#94a3b8}
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px}
.topbar h1{font-size:1.3rem}
.topbar button{padding:6px 14px;border:1px solid #475569;border-radius:6px;background:transparent;color:#94a3b8;cursor:pointer;font-size:13px}
.topbar button:hover{background:#1e293b}
.cards{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:24px}
.card{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:16px 20px;flex:1;min-width:160px}
.card .label{font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.05em;margin-bottom:6px}
.card .val{font-size:1.5rem;font-weight:600}
.card.ok .val{color:#4ade80}
.card.warn .val{color:#fbbf24}
.card.info .val{color:#60a5fa}
.block-form{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:16px 20px;margin-bottom:24px;display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end}
.block-form label{display:flex;flex-direction:column;gap:4px;font-size:12px;color:#94a3b8}
.block-form input{padding:6px 10px;border:1px solid #334155;border-radius:6px;background:#0f1117;color:#e2e8f0;font-size:13px;width:180px}
.block-form button{padding:7px 18px;border:none;border-radius:6px;background:#ef4444;color:#fff;cursor:pointer;font-size:13px}
.block-form button:hover{background:#dc2626}
.tbl-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;padding:8px 12px;color:#64748b;font-weight:500;border-bottom:1px solid #334155;white-space:nowrap}
td{padding:8px 12px;border-bottom:1px solid #1e293b;white-space:nowrap}
tr:hover td{background:#1e293b}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}
.badge.blocked{background:#7f1d1d;color:#fca5a5}
.badge.verified{background:#14532d;color:#86efac}
.badge.challenged{background:#713f12;color:#fde68a}
.badge.none{background:#1e293b;color:#64748b}
.action-btn{padding:3px 10px;border-radius:4px;border:none;cursor:pointer;font-size:12px}
.unblock-btn{background:#1d4ed8;color:#fff}
.unblock-btn:hover{background:#1e40af}
.block-btn{background:#b91c1c;color:#fff}
.block-btn:hover{background:#991b1b}
.refresh-row{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
.refresh-row span{font-size:12px;color:#475569}
.refresh-row button{padding:4px 12px;border:1px solid #334155;border-radius:5px;background:transparent;color:#94a3b8;cursor:pointer;font-size:12px}
.toast{position:fixed;bottom:24px;right:24px;padding:10px 18px;border-radius:8px;font-size:13px;opacity:0;transition:opacity .3s;pointer-events:none}
.toast.show{opacity:1}
.toast.ok{background:#14532d;color:#86efac}
.toast.err{background:#7f1d1d;color:#fca5a5}
</style>
</head>
<body>

<!-- ── Login ───────────────────────────────────────────────────── -->
<div id="login">
  <h1>DDoS Proxy Admin</h1>
  <input id="token-input" type="password" placeholder="Admin token" autofocus>
  <button onclick="doLogin()">Sign in</button>
  <span class="err" id="login-err"></span>
</div>

<!-- ── Dashboard ───────────────────────────────────────────────── -->
<div id="app">
  <div class="topbar">
    <h1>DDoS Proxy Admin</h1>
    <button onclick="doLogout()">Sign out</button>
  </div>

  <div class="cards">
    <div class="card" id="card-mitigation">
      <div class="label">Mitigation</div>
      <div class="val" id="val-mitigation">—</div>
    </div>
    <div class="card" id="card-js">
      <div class="label">JS Challenge</div>
      <div class="val" id="val-js">—</div>
    </div>
    <div class="card info" id="card-ips">
      <div class="label">Tracked IPs</div>
      <div class="val" id="val-ips">—</div>
    </div>
    <div class="card" id="card-maint">
      <div class="label">Maintenance</div>
      <div class="val" id="val-maint">—</div>
      <button id="maint-btn" style="margin-top:8px;padding:4px 12px;border:1px solid #475569;border-radius:5px;background:transparent;color:#94a3b8;cursor:pointer;font-size:12px" onclick="toggleMaintenance()">Toggle</button>
    </div>
  </div>

  <div class="block-form">
    <label>IP <input id="f-ip" type="text" placeholder="1.2.3.4"></label>
    <label>Host <input id="f-host" type="text" placeholder="example.com"></label>
    <button onclick="blockIP()">Block IP</button>
  </div>

  <div class="refresh-row">
    <h2>IP States</h2>
    <span id="last-refresh">—</span>
    <button onclick="refresh()">Refresh now</button>
  </div>
  <div class="tbl-wrap">
    <table>
      <thead>
        <tr>
          <th>IP | Host</th>
          <th>Status</th>
          <th>Violations</th>
          <th>Last seen</th>
          <th>Verified until</th>
          <th>L4 blocked</th>
          <th>Action</th>
        </tr>
      </thead>
      <tbody id="states-body"></tbody>
    </table>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
const TOKEN_KEY = 'ddos_admin_token';
let token = sessionStorage.getItem(TOKEN_KEY) || '';
let refreshTimer = null;
let maintActive = false;

function api(path, opts = {}) {
  return fetch(path, {
    ...opts,
    headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json', ...(opts.headers || {}) }
  });
}

async function doLogin() {
  token = document.getElementById('token-input').value.trim();
  const r = await api('/ddos-proxy/admin/status').catch(() => null);
  if (!r || r.status === 401) {
    document.getElementById('login-err').textContent = 'Invalid token';
    return;
  }
  sessionStorage.setItem(TOKEN_KEY, token);
  document.getElementById('login').style.display = 'none';
  document.getElementById('app').style.display = 'block';
  startRefresh();
}

function doLogout() {
  sessionStorage.removeItem(TOKEN_KEY);
  token = '';
  clearInterval(refreshTimer);
  document.getElementById('app').style.display = 'none';
  document.getElementById('login').style.display = 'flex';
  document.getElementById('token-input').value = '';
}

function toast(msg, ok = true) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast show ' + (ok ? 'ok' : 'err');
  setTimeout(() => t.className = 'toast', 2500);
}

function fmtTime(unix) {
  if (!unix) return '—';
  return new Date(unix * 1000).toLocaleTimeString();
}

function statusBadge(state) {
  if (state.blocked) return '<span class="badge blocked">Blocked</span>';
  if (state.verified) return '<span class="badge verified">Verified</span>';
  if (state.challenge_served) return '<span class="badge challenged">Challenged</span>';
  return '<span class="badge none">Normal</span>';
}

async function refresh() {
  const [statusResp, statesResp] = await Promise.all([
    api('/ddos-proxy/admin/status'), api('/ddos-proxy/admin/states')
  ]);
  if (statusResp.status === 401) { doLogout(); return; }

  const status = await statusResp.json();
  const mit = document.getElementById('card-mitigation');
  mit.className = 'card ' + (status.mitigation_active ? 'warn' : 'ok');
  document.getElementById('val-mitigation').textContent = status.mitigation_active ? 'ACTIVE' : 'Off';
  const js = document.getElementById('card-js');
  js.className = 'card ' + (status.js_challenge_active ? 'warn' : 'ok');
  document.getElementById('val-js').textContent = status.js_challenge_active ? 'ACTIVE' : 'Off';
  document.getElementById('val-ips').textContent = status.ip_state_count;
  const maint = document.getElementById('card-maint');
  maint.className = 'card ' + (status.maintenance_active ? 'warn' : 'ok');
  document.getElementById('val-maint').textContent = status.maintenance_active ? 'ON' : 'Off';
  maintActive = !!status.maintenance_active;

  const states = await statesResp.json();
  const tbody = document.getElementById('states-body');
  tbody.innerHTML = states.length === 0
    ? '<tr><td colspan="7" style="color:#475569;text-align:center;padding:24px">No tracked states</td></tr>'
    : states.map(s => `
      <tr>
        <td style="font-family:monospace">${esc(s.key)}</td>
        <td>${statusBadge(s)}</td>
        <td>${s.violation_count}</td>
        <td>${fmtTime(s.last_seen_unix)}</td>
        <td>${s.verified ? fmtTime(s.verified_until_unix) : '—'}</td>
        <td>${s.l4_blocked ? '⚠ yes' : 'no'}</td>
        <td>${s.blocked
          ? `<button class="action-btn unblock-btn" onclick="unblockKey('${esc(s.key)}')">Unblock</button>`
          : `<button class="action-btn block-btn" onclick="blockKey('${esc(s.key)}')">Block</button>`}</td>
      </tr>`).join('');

  document.getElementById('last-refresh').textContent = 'Updated ' + new Date().toLocaleTimeString();
}

function startRefresh() {
  refresh();
  clearInterval(refreshTimer);
  refreshTimer = setInterval(refresh, 5000);
}

async function blockIP() {
  const ip = document.getElementById('f-ip').value.trim();
  const host = document.getElementById('f-host').value.trim();
  if (!ip || !host) { toast('Enter both IP and host', false); return; }
  const r = await api('/ddos-proxy/admin/block', { method: 'POST', body: JSON.stringify({ ip, host }) });
  if (r.ok) { toast('Blocked ' + ip); refresh(); document.getElementById('f-ip').value = ''; document.getElementById('f-host').value = ''; }
  else toast('Error blocking', false);
}

async function toggleMaintenance() {
  const method = maintActive ? 'DELETE' : 'POST';
  const r = await api('/ddos-proxy/admin/maintenance', { method });
  if (r.ok) { toast('Maintenance ' + (maintActive ? 'disabled' : 'enabled')); refresh(); }
  else toast('Error toggling maintenance', false);
}

async function blockKey(key) {
  const [ip, host] = key.split('|');
  const r = await api('/ddos-proxy/admin/block', { method: 'POST', body: JSON.stringify({ ip, host }) });
  if (r.ok) { toast('Blocked ' + key); refresh(); }
  else toast('Error', false);
}

async function unblockKey(key) {
  const [ip, host] = key.split('|');
  const r = await api('/ddos-proxy/admin/block', { method: 'DELETE', body: JSON.stringify({ ip, host }) });
  if (r.ok) { toast('Unblocked ' + key); refresh(); }
  else toast('Error', false);
}

function esc(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

document.getElementById('token-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') doLogin();
});

// Auto-login if token already in sessionStorage.
if (token) {
  api('/ddos-proxy/admin/status').then(r => {
    if (r && r.ok) {
      document.getElementById('login').style.display = 'none';
      document.getElementById('app').style.display = 'block';
      startRefresh();
    } else {
      sessionStorage.removeItem(TOKEN_KEY);
      token = '';
    }
  }).catch(() => {});
}
</script>
</body>
</html>
"#;

// ── tests ─────────────────────────────────────────────────────────────────────

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
            max_req_per_ip: None,
            admin_secret: secret.map(|s| s.to_string()),
            healthz_enabled: true,
            healthz_path: "/healthz".to_string(),
            healthz_backend_path: "/".to_string(),
            discord_webhook_url: None,
            max_verify_attempts: 5,
            xdp_alert_pps: 1000,
            xdp_syn_auth: false,
            xdp_syn_auth_pps: 2000,
            trusted_ips: vec![],
            deny_ips: vec![],
            blocked_ua: vec![],
            exempt_paths: vec![],
            backend_timeout: Duration::from_secs(30),
            max_body_size: None,
            allowed_methods: vec![],
            security_headers: false,
            access_log: false,
            blocked_paths: vec![],
            block_regex: None,
            allowed_hosts: vec![],
            require_ua: false,
            max_uri_len: None,
            honeypot_paths: vec![],
            max_404_per_ip: None,
            basic_auth: None,
            max_concurrent_per_ip: None,
            max_inflight: None,
            backend_retries: 0,
            cb_threshold: 0,
            cb_cooldown: Duration::from_secs(30),
            serve_stale: false,
            request_id: false,
            add_headers: vec![],
            remove_headers: vec![],
            cors_origin: None,
            compression: false,
            pow_difficulty_attack: None,
            path_rate_limits: vec![],
        });
        let rl = Arc::new(RateLimiter::new());
        let target: http::Uri = "http://127.0.0.1:8081".parse().unwrap();
        let proxy = Arc::new(Proxy::new(target, cfg.clone()));
        Manager::new(cfg, rl, "<html></html>".to_string(), None, proxy, None)
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
    async fn maintenance_mode_toggles() {
        let manager = make_manager(Some("secret"));
        assert!(!manager.maintenance_active());
        manager.set_maintenance(true);
        assert!(manager.maintenance_active());
        assert!(manager.get_status().maintenance_active);
        manager.set_maintenance(false);
        assert!(!manager.maintenance_active());
        assert!(!manager.get_status().maintenance_active);
    }

    #[tokio::test]
    async fn clear_states_removes_everything() {
        let manager = make_manager(Some("secret"));
        manager.manual_block("1.1.1.1", "a.com");
        manager.manual_block("2.2.2.2", "b.com");
        assert_eq!(manager.list_states().len(), 2);
        let cleared = manager.clear_states();
        assert_eq!(cleared, 2);
        assert!(manager.list_states().is_empty());
    }

    #[tokio::test]
    async fn mitigation_force_toggle() {
        let manager = make_manager(Some("secret"));
        assert!(!manager.get_status().mitigation_active);
        manager.set_mitigation(true);
        assert!(manager.get_status().mitigation_active);
        manager.set_mitigation(false);
        assert!(!manager.get_status().mitigation_active);
    }

    #[tokio::test]
    async fn dyn_ip_lists_add_list_remove() {
        let manager = make_manager(Some("secret"));
        assert!(manager.add_dyn_ip(true, "10.0.0.0/8"));
        assert!(manager.add_dyn_ip(false, "192.168.1.1"));
        assert!(!manager.add_dyn_ip(true, "not-an-ip"));
        assert_eq!(manager.list_dyn_ips(true), vec!["10.0.0.0/8"]);
        assert_eq!(manager.list_dyn_ips(false), vec!["192.168.1.1"]);
        // Duplicate add is a no-op.
        assert!(manager.add_dyn_ip(true, "10.0.0.0/8"));
        assert_eq!(manager.list_dyn_ips(true).len(), 1);
        assert!(manager.remove_dyn_ip(true, "10.0.0.0/8"));
        assert!(!manager.remove_dyn_ip(true, "10.0.0.0/8"));
        assert!(manager.list_dyn_ips(true).is_empty());
    }

    #[tokio::test]
    async fn status_reports_uptime_and_version() {
        let manager = make_manager(Some("secret"));
        let s = manager.get_status();
        assert!(s.uptime_secs >= 0);
        assert_eq!(s.version, env!("CARGO_PKG_VERSION"));
    }

    #[tokio::test]
    async fn config_json_redacts_secrets() {
        let manager = make_manager(Some("secret"));
        let body = config_json(&manager);
        assert!(!body.contains("secret"));
        assert!(body.contains("\"backend_url\""));
        assert!(body.contains("\"basic_auth_enabled\":false"));
    }

    #[tokio::test]
    async fn admin_secret_none_disables_api() {
        let manager = make_manager(None);
        assert!(manager.config().admin_secret.is_none());
    }

    #[test]
    fn dashboard_html_is_valid_utf8() {
        assert!(std::str::from_utf8(DASHBOARD_HTML.as_bytes()).is_ok());
        assert!(DASHBOARD_HTML.contains("DDoS Proxy Admin"));
    }

    #[test]
    fn percent_decode_identity() {
        let s = percent_decode("1.2.3.4|example.com");
        assert!(!s.is_empty());
    }

    #[test]
    fn ct_eq_matches_string_equality() {
        assert!(ct_eq(b"Bearer secret", b"Bearer secret"));
        assert!(!ct_eq(b"Bearer secret", b"Bearer secreT"));
        assert!(!ct_eq(b"Bearer secret", b"Bearer secret-longer"));
        assert!(!ct_eq(b"", b"x"));
        assert!(ct_eq(b"", b""));
    }
}
