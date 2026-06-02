//! TLS termination with on-demand ACME certificate issuance.
//!
//! Faithful to the Go implementation's intent (autocert-style on-demand certs,
//! HTTP-01, a host policy that only issues for hosts the backend answers 200 on,
//! staging / custom directory / EAB support, and a cert cache renewed 24h before
//! expiry). Differences from Go are noted inline.
//!
//! Note: rustls' certificate resolver is synchronous, so unlike Go (which blocks
//! the first TLS handshake while a cert is obtained), issuance runs in the
//! background and the very first handshake for a brand-new host fails; the
//! client's retry succeeds once the cert is ready.

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use dashmap::DashMap;
use http::{Request, Response, StatusCode, Uri};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, ExternalAccountKey, Identifier, LetsEncrypt,
    NewAccount, NewOrder, OrderStatus,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::net::TcpListener;
use tokio::sync::OnceCell;

use crate::body::{full, BoxedBody};
use crate::config::Config;
use crate::limiter::{IPLimiter, RateLimiter};
use crate::proxy::ReqCtx;
use crate::util::now_unix;
use crate::waf::Manager;

const RENEW_BEFORE_SECS: i64 = 24 * 3600;
const RETRY_BACKOFF_SECS: i64 = 60;

type Challenges = Arc<DashMap<String, String>>; // token -> key authorization

struct CachedCert {
    key: Arc<CertifiedKey>,
    renew_at: i64,
}

struct ResolverInner {
    cfg: Arc<Config>,
    certs: DashMap<String, Arc<CachedCert>>,
    inflight: DashMap<String, ()>,
    backoff: DashMap<String, i64>, // host -> earliest next attempt (unix secs)
    challenges: Challenges,
    account: Arc<OnceCell<Arc<Account>>>,
    cert_dir: PathBuf,
}

/// rustls cert resolver wrapper. rustls calls `resolve(&self, ...)`, so we keep
/// the shared state behind an `Arc` we can clone into background issuance tasks.
pub struct OnDemandResolver(Arc<ResolverInner>);

impl fmt::Debug for OnDemandResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OnDemandResolver")
    }
}

impl ResolvesServerCert for OnDemandResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        self.0.resolve_host(client_hello)
    }
}

impl ResolverInner {
    fn resolve_host(self: &Arc<Self>, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let host = client_hello.server_name()?.to_lowercase();

        if let Some(c) = self.certs.get(&host) {
            if now_unix() < c.renew_at {
                return Some(c.key.clone());
            }
        }

        // Try loading a previously issued cert from disk.
        if let Some(cached) = self.load_from_disk(&host) {
            let key = cached.key.clone();
            let fresh = now_unix() < cached.renew_at;
            self.certs.insert(host.clone(), Arc::new(cached));
            if fresh {
                return Some(key);
            }
        }

        self.trigger_issue(host);
        None
    }
}

impl ResolverInner {
    fn trigger_issue(self: &Arc<Self>, host: String) {
        let now = now_unix();
        if let Some(next) = self.backoff.get(&host) {
            if now < *next {
                return;
            }
        }
        if self.inflight.contains_key(&host) {
            return;
        }
        self.inflight.insert(host.clone(), ());

        let this = self.clone();
        tokio::spawn(async move {
            match this.issue(&host).await {
                Ok(cached) => {
                    tracing::info!(server_name = %host, "TLS certificate request succeeded");
                    this.certs.insert(host.clone(), Arc::new(cached));
                    this.backoff.remove(&host);
                }
                Err(e) => {
                    tracing::error!(server_name = %host, error = %e, "TLS certificate request failed");
                    this.backoff.insert(host.clone(), now_unix() + RETRY_BACKOFF_SECS);
                }
            }
            this.inflight.remove(&host);
        });
    }

    /// Host policy: only issue if the backend answers 200 on `/` for this host.
    async fn host_policy_ok(&self, host: &str) -> bool {
        let url = format!("{}/", self.cfg.backend_url.trim_end_matches('/'));
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
        {
            Ok(c) => c,
            Err(_) => return false,
        };
        match client.get(&url).header(http::header::HOST, host).send().await {
            Ok(resp) => {
                let ok = resp.status() == StatusCode::OK;
                if ok {
                    tracing::info!(host = host, backend = %self.cfg.backend_url, "ACME host policy approved host");
                } else {
                    tracing::error!(host = host, status_code = resp.status().as_u16(), "ACME host policy rejected host");
                }
                ok
            }
            Err(e) => {
                tracing::error!(host = host, error = %e, "ACME host policy backend probe failed");
                false
            }
        }
    }

    async fn get_account(&self) -> Result<Arc<Account>, String> {
        self.account
            .get_or_try_init(|| async {
                let directory = if !self.cfg.acme_directory_url.is_empty() {
                    self.cfg.acme_directory_url.clone()
                } else if self.cfg.acme_staging {
                    LetsEncrypt::Staging.url().to_string()
                } else {
                    LetsEncrypt::Production.url().to_string()
                };

                let eab = build_eab(&self.cfg)?;

                let contact_storage;
                let contact: Vec<&str> = if !self.cfg.acme_email.is_empty() {
                    contact_storage = format!("mailto:{}", self.cfg.acme_email);
                    vec![contact_storage.as_str()]
                } else {
                    Vec::new()
                };

                let (account, _creds) = Account::create(
                    &NewAccount {
                        contact: &contact,
                        terms_of_service_agreed: true,
                        only_return_existing: false,
                    },
                    &directory,
                    eab.as_ref(),
                )
                .await
                .map_err(|e| format!("ACME account creation failed: {e}"))?;
                Ok::<Arc<Account>, String>(Arc::new(account))
            })
            .await
            .cloned()
    }

    async fn issue(&self, host: &str) -> Result<CachedCert, String> {
        tracing::info!(server_name = host, "TLS certificate request received");

        if !self.host_policy_ok(host).await {
            return Err("host policy rejected".to_string());
        }

        let account = self.get_account().await?;

        let mut order = account
            .new_order(&NewOrder {
                identifiers: &[Identifier::Dns(host.to_string())],
            })
            .await
            .map_err(|e| format!("new order: {e}"))?;

        // Provision HTTP-01 challenges.
        let authorizations = order
            .authorizations()
            .await
            .map_err(|e| format!("authorizations: {e}"))?;
        let mut ready_urls: Vec<String> = Vec::new();
        let mut tokens: Vec<String> = Vec::new();
        for authz in &authorizations {
            match authz.status {
                AuthorizationStatus::Valid => continue,
                AuthorizationStatus::Pending => {}
                _ => return Err(format!("unexpected authorization status: {:?}", authz.status)),
            }
            let challenge = authz
                .challenges
                .iter()
                .find(|c| c.r#type == ChallengeType::Http01)
                .ok_or_else(|| "no http-01 challenge".to_string())?;
            let key_auth = order.key_authorization(challenge);
            self.challenges
                .insert(challenge.token.clone(), key_auth.as_str().to_string());
            tokens.push(challenge.token.clone());
            ready_urls.push(challenge.url.clone());
        }
        for url in &ready_urls {
            order
                .set_challenge_ready(url)
                .await
                .map_err(|e| format!("set challenge ready: {e}"))?;
        }

        // Poll until the order is ready (or fails).
        let mut tries = 0;
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            let state = order.refresh().await.map_err(|e| format!("refresh: {e}"))?;
            match state.status {
                OrderStatus::Ready | OrderStatus::Valid => break,
                OrderStatus::Invalid => {
                    self.clear_tokens(&tokens);
                    return Err("order became invalid".to_string());
                }
                _ => {}
            }
            tries += 1;
            if tries > 30 {
                self.clear_tokens(&tokens);
                return Err("order timed out".to_string());
            }
        }

        // Finalize with a freshly generated key + CSR.
        let key_pair = rcgen::KeyPair::generate().map_err(|e| format!("keygen: {e}"))?;
        let params = rcgen::CertificateParams::new(vec![host.to_string()])
            .map_err(|e| format!("cert params: {e}"))?;
        let csr = params
            .serialize_request(&key_pair)
            .map_err(|e| format!("csr: {e}"))?;
        order
            .finalize(csr.der())
            .await
            .map_err(|e| format!("finalize: {e}"))?;

        // Retrieve the issued certificate chain.
        let cert_chain_pem = loop {
            match order.certificate().await.map_err(|e| format!("certificate: {e}"))? {
                Some(c) => break c,
                None => tokio::time::sleep(Duration::from_secs(1)).await,
            }
        };

        self.clear_tokens(&tokens);

        let key_pem = key_pair.serialize_pem();
        let cached = build_cached_cert(&cert_chain_pem, &key_pem)?;

        // Persist to disk for reuse across restarts.
        let _ = std::fs::write(self.cert_dir.join(format!("{host}.crt")), &cert_chain_pem);
        let _ = std::fs::write(self.cert_dir.join(format!("{host}.key")), &key_pem);

        Ok(cached)
    }

    fn clear_tokens(&self, tokens: &[String]) {
        for t in tokens {
            self.challenges.remove(t);
        }
    }

    fn load_from_disk(&self, host: &str) -> Option<CachedCert> {
        let crt = std::fs::read_to_string(self.cert_dir.join(format!("{host}.crt"))).ok()?;
        let key = std::fs::read_to_string(self.cert_dir.join(format!("{host}.key"))).ok()?;
        build_cached_cert(&crt, &key).ok()
    }
}

fn build_cached_cert(cert_chain_pem: &str, key_pem: &str) -> Result<CachedCert, String> {
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_chain_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("parse cert chain: {e}"))?;
    if certs.is_empty() {
        return Err("empty cert chain".to_string());
    }

    let key_der: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .map_err(|e| format!("parse key: {e}"))?
        .ok_or_else(|| "no private key".to_string())?;
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)
        .map_err(|e| format!("signing key: {e}"))?;

    // Compute renewal deadline (notAfter - 24h) from the leaf cert.
    let renew_at = match x509_parser::parse_x509_certificate(certs[0].as_ref()) {
        Ok((_, cert)) => cert.validity().not_after.timestamp() - RENEW_BEFORE_SECS,
        Err(_) => now_unix() + 24 * 3600, // fallback: treat as valid for a day
    };

    let certified = CertifiedKey::new(certs, signing_key);
    Ok(CachedCert {
        key: Arc::new(certified),
        renew_at,
    })
}

/// Decode the EAB HMAC trying base64url(no pad), base64url, base64(no pad), base64 — like Go.
fn decode_eab_hmac(value: &str) -> Result<Vec<u8>, String> {
    let v = value.trim();
    if v.is_empty() {
        return Err("empty EAB HMAC".to_string());
    }
    let engines: [base64::engine::GeneralPurpose; 4] = [
        base64::engine::general_purpose::URL_SAFE_NO_PAD,
        base64::engine::general_purpose::URL_SAFE,
        base64::engine::general_purpose::STANDARD_NO_PAD,
        base64::engine::general_purpose::STANDARD,
    ];
    for eng in engines {
        if let Ok(d) = eng.decode(v) {
            return Ok(d);
        }
    }
    Err("unsupported EAB HMAC encoding".to_string())
}

fn build_eab(cfg: &Config) -> Result<Option<ExternalAccountKey>, String> {
    if cfg.acme_eab_key_id.is_empty() && cfg.acme_eab_hmac.is_empty() {
        return Ok(None);
    }
    if cfg.acme_eab_key_id.is_empty() || cfg.acme_eab_hmac.is_empty() {
        return Err(
            "Incomplete ACME EAB configuration; both PROXY_ACME_EAB_KEY_ID and PROXY_ACME_EAB_HMAC are required"
                .to_string(),
        );
    }
    let hmac = decode_eab_hmac(&cfg.acme_eab_hmac)?;
    Ok(Some(ExternalAccountKey::new(
        cfg.acme_eab_key_id.clone(),
        &hmac,
    )))
}

pub async fn serve_tls(
    cfg: Arc<Config>,
    manager: Arc<Manager>,
    rl: Arc<RateLimiter>,
    ip_limiter: Option<Arc<IPLimiter>>,
    target: Uri,
) {
    // Validate EAB configuration up front (Go exits on incomplete EAB).
    if let Err(e) = build_eab(&cfg) {
        tracing::error!(error = %e, "Invalid ACME configuration");
        std::process::exit(1);
    }
    if !cfg.acme_directory_url.is_empty() {
        tracing::warn!(directory_url = %cfg.acme_directory_url, "Custom ACME directory is enabled");
    } else if cfg.acme_staging {
        tracing::warn!("ACME staging is enabled; issued certificates will not be trusted by browsers");
    }

    let cert_dir = PathBuf::from("certs");
    if let Err(e) = std::fs::create_dir_all(&cert_dir) {
        tracing::error!(error = %e, "Failed to create certs directory");
        std::process::exit(1);
    }

    let challenges: Challenges = Arc::new(DashMap::new());

    let _ = target;
    let resolver = Arc::new(OnDemandResolver(Arc::new(ResolverInner {
        cfg: cfg.clone(),
        certs: DashMap::new(),
        inflight: DashMap::new(),
        backoff: DashMap::new(),
        challenges: challenges.clone(),
        account: Arc::new(OnceCell::new()),
        cert_dir,
    })));

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

    // HTTP-01 challenge + HTTP→HTTPS redirect server.
    spawn_http_redirect(cfg.clone(), challenges.clone());

    let addr = format!("0.0.0.0:{}", cfg.port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(error = %e, addr = %addr, "Server failed");
            std::process::exit(1);
        }
    };

    let mut shutdown = crate::signal_future();

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("Shutting down server...");
                break;
            }
            accept = listener.accept() => {
                let (stream, peer) = match accept {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                rl.inc_conn();
                let acceptor = tls_acceptor.clone();
                let manager = manager.clone();
                let ip_limiter = ip_limiter.clone();
                let remote = peer.to_string();
                tokio::spawn(async move {
                    let tls_stream = match acceptor.accept(stream).await {
                        Ok(s) => s,
                        Err(_) => return, // handshake failed (e.g. cert not ready yet)
                    };
                    let io = TokioIo::new(tls_stream);
                    let service = service_fn(move |req: Request<Incoming>| {
                        let manager = manager.clone();
                        let ip_limiter = ip_limiter.clone();
                        let ctx = ReqCtx { is_tls: true, remote_addr: remote.clone() };
                        async move { crate::route(req, ctx, manager, ip_limiter).await }
                    });
                    let _ = auto::Builder::new(TokioExecutor::new())
                        .serve_connection_with_upgrades(io, service)
                        .await;
                });
            }
        }
    }

    tracing::info!("Server exited properly");
}

fn spawn_http_redirect(cfg: Arc<Config>, challenges: Challenges) {
    tokio::spawn(async move {
        let addr = format!("0.0.0.0:{}", cfg.http_port);
        let listener = match TcpListener::bind(&addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(error = %e, "HTTP redirect server failed");
                return;
            }
        };
        tracing::info!(port = %cfg.http_port, "Starting HTTP to HTTPS redirect server");
        loop {
            let (stream, _peer) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => continue,
            };
            let challenges = challenges.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let service = service_fn(move |req: Request<Incoming>| {
                    let challenges = challenges.clone();
                    async move { Ok::<_, std::convert::Infallible>(redirect_or_challenge(req, challenges)) }
                });
                let _ = auto::Builder::new(TokioExecutor::new())
                    .serve_connection(io, service)
                    .await;
            });
        }
    });
}

fn redirect_or_challenge(req: Request<Incoming>, challenges: Challenges) -> Response<BoxedBody> {
    let path = req.uri().path().to_string();
    if let Some(token) = path.strip_prefix("/.well-known/acme-challenge/") {
        tracing::info!(path = %path, "ACME HTTP-01 challenge request received");
        if let Some(key_auth) = challenges.get(token) {
            let mut resp = Response::new(full(key_auth.clone()));
            resp.headers_mut().insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("text/plain"),
            );
            return resp;
        }
        let mut resp = Response::new(full("not found"));
        *resp.status_mut() = StatusCode::NOT_FOUND;
        return resp;
    }

    // Redirect everything else to HTTPS.
    let host = req
        .headers()
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let pq = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    let target = format!("https://{host}{pq}");
    let mut resp = Response::new(full(""));
    *resp.status_mut() = StatusCode::MOVED_PERMANENTLY;
    if let Ok(hv) = http::HeaderValue::from_str(&target) {
        resp.headers_mut().insert(http::header::LOCATION, hv);
    }
    resp
}
