package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"html/template"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/hegy/ddos-proxy/internal/config"
	"github.com/hegy/ddos-proxy/internal/limiter"
	"github.com/hegy/ddos-proxy/internal/metrics"
	"github.com/hegy/ddos-proxy/internal/proxy"
	"github.com/hegy/ddos-proxy/internal/waf"
	"github.com/hegy/ddos-proxy/internal/xdp"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)
	stdLogger := log.New(logWriter{}, "", 0)

	cfg, err := config.Load()
	if err != nil {
		slog.Error("Failed to load configuration", "error", "PROXY_BACKEND_URL is required")
		os.Exit(1)
	}

	// Parse the backend URL.
	targetURL, err := url.Parse(cfg.BackendURL)
	if err != nil {
		slog.Error("Invalid backend URL", "url", cfg.BackendURL, "error", err)
		os.Exit(1)
	}

	// Load templates
	tmpl, err := template.ParseFiles("challenge.html")
	if err != nil {
		slog.Error("Failed to load templates", "error", err)
		os.Exit(1)
	}

	rl := limiter.New()

	var xdpBlocker xdp.Blocker
	if cfg.XDPInterface != "" {
		slog.Info("Initializing XDP blocker", "interface", cfg.XDPInterface)
		blocker, err := xdp.InitXDP(cfg.XDPInterface)
		if err != nil {
			slog.Error("Failed to initialize XDP", "error", err)
			os.Exit(1)
		}
		defer blocker.Close()
		xdpBlocker = blocker

		// Start a goroutine to print XDP stats every second
		go func() {
			ticker := time.NewTicker(1 * time.Second)
			defer ticker.Stop()

			var prevAllowed, prevBlocked uint64
			// Initialize with current stats to avoid huge spikes if XDP was already running
			if initialStats, err := blocker.GetStats(); err == nil {
				prevAllowed = initialStats.Allowed
				prevBlocked = initialStats.Blocked
			}

			for range ticker.C {
				stats, err := blocker.GetStats()
				if err == nil {
					var deltaAllowed, deltaBlocked uint64
					if stats.Allowed >= prevAllowed {
						deltaAllowed = stats.Allowed - prevAllowed
					} else {
						// eBPF counters reset
						deltaAllowed = stats.Allowed
					}

					if stats.Blocked >= prevBlocked {
						deltaBlocked = stats.Blocked - prevBlocked
					} else {
						deltaBlocked = stats.Blocked
					}

					if deltaAllowed > 0 || deltaBlocked > 0 {
						slog.Info("XDP Stats (per sec)", "ALLOWED", deltaAllowed, "BLOCKED", deltaBlocked)
					}

					if cfg.PrometheusEnabled {
						if deltaAllowed > 0 {
							metrics.XDPPackets.WithLabelValues("allowed").Add(float64(deltaAllowed))
						}
						if deltaBlocked > 0 {
							metrics.XDPPackets.WithLabelValues("blocked").Add(float64(deltaBlocked))
						}
					}
					prevAllowed = stats.Allowed
					prevBlocked = stats.Blocked
				} else {
					slog.Error("Failed to get XDP stats", "error", err)
				}
			}
		}()
	} else {
		slog.Info("XDP blocking is disabled (PROXY_XDP_INTERFACE not set)")
	}

	wafManager := waf.NewManager(cfg, rl, tmpl, xdpBlocker)

	// Start rate limiter reset ticker
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			rl.Reset()
		}
	}()

	reverseProxy := proxy.New(targetURL, cfg)
	handler := wafManager.Middleware(reverseProxy)

	mux := http.NewServeMux()
	mux.Handle("/", handler)

	if cfg.PrometheusEnabled {
		metricsLimiter := limiter.NewIPLimiter()
		metricsHandler := promhttp.Handler()
		mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
			ip, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				ip = r.RemoteAddr
			}
			if !metricsLimiter.Allow(ip) {
				metrics.DroppedRequests.WithLabelValues("metrics_rate_limit").Inc()
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
			metricsHandler.ServeHTTP(w, r)
		})
		slog.Info("Prometheus metrics enabled", "endpoint", "/metrics")
	}

	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
		ErrorLog:     stdLogger,
		ConnState: func(conn net.Conn, state http.ConnState) {
			if state == http.StateNew {
				rl.IncConn()
			}
		},
	}

	acmeDirectoryURL := ""
	certCoordinator := newCertRequestCoordinator()
	hostCertCache := newHostCertCache()
	if cfg.EnableSSL {
		// Ensure the certs directory exists
		if err := os.MkdirAll("certs", 0700); err != nil {
			slog.Error("Failed to create certs directory", "error", err)
			os.Exit(1)
		}

		m := &autocert.Manager{
			Cache:  autocert.DirCache("certs"),
			Prompt: autocert.AcceptTOS,
			Email:  cfg.ACMEEmail,
			HostPolicy: func(ctx context.Context, host string) error {
				slog.Info("ACME host policy check started", "host", host, "backend", cfg.BackendURL)
				req, err := http.NewRequestWithContext(ctx, "GET", cfg.BackendURL+"/", nil)
				if err != nil {
					slog.Error("ACME host policy request creation failed", "host", host, "error", err)
					return err
				}
				req.Host = host

				client := &http.Client{
					Timeout: 5 * time.Second,
				}
				resp, err := client.Do(req)
				if err != nil {
					slog.Error("ACME host policy backend probe failed", "host", host, "backend", cfg.BackendURL, "error", err)
					return err
				}
				defer resp.Body.Close()

				if resp.StatusCode != http.StatusOK {
					err := fmt.Errorf("backend did not respond with 200 OK on root, got %d", resp.StatusCode)
					slog.Error("ACME host policy rejected host", "host", host, "backend", cfg.BackendURL, "status_code", resp.StatusCode, "error", err)
					return err
				}
				slog.Info("ACME host policy approved host", "host", host, "backend", cfg.BackendURL, "status_code", resp.StatusCode)
				return nil
			},
		}
		acmeDirectoryURL = cfg.ACMEDirectoryURL
		if acmeDirectoryURL == "" && cfg.ACMEStaging {
			acmeDirectoryURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
		}
		if acmeDirectoryURL != "" {
			m.Client = &acme.Client{DirectoryURL: acmeDirectoryURL}
		}
		if cfg.ACMEDirectoryURL != "" {
			slog.Warn("Custom ACME directory is enabled", "directory_url", cfg.ACMEDirectoryURL)
		} else if cfg.ACMEStaging {
			slog.Warn("ACME staging is enabled; issued certificates will not be trusted by browsers")
		}
		if cfg.ACMEEABKeyID != "" || cfg.ACMEEABHMAC != "" {
			if cfg.ACMEEABKeyID == "" || cfg.ACMEEABHMAC == "" {
				slog.Error("Incomplete ACME EAB configuration; both PROXY_ACME_EAB_KEY_ID and PROXY_ACME_EAB_HMAC are required")
				os.Exit(1)
			}
			eabKey, err := decodeACMEEABKey(cfg.ACMEEABHMAC)
			if err != nil {
				slog.Error("Failed to decode ACME EAB HMAC", "error", err)
				os.Exit(1)
			}
			m.ExternalAccountBinding = &acme.ExternalAccountBinding{
				KID: cfg.ACMEEABKeyID,
				Key: eabKey,
			}
			slog.Info("ACME external account binding is enabled", "kid", cfg.ACMEEABKeyID)
		}
		tlsConfig := m.TLSConfig()
		origGetCertificate := tlsConfig.GetCertificate
		tlsConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			remoteAddr := clientHelloRemoteAddr(hello)
			host := normalizeServerName(hello)
			if cert, ok := hostCertCache.Get(host); ok {
				return cert, nil
			}
			slog.Info("TLS certificate request received",
				"server_name", host,
				"remote_addr", remoteAddr,
				"supported_protos", hello.SupportedProtos,
			)

			waitCh, started, err := certCoordinator.Start(host)
			if err != nil {
				slog.Warn("TLS certificate request rejected during ACME cooldown",
					"server_name", host,
					"remote_addr", remoteAddr,
					"error", err,
				)
				return nil, err
			}
			if !started {
				result := <-waitCh
				if result.err != nil {
					return nil, result.err
				}
				return result.cert, nil
			}

			cert, err := origGetCertificate(hello)
			certCoordinator.Finish(host, cert, err)
			if err != nil {
				slog.Error("TLS certificate request failed",
					"server_name", host,
					"remote_addr", remoteAddr,
					"error", err,
				)
				return nil, err
			}
			hostCertCache.Put(host, cert)

			slog.Info("TLS certificate request succeeded",
				"server_name", host,
				"remote_addr", remoteAddr,
			)
			return cert, nil
		}
		server.TLSConfig = tlsConfig

		// Start HTTP redirect server for Let's Encrypt HTTP-01 challenges and HTTPS redirection
		go func() {
			redirectHandler := m.HTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				target := "https://" + r.Host + r.URL.Path
				if len(r.URL.RawQuery) > 0 {
					target += "?" + r.URL.RawQuery
				}
				slog.Info("HTTP redirect request received", "host", r.Host, "path", r.URL.Path, "target", target, "remote_addr", r.RemoteAddr)
				http.Redirect(w, r, target, http.StatusMovedPermanently)
			}))

			redirectSrv := &http.Server{
				Addr: ":" + cfg.HTTPPort,
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
						slog.Info("ACME HTTP-01 challenge request received", "host", r.Host, "path", r.URL.Path, "remote_addr", r.RemoteAddr)
					}
					redirectHandler.ServeHTTP(w, r)
				}),
				ReadTimeout:  10 * time.Second,
				WriteTimeout: 10 * time.Second,
				ErrorLog:     stdLogger,
			}

			slog.Info("Starting HTTP to HTTPS redirect server", "port", cfg.HTTPPort)
			if err := redirectSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("HTTP redirect server failed", "error", err)
			}
		}()
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		slog.Info("Starting proxy server",
			"port", cfg.Port,
			"backend", cfg.BackendURL,
			"max_req_per_sec", cfg.MaxReqPerSec,
			"max_conn_per_sec", cfg.MaxConnPerSec,
			"mitigation_time", cfg.MitigationTime,
			"always_on", cfg.AlwaysOn,
			"prometheus_enabled", cfg.PrometheusEnabled,
			"ssl_enabled", cfg.EnableSSL,
			"acme_staging", cfg.ACMEStaging,
			"acme_directory_url", acmeDirectoryURL,
			"acme_email", cfg.ACMEEmail,
			"acme_eab_enabled", cfg.ACMEEABKeyID != "" && cfg.ACMEEABHMAC != "",
		)
		if cfg.EnableSSL {
			if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				slog.Error("Server failed", "error", err)
				os.Exit(1)
			}
		} else {
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("Server failed", "error", err)
				os.Exit(1)
			}
		}
	}()

	<-stop
	slog.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		slog.Error("Server forced to shutdown", "error", err)
	}

	slog.Info("Server exited properly")
}

type logWriter struct{}

func (logWriter) Write(p []byte) (int, error) {
	msg := strings.TrimRight(string(p), "\r\n")
	if msg != "" {
		slog.Error("HTTP server internal log", "message", msg)
	}
	return len(p), nil
}

func clientHelloRemoteAddr(hello *tls.ClientHelloInfo) string {
	if hello == nil || hello.Conn == nil || hello.Conn.RemoteAddr() == nil {
		return ""
	}
	return hello.Conn.RemoteAddr().String()
}

func decodeACMEEABKey(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("empty EAB HMAC")
	}

	decoders := []struct {
		name string
		fn   func(string) ([]byte, error)
	}{
		{name: "base64url-no-padding", fn: base64.RawURLEncoding.DecodeString},
		{name: "base64url", fn: base64.URLEncoding.DecodeString},
		{name: "base64-no-padding", fn: base64.RawStdEncoding.DecodeString},
		{name: "base64", fn: base64.StdEncoding.DecodeString},
	}

	var lastErr error
	for _, decoder := range decoders {
		decoded, err := decoder.fn(value)
		if err == nil {
			return decoded, nil
		}
		lastErr = err
	}

	return nil, fmt.Errorf("unsupported EAB HMAC encoding: %w", lastErr)
}

const defaultCertRetryBackoff = time.Minute
const certCacheRenewBefore = 24 * time.Hour

type certRequestCoordinator struct {
	mu     sync.Mutex
	states map[string]*certRequestState
}

type certRequestState struct {
	inFlight    bool
	waiters     []chan certRequestResult
	nextAttempt time.Time
	lastErr     string
}

type certRequestResult struct {
	cert *tls.Certificate
	err  error
}

func newCertRequestCoordinator() *certRequestCoordinator {
	return &certRequestCoordinator{
		states: make(map[string]*certRequestState),
	}
}

func (c *certRequestCoordinator) Start(host string) (<-chan certRequestResult, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	state := c.getState(host)
	now := time.Now()
	if !state.nextAttempt.IsZero() && now.Before(state.nextAttempt) {
		return nil, false, fmt.Errorf("next certificate attempt for %q allowed in %s", host, time.Until(state.nextAttempt).Round(time.Second))
	}

	if state.inFlight {
		waitCh := make(chan certRequestResult, 1)
		state.waiters = append(state.waiters, waitCh)
		return waitCh, false, nil
	}

	state.inFlight = true
	return nil, true, nil
}

func (c *certRequestCoordinator) Finish(host string, cert *tls.Certificate, err error) {
	c.mu.Lock()
	state := c.getState(host)
	state.inFlight = false

	result := certRequestResult{cert: cert, err: err}
	waiters := state.waiters
	state.waiters = nil

	if err == nil {
		state.nextAttempt = time.Time{}
		state.lastErr = ""
	} else {
		backoff := defaultCertRetryBackoff
		if retryAfter, ok := acme.RateLimit(err); ok && retryAfter > 0 {
			backoff = retryAfter
		}
		state.nextAttempt = time.Now().Add(backoff)
		state.lastErr = err.Error()
		slog.Warn("ACME certificate acquisition backoff enabled",
			"server_name", host,
			"retry_after", backoff.String(),
			"error", err,
		)
	}
	c.mu.Unlock()

	for _, waitCh := range waiters {
		waitCh <- result
		close(waitCh)
	}
}

func (c *certRequestCoordinator) getState(host string) *certRequestState {
	state, ok := c.states[host]
	if !ok {
		state = &certRequestState{}
		c.states[host] = state
	}
	return state
}

func normalizeServerName(hello *tls.ClientHelloInfo) string {
	if hello == nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(hello.ServerName))
}

type hostCertCache struct {
	mu    sync.RWMutex
	certs map[string]cachedHostCert
}

type cachedHostCert struct {
	cert      *tls.Certificate
	expiresAt time.Time
}

func newHostCertCache() *hostCertCache {
	return &hostCertCache{
		certs: make(map[string]cachedHostCert),
	}
}

func (c *hostCertCache) Get(host string) (*tls.Certificate, bool) {
	if host == "" {
		return nil, false
	}

	c.mu.RLock()
	entry, ok := c.certs[host]
	c.mu.RUnlock()
	if !ok {
		return nil, false
	}

	if time.Now().After(entry.expiresAt) {
		c.mu.Lock()
		delete(c.certs, host)
		c.mu.Unlock()
		return nil, false
	}

	return entry.cert, true
}

func (c *hostCertCache) Put(host string, cert *tls.Certificate) {
	if host == "" || cert == nil {
		return
	}

	expiresAt, ok := certRenewDeadline(cert)
	if !ok {
		return
	}

	c.mu.Lock()
	c.certs[host] = cachedHostCert{
		cert:      cert,
		expiresAt: expiresAt,
	}
	c.mu.Unlock()
}

func certRenewDeadline(cert *tls.Certificate) (time.Time, bool) {
	if cert == nil || len(cert.Certificate) == 0 {
		return time.Time{}, false
	}

	leaf := cert.Leaf
	if leaf == nil {
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return time.Time{}, false
		}
		leaf = parsed
	}

	deadline := leaf.NotAfter.Add(-certCacheRenewBefore)
	if deadline.Before(time.Now()) {
		return time.Time{}, false
	}
	return deadline, true
}
