package waf

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hegy/ddos-proxy/internal/config"
	"github.com/hegy/ddos-proxy/internal/limiter"
	"github.com/hegy/ddos-proxy/internal/metrics"
	"github.com/hegy/ddos-proxy/internal/xdp"
)

var recorderPool = sync.Pool{
	New: func() any { return &responseRecorder{statusCode: http.StatusOK} },
}

// Manager holds the application state and protection logic.
type Manager struct {
	cfg             *config.Config
	rl              *limiter.RateLimiter
	templates       *template.Template
	xdp             xdp.Blocker
	mitigationUntil int64        // Atomic unix timestamp
	timeoutCount    int64        // Atomic counter for long/timed-out requests
	ipStates        sync.Map     // map[string]*ClientState
	ipStateCount    atomic.Int64 // total entries in ipStates
}

// ChallengeData is passed to the template.
type ChallengeData struct {
	Error         string
	SiteKey       string
	OriginalURL   string
	PoWSalt       string
	PoWDifficulty int
}

// NewManager creates a new WAF manager.
func NewManager(cfg *config.Config, rl *limiter.RateLimiter, tmpl *template.Template, xdpBlocker xdp.Blocker) *Manager {
	manager := &Manager{
		cfg:       cfg,
		rl:        rl,
		templates: tmpl,
		xdp:       xdpBlocker,
	}

	// Start cleanup ticker — 10s cadence keeps ipStates from growing too large.
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			manager.cleanup()
		}
	}()

	return manager
}

func (m *Manager) getClientIP(r *http.Request) string {
	if m.cfg.CloudflareSupport {
		cfIP := r.Header.Get("CF-Connecting-IP")
		if cfIP != "" {
			return cfIP
		}
	}

	if m.cfg.UseForwardedFor {
		forwarded := r.Header.Get("X-Forwarded-For")
		if forwarded != "" {
			// X-Forwarded-For: client, proxy1, proxy2
			ips := strings.Split(forwarded, ",")
			clientIP := strings.TrimSpace(ips[0])
			if clientIP != "" {
				return clientIP
			}
		}
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// If RemoteAddr doesn't have port (e.g. unit tests or special listeners), use it as is
		return r.RemoteAddr
	}
	return ip
}

func (m *Manager) verifyTurnstile(responseToken, remoteIP string) bool {
	formData := url.Values{}
	formData.Set("secret", m.cfg.TurnstileSecretKey)
	formData.Set("response", responseToken)
	formData.Set("remoteip", remoteIP)

	resp, err := http.PostForm("https://challenges.cloudflare.com/turnstile/v0/siteverify", formData)
	if err != nil {
		slog.Error("Turnstile verification failed", "error", err)
		return false
	}
	defer resp.Body.Close()

	var result struct {
		Success bool `json:"success"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		slog.Error("Failed to decode Turnstile response", "error", err)
		return false
	}
	return result.Success
}

func (m *Manager) serveChallenge(w http.ResponseWriter, r *http.Request, errMsg string) {
	ip := m.getClientIP(r)
	state := m.getClientState(ip, r.Host)

	state.mu.Lock()
	if state.powSalt == "" {
		b := make([]byte, 16)
		rand.Read(b)
		state.powSalt = hex.EncodeToString(b)
	}
	state.challengeServedAt = time.Now()
	salt := state.powSalt
	state.mu.Unlock()

	data := ChallengeData{
		Error:         errMsg,
		SiteKey:       m.cfg.TurnstileSiteKey,
		OriginalURL:   r.URL.String(),
		PoWSalt:       salt,
		PoWDifficulty: m.cfg.PoWDifficulty,
	}

	w.Header().Set("X-Mitigation", "challenge")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(http.StatusTeapot)
	m.templates.Execute(w, data)

	// Increment challenged requests metric
	if m.cfg.PrometheusEnabled {
		metrics.ChallengedRequests.Inc()
	}
}

func (m *Manager) verifyChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		if m.cfg.PrometheusEnabled {
			metrics.DroppedRequests.WithLabelValues("challenge_invalid_form").Inc()
		}
		m.serveChallenge(w, r, "Invalid form data")
		return
	}

	ip := m.getClientIP(r)

	if m.cfg.TurnstileSiteKey != "" {
		// Turnstile Verification
		responseToken := r.FormValue("cf-turnstile-response")
		if responseToken == "" {
			if m.cfg.PrometheusEnabled {
				metrics.DroppedRequests.WithLabelValues("challenge_empty_token").Inc()
			}
			m.serveChallenge(w, r, "Please complete the CAPTCHA")
			return
		}
		if !m.verifyTurnstile(responseToken, ip) {
			if m.cfg.PrometheusEnabled {
				metrics.DroppedRequests.WithLabelValues("challenge_verification_failed").Inc()
			}
			m.serveChallenge(w, r, "CAPTCHA verification failed")
			return
		}
	} else {
		// PoW Verification
		nonce := r.FormValue("pow_nonce")
		if nonce == "" {
			if m.cfg.PrometheusEnabled {
				metrics.DroppedRequests.WithLabelValues("challenge_empty_pow").Inc()
			}
			m.serveChallenge(w, r, "Please complete the PoW")
			return
		}

		state := m.getClientState(ip, r.Host)
		if state == nil {
			m.serveChallenge(w, r, "Invalid challenge session")
			return
		}
		state.mu.Lock()
		salt := state.powSalt
		servedAt := state.challengeServedAt
		state.mu.Unlock()

		if salt == "" {
			m.serveChallenge(w, r, "Invalid challenge session")
			return
		}

		if time.Since(servedAt) < 2*time.Second {
			if m.cfg.PrometheusEnabled {
				metrics.DroppedRequests.WithLabelValues("challenge_too_fast").Inc()
			}
			m.serveChallenge(w, r, "Challenge solved too quickly, please try again")
			return
		}

		hash := sha256.Sum256([]byte(salt + nonce))
		hashHex := hex.EncodeToString(hash[:])
		targetPrefix := strings.Repeat("0", m.cfg.PoWDifficulty)
		if !strings.HasPrefix(hashHex, targetPrefix) {
			if m.cfg.PrometheusEnabled {
				metrics.DroppedRequests.WithLabelValues("challenge_pow_failed").Inc()
			}
			m.serveChallenge(w, r, "PoW verification failed")
			return
		}
	}

	// Mark IP as verified
	state := m.getClientState(ip, r.Host)
	if state != nil {
		verifiedAt := time.Now()
		state.mu.Lock()
		state.violationCount = 0
		state.challengeServed = false
		state.blocked = false
		state.verified = true
		state.verifiedAt = verifiedAt
		state.powSalt = ""
		// Sync atomic fast-path fields.
		state.blockedFlag.Store(false)
		state.verifiedFlag.Store(true)
		state.verifiedUntil.Store(verifiedAt.Add(m.cfg.VerifyTime).Unix())
		state.mu.Unlock()
	}

	// Redirect to original URL
	originalURL := r.FormValue("original_url")
	if originalURL == "" {
		originalURL = "/"
	}

	if m.cfg.PrometheusEnabled {
		metrics.AllowedRequests.WithLabelValues("challenge_solved").Inc()
	}

	http.Redirect(w, r, originalURL, http.StatusFound)
}

func (m *Manager) blockL4(ip string) {
	if m.xdp == nil {
		return
	}
	slog.Info("Blocking IP on L4 via XDP", "ip", ip)
	if err := m.xdp.BlockIP(ip); err != nil {
		slog.Error("Failed to add XDP block rule", "ip", ip, "error", err)
	}
}

func (m *Manager) unblockL4(ip string) {
	if m.xdp == nil {
		return
	}
	slog.Info("Unblocking IP on L4 via XDP", "ip", ip)
	if err := m.xdp.UnblockIP(ip); err != nil {
		slog.Error("Failed to remove XDP block rule", "ip", ip, "error", err)
	}
}

func (m *Manager) getClientState(ip, host string) *ClientState {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}
	key := ip + "|" + h

	if val, ok := m.ipStates.Load(key); ok {
		return val.(*ClientState)
	}

	// Cap total tracked IPs to prevent OOM under IP-spoofed floods (0 = unlimited).
	if m.cfg.MaxIPStates > 0 && m.ipStateCount.Load() >= int64(m.cfg.MaxIPStates) {
		return nil
	}

	state := &ClientState{}
	state.lastSeen.Store(time.Now().Unix())
	actual, loaded := m.ipStates.LoadOrStore(key, state)
	if !loaded {
		m.ipStateCount.Add(1)
	}
	return actual.(*ClientState)
}

func (m *Manager) cleanup() {
	now := time.Now()
	mitigationEnd := time.Unix(atomic.LoadInt64(&m.mitigationUntil), 0)
	attackEnded := now.After(mitigationEnd)

	atomic.StoreInt64(&m.timeoutCount, 0)

	m.ipStates.Range(func(key, value interface{}) bool {
		state := value.(*ClientState)
		state.mu.Lock()
		defer state.mu.Unlock()

		// Expire verification — sync atomic flag.
		if state.verified && now.Sub(state.verifiedAt) > m.cfg.VerifyTime {
			state.verified = false
			state.verifiedFlag.Store(false)
		}

		if attackEnded && !m.cfg.AlwaysOn && !state.verified {
			m.ipStates.Delete(key)
			m.ipStateCount.Add(-1)
			return true
		}

		// Unblock after 5 minutes — sync atomic flag.
		if state.blocked && now.Sub(state.blockedAt) > 5*time.Minute {
			state.blocked = false
			state.blockedFlag.Store(false)
			state.violationCount = 0
			state.challengeServed = false
			state.errorCount = 0
			if state.l4Blocked {
				state.l4Blocked = false
				parts := strings.Split(key.(string), "|")
				if len(parts) > 0 {
					go m.unblockL4(parts[0])
				}
			}
		}

		// Evict idle unverified entries.
		if !state.verified && now.Unix()-state.lastSeen.Load() > 10*60 {
			m.ipStates.Delete(key)
			m.ipStateCount.Add(-1)
		}

		return true
	})
}

func isWebSocketUpgrade(req *http.Request) bool {
	return strings.Contains(strings.ToLower(req.Header.Get("Connection")), "upgrade") &&
		strings.ToLower(req.Header.Get("Upgrade")) == "websocket"
}

// Middleware is the main entry point for the WAF protection.
// It checks rate limits, IP blocking, and serves challenges if necessary.
func (m *Manager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isWebSocketUpgrade(r) {
			next.ServeHTTP(w, r)
			return
		}

		// Whitelisted UA check.
		ua := r.Header.Get("User-Agent")
		if len(m.cfg.WhitelistedUA) > 0 {
			for _, wua := range m.cfg.WhitelistedUA {
				if strings.Contains(ua, wua) {
					if m.rl.GetWhitelistReqCount() >= m.cfg.WhitelistRateLimit {
						if m.cfg.PrometheusEnabled {
							metrics.DroppedRequests.WithLabelValues("whitelist_rate_limit").Inc()
						}
						http.Error(w, "Rate Limit Exceeded", http.StatusTooManyRequests)
						return
					}
					m.rl.IncWhitelistReq()
					if m.cfg.PrometheusEnabled {
						metrics.AllowedRequests.WithLabelValues("whitelist").Inc()
					}
					next.ServeHTTP(w, r)
					return
				}
			}
		}

		ip := m.getClientIP(r)
		now := time.Now()
		nowUnix := now.Unix()

		state := m.getClientState(ip, r.Host)
		if state == nil {
			// ipStates cap hit — serve challenge without tracking.
			m.serveChallenge(w, r, "")
			return
		}

		state.lastSeen.Store(nowUnix)

		// ── Blocked fast-path ────────────────────────────────────────────
		if state.blockedFlag.Load() {
			state.mu.Lock()
			if state.blocked {
				if !m.cfg.CloudflareSupport && !m.cfg.UseForwardedFor {
					if !state.l4Blocked {
						state.errorCount++
						if state.errorCount > 5 {
							state.l4Blocked = true
							go m.blockL4(ip)
							state.mu.Unlock()
							if hijacker, ok := w.(http.Hijacker); ok {
								if conn, _, err := hijacker.Hijack(); err == nil {
									conn.Close()
								}
							}
							return
						}
					} else {
						state.mu.Unlock()
						if hijacker, ok := w.(http.Hijacker); ok {
							if conn, _, err := hijacker.Hijack(); err == nil {
								conn.Close()
							}
						}
						return
					}
				}
				state.mu.Unlock()
				if m.cfg.PrometheusEnabled {
					metrics.DroppedRequests.WithLabelValues("blocked_ip").Inc()
				}
				if m.cfg.BlockAction == "close" {
					if hijacker, ok := w.(http.Hijacker); ok {
						if conn, _, err := hijacker.Hijack(); err == nil {
							conn.Close()
						}
					} else {
						http.Error(w, "Forbidden", http.StatusForbidden)
					}
				} else {
					http.Error(w, "Forbidden", http.StatusForbidden)
				}
				return
			}
			state.mu.Unlock()
		}

		// ── Verified fast-path ───────────────────────────────────────────
		if state.verifiedFlag.Load() && nowUnix < state.verifiedUntil.Load() {
			if m.cfg.PrometheusEnabled {
				metrics.AllowedRequests.WithLabelValues("verified").Inc()
			}
			next.ServeHTTP(w, r)
			return
		}

		// Expire stale verified state under lock.
		state.mu.Lock()
		if state.verified {
			if now.Sub(state.verifiedAt) < m.cfg.VerifyTime {
				state.mu.Unlock()
				if m.cfg.PrometheusEnabled {
					metrics.AllowedRequests.WithLabelValues("verified").Inc()
				}
				next.ServeHTTP(w, r)
				return
			}
			state.verified = false
			state.verifiedFlag.Store(false)
		}
		state.mu.Unlock()

		if r.URL.Path == "/challenge/verify" {
			m.verifyChallenge(w, r)
			return
		}

		// Check global rate limits.
		reqRate, connRate := m.rl.GetCounts()
		mitigationUntil := atomic.LoadInt64(&m.mitigationUntil)
		shouldServeChallenge := m.cfg.AlwaysOn

		if reqRate >= m.cfg.MaxReqPerSec || connRate >= m.cfg.MaxConnPerSec {
			atomic.StoreInt64(&m.mitigationUntil, now.Add(m.cfg.MitigationTime).Unix())
			shouldServeChallenge = true
		} else if nowUnix < mitigationUntil {
			shouldServeChallenge = true
		} else if m.cfg.AutoMitigationOnTimeout {
			if atomic.LoadInt64(&m.timeoutCount) >= int64(m.cfg.MaxTimeouts) {
				atomic.StoreInt64(&m.mitigationUntil, now.Add(m.cfg.MitigationTime).Unix())
				shouldServeChallenge = true
			}
		}

		if shouldServeChallenge {
			state.mu.Lock()
			if !state.challengeServed {
				state.challengeServed = true
				state.violationCount = 0
			} else {
				state.violationCount++
				if state.violationCount > m.cfg.MaxFailedChallenges {
					state.blocked = true
					state.blockedAt = now
					state.blockedFlag.Store(true)
					state.mu.Unlock()
					if m.cfg.PrometheusEnabled {
						metrics.DroppedRequests.WithLabelValues("challenge_violation").Inc()
					}
					if m.cfg.BlockAction == "close" {
						if hijacker, ok := w.(http.Hijacker); ok {
							if conn, _, err := hijacker.Hijack(); err == nil {
								conn.Close()
							}
						}
					} else {
						http.Error(w, "Forbidden", http.StatusForbidden)
					}
					return
				}
			}
			state.mu.Unlock()
			m.serveChallenge(w, r, "")
			return
		}

		m.rl.IncReq()
		if m.cfg.PrometheusEnabled {
			metrics.AllowedRequests.WithLabelValues("normal").Inc()
		}

		if m.cfg.AutoMitigationOnTimeout {
			rr := recorderPool.Get().(*responseRecorder)
			rr.ResponseWriter = w
			rr.statusCode = http.StatusOK
			next.ServeHTTP(rr, r)
			duration := time.Since(now)
			status := rr.statusCode
			recorderPool.Put(rr)

			if duration >= m.cfg.TimeoutThreshold || status == http.StatusGatewayTimeout || status == http.StatusBadGateway {
				count := atomic.AddInt64(&m.timeoutCount, 1)
				if count >= int64(m.cfg.MaxTimeouts) {
					atomic.StoreInt64(&m.mitigationUntil, time.Now().Add(m.cfg.MitigationTime).Unix())
				}
			}
		} else {
			next.ServeHTTP(w, r)
		}
	})
}

// responseRecorder captures the status code from the ResponseWriter
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (rr *responseRecorder) WriteHeader(code int) {
	rr.statusCode = code
	rr.ResponseWriter.WriteHeader(code)
}

// Hijack implements the http.Hijacker interface to support websockets and other hijacked connections
func (rr *responseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := rr.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// Flush implements the http.Flusher interface
func (rr *responseRecorder) Flush() {
	if flusher, ok := rr.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}
