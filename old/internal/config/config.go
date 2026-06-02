package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds the application configuration loaded from environment variables.
type Config struct {
	BackendURL              string
	Port                    string
	HTTPPort                string
	MaxReqPerSec            int64
	MaxConnPerSec           int64
	VerifyTime              time.Duration
	MitigationTime          time.Duration
	TurnstileSiteKey        string
	TurnstileSecretKey      string
	AlwaysOn                bool
	UseForwardedFor         bool
	CloudflareSupport       bool
	WhitelistedUA           []string
	WhitelistRateLimit      int64
	MaxFailedChallenges     int
	PrometheusEnabled       bool
	BlockAction             string
	AutoMitigationOnTimeout bool
	MaxTimeouts             int
	TimeoutThreshold        time.Duration
	CacheEnabled            bool
	EnableSSL               bool
	ACMEStaging             bool
	ACMEDirectoryURL        string
	ACMEEmail               string
	ACMEEABKeyID            string
	ACMEEABHMAC             string
	XDPInterface            string
	PoWDifficulty           int
	MaxIPStates             int
}

// Load loads the configuration from environment variables.
// Returns an error if critical configuration is missing.
func Load() (*Config, error) {
	backendURL := os.Getenv("PROXY_BACKEND_URL")
	if backendURL == "" {
		return nil, os.ErrNotExist
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	httpPort := os.Getenv("PROXY_HTTP_PORT")
	if httpPort == "" {
		httpPort = "80"
	}

	maxReq := int64(300)
	if s := os.Getenv("PROXY_MAX_REQ"); s != "" {
		if v, err := strconv.ParseInt(s, 10, 64); err == nil {
			maxReq = v
		}
	}

	maxConn := int64(50)
	if s := os.Getenv("PROXY_MAX_CONN"); s != "" {
		if v, err := strconv.ParseInt(s, 10, 64); err == nil {
			maxConn = v
		}
	}

	verifyTime := 10 * time.Minute // Default 10 minutes
	if s := os.Getenv("PROXY_VERIFY_TIME"); s != "" {
		if v, err := time.ParseDuration(s); err == nil {
			verifyTime = v
		} else if vInt, err := strconv.Atoi(s); err == nil {
			verifyTime = time.Duration(vInt) * time.Second
		}
	}

	mitigationTime := 5 * time.Minute // Default 5 minutes
	if s := os.Getenv("PROXY_MITIGATION_TIME"); s != "" {
		if v, err := time.ParseDuration(s); err == nil {
			mitigationTime = v
		} else if vInt, err := strconv.Atoi(s); err == nil {
			mitigationTime = time.Duration(vInt) * time.Second
		}
	}

	alwaysOn := false
	if s := os.Getenv("PROXY_ALWAYS_ON"); s == "true" || s == "1" {
		alwaysOn = true
	}

	useForwardedFor := false
	if s := os.Getenv("PROXY_USE_FORWARDED_FOR"); s == "true" || s == "1" {
		useForwardedFor = true
	}

	cloudflareSupport := false
	if s := os.Getenv("PROXY_CLOUDFLARE_SUPPORT"); s == "true" || s == "1" {
		cloudflareSupport = true
	}

	var whitelistedUA []string
	if s := os.Getenv("PROXY_WHITELIST_UA"); s != "" {
		parts := strings.Split(s, ",")
		for _, p := range parts {
			if trimmed := strings.TrimSpace(p); trimmed != "" {
				whitelistedUA = append(whitelistedUA, trimmed)
			}
		}
	}

	whitelistRateLimit := int64(10)
	if s := os.Getenv("PROXY_WHITELIST_RATE"); s != "" {
		if v, err := strconv.ParseInt(s, 10, 64); err == nil {
			whitelistRateLimit = v
		}
	}

	prometheusEnabled := false
	if s := os.Getenv("PROXY_PROMETHEUS_ENABLED"); s == "true" || s == "1" {
		prometheusEnabled = true
	}

	maxFailedChallenges := 5
	if s := os.Getenv("PROXY_MAX_FAILED_CHALLENGES"); s != "" {
		if v, err := strconv.Atoi(s); err == nil {
			maxFailedChallenges = v
		}
	}

	blockAction := "403"
	if s := os.Getenv("PROXY_BLOCK_ACTION"); s == "close" {
		blockAction = "close"
	}

	autoMitigationOnTimeout := false
	if s := os.Getenv("PROXY_AUTO_MITIGATION_ON_TIMEOUT"); s == "true" || s == "1" {
		autoMitigationOnTimeout = true
	}

	maxTimeouts := 5
	if s := os.Getenv("PROXY_MAX_TIMEOUTS"); s != "" {
		if v, err := strconv.Atoi(s); err == nil {
			maxTimeouts = v
		}
	}

	timeoutThreshold := 5 * time.Second
	if s := os.Getenv("PROXY_TIMEOUT_THRESHOLD"); s != "" {
		if v, err := time.ParseDuration(s); err == nil {
			timeoutThreshold = v
		} else if vInt, err := strconv.Atoi(s); err == nil {
			timeoutThreshold = time.Duration(vInt) * time.Second
		}
	}

	cacheEnabled := false
	if s := os.Getenv("PROXY_CACHE_ENABLED"); s == "true" || s == "1" {
		cacheEnabled = true
	}

	enableSSL := false
	if s := os.Getenv("PROXY_ENABLE_SSL"); s == "true" || s == "1" {
		enableSSL = true
	}

	acmeStaging := false
	if s := os.Getenv("PROXY_ACME_STAGING"); s == "true" || s == "1" {
		acmeStaging = true
	}
	acmeDirectoryURL := strings.TrimSpace(os.Getenv("PROXY_ACME_DIRECTORY_URL"))
	acmeEmail := strings.TrimSpace(os.Getenv("PROXY_ACME_EMAIL"))
	acmeEABKeyID := strings.TrimSpace(os.Getenv("PROXY_ACME_EAB_KEY_ID"))
	acmeEABHMAC := strings.TrimSpace(os.Getenv("PROXY_ACME_EAB_HMAC"))

	powDifficulty := 5
	if s := os.Getenv("PROXY_POW_DIFFICULTY"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 {
			powDifficulty = v
		}
	}

	xdpInterface := os.Getenv("PROXY_XDP_INTERFACE")

	maxIPStates := 500_000
	if s := os.Getenv("PROXY_MAX_IP_STATES"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 {
			maxIPStates = v
		}
	}

	return &Config{
		BackendURL:              backendURL,
		Port:                    port,
		HTTPPort:                httpPort,
		MaxReqPerSec:            maxReq,
		MaxConnPerSec:           maxConn,
		VerifyTime:              verifyTime,
		MitigationTime:          mitigationTime,
		TurnstileSiteKey:        os.Getenv("PROXY_TURNSTILE_PUBLIC_KEY"),
		TurnstileSecretKey:      os.Getenv("PROXY_TURNSTILE_PRIVATE_KEY"),
		AlwaysOn:                alwaysOn,
		UseForwardedFor:         useForwardedFor,
		CloudflareSupport:       cloudflareSupport,
		WhitelistedUA:           whitelistedUA,
		WhitelistRateLimit:      whitelistRateLimit,
		MaxFailedChallenges:     maxFailedChallenges,
		PrometheusEnabled:       prometheusEnabled,
		BlockAction:             blockAction,
		AutoMitigationOnTimeout: autoMitigationOnTimeout,
		MaxTimeouts:             maxTimeouts,
		TimeoutThreshold:        timeoutThreshold,
		CacheEnabled:            cacheEnabled,
		EnableSSL:               enableSSL,
		ACMEStaging:             acmeStaging,
		ACMEDirectoryURL:        acmeDirectoryURL,
		ACMEEmail:               acmeEmail,
		ACMEEABKeyID:            acmeEABKeyID,
		ACMEEABHMAC:             acmeEABHMAC,
		XDPInterface:            xdpInterface,
		PoWDifficulty:           powDifficulty,
		MaxIPStates:             maxIPStates,
	}, nil
}
