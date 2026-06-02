package limiter

import (
	"sync"
	"time"
)

// IPLimiter limits requests per IP address.
type IPLimiter struct {
	mu       sync.Mutex
	visitors map[string]time.Time
}

// NewIPLimiter creates a new IPLimiter.
func NewIPLimiter() *IPLimiter {
	l := &IPLimiter{
		visitors: make(map[string]time.Time),
	}
	// Start cleanup routine to remove old entries
	go l.cleanup()
	return l
}

// Allow checks if the request from the given IP is allowed.
// It allows 1 request per second.
func (l *IPLimiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	last, exists := l.visitors[ip]
	now := time.Now()
	if exists && now.Sub(last) < time.Second {
		return false
	}
	l.visitors[ip] = now
	return true
}

// cleanup removes entries that haven't been seen for a while.
func (l *IPLimiter) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		l.mu.Lock()
		for ip, t := range l.visitors {
			if time.Since(t) > 1*time.Minute {
				delete(l.visitors, ip)
			}
		}
		l.mu.Unlock()
	}
}
