package limiter

import (
	"testing"
	"time"
)

func TestIPLimiter(t *testing.T) {
	l := NewIPLimiter()
	ip := "127.0.0.1"

	// First request should be allowed
	if !l.Allow(ip) {
		t.Error("First request should be allowed")
	}

	// Immediate second request should be denied
	if l.Allow(ip) {
		t.Error("Second request within 1s should be denied")
	}

	// Wait for 1 second
	time.Sleep(1100 * time.Millisecond)

	// Third request should be allowed
	if !l.Allow(ip) {
		t.Error("Third request after 1s should be allowed")
	}
}
