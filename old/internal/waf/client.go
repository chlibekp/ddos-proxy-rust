package waf

import (
	"sync"
	"sync/atomic"
	"time"
)

// ClientState tracks the state of a single client IP.
type ClientState struct {
	// Atomic fast-path fields — read without lock in hot path.
	// Always kept in sync with the mutex-protected canonical fields below.
	lastSeen      atomic.Int64 // unix timestamp
	blockedFlag   atomic.Bool
	verifiedFlag  atomic.Bool
	verifiedUntil atomic.Int64 // unix timestamp when verification expires

	// Mutex-protected fields for state mutations.
	mu                sync.Mutex
	blocked           bool
	blockedAt         time.Time
	violationCount    int
	challengeServed   bool
	challengeServedAt time.Time
	verified          bool
	verifiedAt        time.Time
	powSalt           string
	errorCount        int
	l4Blocked         bool
}
