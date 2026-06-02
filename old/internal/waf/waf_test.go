package waf

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hegy/ddos-proxy/internal/config"
	"github.com/hegy/ddos-proxy/internal/limiter"
)

// MockHijacker implements http.Hijacker and http.ResponseWriter
type MockHijacker struct {
	*httptest.ResponseRecorder
	Conn net.Conn
}

func (m *MockHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return m.Conn, bufio.NewReadWriter(bufio.NewReader(m.Conn), bufio.NewWriter(m.Conn)), nil
}

// MockConn implements net.Conn
type MockConn struct {
	net.Conn
	Closed bool
}

func (m *MockConn) Close() error {
	m.Closed = true
	return nil
}

func (m *MockConn) Read(b []byte) (n int, err error)   { return 0, nil }
func (m *MockConn) Write(b []byte) (n int, err error)  { return 0, nil }
func (m *MockConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (m *MockConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (m *MockConn) SetDeadline(t time.Time) error      { return nil }
func (m *MockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *MockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestBlockAction(t *testing.T) {
	cfg := &config.Config{
		BlockAction: "403",
		VerifyTime:  10 * time.Minute,
	}
	rl := limiter.New()
	m := NewManager(cfg, rl, nil, nil)

	// Simulate a blocked client
	// We need to access internal state. Since we are in package waf, we can use getClientState.
	// Note: getClientState returns *ClientState, which has unexported fields.
	// Since we are in the same package, we can access them.

	ip := "127.0.0.1"
	host := "example.com"
	// Ensure the state exists
	_ = m.getClientState(ip, host)

	// We need to set the state to blocked.
	// Since getClientState returns the struct pointer, we can modify it directly.
	// We need to use Range or similar to find it if we don't have direct access,
	// but getClientState gives us the pointer.

	state := m.getClientState(ip, host)
	state.mu.Lock()
	state.blocked = true
	state.mu.Unlock()
	state.blockedFlag.Store(true)

	// Test 403 (Default)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()

	// Create a dummy next handler
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := m.Middleware(next)
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d", w.Code)
	}

	// Test Close
	cfg.BlockAction = "close"
	mockConn := &MockConn{}
	mockHijacker := &MockHijacker{
		ResponseRecorder: httptest.NewRecorder(),
		Conn:             mockConn,
	}

	// Reset recorder
	mockHijacker.ResponseRecorder = httptest.NewRecorder()

	handler.ServeHTTP(mockHijacker, req)

	if !mockConn.Closed {
		t.Errorf("Expected connection to be closed when BlockAction is 'close'")
	}

	// Verify that if we change it back to 403, it returns 403
	cfg.BlockAction = "403"
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req)
	if w2.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 after changing back, got %d", w2.Code)
	}
}
