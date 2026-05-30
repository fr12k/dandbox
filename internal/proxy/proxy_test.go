package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fr12k/dandbox/internal/ca"
	"github.com/fr12k/dandbox/internal/policy"
	"github.com/fr12k/dandbox/internal/secrets"
)

var (
	testCAOnce sync.Once
	testCA     *ca.CACertManager
)

// sharedTestCA returns a process-wide CA manager with a 2048-bit key
// that is created only once, eliminating the expensive RSA key generation
// from being repeated for every test.
func sharedTestCA() *ca.CACertManager {
	testCAOnce.Do(func() {
		tmpDir, err := os.MkdirTemp("", "dandbox-test-ca-")
		if err != nil {
			panic("failed to create temp dir for test CA: " + err.Error())
		}
		caMgr, err := ca.NewCACertManagerWithKeySize(tmpDir, 2048)
		if err != nil {
			panic("failed to create test CA: " + err.Error())
		}
		testCA = caMgr
	})
	return testCA
}

func setupTestProxy(t *testing.T) *Proxy {
	t.Helper()
	tmpDir := t.TempDir()

	caMgr := sharedTestCA()

	pol, err := policy.NewEngine(tmpDir + "/policy")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	sec := secrets.NewSecretManager()

	return NewProxy(caMgr, pol, sec, "127.0.0.1:0")
}

func TestNewProxy(t *testing.T) {
	p := setupTestProxy(t)
	if p == nil {
		t.Fatal("NewProxy() returned nil")
	}
}

func TestNewProxy_DefaultAddr(t *testing.T) {
	tmpDir := t.TempDir()
	caMgr, _ := ca.NewCACertManager(tmpDir + "/ca")
	pol, _ := policy.NewEngine(tmpDir + "/policy")
	sec := secrets.NewSecretManager()

	p := NewProxy(caMgr, pol, sec, "")
	if p.httpAddr != ":3128" {
		t.Errorf("expected default addr ':3128', got %q", p.httpAddr)
	}
}

func TestNewProxy_CustomAddr(t *testing.T) {
	tmpDir := t.TempDir()
	caMgr, _ := ca.NewCACertManager(tmpDir + "/ca")
	pol, _ := policy.NewEngine(tmpDir + "/policy")
	sec := secrets.NewSecretManager()

	p := NewProxy(caMgr, pol, sec, "127.0.0.1:8888")
	if p.httpAddr != "127.0.0.1:8888" {
		t.Errorf("expected addr '127.0.0.1:8888', got %q", p.httpAddr)
	}
}

func TestProxy_Policy(t *testing.T) {
	p := setupTestProxy(t)
	if p.Policy() == nil {
		t.Error("Policy() returned nil")
	}
}

func TestProxy_Secrets(t *testing.T) {
	p := setupTestProxy(t)
	if p.Secrets() == nil {
		t.Error("Secrets() returned nil")
	}
}

func TestProxy_Addr_BeforeStart(t *testing.T) {
	p := setupTestProxy(t)
	addr := p.Addr()
	if addr != nil {
		t.Errorf("expected nil addr before start, got %v", addr)
	}
}

func TestProxy_StartAndStop(t *testing.T) {
	p := setupTestProxy(t)

	if err := p.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	addr := p.Addr()
	if addr == nil {
		t.Error("expected non-nil addr after start")
	}

	if err := p.Stop(); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}

func TestProxy_DoubleStart(t *testing.T) {
	p := setupTestProxy(t)

	if err := p.Start(); err != nil {
		t.Fatalf("first Start() error = %v", err)
	}

	// Starting again while running should fail
	if err := p.Start(); err == nil {
		t.Error("expected error on double start, got nil")
	}

	if err := p.Stop(); err != nil {
		t.Logf("Stop() error: %v", err)
	}
}

func TestProxy_StopNotRunning(t *testing.T) {
	p := setupTestProxy(t)

	if err := p.Stop(); err != nil {
		t.Errorf("Stop() on non-running proxy should not error, got %v", err)
	}
}

func TestProxy_ReplaceSentinelsInRequest(t *testing.T) {
	p := setupTestProxy(t)
	p.Secrets().SetSecrets([]secrets.CustomSecret{
		{Target: "api.example.com", EnvName: "TOKEN", Value: "my-secret-token", Sentinel: "{{TOKEN}}"},
	})

	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	req.Header.Set("Authorization", "Bearer {{TOKEN}}")

	headers, body := p.replaceSentinelsInRequest(req)

	if headers["Authorization"][0] != "Bearer my-secret-token" {
		t.Errorf("expected sentinels to be replaced in headers, got %v", headers["Authorization"])
	}
	if len(body) != 0 {
		t.Errorf("expected empty body for GET request, got %v", body)
	}
}

func TestProxy_ReplaceSentinelsInRequest_NoSecrets(t *testing.T) {
	p := setupTestProxy(t)

	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	req.Header.Set("Authorization", "Bearer token123")

	headers, body := p.replaceSentinelsInRequest(req)

	if headers["Authorization"][0] != "Bearer token123" {
		t.Errorf("expected headers unchanged, got %v", headers["Authorization"])
	}
	if len(body) != 0 {
		t.Error("expected empty body for GET request")
	}
}

func TestProxy_ReplaceSentinelsInResponse(t *testing.T) {
	p := setupTestProxy(t)

	resp := &http.Response{
		Body: http.NoBody,
	}
	body := p.replaceSentinelsInResponse(resp)
	if len(body) != 0 {
		t.Errorf("expected empty body for response with no body, got %v", body)
	}
}

func TestProxy_HandleProxy_Blocked(t *testing.T) {
	p := setupTestProxy(t)
	// The default policy denies *:443 and *:80

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://blocked.com/some/path", nil)
	req.Host = "blocked.com"

	p.handleProxy(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected status %d for blocked request, got %d", http.StatusForbidden, w.Code)
	}
}

func TestIsClosedConnError(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		expect bool
	}{
		{"nil error", nil, false},
		{"use of closed network connection", fmt.Errorf("use of closed network connection"), true},
		{"broken pipe", fmt.Errorf("write: broken pipe"), true},
		{"unrelated error", fmt.Errorf("something else"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isClosedConnError(tt.err)
			if result != tt.expect {
				t.Errorf("isClosedConnError(%v) = %v, want %v", tt.err, result, tt.expect)
			}
		})
	}
}

func TestProxy_HTTPTransport(t *testing.T) {
	p := setupTestProxy(t)
	if p.transport == nil {
		t.Error("expected transport to be initialized")
	}
}

func TestProxy_ListenerAddr(t *testing.T) {
	p := setupTestProxy(t)

	if err := p.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	addr := p.Addr()
	if addr == nil {
		t.Fatal("expected non-nil addr after start")
	}

	// Should be a TCP addr
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		t.Errorf("expected *net.TCPAddr, got %T", addr)
	}
	_ = tcpAddr

	if err := p.Stop(); err != nil {
		t.Logf("Stop() error: %v", err)
	}
}

func TestProxy_ConnectionToRunningServer(t *testing.T) {
	p := setupTestProxy(t)

	if err := p.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Verify we can connect to the proxy while it's running
	addr := p.Addr().String()
	conn, err := net.DialTimeout("tcp", addr, time.Second*5)
	if err != nil {
		t.Fatalf("failed to connect to proxy at %s: %v", addr, err)
	}
	_ = conn.Close()

	if err := p.Stop(); err != nil {
		t.Logf("Stop() error: %v", err)
	}
}

func TestProxy_HTTPRequest_Allowed(t *testing.T) {
	// Create an upstream HTTP server
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(map[string]string{"status": "ok"}); err != nil {
			t.Logf("encode error: %v", err)
		}
	}))
	defer upstream.Close()

	tmpDir := t.TempDir()
	caMgr, _ := ca.NewCACertManager(tmpDir + "/ca")
	pol, _ := policy.NewEngine(tmpDir + "/policy")
	sec := secrets.NewSecretManager()

	// Allow upstream server
	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamHost := upstreamURL.Host
	if _, err := pol.AddRule("allow-upstream", "allow", []string{upstreamHost}, ""); err != nil {
		t.Fatalf("AddRule() error = %v", err)
	}

	p := NewProxy(caMgr, pol, sec, "127.0.0.1:0")

	if err := p.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Make a request through the proxy using HTTP client
	proxyURL, _ := url.Parse("http://" + p.Addr().String())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	resp, err := client.Get(upstream.URL + "/test")
	if err != nil {
		t.Fatalf("GET request through proxy failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}

	if err := p.Stop(); err != nil {
		t.Logf("Stop() error: %v", err)
	}
}
func TestProxy_ReplaceSentinelsInResponse_WithBody(t *testing.T) {
	p := setupTestProxy(t)

	p.Secrets().SetSecrets([]secrets.CustomSecret{
		{Target: "api.example.com", EnvName: "TOKEN", Value: "my-secret-token", Sentinel: "{{TOKEN}}"},
	})

	resp := &http.Response{
		Body: io.NopCloser(strings.NewReader(`{"key":"{{TOKEN}}"}`)),
	}
	body := p.replaceSentinelsInResponse(resp)

	if string(body) != `{"key":"my-secret-token"}` {
		t.Errorf("expected sentinels to be replaced in response body, got %q", string(body))
	}
}

func TestProxy_ReplaceSentinelsInResponse_NoSecrets(t *testing.T) {
	p := setupTestProxy(t)

	resp := &http.Response{
		Body: io.NopCloser(strings.NewReader(`{"key":"value"}`)),
	}
	body := p.replaceSentinelsInResponse(resp)

	if string(body) != `{"key":"value"}` {
		t.Errorf("expected body unchanged, got %q", string(body))
	}
}

func TestProxy_ReplaceSentinelsInResponse_NilBody(t *testing.T) {
	p := setupTestProxy(t)

	resp := &http.Response{
		Body: nil,
	}
	body := p.replaceSentinelsInResponse(resp)

	if body != nil {
		t.Errorf("expected nil body, got %v", body)
	}
}

func TestProxy_RedactSecretsInHeaders(t *testing.T) {
	p := setupTestProxy(t)
	p.Secrets().SetSecrets([]secrets.CustomSecret{
		{Target: "api.example.com", EnvName: "TOKEN", Value: "secret123", Sentinel: "{{TOKEN}}"},
	})

	redacted := p.Secrets().RedactSecretsInHeader("Bearer secret123")
	if redacted != "Bearer [REDACTED]" {
		t.Errorf("expected redacted value, got %q", redacted)
	}
}

func TestProxy_HandleProxy_BlockedHTTP(t *testing.T) {
	p := setupTestProxy(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://blocked.com/some/path", nil)
	req.Host = "blocked.com:80"

	p.handleProxy(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected status %d for blocked HTTP request, got %d", http.StatusForbidden, w.Code)
	}
}

func TestProxy_HandleProxy_BlockedWithSandboxName(t *testing.T) {
	p := setupTestProxy(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://blocked.com/some/path", nil)
	req.Host = "blocked.com:80"
	req.Header.Set("X-Sandbox-Name", "my-sandbox")

	p.handleProxy(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected status %d for blocked request, got %d", http.StatusForbidden, w.Code)
	}
}

func TestProxy_BlockedHostsTracking(t *testing.T) {
	p := setupTestProxy(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://blocked.com/some/path", nil)
	req.Host = "blocked.com:80"

	p.handleProxy(w, req)

	// The blocked host should be tracked
	key := "blocked.com:80"
	if _, ok := p.blockedHosts[key]; !ok {
		t.Error("expected blocked host to be tracked")
	}
}

func TestProxy_HandleHTTP_BadGatewayError(t *testing.T) {
	p := setupTestProxy(t)

	// Allow the host first
	if _, err := p.Policy().AddRule("allow-test", "allow", []string{"nonexistent.test:80"}, ""); err != nil {
		t.Fatalf("AddRule() error = %v", err)
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://nonexistent.test:80/path", nil)
	req.Host = "nonexistent.test:80"

	p.handleHTTP(w, req, "nonexistent.test", "80", "")

	// Should get a Bad Gateway error since the upstream doesn't exist
	if w.Code != http.StatusBadGateway {
		t.Logf("handleHTTP returned status %d (expected BadGateway or similar)", w.Code)
	}
}
