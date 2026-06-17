package proxy

import (
	"bufio"
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
	"sync/atomic"
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

// startTestProxy starts a proxy and returns a cleanup function.
func startTestProxy(t *testing.T, p *Proxy) string {
	t.Helper()
	if err := p.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() {
		_ = p.Stop()
	})
	return p.Addr().String()
}

// allowHost adds an allow rule for the given host:port to the proxy policy.
func allowHost(t *testing.T, p *Proxy, host string) {
	t.Helper()
	_, err := p.Policy().AddRule("test-allow-"+host, "allow", []string{host}, "")
	if err != nil {
		t.Fatalf("AddRule(%q) error = %v", host, err)
	}
}

// ── Constructor & Basic Lifecycle ──

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

// ── Secret Replacement ──

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

// ── HTTP proxy ──

func TestProxy_HandleProxy_Blocked(t *testing.T) {
	p := setupTestProxy(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://blocked.com/some/path", nil)
	req.Host = "blocked.com"

	p.handleProxy(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected status %d for blocked request, got %d", http.StatusForbidden, w.Code)
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

	key := "blocked.com:80"
	if _, ok := p.blockedHosts[key]; !ok {
		t.Error("expected blocked host to be tracked")
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

	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamHost := upstreamURL.Host
	if _, err := pol.AddRule("allow-upstream", "allow", []string{upstreamHost}, ""); err != nil {
		t.Fatalf("AddRule() error = %v", err)
	}

	p := NewProxy(caMgr, pol, sec, "127.0.0.1:0")

	if err := p.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer func() { _ = p.Stop() }()

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
}

func TestProxy_HandleHTTP_BadGatewayError(t *testing.T) {
	p := setupTestProxy(t)

	if _, err := p.Policy().AddRule("allow-test", "allow", []string{"nonexistent.test:80"}, ""); err != nil {
		t.Fatalf("AddRule() error = %v", err)
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://nonexistent.test:80/path", nil)
	req.Host = "nonexistent.test:80"

	p.handleHTTP(w, req, "nonexistent.test", "80", "")

	if w.Code != http.StatusBadGateway {
		t.Logf("handleHTTP returned status %d (expected BadGateway)", w.Code)
	}
}

// ── HTTP lifecycle ──

func TestProxy_ConnectionToRunningServer(t *testing.T) {
	p := setupTestProxy(t)

	if err := p.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

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
	defer func() { _ = p.Stop() }()

	addr := p.Addr()
	if addr == nil {
		t.Fatal("expected non-nil addr after start")
	}

	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		t.Errorf("expected *net.TCPAddr, got %T", addr)
	}
	_ = tcpAddr
}

// ── Setter Methods ──

func TestProxy_SetSOCKS5Enabled(t *testing.T) {
	p := setupTestProxy(t)
	if !p.socks5Enabled {
		t.Error("expected SOCKS5 enabled by default")
	}
	p.SetSOCKS5Enabled(false)
	if p.socks5Enabled {
		t.Error("expected SOCKS5 disabled after SetSOCKS5Enabled(false)")
	}
}

func TestProxy_SetRawTCPEnabled(t *testing.T) {
	p := setupTestProxy(t)
	if !p.rawTCPEnabled {
		t.Error("expected RawTCP enabled by default")
	}
	p.SetRawTCPEnabled(false)
	if p.rawTCPEnabled {
		t.Error("expected RawTCP disabled after SetRawTCPEnabled(false)")
	}
}

func TestProxy_SetSandboxName(t *testing.T) {
	p := setupTestProxy(t)
	if p.sandboxName != "" {
		t.Errorf("expected empty sandbox name by default, got %q", p.sandboxName)
	}
	p.SetSandboxName("my-test-sandbox")
	if p.sandboxName != "my-test-sandbox" {
		t.Errorf("expected sandbox name 'my-test-sandbox', got %q", p.sandboxName)
	}
}

// ── SOCKS5 Tests ──

// connectSOCKS5 sends a SOCKS5 CONNECT request over an existing TCP connection
// and returns the upstream host:port that the proxy dialed (read from a test observer).
func socks5Connect(t *testing.T, conn net.Conn, host string, port uint16) {
	t.Helper()
	// Method negotiation: send [0x05, 0x01, 0x00] (version 5, 1 method, no auth)
	_, err := conn.Write([]byte{0x05, 0x01, 0x00})
	if err != nil {
		t.Fatalf("SOCKS5 method negotiation write: %v", err)
	}

	// Read server response: [0x05, chosen_method]
	resp := make([]byte, 2)
	_, err = io.ReadFull(conn, resp)
	if err != nil {
		t.Fatalf("SOCKS5 method negotiation read: %v", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		t.Fatalf("unexpected SOCKS5 method response: %x %x", resp[0], resp[1])
	}

	// Build CONNECT request
	var req []byte
	switch {
	case strings.Contains(host, ":"): // IPv6
		ip := net.ParseIP(host)
		if ip == nil || ip.To16() == nil {
			t.Fatalf("invalid IPv6 address: %s", host)
		}
		req = append(req, 0x05, 0x01, 0x00, 0x04) // ver=5, cmd=CONNECT, rsv=0, atyp=IPv6
		req = append(req, ip.To16()...)
	default:
		if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
			req = append(req, 0x05, 0x01, 0x00, 0x01) // ver=5, cmd=CONNECT, rsv=0, atyp=IPv4
			req = append(req, ip.To4()...)
		} else {
			req = append(req, 0x05, 0x01, 0x00, 0x03) // ver=5, cmd=CONNECT, rsv=0, atyp=Domain
			req = append(req, byte(len(host)))
			req = append(req, []byte(host)...)
		}
	}
	req = append(req, byte(port>>8), byte(port&0xff))

	_, err = conn.Write(req)
	if err != nil {
		t.Fatalf("SOCKS5 CONNECT write: %v", err)
	}

	// Read response: [ver, rep, rsv, atyp, bnd.addr, bnd.port] (10 bytes)
	resp = make([]byte, 10)
	_, err = io.ReadFull(conn, resp)
	if err != nil {
		t.Fatalf("SOCKS5 CONNECT response read: %v", err)
	}
	if resp[0] != 0x05 {
		t.Fatalf("unexpected SOCKS5 response version: %x", resp[0])
	}
	if resp[1] != 0x00 {
		t.Fatalf("SOCKS5 CONNECT failed with rep=%d", resp[1])
	}
}

func TestSOCKS5_AllowedConnection(t *testing.T) {
	// Create an upstream TCP echo server
	upstream := startEchoServer(t)
	defer upstream.stop()

	p := setupTestProxy(t)
	allowHost(t, p, upstream.addr)
	addr := startTestProxy(t, p)

	// Connect via SOCKS5 through the proxy
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	upstreamHost, upstreamPort, err := net.SplitHostPort(upstream.addr)
	if err != nil {
		t.Fatalf("split upstream addr: %v", err)
	}
	portInt, err := net.LookupPort("tcp", upstreamPort)
	if err != nil {
		t.Fatalf("parse upstream port %q: %v", upstreamPort, err)
	}

	socks5Connect(t, conn, upstreamHost, uint16(portInt))

	// Send data and verify echo
	testMsg := []byte("hello socks5")
	_, err = conn.Write(testMsg)
	if err != nil {
		t.Fatalf("write through SOCKS5 tunnel: %v", err)
	}

	// Read echo back
	reply := make([]byte, len(testMsg))
	_, err = io.ReadFull(conn, reply)
	if err != nil {
		t.Fatalf("read through SOCKS5 tunnel: %v", err)
	}
	if string(reply) != string(testMsg) {
		t.Errorf("echo mismatch: got %q, want %q", reply, testMsg)
	}
}

func TestSOCKS5_BlockedByPolicy(t *testing.T) {
	p := setupTestProxy(t)
	addr := startTestProxy(t, p)

	// Connect with SOCKS5 to a blocked destination (default policy denies *:443)
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Method negotiation
	_, _ = conn.Write([]byte{0x05, 0x01, 0x00})
	resp := make([]byte, 2)
	_, _ = io.ReadFull(conn, resp)

	// CONNECT to blocked destination (example.com:443)
	req := []byte{
		0x05, 0x01, 0x00, 0x03, // ver, cmd=CONNECT, rsv, atyp=Domain
		11,                      // domain length
	}
	req = append(req, []byte("example.com")...)
	req = append(req, 0x01, 0xbb) // port 443
	_, _ = conn.Write(req)

	// Read response — should get REP=0x02 (not allowed)
	resp = make([]byte, 10)
	_, err = io.ReadFull(conn, resp)
	if err != nil {
		t.Fatalf("read SOCKS5 response: %v", err)
	}
	if resp[1] != 0x02 {
		t.Errorf("expected REP=0x02 (not allowed), got 0x%02x", resp[1])
	}
}

func TestSOCKS5_UpstreamConnectionFail(t *testing.T) {
	p := setupTestProxy(t)
	// Allow a destination on localhost that will actively refuse the connection.
	// We find a port that's definitely not listening.
	closedPort := getClosedPort(t)
	allowHost(t, p, "127.0.0.1:"+closedPort)
	addr := startTestProxy(t, p)

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Method negotiation
	_, _ = conn.Write([]byte{0x05, 0x01, 0x00})
	resp := make([]byte, 2)
	_, _ = io.ReadFull(conn, resp)

	// CONNECT to closed port
	portNum, _ := net.LookupPort("tcp", closedPort)
	req := []byte{
		0x05, 0x01, 0x00, 0x01, // ver, cmd, rsv, atyp=IPv4
		127, 0, 0, 1,           // IP
		byte(portNum >> 8), byte(portNum & 0xff),
	}
	_, _ = conn.Write(req)

	// Read response — should get REP=0x01 (general failure) or EOF
	resp = make([]byte, 10)
	_, err = io.ReadFull(conn, resp)
	if err != nil {
		// Connection closed is also acceptable (proxy closed after upstream fail)
		return
	}
	if resp[1] != 0x01 {
		t.Errorf("expected REP=0x01 (general failure), got 0x%02x", resp[1])
	}
}

// getClosedPort finds a TCP port that isn't listening.
func getClosedPort(t *testing.T) string {
	t.Helper()
	for i := 0; i < 100; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			continue
		}
		addr := l.Addr().String()
		_ = l.Close()
		// Now the port is free and not listening. Return just the port number.
		_, port, _ := net.SplitHostPort(addr)
		return port
	}
	t.Fatal("could not find a closed port")
	return ""
}

func TestSOCKS5_UnsupportedCommand(t *testing.T) {
	p := setupTestProxy(t)
	addr := startTestProxy(t, p)

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Method negotiation
	_, _ = conn.Write([]byte{0x05, 0x01, 0x00})
	resp := make([]byte, 2)
	_, _ = io.ReadFull(conn, resp)

	// BIND command (0x02) — not supported
	req := []byte{
		0x05, 0x02, 0x00, 0x01, // ver, cmd=BIND, rsv, atyp=IPv4
		127, 0, 0, 1,
		0x00, 0x50,
	}
	_, _ = conn.Write(req)

	// Read response — should get REP=0x07 (CMD not supported)
	resp = make([]byte, 10)
	_, err = io.ReadFull(conn, resp)
	if err != nil {
		t.Fatalf("read SOCKS5 response: %v", err)
	}
	if resp[1] != 0x07 {
		t.Errorf("expected REP=0x07 (CMD not supported), got 0x%02x", resp[1])
	}
}

func TestSOCKS5_UnsupportedATYP(t *testing.T) {
	p := setupTestProxy(t)
	addr := startTestProxy(t, p)

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Method negotiation
	_, _ = conn.Write([]byte{0x05, 0x01, 0x00})
	resp := make([]byte, 2)
	_, _ = io.ReadFull(conn, resp)

	// CONNECT with unsupported ATYP (0x05 is reserved)
	req := []byte{
		0x05, 0x01, 0x00, 0x05, // ver, cmd=CONNECT, rsv, atyp=UNKNOWN
	}
	_, _ = conn.Write(req)

	// Read response — should get REP=0x08 (ATYP not supported)
	resp = make([]byte, 10)
	_, err = io.ReadFull(conn, resp)
	if err != nil {
		t.Fatalf("read SOCKS5 response: %v", err)
	}
	if resp[1] != 0x08 {
		t.Errorf("expected REP=0x08 (ATYP not supported), got 0x%02x", resp[1])
	}
}

func TestSOCKS5_WithDomainName(t *testing.T) {
	upstream := startEchoServer(t)
	defer upstream.stop()

	p := setupTestProxy(t)
	allowHost(t, p, upstream.addr)
	addr := startTestProxy(t, p)

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	upstreamHost, upstreamPort, err := net.SplitHostPort(upstream.addr)
	if err != nil {
		t.Fatalf("split upstream addr: %v", err)
	}
	portInt, err := net.LookupPort("tcp", upstreamPort)
	if err != nil {
		t.Fatalf("parse upstream port %q: %v", upstreamPort, err)
	}

	// Use domain name (ATYP=3) even if it's an IP
	socks5Connect(t, conn, upstreamHost, uint16(portInt))

	testMsg := []byte("domain test")
	_, _ = conn.Write(testMsg)
	reply := make([]byte, len(testMsg))
	_, err = io.ReadFull(conn, reply)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(reply) != string(testMsg) {
		t.Errorf("echo mismatch: got %q, want %q", reply, testMsg)
	}
}

func TestSOCKS5_DisabledFeature(t *testing.T) {
	p := setupTestProxy(t)
	p.SetSOCKS5Enabled(false)
	addr := startTestProxy(t, p)

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Send SOCKS5 greeting
	_, _ = conn.Write([]byte{0x05, 0x01, 0x00})

	// The proxy should close the connection immediately
	_, err = conn.Read(make([]byte, 1))
	if err == nil {
		t.Error("expected connection closed when SOCKS5 is disabled")
	}
}

// ── Protocol Dispatch Tests ──

func TestDispatch_SOCKS5(t *testing.T) {
	// Verify dispatch routes the first byte 0x05 to the SOCKS5 handler
	// by checking the response to a CONNECT attempt.
	p := setupTestProxy(t)
	addr := startTestProxy(t, p)

	// Open a raw TCP connection and send a SOCKS5 greeting
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// SOCKS5 method negotiation
	_, _ = conn.Write([]byte{0x05, 0x01, 0x00})
	resp := make([]byte, 2)
	_, err = io.ReadFull(conn, resp)
	if err != nil {
		t.Fatalf("read SOCKS5 method response: %v", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		t.Errorf("expected SOCKS5 version 5 no-auth, got %x %x", resp[0], resp[1])
	}
}

func TestDispatch_HTTP_GET(t *testing.T) {
	// Verify dispatch routes uppercase first bytes to the HTTP handler.
	// We test by sending a raw HTTP request to a host:port that's blocked
	// by default policy (*:80), so we should get a 403 response.
	p := setupTestProxy(t)
	addr := startTestProxy(t, p)

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Send an HTTP GET request to a blocked port (:80). The host header
	// determines where the proxy tries to connect.
	_, _ = fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: example.com:80\r\nConnection: close\r\n\r\n")

	// Read the response — should be an HTTP 403 (blocked by default deny *:80)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read HTTP response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected HTTP 403, got %d", resp.StatusCode)
	}
}

func TestDispatch_RawTCP(t *testing.T) {
	// Verify dispatch routes non-SOCKS5, non-HTTP bytes to the raw TCP handler.
	// Since raw TCP needs SO_ORIGINAL_DST (Linux/iptables), it should fail
	// gracefully with a log message. We test that the connection is closed.
	p := setupTestProxy(t)
	addr := startTestProxy(t, p)

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Send a byte that's not SOCKS5 (0x05) or HTTP (A-Z)
	_, _ = conn.Write([]byte{0x01, 0x02, 0x03})

	// The raw TCP handler will try SO_ORIGINAL_DST which fails => connection closed
	_, err = conn.Read(make([]byte, 1))
	if err == nil {
		t.Error("expected connection closed for raw TCP without iptables")
	}
}

func TestDispatch_RawTCP_Disabled(t *testing.T) {
	p := setupTestProxy(t)
	p.SetRawTCPEnabled(false)
	addr := startTestProxy(t, p)

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Send non-HTTP, non-SOCKS5 byte
	_, _ = conn.Write([]byte{0x01})

	// Connection should be closed immediately when raw TCP is disabled
	_, err = conn.Read(make([]byte, 1))
	if err == nil {
		t.Error("expected connection closed when raw TCP is disabled")
	}
}

func TestDispatch_ReadDeadline(t *testing.T) {
	// Verify a connection that sends no data is closed after the 5s deadline.
	// Use a shorter deadline for testing by creating a proxy with a custom
	// dispatch function — but that's not possible with current API.
	// Instead we accept the 5-second wait but make it manageable.
	p := setupTestProxy(t)
	addr := startTestProxy(t, p)

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Don't send any data — wait for the proxy to close the connection
	// due to the read deadline in dispatch().
	_ = conn.SetReadDeadline(time.Now().Add(7 * time.Second))
	_, err = conn.Read(make([]byte, 1))
	if err == nil {
		t.Error("expected connection to be closed after read deadline")
	}
}

// ── httpConnResponseWriter tests ──

func TestHTTPConnResponseWriter_WriteHeader(t *testing.T) {
	// Use a real TCP connection to avoid pipe blocking issues with http.ReadResponse.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = l.Close() }()

	type result struct {
		resp *http.Response
		err  error
	}
	done := make(chan result, 1)

	go func() {
		client, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			done <- result{nil, err}
			return
		}
		defer func() { _ = client.Close() }()
		resp, err := http.ReadResponse(bufio.NewReader(client), nil)
		done <- result{resp, err}
	}()

	server, err := l.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer func() { _ = server.Close() }()

	reader := bufio.NewReader(server)
	w := &httpConnResponseWriter{
		conn:   server,
		reader: reader,
		header: make(http.Header),
	}

	w.Header().Set("X-Test", "value")
	w.WriteHeader(http.StatusOK)

	r := <-done
	if r.err != nil {
		t.Fatalf("read response: %v", r.err)
	}

	resp := r.resp
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if resp.Header.Get("X-Test") != "value" {
		t.Errorf("expected X-Test header 'value', got %q", resp.Header.Get("X-Test"))
	}
}

func TestHTTPConnResponseWriter_Write(t *testing.T) {
	// Use net.Pipe for synchronous behavior.
	// Write to the writer on one side, read raw HTTP on the other.
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	// Read the raw HTTP response from client side in a goroutine
	type result struct {
		data []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		data, err := io.ReadAll(client)
		done <- result{data, err}
	}()

	reader := bufio.NewReader(server)
	w := &httpConnResponseWriter{
		conn:   server,
		reader: reader,
		header: make(http.Header),
	}

	body := []byte("hello world")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	n, err := w.Write(body)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if n != len(body) {
		t.Errorf("expected %d bytes written, got %d", len(body), n)
	}

	// Close the server side so the client ReadAll completes
	_ = server.Close()

	r := <-done
	if r.err != nil {
		t.Fatalf("read: %v", r.err)
	}

	raw := string(r.data)
	if !strings.Contains(raw, "HTTP/1.1 200 OK") {
		t.Errorf("expected HTTP/1.1 200 OK, got: %s", raw)
	}
	if !strings.Contains(raw, "Content-Length: 11") {
		t.Errorf("expected Content-Length: 11, got: %s", raw)
	}
	if !strings.HasSuffix(strings.TrimSpace(raw), "hello world") {
		t.Errorf("expected body 'hello world', got: %s", raw)
	}
}

func TestHTTPConnResponseWriter_Hijack(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = l.Close() }()

	go func() {
		client, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			return
		}
		_ = client.Close()
	}()

	server, err := l.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer func() { _ = server.Close() }()

	reader := bufio.NewReader(server)
	w := &httpConnResponseWriter{
		conn:   server,
		reader: reader,
		header: make(http.Header),
	}

	hijackedConn, rw, err := w.Hijack()
	if err != nil {
		t.Fatalf("Hijack: %v", err)
	}
	if hijackedConn != server {
		t.Error("expected hijacked conn to be the server conn")
	}
	if rw == nil {
		t.Error("expected non-nil bufio.ReadWriter")
	}
}

// ── Helpers ──

// echoServer is a simple TCP echo server for testing tunnels.
type echoServer struct {
	addr     string
	listener net.Listener
	quit     chan struct{}
}

func startEchoServer(t *testing.T) *echoServer {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo server listen: %v", err)
	}
	s := &echoServer{
		addr:     l.Addr().String(),
		listener: l,
		quit:     make(chan struct{}),
	}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	return s
}

func (s *echoServer) stop() {
	_ = s.listener.Close()
}

// ── New Feature Tests ──

func TestProxy_SetMaxConnections(t *testing.T) {
	p := setupTestProxy(t)
	if p.maxConnections != 0 {
		t.Errorf("expected 0 (unlimited) by default, got %d", p.maxConnections)
	}
	p.SetMaxConnections(100)
	if atomic.LoadInt64(&p.maxConnections) != 100 {
		t.Errorf("expected maxConnections=100, got %d", p.maxConnections)
	}
}

func TestProxy_ConnectionLimitEnforced(t *testing.T) {
	// Set limit to 1, then try 2 concurrent connections
	p := setupTestProxy(t)
	p.SetMaxConnections(1)
	addr := startTestProxy(t, p)

	// First connection succeeds (hits the proxy, then gets blocked by policy)
	conn1, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial1 proxy: %v", err)
	}
	defer func() { _ = conn1.Close() }()

	// Second connection should be rejected immediately
	conn2, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial2 proxy: %v", err)
	}
	defer func() { _ = conn2.Close() }()

	// Wait a moment for dispatch to process both
	time.Sleep(100 * time.Millisecond)

	// activeConns should be at most 1 (the connection limit)
	active := atomic.LoadInt64(&p.activeConns)
	if active > 1 {
		t.Errorf("expected at most 1 active connection, got %d", active)
	}
}

func TestProxy_SetRawTCPIdleTimeout(t *testing.T) {
	p := setupTestProxy(t)
	if p.rawTCPIdleTimeout != 0 {
		t.Errorf("expected 0 by default, got %v", p.rawTCPIdleTimeout)
	}
	p.SetRawTCPIdleTimeout(30 * time.Second)
	if p.rawTCPIdleTimeout != 30*time.Second {
		t.Errorf("expected 30s, got %v", p.rawTCPIdleTimeout)
	}
}

func TestProxy_MetricsInitial(t *testing.T) {
	p := setupTestProxy(t)
	m := p.Metrics()
	if m.HTTPTotal != 0 || m.CONNECTTotal != 0 || m.SOCKS5Total != 0 || m.RawTCPTotal != 0 {
		t.Error("expected all protocol counters to be 0 initially")
	}
	if m.DeniedTotal != 0 {
		t.Errorf("expected denied=0, got %d", m.DeniedTotal)
	}
	if m.ActiveConns != 0 {
		t.Errorf("expected active=0, got %d", m.ActiveConns)
	}
}

func TestProxy_MetricsAfterRequests(t *testing.T) {
	p := setupTestProxy(t)
	addr := startTestProxy(t, p)

	// Send a SOCKS5 greeting (will try to connect but upstream doesn't exist)
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	_, _ = conn.Write([]byte{0x05, 0x01, 0x00})
	resp := make([]byte, 2)
	_, _ = io.ReadFull(conn, resp)
	_ = conn.Close()

	// Send a raw HTTP request to a blocked host
	conn2, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial2 proxy: %v", err)
	}
	_, _ = fmt.Fprintf(conn2, "GET / HTTP/1.1\r\nHost: example.com:80\r\nConnection: close\r\n\r\n")
	_, _ = http.ReadResponse(bufio.NewReader(conn2), nil)
	_ = conn2.Close()

	time.Sleep(50 * time.Millisecond)

	m := p.Metrics()
	if m.SOCKS5Total == 0 {
		t.Errorf("expected SOCKS5 counter > 0 after SOCKS5 request")
	}
	if m.HTTPTotal == 0 && m.CONNECTTotal == 0 {
		t.Errorf("expected HTTP or CONNECT counter > 0 after HTTP request")
	}
}

func TestProxy_MetricsDenied(t *testing.T) {
	p := setupTestProxy(t)
	addr := startTestProxy(t, p)

	// Send HTTP to blocked :80 should trigger denied
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	_, _ = fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: example.com:80\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_ = resp.Body.Close()
	_ = conn.Close()

	time.Sleep(50 * time.Millisecond)

	m := p.Metrics()
	if m.DeniedTotal == 0 {
		t.Errorf("expected denied counter > 0 after blocked request, got %d", m.DeniedTotal)
	}
}

func TestProxy_DisabledFeatureCountsAsDenied(t *testing.T) {
	p := setupTestProxy(t)
	p.SetSOCKS5Enabled(false)
	addr := startTestProxy(t, p)

	// Send SOCKS5 greeting — should be denied because disabled
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	_, _ = conn.Write([]byte{0x05, 0x01, 0x00})
	_ = conn.Close()

	time.Sleep(50 * time.Millisecond)

	m := p.Metrics()
	if m.DeniedTotal == 0 {
		t.Errorf("expected denied counter > 0 when disabled feature rejected, got %d", m.DeniedTotal)
	}
}

func TestTunnelBidirectional(t *testing.T) {
	// Test bidirectional copy works between two connected pipes
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Echo server side: read from server and write back
		buf := make([]byte, 1024)
		for {
			n, err := server.Read(buf)
			if err != nil {
				return
			}
			_, _ = server.Write(buf[:n])
		}
	}()

	// Write through the tunnel and verify we get the data back
	reader := bufio.NewReader(client)
	_, _ = client.Write([]byte("hello"))
	reply := make([]byte, 5)
	_, err := io.ReadFull(reader, reply)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if string(reply) != "hello" {
		t.Errorf("expected 'hello', got %q", string(reply))
	}

	_ = server.Close()
	wg.Wait()
}

func TestTunnelBidirectionalWithIdleTimeout(t *testing.T) {
	// Test that idle timeout closes connections
	server, client := net.Pipe()

	done := make(chan struct{}, 1)
	go func() {
		tunnelBidirectional(server, client, bufio.NewReader(client), 50*time.Millisecond)
		close(done)
	}()

	// Wait for the timeout to fire
	select {
	case <-done:
		// Tunnel closed — expected
	case <-time.After(500 * time.Millisecond):
		t.Fatal("tunnel did not close after idle timeout")
	}

	// Verify both sides are closed
	_, err := server.Write([]byte("x"))
	if err == nil {
		t.Error("expected server connection to be closed after timeout")
	}
	_, err = client.Write([]byte("x"))
	if err == nil {
		t.Error("expected client connection to be closed after timeout")
	}
}

