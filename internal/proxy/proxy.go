package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fr12k/dandbox/internal/ca"
	"github.com/fr12k/dandbox/internal/container"
	"github.com/fr12k/dandbox/internal/policy"
	"github.com/fr12k/dandbox/internal/secrets"
)

// Proxy implements a universal TCP proxy with MITM for policy enforcement and
// secret replacement. It handles HTTP, HTTPS CONNECT, SOCKS5, and raw TCP
// (via iptables REDIRECT) on a single listener.
type Proxy struct {
	ca       *ca.CACertManager
	policy   *policy.Engine
	secrets  *secrets.SecretManager
	httpAddr string
	listener net.Listener
	mu       sync.Mutex
	running  bool

	// Reusable HTTP transport with connection pooling
	transport *http.Transport

	// Track which host:port requests are blocked
	blockedHosts map[string]int64

	// Feature toggles
	socks5Enabled bool
	rawTCPEnabled bool

	// Sandbox name for scoped policy evaluation
	sandboxName string

	// Connection tracking (atomic for lock-free reads in hot path)
	activeConns    int64
	maxConnections int64 // 0 = unlimited

	// Idle timeout for raw TCP and SOCKS5 tunnels (0 = unlimited)
	rawTCPIdleTimeout time.Duration

	// Metrics counters (atomic for lock-free reads)
	connsTotalHTTP     int64
	connsTotalCONNECT  int64
	connsTotalSOCKS5   int64
	connsTotalRawTCP   int64
	deniedTotal        int64
}

// NewProxy creates a new proxy server.
func NewProxy(ca *ca.CACertManager, pol *policy.Engine, sec *secrets.SecretManager, addr string) *Proxy {
	if addr == "" {
		addr = ":3128"
	}
	return &Proxy{
		ca:            ca,
		policy:        pol,
		secrets:       sec,
		httpAddr:      addr,
		blockedHosts:  make(map[string]int64),
		socks5Enabled: true,
		rawTCPEnabled: true,
		transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:        100,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}
}

// Start binds the proxy listener and starts the accept loop.
func (p *Proxy) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.running {
		return fmt.Errorf("proxy already running")
	}

	listener, err := net.Listen("tcp", p.httpAddr)
	if err != nil {
		return fmt.Errorf("proxy listen on %s: %w", p.httpAddr, err)
	}
	p.listener = listener
	p.running = true

	go func() {
		log.Printf("[proxy] Listening on %s (HTTP/SOCKS5/RawTCP)", p.httpAddr)
		for {
			conn, err := p.listener.Accept()
			if err != nil {
				p.mu.Lock()
				running := p.running
				p.mu.Unlock()
				if !running {
					return
				}
				log.Printf("[proxy] Accept error: %v", err)
				continue
			}
			go p.dispatch(conn)
		}
	}()

	return nil
}

// Stop gracefully shuts down the proxy.
func (p *Proxy) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.running {
		return nil
	}
	p.running = false
	if p.listener != nil {
		return p.listener.Close()
	}
	return nil
}

// Policy returns the policy engine used by this proxy.
func (p *Proxy) Policy() *policy.Engine {
	return p.policy
}

// Secrets returns the secret manager used by this proxy.
func (p *Proxy) Secrets() *secrets.SecretManager {
	return p.secrets
}

// Addr returns the listening address.
func (p *Proxy) Addr() net.Addr {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.listener != nil {
		return p.listener.Addr()
	}
	return nil
}

// SetSOCKS5Enabled enables or disables SOCKS5 handling.
func (p *Proxy) SetSOCKS5Enabled(enabled bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.socks5Enabled = enabled
}

// SetRawTCPEnabled enables or disables raw TCP tunnel handling.
func (p *Proxy) SetRawTCPEnabled(enabled bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rawTCPEnabled = enabled
}

// SetSandboxName sets the sandbox name for scoped policy evaluation.
func (p *Proxy) SetSandboxName(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sandboxName = name
}

// SetMaxConnections sets the maximum number of concurrent connections.
// 0 means unlimited.
func (p *Proxy) SetMaxConnections(max int64) {
	atomic.StoreInt64(&p.maxConnections, max)
}

// SetRawTCPIdleTimeout sets the idle timeout for raw TCP and SOCKS5 tunnels.
// 0 means unlimited.
func (p *Proxy) SetRawTCPIdleTimeout(d time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rawTCPIdleTimeout = d
}

// ── Metrics ──

// MetricsSnapshot holds a point-in-time snapshot of proxy metrics.
type MetricsSnapshot struct {
	ActiveConns   int64
	CONNECTTotal  int64
	HTTPTotal     int64
	SOCKS5Total   int64
	RawTCPTotal   int64
	DeniedTotal   int64
}

// Metrics returns a point-in-time snapshot of all proxy counters.
func (p *Proxy) Metrics() MetricsSnapshot {
	return MetricsSnapshot{
		ActiveConns:  atomic.LoadInt64(&p.activeConns),
		CONNECTTotal: atomic.LoadInt64(&p.connsTotalCONNECT),
		HTTPTotal:    atomic.LoadInt64(&p.connsTotalHTTP),
		SOCKS5Total:  atomic.LoadInt64(&p.connsTotalSOCKS5),
		RawTCPTotal:  atomic.LoadInt64(&p.connsTotalRawTCP),
		DeniedTotal:  atomic.LoadInt64(&p.deniedTotal),
	}
}

// incConn increments the per-protocol connection counter.
func (p *Proxy) incConn(protocol string) {
	switch protocol {
	case "http":
		atomic.AddInt64(&p.connsTotalHTTP, 1)
	case "connect":
		atomic.AddInt64(&p.connsTotalCONNECT, 1)
	case "socks5":
		atomic.AddInt64(&p.connsTotalSOCKS5, 1)
	case "rawtcp":
		atomic.AddInt64(&p.connsTotalRawTCP, 1)
	}
}

// incDenied increments the denied-connections counter.
func (p *Proxy) incDenied() {
	atomic.AddInt64(&p.deniedTotal, 1)
}

// dispatch reads the first byte of a connection to determine the protocol
// and routes it to the appropriate handler.
func (p *Proxy) dispatch(conn net.Conn) {
	// Check connection limit before doing any work
	maxConns := atomic.LoadInt64(&p.maxConnections)
	if maxConns > 0 {
		cur := atomic.AddInt64(&p.activeConns, 1)
		if cur > maxConns {
			atomic.AddInt64(&p.activeConns, -1)
			log.Printf("[proxy] connection limit reached (%d), closing %s", maxConns, conn.RemoteAddr())
			_ = conn.Close()
			return
		}
		defer atomic.AddInt64(&p.activeConns, -1)
	}

	reader := bufio.NewReaderSize(conn, 4096)

	// Set a short read deadline for protocol detection
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		log.Printf("[proxy] dispatch: set read deadline: %v", err)
	}

	b, err := reader.Peek(1)
	if err != nil {
		_ = conn.Close()
		return
	}

	// Disable the deadline now that we've read the first byte
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		log.Printf("[proxy] dispatch: clear read deadline: %v", err)
	}

	p.mu.Lock()
	sandboxName := p.sandboxName
	socks5Enabled := p.socks5Enabled
	rawTCPEnabled := p.rawTCPEnabled
	p.mu.Unlock()

	switch {
	case b[0] == 0x05: // SOCKS5 version byte
		if !socks5Enabled {
			log.Printf("[proxy] SOCKS5 disabled, closing connection from %s", conn.RemoteAddr())
			p.incDenied()
			_ = conn.Close()
			return
		}
		p.incConn("socks5")
		p.handleSOCKS5(reader, conn, sandboxName)

	case b[0] >= 'A' && b[0] <= 'Z': // HTTP method (GET, POST, CONNECT, etc.)
		p.handleHTTPFromReader(reader, conn, sandboxName)

	default:
		if !rawTCPEnabled {
			log.Printf("[proxy] Raw TCP disabled, closing connection from %s", conn.RemoteAddr())
			p.incDenied()
			_ = conn.Close()
			return
		}
		p.incConn("rawtcp")
		p.handleRawTCP(reader, conn, sandboxName)
	}
}

// handleHTTPFromReader reads an HTTP request from a buffered reader that has
// already consumed the first byte(s) during protocol detection, and dispatches
// it to the existing HTTP/HTTPS CONNECT handlers.
func (p *Proxy) handleHTTPFromReader(reader *bufio.Reader, conn net.Conn, sandboxName string) {
	// Read the full HTTP request from the buffered reader.
	// The reader already contains any bytes peeked during protocol detection.
	req, err := http.ReadRequest(reader)
	if err != nil {
		log.Printf("[proxy] HTTP parse error from %s: %v", conn.RemoteAddr(), err)
		_ = conn.Close()
		return
	}

	// Build a ResponseWriter that writes back to the connection.
	connWriter := &httpConnResponseWriter{
		conn:   conn,
		reader: reader,
		header: make(http.Header),
	}

	// Pass sandbox name to handleProxy via header (the existing handler
	// reads X-Sandbox-Name from the request for policy scoping).
	if sandboxName != "" {
		req.Header.Set("X-Sandbox-Name", sandboxName)
	}

	// Use the existing handleProxy logic
	p.handleProxy(connWriter, req)
}

// httpConnResponseWriter implements http.ResponseWriter and http.Hijacker
// over a raw net.Conn with a buffered reader.
type httpConnResponseWriter struct {
	conn       net.Conn
	reader     *bufio.Reader
	header     http.Header
	code       int
	wroteHeader bool
}

func (w *httpConnResponseWriter) Header() http.Header {
	return w.header
}

func (w *httpConnResponseWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.code = code

	statusText := http.StatusText(code)
	if statusText == "" {
		statusText = fmt.Sprintf("status code %d", code)
	}

	// Write HTTP/1.1 status line
	_, _ = fmt.Fprintf(w.conn, "HTTP/1.1 %d %s\r\n", code, statusText)

	// Write headers
	for k, vals := range w.header {
		for _, v := range vals {
			_, _ = fmt.Fprintf(w.conn, "%s: %s\r\n", k, v)
		}
	}
	_, _ = fmt.Fprintf(w.conn, "\r\n")
}

func (w *httpConnResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.conn.Write(b)
}

func (w *httpConnResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	rw := bufio.NewReadWriter(w.reader, bufio.NewWriter(w.conn))
	return w.conn, rw, nil
}

// replaceSentinelsInRequest extracts and replaces sentinel placeholders in
// request headers and body. Returns the modified headers and body bytes.
func (p *Proxy) replaceSentinelsInRequest(r *http.Request) (map[string][]string, []byte) {
	headers := p.secrets.ReplaceSentinelsInHeaders(r.Header)
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(r.Body)
		_ = r.Body.Close()
		body = p.secrets.ReplaceSentinelsInBody(body)
	}
	return headers, body
}

// replaceSentinelsInResponse replaces sentinel placeholders in the response body.
// Returns nil if the response has no body.
func (p *Proxy) replaceSentinelsInResponse(resp *http.Response) []byte {
	if resp.Body == nil {
		return nil
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return p.secrets.ReplaceSentinelsInBody(body)
}

// handleProxy is the main HTTP handler for all proxy requests.
func (p *Proxy) handleProxy(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	port := "80"
	if h, p, err := net.SplitHostPort(host); err == nil {
		host = h
		port = p
	}

	sandboxName := r.Header.Get("X-Sandbox-Name")
	if sandboxName != "" {
		r.Header.Del("X-Sandbox-Name")
	}

	if r.Method == http.MethodConnect {
		p.incConn("connect")
		p.handleCONNECT(w, r, host, port, sandboxName)
	} else {
		p.incConn("http")
		p.handleHTTP(w, r, host, port, sandboxName)
	}
}

// handleCONNECT handles HTTPS CONNECT tunneling with MITM.
func (p *Proxy) handleCONNECT(w http.ResponseWriter, r *http.Request, host, port, sandboxName string) {
	decision, ruleID := p.policy.Evaluate(host, port, sandboxName)
	if decision == policy.DecisionDeny {
		p.blockedHosts[host+":"+port] = time.Now().Unix()
		p.incDenied()
		log.Printf("[proxy] BLOCKED CONNECT %s:%s (rule: %s, sandbox: %s)", host, port, ruleID, sandboxName)
		http.Error(w, fmt.Sprintf("Blocked by policy (rule: %s)", ruleID), http.StatusForbidden)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		log.Printf("[proxy] Hijack failed for CONNECT %s:%s: %v", host, port, err)
		return
	}

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		_ = clientConn.Close()
		return
	}

	tlsConfig := p.ca.TLSConfig()
	tlsConn := tls.Server(clientConn, tlsConfig)
	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		log.Printf("[proxy] Failed to set deadline on TLS conn: %v", err)
	}
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("[proxy] TLS handshake with %s failed for %s:%s: %v", r.RemoteAddr, host, port, err)
		_ = clientConn.Close()
		return
	}

	reader := bufio.NewReader(tlsConn)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			if err != io.EOF && !isClosedConnError(err) {
				log.Printf("[proxy] Error reading request from MITM conn %s:%s: %v", host, port, err)
			}
			break
		}

		// Replace sentinels in headers and body
		headers, bodyBytes := p.replaceSentinelsInRequest(req)
		req.Header = headers
		container.SetRequestBody(req, bodyBytes)

		req.URL = &url.URL{
			Scheme:   "https",
			Host:     host + ":" + port,
			Path:     req.URL.Path,
			RawQuery: req.URL.RawQuery,
		}
		req.RequestURI = ""
		req.RemoteAddr = r.RemoteAddr

		log.Printf("[proxy] MITM %s https://%s%s", req.Method, host, req.URL.RequestURI())

		upstreamResp, err := p.upstreamRoundTrip(req)
		if err != nil {
			log.Printf("[proxy] Upstream request failed for %s:%s: %v", host, port, err)
			resp := &http.Response{
				StatusCode: http.StatusBadGateway,
				ProtoMajor: 1,
				ProtoMinor: 1,
				Body:       io.NopCloser(strings.NewReader("Bad Gateway\n")),
			}
			_ = resp.Write(tlsConn)
			continue
		}

		// Replace sentinels in response body
		respBody := p.replaceSentinelsInResponse(upstreamResp)
		if respBody != nil {
			upstreamResp.Body = io.NopCloser(strings.NewReader(string(respBody)))
			upstreamResp.ContentLength = int64(len(respBody))
		}

		_ = upstreamResp.Write(tlsConn)
	}

	_ = tlsConn.Close()
}

// handleHTTP handles plain HTTP proxy requests (non-CONNECT).
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request, host, port, sandboxName string) {
	decision, ruleID := p.policy.Evaluate(host, port, sandboxName)
	if decision == policy.DecisionDeny {
		p.blockedHosts[host+":"+port] = time.Now().Unix()
		p.incDenied()
		log.Printf("[proxy] BLOCKED HTTP %s %s:%s%s (rule: %s, sandbox: %s)", r.Method, host, port, r.URL.RequestURI(), ruleID, sandboxName)
		http.Error(w, fmt.Sprintf("Blocked by policy (rule: %s)", ruleID), http.StatusForbidden)
		return
	}

	// Replace sentinels in headers and body
	headers, bodyBytes := p.replaceSentinelsInRequest(r)
	r.Header = headers
	container.SetRequestBody(r, bodyBytes)

	upstreamURL := &url.URL{
		Scheme:   "http",
		Host:     host + ":" + port,
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}
	r.URL = upstreamURL
	r.RequestURI = ""

	log.Printf("[proxy] HTTP %s http://%s%s", r.Method, host+":"+port, r.URL.RequestURI())

	resp, err := p.upstreamRoundTrip(r)
	if err != nil {
		log.Printf("[proxy] HTTP upstream error %s:%s: %v", host, port, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	// Replace sentinels in response body
	respBody := p.replaceSentinelsInResponse(resp)

	// Copy headers with secret redaction
	for k, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(k, p.secrets.RedactSecretsInHeader(v))
		}
	}
	w.WriteHeader(resp.StatusCode)
	if respBody != nil {
		_, _ = w.Write(respBody)
	} else {
		_, _ = io.Copy(w, resp.Body)
	}
}

// upstreamRoundTrip sends a request to the actual upstream server.
func (p *Proxy) upstreamRoundTrip(req *http.Request) (*http.Response, error) {
	return p.transport.RoundTrip(req)
}

// isClosedConnError checks if an error is a closed connection error.
func isClosedConnError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "use of closed network connection") ||
		strings.Contains(s, "broken pipe") ||
		strings.Contains(s, "connection reset") ||
		strings.Contains(s, "http: Server closed") ||
		strings.Contains(s, "tls: ") && strings.Contains(s, "closed")
}
