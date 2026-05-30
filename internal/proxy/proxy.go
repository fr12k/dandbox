package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/fr12k/dandbox/internal/ca"
	"github.com/fr12k/dandbox/internal/container"
	"github.com/fr12k/dandbox/internal/policy"
	"github.com/fr12k/dandbox/internal/secrets"
)

// Proxy implements an HTTP/S proxy with MITM for policy enforcement and
// secret replacement.
type Proxy struct {
	ca       *ca.CACertManager
	policy   *policy.Engine
	secrets  *secrets.SecretManager
	httpAddr string
	server   *http.Server
	listener net.Listener
	mu       sync.Mutex
	running  bool

	// Reusable HTTP transport with connection pooling
	transport *http.Transport

	// Track which host:port requests are blocked
	blockedHosts map[string]int64
}

// NewProxy creates a new proxy server.
func NewProxy(ca *ca.CACertManager, pol *policy.Engine, sec *secrets.SecretManager, addr string) *Proxy {
	if addr == "" {
		addr = ":3128"
	}
	return &Proxy{
		ca:           ca,
		policy:       pol,
		secrets:      sec,
		httpAddr:     addr,
		blockedHosts: make(map[string]int64),
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

// Start binds the proxy listener and starts serving.
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

	handler := http.HandlerFunc(p.handleProxy)
	p.server = &http.Server{
		Handler:      handler,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		log.Printf("[proxy] Listening on %s", p.httpAddr)
		if err := p.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("[proxy] Server error: %v", err)
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
	if p.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return p.server.Shutdown(ctx)
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
		p.handleCONNECT(w, r, host, port, sandboxName)
	} else {
		p.handleHTTP(w, r, host, port, sandboxName)
	}
}

// handleCONNECT handles HTTPS CONNECT tunneling with MITM.
func (p *Proxy) handleCONNECT(w http.ResponseWriter, r *http.Request, host, port, sandboxName string) {
	decision, ruleID := p.policy.Evaluate(host, port, sandboxName)
	if decision == policy.DecisionDeny {
		p.blockedHosts[host+":"+port] = time.Now().Unix()
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
