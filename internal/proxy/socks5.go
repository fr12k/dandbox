package proxy

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/fr12k/dandbox/internal/policy"
)

// handleSOCKS5 handles a SOCKS5 connection.
// The reader still contains the initial 0x05 byte (dispatch peeks but does
// not consume). The handler reads everything from the buffered reader.
func (p *Proxy) handleSOCKS5(reader *bufio.Reader, conn net.Conn, sandboxName string) {
	defer func() { _ = conn.Close() }()

	// ── Method negotiation (RFC 1928 §3) ──
	// Read: [ver, n_methods, methods...]
	buf := make([]byte, 256)
	_, err := io.ReadFull(reader, buf[:2])
	if err != nil || buf[0] != 0x05 {
		return
	}
	nMethods := int(buf[1])
	if nMethods == 0 || nMethods > 255 {
		return
	}
	_, err = io.ReadFull(reader, buf[:nMethods])
	if err != nil {
		return
	}
	// Reply: SOCKS5, NO AUTHENTICATION REQUIRED (0x00)
	_, _ = conn.Write([]byte{0x05, 0x00})

	// ── Request (RFC 1928 §4) ──
	// Read: [ver, cmd, rsv, atyp]
	_, err = io.ReadFull(reader, buf[:4])
	if err != nil || buf[0] != 0x05 {
		return
	}

	// Only CONNECT (0x01) is supported
	if buf[1] != 0x01 {
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // CMD not supported
		return
	}

	atyp := buf[3]
	var host string
	switch atyp {
	case 0x01: // IPv4
		_, err = io.ReadFull(reader, buf[:4])
		if err != nil {
			return
		}
		host = net.IP(buf[:4]).String()
	case 0x03: // Domain name
		_, err = io.ReadFull(reader, buf[:1])
		if err != nil {
			return
		}
		domainLen := int(buf[0])
		if domainLen == 0 || domainLen > 255 {
			_, _ = conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // ATYP not supported
			return
		}
		_, err = io.ReadFull(reader, buf[:domainLen])
		if err != nil {
			return
		}
		host = string(buf[:domainLen])
	case 0x04: // IPv6
		_, err = io.ReadFull(reader, buf[:16])
		if err != nil {
			return
		}
		host = net.IP(buf[:16]).String()
	default:
		_, _ = conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // ATYP not supported
		return
	}

	// Read port (2 bytes, network byte order)
	_, err = io.ReadFull(reader, buf[:2])
	if err != nil {
		return
	}
	port := int(buf[0])<<8 | int(buf[1])
	portStr := fmt.Sprintf("%d", port)

	// ── Policy check ──
	decision, ruleID := p.policy.Evaluate(host, portStr, sandboxName)
	if decision == policy.DecisionDeny {
		log.Printf("[proxy] BLOCKED SOCKS5 %s:%s (rule: %s, sandbox: %s)",
			host, portStr, ruleID, sandboxName)
		_, _ = conn.Write([]byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // not allowed
		return
	}

	// ── Connect upstream ──
	upstream, err := net.DialTimeout("tcp",
		net.JoinHostPort(host, portStr), 10*time.Second)
	if err != nil {
		log.Printf("[proxy] SOCKS5 upstream dial failed %s:%s: %v", host, portStr, err)
		_, _ = conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // general failure
		return
	}
	defer func() { _ = upstream.Close() }()

	// Success response (BND.ADDR = 0.0.0.0:0, we don't care)
	_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	log.Printf("[proxy] SOCKS5 tunnel %s -> %s:%s (sandbox: %s)",
		conn.RemoteAddr(), host, portStr, sandboxName)

	// ── Bidirectional tunnel with optional idle timeout ──
	p.mu.Lock()
	timeout := p.rawTCPIdleTimeout
	p.mu.Unlock()

	tunnelBidirectional(upstream, conn, reader, timeout)

	log.Printf("[proxy] SOCKS5 tunnel closed %s -> %s:%s",
		conn.RemoteAddr(), host, portStr)
}
