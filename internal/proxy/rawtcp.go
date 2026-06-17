package proxy

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/fr12k/dandbox/internal/policy"
)

// localIPs caches the container's own IP addresses so the proxy can detect
// when an upstream destination is local and redirect to 127.0.0.1.
var localIPs []net.IP

func init() {
	localIPs = getLocalIPs()
}

// getLocalIPs returns all non-loopback IPv4 addresses assigned to the host.
func getLocalIPs() []net.IP {
	var ips []net.IP
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ips
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			if ipnet.IP.To4() != nil && !ipnet.IP.IsLoopback() {
				ips = append(ips, ipnet.IP)
			}
		}
	}
	return ips
}

// isLocalIP checks if an IP belongs to any of the host's network interfaces.
func isLocalIP(ip net.IP) bool {
	for _, local := range localIPs {
		if local.Equal(ip) {
			return true
		}
	}
	return false
}

// SOL_IP is the IP protocol level for getsockopt.
// It's defined as 0 in the Linux kernel.
const solIP = 0

// getOriginalDst retrieves the original destination IP and port from a
// connection that arrived via iptables REDIRECT.
//
// Uses getsockopt with SO_ORIGINAL_DST (Linux-specific, IPv4 only).
// For IPv6, IP6T_SO_ORIGINAL_DST would be used (value 80 on SOL_IPV6).
func getOriginalDst(conn net.Conn) (net.IP, int, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, 0, fmt.Errorf("not a TCP connection")
	}

	f, err := tcpConn.File()
	if err != nil {
		return nil, 0, err
	}
	defer f.Close() //nolint:errcheck

	fd := int(f.Fd())

	// SO_ORIGINAL_DST is defined as 80 on Linux for SOL_IP
	const SO_ORIGINAL_DST = 80

	// Retrieve the socket option using raw syscall.
	// sockaddr_in: 2 bytes family, 2 bytes port (network byte order),
	//              4 bytes IP, 8 bytes padding = 16 bytes total.
	raw := make([]byte, 16)
	optlen := uint32(len(raw))

	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(solIP),
		uintptr(SO_ORIGINAL_DST),
		uintptr(unsafe.Pointer(&raw[0])),
		uintptr(unsafe.Pointer(&optlen)),
		0,
	)
	if errno != 0 {
		return nil, 0, fmt.Errorf("getsockopt SO_ORIGINAL_DST: %w", errno)
	}

	if len(raw) < 8 {
		return nil, 0, fmt.Errorf("short getsockopt result: %d bytes", len(raw))
	}

	port := int(raw[2])<<8 | int(raw[3])
	ip := net.IP(raw[4:8])
	return ip, port, nil
}

// handleRawTCP handles a TCP connection that arrived without an HTTP or SOCKS
// protocol header (i.e., it was redirected by iptables REDIRECT).
//
// It uses SO_ORIGINAL_DST to retrieve the original destination, checks policy,
// and either opens a tunnel or rejects the connection.
//
// The reader may contain bytes already read during protocol detection.
func (p *Proxy) handleRawTCP(reader *bufio.Reader, conn net.Conn, sandboxName string) {
	origIP, origPort, err := getOriginalDst(conn)
	if err != nil {
		log.Printf("[proxy] RAW TCP: cannot determine original dst: %v", err)
		_ = conn.Close()
		return
	}

	host := origIP.String()
	portStr := fmt.Sprintf("%d", origPort)

	// Policy check
	decision, ruleID := p.policy.Evaluate(host, portStr, sandboxName)
	if decision == policy.DecisionDeny {
		log.Printf("[proxy] BLOCKED RAW TCP %s:%s (rule: %s, sandbox: %s)",
			host, portStr, ruleID, sandboxName)
		_ = conn.Close()
		return
	}

	// Connect upstream — rewrite local IP destinations to 127.0.0.1
	// to prevent the proxy's own upstream connections from looping back
	// through iptables REDIRECT (which catches non-loopback TCP).
	if isLocalIP(origIP) {
		host = "127.0.0.1"
		log.Printf("[proxy] RAW TCP rewriting local IP %s -> 127.0.0.1 for upstream dial", origIP)
	}
	upstream, err := net.DialTimeout("tcp", net.JoinHostPort(host, portStr), 10*time.Second)
	if err != nil {
		log.Printf("[proxy] RAW TCP upstream dial failed %s:%s: %v", host, portStr, err)
		_ = conn.Close()
		return
	}

	log.Printf("[proxy] RAW TCP tunnel %s -> %s:%s (sandbox: %s)",
		conn.RemoteAddr(), host, portStr, sandboxName)

	// Fetch idle timeout (read under lock for safety)
	p.mu.Lock()
	timeout := p.rawTCPIdleTimeout
	p.mu.Unlock()

	tunnelBidirectional(upstream, conn, reader, timeout)

	log.Printf("[proxy] RAW TCP tunnel closed %s -> %s:%s", conn.RemoteAddr(), host, portStr)
}

// tunnelBidirectional copies data bidirectionally between two connections
// with an optional idle timeout. If timeout is 0, no timeout is enforced.
func tunnelBidirectional(upstream, downstream net.Conn, reader *bufio.Reader, timeout time.Duration) {
	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Upstream
	go func() {
		defer wg.Done()
		if timeout > 0 {
			_, _ = io.Copy(upstream, &deadlineReader{conn: downstream, inner: reader, timeout: timeout})
		} else {
			_, _ = io.Copy(upstream, reader)
		}
		// Shutdown write side — client is done sending, but upstream may still
		// need to send response data back before we fully close.
		if tc, ok := upstream.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		} else {
			_ = upstream.Close()
		}
	}()

	// Upstream -> Client
	go func() {
		defer wg.Done()
		if timeout > 0 {
			_, _ = io.Copy(downstream, &deadlineReader{conn: upstream, inner: upstream, timeout: timeout})
		} else {
			_, _ = io.Copy(downstream, upstream)
		}
		_ = downstream.Close()
	}()

	wg.Wait()
}

// deadlineReader wraps an io.Reader and sets a read deadline on a net.Conn
// before each Read call, enforcing an idle timeout.
type deadlineReader struct {
	conn    net.Conn
	inner   io.Reader
	timeout time.Duration
}

func (r *deadlineReader) Read(p []byte) (int, error) {
	if err := r.conn.SetReadDeadline(time.Now().Add(r.timeout)); err != nil {
		return 0, err
	}
	return r.inner.Read(p)
}
