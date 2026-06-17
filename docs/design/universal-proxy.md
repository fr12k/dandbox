# Universal TCP/Protocol-Agnostic Proxy

**Status:** Fully implemented (Phases 1–5 complete), decisions resolved (see §11 and §13)  
**Date:** 2025-07-16 (Phase 4-5 completed 2025-07-16)  
**Authors:** dandbox team  

---

## 1. Motivation

The current proxy-sidecar is an **HTTP/HTTPS MITM proxy only**. It intercepts HTTP and TLS-wrapped HTTP (via CONNECT), but any non-HTTP protocol — SSH, SMTP, DNS-over-TCP, custom TCP protocols, UDP traffic — bypasses it entirely. Tools like `socat`, `nc`, raw TCP clients, and non-HTTP services cannot be inspected, blocked, or logged.

The goal is to make **every outbound connection attempt** from the sandbox container visible to, and subject to, the same policy engine — independent of protocol.

---

## 2. Architecture Overview

```
┌──────────────────────────────────────────────────┐
│                Sandbox Container                  │
│                                                   │
│  ┌──────────┐    ┌──────────────┐                │
│  │  socat   │    │  curl/wget   │   SSH / SMTP   │
│  │  raw TCP │    │  (HTTP/HTTPS)│   (TCP apps)   │
│  └────┬─────┘    └──────┬───────┘   ───┬───      │
│       │                 │              │         │
│       │    TCP :3128    │              │         │
│       ├─────────────────┼──────────────┤         │
│       │                 │              │         │
│       ▼                 ▼              ▼         │
│  ┌──────────────────────────────────────────┐   │
│  │      iptables REDIRECT (all TCP)         │   │
│  │  OUTPUT chain: !localhost → :3128        │   │
│  └──────────────────┬───────────────────────┘   │
│                     │                           │
│                     │ all TCP to :3128          │
│                     │ (SO_ORIGINAL_DST intact)  │
│                     ▼                           │
│  ┌──────────────────────────────────────────┐   │
│  │         Proxy Sidecar (extended)          │   │
│  │                                           │   │
│  │  ┌─ Protocol Detection (1st bytes) ───┐  │   │
│  │  │                                    │  │   │
│  │  │  0x05        → SOCKS5 handler      │  │   │
│  │  │  GET/POST..  → HTTP handler        │  │   │
│  │  │  CONNECT     → CONNECT handler     │  │   │
│  │  │  other/raw   → Raw TCP tunnel      │  │   │
│  │  │  (incl.      → (uses SO_ORIGINAL   │  │   │
│  │  │   REDSOCKS)     _DST)              │  │   │
│  │  └────────────────────────────────────┘  │   │
│  │                                           │   │
│  │  ┌─ Policy Engine ──────────────────────┐ │   │
│  │  │  Evaluate(host, port, sandbox)       │ │   │
│  │  │  → ALLOW or DENY (shared across all  │ │   │
│  │  │    protocol handlers)                │ │   │
│  │  └──────────────────────────────────────┘ │   │
│  │                                           │   │
│  │  ┌─ Stats / Logging ───────────────────┐ │   │
│  │  │  protocol, src→dst, bytes, duration │ │   │
│  │  └──────────────────────────────────────┘ │   │
│  └──────────────────────┬────────────────────┘   │
└─────────────────────────┼────────────────────────┘
                          │
                          ▼
                   ┌──────────────┐
                   │  Internet /  │
                   │  Upstream    │
                   └──────────────┘
```

### Key design points

- **Single listener on `:3128`** handles HTTP, HTTPS CONNECT, SOCKS5, and raw TCP via first-byte protocol detection.
- **iptables REDIRECT** in the container ensures all outbound TCP hits the proxy transparently.
- **`SO_ORIGINAL_DST`** on the received socket lets the proxy retrieve the original destination IP/port that the client intended to connect to before iptables redirected it.
- **Policy engine is shared** — the same `Engine.Evaluate(host, port, sandboxName)` call is used for all protocols.
- **Secret replacement** is HTTP-only for now (other protocols lack framing knowledge).

---

## 3. Approach A: Transparent TCP Interception (REDSOCKS-style)

### 3.1. How it works

1. The sandbox container starts with an init script (`/bin/sh -c`) that runs **before** the user's command.
2. The init script installs two `iptables` rules in the `OUTPUT` chain of the `nat` table:
   - **Skip rule**: Accept traffic destined to `127.0.0.0/8` and port `:3128` (avoid loop).
   - **Redirect rule**: All other outbound TCP is REDIRECTed to `:3128`.
3. The proxy receives the connection. Because the connection came through a `REDIRECT` target, `SO_ORIGINAL_DST` (getsockopt) reveals the original destination IP and port.
4. The proxy performs a policy lookup on `origDstIP:origDstPort`, then either:
   - **Allow**: Create a new TCP connection to the original destination and `io.Copy` bidirectionally.
   - **Deny**: Close the connection immediately (TCP RST).

### 3.2. iptables rules

```sh
# Must be run inside the sandbox container with CAP_NET_ADMIN
iptables -t nat -A OUTPUT -p tcp --dport 3128 -j ACCEPT
iptables -t nat -A OUTPUT -p tcp -d 127.0.0.0/8 -j ACCEPT
iptables -t nat -A OUTPUT -p tcp ! -d 127.0.0.0/8 -j REDIRECT --to-port 3128
```

Optional — UDP interception (future work):
```sh
iptables -t nat -A OUTPUT -p udp ! -d 127.0.0.0/8 -j REDIRECT --to-port 3128
```

### 3.3. Container requirements

- **Capabilities added**: `NET_ADMIN`, `NET_RAW`
- The `HostConfig` in `container.go` changes from:
  ```go
  "Privileged": false,
  ```
  to:
  ```go
  "Privileged": false,
  "CapAdd": []string{"NET_ADMIN", "NET_RAW"},
  ```
- **iptables binary** must be available in the container image. The proxy-sidecar Docker image should include it (`apt-get install iptables` or use `alpine` with `iptables` package).
- The init script that runs iptables must be injected into the container's `Cmd` (similar to how CA cert injection currently works in `container.go` lines 124–128).

### 3.4. `SO_ORIGINAL_DST` retrieval

Go does not provide a stdlib API for `SO_ORIGINAL_DST`. We use the `golang.org/x/sys/unix` package:

```go
import (
    "golang.org/x/sys/unix"
    "net"
    "syscall"
)

// getOriginalDst retrieves the original destination IP and port
// from a connection that arrived via iptables REDIRECT.
// Uses getsockopt with SO_ORIGINAL_DST (Linux-specific).
func getOriginalDst(conn net.Conn) (net.IP, int, error) {
    tcpConn, ok := conn.(*net.TCPConn)
    if !ok {
        return nil, 0, fmt.Errorf("not a TCP connection")
    }
    f, err := tcpConn.File()
    if err != nil {
        return nil, 0, err
    }
    defer f.Close()

    fd := int(f.Fd())

    // SO_ORIGINAL_DST is defined as 80 on Linux
    const SO_ORIGINAL_DST = 80

    // Retrieve the socket option
    // The result is a sockaddr_in struct
    raw, err := unix.GetsockoptRaw(fd, unix.SOL_IP, SO_ORIGINAL_DST, 16)
    if err != nil {
        return nil, 0, fmt.Errorf("getsockopt SO_ORIGINAL_DST: %w", err)
    }

    // Parse sockaddr_in: 2 bytes family, 2 bytes port (network byte order),
    // 4 bytes IP, 8 bytes padding
    if len(raw) < 8 {
        return nil, 0, fmt.Errorf("short getsockopt result")
    }
    port := int(raw[2])<<8 | int(raw[3])
    ip := net.IP(raw[4:8])
    return ip, port, nil
}
```

> **Note:** This is Linux-specific and only works for IPv4. For IPv6, `IP6T_SO_ORIGINAL_DST` is used (value 80 on `SOL_IPV6`). The current implementation should handle IPv4 only, with IPv6 as a future extension.

### 3.5. Raw TCP handler

```go
// handleRawTCP handles a TCP connection that arrived without an HTTP or SOCKS
// protocol header. It tries SO_ORIGINAL_DST to get the original destination,
// then either opens a tunnel or rejects based on policy.
func (p *Proxy) handleRawTCP(conn net.Conn, sandboxName string) {
    origIP, origPort, err := getOriginalDst(conn)
    if err != nil {
        log.Printf("[proxy] RAW TCP: cannot determine original dst: %v", err)
        conn.Close()
        return
    }

    host := origIP.String()
    portStr := fmt.Sprintf("%d", origPort)

    // Policy check
    decision, ruleID := p.policy.Evaluate(host, portStr, sandboxName)
    if decision == policy.DecisionDeny {
        log.Printf("[proxy] BLOCKED RAW TCP %s:%s (rule: %s, sandbox: %s)",
            host, portStr, ruleID, sandboxName)
        conn.Close()
        return
    }

    // Connect upstream
    upstream, err := net.DialTimeout("tcp", net.JoinHostPort(host, portStr), 10*time.Second)
    if err != nil {
        log.Printf("[proxy] RAW TCP upstream dial failed %s:%s: %v", host, portStr, err)
        conn.Close()
        return
    }

    log.Printf("[proxy] RAW TCP tunnel %s -> %s:%s (sandbox: %s)",
        conn.RemoteAddr(), host, portStr, sandboxName)

    // Bidirectional copy
    var wg sync.WaitGroup
    wg.Add(2)
    go func() {
        defer wg.Done()
        io.Copy(upstream, conn)
        upstream.Close()
    }()
    go func() {
        defer wg.Done()
        io.Copy(conn, upstream)
        conn.Close()
    }()
    wg.Wait()

    log.Printf("[proxy] RAW TCP tunnel closed %s -> %s:%s", conn.RemoteAddr(), host, portStr)
}
```

### 3.6. Pros and Cons of Approach A

| Pros | Cons |
|------|------|
| Transparent — no app changes needed | Requires `CAP_NET_ADMIN` in container |
| Catches **all** TCP, even from apps that ignore proxy env vars | Only TCP (UDP is possible but complex) |
| Works with `socat`, `nc`, SSH, SMTP, etc. | iptables binary must be in image |
| User cannot bypass the proxy | IPv6 needs separate handling |
| Policy is enforced at the kernel level | Slightly higher latency (iptables overhead) |

---

## 4. Approach B: SOCKS5 Handler

### 4.1. How it works

The proxy listens on port `:3128` and detects SOCKS5 connections by reading the first byte (`0x05`). It then follows the SOCKS5 protocol (RFC 1928):

```
Client                              Proxy
  │                                  │
  │  [0x05, n_methods, methods...]   │  Method negotiation
  │─────────────────────────────────>│
  │  [0x05, chosen_method]           │
  │<─────────────────────────────────│
  │                                  │
  │  [0x05, CMD, ATYP, DST...]      │  Request (CMD=1 CONNECT)
  │─────────────────────────────────>│
  │                                  │── Policy check ──
  │                                  │── Connect upstream ──
  │  [0x05, status, RSV, ATYP, ...] │  Response
  │<─────────────────────────────────│
  │                                  │
  │  <bidirectional tunnel>          │  Data relay
  │<════════════════════════════════>│
```

### 4.2. SOCKS5 protocol implementation

**Method negotiation** (RFC 1928 §3):

```go
// Read: [ver, n_methods, methods...]
// Write: [ver, chosen_method]
// We only support NO AUTHENTICATION REQUIRED (0x00).
```

**Request** (RFC 1928 §4):

```
+----+-----+-------+------+----------+----------+
|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
+----+-----+-------+------+----------+----------+
| 1  |  1  | X'00' |  1   | Variable |    2     |
+----+-----+-------+------+----------+----------+
```

- `CMD`: 1 = CONNECT, 2 = BIND, 3 = UDP ASSOCIATE
- `ATYP`: 1 = IPv4, 3 = Domain name, 4 = IPv6
- `DST.ADDR`: length depends on ATYP

**Response** (RFC 1928 §5):

```
+----+-----+-------+------+----------+----------+
|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
+----+-----+-------+------+----------+----------+
```

- `REP`: 0 = success, 1 = general SOCKS server failure, 2 = not allowed

### 4.3. SOCKS5 handler pseudocode

```go
// handleSOCKS5 handles a SOCKS5 connection.
func (p *Proxy) handleSOCKS5(conn net.Conn, sandboxName string) {
    defer conn.Close()

    // 1. Method negotiation
    buf := make([]byte, 257)
    n, err := io.ReadAtLeast(conn, buf, 2)
    if err != nil || buf[0] != 0x05 {
        return
    }
    nMethods := int(buf[1])
    if n < 2+nMethods {
        return
    }
    // Reply: version 5, no auth
    conn.Write([]byte{0x05, 0x00})

    // 2. Read request
    n, err = io.ReadAtLeast(conn, buf, 4)
    if err != nil || buf[0] != 0x05 || buf[1] != 0x01 { // Only CONNECT
        conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0,0,0,0, 0,0}) // CMD not supported
        return
    }

    atyp := buf[3]
    var host string
    switch atyp {
    case 0x01: // IPv4
        _, err = io.ReadFull(conn, buf[:4])
        host = net.IP(buf[:4]).String()
    case 0x03: // Domain name
        _, err = io.ReadFull(conn, buf[:1])
        domainLen := int(buf[0])
        _, err = io.ReadFull(conn, buf[:domainLen])
        host = string(buf[:domainLen])
    case 0x04: // IPv6
        _, err = io.ReadFull(conn, buf[:16])
        host = net.IP(buf[:16]).String()
    default:
        conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0,0,0,0, 0,0}) // ATYP not supported
        return
    }
    _, err = io.ReadFull(conn, buf[:2])
    port := int(buf[0])<<8 | int(buf[1])
    portStr := fmt.Sprintf("%d", port)

    // 3. Policy check
    decision, ruleID := p.policy.Evaluate(host, portStr, sandboxName)
    if decision == policy.DecisionDeny {
        log.Printf("[proxy] BLOCKED SOCKS5 %s:%s (rule: %s, sandbox: %s)",
            host, portStr, ruleID, sandboxName)
        conn.Write([]byte{0x05, 0x02, 0x00, 0x01, 0,0,0,0, 0,0}) // not allowed
        return
    }

    // 4. Connect upstream
    upstream, err := net.DialTimeout("tcp",
        net.JoinHostPort(host, portStr), 10*time.Second)
    if err != nil {
        log.Printf("[proxy] SOCKS5 upstream dial failed %s:%s: %v", host, portStr, err)
        conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0,0,0,0, 0,0}) // general failure
        return
    }
    defer upstream.Close()

    // Bind address (we use 0.0.0.0:0 as we don't care)
    conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0}) // success

    // 5. Bidirectional tunnel
    log.Printf("[proxy] SOCKS5 tunnel %s -> %s:%s (sandbox: %s)",
        conn.RemoteAddr(), host, portStr, sandboxName)

    var wg sync.WaitGroup
    wg.Add(2)
    go func() {
        defer wg.Done()
        io.Copy(upstream, conn)
        upstream.Close()
    }()
    go func() {
        defer wg.Done()
        io.Copy(conn, upstream)
        conn.Close()
    }()
    wg.Wait()

    log.Printf("[proxy] SOCKS5 tunnel closed %s -> %s:%s",
        conn.RemoteAddr(), host, portStr)
}
```

### 4.4. UDP ASSOCIATE (future consideration)

SOCKS5 supports UDP association (CMD=3). This would allow intercepting DNS and other UDP traffic. Implementation sketch:

- Create a UDP socket bound to an ephemeral port
- Reply with the bound address in the SOCKS5 response
- Relay UDP datagrams between client and upstream
- Filter based on policy (host:port extracted from each datagram)

Not required for initial implementation.

### 4.5. BIND support (not needed)

SOCKS5 BIND (CMD=2) is used for incoming connections (e.g., FTP active mode). It is rarely used and can be stubbed with a "command not supported" error initially.

### 4.6. Pros and Cons of Approach B

| Pros | Cons |
|------|------|
| Standard protocol, many apps support it natively | Requires app-level SOCKS configuration |
| No `CAP_NET_ADMIN` needed | Does NOT catch apps unaware of SOCKS |
| Works with SSH (`ProxyCommand=nc -X 5 ...`) | Does not catch raw TCP tools like `socat` |
| Can support UDP (future) | Slightly more processing per connection |
| Clean protocol with standard framing | |

---

## 5. Combined Approach: A + B

### 5.1. Why both?

Neither approach alone is sufficient:

- **Approach A alone** (transparent redirect): Requires `CAP_NET_ADMIN` and only works inside the container. If the user disables the init script or runs without networking, the proxy is bypassed.
- **Approach B alone** (SOCKS5): Only works when the application knows to use a SOCKS proxy. Many tools (`wget`, `curl` by default, `nc`, `ping`, etc.) do not speak SOCKS.

By implementing **both**, we get:

- Transparent capture of **all** TCP traffic via iptables REDIRECT (Approach A)
- Explicit SOCKS5 support for apps that prefer it (Approach B)
- Existing HTTP/HTTPS support unchanged

### 5.2. Protocol detection on the shared listener

The current proxy uses `http.Server` which implicitly speaks only HTTP. We replace it with a **protocol detection listener** that peeks at the first bytes:

```go
// Listener that detects protocol and dispatches to the correct handler.
type protocolDetectListener struct {
    net.Listener
    httpHandler    func(net.Conn)
    socks5Handler  func(net.Conn)
    rawTCPHandler  func(net.Conn)
}

func (l *protocolDetectListener) Accept() (net.Conn, error) {
    conn, err := l.Listener.Accept()
    if err != nil {
        return nil, err
    }
    go l.dispatch(conn)
    return nil, nil // We handle the connection ourselves; caller gets no conn back
}
```

Wait — that violates the expected pattern. Better approach: **replace the `http.Server` with a raw TCP listener** that reads the first bytes and dispatches:

```go
func (p *Proxy) acceptLoop() error {
    for {
        conn, err := p.listener.Accept()
        if err != nil {
            return err
        }
        go p.dispatch(conn)
    }
}

func (p *Proxy) dispatch(conn net.Conn) {
    // Peek at the first bytes to determine protocol
    buf := make([]byte, 1)
    conn.SetReadDeadline(time.Now().Add(5 * time.Second))
    _, err := io.ReadFull(conn, buf)
    if err != nil {
        conn.Close()
        return
    }
    conn.SetReadDeadline(time.Time{}) // disable deadline

    switch buf[0] {
    case 0x05: // SOCKS5 version byte
        // Prepend the byte back and handle
        // Use a buffered reader
        reader := bufio.NewReader(conn)
        reader.UnreadByte() // Not possible directly — need different approach
    }
}
```

**Better approach: Use `bufio.Reader` with a peek.**

```go
func (p *Proxy) dispatch(conn net.Conn) {
    reader := bufio.NewReaderSize(conn, 4)
    
    // Set a short read deadline for protocol detection
    conn.SetReadDeadline(time.Now().Add(5 * time.Second))
    b, err := reader.Peek(1)
    if err != nil {
        conn.Close()
        return
    }
    conn.SetReadDeadline(time.Time{})

    switch b[0] {
    case 0x05:
        p.handleSOCKS5(reader, p.sandboxName)
    default:
        // Try HTTP (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, CONNECT)
        if b[0] >= 0x41 && b[0] <= 0x5A { // ASCII uppercase letter
            p.handleHTTPorCONNECT(reader, p.sandboxName)
        } else {
            // Assume raw TCP (via REDSOCKS redirect)
            p.handleRawTCP(reader, p.sandboxName)
        }
    }
}
```

Actually, the cleanest approach is to **not use `http.Server` at all** and handle all protocols by hand. The current code uses `http.Server` for HTTP. We need two options:

**Option 1: Two listeners (preferred for simplicity)**
- Keep the current `http.Server` on `:3128` for HTTP/HTTPS
- Add a second listener on `:1080` (standard SOCKS port) for SOCKS5
- Raw TCP from REDSOCKS redirect arrives on `:3128` but we cannot distinguish it from HTTP there

This doesn't work well because REDSOCKS sends all TCP to `:3128`.

**Option 2: Replace `http.Server` with a custom TCP listener**
- Accept raw TCP connections
- Peek at the first byte(s) to detect protocol
- Dispatch to the right handler
- For HTTP, construct an `http.Request` from the buffered reader and pass it to the existing HTTP handler

This is the correct approach. See §6 for the refactoring plan.

### 5.3. Combined behavior matrix

| Connection arrives as... | Detected by... | Dispatched to... |
|---|---|---|
| HTTP request (GET, POST, etc.) | First byte = `G`, `P`, `D`, etc. | `handleHTTP` (existing) |
| HTTPS CONNECT tunnel | Bytes = `CONNECT` | `handleCONNECT` (existing) |
| SOCKS5 protocol | First byte = `0x05` | `handleSOCKS5` (new) |
| iptables REDIRECT (raw TCP) | First byte = anything else | `handleRawTCP` (new) |

---

## 6. Refactoring Plan

### 6.1. Replace `http.Server` with raw TCP accept loop

**Current** (`proxy.go` lines 84–97):
```go
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
```

**New**:
```go
go func() {
    log.Printf("[proxy] Listening on %s (HTTP/SOCKS5/RawTCP)", p.httpAddr)
    for {
        conn, err := p.listener.Accept()
        if err != nil {
            if !p.running {
                return
            }
            log.Printf("[proxy] Accept error: %v", err)
            continue
        }
        go p.dispatch(conn)
    }
}()
```

### 6.2. Extract HTTP handling from `handleProxy`

The current `handleProxy` method (line ~102) is an `http.Handler` that receives an `http.ResponseWriter` and `*http.Request`. We need to keep this logic but adapt it to work from a raw `net.Conn`.

**Strategy:** 

1. Keep the existing `handleProxy` as-is for backward compatibility.
2. Add a new internal method `handleHTTPFromReader` that accepts a `*bufio.Reader` and `net.Conn`, parses the HTTP request, and calls the existing CONNECT/HTTP handlers.
3. For the SOCKS5 and raw TCP handlers, they use the `net.Conn` directly.

```go
func (p *Proxy) dispatch(conn net.Conn) {
    reader := bufio.NewReaderSize(conn, 4096)
    
    conn.SetReadDeadline(time.Now().Add(5 * time.Second))
    b, err := reader.Peek(1)
    if err != nil {
        conn.Close()
        return
    }
    conn.SetReadDeadline(time.Time{})

    switch {
    case b[0] == 0x05:
        p.handleSOCKS5(reader, conn, p.sandboxName)
    case b[0] >= 'A' && b[0] <= 'Z':
        // HTTP method (GET, POST, CONNECT, etc.)
        p.handleHTTPFromReader(reader, conn, p.sandboxName)
    default:
        p.handleRawTCP(reader, conn, p.sandboxName)
    }
}
```

### 6.3. Files to create/modify

| File | Action |
|------|--------|
| `internal/proxy/proxy.go` | Replace `http.Server` with raw accept loop; add `dispatch()` method |
| `internal/proxy/socks5.go` | **New** — SOCKS5 handler |
| `internal/proxy/rawtcp.go` | **New** — Raw TCP tunnel handler with `SO_ORIGINAL_DST` |
| `internal/proxy/proxy_test.go` | Add tests for SOCKS5 and raw TCP |
| `internal/container/container.go` | Add `CapAdd: [NET_ADMIN, NET_RAW]` to `HostConfig`; inject iptables init script |
| `cmd/proxy-sidecar/main.go` | Add CLI flags for enabling/disabling SOCKS5 and raw TCP modes |
| `Dockerfile` (proxy-sidecar) | Ensure `iptables` binary is installed |
| `go.mod` | Add `golang.org/x/sys` dependency |

### 6.4. Detailed implementation order

**Phase 1 — Foundation (1 day)**:

1. **`internal/proxy/proxy.go`**: Refactor accept loop from `http.Server.Serve()` to raw `for { Accept(); go dispatch() }`. Keep existing `handleProxy` for HTTP, but wrap it for raw reader input.
2. **`internal/proxy/socks5.go`**: Implement SOCKS5 CONNECT handler.
3. **`internal/proxy/rawtcp.go`**: Implement raw TCP tunnel with `SO_ORIGINAL_DST`.

**Phase 2 — Container plumbing (1 day)**:

4. **`internal/container/container.go`**: Add `CapAdd` and iptables init script to container creation.
5. **Dockerfile**: Install `iptables` in the proxy-sidecar image (or use `apt-get` / `apk`).

**Phase 3 — Integration (0.5 day)**:

6. **`cmd/proxy-sidecar/main.go`**: Add flags: `--enable-socks5`, `--enable-rawtcp`, `--socks5-port` (default `:1080` for explicit SOCKS, but detection on `:3128` also works).
7. **Policy propagation**: Ensure policy engine is reachable from all three handler paths (it already is via `p.policy`).

**Phase 4 — Testing (1 day)**:

8. **Unit tests**:
   - SOCKS5 CONNECT with mock upstream ✅
   - Raw TCP tunnel with mock upstream ✅
   - Protocol detection (first-byte dispatch) ✅
   - Policy enforcement on SOCKS5 and raw TCP ✅
   - Connection limit enforcement ✅
   - Metrics counters after requests ✅
   - Metrics denied count ✅
   - Disabled feature counts as denied ✅
   - Idle timeout closes connections ✅
   - TunnelBidirectional basic copy ✅
   - TunnelBidirectional with idle timeout ✅
9. **Integration test**: Full end-to-end with a sandbox container that uses `socat`
   to make an outbound connection. ✅ **Implemented** — see `test/integration/`.
   Gated behind the `integration` Go build tag.
   Shell script: `test/integration/run_integration_test.sh`
   Go test: `go test -tags=integration -v ./test/integration/`

**Phase 5 — Documentation & hardening (0.5 day)**:

10. Update this document with final decisions. ✅
11. Add connection tracking and timeouts to prevent leaked goroutines. ✅
    - `--max-connections` (default 0 = unlimited)
    - `--raw-tcp-idle-timeout` (default 0 = unlimited)
    - Atomic active-connection counter with deferred decrement
12. Add metrics (connections per protocol, bytes transferred). ✅
    - Per-protocol counters (HTTP, CONNECT, SOCKS5, raw TCP)
    - Denied-connection counter
    - Active-connection gauge
    - Hand-rolled Prometheus `/metrics` endpoint on `:9099`
    - No Prometheus Go library dependency

> **Integration test:** Two entry points in `test/integration/`:
>
> **1. Shell script** (for manual execution):
> ```sh
> ./test/integration/run_integration_test.sh
> ```
> This builds the proxy, creates two containers on a shared Docker bridge network:
> - Container1 runs the proxy + echo server (proxy connects to echo via loopback)
> - Container2 has iptables DNAT redirecting non-loopback TCP to Container1:3128
>
> **2. Go test** (gated behind `integration` build tag):
> ```sh
> go clean -testcache && go test -tags=integration -v ./test/integration/
> ```
> Does the same programmatically using `sh -c` helpers. Requires a running
> Docker daemon. Excluded from `go test ./...` by default.

---

## 7. Backward Compatibility

- The existing HTTP/HTTPS MITM proxy continues to work unchanged.
- Existing sandbox containers (without `CAP_NET_ADMIN`) continue to use HTTP proxy via env vars.
- New sandbox containers automatically get transparent interception, but HTTP traffic still goes through the HTTP handler (first-byte detection).
- The `handleProxy` method signature stays the same.
- The proxy-sidecar's HTTP control API (`:9099`) stays on a separate port and remains unchanged.

---

## 8. Security Considerations

| Concern | Mitigation |
|---------|------------|
| iptables rules inside container break host networking | Rules are applied in the container's own network namespace via `iptables` in the init script. They are automatically destroyed when the container stops. |
| `CAP_NET_ADMIN` escalation | The proxy already runs as a sidecar with limited privileges. The sandbox container gets the capability, but it runs the user's code anyway. |
| `SO_ORIGINAL_DST` spoofing | Only the kernel sets `SO_ORIGINAL_DST`. An attacker inside the container cannot spoof it. |
| SOCKS5 without auth | Only no-auth is supported initially. The proxy is internal to the sandbox container; no external party can reach it. If needed, username/password auth (RFC 1929) can be added later. |
| Resource exhaustion (too many tunnels) | Add a per-sandbox connection limit. The existing `http.Transport` already limits idle connections. Raw tunnels should have a configurable max. |

---

## 9. Future Work

| Feature | Notes |
|---------|-------|
| UDP interception (SOCKS5 UDP ASSOCIATE + iptables UDP REDIRECT) | For DNS and other UDP protocols |
| Protocol-aware logging (SSH, SMTP, etc.) | Read banners after tunnel establishment for richer logs |
| SOCKS5 username/password auth | RFC 1929 |
| Per-connection bandwidth limits | `token bucket` per tunnel |
| IPv6 `SO_ORIGINAL_DST` | `IP6T_SO_ORIGINAL_DST` via `SOL_IPV6` |
| Transparent DNS proxy | Redirect UDP :53 to a DNS filter |

---

## 10. Appendix: How the proxy-sidecar binary is used

From `cmd/proxy-sidecar/main.go` (simplified):

```go
func main() {
    // Parse flags
    proxyPort := flag.String("proxy-port", "3128", "Proxy listen port")
    controlPort := flag.String("control-port", "9099", "Control API port")
    enableSOCKS5 := flag.Bool("enable-socks5", true, "Enable SOCKS5 support")
    enableRawTCP := flag.Bool("enable-rawtcp", true, "Enable raw TCP tunnel (REDSOCKS)")
    flag.Parse()

    // Initialize CA, policy, secrets from env/API
    // ...

    proxy := proxy.NewProxy(ca, policy, secrets, ":"+*proxyPort)
    proxy.SetSOCKS5Enabled(*enableSOCKS5)
    proxy.SetRawTCPEnabled(*enableRawTCP)
    proxy.Start()
}
```

## 11. Open Questions & Missing Decisions

The following items were identified during code review and design reconciliation.
They are captured here so the team can make explicit decisions and update the
implementation accordingly.

---

### 11.1. Order of `Cmd` vs `Entrypoint` in container init script

**Observed:** In `internal/container/container.go` `CreateContainer()`, the user's
command is set as `Entrypoint` and the init script (iptables + CA cert) is set
as `Cmd`. This means Docker runs:

```
<user_command[0]> <user_command[1:]> /bin/sh -c "iptables …; exec \"$@\""
```

The user command runs *first* (as Entrypoint), and *then* `sh` runs the iptables
script — the opposite of what §3.1 describes.

**Question:** Should `Entrypoint` and `Cmd` be swapped so the init script runs
first? i.e.:

```go
createReq["Entrypoint"] = []string{"/bin/sh", "-c", initScript}
createReq["Cmd"] = args
```

**Status:** ✅ **Decision:** Swap Entrypoint and Cmd so the init script runs first.

---

### 11.2. `ForwardSSHAgent` path lacks transparent proxy

**Observed:** The `ForwardSSHAgent()` method in `container.go` creates a
container with HTTP proxy env vars but does **not** set `CapAdd: [NET_ADMIN,
NET_RAW]` and does **not** inject the iptables init script. The design doc
doesn't mention this code path.

**Questions:**
- Should SSH-agent-forwarded containers also get transparent TCP interception?
- If yes, should the CapAdd + iptables logic be extracted into a shared helper
  to avoid duplication between `CreateContainer()` and `ForwardSSHAgent()`?
- If intentionally omitted, why?

**Status:** ✅ **Decision:** Skip for now. Moved to a dedicated design document.

---

### 11.3. Connection limits (was §12.6 in original draft)

**Design says** (old §11.6): "Not yet implemented. A per-sandbox connection limit
should be added before production use."

**Questions:**
- What is the default limit? (Proposal: 0 = unlimited, overridable via CLI flag)
- What counts toward the limit? (Active tunnels only? Open HTTP connections?)
- What happens when the limit is reached? (Drop new connections with a log
  message? Return SOCKS5/HTTP error for protocol-aware clients?)
- How is it configured? (CLI flag `--max-connections`? Environment variable?
  Control API endpoint?)

**Proposal (not yet approved):** `--max-connections` flag (default 0 =
unlimited). Track via atomic counter incremented at dispatch start and
decremented when tunnels/requests complete. At limit, close new connections
immediately with a log message. SOCKS5 connections get a "server failure"
response before closing.

**Status:** ✅ **Decision:** Follow the proposal — add `--max-connections` flag (default 0 = unlimited).

---

### 11.4. Metrics / observability (was §12.7 in original draft)

**Design says** (old §11.10): "A future `/metrics` endpoint on the control port
could expose Prometheus counters."

**Questions:**
- Which format? (Prometheus text format on `/metrics`? JSON? Both?)
- Which counters?
  - Connections per protocol (`http`, `https_connect`, `socks5`, `raw_tcp`)
  - Allowed vs denied per protocol
  - Bytes transferred (ingress / egress)
  - Active connection gauge
  - Connection duration histogram
- Cardinality risk: should per-host labels be avoided at the proxy level?

**Proposal (not yet approved):** Prometheus-format `/metrics` on the control
port (`127.0.0.1:9099`). Expose:
- `dandbox_connections_total{protocol,decision}`
- `dandbox_bytes_total{direction}`
- `dandbox_active_connections`
- `dandbox_connection_duration_seconds`

No per-host labels (aggregate at protocol level only).

**Status:** ✅ **Decision:** Follow the proposal (Prometheus-format `/metrics` on `:9099`), but **without** adding a Prometheus Go client library dependency — serve the text format by hand.

---

### 11.5. Idle timeout for raw TCP / SOCKS5 tunnels (was §12.5 in original draft)

**Design says** (old §11.5): "Raw TCP tunnels use no idle timeout for the
bidirectional copy. This is a deliberate choice — raw TCP can be long-lived."

**Questions:**
- Should a configurable idle timeout be added? (Default 0 = no timeout, but
  allow `--raw-tcp-idle-timeout=30m` via CLI flag.)
- How would it be enforced? (`SetReadDeadline()` on each `io.Copy` iteration,
  or a per-connection watchdog goroutine?)
- If enabled, should SOCKS5 tunnels share the same timeout or have their own?

**Proposal (not yet approved):** Add `--raw-tcp-idle-timeout` (default `0` =
unlimited). Implement via a goroutine that resets a `time.Timer` on each data
read from either direction. If the timer fires, close both sides.

**Status:** ✅ **Decision:** Follow the proposal — add `--raw-tcp-idle-timeout` (default `0` = unlimited) with a timer-based watchdog goroutine.

---

### 11.6. Decision string literal vs named constant

**Observed:** In `socks5.go` and `rawtcp.go`, the policy decision is compared
as a string literal:

```go
if decision == "deny" { ... }
```

But in `proxy.go` the named constant `policy.DecisionDeny` is used.

**Question:** Should the string literals be replaced with the named constant
for consistency and safety?

**Proposal:** Replace all `== "deny"` with `== policy.DecisionDeny`.

**Status:** ✅ **Decision:** Follow the proposal.

---

### 11.7. UDP interception — first concrete step

**Design says** (§4.4, §10): UDP is "future work" — SOCKS5 UDP ASSOCIATE and
iptables UDP REDIRECT.

**Question:** What is the first concrete use case to target?

**Proposal (not yet approved):** Start with **DNS interception only**
(port 53 UDP):
- Redirect UDP :53 via `iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-port 3128`
- Parse DNS queries (simple header parser) to extract the queried domain
- Log the domain and apply policy (allow/deny)
- Forward allowed queries to upstream resolver
- Full SOCKS5 UDP ASSOCIATE comes later if needed

**Status:** ✅ **Decision:** Skip UDP for now. Create a separate follow-up design document for UDP interception (DNS port 53 first).

---

### 11.8. IPv6 support plan

**Design says** (§11.8): "Not supported. `SO_ORIGINAL_DST` only for IPv4."

**Questions:**
- When should IPv6 support be added? Is there a concrete user need?
- Full scope: `IP6T_SO_ORIGINAL_DST`, IPv6 iptables rules, IPv6 DNS resolution
  in the policy engine, CI with Docker IPv6 enabled.

**Proposal (not yet approved):** Defer until a concrete user need arises.
Document the gap in the README.

**Status:** ✅ **Decision:** Defer until a concrete user need arises. Document the gap in the README.

---

### 11.9. SOCKS5 username/password authentication (RFC 1929)

**Design says** (§8): "Only no-auth is supported initially. If needed,
username/password auth (RFC 1929) can be added later."

**Question:** Is RFC 1929 auth ever needed? The SOCKS5 listener is on the
container's loopback (via iptables REDIRECT to `:3128`), so no external party
can reach it. Most SOCKS5 clients are fine with "no auth".

**Proposal (not yet approved):** Keep "no auth" indefinitely. Add RFC 1929 only
when a user reports a client that refuses to connect without authentication.

**Status:** ✅ **Decision:** Keep "no auth" indefinitely. Add RFC 1929 only when a user reports a client that refuses to connect.

---

### 11.10. `golang.org/x/sys` dependency vs raw syscall

**Design says** (§3.4): Use `golang.org/x/sys/unix.GetsockoptRaw`.

**Observed:** The implementation in `rawtcp.go` uses `syscall.Syscall6`
directly instead of `unix.GetsockoptRaw`. The `golang.org/x/sys` package is in
`go.mod` as a transitive dependency but is not used by the proxy.

**Question:** Should the implementation switch to `unix.GetsockoptRaw` (as the
design recommends) or keep the raw syscall (as implemented)?

**Proposal (not yet approved):** Keep the raw `syscall.Syscall6` approach — it
avoids an indirect dependency and is well-understood. Update the design doc to
match reality.

**Status:** ✅ **Decision:** Follow the proposal — keep the raw `syscall.Syscall6` approach. Update the design doc code snippet in §3.4 to match.

---

## 12. Implementation Notes


### 12.1. `SO_ORIGINAL_DST` via Raw Syscall

`golang.org/x/sys v0.46.0` does not provide `GetsockoptRaw`. The implementation uses `syscall.Syscall6` with `SYS_GETSOCKOPT` directly (see `internal/proxy/rawtcp.go`). This is Linux-specific, but the proxy is always deployed as a Linux container.

### 12.2. HTTP Bridge via `httpConnResponseWriter`

When `dispatch()` detects an HTTP request, it reads the full HTTP request from the buffered `*bufio.Reader` using `http.ReadRequest()`, then constructs an `httpConnResponseWriter` that implements both `http.ResponseWriter` and `http.Hijacker` over the raw `net.Conn`. This allows the existing `handleCONNECT` (which uses hijacking for TLS MITM) and `handleHTTP` handlers to work without modification.

### 12.3. Sandbox Name Propagation

The proxy is 1:1 with sandbox containers — one proxy sidecar per sandbox. The sandbox name is set once at construction via `SetSandboxName()` and stored in the `Proxy` struct. `dispatch()` reads it under the lock and passes it to each handler.

### 12.4. Feature Toggles

Both SOCKS5 and raw TCP handlers are enabled by default. They can be disabled via `SetSOCKS5Enabled(false)` / `SetRawTCPEnabled(false)`. When disabled, connections matching those protocols are immediately closed with a log message.

### 12.5. Idle Timeout

Configurable via `--raw-tcp-idle-timeout` CLI flag (default `0` = unlimited). When
set, a `deadlineReader` wrapper sets `SetReadDeadline` on each `Read()` call,
causing `io.Copy` to return with a timeout error when no data flows for the
configured duration. Both the upstream and downstream connections are closed
when the timeout fires. The timeout applies to both raw TCP tunnels and SOCKS5
tunnels.

### 12.6. Connection Limits

Configurable via `--max-connections` CLI flag (default `0` = unlimited). Tracked
with an atomic int64 counter incremented at the top of `dispatch()` and
decremented on connection close via `defer`. When the limit is reached, new
connections are immediately closed with a log message.

### 12.7. TLS MITM for SOCKS5 CONNECT on Port 443

Not implemented. SOCKS5 CONNECT to port 443 opens a raw TCP tunnel — no TLS interception is performed. The SOCKS5 protocol provides no mechanism for the proxy to act as a TLS MITM (no SNI, no certificate generation trigger). HTTP clients should use the HTTP CONNECT method instead.

### 12.8. IPv6

Not supported. `SO_ORIGINAL_DST` is only implemented for IPv4. The iptables rules only match `127.0.0.0/8`. IPv6 (`IP6T_SO_ORIGINAL_DST`) is left as future work.

### 12.9. Protocol Detection Deadline

The first-byte peek uses a 5-second read deadline, which is hardcoded. This is sufficient for local container traffic.

### 12.10. Metrics / Observability

Implemented via hand-rolled Prometheus text format (no Prometheus Go client
library dependency). The proxy maintains atomic counters for:
- `proxy_connections_total{protocol="http"}` — plain HTTP requests
- `proxy_connections_total{protocol="connect"}` — HTTPS CONNECT tunnels
- `proxy_connections_total{protocol="socks5"}` — SOCKS5 connections
- `proxy_connections_total{protocol="rawtcp"}` — raw TCP tunnels
- `proxy_connections_denied_total` — connections blocked by policy
- `proxy_active_connections` — current concurrent connection gauge

Exposed via a `/metrics` endpoint on the control port (`127.0.0.1:9099`).
No per-host labels to avoid cardinality explosion.
