# dandbox

Sandboxed code execution with MITM-proxied network policy enforcement and secret injection.

## Overview

dandbox runs Docker containers in an isolated network environment where all HTTP/HTTPS traffic is intercepted by a man-in-the-middle proxy. The proxy enforces network access policies (allow/deny by host, port, and wildcard patterns) and replaces secret sentinel placeholders with actual values — so container code never sees raw secrets and can only reach approved endpoints.

The project consists of two binaries:

| Binary | Description |
|---|---|
| **`dandbox`** | Daemon that manages sandbox lifecycles — creating, starting, stopping, and removing Docker containers while injecting the proxy sidecar and CA certificate. |
| **`proxy-sidecar`** | Standalone MITM proxy that intercepts HTTP and HTTPS traffic, evaluates policy rules, injects secrets into request/response bodies and headers, and exposes a health/policy/secrets management API on port 9099. |

## Architecture

```
┌──────────────────────────┐
│       dandbox daemon     │  Unix socket API
│  ┌────────────────────┐  │
│  │  Container Manager │──┼──► Docker Engine (sandboxd socket)
│  └────────────────────┘  │
└──────────────────────────┘
           │  spawns & configures
           ▼
┌──────────────────────────┐       ┌────────────────────────┐
│    proxy-sidecar         │       │   sandbox container    │
│  ┌──────┐ ┌──────────┐  │       │  HTTP_PROXY → sidecar  │
│  │  CA  │ │  Policy  │  │◀──────│  HTTPS_PROXY → sidecar │
│  └──────┘ └──────────┘  │  MITM │                        │
│  ┌───────────┐           │──────▶│  Internet (if allowed) │
│  │  Secrets  │           │       └────────────────────────┘
│  └───────────┘           │
│  :3128    :9099           │
└──────────────────────────┘
```

**Key components (`internal/`):**

| Package | Purpose |
|---|---|
| `daemon` | Main daemon — Unix socket API, sandbox CRUD, sidecar lifecycle |
| `proxy` | HTTP/HTTPS CONNECT proxy with request/response interception and modification |
| `policy` | Rule-based allow/deny engine with wildcard matching and per-sandbox scoping |
| `secrets` | Sentinel-to-value replacement in HTTP headers and bodies; redaction for logs |
| `ca` | Dynamic TLS certificate authority — generates per-host certificates on the fly for MITM |
| `container` | Docker container lifecycle (create, start, stop, remove) via raw Engine API over Unix socket |
| `docker` | Docker socket path detection for sandboxd environments |
| `cmdutil` | Shell command execution helpers |

## Building

```bash
go build -o bin/dandbox ./cmd/dandbox
go build -o bin/proxy-sidecar ./cmd/proxy-sidecar
```

## Running the Daemon

```bash
./bin/dandbox \
  -socket ~/.config/sbxsandbox/sbxsandbox.sock \
  -docker-socket /tmp/sboxd-501-sandboxes/docker.sock \
  -state-dir ~/.local/state/sbxsandbox \
  -policy-dir ~/.config/sbxsandbox/policy \
  -ca-dir ~/.config/sbxsandbox/ca
```

## Running the Proxy Sidecar

The sidecar is normally launched automatically by the daemon inside a container, but can be run standalone for testing:

```bash
./bin/proxy-sidecar \
  -proxy-addr :3128 \
  -ca-dir /etc/sbxsandbox/ca \
  -policy-dir /etc/sbxsandbox/policy \
  -sandbox my-sandbox
```

### Runtime API (port 9099, loopback only)

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Health check |
| `/ready` | GET | Readiness check (includes proxy address) |
| `/policy/reload` | POST | Hot-reload policy rules (JSON: `{"rules": [...]}`) |
| `/secrets/reload` | POST | Hot-reload secrets (JSON: `{"secrets": [...]}`) |

### Environment Variables

| Variable | Used by | Description |
|---|---|---|
| `PROXY_RULES_JSON` | proxy-sidecar | Initial policy rules (JSON array) |
| `PROXY_CA_DIR` | proxy-sidecar | CA certificate directory |
| `PROXY_POLICY_DIR` | proxy-sidecar | Policy directory |
| `PROXY_SIDECAR_BIN` | dandbox | Path to the proxy-sidecar binary |
| `SBXSANDBOX_CA_CERT` | container mgr | Path to CA cert for injection into containers |

## License

MIT license