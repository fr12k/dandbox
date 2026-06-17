# Integration Tests

## Prerequisites

- Docker daemon running
- `go` toolchain
- `socat` installed locally (for echo server)

## Manual Integration Test

The `run_integration_test.sh` script exercises the full stack:

1. Builds the proxy-sidecar binary
2. Starts a local TCP echo server (via socat)
3. Starts the proxy-sidecar
4. Creates a sandbox container with `CAP_NET_ADMIN`, iptables REDIRECT, and socat
5. Proves that outbound TCP from the container is intercepted by the proxy

Run it:

```sh
./test/integration/run_integration_test.sh
```

## Go Integration Test

The `integration_test.go` file contains a Go test that does the same
programmatically (using `container.Manager` and the Docker API).
It requires a running Docker daemon and is gated behind the `integration` build tag.

Run it:

```sh
go test -tags=integration -v ./test/integration/
```