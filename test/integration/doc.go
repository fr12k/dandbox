// Package integration contains end-to-end tests that require a running Docker daemon.
//
// These tests are gated behind the "integration" build tag so they are excluded
// from `go test ./...` by default. Run them explicitly:
//
//	go test -tags=integration -v ./test/integration/
//
// Prerequisites:
//   - Docker daemon running and accessible via the docker socket
//   - socat (installed in the test container automatically via apk)
//   - Proxy-sidecar binary (built from source in the test)
package integration