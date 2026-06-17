#!/usr/bin/env bash
#
# Universal Proxy Integration Test
#
# Single container. sleep infinity + docker exec for each step.
# Echo on 127.0.0.1:19999. Proxy on :3128. iptables REDIRECT non-loopback.
# The proxy rewrites local IPs to 127.0.0.1 to break the loop.

set -euo pipefail
cd "$(dirname "$0")/../.."

echo "=== Universal Proxy Integration Test ==="
echo ""

cleanup() {
  [ -n "${CID:-}" ] && docker rm -f "${CID}" 2>/dev/null || true
}
trap cleanup EXIT

# Build proxy
echo "--- Build proxy ---"
DOCKER_ARCH=$(docker info --format '{{.Architecture}}' 2>/dev/null || echo "amd64")
case "${DOCKER_ARCH}" in aarch64|arm64) GOARCH=arm64 ;; *) GOARCH=amd64 ;; esac
GOOS=linux GOARCH=${GOARCH} CGO_ENABLED=0 go build -ldflags="-s -w" -o /tmp/pxy-test ./cmd/proxy-sidecar/
echo ""

# Start container
echo "--- Start container ---"
CID=$(docker run -d --rm \
  --cap-add=NET_ADMIN --cap-add=NET_RAW \
  -v /tmp/pxy-test:/tmp/proxy-sidecar:ro \
  alpine:3.23 sh -c "sleep infinity")
echo "Container: ${CID}"
echo ""

# Install packages
echo "--- Install packages ---"
docker exec "${CID}" apk add -q iptables socat curl
echo ""

# Start echo server
echo "--- Start echo server ---"
docker exec "${CID}" sh -c "socat TCP-LISTEN:19999,bind=127.0.0.1,reuseaddr,fork EXEC:cat &"
echo ""

# Start proxy
echo "--- Start proxy ---"
docker exec "${CID}" sh -c "/tmp/proxy-sidecar --proxy-addr=:3128 --sandbox=integration-test &"
sleep 2
echo ""

# Verify proxy is listening
echo "--- Verify proxy ---"
docker exec "${CID}" sh -c "curl -s --max-time 3 http://127.0.0.1:9099/health" || { echo "FAIL: proxy not healthy"; exit 1; }
echo "  Proxy healthy"
echo ""

# Install iptables
echo "--- Install iptables REDIRECT ---"
docker exec "${CID}" iptables -t nat -A OUTPUT -p tcp --dport 3128 -j ACCEPT
docker exec "${CID}" iptables -t nat -A OUTPUT -p tcp -d 127.0.0.0/8 -j ACCEPT
docker exec "${CID}" iptables -t nat -A OUTPUT -p tcp ! -d 127.0.0.0/8 -j REDIRECT --to-port 3128
echo ""

# Configure policy
echo "--- Configure policy ---"
cat > /tmp/policy.json <<'EOF'
{"rules":[{"id":"allow-echo","name":"allow-echo","decision":"allow","resources":["*:19999"]}]}
EOF
docker cp /tmp/policy.json "${CID}":/tmp/policy.json
docker exec "${CID}" sh -c "curl -s -X POST http://127.0.0.1:9099/policy/reload -H Content-Type:application/json -d @/tmp/policy.json"
echo ""

# Get container IP
MY_IP=$(docker exec "${CID}" sh -c "hostname -i | awk '{print \$1}'")
echo "Container IP: ${MY_IP}"
echo ""

# Test 1: Direct echo
echo "--- Direct echo ---"
RESULT=$(docker exec "${CID}" sh -c "echo direct | timeout 5 socat - TCP:127.0.0.1:19999,connect-timeout=3 2>/dev/null || echo FAIL")
if [ "${RESULT}" != "direct" ]; then
  echo "FAIL: direct echo: ${RESULT}"
  exit 1
fi
echo "  OK"
echo ""

# Test 2: Echo through proxy
echo "--- Echo through proxy ---"
PAYLOAD="hello-$(date +%s)"
RESULT=$(docker exec "${CID}" sh -c "echo '${PAYLOAD}' | timeout 10 socat - TCP:${MY_IP}:19999,connect-timeout=5 2>/dev/null || echo FAIL")
echo "  Sent: ${PAYLOAD}"
echo "  Got:  ${RESULT}"
if [ "${RESULT}" != "${PAYLOAD}" ]; then
  echo "FAIL: echo through proxy"
  docker logs "${CID}"
  exit 1
fi
echo "  OK"
echo ""

# Test 3: Blocked
echo "--- Blocked ---"
docker exec "${CID}" sh -c "echo test | timeout 5 socat - TCP:${MY_IP}:443,connect-timeout=3 2>&1 || echo BLOCKED"
echo ""

echo "=== ALL TESTS PASSED ==="