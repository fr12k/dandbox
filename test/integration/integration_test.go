//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSocatThroughTransparentProxy(t *testing.T) {
	if exec.Command("docker", "info").Run() != nil {
		t.Skip("Docker not available")
	}

	// Build proxy binary for linux matching Docker's arch
	proxyBin := filepath.Join(t.TempDir(), "proxy-sidecar")
	archOut, _ := exec.Command("docker", "info", "--format", "{{.Architecture}}").Output()
	goArch := "amd64"
	switch strings.TrimSpace(string(archOut)) {
	case "aarch64", "arm64":
		goArch = "arm64"
	}
	build := exec.Command("go", "build", "-o", proxyBin, "-ldflags=-s -w",
		"github.com/fr12k/dandbox/cmd/proxy-sidecar")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+goArch, "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, string(out))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// Helper: run a command, log it, return trimmed stdout
	execIn := func(containerID, cmd string) string {
		fullCmd := exec.CommandContext(ctx, "docker", "exec", containerID, "sh", "-c", cmd)
		out, _ := fullCmd.CombinedOutput()
		result := strings.TrimSpace(string(out))
		t.Logf("  exec: %s", cmd)
		return result
	}

	// Start container with sleep infinity — simple, no init script needed
	cid := strings.TrimSpace(string(runCmd(ctx, t,
		"docker", "run", "-d", "--rm",
		"--cap-add=NET_ADMIN", "--cap-add=NET_RAW",
		"-v", proxyBin+":/tmp/proxy-sidecar:ro",
		"alpine:3.23",
		"sh", "-c", "sleep infinity",
	)))
	t.Logf("Container: %s", cid)
	defer runCmd(ctx, t, "docker", "rm", "-f", cid)

	// Step 1: Install packages
	execIn(cid, "apk add -q iptables socat curl")

	// Step 2: Start echo server on 127.0.0.1:19999
	execIn(cid, "socat TCP-LISTEN:19999,bind=127.0.0.1,reuseaddr,fork EXEC:cat &")

	// Step 3: Start proxy
	execIn(cid, "/tmp/proxy-sidecar --proxy-addr=:3128 --sandbox=integration-test &")
	time.Sleep(2 * time.Second)

	// Step 4: Verify proxy is listening
	health := execIn(cid, "curl -s --max-time 3 http://127.0.0.1:9099/health")
	if !strings.Contains(health, "healthy") {
		t.Fatalf("proxy not healthy: %s", health)
	}
	t.Log("Proxy healthy")

	// Step 5: Install iptables REDIRECT rules
	execIn(cid, "iptables -t nat -A OUTPUT -p tcp --dport 3128 -j ACCEPT")
	execIn(cid, "iptables -t nat -A OUTPUT -p tcp -d 127.0.0.0/8 -j ACCEPT")
	execIn(cid, "iptables -t nat -A OUTPUT -p tcp ! -d 127.0.0.0/8 -j REDIRECT --to-port 3128")

	// Step 6: Configure policy via docker cp
	policyJSON := `{"rules":[{"id":"allow-echo","name":"allow-echo","decision":"allow","resources":["*:19999"]}]}`
	policyFile := filepath.Join(t.TempDir(), "policy.json")
	os.WriteFile(policyFile, []byte(policyJSON), 0644)
	runCmd(ctx, t, "docker", "cp", policyFile, cid+":/tmp/policy.json")
	execIn(cid, "curl -s -X POST http://127.0.0.1:9099/policy/reload -H Content-Type:application/json -d @/tmp/policy.json")

	// Get container IP
	myIP := execIn(cid, "hostname -i | awk '{print $1}'")
	if myIP == "" {
		t.Fatal("could not get container IP")
	}
	t.Logf("Container IP: %s", myIP)

	// Test 1: Direct echo works (baseline)
	t.Run("direct_echo", func(t *testing.T) {
		result := execIn(cid, "echo direct | timeout 5 socat - TCP:127.0.0.1:19999,connect-timeout=3 2>/dev/null || echo FAIL")
		if result != "direct" {
			t.Fatalf("direct echo failed: %q", result)
		}
	})

	// Test 2: socat to container IP → REDIRECT → proxy → rewritten to 127.0.0.1 → echo
	t.Run("echo_through_proxy", func(t *testing.T) {
		payload := fmt.Sprintf("hello-%d", time.Now().UnixNano())
		result := execIn(cid, fmt.Sprintf("echo '%s' | timeout 10 socat - TCP:%s:19999,connect-timeout=5 2>/dev/null || echo FAIL", payload, myIP))
		if result != payload {
			proxyLogs, _ := exec.Command("docker", "logs", cid).CombinedOutput()
			t.Fatalf("sent %q got %q\nProxy logs:\n%s", payload, result, string(proxyLogs))
		}
		t.Logf("echo through proxy OK")
	})

	// Test 3: Blocked connection
	t.Run("blocked", func(t *testing.T) {
		result := execIn(cid, fmt.Sprintf("echo test | timeout 5 socat - TCP:%s:443,connect-timeout=3 2>&1 || echo BLOCKED", myIP))
		if strings.Contains(result, "BLOCKED") || strings.Contains(result, "refused") {
			t.Log("Blocked OK")
		} else {
			t.Logf("Blocked result: %q", result)
		}
	})
}

func runCmd(ctx context.Context, t *testing.T, name string, arg ...string) []byte {
	t.Helper()
	out, err := exec.CommandContext(ctx, name, arg...).Output()
	if err != nil {
		t.Fatalf("cmd %s: %v\n%s", name, err, string(out))
	}
	return out
}