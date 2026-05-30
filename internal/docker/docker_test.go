package docker

import (
	"os"
	"testing"
)

func TestDefaultSocketPath(t *testing.T) {
	path := DefaultSocketPath()
	if path == "" {
		t.Error("DefaultSocketPath() returned empty string")
	}
	if !contains(path, "docker.sock") {
		t.Errorf("DefaultSocketPath() = %q, expected to contain 'docker.sock'", path)
	}
}

func TestDetectSocket(t *testing.T) {
	path := DetectSocket()
	if path == "" {
		t.Error("DetectSocket() returned empty string")
	}
	t.Logf("DetectSocket() = %q", path)
}

func TestDetectSocket_FallbackToDefault(t *testing.T) {
	path := DetectSocket()
	if path != DefaultSocketPath() {
		t.Logf("DetectSocket found socket at: %s (default: %s)", path, DefaultSocketPath())
	}
}

func TestPerUserSocket_XDG(t *testing.T) {
	origXDG := os.Getenv("XDG_STATE_HOME")
	if err := os.Setenv("XDG_STATE_HOME", "/tmp/test-xdg"); err != nil {
		t.Fatalf("Setenv failed: %v", err)
	}
	defer func() {
		_ = os.Setenv("XDG_STATE_HOME", origXDG)
	}()

	socket := perUserSocket()
	expected := "/tmp/test-xdg/sandboxes/sandboxes/sandboxd/docker.sock"
	if socket != expected {
		t.Errorf("perUserSocket() with XDG_STATE_HOME = %q, got %q, want %q",
			"/tmp/test-xdg", socket, expected)
	}
}

func TestPerUserSocket_DefaultHome(t *testing.T) {
	origXDG := os.Getenv("XDG_STATE_HOME")
	if err := os.Setenv("XDG_STATE_HOME", ""); err != nil {
		t.Fatalf("Setenv failed: %v", err)
	}
	defer func() {
		_ = os.Setenv("XDG_STATE_HOME", origXDG)
	}()

	socket := perUserSocket()
	if socket == "" {
		t.Error("perUserSocket() returned empty string with default home dir")
	}
	if !contains(socket, "sandboxes") {
		t.Errorf("perUserSocket() = %q, expected to contain 'sandboxes'", socket)
	}
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}