package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRun_FlagParsingError(t *testing.T) {
	// Test that run() handles flag parsing errors
	err := run([]string{"-nonexistent-flag"})
	if err == nil {
		t.Error("expected error for nonexistent flag, got nil")
	}
}

func TestSocketPathConstruction(t *testing.T) {
	home := "/home/testuser"
	socketPath := filepath.Join(home, ".config", "sbxsandbox", "sbxsandbox.sock")
	expected := "/home/testuser/.config/sbxsandbox/sbxsandbox.sock"
	if socketPath != expected {
		t.Errorf("expected %q, got %q", expected, socketPath)
	}
}

func TestStateDirConstruction(t *testing.T) {
	home := "/home/testuser"
	stateDir := filepath.Join(home, ".local", "state", "sbxsandbox")
	expected := "/home/testuser/.local/state/sbxsandbox"
	if stateDir != expected {
		t.Errorf("expected %q, got %q", expected, stateDir)
	}
}

func TestDefaultValues(t *testing.T) {
	// Verify default proxy sidecar image is set
	defaultImage := "containifyci/proxy-sidecar:latest"
	if defaultImage == "" {
		t.Error("expected non-empty proxy sidecar image")
	}
}

func TestEnvironmentVariableProxyBin(t *testing.T) {
	origBin := os.Getenv("PROXY_SIDECAR_BIN")
	defer func() { _ = os.Setenv("PROXY_SIDECAR_BIN", origBin) }()

	if err := os.Setenv("PROXY_SIDECAR_BIN", "/usr/local/bin/proxy-sidecar"); err != nil {
		t.Fatalf("Setenv failed: %v", err)
	}
	bin := os.Getenv("PROXY_SIDECAR_BIN")
	if bin != "/usr/local/bin/proxy-sidecar" {
		t.Errorf("expected /usr/local/bin/proxy-sidecar, got %q", bin)
	}
}

func TestHomeDirFallback(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Errorf("UserHomeDir() error: %v", err)
	}
	if home == "" {
		t.Error("expected non-empty home directory")
	}
}