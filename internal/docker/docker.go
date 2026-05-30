// Package docker provides utilities for discovering the Docker socket path used
// by Docker Sandbox (sandboxd). It checks well-known paths and OS-specific
// locations.
package docker

import (
	"fmt"
	"os"
)

// ── Docker Socket Path ───────────────────────────────────────────────────────

// DefaultSocketPath returns the default sandboxd Docker socket path for
// the current OS. This is the socket through which container operations are
// performed.
func DefaultSocketPath() string {
	// The sandboxd Docker socket is typically at:
	// /tmp/sboxd-<uid>-sandboxes/docker.sock
	// But the exact path is returned by GET /daemon/info.
	// This is a fallback that works on macOS with sandboxd.
	return "/tmp/sboxd-501-sandboxes/docker.sock"
}

// perUserSocket returns the per-user sandboxd Docker Engine socket path,
// honouring the XDG_STATE_HOME environment variable when set.
func perUserSocket() string {
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "" // can't determine path without a home dir
		}
		base = home + "/.local/state"
	}
	return base + "/sandboxes/sandboxes/sandboxd/docker.sock"
}

// DetectSocket tries to find the sandboxd Docker socket.
// First checks the well-known path, then tries to read from
// /proc/self/mountinfo or other OS-specific locations.
func DetectSocket() string {
	// Well-known paths for sandboxd Docker socket
	candidates := []string{
		DefaultSocketPath(),
		"/tmp/sboxd-sandboxes/docker.sock",
	}

	// Per-user XDG_STATE_HOME path (Ubuntu / non-root Docker Sandboxes)
	if p := perUserSocket(); p != "" {
		candidates = append(candidates, p)
	}

	// Try to find by PID
	uid := os.Getuid()
	candidates = append(candidates,
		fmt.Sprintf("/tmp/sboxd-%d-sandboxes/docker.sock", uid),
	)

	for _, p := range candidates {
		if info, err := os.Stat(p); err == nil && info.Mode()&os.ModeSocket != 0 {
			return p
		}
	}
	return DefaultSocketPath()
}
