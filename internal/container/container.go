// Package container manages Docker container lifecycle and provisioning.
// It handles creating, starting, stopping, and removing sandbox containers
// with proxy injection, CA certificate installation, and SSH agent forwarding.
package container

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fr12k/dandbox/internal/cmdutil"
)

// ── Types ─────────────────────────────────────────────────────────────────────

// Container represents a Docker container.
type Container struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Image    string   `json:"image"`
	Status   string   `json:"status"`
	Running  bool     `json:"running"`
	Sandbox  string   `json:"sandbox"`
	Ports    []string `json:"ports,omitempty"`
	ExitCode int      `json:"exitCode"`
	Error    string   `json:"error,omitempty"`
}

// Manager manages sandbox containers via Docker.
type Manager struct {
	socketPath  string
	dockerHost  string
	httpClient  *http.Client
	dataDir     string
	networkName string
}

// NewManager creates a container manager.
func NewManager(socketPath, dataDir string) *Manager {
	m := &Manager{
		socketPath:  socketPath,
		dockerHost:  "unix://" + socketPath,
		dataDir:     dataDir,
		networkName: "sandbox-net",
	}
	m.httpClient = &http.Client{
		Timeout: 120 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
	}
	return m
}

// DockerSocketPath returns the Docker socket path used.
func (m *Manager) DockerSocketPath() string {
	return m.socketPath
}

// ── Container Lifecycle ───────────────────────────────────────────────────────

// CreateContainer creates a new Docker container from the given image and args.
func (m *Manager) CreateContainer(ctx context.Context, image string, args []string, envVars []string, sandboxName string) (*Container, error) {
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	// Ensure network exists
	if err := m.ensureNetwork(ctx); err != nil {
		return nil, fmt.Errorf("ensure network: %w", err)
	}

	containerName := fmt.Sprintf("sbx-%s", sandboxName)

	// Pull the image
	if err := m.pullImage(ctx, image); err != nil {
		return nil, fmt.Errorf("pull image %s: %w", image, err)
	}

	// Read CA certificate
	caPath := os.Getenv("SBXSANDBOX_CA_CERT")
	var caContent string
	if caPath != "" {
		data, err := os.ReadFile(caPath)
		if err == nil {
			caContent = string(data)
		}
	}

	// Prepare environment variables
	env := []string{}
	env = append(env, envVars...)
	env = append(env,
		"HTTP_PROXY=http://host.docker.internal:3128",
		"HTTPS_PROXY=http://host.docker.internal:3128",
		"http_proxy=http://host.docker.internal:3128",
		"https_proxy=http://host.docker.internal:3128",
		"NO_PROXY=localhost,127.0.0.1,.local",
		"no_proxy=localhost,127.0.0.1,.local",
	)

	// Build create request
	createReq := map[string]interface{}{
		"Image":      image,
		"Env":        env,
		"Cmd":        args,
		"HostConfig": map[string]interface{}{
			"NetworkMode": m.networkName,
			"ExtraHosts":  []string{"host.docker.internal:host-gateway"},
			"Privileged":  false,
			"CapAdd":      []string{"NET_ADMIN", "NET_RAW"},
		},
	}

	// Build init script that runs before the user's command.
	// The script installs the CA certificate (if available) and sets up
	// iptables REDIRECT rules for transparent TCP interception.
	initScript := ""

	// CA certificate installation
	if caContent != "" {
		initScript += fmt.Sprintf(
			"mkdir -p /usr/local/share/ca-certificates && "+
				"echo '%s' > /usr/local/share/ca-certificates/sbx-ca.crt && "+
				"update-ca-certificates 2>/dev/null || true; ", caContent)
	}

	// iptables REDIRECT rules for transparent TCP interception.
	// These run inside the container's own network namespace and are
	// automatically destroyed when the container stops.
	// If iptables is not available, the script continues without error.
	initScript += `iptables -t nat -A OUTPUT -p tcp --dport 3128 -j ACCEPT 2>/dev/null; ` +
		`iptables -t nat -A OUTPUT -p tcp -d 127.0.0.0/8 -j ACCEPT 2>/dev/null; ` +
		`iptables -t nat -A OUTPUT -p tcp ! -d 127.0.0.0/8 -j REDIRECT --to-port 3128 2>/dev/null || true; ` +
		`exec "$@"`

	if initScript != "" {
		createReq["Entrypoint"] = []string{
			"/bin/sh", "-c", initScript,
		}
	}

	body, err := json.Marshal(createReq)
	if err != nil {
		return nil, fmt.Errorf("marshal create request: %w", err)
	}

	// Create container
	createURL := fmt.Sprintf("http://localhost/v1.54/containers/create?name=%s", containerName)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, createURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("create container: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("create container failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var createResp struct {
		ID       string `json:"Id"`
		Warnings []string `json:"Warnings"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&createResp); err != nil {
		return nil, fmt.Errorf("decode create response: %w", err)
	}

	container := &Container{
		ID:      createResp.ID,
		Name:    containerName,
		Image:   image,
		Sandbox: sandboxName,
		Status:  "created",
	}

	return container, nil
}

// StartContainer starts an existing container.
func (m *Manager) StartContainer(ctx context.Context, containerID string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	startURL := fmt.Sprintf("http://localhost/v1.54/containers/%s/start", containerID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, startURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("start container: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotModified {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("start container failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// StopContainer stops a running container.
func (m *Manager) StopContainer(ctx context.Context, containerID string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	stopURL := fmt.Sprintf("http://localhost/v1.54/containers/%s/stop", containerID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, stopURL, nil)
	if err != nil {
		return err
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("stop container: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotModified {
		// 304 means already stopped — that's fine
		if resp.StatusCode == http.StatusNotModified {
			return nil
		}
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("stop container failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// RemoveContainer removes a container (force if running).
func (m *Manager) RemoveContainer(ctx context.Context, containerID string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	removeURL := fmt.Sprintf("http://localhost/v1.54/containers/%s?force=true&v=true", containerID)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, removeURL, nil)
	if err != nil {
		return err
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("remove container: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("remove container failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// InspectContainer gets container details.
func (m *Manager) InspectContainer(ctx context.Context, containerID string) (*Container, error) {
	_, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	inspectURL := fmt.Sprintf("http://localhost/v1.54/containers/%s/json", containerID)
	resp, err := m.httpClient.Get(inspectURL)
	if err != nil {
		return nil, fmt.Errorf("inspect container: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("inspect container failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var inspectResp struct {
		ID    string `json:"Id"`
		Name  string `json:"Name"`
		Image string `json:"Image"`
		State struct {
			Status   string `json:"Status"`
			Running  bool   `json:"Running"`
			ExitCode int    `json:"ExitCode"`
			Error    string `json:"Error"`
		} `json:"State"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&inspectResp); err != nil {
		return nil, fmt.Errorf("decode inspect: %w", err)
	}

	container := &Container{
		ID:       inspectResp.ID,
		Name:     strings.TrimPrefix(inspectResp.Name, "/"),
		Image:    inspectResp.Image,
		Status:   inspectResp.State.Status,
		Running:  inspectResp.State.Running,
		ExitCode: inspectResp.State.ExitCode,
		Error:    inspectResp.State.Error,
	}

	return container, nil
}

// ListContainers lists all containers (optionally filtered by label).
func (m *Manager) ListContainers(ctx context.Context) ([]Container, error) {
	_, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	listURL := "http://localhost/v1.54/containers/json?all=true"
	resp, err := m.httpClient.Get(listURL)
	if err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("list containers failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var listResp []struct {
		ID    string `json:"Id"`
		Names []string `json:"Names"`
		Image string `json:"Image"`
		State string `json:"State"`
		Ports []struct {
			PrivatePort int    `json:"PrivatePort"`
			PublicPort  int    `json:"PublicPort"`
			Type        string `json:"Type"`
		} `json:"Ports"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return nil, fmt.Errorf("decode list: %w", err)
	}

	containers := make([]Container, 0, len(listResp))
	for _, c := range listResp {
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		ports := make([]string, 0)
		for _, p := range c.Ports {
			ports = append(ports, fmt.Sprintf("%d/%s", p.PrivatePort, p.Type))
		}
		containers = append(containers, Container{
			ID:      c.ID,
			Name:    name,
			Image:   c.Image,
			Status:  c.State,
			Running: c.State == "running",
			Ports:   ports,
		})
	}

	return containers, nil
}

// WaitForContainerExit waits for a container to exit and returns the exit code.
// Uses the Docker Engine API's /containers/{id}/wait endpoint.
func (m *Manager) WaitForContainerExit(ctx context.Context, containerID string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 24*time.Hour)
	defer cancel()

	waitURL := fmt.Sprintf("http://localhost/v1.54/containers/%s/wait", containerID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, waitURL, nil)
	if err != nil {
		return -1, err
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return -1, fmt.Errorf("wait container: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return -1, fmt.Errorf("wait container failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var waitResp struct {
		StatusCode int    `json:"StatusCode"`
		Error      struct {
			Message string `json:"message"`
		} `json:"Error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&waitResp); err != nil {
		return -1, fmt.Errorf("decode wait response: %w", err)
	}

	if waitResp.Error.Message != "" {
		return waitResp.StatusCode, fmt.Errorf("container error: %s", waitResp.Error.Message)
	}

	return waitResp.StatusCode, nil
}

// GetContainerLogs retrieves logs for a container.
func (m *Manager) GetContainerLogs(ctx context.Context, containerID string, tail int) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if tail <= 0 {
		tail = 100
	}
	logsURL := fmt.Sprintf("http://localhost/v1.54/containers/%s/logs?stdout=true&stderr=true&tail=%d", containerID, tail)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, logsURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("get logs: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("get logs failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read logs: %w", err)
	}

	// Docker log stream format: 8 bytes header + data per frame
	// Strip headers for plain text output
	var result bytes.Buffer
	for i := 0; i < len(raw); {
		if i+8 > len(raw) {
			break
		}
		frameSize := int(raw[7]) | int(raw[6])<<8 | int(raw[5])<<16 | int(raw[4])<<24
		i += 8
		if i+frameSize > len(raw) {
			frameSize = len(raw) - i
		}
		if frameSize > 0 {
			result.Write(raw[i : i+frameSize])
			i += frameSize
		} else {
			break
		}
	}

	return result.String(), nil
}

// ── Image Operations ──────────────────────────────────────────────────────────

// pullImage pulls a Docker image.
func (m *Manager) pullImage(ctx context.Context, image string) error {
	// Check if image exists first
	exists, err := m.imageExists(ctx, image)
	if err == nil && exists {
		return nil
	}

	pullURL := fmt.Sprintf("http://localhost/v1.54/images/create?fromImage=%s", image)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, pullURL, nil)
	if err != nil {
		return err
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("pull image: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("pull image failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	// Read the streaming response
	_, _ = io.ReadAll(resp.Body)
	return nil
}

// imageExists checks if an image is available locally.
func (m *Manager) imageExists(ctx context.Context, image string) (bool, error) {
	inspectURL := fmt.Sprintf("http://localhost/v1.54/images/%s/json", image)
	resp, err := m.httpClient.Get(inspectURL)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode == http.StatusOK, nil
}

// ── Network Operations ────────────────────────────────────────────────────────

// ensureNetwork creates the sandbox network if it doesn't exist.
func (m *Manager) ensureNetwork(ctx context.Context) error {
	// Check if network exists
	listURL := fmt.Sprintf("http://localhost/v1.54/networks?filters={\"name\":[\"%s\"]}", m.networkName)
	resp, err := m.httpClient.Get(listURL)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusOK {
		var networks []struct {
			ID   string `json:"Id"`
			Name string `json:"Name"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&networks); err == nil {
			for _, n := range networks {
				if n.Name == m.networkName {
					return nil // already exists
				}
			}
		}
	}

	// Create network
	createReq := map[string]interface{}{
		"Name":   m.networkName,
		"Driver": "bridge",
		"IPAM": map[string]interface{}{
			"Config": []map[string]interface{}{
				{"Subnet": "172.28.0.0/16"},
			},
		},
	}

	body, _ := json.Marshal(createReq)
	createURL := "http://localhost/v1.54/networks/create"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, createURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err = m.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("create network failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// ── SSH Agent Forwarding ──────────────────────────────────────────────────────

// ForwardSSHAgent creates a container with SSH agent socket forwarding.
func (m *Manager) ForwardSSHAgent(ctx context.Context, image string, args []string, envVars []string, sandboxName string) (*Container, error) {
	sshAuthSock := os.Getenv("SSH_AUTH_SOCK")
	if sshAuthSock == "" {
		return m.CreateContainer(ctx, image, args, envVars, sandboxName)
	}

	containerName := fmt.Sprintf("sbx-%s", sandboxName)

	// Read CA certificate
	caPath := os.Getenv("SBXSANDBOX_CA_CERT")
	var caContent string
	if caPath != "" {
		data, err := os.ReadFile(caPath)
		if err == nil {
			caContent = string(data)
		}
	}

	env := []string{
		"HTTP_PROXY=http://host.docker.internal:3128",
		"HTTPS_PROXY=http://host.docker.internal:3128",
		"http_proxy=http://host.docker.internal:3128",
		"https_proxy=http://host.docker.internal:3128",
		"NO_PROXY=localhost,127.0.0.1,.local",
		"no_proxy=localhost,127.0.0.1,.local",
		"SSH_AUTH_SOCK=/tmp/ssh-agent.sock",
	}
	env = append(env, envVars...)

	createReq := map[string]interface{}{
		"Image":      image,
		"Env":        env,
		"Entrypoint": args,
		"HostConfig": map[string]interface{}{
			"NetworkMode": m.networkName,
			"ExtraHosts":  []string{"host.docker.internal:host-gateway"},
			"Privileged":  false,
			"Binds":       []string{sshAuthSock + ":/tmp/ssh-agent.sock"},
		},
	}

	if caContent != "" {
		createReq["Cmd"] = []string{
			"/bin/sh", "-c",
			fmt.Sprintf("mkdir -p /usr/local/share/ca-certificates && echo '%s' > /usr/local/share/ca-certificates/sbx-ca.crt && update-ca-certificates 2>/dev/null || true && exec \"$@\"", caContent),
		}
	}

	body, _ := json.Marshal(createReq)

	createURL := fmt.Sprintf("http://localhost/v1.54/containers/create?name=%s", containerName)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, createURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("create container with SSH: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("create container failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var createResp struct {
		ID       string   `json:"Id"`
		Warnings []string `json:"Warnings"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&createResp); err != nil {
		return nil, fmt.Errorf("decode create response: %w", err)
	}

	container := &Container{
		ID:      createResp.ID,
		Name:    containerName,
		Image:   image,
		Sandbox: sandboxName,
		Status:  "created",
	}

	return container, nil
}

// ── Hostname Resolution ───────────────────────────────────────────────────────

// ResolveHostIP resolves the host machine's IP address inside the container network.
func ResolveHostIP() string {
	// Try common Docker host IPs
	hosts := []string{
		"host.docker.internal",
		"172.17.0.1",   // default bridge
		"172.28.0.1",   // sandbox bridge
	}

	for _, host := range hosts {
		addrs, err := net.LookupHost(host)
		if err == nil && len(addrs) > 0 {
			return addrs[0]
		}
	}
	return "host.docker.internal"
}

// EnsureDataDir creates the data directory for container state files.
func EnsureDataDir(dataDir string) error {
	if dataDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("get home dir: %w", err)
		}
		dataDir = filepath.Join(home, ".local", "share", "sbxsandbox")
	}
	return os.MkdirAll(dataDir, 0755)
}

// ── Utility (moved from cmdutil to avoid cycle) ────────────────────────────────

// execCmd is a shorthand for cmdutil.RunCmd.
// Used by other methods in this package.
var _ = cmdutil.RunCmd // Ensure cmdutil is imported

// setRequestBody sets the body of a request from bytes and resets ContentLength.
func SetRequestBody(r *http.Request, body []byte) {
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
}

// parseHostPort splits a host:port string.
func ParseHostPort(hostPort string) (host, port string) {
	if idx := strings.LastIndex(hostPort, ":"); idx >= 0 {
		return hostPort[:idx], hostPort[idx+1:]
	}
	return hostPort, "80"
}

// decodeBase64Header decodes a base64-encoded header value.
func DecodeBase64Header(encoded string) string {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return encoded
	}
	return string(decoded)
}

// isClosedConnError checks if an error is a closed connection error.
func IsClosedConnError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "use of closed network connection") ||
		strings.Contains(s, "broken pipe") ||
		strings.Contains(s, "connection reset") ||
		strings.Contains(s, "http: Server closed")
}
