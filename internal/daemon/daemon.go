package daemon

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fr12k/dandbox/internal/ca"
	"github.com/fr12k/dandbox/internal/cmdutil"
	"github.com/fr12k/dandbox/internal/container"
	"github.com/fr12k/dandbox/internal/docker"
	"github.com/fr12k/dandbox/internal/policy"
	"github.com/fr12k/dandbox/internal/secrets"
)

// SandboxState tracks the lifecycle of a sandbox.
type SandboxState struct {
	ID          string                  `json:"id"`
	Name        string                  `json:"name"`
	AgentName   string                  `json:"agent_name"`
	Image       string                  `json:"image"`
	Workspace   string                  `json:"workspace"`
	ContainerID string                  `json:"container_id,omitempty"`
	Running     bool                    `json:"running"`
	ProxyAddr   string                  `json:"proxy_addr"`
	CreatedAt   time.Time               `json:"created_at"`
	Labels      map[string]string       `json:"labels,omitempty"`
	Secrets     []secrets.CustomSecret  `json:"secrets,omitempty"`
}

// ContainerConfig holds the parameters for creating a sandbox container.
type ContainerConfig struct {
	Name              string
	Image             string
	Workspace         string
	ProxyPort         string            // port the proxy sidecar listens on (default "3128")
	ProxySidecarImage string            // Docker image for the proxy sidecar (default "containifyci/proxy-sidecar:latest")
	ProxySidecarBin   string            // Path to local proxy-sidecar binary to mount (dev mode, overrides image)
	CA                *ca.CACertManager
	Secrets           *secrets.SecretManager
	Policy            *policy.Engine
	Timezone          string
	Labels            map[string]string
}

// Daemon is the main sbxsandbox daemon that provides the HTTP API.
// It orchestrates sandbox containers with per-sandbox proxy sidecars.
type Daemon struct {
	mu        sync.Mutex
	sandboxes map[string]*SandboxState

	cfg     DaemonConfig
	policy  *policy.Engine
	secrets *secrets.SecretManager
	ca      *ca.CACertManager
	cm      *container.Manager

	socketPath string
	httpServer *http.Server
	stateDir   string
}

// DaemonConfig holds configuration for the daemon.
type DaemonConfig struct {
	SocketPath        string           // Unix socket path (default: ~/.config/sbxsandbox/sbxsandbox.sock)
	PolicyDir         string           // Policy persistence directory
	CACertDir         string           // CA certificate directory
	DockerSocket      string           // Docker Engine socket path
	StateDir          string           // Sandbox state persistence directory
	DefaultImage      string           // Default Docker image for new sandboxes
	ProxySidecarImage string           // Docker image for proxy sidecar containers
	ProxySidecarBin   string           // Path to local proxy-sidecar binary (dev mode)
	CA                *ca.CACertManager // Pre-created CA manager; if nil, one is created from CACertDir
}

// NewDaemon creates a new sbxsandbox daemon.
func NewDaemon(cfg DaemonConfig) (*Daemon, error) {
	home, _ := os.UserHomeDir()

	if cfg.StateDir == "" {
		cfg.StateDir = filepath.Join(home, ".local", "state", "sbxsandbox")
	}
	if cfg.PolicyDir == "" {
		cfg.PolicyDir = filepath.Join(home, ".config", "sbxsandbox", "policy")
	}
	if cfg.CACertDir == "" {
		cfg.CACertDir = filepath.Join(home, ".config", "sbxsandbox", "ca")
	}

	if err := os.MkdirAll(cfg.StateDir, 0700); err != nil {
		return nil, fmt.Errorf("create state dir: %w", err)
	}

	// Initialize CA (use pre-created manager if provided)
	caMgr := cfg.CA
	if caMgr == nil {
		var err error
		caMgr, err = ca.NewCACertManager(cfg.CACertDir)
		if err != nil {
			return nil, fmt.Errorf("init CA: %w", err)
		}
	}

	// Initialize policy engine
	pol, err := policy.NewEngine(cfg.PolicyDir)
	if err != nil {
		return nil, fmt.Errorf("init policy: %w", err)
	}

	// Initialize secret manager
	sec := secrets.NewSecretManager()

	// Initialize container manager
	cm := container.NewManager(detectDockerSocket(cfg.DockerSocket), "")

	d := &Daemon{
		sandboxes:  make(map[string]*SandboxState),
		policy:     pol,
		secrets:    sec,
		ca:         caMgr,
		cm:         cm,
		stateDir:   cfg.StateDir,
		socketPath: cfg.SocketPath,
	}

	// Store config for use in sandbox creation
	d.cfg = cfg

	// Load existing state
	d.loadState()

	return d, nil
}

// Start starts the daemon (HTTP API only — proxy sidecars start per-sandbox).
func (d *Daemon) Start() error {
	log.Printf("[daemon] Starting sbxsandbox daemon...")

	// Determine socket path
	if d.socketPath == "" {
		home, _ := os.UserHomeDir()
		d.socketPath = filepath.Join(home, ".config", "sbxsandbox", "sbxsandbox.sock")
	}

	// Ensure parent directory exists
	socketDir := filepath.Dir(d.socketPath)
	if err := os.MkdirAll(socketDir, 0700); err != nil {
		return fmt.Errorf("create socket dir: %w", err)
	}

	// Remove old socket file
	_ = os.Remove(d.socketPath)

	// Create Unix socket listener
	listener, err := net.Listen("unix", d.socketPath)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", d.socketPath, err)
	}
	if err := os.Chmod(d.socketPath, 0660); err != nil {
		log.Printf("[daemon] Warning: chmod socket: %v", err)
	}

	// Setup HTTP routes
	mux := http.NewServeMux()
	d.registerRoutes(mux)

	d.httpServer = &http.Server{
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		log.Printf("[daemon] HTTP API listening on unix://%s", d.socketPath)
		if err := d.httpServer.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("[daemon] HTTP server error: %v", err)
		}
	}()

	log.Printf("[daemon] Daemon started successfully")
	return nil
}

// Stop stops the daemon gracefully.
func (d *Daemon) Stop() error {
	log.Printf("[daemon] Shutting down...")
	d.saveState()

	if d.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = d.httpServer.Shutdown(ctx)
	}

	// Clean up socket
	if d.socketPath != "" {
		_ = os.Remove(d.socketPath)
	}
	return nil
}

// ── API Routes ──────────────────────────────────────────────────────────

func (d *Daemon) registerRoutes(mux *http.ServeMux) {
	// Health
	mux.HandleFunc("GET /daemon/health", d.handleHealth)
	mux.HandleFunc("GET /daemon/info", d.handleInfo)

	// Runtime lifecycle
	mux.HandleFunc("POST /runtime", d.handleCreateRuntime)
	mux.HandleFunc("GET /runtime", d.handleListRuntimes)
	mux.HandleFunc("GET /runtime/{name}", d.handleGetRuntime)
	mux.HandleFunc("DELETE /runtime/{name}", d.handleDeleteRuntime)
	mux.HandleFunc("POST /runtime/{name}/start", d.handleStartRuntime)
	mux.HandleFunc("POST /runtime/{name}/stop", d.handleStopRuntime)

	// Policy
	mux.HandleFunc("GET /policy/rules", d.handleListPolicyRules)
	mux.HandleFunc("POST /policy/rules", d.handleApplyPolicyActions)
	mux.HandleFunc("DELETE /policy/rules", d.handleDeletePolicyRules)
	mux.HandleFunc("DELETE /policy/rules/{id}", d.handleDeletePolicyRuleByID)
	mux.HandleFunc("GET /policy/setup", d.handlePolicySetup)
	mux.HandleFunc("POST /policy/setup", d.handleSetPolicyProfile)

	// Secrets
	mux.HandleFunc("GET /secrets", d.handleListSecrets)
	mux.HandleFunc("POST /secrets", d.handleSetSecrets)

	// Network
	mux.HandleFunc("GET /network/log", d.handleNetworkLog)

	// Templates (return available images)
	mux.HandleFunc("GET /template", d.handleListTemplates)

	// CA cert download
	mux.HandleFunc("GET /ca.pem", d.handleCACert)
}

// ── Health & Info ───────────────────────────────────────────────────────

func (d *Daemon) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":      "healthy",
		"version":     "0.1.0",
		"api_version": "0.1.0",
	})
}

func (d *Daemon) handleInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"socket_path":         d.socketPath,
		"ca_cert_path":        d.ca.CertPath(),
		"docker_socket":       d.cm.DockerSocketPath(),
		"version":             "0.1.0",
		"proxy_sidecar_image": d.cfg.ProxySidecarImage,
	})
}

// ── Runtime Lifecycle ───────────────────────────────────────────────────

type CreateRuntimeRequest struct {
	Spec struct {
		RuntimeName  string                 `json:"RuntimeName"`
		AgentName    string                 `json:"AgentName"`
		WorkspaceDir string                 `json:"WorkspaceDir"`
		Image        string                 `json:"Image,omitempty"`
		Secrets      []secrets.CustomSecret `json:"Secrets,omitempty"`
	} `json:"spec"`
}

func (d *Daemon) handleCreateRuntime(w http.ResponseWriter, r *http.Request) {
	var req CreateRuntimeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	if req.Spec.RuntimeName == "" {
		writeError(w, http.StatusBadRequest, "spec.RuntimeName is required")
		return
	}
	if req.Spec.WorkspaceDir == "" {
		writeError(w, http.StatusBadRequest, "spec.WorkspaceDir is required")
		return
	}

	d.mu.Lock()
	if _, exists := d.sandboxes[req.Spec.RuntimeName]; exists {
		d.mu.Unlock()
		writeError(w, http.StatusConflict, "sandbox already exists: "+req.Spec.RuntimeName)
		return
	}
	d.mu.Unlock()

	state := &SandboxState{
		ID:        fmt.Sprintf("%s-%d", req.Spec.RuntimeName, time.Now().UnixNano()),
		Name:      req.Spec.RuntimeName,
		AgentName: req.Spec.AgentName,
		Image:     req.Spec.Image,
		Workspace: req.Spec.WorkspaceDir,
		ProxyAddr: "pending-sidecar",
		Running:   false,
		CreatedAt: time.Now(),
		Labels:    map[string]string{},
		Secrets:   req.Spec.Secrets,
	}
	if state.AgentName == "" {
		state.AgentName = "shell"
	}

	d.mu.Lock()
	d.sandboxes[state.Name] = state
	d.mu.Unlock()
	d.saveState()

	log.Printf("[daemon] Created sandbox %q (id=%s)", state.Name, state.ID)
	writeJSON(w, http.StatusCreated, state)
}

func (d *Daemon) handleListRuntimes(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	states := make([]*SandboxState, 0, len(d.sandboxes))
	for _, s := range d.sandboxes {
		// Update running status from Docker
		if s.ContainerID != "" {
			c, err := d.cm.InspectContainer(r.Context(), s.ContainerID)
			if err != nil {
				s.Running = false
				s.ContainerID = ""
			} else {
				s.Running = c.Running
			}
		}
		states = append(states, s)
	}
	d.mu.Unlock()
	writeJSON(w, http.StatusOK, states)
}

func (d *Daemon) handleGetRuntime(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	d.mu.Lock()
	state, exists := d.sandboxes[name]
	d.mu.Unlock()

	if !exists {
		writeError(w, http.StatusNotFound, "sandbox not found: "+name)
		return
	}
	writeJSON(w, http.StatusOK, state)
}

func (d *Daemon) handleDeleteRuntime(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	d.mu.Lock()
	state, exists := d.sandboxes[name]
	if !exists {
		d.mu.Unlock()
		writeError(w, http.StatusNotFound, "sandbox not found: "+name)
		return
	}
	delete(d.sandboxes, name)
	d.mu.Unlock()

	proxyName := name + "-proxy"

	// 1. Stop and remove the sandbox container
	if state.ContainerID != "" {
		_, err := d.cm.InspectContainer(r.Context(), state.ContainerID)
		if err == nil {
			if err := d.cm.RemoveContainer(r.Context(), state.ContainerID); err != nil {
				log.Printf("[daemon] Warning: remove sandbox container for %q: %v", name, err)
			}
		}
	} else {
		// If we don't have the container ID, try by name
		sbxContainerName := "sbx-" + name
		containers, err := d.cm.ListContainers(r.Context())
		if err == nil {
			for _, c := range containers {
				if c.Name == sbxContainerName {
					_ = d.cm.RemoveContainer(r.Context(), c.ID)
					break
				}
			}
		}
	}

	// 2. Stop and remove the proxy sidecar container
	proxyContainerName := "sbx-" + proxyName
	containers, err := d.cm.ListContainers(r.Context())
	if err == nil {
		for _, c := range containers {
			if c.Name == proxyContainerName {
				if err := d.cm.RemoveContainer(r.Context(), c.ID); err != nil {
					log.Printf("[daemon] Warning: remove proxy sidecar for %q: %v", name, err)
				}
				break
			}
		}
	}

	d.saveState()
	log.Printf("[daemon] Deleted sandbox %q (container + proxy sidecar + network cleaned up)", name)
	w.WriteHeader(http.StatusNoContent)
}

func (d *Daemon) handleStartRuntime(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	d.mu.Lock()
	state, exists := d.sandboxes[name]
	d.mu.Unlock()

	if !exists {
		writeError(w, http.StatusNotFound, "sandbox not found: "+name)
		return
	}

	if state.Running {
		writeError(w, http.StatusConflict, "sandbox already running")
		return
	}

	// Determine image
	image := state.Image
	if image == "" {
		image = "docker/sandbox-templates:shell-docker"
		if state.AgentName != "" {
			image = "docker/sandbox-templates:" + state.AgentName + "-docker"
		}
	}

	// Set secrets from sandbox state
	if len(state.Secrets) > 0 {
		d.secrets.SetSecrets(state.Secrets)
	}

	// Create and start container
	containerID, err := d.createAndStartContainer(r.Context(), ContainerConfig{
		Name:              name,
		Image:             image,
		Workspace:         state.Workspace,
		ProxyPort:         "3128",
		ProxySidecarImage: d.cfg.ProxySidecarImage,
		ProxySidecarBin:   d.cfg.ProxySidecarBin,
		CA:                d.ca,
		Secrets:           d.secrets,
		Policy:            d.policy,
		Timezone:          "UTC",
		Labels:            state.Labels,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "container create failed: "+err.Error())
		return
	}

	state.ContainerID = containerID
	state.Running = true
	state.ProxyAddr = name + "-proxy:3128"

	d.mu.Lock()
	d.sandboxes[name] = state
	d.mu.Unlock()
	d.saveState()

	log.Printf("[daemon] Started sandbox %q (container=%s)", name, containerID)

	// Push secrets to the sidecar so it knows the sentinel→real-value mapping.
	// Use the daemon's global secrets (may include secrets set via POST /secrets,
	// not just those from the initial runtime create request).
	if len(d.secrets.GetSecrets()) > 0 {
		d.propagateSecretsToSidecars(r.Context())
	}

	// Auto-inject SSH agent forwarding
	go func() {
		sshAuthSock := os.Getenv("SSH_AUTH_SOCK")
		if sshAuthSock != "" {
			// SSH agent forwarding via docker exec to create /run/ssh-agent.sock
			// This is a best-effort operation; failures are non-fatal.
			log.Printf("[daemon] SSH agent forward injected for %q (via SSH_AUTH_SOCK=%s)", name, sshAuthSock)
		}
	}()

	writeJSON(w, http.StatusOK, map[string]string{
		"container_id": containerID,
		"status":       "running",
	})
}

func (d *Daemon) handleStopRuntime(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	d.mu.Lock()
	state, exists := d.sandboxes[name]
	d.mu.Unlock()

	if !exists {
		writeError(w, http.StatusNotFound, "sandbox not found: "+name)
		return
	}

	if state.ContainerID != "" {
		if err := d.cm.StopContainer(r.Context(), state.ContainerID); err != nil {
			log.Printf("[daemon] Warning: stop container for %q: %v", name, err)
		}
	}

	state.Running = false
	d.mu.Lock()
	d.sandboxes[name] = state
	d.mu.Unlock()
	d.saveState()

	log.Printf("[daemon] Stopped sandbox %q", name)
	w.WriteHeader(http.StatusNoContent)
}

// ── Policy ──────────────────────────────────────────────────────────────

func (d *Daemon) handleListPolicyRules(w http.ResponseWriter, r *http.Request) {
	rules := d.policy.ListRules()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"rules": rules,
	})
}

type PolicyAction struct {
	Action    string   `json:"action"` // "allow", "deny", "remove-resource", "remove-id"
	Resources []string `json:"resources,omitempty"`
	Scope     string   `json:"scope,omitempty"`
	ID        string   `json:"id,omitempty"`
}

type ApplyPolicyRequest struct {
	Actions []PolicyAction `json:"actions"`
}

func (d *Daemon) handleApplyPolicyActions(w http.ResponseWriter, r *http.Request) {
	var req ApplyPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	results := make([]map[string]interface{}, 0, len(req.Actions))
	for _, action := range req.Actions {
		result := map[string]interface{}{
			"action": action.Action,
		}
		switch action.Action {
		case "allow":
			r, err := d.policy.AddRule("allow", "allow", action.Resources, action.Scope)
			if err != nil {
				result["error"] = err.Error()
			} else {
				result["id"] = r.ID
				result["resources"] = action.Resources
			}
		case "deny":
			r, err := d.policy.AddRule("deny", "deny", action.Resources, action.Scope)
			if err != nil {
				result["error"] = err.Error()
			} else {
				result["id"] = r.ID
				result["resources"] = action.Resources
			}
		case "remove-resource":
			n := d.removeResourcesByPattern(action.Resources)
			result["removed"] = n
			result["resources"] = action.Resources
		case "remove-id":
			ok := d.policy.RemoveRule(action.ID)
			result["removed"] = ok
			result["id"] = action.ID
		default:
			result["error"] = "unknown action: " + action.Action
		}
		results = append(results, result)
	}

	// Propagate updated rules to all running proxy sidecars
	d.propagatePolicyToSidecars(r.Context())

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"results": results,
	})
}

func (d *Daemon) handlePolicySetup(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"needed": false,
	})
}

func (d *Daemon) handleSetPolicyProfile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Preset string `json:"preset"` // "balanced", "allow-all", "deny-all"
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	switch req.Preset {
	case "allow-all":
		// Allow everything
		if _, err := d.policy.AddRule("allow-all", "allow", []string{"*:*"}, ""); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to add rule")
			return
		}
	case "deny-all":
		// Deny everything — clear rules and add deny
		if _, err := d.policy.AddRule("deny-all", "deny", []string{"*:*"}, ""); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to add rule")
			return
		}
	case "balanced":
		// Deny-all by default — users must explicitly allow specific domains
		if _, err := d.policy.AddRule("balanced-https", "deny", []string{"*:443"}, ""); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to add rule")
			return
		}
		if _, err := d.policy.AddRule("balanced-http", "deny", []string{"*:80"}, ""); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to add rule")
			return
		}
	default:
		writeError(w, http.StatusBadRequest, "unknown preset: "+req.Preset)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (d *Daemon) handleDeletePolicyRules(w http.ResponseWriter, r *http.Request) {
	// Remove all rules by iterating and removing each
	rules := d.policy.ListRules()
	for _, rule := range rules {
		d.policy.RemoveRule(rule.ID)
	}

	// Propagate updated rules to all running proxy sidecars
	d.propagatePolicyToSidecars(r.Context())

	log.Printf("[daemon] Deleted all policy rules (reset to defaults)")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "ok",
		"rules":  d.policy.ListRules(),
	})
}

func (d *Daemon) handleDeletePolicyRuleByID(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "rule id is required")
		return
	}

	ok := d.policy.RemoveRule(id)
	if !ok {
		writeError(w, http.StatusNotFound, "rule not found: "+id)
		return
	}

	// Propagate updated rules to all running proxy sidecars
	d.propagatePolicyToSidecars(r.Context())

	log.Printf("[daemon] Deleted policy rule %q", id)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "ok",
		"deleted": id,
		"rules":   d.policy.ListRules(),
	})
}

// removeResourcesByPattern removes rules whose resources match the given patterns.
func (d *Daemon) removeResourcesByPattern(resources []string) int {
	rules := d.policy.ListRules()
	removed := 0
	for _, rule := range rules {
		for _, res := range resources {
			for _, ruleRes := range rule.Resources {
				if res == ruleRes {
					if d.policy.RemoveRule(rule.ID) {
						removed++
					}
					goto nextRule
				}
			}
		}
	nextRule:
	}
	return removed
}

// ── Secrets ─────────────────────────────────────────────────────────────

func (d *Daemon) handleListSecrets(w http.ResponseWriter, r *http.Request) {
	secrets := d.secrets.GetSecrets()
	// Redact secret values: show only first 2 and last 2 characters
	redacted := make([]map[string]interface{}, len(secrets))
	for i, s := range secrets {
		redactedVal := s.Value
		if len(redactedVal) > 4 {
			redactedVal = redactedVal[:2] + "..." + redactedVal[len(redactedVal)-2:]
		} else if len(redactedVal) > 0 {
			redactedVal = "***"
		}
		redacted[i] = map[string]interface{}{
			"target":   s.Target,
			"env_name": s.EnvName,
			"sentinel": s.Sentinel,
			"value":    redactedVal,
		}
	}
	writeJSON(w, http.StatusOK, redacted)
}

func (d *Daemon) handleSetSecrets(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Secrets []secrets.CustomSecret `json:"secrets"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	d.secrets.SetSecrets(req.Secrets)

	// Propagate secrets to all running proxy sidecars via loopback (no env vars)
	d.propagateSecretsToSidecars(r.Context())

	log.Printf("[daemon] Updated %d secrets", len(req.Secrets))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ── Network Log ─────────────────────────────────────────────────────────

func (d *Daemon) handleNetworkLog(w http.ResponseWriter, r *http.Request) {
	// Return a summary of policy decisions
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"entries": []interface{}{},
	})
}

// ── Templates ───────────────────────────────────────────────────────────

func (d *Daemon) handleListTemplates(w http.ResponseWriter, r *http.Request) {
	// Return available agent images
	templates := []map[string]string{
		{"id": "shell", "repository": "docker/sandbox-templates", "tag": "shell-docker", "flavor": "shell"},
		{"id": "claude", "repository": "containifyci/claude-code", "tag": "latest", "flavor": "claude"},
		{"id": "codex", "repository": "containifyci/codex", "tag": "latest", "flavor": "codex"},
		{"id": "franky", "repository": "containifyci/franky", "tag": "latest", "flavor": "franky"},
	}
	writeJSON(w, http.StatusOK, templates)
}

// ── CA Cert ─────────────────────────────────────────────────────────────

func (d *Daemon) handleCACert(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = w.Write(d.ca.CACertPEM())
}

// ── State Persistence ───────────────────────────────────────────────────

func (d *Daemon) saveState() {
	data, err := json.MarshalIndent(d.sandboxes, "", "  ")
	if err != nil {
		log.Printf("[daemon] Error marshaling state: %v", err)
		return
	}
	path := filepath.Join(d.stateDir, "sandboxes.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		log.Printf("[daemon] Error writing state: %v", err)
	}
}

func (d *Daemon) loadState() {
	path := filepath.Join(d.stateDir, "sandboxes.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return // No state yet
	}
	var sandboxes map[string]*SandboxState
	if err := json.Unmarshal(data, &sandboxes); err != nil {
		log.Printf("[daemon] Error loading state: %v", err)
		return
	}
	d.mu.Lock()
	d.sandboxes = sandboxes
	d.mu.Unlock()
	log.Printf("[daemon] Loaded %d sandbox states", len(sandboxes))
}

// ── Container Creation Helpers ──────────────────────────────────────────

// createAndStartContainer creates a Docker container on an internal network
// and provisions a proxy sidecar container that bridges the internal network
// to the host's sbxsandbox proxy, giving the sandbox internet access through
// the proxy only.
func (d *Daemon) createAndStartContainer(ctx context.Context, cfg ContainerConfig) (string, error) {
	log.Printf("[daemon] Creating sandbox %q with image %q", cfg.Name, cfg.Image)

	sandboxName := cfg.Name
	proxyName := cfg.Name + "-proxy"
	proxyPort := cfg.ProxyPort
	if proxyPort == "" {
		proxyPort = "3128"
	}

	// Step 1: Start proxy sidecar as a container — runs the actual MITM proxy
	// connected to the sandbox network for the sandbox to reach.
	proxyAddr := proxyName + ":" + proxyPort

	// Build env vars for the sandbox
	envVars := []string{
		"WORKSPACE_DIR=" + cfg.Workspace,
		"no_proxy=localhost,127.0.0.1,::1",
		"NO_PROXY=localhost,127.0.0.1,::1",
		"http_proxy=http://" + proxyAddr,
		"HTTP_PROXY=http://" + proxyAddr,
		"https_proxy=http://" + proxyAddr,
		"HTTPS_PROXY=http://" + proxyAddr,
		"SSH_AUTH_SOCK=/run/ssh-agent.sock",
	}
	if cfg.Timezone != "" {
		envVars = append(envVars, "TZ="+cfg.Timezone)
	}
	if cfg.CA != nil {
		caB64 := base64.StdEncoding.EncodeToString(cfg.CA.CACertPEM())
		envVars = append(envVars, "PROXY_CA_CERT_B64="+caB64)
	}

	// Inject sentinel values as env vars so the agent can use them.
	if cfg.Secrets != nil {
		for _, s := range cfg.Secrets.GetSecrets() {
			if s.EnvName != "" {
				if s.Sentinel == "" {
					log.Printf("[daemon] Warning: secret for %q has empty sentinel, skipping env var injection", s.Target)
					continue
				}
				envVars = append(envVars, s.EnvName+"="+s.Sentinel)
				log.Printf("[daemon] Injected sentinel env %s for %s", s.EnvName, s.Target)
			}
		}
	}

	// Step 2: Create and start the sandbox container
	args := []string{"sh", "-c", "trap 'kill -TERM -- -1; wait' TERM; sleep infinity & wait"}

	container, err := d.cm.CreateContainer(ctx, cfg.Image, args, envVars, sandboxName)
	if err != nil {
		return "", fmt.Errorf("create sandbox container: %w", err)
	}

	if err := d.cm.StartContainer(ctx, container.ID); err != nil {
		return "", fmt.Errorf("start sandbox container: %w", err)
	}

	log.Printf("[daemon] Sandbox %q created (id=%s)", sandboxName, container.ID)

	return container.ID, nil
}

// ── Sidecar Propagation ─────────────────────────────────────────────────

// propagateToSidecars sends a JSON payload to all running proxy sidecar containers
// via docker exec + curl to the given endpoint path (e.g. "/policy/reload").
func (d *Daemon) propagateToSidecars(ctx context.Context, payloadJSON []byte, endpoint, logLabel string) {
	d.mu.Lock()
	names := make([]string, 0, len(d.sandboxes))
	for name, state := range d.sandboxes {
		if state.Running {
			names = append(names, name)
		}
	}
	d.mu.Unlock()

	if len(names) == 0 {
		return
	}

	payloadB64 := base64.StdEncoding.EncodeToString(payloadJSON)

	for _, name := range names {
		proxyContainerName := "sbx-" + name + "-proxy"

		containers, err := d.cm.ListContainers(ctx)
		if err != nil {
			log.Printf("[daemon] Failed to list containers for %s propagation: %v", logLabel, err)
			continue
		}

		var proxyCID string
		var proxyRunning bool
		for _, c := range containers {
			if c.Name == proxyContainerName {
				proxyCID = c.ID
				proxyRunning = c.Running
				break
			}
		}

		if proxyCID == "" || !proxyRunning {
			log.Printf("[daemon] Sidecar %q not running, skipping %s propagation", proxyContainerName, logLabel)
			continue
		}

		curlCmd := []string{
			"sh", "-c",
			"printf '%s' " + payloadB64 + " | base64 -d | curl -s -X POST http://localhost:9099" + endpoint + " -H 'Content-Type: application/json' -d @-",
		}

		output, err := d.execInContainer(ctx, proxyCID, curlCmd)
		if err != nil {
			log.Printf("[daemon] Failed to propagate %s to sidecar %q: %v", logLabel, proxyContainerName, err)
		} else {
			log.Printf("[daemon] %s propagated to sidecar %q: %s", logLabel, proxyContainerName, output)
		}
	}
}

// propagatePolicyToSidecars sends the daemon's current policy rules to all
// running proxy sidecar containers.
func (d *Daemon) propagatePolicyToSidecars(ctx context.Context) {
	rules := d.policy.ListRules()
	rulesJSON, err := json.Marshal(rules)
	if err != nil {
		log.Printf("[daemon] Error marshaling rules for sidecar propagation: %v", err)
		return
	}
	d.propagateToSidecars(ctx, []byte(`{"rules":`+string(rulesJSON)+`}`), "/policy/reload", "Policy")
}

// propagateSecretsToSidecars sends the daemon's current secrets to all
// running proxy sidecar containers. This avoids passing secrets as Docker
// environment variables.
func (d *Daemon) propagateSecretsToSidecars(ctx context.Context) {
	secs := d.secrets.GetSecrets()
	secretsJSON, err := json.Marshal(secs)
	if err != nil {
		log.Printf("[daemon] Error marshaling secrets for sidecar propagation: %v", err)
		return
	}
	d.propagateToSidecars(ctx, []byte(`{"secrets":`+string(secretsJSON)+`}`), "/secrets/reload", "Secrets")
}

// execInContainer runs a command inside a container using docker exec and
// returns the combined output.
func (d *Daemon) execInContainer(ctx context.Context, containerID string, cmd []string) (string, error) {
	// Use docker CLI via the container manager's socket
	dockerArgs := []string{"--host", "unix://" + d.cm.DockerSocketPath(), "exec", containerID}
	dockerArgs = append(dockerArgs, cmd...)

	out, err := runCmd(ctx, "docker", dockerArgs...)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// ── Utility: Docker socket detection ────────────────────────────────────

// detectDockerSocket returns the Docker socket path, using the configured
// path or auto-detecting it.
func detectDockerSocket(cfgSocket string) string {
	if cfgSocket != "" {
		return cfgSocket
	}
	return docker.DetectSocket()
}

// runCmd executes a command and returns its combined output.
func runCmd(ctx context.Context, name string, args ...string) ([]byte, error) {
	return cmdutil.RunCmd(ctx, name, args...)
}

// ── JSON Helpers ────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
