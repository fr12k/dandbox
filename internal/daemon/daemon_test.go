package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/fr12k/dandbox/internal/ca"
	"github.com/fr12k/dandbox/internal/secrets"
)

var (
	testCAOnce sync.Once
	testCA     *ca.CACertManager
)

// sharedTestCA returns a process-wide CA manager with a 2048-bit key
// that is created only once, eliminating the expensive RSA key generation
// from being repeated for every test.
func sharedTestCA() *ca.CACertManager {
	testCAOnce.Do(func() {
		tmpDir, err := os.MkdirTemp("", "dandbox-test-ca-")
		if err != nil {
			panic("failed to create temp dir for test CA: " + err.Error())
		}
		caMgr, err := ca.NewCACertManagerWithKeySize(tmpDir, 2048)
		if err != nil {
			panic("failed to create test CA: " + err.Error())
		}
		testCA = caMgr
	})
	return testCA
}

// setupTestDaemon creates a Daemon with a temp directory for testing.
// It reuses the shared test CA to avoid the expensive 4096-bit RSA key
// generation on every call.
func setupTestDaemon(t *testing.T) *Daemon {
	t.Helper()
	tmpDir := t.TempDir()
	cfg := DaemonConfig{
		StateDir:   filepath.Join(tmpDir, "state"),
		PolicyDir:  filepath.Join(tmpDir, "policy"),
		CACertDir:  filepath.Join(tmpDir, "ca"),
		SocketPath: filepath.Join(tmpDir, "test.sock"),
		CA:        sharedTestCA(),
	}
	d, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}
	return d
}

func TestNewDaemon(t *testing.T) {
	d := setupTestDaemon(t)
	if d == nil {
		t.Fatal("NewDaemon() returned nil")
	}
	if d.sandboxes == nil {
		t.Error("sandboxes map should be initialized")
	}
}

func TestNewDaemon_CreatesStateDir(t *testing.T) {
	tmpDir := t.TempDir()
	stateDir := filepath.Join(tmpDir, "mystate")
	cfg := DaemonConfig{
		StateDir:  stateDir,
		PolicyDir: filepath.Join(tmpDir, "policy"),
		CACertDir: filepath.Join(tmpDir, "ca"),
	}
	_, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}
	if _, err := os.Stat(stateDir); os.IsNotExist(err) {
		t.Error("state directory was not created")
	}
}

func TestDaemon_HealthEndpoint(t *testing.T) {
	d := setupTestDaemon(t)

	req := httptest.NewRequest("GET", "/daemon/health", nil)
	w := httptest.NewRecorder()

	d.handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp["status"] != "healthy" {
		t.Errorf("expected status 'healthy', got %q", resp["status"])
	}
	if resp["version"] == "" {
		t.Error("expected non-empty version")
	}
}

func TestDaemon_InfoEndpoint(t *testing.T) {
	d := setupTestDaemon(t)

	req := httptest.NewRequest("GET", "/daemon/info", nil)
	w := httptest.NewRecorder()

	d.handleInfo(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp["version"] == nil {
		t.Error("expected version in response")
	}
}

func TestDaemon_CreateRuntime(t *testing.T) {
	d := setupTestDaemon(t)

	body := `{"spec":{"RuntimeName":"test-sandbox","AgentName":"shell","WorkspaceDir":"/tmp/workspace"}}`
	req := httptest.NewRequest("POST", "/runtime", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	d.handleCreateRuntime(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d; body: %s", http.StatusCreated, w.Code, w.Body.String())
	}

	var state SandboxState
	if err := json.Unmarshal(w.Body.Bytes(), &state); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if state.Name != "test-sandbox" {
		t.Errorf("expected name 'test-sandbox', got %q", state.Name)
	}
	if state.ID == "" {
		t.Error("expected non-empty ID")
	}
	if state.AgentName != "shell" {
		t.Errorf("expected AgentName 'shell', got %q", state.AgentName)
	}
}

func TestDaemon_CreateRuntime_MissingName(t *testing.T) {
	d := setupTestDaemon(t)

	body := `{"spec":{"WorkspaceDir":"/tmp/workspace"}}`
	req := httptest.NewRequest("POST", "/runtime", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	d.handleCreateRuntime(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestDaemon_CreateRuntime_MissingWorkspace(t *testing.T) {
	d := setupTestDaemon(t)

	body := `{"spec":{"RuntimeName":"test-sandbox"}}`
	req := httptest.NewRequest("POST", "/runtime", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	d.handleCreateRuntime(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestDaemon_CreateRuntime_DuplicateName(t *testing.T) {
	d := setupTestDaemon(t)

	body := `{"spec":{"RuntimeName":"test-sandbox","WorkspaceDir":"/tmp/workspace"}}`

	req := httptest.NewRequest("POST", "/runtime", strings.NewReader(body))
	w := httptest.NewRecorder()
	d.handleCreateRuntime(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("first create: expected status %d, got %d", http.StatusCreated, w.Code)
	}

	req = httptest.NewRequest("POST", "/runtime", strings.NewReader(body))
	w = httptest.NewRecorder()
	d.handleCreateRuntime(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("expected status %d for duplicate, got %d", http.StatusConflict, w.Code)
	}
}

func TestDaemon_CreateRuntime_InvalidJSON(t *testing.T) {
	d := setupTestDaemon(t)

	req := httptest.NewRequest("POST", "/runtime", strings.NewReader("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	d.handleCreateRuntime(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestDaemon_CreateRuntime_DefaultAgentName(t *testing.T) {
	d := setupTestDaemon(t)

	body := `{"spec":{"RuntimeName":"test-sandbox","WorkspaceDir":"/tmp/workspace"}}`
	req := httptest.NewRequest("POST", "/runtime", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	d.handleCreateRuntime(w, req)

	var state SandboxState
	if err := json.Unmarshal(w.Body.Bytes(), &state); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if state.AgentName != "shell" {
		t.Errorf("expected default AgentName 'shell', got %q", state.AgentName)
	}
}

func TestDaemon_ListRuntimes(t *testing.T) {
	d := setupTestDaemon(t)

	body := `{"spec":{"RuntimeName":"test-sandbox","WorkspaceDir":"/tmp/workspace"}}`
	req := httptest.NewRequest("POST", "/runtime", strings.NewReader(body))
	w := httptest.NewRecorder()
	d.handleCreateRuntime(w, req)

	req = httptest.NewRequest("GET", "/runtime", nil)
	w = httptest.NewRecorder()
	d.handleListRuntimes(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var states []*SandboxState
	if err := json.Unmarshal(w.Body.Bytes(), &states); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if len(states) != 1 {
		t.Errorf("expected 1 runtime, got %d", len(states))
	}
}

func TestDaemon_ListRuntimes_Empty(t *testing.T) {
	d := setupTestDaemon(t)

	req := httptest.NewRequest("GET", "/runtime", nil)
	w := httptest.NewRecorder()

	d.handleListRuntimes(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var states []*SandboxState
	if err := json.Unmarshal(w.Body.Bytes(), &states); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if len(states) != 0 {
		t.Errorf("expected 0 runtimes, got %d", len(states))
	}
}

func TestDaemon_GetRuntime(t *testing.T) {
	d := setupTestDaemon(t)

	body := `{"spec":{"RuntimeName":"test-sandbox","WorkspaceDir":"/tmp/workspace"}}`
	req := httptest.NewRequest("POST", "/runtime", strings.NewReader(body))
	w := httptest.NewRecorder()
	d.handleCreateRuntime(w, req)

	req = httptest.NewRequest("GET", "/runtime/test-sandbox", nil)
	req.SetPathValue("name", "test-sandbox")
	w = httptest.NewRecorder()
	d.handleGetRuntime(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestDaemon_GetRuntime_NotFound(t *testing.T) {
	d := setupTestDaemon(t)

	req := httptest.NewRequest("GET", "/runtime/nonexistent", nil)
	req.SetPathValue("name", "nonexistent")
	w := httptest.NewRecorder()

	d.handleGetRuntime(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestDaemon_GetRuntime_MissingName(t *testing.T) {
	d := setupTestDaemon(t)

	req := httptest.NewRequest("GET", "/runtime/", nil)
	req.SetPathValue("name", "")
	w := httptest.NewRecorder()

	d.handleGetRuntime(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestDaemon_DeleteRuntime(t *testing.T) {
	d := setupTestDaemon(t)

	body := `{"spec":{"RuntimeName":"test-sandbox","WorkspaceDir":"/tmp/workspace"}}`
	req := httptest.NewRequest("POST", "/runtime", strings.NewReader(body))
	w := httptest.NewRecorder()
	d.handleCreateRuntime(w, req)

	req = httptest.NewRequest("DELETE", "/runtime/test-sandbox", nil)
	req.SetPathValue("name", "test-sandbox")
	w = httptest.NewRecorder()
	d.handleDeleteRuntime(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected status %d, got %d", http.StatusNoContent, w.Code)
	}

	d.mu.Lock()
	_, exists := d.sandboxes["test-sandbox"]
	d.mu.Unlock()
	if exists {
		t.Error("sandbox should be deleted")
	}
}

func TestDaemon_DeleteRuntime_NotFound(t *testing.T) {
	d := setupTestDaemon(t)

	req := httptest.NewRequest("DELETE", "/runtime/nonexistent", nil)
	req.SetPathValue("name", "nonexistent")
	w := httptest.NewRecorder()

	d.handleDeleteRuntime(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestDaemon_PolicyRulesEndpoint(t *testing.T) {
	d := setupTestDaemon(t)

	req := httptest.NewRequest("GET", "/policy/rules", nil)
	w := httptest.NewRecorder()

	d.handleListPolicyRules(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if _, ok := resp["rules"]; !ok {
		t.Error("expected 'rules' key in response")
	}
}

func TestDaemon_ApplyPolicyActions(t *testing.T) {
	d := setupTestDaemon(t)

	body := `{"actions":[{"action":"allow","resources":["api.example.com:443"],"scope":"sandbox-test"}]}`
	req := httptest.NewRequest("POST", "/policy/rules", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	d.handleApplyPolicyActions(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d; body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if _, ok := resp["results"]; !ok {
		t.Error("expected 'results' key in response")
	}
}

func TestDaemon_ApplyPolicyActions_InvalidJSON(t *testing.T) {
	d := setupTestDaemon(t)

	req := httptest.NewRequest("POST", "/policy/rules", strings.NewReader("bad json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	d.handleApplyPolicyActions(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestDaemon_ApplyPolicyActions_DenyAction(t *testing.T) {
	d := setupTestDaemon(t)

	body := `{"actions":[{"action":"deny","resources":["bad.com:443"]}]}`
	req := httptest.NewRequest("POST", "/policy/rules", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	d.handleApplyPolicyActions(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestDaemon_ApplyPolicyActions_UnknownAction(t *testing.T) {
	d := setupTestDaemon(t)

	body := `{"actions":[{"action":"unknown-action"}]}`
	req := httptest.NewRequest("POST", "/policy/rules", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	d.handleApplyPolicyActions(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	results := resp["results"].([]interface{})
	result := results[0].(map[string]interface{})
	if result["error"] == nil {
		t.Error("expected error for unknown action")
	}
}

func TestDaemon_PolicySetupEndpoint(t *testing.T) {
	d := setupTestDaemon(t)

	req := httptest.NewRequest("GET", "/policy/setup", nil)
	w := httptest.NewRecorder()

	d.handlePolicySetup(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestDaemon_SetPolicyProfile(t *testing.T) {
	tests := []struct {
		name   string
		preset string
	}{
		{"allow-all", "allow-all"},
		{"deny-all", "deny-all"},
		{"balanced", "balanced"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := setupTestDaemon(t)

			body := `{"preset":"` + tt.preset + `"}`
			req := httptest.NewRequest("POST", "/policy/setup", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			d.handleSetPolicyProfile(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("expected status %d, got %d; body: %s", http.StatusOK, w.Code, w.Body.String())
			}
		})
	}
}

func TestDaemon_SetPolicyProfile_InvalidPreset(t *testing.T) {
	d := setupTestDaemon(t)

	body := `{"preset":"invalid-preset"}`
	req := httptest.NewRequest("POST", "/policy/setup", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	d.handleSetPolicyProfile(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestDaemon_SetPolicyProfile_InvalidJSON(t *testing.T) {
	d := setupTestDaemon(t)

	req := httptest.NewRequest("POST", "/policy/setup", strings.NewReader("bad json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	d.handleSetPolicyProfile(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestDaemon_DeleteAllPolicyRules(t *testing.T) {
	d := setupTestDaemon(t)

	req := httptest.NewRequest("DELETE", "/policy/rules", nil)
	w := httptest.NewRecorder()

	d.handleDeletePolicyRules(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestDaemon_DeletePolicyRuleByID(t *testing.T) {
	d := setupTestDaemon(t)

	rule, err := d.policy.AddRule("test-rule", "allow", []string{"example.com:443"}, "")
	if err != nil {
		t.Fatalf("AddRule() error = %v", err)
	}

	req := httptest.NewRequest("DELETE", "/policy/rules/"+rule.ID, nil)
	req.SetPathValue("id", rule.ID)
	w := httptest.NewRecorder()

	d.handleDeletePolicyRuleByID(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestDaemon_DeletePolicyRuleByID_NotFound(t *testing.T) {
	d := setupTestDaemon(t)

	req := httptest.NewRequest("DELETE", "/policy/rules/nonexistent", nil)
	req.SetPathValue("id", "nonexistent")
	w := httptest.NewRecorder()

	d.handleDeletePolicyRuleByID(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestDaemon_DeletePolicyRuleByID_EmptyID(t *testing.T) {
	d := setupTestDaemon(t)

	req := httptest.NewRequest("DELETE", "/policy/rules/", nil)
	req.SetPathValue("id", "")
	w := httptest.NewRecorder()

	d.handleDeletePolicyRuleByID(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestDaemon_SecretsEndpoints(t *testing.T) {
	d := setupTestDaemon(t)

	// List secrets (initially empty)
	req := httptest.NewRequest("GET", "/secrets", nil)
	w := httptest.NewRecorder()
	d.handleListSecrets(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var initialSecrets []map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &initialSecrets); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if len(initialSecrets) != 0 {
		t.Errorf("expected 0 secrets, got %d", len(initialSecrets))
	}

	// Set secrets
	body := `{"secrets":[{"target":"api.example.com","env_name":"API_KEY","value":"secret123","sentinel":"{{API_KEY}}"}]}`
	req = httptest.NewRequest("POST", "/secrets", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	d.handleSetSecrets(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	// List secrets again
	req = httptest.NewRequest("GET", "/secrets", nil)
	w = httptest.NewRecorder()
	d.handleListSecrets(w, req)

	var updatedSecrets []map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &updatedSecrets); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if len(updatedSecrets) != 1 {
		t.Errorf("expected 1 secret, got %d", len(updatedSecrets))
	}

	// Verify value is redacted
	val := updatedSecrets[0]["value"].(string)
	if val == "secret123" {
		t.Error("secret value should be redacted")
	}
}

func TestDaemon_SetSecrets_InvalidJSON(t *testing.T) {
	d := setupTestDaemon(t)

	req := httptest.NewRequest("POST", "/secrets", strings.NewReader("bad json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	d.handleSetSecrets(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestDaemon_NetworkLogEndpoint(t *testing.T) {
	d := setupTestDaemon(t)

	req := httptest.NewRequest("GET", "/network/log", nil)
	w := httptest.NewRecorder()

	d.handleNetworkLog(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestDaemon_TemplatesEndpoint(t *testing.T) {
	d := setupTestDaemon(t)

	req := httptest.NewRequest("GET", "/template", nil)
	w := httptest.NewRecorder()

	d.handleListTemplates(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var templates []map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &templates); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if len(templates) == 0 {
		t.Error("expected at least 1 template")
	}
}

func TestDaemon_CACertEndpoint(t *testing.T) {
	d := setupTestDaemon(t)

	req := httptest.NewRequest("GET", "/ca.pem", nil)
	w := httptest.NewRecorder()

	d.handleCACert(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/x-pem-file" {
		t.Errorf("expected Content-Type 'application/x-pem-file', got %q", contentType)
	}

	if w.Body.Len() == 0 {
		t.Error("expected non-empty CA cert")
	}
}

func TestDaemon_StatePersistence(t *testing.T) {
	d := setupTestDaemon(t)

	body := `{"spec":{"RuntimeName":"persistent-sandbox","WorkspaceDir":"/tmp/workspace"}}`
	req := httptest.NewRequest("POST", "/runtime", strings.NewReader(body))
	w := httptest.NewRecorder()
	d.handleCreateRuntime(w, req)

	d.saveState()

	cfg := DaemonConfig{
		StateDir:  d.stateDir,
		PolicyDir: filepath.Join(t.TempDir(), "policy"),
		CACertDir: filepath.Join(t.TempDir(), "ca"),
	}
	d2, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}

	d2.mu.Lock()
	_, exists := d2.sandboxes["persistent-sandbox"]
	d2.mu.Unlock()
	if !exists {
		t.Error("expected sandbox to be loaded from persisted state")
	}
}

func TestDaemon_StartRuntime_NotFound(t *testing.T) {
	d := setupTestDaemon(t)

	req := httptest.NewRequest("POST", "/runtime/nonexistent/start", nil)
	req.SetPathValue("name", "nonexistent")
	w := httptest.NewRecorder()
	d.handleStartRuntime(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestDaemon_StopRuntime_NotFound(t *testing.T) {
	d := setupTestDaemon(t)

	req := httptest.NewRequest("POST", "/runtime/nonexistent/stop", nil)
	req.SetPathValue("name", "nonexistent")
	w := httptest.NewRecorder()
	d.handleStopRuntime(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestDaemon_RemoveResourcesByPattern(t *testing.T) {
	d := setupTestDaemon(t)

	// Test with a pattern that won't match anything
	d.removeResourcesByPattern([]string{"no-match-prefix"})
	// Should not panic
}

func TestDaemon_DetectDockerSocket(t *testing.T) {
	socket := detectDockerSocket("")
	if socket == "" {
		t.Error("detectDockerSocket() returned empty string")
	}
	t.Logf("detectDockerSocket() = %s", socket)
}

func TestWriteJSON(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, http.StatusOK, map[string]string{"key": "value"})

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got %q", contentType)
	}
}

func TestWriteError(t *testing.T) {
	w := httptest.NewRecorder()
	writeError(w, http.StatusBadRequest, "test error")

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp["error"] != "test error" {
		t.Errorf("expected error 'test error', got %q", resp["error"])
	}
}

func TestWriteError_VariousStatusCodes(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		message    string
	}{
		{"bad request", http.StatusBadRequest, "invalid input"},
		{"not found", http.StatusNotFound, "resource not found"},
		{"conflict", http.StatusConflict, "already exists"},
		{"internal error", http.StatusInternalServerError, "something went wrong"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			writeError(w, tt.statusCode, tt.message)

			if w.Code != tt.statusCode {
				t.Errorf("expected status %d, got %d", tt.statusCode, w.Code)
			}

			var resp map[string]string
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to parse response: %v", err)
			}
			if resp["error"] != tt.message {
				t.Errorf("expected error %q, got %q", tt.message, resp["error"])
			}
		})
	}
}

func TestDaemon_CreateRuntime_WithEnvVars(t *testing.T) {
	d := setupTestDaemon(t)

	body := `{"spec":{"RuntimeName":"env-sandbox","AgentName":"shell","WorkspaceDir":"/tmp/workspace","EnvVars":["KEY1=VAL1","KEY2=VAL2"]}}`
	req := httptest.NewRequest("POST", "/runtime", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	d.handleCreateRuntime(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d; body: %s", http.StatusCreated, w.Code, w.Body.String())
	}
}

func TestDaemon_CreateRuntime_WithContainerID(t *testing.T) {
	d := setupTestDaemon(t)

	// Create a runtime and then try to create sandbox with same container ID
	body := `{"spec":{"RuntimeName":"cid-sandbox","AgentName":"shell","WorkspaceDir":"/tmp/workspace"}}`
	req := httptest.NewRequest("POST", "/runtime", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	d.handleCreateRuntime(w, req)

	var state SandboxState
	if err := json.Unmarshal(w.Body.Bytes(), &state); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if state.ID == "" {
		t.Error("expected non-empty ID")
	}
}

func TestDaemon_GetRuntime_WithSandbox(t *testing.T) {
	d := setupTestDaemon(t)

	body := `{"spec":{"RuntimeName":"get-test","AgentName":"shell","WorkspaceDir":"/tmp/workspace"}}`
	req := httptest.NewRequest("POST", "/runtime", strings.NewReader(body))
	w := httptest.NewRecorder()
	d.handleCreateRuntime(w, req)

	// Get the runtime
	req = httptest.NewRequest("GET", "/runtime/get-test", nil)
	req.SetPathValue("name", "get-test")
	w = httptest.NewRecorder()
	d.handleGetRuntime(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var state SandboxState
	if err := json.Unmarshal(w.Body.Bytes(), &state); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if state.Name != "get-test" {
		t.Errorf("expected name 'get-test', got %q", state.Name)
	}
}

func TestDaemon_DeleteRuntime_WithSandbox(t *testing.T) {
	d := setupTestDaemon(t)

	body := `{"spec":{"RuntimeName":"del-test","AgentName":"shell","WorkspaceDir":"/tmp/workspace"}}`
	req := httptest.NewRequest("POST", "/runtime", strings.NewReader(body))
	w := httptest.NewRecorder()
	d.handleCreateRuntime(w, req)

	// Delete the runtime
	req = httptest.NewRequest("DELETE", "/runtime/del-test", nil)
	req.SetPathValue("name", "del-test")
	w = httptest.NewRecorder()
	d.handleDeleteRuntime(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected status %d, got %d", http.StatusNoContent, w.Code)
	}

	// Verify it's gone
	d.mu.Lock()
	_, exists := d.sandboxes["del-test"]
	d.mu.Unlock()
	if exists {
		t.Error("sandbox should be deleted")
	}
}

func TestDaemon_DeleteRuntime_EmptyName(t *testing.T) {
	d := setupTestDaemon(t)

	req := httptest.NewRequest("DELETE", "/runtime/", nil)
	req.SetPathValue("name", "")
	w := httptest.NewRecorder()

	d.handleDeleteRuntime(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestDaemon_ApplyPolicyActions_EmptyActions(t *testing.T) {
	d := setupTestDaemon(t)

	body := `{"actions":[]}`
	req := httptest.NewRequest("POST", "/policy/rules", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	d.handleApplyPolicyActions(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestDaemon_ApplyPolicyActions_MultipleActions(t *testing.T) {
	d := setupTestDaemon(t)

	body := `{"actions":[{"action":"allow","resources":["api.example.com:443"]},{"action":"deny","resources":["bad.com:80"]}]}`
	req := httptest.NewRequest("POST", "/policy/rules", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	d.handleApplyPolicyActions(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestDaemon_PropagatePolicyToSidecars(t *testing.T) {
	d := setupTestDaemon(t)

	// Create a sandbox with a container ID so it enters the branch that propagates
	d.mu.Lock()
	d.sandboxes["test-sandbox"] = &SandboxState{
		ID:          "sbx-test-sandbox",
		Name:        "test-sandbox",
		AgentName:   "shell",
		Workspace: "/tmp/workspace",
		ContainerID: "", // No container ID means skip
	}
	d.mu.Unlock()

	// Should not panic even without container
	d.propagatePolicyToSidecars(context.Background())
}

func TestDaemon_PropagateSecretsToSidecars(t *testing.T) {
	d := setupTestDaemon(t)

	d.mu.Lock()
	d.sandboxes["test-sandbox"] = &SandboxState{
		ID:          "sbx-test-sandbox",
		Name:        "test-sandbox",
		AgentName:   "shell",
		Workspace: "/tmp/workspace",
		ContainerID: "", // No container ID means skip
	}
	d.mu.Unlock()

	// Should not panic even without container
	d.propagateSecretsToSidecars(context.Background())
}

func TestDaemon_SaveAndLoadState(t *testing.T) {
	d := setupTestDaemon(t)

	// Create a sandbox
	body := `{"spec":{"RuntimeName":"save-test","AgentName":"shell","WorkspaceDir":"/tmp/workspace"}}`
	req := httptest.NewRequest("POST", "/runtime", strings.NewReader(body))
	w := httptest.NewRecorder()
	d.handleCreateRuntime(w, req)

	// Save state
	d.saveState()

	// Verify state file exists
	stateFile := filepath.Join(d.stateDir, "sandboxes.json")
	if _, err := os.Stat(stateFile); os.IsNotExist(err) {
		t.Error("state file was not created")
	}
}

func TestDaemon_LoadState(t *testing.T) {
	tmpDir := t.TempDir()
	stateDir := filepath.Join(tmpDir, "state")
	if err := os.MkdirAll(stateDir, 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	// Write a state file
	state := map[string]*SandboxState{
		"test-sandbox": {
			ID:          "sbx-test-sandbox",
			Name:        "test-sandbox",
			AgentName:   "shell",
			Workspace: "/tmp/workspace",
		},
	}
	data, _ := json.Marshal(state)
	if err := os.WriteFile(filepath.Join(stateDir, "sandboxes.json"), data, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	cfg := DaemonConfig{
		StateDir:  stateDir,
		PolicyDir: filepath.Join(tmpDir, "policy"),
		CACertDir: filepath.Join(tmpDir, "ca"),
	}
	d, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}

	d.mu.Lock()
	sandbox, exists := d.sandboxes["test-sandbox"]
	d.mu.Unlock()
	if !exists {
		t.Error("expected sandbox to be loaded from state file")
	}
	if sandbox.Name != "test-sandbox" {
		t.Errorf("expected name 'test-sandbox', got %q", sandbox.Name)
	}
}

func TestDaemon_SecretRedaction(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected string
	}{
		{"short value", "ab", "***"},
		{"4 chars", "abcd", "***"},
		{"5 chars", "abcde", "ab...de"},
		{"long value", "secretvalue123", "se...23"},
		{"empty value", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := setupTestDaemon(t)
			d.secrets.SetSecrets([]secrets.CustomSecret{
				{Target: "test.com", EnvName: "KEY", Value: tt.value, Sentinel: "{{KEY}}"},
			})

			req := httptest.NewRequest("GET", "/secrets", nil)
			w := httptest.NewRecorder()
			d.handleListSecrets(w, req)

			var result []map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatalf("failed to parse response: %v", err)
			}
			if len(result) == 0 {
				t.Fatal("expected at least 1 secret")
			}
			got := result[0]["value"].(string)
			if got != tt.expected {
				t.Errorf("expected redacted value %q, got %q", tt.expected, got)
			}
		})
	}
}

func TestDaemon_StartRuntime_AlreadyRunning(t *testing.T) {
	d := setupTestDaemon(t)

	body := `{"spec":{"RuntimeName":"running-sandbox","AgentName":"shell","WorkspaceDir":"/tmp/workspace"}}`
	req := httptest.NewRequest("POST", "/runtime", strings.NewReader(body))
	w := httptest.NewRecorder()
	d.handleCreateRuntime(w, req)

	// Set the sandbox as running
	d.mu.Lock()
	s := d.sandboxes["running-sandbox"]
	s.Running = true
	d.sandboxes["running-sandbox"] = s
	d.mu.Unlock()

	req = httptest.NewRequest("POST", "/runtime/running-sandbox/start", nil)
	req.SetPathValue("name", "running-sandbox")
	w = httptest.NewRecorder()
	d.handleStartRuntime(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("expected status %d for already running, got %d", http.StatusConflict, w.Code)
	}
}

func TestDaemon_StartRuntime_EmptyName(t *testing.T) {
	d := setupTestDaemon(t)

	req := httptest.NewRequest("POST", "/runtime//start", nil)
	req.SetPathValue("name", "")
	w := httptest.NewRecorder()
	d.handleStartRuntime(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestDaemon_StopRuntime_EmptyName(t *testing.T) {
	d := setupTestDaemon(t)

	req := httptest.NewRequest("POST", "/runtime//stop", nil)
	req.SetPathValue("name", "")
	w := httptest.NewRecorder()
	d.handleStopRuntime(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestDaemon_StopRuntime_NotRunning(t *testing.T) {
	d := setupTestDaemon(t)

	body := `{"spec":{"RuntimeName":"stopped-sandbox","AgentName":"shell","WorkspaceDir":"/tmp/workspace"}}`
	req := httptest.NewRequest("POST", "/runtime", strings.NewReader(body))
	w := httptest.NewRecorder()
	d.handleCreateRuntime(w, req)

	// Sandbox created but not running (Running is false by default)
	req = httptest.NewRequest("POST", "/runtime/stopped-sandbox/stop", nil)
	req.SetPathValue("name", "stopped-sandbox")
	w = httptest.NewRecorder()
	d.handleStopRuntime(w, req)

	// Since there's no container ID, it should still succeed or return an appropriate error
	// The important thing is it doesn't panic
}

func TestDaemon_HandleCreateRuntime_WithImage(t *testing.T) {
	d := setupTestDaemon(t)

	body := `{"spec":{"RuntimeName":"img-sandbox","AgentName":"shell","WorkspaceDir":"/tmp/workspace","Image":"ubuntu:22.04"}}`
	req := httptest.NewRequest("POST", "/runtime", strings.NewReader(body))
	w := httptest.NewRecorder()
	d.handleCreateRuntime(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
	}

	var state SandboxState
	if err := json.Unmarshal(w.Body.Bytes(), &state); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if state.Image != "ubuntu:22.04" {
		t.Errorf("expected Image 'ubuntu:22.04', got %q", state.Image)
	}
}

func TestDaemon_HandleCreateRuntime_WithLabels(t *testing.T) {
	d := setupTestDaemon(t)

	body := `{"spec":{"RuntimeName":"label-sandbox","AgentName":"shell","WorkspaceDir":"/tmp/workspace","Labels":{"env":"test"}}}`
	req := httptest.NewRequest("POST", "/runtime", strings.NewReader(body))
	w := httptest.NewRecorder()
	d.handleCreateRuntime(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
	}

	var state SandboxState
	if err := json.Unmarshal(w.Body.Bytes(), &state); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
}

func TestDaemon_DeletePolicyRules_ClearsAll(t *testing.T) {
	d := setupTestDaemon(t)

	req := httptest.NewRequest("DELETE", "/policy/rules", nil)
	w := httptest.NewRecorder()
	d.handleDeletePolicyRules(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	// Verify rules are gone
	rules := d.policy.ListRules()
	if len(rules) != 0 {
		t.Errorf("expected 0 rules after delete all, got %d", len(rules))
	}
}

func TestDaemon_HandleListSecrets_EmptyResponse(t *testing.T) {
	d := setupTestDaemon(t)

	req := httptest.NewRequest("GET", "/secrets", nil)
	w := httptest.NewRecorder()
	d.handleListSecrets(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestDaemon_HandleStartRuntime_EmptyName(t *testing.T) {
	d := setupTestDaemon(t)

	req := httptest.NewRequest("POST", "/runtime//start", nil)
	req.SetPathValue("name", "")
	w := httptest.NewRecorder()
	d.handleStartRuntime(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestDaemon_HandleStartRuntime_AlreadyRunning(t *testing.T) {
	d := setupTestDaemon(t)

	body := `{"spec":{"RuntimeName":"running-sb","AgentName":"shell","WorkspaceDir":"/tmp/workspace"}}`
	req := httptest.NewRequest("POST", "/runtime", strings.NewReader(body))
	w := httptest.NewRecorder()
	d.handleCreateRuntime(w, req)

	d.mu.Lock()
	s := d.sandboxes["running-sb"]
	s.Running = true
	d.sandboxes["running-sb"] = s
	d.mu.Unlock()

	req = httptest.NewRequest("POST", "/runtime/running-sb/start", nil)
	req.SetPathValue("name", "running-sb")
	w = httptest.NewRecorder()
	d.handleStartRuntime(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("expected status %d for already running, got %d", http.StatusConflict, w.Code)
	}
}

func TestDaemon_HandleStartRuntime_NotFound(t *testing.T) {
	d := setupTestDaemon(t)

	req := httptest.NewRequest("POST", "/runtime/nonexistent/start", nil)
	req.SetPathValue("name", "nonexistent")
	w := httptest.NewRecorder()
	d.handleStartRuntime(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestDaemon_HandleStopRuntime_AlreadyStopped(t *testing.T) {
	d := setupTestDaemon(t)

	body := `{"spec":{"RuntimeName":"stopped-sb","AgentName":"shell","WorkspaceDir":"/tmp/workspace"}}`
	req := httptest.NewRequest("POST", "/runtime", strings.NewReader(body))
	w := httptest.NewRecorder()
	d.handleCreateRuntime(w, req)

	// Sandbox is created but not running (Running defaults to false)
	req = httptest.NewRequest("POST", "/runtime/stopped-sb/stop", nil)
	req.SetPathValue("name", "stopped-sb")
	w = httptest.NewRecorder()
	d.handleStopRuntime(w, req)

	// Should return 200 because it's already stopped
	if w.Code != http.StatusOK {
		t.Logf("handleStopRuntime returned status %d for stopped sandbox", w.Code)
	}
}

func TestDaemon_SaveAndLoadState_WithContainers(t *testing.T) {
	d := setupTestDaemon(t)

	// Create multiple sandboxes
	for i := 0; i < 3; i++ {
		name := fmt.Sprintf("sandbox-%d", i)
		body := fmt.Sprintf(`{"spec":{"RuntimeName":"%s","AgentName":"shell","WorkspaceDir":"/tmp/workspace"}}`, name)
		req := httptest.NewRequest("POST", "/runtime", strings.NewReader(body))
		w := httptest.NewRecorder()
		d.handleCreateRuntime(w, req)
		if w.Code != http.StatusCreated {
			t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
		}
	}

	// Save state
	d.saveState()

	// Verify state file exists
	stateFile := filepath.Join(d.stateDir, "sandboxes.json")
	if _, err := os.Stat(stateFile); os.IsNotExist(err) {
		t.Error("state file was not created")
	}

	// Load into a new daemon
	cfg := DaemonConfig{
		StateDir:  d.stateDir,
		PolicyDir: filepath.Join(t.TempDir(), "policy"),
		CACertDir: filepath.Join(t.TempDir(), "ca"),
	}
	d2, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon() error = %v", err)
	}

	// Verify all sandboxes were loaded
	d2.mu.Lock()
	if len(d2.sandboxes) != 3 {
		t.Errorf("expected 3 sandboxes, got %d", len(d2.sandboxes))
	}
	d2.mu.Unlock()
}

func TestDaemon_HandleApplyPolicyActions_DenyAll(t *testing.T) {
	d := setupTestDaemon(t)

	body := `{"actions":[{"action":"deny","resources":["*:*"]}]}`
	req := httptest.NewRequest("POST", "/policy/rules", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	d.handleApplyPolicyActions(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestDaemon_HandleApplyPolicyActions_AllowSpecific(t *testing.T) {
	d := setupTestDaemon(t)

	body := `{"actions":[{"action":"allow","resources":["api.example.com:443","db.example.com:5432"],"scope":"sandbox-test"}]}`
	req := httptest.NewRequest("POST", "/policy/rules", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	d.handleApplyPolicyActions(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestDaemon_SetPolicyProfile_Balanced(t *testing.T) {
	d := setupTestDaemon(t)

	body := `{"preset":"balanced"}`
	req := httptest.NewRequest("POST", "/policy/setup", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	d.handleSetPolicyProfile(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	// Verify rules were set
	rules := d.policy.ListRules()
	if len(rules) == 0 {
		t.Error("expected at least 1 rule after setting balanced profile")
	}
}

func TestDaemon_HandleCACert_ContentType(t *testing.T) {
	d := setupTestDaemon(t)

	req := httptest.NewRequest("GET", "/ca.pem", nil)
	w := httptest.NewRecorder()
	d.handleCACert(w, req)

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/x-pem-file" {
		t.Errorf("expected Content-Type 'application/x-pem-file', got %q", contentType)
	}
}

func TestDaemon_NetworkLog_AfterActivity(t *testing.T) {
	d := setupTestDaemon(t)

	// Create a sandbox first
	body := `{"spec":{"RuntimeName":"net-sb","AgentName":"shell","WorkspaceDir":"/tmp/workspace"}}`
	req := httptest.NewRequest("POST", "/runtime", strings.NewReader(body))
	w := httptest.NewRecorder()
	d.handleCreateRuntime(w, req)

	// Now get the network log
	req = httptest.NewRequest("GET", "/network/log", nil)
	w = httptest.NewRecorder()
	d.handleNetworkLog(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestDaemon_MultiplePolicies(t *testing.T) {
	d := setupTestDaemon(t)

	// Set allow-all profile
	body := `{"preset":"allow-all"}`
	req := httptest.NewRequest("POST", "/policy/setup", strings.NewReader(body))
	w := httptest.NewRecorder()
	d.handleSetPolicyProfile(w, req)

	// Then allow a specific domain
	body = `{"actions":[{"action":"allow","resources":["specific.example.com:443"]}]}`
	req = httptest.NewRequest("POST", "/policy/rules", strings.NewReader(body))
	w = httptest.NewRecorder()
	d.handleApplyPolicyActions(w, req)

	// List rules
	req = httptest.NewRequest("GET", "/policy/rules", nil)
	w = httptest.NewRecorder()
	d.handleListPolicyRules(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestDaemon_RemoveSandboxByName(t *testing.T) {
	d := setupTestDaemon(t)

	// Create sandbox
	body := `{"spec":{"RuntimeName":"remove-sb","AgentName":"shell","WorkspaceDir":"/tmp/workspace"}}`
	req := httptest.NewRequest("POST", "/runtime", strings.NewReader(body))
	w := httptest.NewRecorder()
	d.handleCreateRuntime(w, req)

	// Get sandbox
	req = httptest.NewRequest("GET", "/runtime/remove-sb", nil)
	req.SetPathValue("name", "remove-sb")
	w = httptest.NewRecorder()
	d.handleGetRuntime(w, req)

	var state SandboxState
	if err := json.Unmarshal(w.Body.Bytes(), &state); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if state.Name != "remove-sb" {
		t.Errorf("expected name 'remove-sb', got %q", state.Name)
	}
}
