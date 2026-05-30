package container

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewManager(t *testing.T) {
	m := NewManager("/var/run/docker.sock", "/tmp/test-data")
	if m == nil {
		t.Fatal("NewManager() returned nil")
	}
	if m.DockerSocketPath() != "/var/run/docker.sock" {
		t.Errorf("DockerSocketPath() = %q, want %q", m.DockerSocketPath(), "/var/run/docker.sock")
	}
}

func TestParseHostPort(t *testing.T) {
	tests := []struct {
		input   string
		expHost string
		expPort string
	}{
		{"example.com:443", "example.com", "443"},
		{"sub.example.com:8080", "sub.example.com", "8080"},
		{"192.168.1.1:80", "192.168.1.1", "80"},
		{"example.com", "example.com", "80"},
		{":443", "", "443"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			host, port := ParseHostPort(tt.input)
			if host != tt.expHost || port != tt.expPort {
				t.Errorf("ParseHostPort(%q) = (%q, %q), want (%q, %q)",
					tt.input, host, port, tt.expHost, tt.expPort)
			}
		})
	}
}

func TestDecodeBase64Header(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "valid base64",
			input:    base64.StdEncoding.EncodeToString([]byte("hello world")),
			expected: "hello world",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "invalid base64",
			input:    "not-valid-base64!!!",
			expected: "not-valid-base64!!!",
		},
		{
			name:     "base64 encoded JSON",
			input:    base64.StdEncoding.EncodeToString([]byte(`{"key":"value"}`)),
			expected: `{"key":"value"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DecodeBase64Header(tt.input)
			if result != tt.expected {
				t.Errorf("DecodeBase64Header(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestIsClosedConnError(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		expect bool
	}{
		{"nil error", nil, false},
		{"use of closed network connection", fmt.Errorf("use of closed network connection"), true},
		{"broken pipe", fmt.Errorf("write: broken pipe"), true},
		{"connection reset", fmt.Errorf("connection reset by peer"), true},
		{"http: Server closed", fmt.Errorf("http: Server closed"), true},
		{"unrelated error", fmt.Errorf("something else"), false},
		{"empty error", fmt.Errorf(""), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsClosedConnError(tt.err)
			if result != tt.expect {
				t.Errorf("IsClosedConnError(%v) = %v, want %v", tt.err, result, tt.expect)
			}
		})
	}
}

func TestSetRequestBody(t *testing.T) {
	body := []byte(`{"key":"value"}`)
	req, err := http.NewRequest("POST", "http://example.com/test", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	SetRequestBody(req, body)

	if req.ContentLength != int64(len(body)) {
		t.Errorf("ContentLength = %d, want %d", req.ContentLength, len(body))
	}
}

func TestSetRequestBody_Empty(t *testing.T) {
	req, err := http.NewRequest("POST", "http://example.com/test", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	SetRequestBody(req, []byte{})

	if req.ContentLength != 0 {
		t.Errorf("ContentLength = %d, want 0", req.ContentLength)
	}
}

func TestEnsureDataDir(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := filepath.Join(tmpDir, "sandbox-data")

	err := EnsureDataDir(dataDir)
	if err != nil {
		t.Fatalf("EnsureDataDir() error = %v", err)
	}

	if _, err := os.Stat(dataDir); os.IsNotExist(err) {
		t.Error("data directory was not created")
	}

	err = EnsureDataDir(dataDir)
	if err != nil {
		t.Errorf("EnsureDataDir() on existing dir error = %v", err)
	}
}

func TestEnsureDataDir_Empty(t *testing.T) {
	err := EnsureDataDir("")
	if err != nil {
		t.Errorf("EnsureDataDir(\"\") error = %v", err)
	}
}

func TestResolveHostIP(t *testing.T) {
	ip := ResolveHostIP()
	if ip == "" {
		t.Error("ResolveHostIP() returned empty string")
	}
}

func TestContainer_JSONRoundtrip(t *testing.T) {
	c := Container{
		ID:       "abc123",
		Name:     "test-container",
		Image:    "ubuntu:22.04",
		Status:   "running",
		Running:  true,
		Sandbox:  "test-sandbox",
		Ports:    []string{"8080:80"},
		ExitCode: 0,
	}

	data, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var c2 Container
	if err := json.Unmarshal(data, &c2); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if c2.ID != c.ID {
		t.Errorf("ID mismatch: got %q, want %q", c2.ID, c.ID)
	}
	if c2.Name != c.Name {
		t.Errorf("Name mismatch: got %q, want %q", c2.Name, c.Name)
	}
	if c2.Image != c.Image {
		t.Errorf("Image mismatch: got %q, want %q", c2.Image, c.Image)
	}
}

// ── Mock Transport for Docker API Tests ────────────────────────────────────────

// redirectTransport is an http.RoundTripper that redirects requests
// from http://localhost/... to the mock server.
type redirectTransport struct {
	targetURL *url.URL
}

func (rt *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Rewrite the request URL to point to the target server
	newURL := *rt.targetURL
	newURL.Path = req.URL.Path
	newURL.RawQuery = req.URL.RawQuery
	req.URL = &newURL
	// Use default transport for the actual request
	return http.DefaultTransport.RoundTrip(req)
}

func newManagerWithMock(handler http.HandlerFunc) (*Manager, *httptest.Server) {
	server := httptest.NewServer(handler)
	serverURL, _ := url.Parse(server.URL)

	m := NewManager("/var/run/docker.sock", os.TempDir())
	m.httpClient = &http.Client{
		Timeout:   10 * time.Second,
		Transport: &redirectTransport{targetURL: serverURL},
	}

	return m, server
}

// mockHandler is a helper to create mock Docker API handlers.
type mockHandler struct {
	w        http.ResponseWriter
	enc      *json.Encoder
}

func (m *mockHandler) encode(v interface{}) {
	if err := m.enc.Encode(v); err != nil {
		panic(err)
	}
}

func (m *mockHandler) writeString(s string) {
	if _, err := io.WriteString(m.w, s); err != nil {
		panic(err)
	}
}

func (m *mockHandler) writef(format string, args ...interface{}) {
	if _, err := fmt.Fprintf(m.w, format, args...); err != nil {
		panic(err)
	}
}

func newMockHandler(w http.ResponseWriter) *mockHandler {
	return &mockHandler{w: w, enc: json.NewEncoder(w)}
}

func TestManager_CreateContainer_MockDocker(t *testing.T) {
	created := false
	m, server := newManagerWithMock(func(w http.ResponseWriter, r *http.Request) {
		h := newMockHandler(w)
		switch r.URL.Path {
		case "/v1.54/networks":
			w.WriteHeader(http.StatusOK)
			h.encode([]map[string]interface{}{
				{"Id": "net-123", "Name": "sandbox-net"},
			})
		case "/v1.54/images/create":
			w.WriteHeader(http.StatusOK)
			h.writeString(`{"status":"Pull complete"}`)
		case "/v1.54/containers/create":
			created = true
			w.WriteHeader(http.StatusCreated)
			h.encode(map[string]interface{}{
				"Id": "container-abc123",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
			h.writef("Not found: %s %s", r.Method, r.URL.Path)
		}
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	container, err := m.CreateContainer(ctx, "ubuntu:22.04", []string{"/bin/bash"}, []string{}, "test-sandbox")
	if err != nil {
		t.Fatalf("CreateContainer() error = %v", err)
	}
	if !created {
		t.Error("expected create endpoint to be called")
	}
	if container.ID != "container-abc123" {
		t.Errorf("expected container ID 'container-abc123', got %q", container.ID)
	}
	if container.Name != "sbx-test-sandbox" {
		t.Errorf("expected container name 'sbx-test-sandbox', got %q", container.Name)
	}
}

func TestManager_StartContainer_MockDocker(t *testing.T) {
	m, server := newManagerWithMock(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1.54/containers/container-123/start" {
			w.WriteHeader(http.StatusNoContent)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := m.StartContainer(ctx, "container-123"); err != nil {
		t.Fatalf("StartContainer() error = %v", err)
	}
}

func TestManager_StopContainer_MockDocker(t *testing.T) {
	m, server := newManagerWithMock(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1.54/containers/container-123/stop" {
			w.WriteHeader(http.StatusNoContent)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := m.StopContainer(ctx, "container-123"); err != nil {
		t.Fatalf("StopContainer() error = %v", err)
	}
}

func TestManager_RemoveContainer_MockDocker(t *testing.T) {
	m, server := newManagerWithMock(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1.54/containers/container-123" && r.Method == "DELETE" {
			w.WriteHeader(http.StatusNoContent)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := m.RemoveContainer(ctx, "container-123"); err != nil {
		t.Fatalf("RemoveContainer() error = %v", err)
	}
}

func TestManager_InspectContainer_MockDocker(t *testing.T) {
	m, server := newManagerWithMock(func(w http.ResponseWriter, r *http.Request) {
		h := newMockHandler(w)
		if r.URL.Path == "/v1.54/containers/container-123/json" {
			w.WriteHeader(http.StatusOK)
			h.encode(map[string]interface{}{
				"Id":   "container-123",
				"Name": "/sbx-test",
				"State": map[string]interface{}{
					"Status":   "running",
					"Running":  true,
					"ExitCode": 0,
				},
				"Config": map[string]interface{}{
					"Image": "ubuntu:22.04",
				},
				"NetworkSettings": map[string]interface{}{
					"Ports": map[string]interface{}{},
				},
			})
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	container, err := m.InspectContainer(ctx, "container-123")
	if err != nil {
		t.Fatalf("InspectContainer() error = %v", err)
	}
	if container.ID != "container-123" {
		t.Errorf("expected ID 'container-123', got %q", container.ID)
	}
	if container.Status != "running" {
		t.Errorf("expected status 'running', got %q", container.Status)
	}
}

func TestManager_WaitForContainerExit_MockDocker(t *testing.T) {
	m, server := newManagerWithMock(func(w http.ResponseWriter, r *http.Request) {
		h := newMockHandler(w)
		if r.URL.Path == "/v1.54/containers/container-123/wait" {
			w.WriteHeader(http.StatusOK)
			h.writeString(`{"StatusCode":0}`)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	exitCode, err := m.WaitForContainerExit(ctx, "container-123")
	if err != nil {
		t.Fatalf("WaitForContainerExit() error = %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
}

func TestManager_GetContainerLogs_MockDocker(t *testing.T) {
	m, server := newManagerWithMock(func(w http.ResponseWriter, r *http.Request) {
		h := newMockHandler(w)
		if r.URL.Path == "/v1.54/containers/container-123/logs" {
			w.WriteHeader(http.StatusOK)
			h.writeString("log line 1\nlog line 2\n")
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	logs, err := m.GetContainerLogs(ctx, "container-123", 100)
	if err != nil {
		t.Fatalf("GetContainerLogs() error = %v", err)
	}
	if logs == "" {
		t.Error("expected non-empty logs")
	}
}

func TestManager_StopContainer_NotFound(t *testing.T) {
	m, server := newManagerWithMock(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		newMockHandler(w).writef("container not found")
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := m.StopContainer(ctx, "nonexistent"); err == nil {
		t.Error("expected error for nonexistent container")
	}
}

func TestManager_CreateContainer_DockerError(t *testing.T) {
	m, server := newManagerWithMock(func(w http.ResponseWriter, r *http.Request) {
		h := newMockHandler(w)
		switch r.URL.Path {
		case "/v1.54/networks":
			w.WriteHeader(http.StatusOK)
			h.encode([]map[string]interface{}{
				{"Id": "net-123", "Name": "sandbox-net"},
			})
		case "/v1.54/images/create":
			w.WriteHeader(http.StatusOK)
		case "/v1.54/containers/create":
			w.WriteHeader(http.StatusInternalServerError)
			h.writeString("internal server error")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := m.CreateContainer(ctx, "bad-image", []string{}, []string{}, "test"); err == nil {
		t.Error("expected error for Docker error")
	}
}

func TestManager_InspectContainer_NotFound(t *testing.T) {
	m, server := newManagerWithMock(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := m.InspectContainer(ctx, "nonexistent"); err == nil {
		t.Error("expected error for nonexistent container")
	}
}

func TestManager_WaitForContainerExit_NonZeroExit(t *testing.T) {
	m, server := newManagerWithMock(func(w http.ResponseWriter, r *http.Request) {
		h := newMockHandler(w)
		if r.URL.Path == "/v1.54/containers/container-err/wait" {
			w.WriteHeader(http.StatusOK)
			h.writeString(`{"StatusCode":1}`)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	exitCode, err := m.WaitForContainerExit(ctx, "container-err")
	if err != nil {
		t.Fatalf("WaitForContainerExit() error = %v", err)
	}
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}
}

func TestManager_ListContainers_MockDocker(t *testing.T) {
	m, server := newManagerWithMock(func(w http.ResponseWriter, r *http.Request) {
		h := newMockHandler(w)
		if r.URL.Path == "/v1.54/containers/json" {
			w.WriteHeader(http.StatusOK)
			h.encode([]map[string]interface{}{
				{
					"Id":    "container-1",
					"Names": []string{"/sbx-test"},
					"Image": "ubuntu:22.04",
					"State": "running",
				},
			})
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	containers, err := m.ListContainers(ctx)
	if err != nil {
		t.Fatalf("ListContainers() error = %v", err)
	}
	if len(containers) != 1 {
		t.Errorf("expected 1 container, got %d", len(containers))
	}
}

func TestManager_CreateContainer_NetworkCreate(t *testing.T) {
	networkCreated := false
	m, server := newManagerWithMock(func(w http.ResponseWriter, r *http.Request) {
		h := newMockHandler(w)
		switch r.URL.Path {
		case "/v1.54/networks":
			// Network doesn't exist yet - return empty list
			w.WriteHeader(http.StatusOK)
			h.encode([]map[string]interface{}{})
		case "/v1.54/networks/create":
			networkCreated = true
			w.WriteHeader(http.StatusCreated)
			h.encode(map[string]interface{}{"Id": "new-net-456"})
		case "/v1.54/images/create":
			w.WriteHeader(http.StatusOK)
		case "/v1.54/containers/create":
			w.WriteHeader(http.StatusCreated)
			h.encode(map[string]interface{}{"Id": "container-net-test"})
		default:
			w.WriteHeader(http.StatusNotFound)
			h.writef("Not found: %s %s", r.Method, r.URL.Path)
		}
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	container, err := m.CreateContainer(ctx, "ubuntu:22.04", []string{"/bin/bash"}, []string{}, "net-test")
	if err != nil {
		t.Fatalf("CreateContainer() error = %v", err)
	}
	if container.ID != "container-net-test" {
		t.Errorf("expected container ID 'container-net-test', got %q", container.ID)
	}
	if !networkCreated {
		t.Error("expected network to be created")
	}
}

func TestManager_RemoveContainer_ForceRemoval(t *testing.T) {
	m, server := newManagerWithMock(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1.54/containers/force-123" && r.Method == "DELETE" {
			// Verify force=true and v=true query params
			if r.URL.Query().Get("force") != "true" {
				t.Errorf("expected force=true query param")
			}
			if r.URL.Query().Get("v") != "true" {
				t.Errorf("expected v=true query param")
			}
			w.WriteHeader(http.StatusNoContent)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := m.RemoveContainer(ctx, "force-123"); err != nil {
		t.Fatalf("RemoveContainer() error = %v", err)
	}
}