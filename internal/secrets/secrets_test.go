package secrets

import (
	"testing"
)

func TestNewSecretManager(t *testing.T) {
	sm := NewSecretManager()
	if sm == nil {
		t.Fatal("NewSecretManager() returned nil")
	}
	if len(sm.GetSecrets()) != 0 {
		t.Fatalf("expected 0 secrets, got %d", len(sm.GetSecrets()))
	}
}

func TestSecretManager_SetSecrets_GetSecrets(t *testing.T) {
	sm := NewSecretManager()

	secrets := []CustomSecret{
		{Target: "api.example.com", EnvName: "API_KEY", Value: "secret123", Sentinel: "{{API_KEY}}"},
		{Target: "db.example.com", EnvName: "DB_PASS", Value: "dbpass456", Sentinel: "{{DB_PASS}}"},
	}
	sm.SetSecrets(secrets)

	got := sm.GetSecrets()
	if len(got) != 2 {
		t.Fatalf("expected 2 secrets, got %d", len(got))
	}
	if got[0].EnvName != "API_KEY" {
		t.Errorf("expected env_name API_KEY, got %s", got[0].EnvName)
	}
	if got[1].EnvName != "DB_PASS" {
		t.Errorf("expected env_name DB_PASS, got %s", got[1].EnvName)
	}
}

func TestSecretManager_SetSecrets_Replaces(t *testing.T) {
	sm := NewSecretManager()

	sm.SetSecrets([]CustomSecret{
		{Target: "a.com", EnvName: "A", Value: "val1", Sentinel: "{{A}}"},
	})
	sm.SetSecrets([]CustomSecret{
		{Target: "b.com", EnvName: "B", Value: "val2", Sentinel: "{{B}}"},
	})

	got := sm.GetSecrets()
	if len(got) != 1 {
		t.Fatalf("expected 1 secret after replace, got %d", len(got))
	}
	if got[0].EnvName != "B" {
		t.Errorf("expected env_name B, got %s", got[0].EnvName)
	}
}

func TestReplaceSentinelsInBody(t *testing.T) {
	tests := []struct {
		name     string
		secrets  []CustomSecret
		body     string
		expected string
	}{
		{
			name:     "no secrets set",
			secrets:  nil,
			body:     "hello world",
			expected: "hello world",
		},
		{
			name:     "empty body",
			secrets:  []CustomSecret{{Target: "a.com", EnvName: "KEY", Value: "val", Sentinel: "{{KEY}}"}},
			body:     "",
			expected: "",
		},
		{
			name:     "single sentinel replaced",
			secrets:  []CustomSecret{{Target: "api.example.com", EnvName: "API_KEY", Value: "my-api-key", Sentinel: "{{API_KEY}}"}},
			body:     "key={{API_KEY}}&other=foo",
			expected: "key=my-api-key&other=foo",
		},
		{
			name: "multiple sentinels replaced",
			secrets: []CustomSecret{
				{Target: "a.com", EnvName: "KEY1", Value: "val1", Sentinel: "{{KEY1}}"},
				{Target: "b.com", EnvName: "KEY2", Value: "val2", Sentinel: "{{KEY2}}"},
			},
			body:     "{{KEY1}}-and-{{KEY2}}",
			expected: "val1-and-val2",
		},
		{
			name:     "sentinel not found in body",
			secrets:  []CustomSecret{{Target: "a.com", EnvName: "KEY", Value: "val", Sentinel: "{{KEY}}"}},
			body:     "no sentinel here",
			expected: "no sentinel here",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := NewSecretManager()
			sm.SetSecrets(tt.secrets)
			result := sm.ReplaceSentinelsInBody([]byte(tt.body))
			if string(result) != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, string(result))
			}
		})
	}
}

func TestReplaceSentinelsInHeaders(t *testing.T) {
	tests := []struct {
		name     string
		secrets  []CustomSecret
		headers  map[string][]string
		expected map[string][]string
	}{
		{
			name:     "no secrets set",
			secrets:  nil,
			headers:  map[string][]string{"X-Custom": {"hello"}},
			expected: map[string][]string{"X-Custom": {"hello"}},
		},
		{
			name:     "nil headers with secrets",
			secrets:  []CustomSecret{{Target: "a.com", EnvName: "KEY", Value: "val", Sentinel: "{{KEY}}"}},
			headers:  nil,
			expected: map[string][]string{}, // empty map, not nil
		},
		{
			name:     "nil headers no secrets",
			secrets:  nil,
			headers:  nil,
			expected: nil,
		},
		{
			name:     "sentinel in header value",
			secrets:  []CustomSecret{{Target: "api.com", EnvName: "TOKEN", Value: "abc123", Sentinel: "{{TOKEN}}"}},
			headers:  map[string][]string{"Authorization": {"Bearer {{TOKEN}}"}},
			expected: map[string][]string{"Authorization": {"Bearer abc123"}},
		},
		{
			name: "sentinel in multiple header values",
			secrets: []CustomSecret{
				{Target: "a.com", EnvName: "KEY1", Value: "v1", Sentinel: "{{KEY1}}"},
			},
			headers:  map[string][]string{"X-Auth": {"{{KEY1}}", "other"}},
			expected: map[string][]string{"X-Auth": {"v1", "other"}},
		},
		{
			name: "multiple sentinels replaced",
			secrets: []CustomSecret{
				{Target: "a.com", EnvName: "A", Value: "valA", Sentinel: "{{A}}"},
				{Target: "b.com", EnvName: "B", Value: "valB", Sentinel: "{{B}}"},
			},
			headers: map[string][]string{
				"X-A": {"{{A}}"},
				"X-B": {"{{B}}"},
			},
			expected: map[string][]string{
				"X-A": {"valA"},
				"X-B": {"valB"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := NewSecretManager()
			sm.SetSecrets(tt.secrets)
			result := sm.ReplaceSentinelsInHeaders(tt.headers)
			if tt.expected == nil {
				if result != nil {
					t.Errorf("expected nil, got %v", result)
				}
				return
			}
			for key, expectedVals := range tt.expected {
				gotVals, ok := result[key]
				if !ok {
					t.Errorf("expected header %s, not found", key)
					continue
				}
				if len(gotVals) != len(expectedVals) {
					t.Errorf("for header %s: expected %d values, got %d", key, len(expectedVals), len(gotVals))
					continue
				}
				for i, v := range expectedVals {
					if gotVals[i] != v {
						t.Errorf("for header %s[%d]: expected %q, got %q", key, i, v, gotVals[i])
					}
				}
			}
		})
	}
}

func TestRedactSecretsInHeader(t *testing.T) {
	tests := []struct {
		name     string
		secrets  []CustomSecret
		value    string
		expected string
	}{
		{
			name:     "no secrets set",
			secrets:  nil,
			value:    "Bearer abc123",
			expected: "Bearer abc123",
		},
		{
			name:     "secret value redacted",
			secrets:  []CustomSecret{{Target: "api.com", EnvName: "TOKEN", Value: "abc123", Sentinel: "{{TOKEN}}"}},
			value:    "Bearer abc123",
			expected: "Bearer [REDACTED]",
		},
		{
			name: "multiple secrets redacted",
			secrets: []CustomSecret{
				{Target: "a.com", EnvName: "A", Value: "secretA", Sentinel: "{{A}}"},
				{Target: "b.com", EnvName: "B", Value: "secretB", Sentinel: "{{B}}"},
			},
			value:    "secretA and secretB",
			expected: "[REDACTED] and [REDACTED]",
		},
		{
			name:     "empty value",
			secrets:  []CustomSecret{{Target: "a.com", EnvName: "K", Value: "v", Sentinel: "{{K}}"}},
			value:    "",
			expected: "",
		},
		{
			name:     "empty secret value not redacted",
			secrets:  []CustomSecret{{Target: "a.com", EnvName: "K", Value: "", Sentinel: "{{K}}"}},
			value:    "hello",
			expected: "hello",
		},
		{
			name:     "secret value equals sentinel not redacted",
			secrets:  []CustomSecret{{Target: "a.com", EnvName: "K", Value: "{{K}}", Sentinel: "{{K}}"}},
			value:    "hello {{K}}",
			expected: "hello {{K}}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := NewSecretManager()
			sm.SetSecrets(tt.secrets)
			result := sm.RedactSecretsInHeader(tt.value)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestSecretManager_ConcurrentAccess(t *testing.T) {
	sm := NewSecretManager()

	done := make(chan bool)

	go func() {
		for i := 0; i < 100; i++ {
			sm.SetSecrets([]CustomSecret{
				{Target: "a.com", EnvName: "KEY", Value: "val", Sentinel: "{{KEY}}"},
			})
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 100; i++ {
			_ = sm.GetSecrets()
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 100; i++ {
			_ = sm.ReplaceSentinelsInBody([]byte("{{KEY}}"))
		}
		done <- true
	}()

	for i := 0; i < 3; i++ {
		<-done
	}
}