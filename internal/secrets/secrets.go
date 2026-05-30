// Package secrets manages secret sentinel replacement in HTTP traffic.
// Secrets are defined as sentinel placeholders that get replaced with actual
// values in HTTP headers and bodies when proxying traffic.
package secrets

import (
	"bytes"
	"strings"
	"sync"
)

// CustomSecret defines a secret that should be replaced when seen in HTTP traffic.
type CustomSecret struct {
	Target   string `json:"target"`   // host domain
	EnvName  string `json:"env_name"` // env variable name
	Sentinel string `json:"sentinel"` // placeholder sentinel string
	Value    string `json:"value"`    // actual secret value
}

// SecretManager holds cleartext secrets and provides body/handler replacement.
type SecretManager struct {
	mu      sync.RWMutex
	secrets []CustomSecret
}

// NewSecretManager creates a secret manager.
func NewSecretManager() *SecretManager {
	return &SecretManager{}
}

// SetSecrets replaces the current secret list.
func (sm *SecretManager) SetSecrets(secrets []CustomSecret) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.secrets = secrets
}

// GetSecrets returns a copy of all secrets.
func (sm *SecretManager) GetSecrets() []CustomSecret {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	r := make([]CustomSecret, len(sm.secrets))
	copy(r, sm.secrets)
	return r
}

// ReplaceSentinelsInBody replaces sentinel placeholders with actual secret values
// in the HTTP request/response body.
func (sm *SecretManager) ReplaceSentinelsInBody(body []byte) []byte {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	if len(sm.secrets) == 0 {
		return body
	}
	result := body
	for _, s := range sm.secrets {
		if s.Sentinel != "" && bytes.Contains(result, []byte(s.Sentinel)) {
			result = bytes.ReplaceAll(result, []byte(s.Sentinel), []byte(s.Value))
		}
	}
	return result
}

// ReplaceSentinelsInHeaders replaces sentinel placeholders in HTTP headers.
func (sm *SecretManager) ReplaceSentinelsInHeaders(headers map[string][]string) map[string][]string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	if len(sm.secrets) == 0 {
		return headers
	}
	result := make(map[string][]string, len(headers))
	for k, vals := range headers {
		newVals := make([]string, len(vals))
		for i, v := range vals {
			newV := v
			for _, s := range sm.secrets {
				if s.Sentinel != "" && bytes.Contains([]byte(newV), []byte(s.Sentinel)) {
					newV = string(bytes.ReplaceAll([]byte(newV), []byte(s.Sentinel), []byte(s.Value)))
				}
			}
			newVals[i] = newV
		}
		result[k] = newVals
	}
	return result
}

// RedactSecretsInHeader redacts secret values in a header value for logging.
func (sm *SecretManager) RedactSecretsInHeader(value string) string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	redacted := value
	for _, s := range sm.secrets {
		if s.Value != "" && s.Value != s.Sentinel && strings.Contains(redacted, s.Value) {
			redacted = strings.ReplaceAll(redacted, s.Value, "[REDACTED]")
		}
	}
	return redacted
}
