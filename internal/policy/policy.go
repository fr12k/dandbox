// Package policy implements network access policy evaluation for the MITM proxy.
// It provides rule-based allow/deny decisions with wildcard matching and
// per-sandbox scoping.
package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Decision is the result of a policy evaluation.
type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
)

// Rule defines a single network access rule.
type Rule struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Decision  string   `json:"decision"`        // "allow" or "deny"
	Resources []string `json:"resources"`       // "host:port", "*.domain:port"
	Scope     string   `json:"scope,omitempty"` // empty = global, otherwise sandbox name
}

// Engine evaluates network access requests against rules.
type Engine struct {
	mu          sync.RWMutex
	rules       []Rule
	nextID      int
	policyPath  string
	defaultMode string // "deny-all", "allow-all", "balanced"
}

// NewEngine creates a policy engine with optional persistence.
func NewEngine(policyDir string) (*Engine, error) {
	if policyDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("get home dir: %w", err)
		}
		policyDir = filepath.Join(home, ".config", "sbxsandbox", "policy")
	}
	if err := os.MkdirAll(policyDir, 0700); err != nil {
		return nil, fmt.Errorf("create policy dir: %w", err)
	}

	pe := &Engine{
		policyPath:  filepath.Join(policyDir, "rules.json"),
		defaultMode: "balanced",
	}

	// Always start with deny-by-default rules, regardless of saved state.
	// Users can add allow rules via the API at runtime.
	pe.rules = defaultRules()
	pe.nextID = len(pe.rules) + 1
	_ = pe.save()
	return pe, nil
}

func defaultRules() []Rule {
	rules := []Rule{
		{ID: "default-deny-all-https", Name: "deny-all-https", Decision: "deny", Resources: []string{"*:443"}},
		{ID: "default-deny-all-http", Name: "deny-all-http", Decision: "deny", Resources: []string{"*:80"}},
	}
	return rules
}

func (pe *Engine) save() error {
	data, err := json.MarshalIndent(pe.rules, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(pe.policyPath, data, 0644)
}

// LoadRules replaces the current rules with the given list.
// Used to propagate rules from the daemon to a proxy sidecar.
func (pe *Engine) LoadRules(rules []Rule) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	pe.rules = make([]Rule, len(rules))
	copy(pe.rules, rules)
	// Find the highest ID to set nextID
	maxID := 0
	for _, r := range pe.rules {
		var num int
		if _, err := fmt.Sscanf(r.ID, "rule-%d", &num); err == nil && num > maxID {
			maxID = num
		}
	}
	pe.nextID = maxID + 1
	_ = pe.save()
}

// Evaluate checks whether a request to host:port is allowed.
// Returns decision and which rule matched.
//
// Evaluation order (more specific beats less specific):
//  1. Exact-match allow rules (full host + port match)
//  2. Exact-match deny rules
//  3. Wildcard allow rules (pattern matches)
//  4. Wildcard deny rules
//  5. Fallthrough → DENY
func (pe *Engine) Evaluate(host string, port string, sandboxName string) (Decision, string) {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	hostPort := host + ":" + port

	exactAllow := false
	exactDeny := false
	wildcardAllow := false
	wildcardDeny := false
	allowRuleID := ""
	denyRuleID := ""

	for _, rule := range pe.rules {
		if rule.Scope != "" && rule.Scope != sandboxName {
			continue
		}
		if !matchesResource(hostPort, rule.Resources) {
			continue
		}

		// Determine if this is an exact or wildcard match
		isExact := false
		for _, res := range rule.Resources {
			if !isWildcardPattern(res) {
				isExact = true
				break
			}
		}

		switch rule.Decision {
		case "allow":
			if isExact {
				exactAllow = true
				allowRuleID = rule.ID
			} else {
				wildcardAllow = true
				allowRuleID = rule.ID
			}
		case "deny":
			if isExact {
				exactDeny = true
				denyRuleID = rule.ID
			} else {
				wildcardDeny = true
				denyRuleID = rule.ID
			}
		}
	}

	// Priority: exact allow > exact deny > wildcard allow > wildcard deny
	if exactAllow {
		return DecisionAllow, allowRuleID
	}
	if exactDeny {
		return DecisionDeny, denyRuleID
	}
	if wildcardAllow {
		return DecisionAllow, allowRuleID
	}
	if wildcardDeny {
		return DecisionDeny, denyRuleID
	}

	// Default
	if pe.defaultMode == "allow-all" {
		return DecisionAllow, "default-allow"
	}
	return DecisionDeny, "default-deny"
}

// isWildcardPattern returns true if the resource pattern contains wildcards.
func isWildcardPattern(pattern string) bool {
	return strings.Contains(pattern, "*") || strings.Contains(pattern, "**")
}

// matchesResource checks if hostPort matches any pattern in resources.
func matchesResource(hostPort string, resources []string) bool {
	for _, pattern := range resources {
		if matchHostPort(hostPort, pattern) {
			return true
		}
	}
	return false
}

// matchHostPort matches a host:port against a pattern.
// Patterns support:
//   - exact: "api.example.com:443"
//   - wildcard subdomain: "*.example.com:443" matches "sub.api.example.com:443"
//   - wildcard all: "*:443" matches any host on port 443
//   - wildcard all with **: "**:443" matches everything on port 443
func matchHostPort(target, pattern string) bool {
	if pattern == "*:*" || pattern == "**" {
		return true
	}

	targetHost, targetPort, err := netSplitHostPort(target)
	if err != nil {
		return false
	}
	patHost, patPort, err := netSplitHostPort(pattern)
	if err != nil {
		return false
	}

	// Port must match if specified
	if patPort != "" && patPort != targetPort {
		return false
	}

	// Host matching
	if patHost == "*" || patHost == "**" {
		return true
	}

	if strings.HasPrefix(patHost, "**.") {
		// **.example.com matches example.com and sub.example.com
		suffix := patHost[1:] // "*.example.com"
		if strings.HasSuffix(targetHost, suffix[1:]) {
			return true
		}
	}

	if strings.HasPrefix(patHost, "*.") {
		// *.example.com matches sub.example.com but not example.com
		suffix := patHost[1:] // ".example.com"
		return strings.HasSuffix(targetHost, suffix) && !strings.EqualFold(targetHost, suffix[1:])
	}

	return strings.EqualFold(targetHost, patHost)
}

func netSplitHostPort(hostPort string) (host, port string, err error) {
	if idx := strings.LastIndex(hostPort, ":"); idx >= 0 {
		host = hostPort[:idx]
		port = hostPort[idx+1:]
		return host, port, nil
	}
	return hostPort, "", fmt.Errorf("no port in %q", hostPort)
}

// AddRule adds a new policy rule.
func (pe *Engine) AddRule(name, decision string, resources []string, scope string) (*Rule, error) {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	id := fmt.Sprintf("rule-%d", pe.nextID)
	pe.nextID++

	rule := Rule{
		ID:        id,
		Name:      name,
		Decision:  decision,
		Resources: resources,
		Scope:     scope,
	}
	pe.rules = append(pe.rules, rule)
	_ = pe.save()
	return &rule, nil
}

// RemoveRule removes a rule by ID.
func (pe *Engine) RemoveRule(id string) bool {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	for i, rule := range pe.rules {
		if rule.ID == id {
			pe.rules = append(pe.rules[:i], pe.rules[i+1:]...)
			_ = pe.save()
			return true
		}
	}
	return false
}

// ListRules returns a copy of all rules.
func (pe *Engine) ListRules() []Rule {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	r := make([]Rule, len(pe.rules))
	copy(r, pe.rules)
	return r
}
