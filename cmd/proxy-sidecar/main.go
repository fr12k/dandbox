package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/fr12k/dandbox/internal/ca"
	"github.com/fr12k/dandbox/internal/policy"
	"github.com/fr12k/dandbox/internal/proxy"
	"github.com/fr12k/dandbox/internal/secrets"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmsgprefix)
	log.SetPrefix("[proxy-sidecar] ")

	proxyAddr := flag.String("proxy-addr", ":3128", "Address for the MITM proxy to listen on")
	caDir := flag.String("ca-dir", "", "Directory containing CA certificate and key")
	policyDir := flag.String("policy-dir", "", "Directory containing policy rules")
	secretsFile := flag.String("secrets-file", "", "Path to JSON file with initial secrets")
	sandboxName := flag.String("sandbox", "", "Sandbox name for scoped policy evaluation")
	maxConns := flag.Int64("max-connections", 0, "Maximum concurrent connections (0 = unlimited)")
	rawTCPIdleTimeout := flag.Duration("raw-tcp-idle-timeout", 0, "Idle timeout for raw TCP/SOCKS5 tunnels (e.g. 30m, 0 = unlimited)")
	flag.Parse()

	// CA certificate directory — default to env or well-known path
	if *caDir == "" {
		*caDir = os.Getenv("PROXY_CA_DIR")
	}
	if *caDir == "" {
		*caDir = filepath.Join("/etc", "sbxsandbox", "ca")
	}

	// Policy directory
	if *policyDir == "" {
		*policyDir = os.Getenv("PROXY_POLICY_DIR")
	}
	if *policyDir == "" {
		*policyDir = filepath.Join("/etc", "sbxsandbox", "policy")
	}

	log.Printf("Starting proxy-sidecar for sandbox %q", *sandboxName)
	log.Printf("  Proxy addr: %s", *proxyAddr)
	log.Printf("  CA dir:     %s", *caDir)
	log.Printf("  Policy dir: %s", *policyDir)

	// Initialize CA
	certManager, err := ca.NewCACertManager(*caDir)
	if err != nil {
		log.Fatalf("Failed to initialize CA: %v", err)
	}
	log.Printf("CA loaded (cert: %s)", certManager.CertPath())

	// Initialize policy engine
	pol, err := policy.NewEngine(*policyDir)
	if err != nil {
		log.Fatalf("Failed to initialize policy: %v", err)
	}

	// Load policy rules from environment (sent by daemon at container start)
	if envRules := os.Getenv("PROXY_RULES_JSON"); envRules != "" {
		var rules []policy.Rule
		if err := json.Unmarshal([]byte(envRules), &rules); err == nil {
			pol.LoadRules(rules)
			log.Printf("Loaded %d policy rules from environment", len(rules))
		} else {
			log.Printf("Warning: failed to parse PROXY_RULES_JSON: %v", err)
		}
	}
	log.Printf("Policy engine loaded (%d rules)", len(pol.ListRules()))

	// Initialize secret manager (secrets are loaded at runtime via POST /secrets/reload)
	sec := secrets.NewSecretManager()

	// Load initial secrets from a mounted file if provided
	if *secretsFile != "" {
		data, err := os.ReadFile(*secretsFile)
		if err == nil {
			var secs []secrets.CustomSecret
			if err := json.Unmarshal(data, &secs); err == nil {
				sec.SetSecrets(secs)
				log.Printf("Loaded %d secrets from %s", len(secs), *secretsFile)
			}
		}
	}
	log.Printf("Secret manager initialized (no env vars used)")

	// Create the proxy
	pxy := proxy.NewProxy(certManager, pol, sec, *proxyAddr)
	pxy.SetSandboxName(*sandboxName)

	// Feature flags
	pxy.SetSOCKS5Enabled(true)
	pxy.SetRawTCPEnabled(true)

	// Connection limits
	if *maxConns > 0 {
		pxy.SetMaxConnections(*maxConns)
		log.Printf("  Max connections: %d", *maxConns)
	}

	// Idle timeout for raw TCP / SOCKS5 tunnels
	if *rawTCPIdleTimeout > 0 {
		pxy.SetRawTCPIdleTimeout(*rawTCPIdleTimeout)
		log.Printf("  Raw TCP idle timeout: %v", *rawTCPIdleTimeout)
	}

	// Start the proxy (non-blocking, serves in background)
	if err := pxy.Start(); err != nil {
		log.Fatalf("Failed to start proxy: %v", err)
	}
	log.Printf("Proxy listening on %s (HTTP/SOCKS5/RawTCP)", pxy.Addr().String())

	// Start a simple health endpoint on a separate port
	go startHealthServer(pxy, sec, *sandboxName)

	// Wait for signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	for {
		sig := <-quit
		switch sig {
		case syscall.SIGHUP:
			log.Printf("Received SIGHUP, reloading configuration...")
			// Reload policy from disk
			newPolicy, err := policy.NewEngine(*policyDir)
			if err != nil {
				log.Printf("Failed to reload policy: %v", err)
			} else {
				_ = newPolicy
				log.Printf("Policy reload would apply here")
			}
		case syscall.SIGINT, syscall.SIGTERM:
			log.Printf("Received signal %v, shutting down...", sig)
			if err := pxy.Stop(); err != nil {
				log.Printf("Error stopping proxy: %v", err)
			}
			log.Printf("Shutdown complete")
			return
		}
	}
}

func startHealthServer(pxy *proxy.Proxy, sec *secrets.SecretManager, sandboxName string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":  "healthy",
			"sandbox": sandboxName,
		})
	})
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		addr := "unknown"
		if a := pxy.Addr(); a != nil {
			addr = a.String()
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":     "ready",
			"proxy_addr": addr,
		})
	})

	// Metrics endpoint — hand-rolled Prometheus text format
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		m := pxy.Metrics()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `# HELP proxy_connections_total Total connections by protocol
# TYPE proxy_connections_total counter
proxy_connections_total{protocol="http"} %d
proxy_connections_total{protocol="connect"} %d
proxy_connections_total{protocol="socks5"} %d
proxy_connections_total{protocol="rawtcp"} %d
# HELP proxy_connections_denied_total Total connections denied by policy
# TYPE proxy_connections_denied_total counter
proxy_connections_denied_total %d
# HELP proxy_active_connections Current number of active connections
# TYPE proxy_active_connections gauge
proxy_active_connections %d
`,
			m.HTTPTotal, m.CONNECTTotal, m.SOCKS5Total, m.RawTCPTotal,
			m.DeniedTotal, m.ActiveConns)
	})

	// Policy reload endpoint — accepts new rules via POST JSON body
	mux.HandleFunc("/policy/reload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			Rules []policy.Rule `json:"rules"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		if len(req.Rules) > 0 {
			pxy.Policy().LoadRules(req.Rules)
			log.Printf("Reloaded %d policy rules", len(req.Rules))
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "ok",
			"rules":  pxy.Policy().ListRules(),
		})
	})

	// Secrets reload endpoint — receives secrets via POST (no env vars)
	mux.HandleFunc("/secrets/reload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			Secrets []secrets.CustomSecret `json:"secrets"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		pxy.Secrets().SetSecrets(req.Secrets)
		log.Printf("Reloaded %d secrets", len(req.Secrets))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "ok",
			"secrets": len(req.Secrets),
		})
	})

	server := &http.Server{
		Addr:         "127.0.0.1:9099",
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  10 * time.Second,
	}

	log.Printf("[proxy-sidecar] Health server listening on 127.0.0.1:9099 (loopback only)")
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("[proxy-sidecar] Health server error: %v", err)
	}
}

func init() {
	if os.Getenv("CONTAINER") != "" {
		log.SetFlags(log.Ldate | log.Ltime)
	}
}
