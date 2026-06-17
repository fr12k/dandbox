package ca

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestNewCACertManager(t *testing.T) {
	tmpDir := t.TempDir()
	caDir := filepath.Join(tmpDir, "ca")

	mgr, err := NewCACertManagerWithKeySize(caDir, 2048)
	if err != nil {
		t.Fatalf("NewCACertManager() error = %v", err)
	}
	if mgr == nil {
		t.Fatal("NewCACertManager() returned nil")
	}

	// Verify CA directory was created
	if _, err := os.Stat(caDir); os.IsNotExist(err) {
		t.Error("CA directory was not created")
	}

	// Verify cert and key files were created
	if _, err := os.Stat(mgr.CertPath()); os.IsNotExist(err) {
		t.Error("CA cert file was not created")
	}

	// Verify CACertPEM is not empty
	if len(mgr.CACertPEM()) == 0 {
		t.Error("CACertPEM() returned empty bytes")
	}
}

func TestNewCACertManager_LoadExisting(t *testing.T) {
	tmpDir := t.TempDir()
	caDir := filepath.Join(tmpDir, "ca")

	// Create first manager
	mgr1, err := NewCACertManagerWithKeySize(caDir, 2048)
	if err != nil {
		t.Fatalf("First NewCACertManager() error = %v", err)
	}
	fingerprint1 := mgr1.Fingerprint()

	// Load the same CA again
	mgr2, err := NewCACertManagerWithKeySize(caDir, 2048)
	if err != nil {
		t.Fatalf("Second NewCACertManager() error = %v", err)
	}
	fingerprint2 := mgr2.Fingerprint()

	// Should have the same fingerprint
	if fingerprint1 != fingerprint2 {
		t.Errorf("expected same fingerprint on reload, got %s vs %s", fingerprint1, fingerprint2)
	}
}

func TestFingerprint(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, err := NewCACertManagerWithKeySize(filepath.Join(tmpDir, "ca"), 2048)
	if err != nil {
		t.Fatalf("NewCACertManager() error = %v", err)
	}

	fp := mgr.Fingerprint()
	if fp == "" {
		t.Error("Fingerprint() returned empty string")
	}
	// SHA-1 fingerprint should be 40 hex chars
	if len(fp) != 40 {
		t.Errorf("expected 40-char fingerprint, got %d chars", len(fp))
	}
}

func TestCertPool(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, err := NewCACertManagerWithKeySize(filepath.Join(tmpDir, "ca"), 2048)
	if err != nil {
		t.Fatalf("NewCACertManager() error = %v", err)
	}

	pool := mgr.CertPool()
	if pool == nil {
		t.Error("CertPool() returned nil")
	}
}

func TestTLSConfig(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, err := NewCACertManagerWithKeySize(filepath.Join(tmpDir, "ca"), 2048)
	if err != nil {
		t.Fatalf("NewCACertManager() error = %v", err)
	}

	tlsConfig := mgr.TLSConfig()
	if tlsConfig.GetCertificate == nil {
		t.Error("TLSConfig().GetCertificate is nil")
	}
}

func TestGetCert(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, err := NewCACertManagerWithKeySize(filepath.Join(tmpDir, "ca"), 2048)
	if err != nil {
		t.Fatalf("NewCACertManager() error = %v", err)
	}

	hello := &tls.ClientHelloInfo{
		ServerName: "example.com",
	}

	cert, err := mgr.getCert(hello)
	if err != nil {
		t.Fatalf("getCert() error = %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Error("cert has no certificate data")
	}
}

func TestGetCert_EmptyServerName(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, err := NewCACertManagerWithKeySize(filepath.Join(tmpDir, "ca"), 2048)
	if err != nil {
		t.Fatalf("NewCACertManager() error = %v", err)
	}

	hello := &tls.ClientHelloInfo{
		ServerName: "",
	}

	cert, err := mgr.getCert(hello)
	if err != nil {
		t.Fatalf("getCert() error = %v", err)
	}
	if cert == nil {
		t.Fatal("getCert() returned nil cert for empty server name")
	}
	// Should default to "localhost"
}

func TestGetCert_Caching(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, err := NewCACertManagerWithKeySize(filepath.Join(tmpDir, "ca"), 2048)
	if err != nil {
		t.Fatalf("NewCACertManager() error = %v", err)
	}

	hello := &tls.ClientHelloInfo{
		ServerName: "cached.example.com",
	}

	// First call should generate and cache
	cert1, err := mgr.getCert(hello)
	if err != nil {
		t.Fatalf("first getCert() error = %v", err)
	}

	// Second call should return cached cert
	cert2, err := mgr.getCert(hello)
	if err != nil {
		t.Fatalf("second getCert() error = %v", err)
	}

	// Should be the same cached instance
	if cert1 != cert2 {
		t.Error("expected cached cert to be the same instance")
	}
}

func TestGenerateCert(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, err := NewCACertManagerWithKeySize(filepath.Join(tmpDir, "ca"), 2048)
	if err != nil {
		t.Fatalf("NewCACertManager() error = %v", err)
	}

	tests := []string{
		"example.com",
		"sub.example.com",
		"localhost",
		"*.wildcard.com",
		"192.168.1.1",
	}

	for _, host := range tests {
		t.Run(host, func(t *testing.T) {
			cert, err := mgr.generateCert(host)
			if err != nil {
				t.Fatalf("generateCert(%q) error = %v", host, err)
			}
			if len(cert.Certificate) == 0 {
				t.Errorf("cert for %q has no certificate data", host)
			}
			if cert.PrivateKey == nil {
				t.Errorf("cert for %q has no private key", host)
			}
		})
	}
}

func TestParseHosts(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{
			input:    "example.com",
			expected: []string{"example.com", "*.example.com"},
		},
		{
			input:    "example.com:443",
			expected: []string{"example.com", "*.example.com"},
		},
		{
			input:    "*.example.com",
			expected: []string{"*.example.com", "example.com"},
		},
		{
			input:    "192.168.1.1",
			expected: []string{"192.168.1.1", "*.192.168.1.1"},
		},
		{
			input:    "localhost",
			expected: []string{"localhost", "*.localhost"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			hosts := parseHosts(tt.input)
			if len(hosts) != len(tt.expected) {
				t.Errorf("parseHosts(%q) = %v, want %v", tt.input, hosts, tt.expected)
				return
			}
			for i, h := range hosts {
				if h != tt.expected[i] {
					t.Errorf("parseHosts(%q)[%d] = %q, want %q", tt.input, i, h, tt.expected[i])
				}
			}
		})
	}
}

func TestCACertPEM_NonEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, err := NewCACertManagerWithKeySize(filepath.Join(tmpDir, "ca"), 2048)
	if err != nil {
		t.Fatalf("NewCACertManager() error = %v", err)
	}

	pem := mgr.CACertPEM()
	if len(pem) == 0 {
		t.Error("CACertPEM() returned empty bytes")
	}
}

func TestGeneratedCertIsValid(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, err := NewCACertManagerWithKeySize(filepath.Join(tmpDir, "ca"), 2048)
	if err != nil {
		t.Fatalf("NewCACertManager() error = %v", err)
	}

	cert, err := mgr.generateCert("test.example.com")
	if err != nil {
		t.Fatalf("generateCert() error = %v", err)
	}

	// Parse the leaf certificate
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}

	// Verify subject
	if x509Cert.Subject.CommonName != "test.example.com" {
		t.Errorf("expected CommonName 'test.example.com', got %q", x509Cert.Subject.CommonName)
	}

	// Verify DNS names
	foundDNS := false
	for _, name := range x509Cert.DNSNames {
		if name == "test.example.com" {
			foundDNS = true
		}
	}
	if !foundDNS {
		t.Errorf("expected DNS SAN 'test.example.com', got %v", x509Cert.DNSNames)
	}

	// Verify it's a server auth cert
	foundServerAuth := false
	for _, eku := range x509Cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			foundServerAuth = true
		}
	}
	if !foundServerAuth {
		t.Error("certificate does not have ServerAuth key usage")
	}
}

func TestGeneratedCertSignedByCA(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, err := NewCACertManagerWithKeySize(filepath.Join(tmpDir, "ca"), 2048)
	if err != nil {
		t.Fatalf("NewCACertManager() error = %v", err)
	}

	cert, err := mgr.generateCert("verify.example.com")
	if err != nil {
		t.Fatalf("generateCert() error = %v", err)
	}

	// Verify that the cert can be verified against the CA pool
	certPool := mgr.CertPool()

	opts := x509.VerifyOptions{
		Roots: certPool,
		DNSName: "verify.example.com",
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}

	// Verify certificate chain
	if _, err := x509Cert.Verify(opts); err != nil {
		t.Errorf("certificate verification failed: %v", err)
	}
}

func TestConcurrentGetCert(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, err := NewCACertManagerWithKeySize(filepath.Join(tmpDir, "ca"), 2048)
	if err != nil {
		t.Fatalf("NewCACertManager() error = %v", err)
	}

	// Test concurrent cert generation doesn't panic
	errCh := make(chan error, 10)
	for i := 0; i < 10; i++ {
		go func(idx int) {
			host := "concurrent.example.com"
			hello := &tls.ClientHelloInfo{ServerName: host}
			_, err := mgr.getCert(hello)
			errCh <- err
		}(i)
	}

	for i := 0; i < 10; i++ {
		if err := <-errCh; err != nil {
			t.Errorf("concurrent getCert() error: %v", err)
		}
	}
}

func TestParseHosts_WithIP(t *testing.T) {
	ips := parseHosts("192.168.1.1")
	hasIP := false
	hasWildcard := false
	for _, h := range ips {
		if h == "192.168.1.1" {
			hasIP = true
		}
		if h == "*.192.168.1.1" {
			hasWildcard = true
		}
	}
	if !hasIP {
		t.Error("expected IP in parseHosts output")
	}
	if !hasWildcard {
		t.Error("expected wildcard in parseHosts output")
	}

	_ = net.ParseIP // just to use the import
}