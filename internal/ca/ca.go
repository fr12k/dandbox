// Package ca provides a CA certificate manager that generates dynamic TLS
// certificates for MITM proxying. It loads or creates a root CA and creates
// per-host TLS certificates on the fly.
package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// CACertManager handles CA certificate loading and dynamic TLS cert generation.
type CACertManager struct {
	caCert    *x509.Certificate
	caKey     interface{}
	caCertPEM []byte
	caKeyPEM  []byte
	certPath  string
	keyPath   string
	certPool  *x509.CertPool
	mu        sync.RWMutex
	certCache map[string]*tls.Certificate
	caKeySize int // RSA key size for CA key generation
}

// NewCACertManager loads or creates a CA certificate with the default 4096-bit key.
func NewCACertManager(caDir string) (*CACertManager, error) {
	return NewCACertManagerWithKeySize(caDir, 4096)
}

// NewCACertManagerWithKeySize loads or creates a CA certificate with the given RSA key size.
// A smaller key size (e.g. 2048) can be used in tests for faster key generation.
func NewCACertManagerWithKeySize(caDir string, keySize int) (*CACertManager, error) {
	if caDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("get home dir: %w", err)
		}
		caDir = filepath.Join(home, ".config", "sbxsandbox", "ca")
	}

	if err := os.MkdirAll(caDir, 0700); err != nil {
		return nil, fmt.Errorf("create CA dir: %w", err)
	}

	certPath := filepath.Join(caDir, "ca-cert.pem")
	keyPath := filepath.Join(caDir, "ca-key.pem")

	m := &CACertManager{
		certPath:  certPath,
		keyPath:   keyPath,
		certCache: make(map[string]*tls.Certificate),
		caKeySize: keySize,
	}

	// Try loading existing CA
	if err := m.loadCA(); err != nil {
		// Create a new CA
		if err := m.createCA(); err != nil {
			return nil, fmt.Errorf("create CA: %w", err)
		}
		if err := m.saveCA(); err != nil {
			return nil, fmt.Errorf("save CA: %w", err)
		}
	}

	// Build cert pool
	m.certPool = x509.NewCertPool()
	m.certPool.AppendCertsFromPEM(m.caCertPEM)

	return m, nil
}

func (m *CACertManager) loadCA() error {
	certPEM, err := os.ReadFile(m.certPath)
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(m.keyPath)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("failed to decode CA cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode CA key PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse CA key: %w", err)
	}

	m.caCert = cert
	m.caKey = key
	m.caCertPEM = certPEM
	m.caKeyPEM = keyPEM
	return nil
}

func (m *CACertManager) createCA() error {
	keySize := m.caKeySize
	if keySize == 0 {
		keySize = 4096
	}
	key, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return fmt.Errorf("generate CA key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "dandbox CA",
			Organization: []string{"dandbox"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create CA cert: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("parse CA cert: %w", err)
	}

	m.caCert = cert
	m.caKey = key
	m.caCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal CA key: %w", err)
	}
	m.caKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})

	return nil
}

func (m *CACertManager) saveCA() error {
	if err := os.WriteFile(m.certPath, m.caCertPEM, 0644); err != nil {
		return err
	}
	return os.WriteFile(m.keyPath, m.caKeyPEM, 0600)
}

// CertPath returns the path to the CA certificate file.
func (m *CACertManager) CertPath() string {
	return m.certPath
}

// CACertPEM returns the CA certificate in PEM format.
func (m *CACertManager) CACertPEM() []byte {
	return m.caCertPEM
}

// TLSConfig returns a TLS config that dynamically generates per-host certs.
func (m *CACertManager) TLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: m.getCert,
	}
}

func (m *CACertManager) getCert(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := hello.ServerName
	if host == "" {
		host = "localhost"
	}

	m.mu.RLock()
	cached, ok := m.certCache[host]
	m.mu.RUnlock()
	if ok {
		return cached, nil
	}

	cert, err := m.generateCert(host)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	m.certCache[host] = cert
	m.mu.Unlock()

	return cert, nil
}

func (m *CACertManager) generateCert(host string) (*tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   host,
			Organization: []string{"dandbox"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Add SANs
	hosts := parseHosts(host)
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, m.caCert, &key.PublicKey, m.caKey)
	if err != nil {
		return nil, fmt.Errorf("create cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyBytes, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse key pair: %w", err)
	}

	return &tlsCert, nil
}

// CertPool returns the CA certificate pool for TLS verification.
func (m *CACertManager) CertPool() *x509.CertPool {
	return m.certPool
}

// Fingerprint returns the SHA-1 fingerprint of the CA certificate.
func (m *CACertManager) Fingerprint() string {
	if m.caCert == nil {
		return ""
	}
	return fmt.Sprintf("%x", sha1.Sum(m.caCert.Raw))
}

// parseHosts extracts hostnames and IPs from a host string.
func parseHosts(host string) []string {
	// Remove port if present
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	hosts := []string{host}

	// Add wildcard variants
	if strings.HasPrefix(host, "*.") {
		hosts = append(hosts, host[2:])
	} else if !strings.Contains(host, "*") {
		hosts = append(hosts, "*."+host)
	}

	return hosts
}
