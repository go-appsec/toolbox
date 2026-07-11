package proxy

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-appsec/toolbox/sectool/service/dedupe"
	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
	"github.com/go-appsec/toolbox/sectool/service/store"
)

const (
	caCertFile = "ca.pem"
	caKeyFile  = "ca-key.pem"
)

// certCacheEntry is the serializable form of a tls.Certificate for SpillStore.
type certCacheEntry struct {
	CertChain  [][]byte `msgpack:"c"`
	PrivateKey []byte   `msgpack:"k"` // PKCS8 DER
}

// CertManager handles CA certificate loading/generation and on-demand
// certificate generation for HTTPS MITM interception.
type CertManager struct {
	mu     sync.Mutex
	caCert *x509.Certificate
	caKey  crypto.Signer // supports RSA, ECDSA, and Ed25519 keys

	// cache stores generated certificates by hostname
	cache store.Storage
}

// newCertManager loads or generates a CA certificate.
// configDir is the directory for CA files (typically ~/.sectool).
func newCertManager(configDir string) (*CertManager, error) {
	cache, err := store.NewSpillStore(store.DefaultSpillStoreConfig())
	if err != nil {
		return nil, fmt.Errorf("create cert cache: %w", err)
	}
	m := &CertManager{
		cache: cache,
	}

	if err := m.loadOrGenerateCA(configDir); err != nil {
		_ = cache.Close()
		return nil, err
	}

	return m, nil
}

// GetCertificate returns a certificate for the hostname, whose SANs additionally
// include any names in spec (nil spec yields a single-SAN leaf).
// Generates and caches if not already cached.
func (m *CertManager) GetCertificate(hostname string, spec *types.CertSpec) (*tls.Certificate, error) {
	key := certCacheKey(hostname, spec)

	// Fast path: check cache (SpillStore is thread-safe)
	cert, err := m.getCachedCert(key)
	if err != nil {
		return nil, err
	} else if cert != nil {
		return cert, nil
	}

	// Slow path: generate under lock to avoid duplicate generation
	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check after acquiring lock
	cert, err = m.getCachedCert(key)
	if err != nil {
		return nil, err
	} else if cert != nil {
		return cert, nil
	}

	cert, err = m.generateCertificate(hostname, spec)
	if err != nil {
		return nil, fmt.Errorf("generate certificate for %s: %w", hostname, err)
	} else if err := m.storeCert(key, cert); err != nil {
		return nil, fmt.Errorf("cache certificate for %s: %w", hostname, err)
	}
	return cert, nil
}

// certCacheKey derives an order-independent cache key from the hostname and any
// additive SANs, so a host served with and without mirrored SANs (or across an
// upstream SAN rotation) does not collide on a stale leaf.
func certCacheKey(hostname string, spec *types.CertSpec) string {
	if spec.Empty() {
		return hostname
	}
	var b strings.Builder
	b.WriteString(hostname)
	appendSorted := func(tag string, vals []string) {
		if len(vals) == 0 {
			return
		}
		vals = slices.Clone(vals)
		slices.Sort(vals)
		b.WriteByte(0)
		b.WriteString(tag)
		for _, v := range vals {
			b.WriteByte(0)
			b.WriteString(v)
		}
	}
	appendSorted("d", spec.DNSNames)
	appendSorted("i", ipStrings(spec.IPAddresses))
	appendSorted("u", uriStrings(spec.URIs))
	appendSorted("e", spec.Emails)
	if spec.CommonName != "" {
		appendSorted("c", []string{spec.CommonName})
	}
	return b.String()
}

// CACert returns the CA certificate for clients to trust.
func (m *CertManager) CACert() *x509.Certificate {
	return m.caCert
}

// Close releases resources held by the cert cache.
func (m *CertManager) Close() error {
	return m.cache.Close()
}

// getCachedCert retrieves a certificate from the SpillStore cache by cache key.
func (m *CertManager) getCachedCert(key string) (*tls.Certificate, error) {
	data, found, err := m.cache.Get(key)
	if err != nil {
		return nil, fmt.Errorf("cert cache get: %w", err)
	} else if !found {
		return nil, nil
	}
	return deserializeCert(data)
}

// storeCert serializes and stores a certificate in the SpillStore cache by cache key.
func (m *CertManager) storeCert(key string, cert *tls.Certificate) error {
	data, err := serializeCert(cert)
	if err != nil {
		return err
	}
	return m.cache.Set(key, data)
}

func serializeCert(cert *tls.Certificate) ([]byte, error) {
	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	return store.Serialize(certCacheEntry{
		CertChain:  cert.Certificate,
		PrivateKey: privKeyBytes,
	})
}

func deserializeCert(data []byte) (*tls.Certificate, error) {
	var entry certCacheEntry
	if err := store.Deserialize(data, &entry); err != nil {
		return nil, fmt.Errorf("deserialize cert: %w", err)
	}
	privKey, err := x509.ParsePKCS8PrivateKey(entry.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("parse cached private key: %w", err)
	}
	return &tls.Certificate{
		Certificate: entry.CertChain,
		PrivateKey:  privKey,
	}, nil
}

// loadOrGenerateCA loads existing CA or generates a new one.
func (m *CertManager) loadOrGenerateCA(configDir string) error {
	certPath := filepath.Join(configDir, caCertFile)
	keyPath := filepath.Join(configDir, caKeyFile)

	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)
	certExists := certErr == nil
	keyExists := keyErr == nil

	// Error if only one file exists (orphaned state)
	if certExists != keyExists {
		if certExists {
			return fmt.Errorf("CA certificate exists at %s but key is missing at %s; delete both to regenerate", certPath, keyPath)
		}
		return fmt.Errorf("CA key exists at %s but certificate is missing at %s; delete both to regenerate", keyPath, certPath)
	}

	now := time.Now()
	if !certExists { // generate a new CA
		key, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return fmt.Errorf("generate key: %w", err)
		}

		serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			return fmt.Errorf("generate serial: %w", err)
		}

		template := &x509.Certificate{
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				Organization: []string{"go-appsec toolbox"},
				CommonName:   "go-appsec sectool CA",
			},
			NotBefore:             now.Add(-time.Hour), // clock skew tolerance
			NotAfter:              now.AddDate(10, 0, 0),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
			MaxPathLen:            0,
			MaxPathLenZero:        true,
		}

		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			return fmt.Errorf("create certificate: %w", err)
		}

		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return fmt.Errorf("parse certificate: %w", err)
		}

		if err := os.MkdirAll(configDir, 0755); err != nil {
			return fmt.Errorf("create config dir: %w", err)
		}

		certPath := filepath.Join(configDir, caCertFile)
		certFile, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			return fmt.Errorf("create cert file: %w", err)
		}
		defer func() { _ = certFile.Close() }()
		if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
			return fmt.Errorf("write cert: %w", err)
		}

		// Write key (restricted permissions)
		keyPath := filepath.Join(configDir, caKeyFile)
		keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return fmt.Errorf("create key file: %w", err)
		}
		defer func() { _ = keyFile.Close() }()
		if err := pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
			return fmt.Errorf("write key: %w", err)
		}

		m.caCert = cert
		m.caKey = key
		log.Printf("proxy: generated CA certificate at %s", certPath)
		return nil
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("read CA certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read CA key: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return errors.New("failed to parse CA certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse CA certificate: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return errors.New("failed to parse CA key PEM")
	}
	key, err := parsePrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse CA key: %w", err)
	}

	if !cert.IsCA {
		return fmt.Errorf("certificate at %s is not a CA certificate; delete both files to regenerate", certPath)
	} else if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("certificate at %s lacks KeyUsageCertSign; delete both files to regenerate", certPath)
	} else if now.After(cert.NotAfter) {
		return fmt.Errorf("certificate at %s has expired; delete both files to regenerate", certPath)
	}

	m.caCert = cert
	m.caKey = key
	log.Printf("proxy: loaded CA certificate from %s", certPath)
	return nil
}

// generateCertificate creates a certificate for the given hostname, signed by the
// CA. Its SANs are {hostname} plus any additive names in spec (nil for single-SAN).
func (m *CertManager) generateCertificate(hostname string, spec *types.CertSpec) (*tls.Certificate, error) {
	// Generate RSA key (2048-bit for speed)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: hostname,
		},
		NotBefore:   now.Add(-time.Hour), // clock skew tolerance
		NotAfter:    now.AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	// Base SAN from the hostname (DNS or IP), then additive names from spec
	var dnsNames []string
	var ips []net.IP
	if ip := net.ParseIP(hostname); ip != nil {
		ips = append(ips, ip)
	} else {
		dnsNames = append(dnsNames, hostname)
	}
	if spec != nil {
		dnsNames = append(dnsNames, spec.DNSNames...)
		ips = append(ips, spec.IPAddresses...)
		template.URIs = dedupeURIs(spec.URIs)
		template.EmailAddresses = dedupe.Slice(spec.Emails)
		// Upstream/declared CN joins the SAN set (DNS, or IP if it parses as one)
		if spec.CommonName != "" {
			if ip := net.ParseIP(spec.CommonName); ip != nil {
				ips = append(ips, ip)
			} else {
				dnsNames = append(dnsNames, spec.CommonName)
			}
		}
	}
	template.DNSNames = dedupe.Slice(dnsNames)
	template.IPAddresses = dedupeIPs(ips)

	certDER, err := x509.CreateCertificate(rand.Reader, template, m.caCert, &key.PublicKey, m.caKey)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{certDER, m.caCert.Raw},
		PrivateKey:  key,
	}

	return cert, nil
}

// ipStrings renders IPs to their canonical string form.
func ipStrings(ips []net.IP) []string {
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = ip.String()
	}
	return out
}

// uriStrings renders URIs to their string form.
func uriStrings(uris []*url.URL) []string {
	out := make([]string, len(uris))
	for i, u := range uris {
		out[i] = u.String()
	}
	return out
}

// dedupeIPs removes duplicate IPs (by canonical string), preserving first-seen order.
func dedupeIPs(ips []net.IP) []net.IP {
	if len(ips) < 2 {
		return ips
	}
	seen := make(map[string]struct{}, len(ips))
	out := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		k := ip.String()
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, ip)
	}
	return out
}

// dedupeURIs removes duplicate URIs (by string form), preserving first-seen order.
func dedupeURIs(uris []*url.URL) []*url.URL {
	if len(uris) < 2 {
		return uris
	}
	seen := make(map[string]struct{}, len(uris))
	out := make([]*url.URL, 0, len(uris))
	for _, u := range uris {
		k := u.String()
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, u)
	}
	return out
}

// parsePrivateKey tries to parse a private key in various formats.
// Supports PKCS#8 (RSA, ECDSA, Ed25519), PKCS#1 (RSA), and SEC1 (ECDSA).
func parsePrivateKey(der []byte) (crypto.Signer, error) {
	// Try PKCS#8 first (most common for modern tools)
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if signer, ok := key.(crypto.Signer); ok {
			return signer, nil
		}
		return nil, errors.New("PKCS#8 key does not implement crypto.Signer")
	}

	// Try RSA PKCS#1
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}

	// Try ECDSA SEC1
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("failed to parse private key (tried PKCS#8, PKCS#1, SEC1)")
}
