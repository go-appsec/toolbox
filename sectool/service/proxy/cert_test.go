package proxy

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCertManager(t *testing.T) {
	t.Parallel()

	t.Run("generates_new_ca", func(t *testing.T) {
		t.Parallel()

		tempDir := t.TempDir()

		cm, err := newCertManager(tempDir)
		require.NoError(t, err)
		require.NotNil(t, cm)
		t.Cleanup(func() { _ = cm.Close() })

		certPath := filepath.Join(tempDir, "ca.pem")
		keyPath := filepath.Join(tempDir, "ca-key.pem")

		_, err = os.Stat(certPath)
		require.NoError(t, err)

		_, err = os.Stat(keyPath)
		require.NoError(t, err)

		keyInfo, _ := os.Stat(keyPath)
		assert.Equal(t, os.FileMode(0600), keyInfo.Mode().Perm())
	})

	t.Run("loads_existing_ca", func(t *testing.T) {
		t.Parallel()

		tempDir := t.TempDir()

		cm1, err := newCertManager(tempDir)
		require.NoError(t, err)
		caCert1 := cm1.CACert()
		require.NoError(t, cm1.Close())

		cm2, err := newCertManager(tempDir)
		require.NoError(t, err)
		t.Cleanup(func() { _ = cm2.Close() })
		caCert2 := cm2.CACert()

		assert.Equal(t, caCert1.Raw, caCert2.Raw)
	})

	t.Run("error_on_orphaned_cert", func(t *testing.T) {
		t.Parallel()

		tempDir := t.TempDir()

		err := os.WriteFile(filepath.Join(tempDir, "ca.pem"), []byte("dummy"), 0644)
		require.NoError(t, err)

		_, err = newCertManager(tempDir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key is missing")
	})

	t.Run("error_on_orphaned_key", func(t *testing.T) {
		t.Parallel()

		tempDir := t.TempDir()

		err := os.WriteFile(filepath.Join(tempDir, "ca-key.pem"), []byte("dummy"), 0600)
		require.NoError(t, err)

		_, err = newCertManager(tempDir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "certificate is missing")
	})

	t.Run("error_on_invalid_cert_pem", func(t *testing.T) {
		t.Parallel()

		tempDir := t.TempDir()

		// Write invalid PEM content (not a valid PEM block)
		err := os.WriteFile(filepath.Join(tempDir, "ca.pem"), []byte("not a valid pem"), 0644)
		require.NoError(t, err)
		err = os.WriteFile(filepath.Join(tempDir, "ca-key.pem"), []byte("dummy key"), 0600)
		require.NoError(t, err)

		_, err = newCertManager(tempDir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parse CA certificate PEM")
	})

	t.Run("error_on_invalid_key_pem", func(t *testing.T) {
		t.Parallel()

		tempDir := t.TempDir()

		// First generate valid CA to get a valid cert
		cm, err := newCertManager(tempDir)
		require.NoError(t, err)
		require.NoError(t, cm.Close())

		// Overwrite key with invalid PEM
		err = os.WriteFile(filepath.Join(tempDir, "ca-key.pem"), []byte("not a valid pem"), 0600)
		require.NoError(t, err)

		_, err = newCertManager(tempDir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parse CA key PEM")
	})

	t.Run("error_on_invalid_cert_der", func(t *testing.T) {
		t.Parallel()

		tempDir := t.TempDir()

		// Valid PEM wrapper but garbage DER content
		invalidCertPEM := "-----BEGIN CERTIFICATE-----\nZHVtbXkgY2VydCBkYXRh\n-----END CERTIFICATE-----\n"
		err := os.WriteFile(filepath.Join(tempDir, "ca.pem"), []byte(invalidCertPEM), 0644)
		require.NoError(t, err)

		invalidKeyPEM := "-----BEGIN RSA PRIVATE KEY-----\nZHVtbXkga2V5IGRhdGE=\n-----END RSA PRIVATE KEY-----\n"
		err = os.WriteFile(filepath.Join(tempDir, "ca-key.pem"), []byte(invalidKeyPEM), 0600)
		require.NoError(t, err)

		_, err = newCertManager(tempDir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parse CA certificate")
	})

	t.Run("error_on_non_ca_cert", func(t *testing.T) {
		t.Parallel()

		tempDir := t.TempDir()

		// Generate valid CA first
		cm, err := newCertManager(tempDir)
		require.NoError(t, err)

		// Generate a leaf certificate (not CA)
		leafCert, err := cm.GetCertificate("example.com")
		require.NoError(t, err)
		require.NoError(t, cm.Close())

		// Overwrite CA cert with leaf cert
		leafCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Certificate[0]})
		err = os.WriteFile(filepath.Join(tempDir, "ca.pem"), leafCertPEM, 0644)
		require.NoError(t, err)

		_, err = newCertManager(tempDir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a CA certificate")
	})

	t.Run("error_on_expired_ca_cert", func(t *testing.T) {
		t.Parallel()

		tempDir := t.TempDir()

		// Generate valid CA first to get a valid key
		cm, err := newCertManager(tempDir)
		require.NoError(t, err)

		// Create an expired certificate
		expiredTemplate := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               cm.caCert.Subject,
			NotBefore:             time.Now().Add(-2 * 365 * 24 * time.Hour),
			NotAfter:              time.Now().Add(-1 * 365 * 24 * time.Hour), // expired 1 year ago
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}

		expiredCertDER, err := x509.CreateCertificate(rand.Reader, expiredTemplate, expiredTemplate, cm.caKey.Public(), cm.caKey)
		require.NoError(t, err)
		require.NoError(t, cm.Close())

		expiredCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: expiredCertDER})
		err = os.WriteFile(filepath.Join(tempDir, "ca.pem"), expiredCertPEM, 0644)
		require.NoError(t, err)

		_, err = newCertManager(tempDir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expired")
	})

	t.Run("error_on_missing_key_usage_cert_sign", func(t *testing.T) {
		t.Parallel()

		tempDir := t.TempDir()

		// Generate valid CA first to get a valid key
		cm, err := newCertManager(tempDir)
		require.NoError(t, err)

		// Create a CA cert missing KeyUsageCertSign
		badTemplate := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               cm.caCert.Subject,
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().AddDate(10, 0, 0),
			KeyUsage:              x509.KeyUsageCRLSign, // missing KeyUsageCertSign
			BasicConstraintsValid: true,
			IsCA:                  true,
		}

		badCertDER, err := x509.CreateCertificate(rand.Reader, badTemplate, badTemplate, cm.caKey.Public(), cm.caKey)
		require.NoError(t, err)
		require.NoError(t, cm.Close())

		badCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: badCertDER})
		err = os.WriteFile(filepath.Join(tempDir, "ca.pem"), badCertPEM, 0644)
		require.NoError(t, err)

		_, err = newCertManager(tempDir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "lacks KeyUsageCertSign")
	})
}

func TestGetCertificate(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	cm, err := newCertManager(tempDir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = cm.Close() })

	t.Run("hostname_cert", func(t *testing.T) {
		cert, err := cm.GetCertificate("example.com")
		require.NoError(t, err)
		require.NotNil(t, cert)

		x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
		require.NoError(t, err)

		assert.Equal(t, "example.com", x509Cert.Subject.CommonName)
		assert.Contains(t, x509Cert.DNSNames, "example.com")
		assert.True(t, x509Cert.NotBefore.Before(time.Now()))
		assert.True(t, x509Cert.NotAfter.After(time.Now()))
	})

	t.Run("cached_cert", func(t *testing.T) {
		cert1, err := cm.GetCertificate("cached.example.com")
		require.NoError(t, err)

		cert2, err := cm.GetCertificate("cached.example.com")
		require.NoError(t, err)

		// Compare DER bytes (deserialized copies won't be pointer-equal)
		assert.Equal(t, cert1.Certificate, cert2.Certificate)
	})

	t.Run("ip_address_cert", func(t *testing.T) {
		cert, err := cm.GetCertificate("192.168.1.1")
		require.NoError(t, err)
		require.NotNil(t, cert)

		x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
		require.NoError(t, err)

		assert.Empty(t, x509Cert.DNSNames)
		assert.Len(t, x509Cert.IPAddresses, 1)
		assert.Equal(t, "192.168.1.1", x509Cert.IPAddresses[0].String())
	})

	t.Run("certificate_chain", func(t *testing.T) {
		cert, err := cm.GetCertificate("chain.example.com")
		require.NoError(t, err)

		assert.Len(t, cert.Certificate, 2)

		leafCert, err := x509.ParseCertificate(cert.Certificate[0])
		require.NoError(t, err)
		caCert, err := x509.ParseCertificate(cert.Certificate[1])
		require.NoError(t, err)

		err = leafCert.CheckSignatureFrom(caCert)
		assert.NoError(t, err)
	})

	t.Run("ipv6_address_cert", func(t *testing.T) {
		ipv6Addresses := []string{"::1", "2001:db8::1"}

		for _, addr := range ipv6Addresses {
			cert, err := cm.GetCertificate(addr)
			require.NoError(t, err)
			require.NotNil(t, cert)

			x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
			require.NoError(t, err)

			assert.Empty(t, x509Cert.DNSNames)
			assert.Len(t, x509Cert.IPAddresses, 1)
			assert.Equal(t, addr, x509Cert.IPAddresses[0].String())
		}
	})

	t.Run("wildcard_hostname", func(t *testing.T) {
		cert, err := cm.GetCertificate("*.example.com")
		require.NoError(t, err)
		require.NotNil(t, cert)

		x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
		require.NoError(t, err)

		assert.Contains(t, x509Cert.DNSNames, "*.example.com")
	})

	t.Run("hostname_with_trailing_dot", func(t *testing.T) {
		cert, err := cm.GetCertificate("example.com.")
		require.NoError(t, err)
		require.NotNil(t, cert)

		x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
		require.NoError(t, err)

		assert.Contains(t, x509Cert.DNSNames, "example.com.")
	})

	t.Run("very_long_hostname", func(t *testing.T) {
		// DNS name max is 253 chars, test near this limit
		longHostname := "a." + string(make([]byte, 240)) // will have invalid chars but tests handling
		for i := range longHostname {
			if longHostname[i] == 0 {
				longHostname = longHostname[:i] + "x" + longHostname[i+1:]
			}
		}
		longHostname = "abcdefghij." + "x.y.z.a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w" + ".example.com"
		cert, err := cm.GetCertificate(longHostname)
		require.NoError(t, err)
		require.NotNil(t, cert)

		x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
		require.NoError(t, err)

		assert.Contains(t, x509Cert.DNSNames, longHostname)
	})

	t.Run("punycode_hostname", func(t *testing.T) {
		// IDN in punycode form
		cert, err := cm.GetCertificate("xn--nxasmq5b.com")
		require.NoError(t, err)
		require.NotNil(t, cert)

		x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
		require.NoError(t, err)

		assert.Contains(t, x509Cert.DNSNames, "xn--nxasmq5b.com")
	})

	t.Run("empty_hostname_cert", func(t *testing.T) {
		cert, err := cm.GetCertificate("")
		require.NoError(t, err)
		require.NotNil(t, cert)

		x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
		require.NoError(t, err)

		// Empty hostname should be treated as DNS name, not IP
		assert.Contains(t, x509Cert.DNSNames, "")
		assert.Empty(t, x509Cert.IPAddresses)
	})

	t.Run("concurrent_same_hostname", func(t *testing.T) {
		const hostname = "concurrent.example.com"
		const goroutines = 10

		type result struct {
			certDER [][]byte
			err     error
		}
		results := make(chan result, goroutines)

		for i := 0; i < goroutines; i++ {
			go func() {
				cert, err := cm.GetCertificate(hostname)
				if err != nil {
					results <- result{err: err}
					return
				}
				results <- result{certDER: cert.Certificate}
			}()
		}

		var certs [][][]byte
		for i := 0; i < goroutines; i++ {
			r := <-results
			require.NoError(t, r.err)
			certs = append(certs, r.certDER)
		}

		// All should return the same certificate chain
		for _, certDER := range certs[1:] {
			assert.Equal(t, certs[0], certDER)
		}
	})

	t.Run("concurrent_different_hostnames", func(t *testing.T) {
		const goroutines = 10
		hostnames := make([]string, goroutines)
		for i := 0; i < goroutines; i++ {
			hostnames[i] = fmt.Sprintf("concurrent-%d.example.com", i)
		}

		var wg sync.WaitGroup
		certDERs := make([][][]byte, goroutines)
		errors := make([]error, goroutines)

		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				cert, err := cm.GetCertificate(hostnames[idx])
				if err != nil {
					errors[idx] = err
					return
				}
				certDERs[idx] = cert.Certificate
			}(i)
		}

		wg.Wait()

		// All should succeed with unique certs
		for i := 0; i < goroutines; i++ {
			require.NoError(t, errors[i])
			require.NotNil(t, certDERs[i])

			x509Cert, err := x509.ParseCertificate(certDERs[i][0])
			require.NoError(t, err)
			assert.Equal(t, hostnames[i], x509Cert.Subject.CommonName)
		}
	})

	t.Run("certificate_validity_window", func(t *testing.T) {
		cert, err := cm.GetCertificate("validity.example.com")
		require.NoError(t, err)

		x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
		require.NoError(t, err)

		now := time.Now()
		// NotBefore should be ~1 hour before now (clock skew tolerance)
		assert.True(t, x509Cert.NotBefore.Before(now))
		assert.True(t, x509Cert.NotBefore.After(now.Add(-2*time.Hour)))
		// NotAfter should be ~1 year in the future
		assert.True(t, x509Cert.NotAfter.After(now.Add(364*24*time.Hour)))
		assert.True(t, x509Cert.NotAfter.Before(now.Add(366*24*time.Hour)))
	})

	t.Run("certificate_key_usage", func(t *testing.T) {
		cert, err := cm.GetCertificate("keyusage.example.com")
		require.NoError(t, err)

		x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
		require.NoError(t, err)

		// Verify KeyUsage
		assert.NotEqual(t, x509.KeyUsage(0), x509Cert.KeyUsage&x509.KeyUsageDigitalSignature)
		assert.NotEqual(t, x509.KeyUsage(0), x509Cert.KeyUsage&x509.KeyUsageKeyEncipherment)
		// Verify ExtKeyUsage
		assert.Contains(t, x509Cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	})

	t.Run("certificate_serial_uniqueness", func(t *testing.T) {
		cert1, err := cm.GetCertificate("serial1.example.com")
		require.NoError(t, err)
		cert2, err := cm.GetCertificate("serial2.example.com")
		require.NoError(t, err)

		x509Cert1, err := x509.ParseCertificate(cert1.Certificate[0])
		require.NoError(t, err)
		x509Cert2, err := x509.ParseCertificate(cert2.Certificate[0])
		require.NoError(t, err)

		assert.NotEqual(t, x509Cert1.SerialNumber, x509Cert2.SerialNumber)
	})
}

func TestCACert(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	cm, err := newCertManager(tempDir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = cm.Close() })

	caCert := cm.CACert()
	require.NotNil(t, caCert)

	assert.True(t, caCert.IsCA)
	assert.NotEqual(t, x509.KeyUsage(0), caCert.KeyUsage&x509.KeyUsageCertSign)
	assert.Equal(t, "sectool CA", caCert.Subject.CommonName)
	assert.Contains(t, caCert.Subject.Organization, "sectool")

	// Verify validity window
	now := time.Now()
	assert.True(t, caCert.NotBefore.Before(now))
	assert.True(t, caCert.NotBefore.After(now.Add(-2*time.Hour)))
	// NotAfter should be ~10 years in the future
	assert.True(t, caCert.NotAfter.After(now.AddDate(9, 0, 0)))
	assert.True(t, caCert.NotAfter.Before(now.AddDate(11, 0, 0)))

	// Verify MaxPathLen constraints
	assert.Equal(t, 0, caCert.MaxPathLen)
	assert.True(t, caCert.MaxPathLenZero)
}

func TestCACertConcurrentReads(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	cm, err := newCertManager(tempDir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = cm.Close() })

	const goroutines = 20
	var wg sync.WaitGroup
	results := make([]*x509.Certificate, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = cm.CACert()
		}(i)
	}
	wg.Wait()

	// All should return the same CA certificate
	for i := 1; i < goroutines; i++ {
		assert.Equal(t, results[0].Raw, results[i].Raw)
	}
}
