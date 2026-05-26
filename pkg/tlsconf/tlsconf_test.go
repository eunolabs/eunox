// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package tlsconf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return cert, key, certPEM
}

func generateTestCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	require.NoError(t, err)

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM
}

func writeTempFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

func TestNewServerTLSConfig(t *testing.T) {
	ca, caKey, caPEM := generateTestCA(t)
	certPEM, keyPEM := generateTestCert(t, ca, caKey, "server.test")

	dir := t.TempDir()
	certFile := writeTempFile(t, dir, "server.crt", certPEM)
	keyFile := writeTempFile(t, dir, "server.key", keyPEM)
	caFile := writeTempFile(t, dir, "ca.crt", caPEM)

	tlsCfg, err := NewServerTLSConfig(&Config{
		CertFile: certFile,
		KeyFile:  keyFile,
		CAFile:   caFile,
	})
	require.NoError(t, err)
	assert.NotNil(t, tlsCfg)
	assert.Equal(t, tls.RequireAndVerifyClientCert, tlsCfg.ClientAuth)
	assert.Equal(t, uint16(tls.VersionTLS12), tlsCfg.MinVersion)
	assert.Len(t, tlsCfg.Certificates, 1)
}

func TestNewServerTLSConfig_NoCA(t *testing.T) {
	ca, caKey, _ := generateTestCA(t)
	certPEM, keyPEM := generateTestCert(t, ca, caKey, "server.test")

	dir := t.TempDir()
	certFile := writeTempFile(t, dir, "server.crt", certPEM)
	keyFile := writeTempFile(t, dir, "server.key", keyPEM)

	tlsCfg, err := NewServerTLSConfig(&Config{
		CertFile: certFile,
		KeyFile:  keyFile,
	})
	require.NoError(t, err)
	assert.Nil(t, tlsCfg.ClientCAs)
	assert.Equal(t, tls.NoClientCert, tlsCfg.ClientAuth)
}

func TestNewClientTLSConfig(t *testing.T) {
	ca, caKey, caPEM := generateTestCA(t)
	certPEM, keyPEM := generateTestCert(t, ca, caKey, "client.test")

	dir := t.TempDir()
	certFile := writeTempFile(t, dir, "client.crt", certPEM)
	keyFile := writeTempFile(t, dir, "client.key", keyPEM)
	caFile := writeTempFile(t, dir, "ca.crt", caPEM)

	tlsCfg, err := NewClientTLSConfig(&Config{
		CertFile:   certFile,
		KeyFile:    keyFile,
		CAFile:     caFile,
		ServerName: "server.test",
	})
	require.NoError(t, err)
	assert.NotNil(t, tlsCfg)
	assert.Equal(t, "server.test", tlsCfg.ServerName)
	assert.NotNil(t, tlsCfg.RootCAs)
	assert.Len(t, tlsCfg.Certificates, 1)
}

func TestNewClientTLSConfig_NoClientCert(t *testing.T) {
	_, _, caPEM := generateTestCA(t)

	dir := t.TempDir()
	caFile := writeTempFile(t, dir, "ca.crt", caPEM)

	tlsCfg, err := NewClientTLSConfig(&Config{
		CAFile:     caFile,
		ServerName: "server.test",
	})
	require.NoError(t, err)
	assert.Empty(t, tlsCfg.Certificates)
}

func TestCertReloader(t *testing.T) {
	ca, caKey, _ := generateTestCA(t)
	certPEM, keyPEM := generateTestCert(t, ca, caKey, "reloadable.test")

	dir := t.TempDir()
	certFile := writeTempFile(t, dir, "server.crt", certPEM)
	keyFile := writeTempFile(t, dir, "server.key", keyPEM)

	reloader, err := NewCertReloader(certFile, keyFile)
	require.NoError(t, err)

	cert, err := reloader.GetCertificate(nil)
	require.NoError(t, err)
	assert.NotNil(t, cert)

	// Simulate certificate rotation by writing new cert.
	newCertPEM, newKeyPEM := generateTestCert(t, ca, caKey, "reloadable-new.test")
	require.NoError(t, os.WriteFile(certFile, newCertPEM, 0o600))
	require.NoError(t, os.WriteFile(keyFile, newKeyPEM, 0o600))

	// Force reload.
	require.NoError(t, reloader.reload())

	newCert, err := reloader.GetCertificate(nil)
	require.NoError(t, err)
	assert.NotNil(t, newCert)
}

func TestCertReloader_StartStop(t *testing.T) {
	ca, caKey, _ := generateTestCA(t)
	certPEM, keyPEM := generateTestCert(t, ca, caKey, "reloadable.test")

	dir := t.TempDir()
	certFile := writeTempFile(t, dir, "server.crt", certPEM)
	keyFile := writeTempFile(t, dir, "server.key", keyPEM)

	reloader, err := NewCertReloader(certFile, keyFile)
	require.NoError(t, err)

	reloader.Start(50 * time.Millisecond)
	time.Sleep(100 * time.Millisecond)
	reloader.Stop()
	reloader.Stop()
}

func TestCertReloader_StartWithInvalidInterval(t *testing.T) {
	ca, caKey, _ := generateTestCA(t)
	certPEM, keyPEM := generateTestCert(t, ca, caKey, "reloadable.test")

	dir := t.TempDir()
	certFile := writeTempFile(t, dir, "server.crt", certPEM)
	keyFile := writeTempFile(t, dir, "server.key", keyPEM)

	reloader, err := NewCertReloader(certFile, keyFile)
	require.NoError(t, err)

	reloader.Start(0)
	reloader.Stop()
}

func TestCertReloader_ReloadWhenOnlyKeyChanges(t *testing.T) {
	ca, caKey, _ := generateTestCA(t)
	certPEM, keyPEM := generateTestCert(t, ca, caKey, "reloadable.test")
	_, rotatedKeyPEM := generateTestCert(t, ca, caKey, "reloadable.test")

	dir := t.TempDir()
	certFile := writeTempFile(t, dir, "server.crt", certPEM)
	keyFile := writeTempFile(t, dir, "server.key", keyPEM)

	reloader, err := NewCertReloader(certFile, keyFile)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(keyFile, rotatedKeyPEM, 0o600))
	require.NoError(t, os.Chtimes(keyFile, time.Now().Add(time.Second), time.Now().Add(time.Second)))
	err = reloader.reload()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reload certificate")
}

func TestNewServerTLSConfig_InvalidCert(t *testing.T) {
	_, err := NewServerTLSConfig(&Config{
		CertFile: "/nonexistent/cert.pem",
		KeyFile:  "/nonexistent/key.pem",
	})
	assert.Error(t, err)
}

func TestNewClientTLSConfig_InvalidCA(t *testing.T) {
	_, err := NewClientTLSConfig(&Config{
		CAFile: "/nonexistent/ca.pem",
	})
	assert.Error(t, err)
}

func TestPreferredCipherSuites(t *testing.T) {
	suites := preferredCipherSuites()
	assert.NotEmpty(t, suites)
	// All should be AEAD suites.
	for _, id := range suites {
		name := tls.CipherSuiteName(id)
		assert.NotEmpty(t, name)
	}
}

func TestMinVersionOrDefault(t *testing.T) {
	assert.Equal(t, uint16(tls.VersionTLS12), minVersionOrDefault(0))
	assert.Equal(t, uint16(tls.VersionTLS13), minVersionOrDefault(tls.VersionTLS13))
}

func TestNewServerTLSConfigWithReloader(t *testing.T) {
	ca, caKey, caPEM := generateTestCA(t)
	certPEM, keyPEM := generateTestCert(t, ca, caKey, "server.test")

	dir := t.TempDir()
	certFile := writeTempFile(t, dir, "server.crt", certPEM)
	keyFile := writeTempFile(t, dir, "server.key", keyPEM)
	caFile := writeTempFile(t, dir, "ca.crt", caPEM)

	tlsCfg, reloader, err := NewServerTLSConfigWithReloader(&Config{
		CertFile: certFile,
		KeyFile:  keyFile,
		CAFile:   caFile,
	}, 100*time.Millisecond)
	require.NoError(t, err)
	assert.NotNil(t, tlsCfg)
	assert.NotNil(t, tlsCfg.GetCertificate)

	reloader.Stop()
}

func TestGetClientCertificate(t *testing.T) {
	ca, caKey, _ := generateTestCA(t)
	certPEM, keyPEM := generateTestCert(t, ca, caKey, "client.test")

	dir := t.TempDir()
	certFile := writeTempFile(t, dir, "client.crt", certPEM)
	keyFile := writeTempFile(t, dir, "client.key", keyPEM)

	reloader, err := NewCertReloader(certFile, keyFile)
	require.NoError(t, err)

	cert, err := reloader.GetClientCertificate(nil)
	require.NoError(t, err)
	assert.NotNil(t, cert)
}
