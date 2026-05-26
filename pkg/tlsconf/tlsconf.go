// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

// Package tlsconf provides TLS configuration helpers for inter-service
// communication, including mTLS (mutual TLS) setup and certificate rotation.
package tlsconf

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// Config holds TLS configuration options for a service.
type Config struct {
	// CertFile is the path to the TLS certificate file (PEM).
	CertFile string
	// KeyFile is the path to the TLS private key file (PEM).
	KeyFile string
	// CAFile is the path to the CA certificate for verifying peers (mTLS).
	CAFile string
	// ServerName is the expected server name for TLS verification.
	ServerName string
	// MinVersion is the minimum TLS version (default: TLS 1.2).
	MinVersion uint16
	// ClientAuth specifies the client authentication policy (mTLS).
	ClientAuth tls.ClientAuthType
}

// NewServerTLSConfig creates a *tls.Config suitable for a TLS server.
// If CAFile is provided, client certificate verification is enabled (mTLS).
func NewServerTLSConfig(cfg *Config) (*tls.Config, error) {
	if cfg == nil {
		return nil, errors.New("TLS config is required")
	}

	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load server certificate: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   minVersionOrDefault(cfg.MinVersion),
		CipherSuites: preferredCipherSuites(),
	}

	if cfg.CAFile != "" {
		caPool, err := loadCAPool(cfg.CAFile)
		if err != nil {
			return nil, err
		}
		tlsCfg.ClientCAs = caPool
		tlsCfg.ClientAuth = cfg.ClientAuth
		if tlsCfg.ClientAuth == 0 {
			tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
		}
	}

	return tlsCfg, nil
}

// NewClientTLSConfig creates a *tls.Config suitable for a TLS client.
// If CertFile and KeyFile are provided, client certificate is presented (mTLS).
func NewClientTLSConfig(cfg *Config) (*tls.Config, error) {
	if cfg == nil {
		return nil, errors.New("TLS config is required")
	}

	tlsCfg := &tls.Config{
		MinVersion: minVersionOrDefault(cfg.MinVersion),
		ServerName: cfg.ServerName,
	}

	if cfg.CAFile != "" {
		caPool, err := loadCAPool(cfg.CAFile)
		if err != nil {
			return nil, err
		}
		tlsCfg.RootCAs = caPool
	}

	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return tlsCfg, nil
}

// CertReloader watches certificate files and reloads them on change.
// It enables zero-downtime certificate rotation by periodically checking
// the certificate modification time.
type CertReloader struct {
	certFile string
	keyFile  string

	mu      sync.RWMutex
	cert    *tls.Certificate
	certMod time.Time
	keyMod  time.Time

	stopCh   chan struct{}
	stopOnce sync.Once
}

// NewCertReloader creates a new certificate reloader.
func NewCertReloader(certFile, keyFile string) (*CertReloader, error) {
	r := &CertReloader{
		certFile: certFile,
		keyFile:  keyFile,
		stopCh:   make(chan struct{}),
	}
	if err := r.reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// GetCertificate returns the current certificate. It implements the
// tls.Config.GetCertificate callback signature.
func (r *CertReloader) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cert, nil
}

// GetClientCertificate returns the current certificate for client mTLS.
func (r *CertReloader) GetClientCertificate(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cert, nil
}

// Start begins periodic certificate reload checks at the given interval.
func (r *CertReloader) Start(interval time.Duration) {
	if interval <= 0 {
		slog.Error("certificate reloader interval must be positive", slog.Duration("interval", interval))
		return
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := r.reload(); err != nil {
					slog.Error("certificate reload failed", slog.String("error", err.Error()))
				}
			case <-r.stopCh:
				return
			}
		}
	}()
}

// Stop halts the periodic reload.
func (r *CertReloader) Stop() {
	r.stopOnce.Do(func() {
		close(r.stopCh)
	})
}

func (r *CertReloader) reload() error {
	certInfo, err := os.Stat(r.certFile)
	if err != nil {
		return err
	}

	keyInfo, err := os.Stat(r.keyFile)
	if err != nil {
		return err
	}

	r.mu.RLock()
	unchanged := certInfo.ModTime().Equal(r.certMod) && keyInfo.ModTime().Equal(r.keyMod)
	r.mu.RUnlock()
	if unchanged {
		return nil
	}

	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return fmt.Errorf("reload certificate: %w", err)
	}

	r.mu.Lock()
	r.cert = &cert
	r.certMod = certInfo.ModTime()
	r.keyMod = keyInfo.ModTime()
	r.mu.Unlock()
	return nil
}

// NewServerTLSConfigWithReloader creates a server TLS config that automatically
// reloads certificates when they change on disk.
func NewServerTLSConfigWithReloader(cfg *Config, reloadInterval time.Duration) (*tls.Config, *CertReloader, error) {
	if cfg == nil {
		return nil, nil, errors.New("TLS config is required")
	}

	reloader, err := NewCertReloader(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, nil, err
	}

	tlsCfg := &tls.Config{
		GetCertificate: reloader.GetCertificate,
		MinVersion:     minVersionOrDefault(cfg.MinVersion),
		CipherSuites:   preferredCipherSuites(),
	}

	if cfg.CAFile != "" {
		caPool, err := loadCAPool(cfg.CAFile)
		if err != nil {
			return nil, nil, err
		}
		tlsCfg.ClientCAs = caPool
		tlsCfg.ClientAuth = cfg.ClientAuth
		if tlsCfg.ClientAuth == 0 {
			tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
		}
	}

	reloader.Start(reloadInterval)
	return tlsCfg, reloader, nil
}

func loadCAPool(caFile string) (*x509.CertPool, error) {
	caPEM, err := os.ReadFile(caFile) //nolint:gosec // CA file path is from trusted server config
	if err != nil {
		return nil, fmt.Errorf("read CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("failed to parse CA certificate")
	}
	return pool, nil
}

func minVersionOrDefault(v uint16) uint16 {
	if v == 0 {
		return tls.VersionTLS12
	}
	return v
}

// preferredCipherSuites returns the recommended cipher suites for TLS 1.2.
// TLS 1.3 cipher suites are not configurable (Go handles them automatically).
func preferredCipherSuites() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}
}
