// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// Transport errors.
var (
	ErrTransportClosed  = errors.New("audit: transport is closed")
	ErrTransportTimeout = errors.New("audit: transport delivery timeout")
	ErrBatchFull        = errors.New("audit: batch buffer full")
)

// OCSFTransport delivers signed OCSF audit events to external SIEM sinks.
type OCSFTransport interface {
	// Send delivers a batch of signed audit evidence records to the sink.
	Send(ctx context.Context, records []SignedAuditEvidence) error
	// Close flushes pending events and releases resources.
	Close() error
}

// TransportConfig holds configuration for OCSF transports.
type TransportConfig struct {
	// BatchSize is the maximum number of records per batch.
	BatchSize int
	// FlushInterval is the maximum time between flushes.
	FlushInterval time.Duration
	// MaxRetries is the maximum number of delivery retries.
	MaxRetries int
	// RetryBackoff is the initial backoff duration between retries.
	RetryBackoff time.Duration
	// BufferSize is the size of the internal event buffer.
	BufferSize int
}

// DefaultTransportConfig returns sensible default transport configuration.
func DefaultTransportConfig() TransportConfig {
	return TransportConfig{
		BatchSize:     100,
		FlushInterval: 5 * time.Second,
		MaxRetries:    3,
		RetryBackoff:  1 * time.Second,
		BufferSize:    10000,
	}
}

// --- HTTP Transport (Generic Webhook / Splunk HEC) ---

// HTTPTransportConfig configures the HTTP transport.
type HTTPTransportConfig struct {
	TransportConfig
	// Endpoint is the URL to POST events to.
	Endpoint string
	// AuthHeader is the authorization header value (e.g., "Splunk <token>").
	AuthHeader string
	// ContentType override (default: application/json).
	ContentType string
	// Headers are additional HTTP headers to include.
	Headers map[string]string
}

// HTTPTransport delivers OCSF events via HTTP POST.
type HTTPTransport struct {
	config HTTPTransportConfig
	client *http.Client
	logger *slog.Logger

	buffer chan *SignedAuditEvidence
	wg     sync.WaitGroup
	done   chan struct{}
	closed bool
	mu     sync.Mutex
}

// NewHTTPTransport creates a new HTTP-based OCSF transport.
func NewHTTPTransport(cfg HTTPTransportConfig, logger *slog.Logger) *HTTPTransport {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = DefaultTransportConfig().BatchSize
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = DefaultTransportConfig().FlushInterval
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = DefaultTransportConfig().MaxRetries
	}
	if cfg.RetryBackoff <= 0 {
		cfg.RetryBackoff = DefaultTransportConfig().RetryBackoff
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = DefaultTransportConfig().BufferSize
	}
	if cfg.ContentType == "" {
		cfg.ContentType = "application/json"
	}
	if logger == nil {
		logger = slog.Default()
	}

	t := &HTTPTransport{
		config: cfg,
		client: &http.Client{Timeout: 30 * time.Second},
		logger: logger,
		buffer: make(chan *SignedAuditEvidence, cfg.BufferSize),
		done:   make(chan struct{}),
	}

	t.wg.Add(1)
	go t.flushLoop()

	return t
}

// Enqueue adds a single record to the transport buffer for batched delivery.
func (t *HTTPTransport) Enqueue(evidence *SignedAuditEvidence) error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return ErrTransportClosed
	}
	t.mu.Unlock()

	select {
	case t.buffer <- evidence:
		return nil
	default:
		return ErrBatchFull
	}
}

// Send delivers a batch of records immediately (bypasses internal buffer).
func (t *HTTPTransport) Send(ctx context.Context, records []SignedAuditEvidence) error {
	if len(records) == 0 {
		return nil
	}
	return t.deliverWithRetry(ctx, records)
}

// Close flushes remaining events and stops the background flush loop.
func (t *HTTPTransport) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	t.mu.Unlock()

	close(t.done)
	t.wg.Wait()

	// Flush remaining buffer.
	t.flushBuffer()
	return nil
}

func (t *HTTPTransport) flushLoop() {
	defer t.wg.Done()

	ticker := time.NewTicker(t.config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-t.done:
			return
		case <-ticker.C:
			t.flushBuffer()
		}
	}
}

func (t *HTTPTransport) flushBuffer() {
	batch := make([]SignedAuditEvidence, 0, t.config.BatchSize)

	for {
		select {
		case ev := <-t.buffer:
			batch = append(batch, *ev)
			if len(batch) >= t.config.BatchSize {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				if err := t.deliverWithRetry(ctx, batch); err != nil {
					t.logger.Error("audit transport: delivery failed",
						"error", err, "batch_size", len(batch))
				}
				cancel()
				batch = batch[:0]
			}
		default:
			// No more buffered events.
			if len(batch) > 0 {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				if err := t.deliverWithRetry(ctx, batch); err != nil {
					t.logger.Error("audit transport: delivery failed",
						"error", err, "batch_size", len(batch))
				}
				cancel()
			}
			return
		}
	}
}

func (t *HTTPTransport) deliverWithRetry(ctx context.Context, records []SignedAuditEvidence) error {
	var lastErr error
	backoff := t.config.RetryBackoff

	for attempt := 0; attempt <= t.config.MaxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return fmt.Errorf("audit: transport context cancelled: %w", ctx.Err())
			case <-time.After(backoff):
				backoff *= 2
			}
		}

		err := t.deliver(ctx, records)
		if err == nil {
			return nil
		}
		lastErr = err
		t.logger.Warn("audit transport: delivery attempt failed",
			"attempt", attempt+1, "error", err)
	}

	return fmt.Errorf("audit: transport delivery failed after %d retries: %w",
		t.config.MaxRetries+1, lastErr)
}

func (t *HTTPTransport) deliver(ctx context.Context, records []SignedAuditEvidence) error {
	body, err := json.Marshal(records)
	if err != nil {
		return fmt.Errorf("audit: marshal batch: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.config.Endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("audit: create request: %w", err)
	}

	req.Header.Set("Content-Type", t.config.ContentType)
	if t.config.AuthHeader != "" {
		req.Header.Set("Authorization", t.config.AuthHeader)
	}
	for k, v := range t.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("audit: HTTP request failed: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	return fmt.Errorf("audit: HTTP transport returned status %d", resp.StatusCode)
}

// --- Azure Sentinel Transport ---

// AzureSentinelConfig configures the Azure Sentinel transport.
type AzureSentinelConfig struct {
	TransportConfig
	// WorkspaceID is the Log Analytics workspace ID.
	WorkspaceID string
	// SharedKey is the workspace shared key for HMAC authentication.
	SharedKey string
	// LogType is the custom log type name (table name in Log Analytics).
	LogType string
	// Endpoint override (default: constructed from WorkspaceID).
	Endpoint string
}

// AzureSentinelTransport delivers OCSF events to Azure Sentinel (Log Analytics).
type AzureSentinelTransport struct {
	config AzureSentinelConfig
	client *http.Client
	logger *slog.Logger

	buffer chan *SignedAuditEvidence
	wg     sync.WaitGroup
	done   chan struct{}
	closed bool
	mu     sync.Mutex
}

// NewAzureSentinelTransport creates a new Azure Sentinel transport.
func NewAzureSentinelTransport(cfg AzureSentinelConfig, logger *slog.Logger) *AzureSentinelTransport {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = DefaultTransportConfig().BatchSize
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = DefaultTransportConfig().FlushInterval
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = DefaultTransportConfig().MaxRetries
	}
	if cfg.RetryBackoff <= 0 {
		cfg.RetryBackoff = DefaultTransportConfig().RetryBackoff
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = DefaultTransportConfig().BufferSize
	}
	if cfg.LogType == "" {
		cfg.LogType = "EunoAudit"
	}
	if cfg.Endpoint == "" && cfg.WorkspaceID != "" {
		cfg.Endpoint = fmt.Sprintf(
			"https://%s.ods.opinsights.azure.com/api/logs?api-version=2016-04-01",
			cfg.WorkspaceID,
		)
	}
	if logger == nil {
		logger = slog.Default()
	}

	t := &AzureSentinelTransport{
		config: cfg,
		client: &http.Client{Timeout: 30 * time.Second},
		logger: logger,
		buffer: make(chan *SignedAuditEvidence, cfg.BufferSize),
		done:   make(chan struct{}),
	}

	t.wg.Add(1)
	go t.flushLoop()

	return t
}

// Enqueue adds a single record to the Azure Sentinel transport buffer.
func (t *AzureSentinelTransport) Enqueue(evidence *SignedAuditEvidence) error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return ErrTransportClosed
	}
	t.mu.Unlock()

	select {
	case t.buffer <- evidence:
		return nil
	default:
		return ErrBatchFull
	}
}

// Send delivers a batch of records immediately to Azure Sentinel.
func (t *AzureSentinelTransport) Send(ctx context.Context, records []SignedAuditEvidence) error {
	if len(records) == 0 {
		return nil
	}
	return t.deliverWithRetry(ctx, records)
}

// Close flushes remaining events and stops the background loop.
func (t *AzureSentinelTransport) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	t.mu.Unlock()

	close(t.done)
	t.wg.Wait()

	// Flush remaining buffer.
	t.flushBuffer()
	return nil
}

func (t *AzureSentinelTransport) flushLoop() {
	defer t.wg.Done()

	ticker := time.NewTicker(t.config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-t.done:
			return
		case <-ticker.C:
			t.flushBuffer()
		}
	}
}

func (t *AzureSentinelTransport) flushBuffer() {
	batch := make([]SignedAuditEvidence, 0, t.config.BatchSize)

	for {
		select {
		case ev := <-t.buffer:
			batch = append(batch, *ev)
			if len(batch) >= t.config.BatchSize {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				if err := t.deliverWithRetry(ctx, batch); err != nil {
					t.logger.Error("azure sentinel transport: delivery failed",
						"error", err, "batch_size", len(batch))
				}
				cancel()
				batch = batch[:0]
			}
		default:
			if len(batch) > 0 {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				if err := t.deliverWithRetry(ctx, batch); err != nil {
					t.logger.Error("azure sentinel transport: delivery failed",
						"error", err, "batch_size", len(batch))
				}
				cancel()
			}
			return
		}
	}
}

func (t *AzureSentinelTransport) deliverWithRetry(ctx context.Context, records []SignedAuditEvidence) error {
	var lastErr error
	backoff := t.config.RetryBackoff

	for attempt := 0; attempt <= t.config.MaxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return fmt.Errorf("audit: sentinel context cancelled: %w", ctx.Err())
			case <-time.After(backoff):
				backoff *= 2
			}
		}

		err := t.deliver(ctx, records)
		if err == nil {
			return nil
		}
		lastErr = err
		t.logger.Warn("azure sentinel transport: delivery attempt failed",
			"attempt", attempt+1, "error", err)
	}

	return fmt.Errorf("audit: sentinel delivery failed after %d retries: %w",
		t.config.MaxRetries+1, lastErr)
}

func (t *AzureSentinelTransport) deliver(ctx context.Context, records []SignedAuditEvidence) error {
	body, err := json.Marshal(records)
	if err != nil {
		return fmt.Errorf("audit: marshal sentinel batch: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.config.Endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("audit: create sentinel request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Log-Type", t.config.LogType)
	req.Header.Set("x-ms-date", time.Now().UTC().Format(time.RFC1123))

	// In production, this would compute the Azure Log Analytics HMAC-SHA256 signature.
	// For now, use SharedKey header for the authorization.
	if t.config.SharedKey != "" {
		req.Header.Set("Authorization", "SharedKey "+t.config.WorkspaceID+":"+t.config.SharedKey)
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("audit: sentinel HTTP request failed: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	return fmt.Errorf("audit: sentinel returned status %d", resp.StatusCode)
}
