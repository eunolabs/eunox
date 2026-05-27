// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package audit

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
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

// defaultDeliveryTimeout is the per-batch delivery timeout for transport flush operations.
const defaultDeliveryTimeout = 30 * time.Second

// HTTPTransport delivers OCSF events via HTTP POST.
type HTTPTransport struct {
	config          HTTPTransportConfig
	client          *http.Client
	logger          *slog.Logger
	metrics         *TransportMetrics
	transportName   string
	parentCtx       context.Context
	lifecycleCtx    context.Context
	lifecycleCancel context.CancelFunc

	buffer chan *SignedAuditEvidence
	wg     sync.WaitGroup
	done   chan struct{}
	closed bool
	mu     sync.Mutex
}

// HTTPTransportOption configures optional behaviour for HTTPTransport.
type HTTPTransportOption func(*HTTPTransport)

// WithHTTPTransportMetrics attaches Prometheus metrics to the transport.
func WithHTTPTransportMetrics(m *TransportMetrics) HTTPTransportOption {
	return func(t *HTTPTransport) {
		t.metrics = m
	}
}

// WithLifecycleContext derives the transport lifecycle from the provided parent context.
func WithLifecycleContext(ctx context.Context) HTTPTransportOption {
	return func(t *HTTPTransport) {
		t.parentCtx = ctx
	}
}

// NewHTTPTransport creates a new HTTP-based OCSF transport.
func NewHTTPTransport(cfg *HTTPTransportConfig, logger *slog.Logger, opts ...HTTPTransportOption) *HTTPTransport {
	resolvedCfg := HTTPTransportConfig{}
	if cfg != nil {
		resolvedCfg = *cfg
	}
	cfg = &resolvedCfg
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
		config:        *cfg,
		client:        &http.Client{Timeout: defaultDeliveryTimeout},
		logger:        logger,
		transportName: "http",
		buffer:        make(chan *SignedAuditEvidence, cfg.BufferSize),
		done:          make(chan struct{}),
	}

	for _, opt := range opts {
		opt(t)
	}
	if t.parentCtx == nil {
		t.parentCtx = context.Background()
	}
	t.lifecycleCtx, t.lifecycleCancel = context.WithCancel(t.parentCtx)

	t.wg.Add(1)
	go t.flushLoop()

	return t
}

// Enqueue adds a single record to the transport buffer for batched delivery.
//
// Overflow policy: Enqueue is NON-BLOCKING. When the internal buffer is
// full, it returns ErrBatchFull immediately and records a "dropped" metric via
// audit_enqueue_total{status="dropped"}. The event is permanently lost from this
// transport's perspective — it is NOT retried or written aside. Callers SHOULD
// log the returned error with sufficient context (e.g., record ID, timestamp) to
// enable manual reconciliation from the upstream audit ledger.
//
// This drop-on-full policy ensures the enforcement hot path is never blocked by
// slow SIEM sinks. For high-assurance deployments requiring guaranteed delivery,
// operators should increase BufferSize or deploy a write-aside disk queue upstream.
func (t *HTTPTransport) Enqueue(evidence *SignedAuditEvidence) error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return ErrTransportClosed
	}
	t.mu.Unlock()

	select {
	case t.buffer <- evidence:
		t.metrics.observeEnqueue(t.transportName, "success")
		t.metrics.observeBufferUtilization(t.transportName, len(t.buffer), cap(t.buffer))
		return nil
	default:
		t.metrics.observeEnqueue(t.transportName, "dropped")
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

	// Flush remaining buffer with a bounded context.
	t.flushBuffer(context.Background())
	t.lifecycleCancel()
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
		case <-t.lifecycleCtx.Done():
			return
		case <-ticker.C:
			t.flushBuffer(t.lifecycleCtx)
		}
	}
}

func (t *HTTPTransport) flushBuffer(parentCtx context.Context) {
	if parentCtx == nil {
		parentCtx = context.Background()
	}

	batch := make([]SignedAuditEvidence, 0, t.config.BatchSize)

	for {
		select {
		case ev := <-t.buffer:
			batch = append(batch, *ev)
			if len(batch) >= t.config.BatchSize {
				t.metrics.observeFlushBatch(t.transportName, len(batch))
				ctx, cancel := context.WithTimeout(parentCtx, defaultDeliveryTimeout)
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
				t.metrics.observeFlushBatch(t.transportName, len(batch))
				ctx, cancel := context.WithTimeout(parentCtx, defaultDeliveryTimeout)
				if err := t.deliverWithRetry(ctx, batch); err != nil {
					t.logger.Error("audit transport: delivery failed",
						"error", err, "batch_size", len(batch))
				}
				cancel()
			}
			t.metrics.observeBufferUtilization(t.transportName, len(t.buffer), cap(t.buffer))
			return
		}
	}
}

func (t *HTTPTransport) deliverWithRetry(ctx context.Context, records []SignedAuditEvidence) error {
	var lastErr error
	backoff := t.config.RetryBackoff
	start := time.Now()

	for attempt := 0; attempt <= t.config.MaxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				t.metrics.observeDelivery(t.transportName, "failure", time.Since(start).Seconds())
				return fmt.Errorf("audit: transport context cancelled: %w", ctx.Err())
			case <-time.After(backoff):
				backoff *= 2
			}
		}

		err := t.deliver(ctx, records)
		if err == nil {
			t.metrics.observeDelivery(t.transportName, "success", time.Since(start).Seconds())
			return nil
		}
		lastErr = err
		t.logger.Warn("audit transport: delivery attempt failed",
			"attempt", attempt+1, "error", err)
	}

	t.metrics.observeDelivery(t.transportName, "failure", time.Since(start).Seconds())
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
	config          AzureSentinelConfig
	client          *http.Client
	logger          *slog.Logger
	metrics         *TransportMetrics
	transportName   string
	parentCtx       context.Context
	lifecycleCtx    context.Context
	lifecycleCancel context.CancelFunc

	buffer chan *SignedAuditEvidence
	wg     sync.WaitGroup
	done   chan struct{}
	closed bool
	mu     sync.Mutex
}

// AzureSentinelTransportOption configures optional behaviour for AzureSentinelTransport.
type AzureSentinelTransportOption func(*AzureSentinelTransport)

// WithAzureSentinelTransportMetrics attaches Prometheus metrics to the transport.
func WithAzureSentinelTransportMetrics(m *TransportMetrics) AzureSentinelTransportOption {
	return func(t *AzureSentinelTransport) {
		t.metrics = m
	}
}

// WithAzureSentinelLifecycleContext derives the transport lifecycle from the provided parent context.
func WithAzureSentinelLifecycleContext(ctx context.Context) AzureSentinelTransportOption {
	return func(t *AzureSentinelTransport) {
		t.parentCtx = ctx
	}
}

// NewAzureSentinelTransport creates a new Azure Sentinel transport.
func NewAzureSentinelTransport(cfg *AzureSentinelConfig, logger *slog.Logger, opts ...AzureSentinelTransportOption) *AzureSentinelTransport {
	resolvedCfg := AzureSentinelConfig{}
	if cfg != nil {
		resolvedCfg = *cfg
	}
	cfg = &resolvedCfg
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
		config:        *cfg,
		client:        &http.Client{Timeout: defaultDeliveryTimeout},
		logger:        logger,
		transportName: "azure_sentinel",
		buffer:        make(chan *SignedAuditEvidence, cfg.BufferSize),
		done:          make(chan struct{}),
	}

	for _, opt := range opts {
		opt(t)
	}
	if t.parentCtx == nil {
		t.parentCtx = context.Background()
	}
	t.lifecycleCtx, t.lifecycleCancel = context.WithCancel(t.parentCtx)

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
		t.metrics.observeEnqueue(t.transportName, "success")
		t.metrics.observeBufferUtilization(t.transportName, len(t.buffer), cap(t.buffer))
		return nil
	default:
		t.metrics.observeEnqueue(t.transportName, "dropped")
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

	// Flush remaining buffer with a bounded context.
	t.flushBuffer(context.Background())
	t.lifecycleCancel()
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
		case <-t.lifecycleCtx.Done():
			return
		case <-ticker.C:
			t.flushBuffer(t.lifecycleCtx)
		}
	}
}

func (t *AzureSentinelTransport) flushBuffer(parentCtx context.Context) {
	if parentCtx == nil {
		parentCtx = context.Background()
	}

	batch := make([]SignedAuditEvidence, 0, t.config.BatchSize)

	for {
		select {
		case ev := <-t.buffer:
			batch = append(batch, *ev)
			if len(batch) >= t.config.BatchSize {
				t.metrics.observeFlushBatch(t.transportName, len(batch))
				ctx, cancel := context.WithTimeout(parentCtx, defaultDeliveryTimeout)
				if err := t.deliverWithRetry(ctx, batch); err != nil {
					t.logger.Error("azure sentinel transport: delivery failed",
						"error", err, "batch_size", len(batch))
				}
				cancel()
				batch = batch[:0]
			}
		default:
			if len(batch) > 0 {
				t.metrics.observeFlushBatch(t.transportName, len(batch))
				ctx, cancel := context.WithTimeout(parentCtx, defaultDeliveryTimeout)
				if err := t.deliverWithRetry(ctx, batch); err != nil {
					t.logger.Error("azure sentinel transport: delivery failed",
						"error", err, "batch_size", len(batch))
				}
				cancel()
			}
			t.metrics.observeBufferUtilization(t.transportName, len(t.buffer), cap(t.buffer))
			return
		}
	}
}

func (t *AzureSentinelTransport) deliverWithRetry(ctx context.Context, records []SignedAuditEvidence) error {
	var lastErr error
	backoff := t.config.RetryBackoff
	start := time.Now()

	for attempt := 0; attempt <= t.config.MaxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				t.metrics.observeDelivery(t.transportName, "failure", time.Since(start).Seconds())
				return fmt.Errorf("audit: sentinel context cancelled: %w", ctx.Err())
			case <-time.After(backoff):
				backoff *= 2
			}
		}

		err := t.deliver(ctx, records)
		if err == nil {
			t.metrics.observeDelivery(t.transportName, "success", time.Since(start).Seconds())
			return nil
		}
		lastErr = err
		t.logger.Warn("azure sentinel transport: delivery attempt failed",
			"attempt", attempt+1, "error", err)
	}

	t.metrics.observeDelivery(t.transportName, "failure", time.Since(start).Seconds())
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
	dateHeader := time.Now().UTC().Format(http.TimeFormat)
	req.Header.Set("x-ms-date", dateHeader)
	if t.config.SharedKey != "" {
		authHeader, err := buildAzureSentinelAuthorization(t.config.WorkspaceID, t.config.SharedKey, len(body), req.Header.Get("Content-Type"), dateHeader, req.URL.EscapedPath())
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", authHeader)
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

func buildAzureSentinelAuthorization(workspaceID, sharedKey string, contentLength int, contentType, dateHeader, resourcePath string) (string, error) {
	if workspaceID == "" {
		return "", errors.New("audit: azure sentinel workspace ID is required when shared key authentication is enabled")
	}
	decodedKey, err := base64.StdEncoding.DecodeString(sharedKey)
	if err != nil {
		return "", fmt.Errorf("audit: decode azure sentinel shared key: %w", err)
	}

	stringToSign := fmt.Sprintf("POST\n%d\n%s\nx-ms-date:%s\n%s", contentLength, contentType, dateHeader, resourcePath)
	mac := hmac.New(sha256.New, decodedKey)
	mac.Write([]byte(stringToSign))
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	return "SharedKey " + workspaceID + ":" + signature, nil
}
