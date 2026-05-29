// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package audit

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- TEST-4: Concurrent Access Tests for Audit Transport ---

func TestHTTPTransport_ConcurrentEnqueue(t *testing.T) {
	t.Parallel()

	var received atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var records []SignedAuditEvidence
		_ = json.Unmarshal(body, &records)
		received.Add(int64(len(records)))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	transport := NewHTTPTransport(&HTTPTransportConfig{
		TransportConfig: TransportConfig{
			BatchSize:     50,
			FlushInterval: 50 * time.Millisecond,
			MaxRetries:    1,
			RetryBackoff:  time.Millisecond,
			BufferSize:    500,
		},
		Endpoint: server.URL,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	var enqueueErrors atomic.Int64
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			err := transport.Enqueue(&SignedAuditEvidence{
				Record: LogEntry{ID: "rec-" + itoa(idx), EventType: "test", Action: "action"},
			})
			if err != nil {
				enqueueErrors.Add(1)
			}
		}(i)
	}
	wg.Wait()

	// Close triggers final flush.
	require.NoError(t, transport.Close())

	// All records should have been enqueued (buffer=500 > goroutines=100).
	assert.Equal(t, int64(0), enqueueErrors.Load(), "no enqueue errors expected")
	assert.Equal(t, int64(goroutines), received.Load(), "all records should be delivered")
}

func TestHTTPTransport_ConcurrentEnqueueAndClose(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	transport := NewHTTPTransport(&HTTPTransportConfig{
		TransportConfig: TransportConfig{
			BatchSize:     100,
			FlushInterval: time.Hour,
			MaxRetries:    1,
			RetryBackoff:  time.Millisecond,
			BufferSize:    200,
		},
		Endpoint: server.URL,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines + 1)

	// Spawn goroutines that enqueue.
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			_ = transport.Enqueue(&SignedAuditEvidence{
				Record: LogEntry{ID: "rec-" + itoa(idx)},
			})
		}(i)
	}

	// Close concurrently.
	go func() {
		defer wg.Done()
		time.Sleep(1 * time.Millisecond) // Slight delay.
		_ = transport.Close()
	}()

	wg.Wait()

	// After close, all enqueues should return ErrTransportClosed.
	err := transport.Enqueue(&SignedAuditEvidence{Record: LogEntry{ID: "after-close"}})
	assert.ErrorIs(t, err, ErrTransportClosed)
}

func TestHTTPTransport_ConcurrentEnqueue_BufferPressure(t *testing.T) {
	t.Parallel()

	var delivered atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var records []SignedAuditEvidence
		_ = json.Unmarshal(body, &records)
		delivered.Add(int64(len(records)))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Small buffer to force some drops.
	transport := NewHTTPTransport(&HTTPTransportConfig{
		TransportConfig: TransportConfig{
			BatchSize:     5,
			FlushInterval: 20 * time.Millisecond,
			MaxRetries:    1,
			RetryBackoff:  time.Millisecond,
			BufferSize:    10, // Very small buffer.
		},
		Endpoint: server.URL,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	var accepted, dropped atomic.Int64
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			err := transport.Enqueue(&SignedAuditEvidence{
				Record: LogEntry{ID: "rec-" + itoa(idx)},
			})
			if err == nil {
				accepted.Add(1)
			} else {
				dropped.Add(1)
			}
		}(i)
	}
	wg.Wait()

	// Close flushes remaining.
	require.NoError(t, transport.Close())

	// Some records may have been dropped due to buffer pressure.
	assert.True(t, accepted.Load()+dropped.Load() == int64(goroutines))
	// All accepted records should eventually be delivered.
	assert.Equal(t, accepted.Load(), delivered.Load())
}

func TestHTTPTransport_ConcurrentSend(t *testing.T) {
	t.Parallel()

	var received atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var records []SignedAuditEvidence
		_ = json.Unmarshal(body, &records)
		received.Add(int64(len(records)))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	transport := NewHTTPTransport(&HTTPTransportConfig{
		TransportConfig: TransportConfig{
			BatchSize:     10,
			FlushInterval: time.Hour,
			MaxRetries:    1,
			RetryBackoff:  time.Millisecond,
			BufferSize:    100,
		},
		Endpoint: server.URL,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer func() { _ = transport.Close() }()

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)

	errs := make([]error, goroutines)
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			errs[idx] = transport.Send(context.Background(), []SignedAuditEvidence{
				{Record: LogEntry{ID: "send-" + itoa(idx)}},
			})
		}(i)
	}
	wg.Wait()

	for i, e := range errs {
		assert.NoError(t, e, "goroutine %d failed", i)
	}
	assert.Equal(t, int64(goroutines), received.Load())
}

func TestHTTPTransport_FlushLoopStress(t *testing.T) {
	t.Parallel()

	var received atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var records []SignedAuditEvidence
		_ = json.Unmarshal(body, &records)
		received.Add(int64(len(records)))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	transport := NewHTTPTransport(&HTTPTransportConfig{
		TransportConfig: TransportConfig{
			BatchSize:     5,
			FlushInterval: 10 * time.Millisecond, // Very frequent.
			MaxRetries:    1,
			RetryBackoff:  time.Millisecond,
			BufferSize:    500,
		},
		Endpoint: server.URL,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Continuously enqueue while flush loop runs.
	const totalRecords = 200
	for i := range totalRecords {
		err := transport.Enqueue(&SignedAuditEvidence{
			Record: LogEntry{ID: "stress-" + itoa(i)},
		})
		require.NoError(t, err)
		if i%20 == 0 {
			time.Sleep(5 * time.Millisecond) // Allow flush loop to run.
		}
	}

	// Close flushes remaining.
	require.NoError(t, transport.Close())
	assert.Equal(t, int64(totalRecords), received.Load())
}

func TestHTTPTransport_DoubleClose(t *testing.T) {
	t.Parallel()

	transport := NewHTTPTransport(&HTTPTransportConfig{
		TransportConfig: TransportConfig{
			FlushInterval: time.Hour,
			BufferSize:    100,
		},
		Endpoint: "http://localhost:9999",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	err := transport.Close()
	require.NoError(t, err)

	// Second close should not panic.
	err = transport.Close()
	assert.NoError(t, err)
}

// itoa converts int to string without importing strconv.
func itoa(i int) string {
	const digits = "0123456789"
	if i < 0 {
		return "-" + itoa(-i)
	}
	if i < 10 {
		return string(digits[i])
	}
	return itoa(i/10) + string(digits[i%10])
}
