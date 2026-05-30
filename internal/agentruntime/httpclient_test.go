// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package agentruntime

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultHTTPClient_NilContext(t *testing.T) {
	client := NewDefaultHTTPClient()

	_, err := client.Do(&HTTPRequest{
		Method: "GET",
		URL:    "http://example.com",
		// Context intentionally nil
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilContext), "expected ErrNilContext, got: %v", err)
}

func TestDefaultHTTPClient_WithContext(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Test", "ok")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	client := NewDefaultHTTPClient()

	resp, err := client.Do(&HTTPRequest{
		Context: context.Background(),
		Method:  "GET",
		URL:     srv.URL,
	})
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "ok", resp.Headers["X-Test"])
	assert.Equal(t, `{"status":"ok"}`, string(resp.Body))
}

func TestDefaultHTTPClient_CancelledContext(t *testing.T) {
	client := NewDefaultHTTPClient()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := client.Do(&HTTPRequest{
		Context: ctx,
		Method:  "GET",
		URL:     "http://unreachable.invalid",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")
}

func TestDefaultHTTPClient_PostWithBody(t *testing.T) {
	var receivedBody []byte
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		receivedBody, err = readAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	client := NewDefaultHTTPClient()

	resp, err := client.Do(&HTTPRequest{
		Context: context.Background(),
		Method:  "POST",
		URL:     srv.URL,
		Headers: map[string]string{"Content-Type": "application/json"},
		Body:    []byte(`{"key":"value"}`),
	})
	require.NoError(t, err)
	assert.Equal(t, 201, resp.StatusCode)
	assert.Equal(t, `{"key":"value"}`, string(receivedBody))
}

func readAll(r interface{ Read([]byte) (int, error) }) ([]byte, error) {
	var buf []byte
	tmp := make([]byte, 1024)
	for {
		n, err := r.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return buf, nil
			}
			return buf, err
		}
	}
}
