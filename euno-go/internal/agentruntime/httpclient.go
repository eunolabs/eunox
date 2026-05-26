// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

package agentruntime

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DefaultHTTPClient wraps a standard net/http.Client to implement HTTPClient.
type DefaultHTTPClient struct {
	client *http.Client
}

// NewDefaultHTTPClient creates a default HTTP client with sensible timeouts.
func NewDefaultHTTPClient() *DefaultHTTPClient {
	return &DefaultHTTPClient{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Do executes an HTTP request.
func (c *DefaultHTTPClient) Do(req *HTTPRequest) (*HTTPResponse, error) {
	var body io.Reader
	if req.Body != nil {
		body = bytes.NewReader(req.Body)
	}

	httpReq, err := http.NewRequestWithContext(context.Background(), req.Method, req.URL, body)
	if err != nil {
		return nil, fmt.Errorf("create HTTP request: %w", err)
	}

	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("execute HTTP request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10 MB limit
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	headers := make(map[string]string)
	for k := range resp.Header {
		headers[k] = resp.Header.Get(k)
	}

	return &HTTPResponse{
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       respBody,
	}, nil
}
