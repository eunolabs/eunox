// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

package agentruntime

import (
	"sync"
)

// MockHTTPClient is a test HTTP client that records requests and returns configured responses.
type MockHTTPClient struct {
	mu       sync.Mutex
	requests []*HTTPRequest
	handler  func(*HTTPRequest) (*HTTPResponse, error)
}

// NewMockHTTPClient creates a new mock HTTP client.
func NewMockHTTPClient(handler func(*HTTPRequest) (*HTTPResponse, error)) *MockHTTPClient {
	return &MockHTTPClient{handler: handler}
}

// Do records the request and delegates to the configured handler.
func (m *MockHTTPClient) Do(req *HTTPRequest) (*HTTPResponse, error) {
	m.mu.Lock()
	m.requests = append(m.requests, req)
	m.mu.Unlock()

	return m.handler(req)
}

// Requests returns all recorded requests.
func (m *MockHTTPClient) Requests() []*HTTPRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]*HTTPRequest, len(m.requests))
	copy(result, m.requests)
	return result
}

// Reset clears recorded requests.
func (m *MockHTTPClient) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests = nil
}
