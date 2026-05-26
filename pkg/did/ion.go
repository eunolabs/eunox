// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package did

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// IONResolver resolves did:ion DIDs by querying a Microsoft ION network endpoint.
type IONResolver struct {
	endpoint string
	client   *http.Client
}

// IONResolverOption configures an IONResolver.
type IONResolverOption func(*IONResolver)

// WithIONEndpoint sets the ION network resolution endpoint.
func WithIONEndpoint(endpoint string) IONResolverOption {
	return func(r *IONResolver) {
		r.endpoint = endpoint
	}
}

// WithIONHTTPClient sets a custom HTTP client for the ION resolver.
func WithIONHTTPClient(client *http.Client) IONResolverOption {
	return func(r *IONResolver) {
		r.client = client
	}
}

// DefaultIONEndpoint is the default ION network resolver URL.
const DefaultIONEndpoint = "https://beta.discover.did.microsoft.com/1.0/identifiers/"

// NewIONResolver creates a did:ion resolver.
func NewIONResolver(opts ...IONResolverOption) *IONResolver {
	r := &IONResolver{
		endpoint: DefaultIONEndpoint,
		client:   &http.Client{Timeout: 30 * time.Second},
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Resolve resolves a did:ion DID by querying the ION network.
func (r *IONResolver) Resolve(ctx context.Context, did string) (*Document, error) {
	if !strings.HasPrefix(did, "did:ion:") {
		return nil, fmt.Errorf("invalid did:ion URI: %q", did)
	}

	url := r.endpoint + did

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/did+json, application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch did:ion document: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // Best-effort close.

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("did:ion resolution failed: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read did:ion document: %w", err)
	}

	// ION responses may wrap the document in a didDocument field.
	var raw json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse did:ion response: %w", err)
	}

	// Try to extract didDocument from wrapper.
	var wrapper struct {
		DIDDocument json.RawMessage `json:"didDocument"`
	}
	if err := json.Unmarshal(raw, &wrapper); err == nil && wrapper.DIDDocument != nil {
		var doc Document
		if err := json.Unmarshal(wrapper.DIDDocument, &doc); err != nil {
			return nil, fmt.Errorf("parse did:ion document: %w", err)
		}
		if doc.ID == "" {
			doc.ID = did
		}
		return &doc, nil
	}

	// Try direct document parsing.
	var doc Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse did:ion document: %w", err)
	}

	if doc.ID == "" {
		doc.ID = did
	}

	return &doc, nil
}

// Healthy checks if the ION endpoint is reachable.
func (r *IONResolver) Healthy(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.endpoint, http.NoBody)
	if err != nil {
		return fmt.Errorf("create health check request: %w", err)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("ION endpoint unreachable: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // Best-effort close.

	// Any response (even 4xx for missing DID) means the endpoint is up.
	if resp.StatusCode >= 500 {
		return fmt.Errorf("ION endpoint returned server error: HTTP %d", resp.StatusCode)
	}

	return nil
}
