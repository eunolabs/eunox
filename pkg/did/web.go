// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package did

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// WebResolver resolves did:web DIDs by fetching /.well-known/did.json from the domain.
type WebResolver struct {
	client *http.Client
}

// WebResolverOption configures a WebResolver.
type WebResolverOption func(*WebResolver)

// WithHTTPClient sets a custom HTTP client for the resolver.
func WithHTTPClient(client *http.Client) WebResolverOption {
	return func(r *WebResolver) {
		r.client = client
	}
}

// NewWebResolver creates a did:web resolver.
func NewWebResolver(opts ...WebResolverOption) *WebResolver {
	r := &WebResolver{
		client: &http.Client{Timeout: 10 * time.Second},
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Resolve resolves a did:web DID by fetching the DID document from the domain.
// did:web:example.com → https://example.com/.well-known/did.json
// did:web:example.com:path:to:resource → https://example.com/path/to/resource/did.json
func (r *WebResolver) Resolve(ctx context.Context, did string) (*Document, error) {
	if !strings.HasPrefix(did, "did:web:") {
		return nil, fmt.Errorf("invalid did:web URI: %q", did)
	}

	url, err := webDIDToURL(did)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/did+json, application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch did:web document: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // Best-effort close.

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("did:web resolution failed: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read did:web document: %w", err)
	}

	var doc Document
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parse did:web document: %w", err)
	}

	if doc.ID == "" {
		doc.ID = did
	}

	return &doc, nil
}

// webDIDToURL converts a did:web URI to an HTTPS URL.
func webDIDToURL(did string) (string, error) {
	methodSpecific := did[len("did:web:"):]
	if methodSpecific == "" {
		return "", fmt.Errorf("invalid did:web URI: empty method-specific ID")
	}

	// Split into domain and optional path segments.
	parts := strings.Split(methodSpecific, ":")

	// URL-decode the domain (percent-encoded colons become port separators).
	domain, err := url.PathUnescape(parts[0])
	if err != nil {
		return "", fmt.Errorf("invalid did:web domain encoding: %w", err)
	}

	if len(parts) == 1 {
		// No path: /.well-known/did.json
		return "https://" + domain + "/.well-known/did.json", nil
	}

	// With path segments: /path/to/resource/did.json
	path := strings.Join(parts[1:], "/")
	return "https://" + domain + "/" + path + "/did.json", nil
}
