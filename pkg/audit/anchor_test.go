// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package audit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestS3AnchorBackend_SignsRequestsWithCredentials(t *testing.T) {
	t.Parallel()

	var capturedHeaders http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	backend := NewS3AnchorBackend(&S3AnchorConfig{
		Bucket:         "test-bucket",
		Prefix:         "anchors/",
		Region:         "us-east-1",
		Endpoint:       srv.URL,
		AccessKeyID:    "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	})

	anchor := &ChainAnchor{
		AnchorID:    "anchor-test-1",
		ReplicaID:   "replica-1",
		SequenceNum: 42,
		ChainHash:   "abc123",
		MerkleRoot:  "def456",
	}

	ref, err := backend.Anchor(context.Background(), anchor)
	require.NoError(t, err)
	assert.Contains(t, ref, "s3://test-bucket/anchors/anchor-test-1.json")

	// Verify SigV4 headers are present.
	assert.NotEmpty(t, capturedHeaders.Get("Authorization"))
	assert.True(t, strings.HasPrefix(capturedHeaders.Get("Authorization"), "AWS4-HMAC-SHA256"))
	assert.NotEmpty(t, capturedHeaders.Get("X-Amz-Date"))
	assert.NotEmpty(t, capturedHeaders.Get("X-Amz-Content-Sha256"))
}

func TestS3AnchorBackend_IncludesSessionToken(t *testing.T) {
	t.Parallel()

	var capturedHeaders http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	backend := NewS3AnchorBackend(&S3AnchorConfig{
		Bucket:         "test-bucket",
		Prefix:         "",
		Region:         "eu-west-1",
		Endpoint:       srv.URL,
		AccessKeyID:    "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:   "FwoGZXIvYXdzEBY-session-token-example",
	})

	anchor := &ChainAnchor{
		AnchorID:    "anchor-sess-1",
		ReplicaID:   "replica-1",
		SequenceNum: 10,
		ChainHash:   "hash1",
		MerkleRoot:  "root1",
	}

	_, err := backend.Anchor(context.Background(), anchor)
	require.NoError(t, err)

	assert.Equal(t, "FwoGZXIvYXdzEBY-session-token-example", capturedHeaders.Get("X-Amz-Security-Token"))
}

func TestS3AnchorBackend_NoSigningWithoutCredentials(t *testing.T) {
	t.Parallel()

	var capturedHeaders http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	backend := NewS3AnchorBackend(&S3AnchorConfig{
		Bucket:   "test-bucket",
		Prefix:   "",
		Region:   "us-east-1",
		Endpoint: srv.URL,
		// No credentials.
	})

	anchor := &ChainAnchor{
		AnchorID:    "anchor-no-auth-1",
		ReplicaID:   "replica-1",
		SequenceNum: 5,
		ChainHash:   "hash",
		MerkleRoot:  "root",
	}

	_, err := backend.Anchor(context.Background(), anchor)
	require.NoError(t, err)

	// Should NOT have Authorization header.
	assert.Empty(t, capturedHeaders.Get("Authorization"))
	assert.Empty(t, capturedHeaders.Get("X-Amz-Date"))
}

func TestS3AnchorBackend_Verify_WithCredentials(t *testing.T) {
	t.Parallel()

	var capturedHeaders http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header.Clone()
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	backend := NewS3AnchorBackend(&S3AnchorConfig{
		Bucket:         "test-bucket",
		Prefix:         "anchors/",
		Region:         "us-east-1",
		Endpoint:       srv.URL,
		AccessKeyID:    "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	})

	anchor := &ChainAnchor{
		AnchorID: "anchor-verify-1",
	}

	exists, err := backend.Verify(context.Background(), anchor)
	require.NoError(t, err)
	assert.True(t, exists)

	// Verify SigV4 headers are present on HEAD request.
	assert.True(t, strings.HasPrefix(capturedHeaders.Get("Authorization"), "AWS4-HMAC-SHA256"))
}

func TestS3AnchorBackend_Anchor_HTTPError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	backend := NewS3AnchorBackend(&S3AnchorConfig{
		Bucket:         "test-bucket",
		Prefix:         "",
		Region:         "us-east-1",
		Endpoint:       srv.URL,
		AccessKeyID:    "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "secret",
	})

	anchor := &ChainAnchor{
		AnchorID:    "anchor-err-1",
		ReplicaID:   "replica-1",
		SequenceNum: 1,
		ChainHash:   "hash",
		MerkleRoot:  "root",
	}

	_, err := backend.Anchor(context.Background(), anchor)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}

func TestSignAWSRequest_ProducesValidAuthHeader(t *testing.T) {
	t.Parallel()

	req, _ := http.NewRequest(http.MethodPut, "https://mybucket.s3.us-east-1.amazonaws.com/mykey.json", http.NoBody)
	payload := []byte(`{"test":"data"}`)

	signAWSRequest(req, payload, "us-east-1", "s3", "AKID", "SECRET", "")

	auth := req.Header.Get("Authorization")
	assert.True(t, strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AKID/"))
	assert.Contains(t, auth, "/us-east-1/s3/aws4_request")
	assert.Contains(t, auth, "SignedHeaders=")
	assert.Contains(t, auth, "Signature=")

	// Verify X-Amz-Date format (yyyyMMdd'T'HHmmss'Z').
	amzDate := req.Header.Get("X-Amz-Date")
	assert.Len(t, amzDate, 16) // e.g., "20260526T123456Z"
	assert.Equal(t, "T", string(amzDate[8]))
	assert.Equal(t, "Z", string(amzDate[15]))
}

func TestDeriveSigningKey_Deterministic(t *testing.T) {
	t.Parallel()

	// Same inputs should always produce same output.
	key1 := deriveSigningKey("secret", "20260526", "us-east-1", "s3")
	key2 := deriveSigningKey("secret", "20260526", "us-east-1", "s3")
	assert.Equal(t, key1, key2)

	// Different date produces different key.
	key3 := deriveSigningKey("secret", "20260527", "us-east-1", "s3")
	assert.NotEqual(t, key1, key3)
}

func TestBuildCanonicalQueryString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		input  map[string][]string
		expect string
	}{
		{"empty", nil, ""},
		{"single", map[string][]string{"key": {"value"}}, "key=value"},
		{"sorted", map[string][]string{"b": {"2"}, "a": {"1"}}, "a=1&b=2"},
		{"encoded", map[string][]string{"k": {"v w"}}, "k=v+w"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildCanonicalQueryString(tt.input)
			assert.Equal(t, tt.expect, result)
		})
	}
}

func TestSha256Hex(t *testing.T) {
	t.Parallel()
	// Empty payload hash (AWS requires this for empty bodies).
	emptyHash := sha256Hex(nil)
	assert.Equal(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", emptyHash)

	// Known hash.
	hash := sha256Hex([]byte("hello"))
	assert.Equal(t, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", hash)
}
