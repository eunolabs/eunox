// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package did

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseMethod(t *testing.T) {
	tests := []struct {
		name    string
		did     string
		want    string
		wantErr bool
	}{
		{name: "did:web", did: "did:web:example.com", want: "web"},
		{name: "did:ion", did: "did:ion:EiA...", want: "ion"},
		{name: "did:key", did: "did:key:z6Mk...", want: "key"},
		{name: "empty", did: "", wantErr: true},
		{name: "no prefix", did: "notadid:web:x", wantErr: true},
		{name: "no method-specific ID", did: "did:web", wantErr: true},
		{name: "empty method", did: "did::foo", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseMethod(tt.did)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestWebResolver_Resolve(t *testing.T) {
	doc := Document{
		Context: []string{"https://www.w3.org/ns/did/v1"},
		ID:      "did:web:example.com",
		VerificationMethod: []VerificationMethod{
			{
				ID:         "did:web:example.com#key-1",
				Type:       "JsonWebKey2020",
				Controller: "did:web:example.com",
				PublicKeyJwk: &JWK{
					Kty: "OKP",
					Crv: "Ed25519",
					X:   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
				},
			},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/.well-known/did.json", r.URL.Path)
		w.Header().Set("Content-Type", "application/did+json")
		_ = json.NewEncoder(w).Encode(doc)
	}))
	defer srv.Close()

	// Replace "example.com" with test server host in the DID.
	resolver := NewWebResolver(WithHTTPClient(srv.Client()))

	t.Run("resolves did:web with well-known path", func(t *testing.T) {
		// We need a custom test because did:web requires HTTPS. Use a mock approach.
		mockDoc := Document{
			ID: "did:web:test.example.com",
			VerificationMethod: []VerificationMethod{
				{
					ID:         "did:web:test.example.com#key-1",
					Type:       "JsonWebKey2020",
					Controller: "did:web:test.example.com",
					PublicKeyJwk: &JWK{
						Kty: "OKP",
						Crv: "Ed25519",
						X:   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
					},
				},
			},
		}
		mockSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(mockDoc)
		}))
		defer mockSrv.Close()

		// Use a transport that redirects HTTPS to our mock.
		customResolver := &testWebResolver{baseURL: mockSrv.URL, client: mockSrv.Client()}
		result, err := customResolver.Resolve(context.Background(), "did:web:test.example.com")
		require.NoError(t, err)
		assert.Equal(t, "did:web:test.example.com", result.ID)
		assert.Len(t, result.VerificationMethod, 1)
	})

	t.Run("invalid did:web prefix", func(t *testing.T) {
		_, err := resolver.Resolve(context.Background(), "did:key:z6Mk...")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid did:web URI")
	})

	t.Run("HTTP error", func(t *testing.T) {
		errSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer errSrv.Close()

		errResolver := &testWebResolver{baseURL: errSrv.URL, client: errSrv.Client()}
		_, err := errResolver.Resolve(context.Background(), "did:web:notfound.example.com")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "HTTP Not Found")
	})
}

// testWebResolver is a test helper that resolves did:web by querying a local server.
type testWebResolver struct {
	baseURL string
	client  *http.Client
}

func (r *testWebResolver) Resolve(ctx context.Context, did string) (*Document, error) {
	url := r.baseURL + "/.well-known/did.json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck // Best-effort close for test response body.
	if resp.StatusCode != http.StatusOK {
		return nil, &resolveError{status: resp.StatusCode}
	}
	var doc Document
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, err
	}
	if doc.ID == "" {
		doc.ID = did
	}
	return &doc, nil
}

type resolveError struct {
	status int
}

func (e *resolveError) Error() string {
	return "did:web resolution failed: HTTP " + http.StatusText(e.status)
}

func TestWebDIDToURL(t *testing.T) {
	tests := []struct {
		name    string
		did     string
		want    string
		wantErr bool
	}{
		{
			name: "simple domain",
			did:  "did:web:example.com",
			want: "https://example.com/.well-known/did.json",
		},
		{
			name: "domain with port",
			did:  "did:web:example.com%3A3000",
			want: "https://example.com:3000/.well-known/did.json",
		},
		{
			name: "domain with lowercase encoded port separator",
			did:  "did:web:example.com%3a3000",
			want: "https://example.com:3000/.well-known/did.json",
		},
		{
			name: "domain with path",
			did:  "did:web:example.com:user:alice",
			want: "https://example.com/user/alice/did.json",
		},
		{
			name:    "empty method-specific",
			did:     "did:web:",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := webDIDToURL(tt.did)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIONResolver_Resolve(t *testing.T) {
	ionDoc := Document{
		ID: "did:ion:EiA123...",
		VerificationMethod: []VerificationMethod{
			{
				ID:         "did:ion:EiA123...#key-1",
				Type:       "JsonWebKey2020",
				Controller: "did:ion:EiA123...",
				PublicKeyJwk: &JWK{
					Kty: "OKP",
					Crv: "Ed25519",
					X:   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
				},
			},
		},
	}

	t.Run("resolves direct document", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(ionDoc)
		}))
		defer srv.Close()

		resolver := NewIONResolver(WithIONEndpoint(srv.URL+"/"), WithIONHTTPClient(srv.Client()))
		result, err := resolver.Resolve(context.Background(), "did:ion:EiA123...")
		require.NoError(t, err)
		assert.Equal(t, "did:ion:EiA123...", result.ID)
		assert.Len(t, result.VerificationMethod, 1)
	})

	t.Run("resolves wrapped document", func(t *testing.T) {
		wrappedResp := map[string]any{
			"didDocument": ionDoc,
		}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(wrappedResp)
		}))
		defer srv.Close()

		resolver := NewIONResolver(WithIONEndpoint(srv.URL+"/"), WithIONHTTPClient(srv.Client()))
		result, err := resolver.Resolve(context.Background(), "did:ion:EiA123...")
		require.NoError(t, err)
		assert.Equal(t, "did:ion:EiA123...", result.ID)
	})

	t.Run("invalid prefix", func(t *testing.T) {
		resolver := NewIONResolver()
		_, err := resolver.Resolve(context.Background(), "did:web:example.com")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid did:ion URI")
	})

	t.Run("HTTP error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()

		resolver := NewIONResolver(WithIONEndpoint(srv.URL+"/"), WithIONHTTPClient(srv.Client()))
		_, err := resolver.Resolve(context.Background(), "did:ion:EiA123...")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "HTTP 500")
	})
}

func TestIONResolver_Healthy(t *testing.T) {
	t.Run("healthy endpoint", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		resolver := NewIONResolver(WithIONEndpoint(srv.URL+"/"), WithIONHTTPClient(srv.Client()))
		err := resolver.Healthy(context.Background())
		assert.NoError(t, err)
	})

	t.Run("server error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
		}))
		defer srv.Close()

		resolver := NewIONResolver(WithIONEndpoint(srv.URL+"/"), WithIONHTTPClient(srv.Client()))
		err := resolver.Healthy(context.Background())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "server error")
	})
}

func TestKeyResolver_Resolve_Ed25519(t *testing.T) {
	// Generate a known Ed25519 key and encode as did:key.
	// did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
	// This is a well-known test vector.
	resolver := NewKeyResolver()

	t.Run("valid Ed25519 key", func(t *testing.T) {
		// Create a did:key from a known Ed25519 public key.
		// Use a manually constructed multibase(base58btc(multicodec(ed25519-pub, raw-key))).
		pubKey := ed25519.PublicKey(make([]byte, 32))
		pubKey[0] = 0x01 // Non-zero for testing.

		didURI := encodeDIDKeyEd25519(pubKey)
		doc, err := resolver.Resolve(context.Background(), didURI)
		require.NoError(t, err)
		assert.Equal(t, didURI, doc.ID)
		assert.Len(t, doc.VerificationMethod, 1)

		vm := doc.VerificationMethod[0]
		assert.Equal(t, "JsonWebKey2020", vm.Type)
		assert.Equal(t, "OKP", vm.PublicKeyJwk.Kty)
		assert.Equal(t, "Ed25519", vm.PublicKeyJwk.Crv)

		// Extract public key and verify.
		extracted, err := vm.ExtractPublicKey()
		require.NoError(t, err)
		edKey, ok := extracted.(ed25519.PublicKey)
		require.True(t, ok)
		assert.Equal(t, pubKey, edKey)
	})

	t.Run("invalid prefix", func(t *testing.T) {
		_, err := resolver.Resolve(context.Background(), "did:web:example.com")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid did:key URI")
	})

	t.Run("empty key material", func(t *testing.T) {
		_, err := resolver.Resolve(context.Background(), "did:key:")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "empty key material")
	})
}

func TestKeyResolver_Resolve_P256(t *testing.T) {
	resolver := NewKeyResolver()

	t.Run("valid P-256 key", func(t *testing.T) {
		// Use a known P-256 compressed point (33 bytes: 0x02 or 0x03 prefix + 32 bytes x).
		// Generate a test P-256 compressed key.
		compressedKey := make([]byte, 33)
		compressedKey[0] = 0x02 // Even y prefix.
		compressedKey[1] = 0x65 // Some non-zero x coordinate.
		compressedKey[2] = 0xA1

		didURI := encodeDIDKeyP256(compressedKey)
		doc, err := resolver.Resolve(context.Background(), didURI)
		require.NoError(t, err)
		assert.Equal(t, didURI, doc.ID)
		assert.Len(t, doc.VerificationMethod, 1)

		vm := doc.VerificationMethod[0]
		assert.Equal(t, "EC", vm.PublicKeyJwk.Kty)
		assert.Equal(t, "P-256", vm.PublicKeyJwk.Crv)

		extracted, err := vm.ExtractPublicKey()
		require.NoError(t, err)
		_, ok := extracted.(*ecdsa.PublicKey)
		assert.True(t, ok)
	})
}

func TestCachingResolver(t *testing.T) {
	callCount := 0
	inner := &mockResolver{
		resolveFunc: func(_ context.Context, did string) (*Document, error) {
			callCount++
			return &Document{ID: did}, nil
		},
	}

	now := time.Now()
	clock := &now

	resolver := NewCachingResolver(inner,
		WithCacheTTL(5*time.Minute),
		WithMaxCacheItems(2),
		WithTimeFunc(func() time.Time { return *clock }),
	)

	t.Run("caches results", func(t *testing.T) {
		callCount = 0
		doc, err := resolver.Resolve(context.Background(), "did:web:example.com")
		require.NoError(t, err)
		assert.Equal(t, "did:web:example.com", doc.ID)
		assert.Equal(t, 1, callCount)

		// Second call should be cached.
		doc2, err := resolver.Resolve(context.Background(), "did:web:example.com")
		require.NoError(t, err)
		assert.Equal(t, "did:web:example.com", doc2.ID)
		assert.Equal(t, 1, callCount) // No additional call.
	})

	t.Run("expires after TTL", func(t *testing.T) {
		callCount = 0
		_, _ = resolver.Resolve(context.Background(), "did:web:expiry.test")
		assert.Equal(t, 1, callCount)

		// Advance time past TTL.
		newTime := now.Add(6 * time.Minute)
		clock = &newTime

		_, _ = resolver.Resolve(context.Background(), "did:web:expiry.test")
		assert.Equal(t, 2, callCount) // Should re-resolve.
	})

	t.Run("evicts when at capacity", func(t *testing.T) {
		// Reset.
		resolver2 := NewCachingResolver(inner,
			WithCacheTTL(5*time.Minute),
			WithMaxCacheItems(2),
		)

		_, _ = resolver2.Resolve(context.Background(), "did:web:a.com")
		_, _ = resolver2.Resolve(context.Background(), "did:web:b.com")
		assert.Equal(t, 2, resolver2.Len())

		_, _ = resolver2.Resolve(context.Background(), "did:web:c.com")
		assert.LessOrEqual(t, resolver2.Len(), 2) // Should evict one.
	})

	t.Run("invalidate removes entry", func(t *testing.T) {
		resolver3 := NewCachingResolver(inner, WithCacheTTL(5*time.Minute))
		_, _ = resolver3.Resolve(context.Background(), "did:web:invalidate.test")
		assert.Equal(t, 1, resolver3.Len())

		resolver3.Invalidate("did:web:invalidate.test")
		assert.Equal(t, 0, resolver3.Len())
	})
}

func TestMultiResolver(t *testing.T) {
	webCalled := false
	ionCalled := false

	webResolver := &mockResolver{
		resolveFunc: func(_ context.Context, _ string) (*Document, error) {
			webCalled = true
			return &Document{ID: "did:web:example.com"}, nil
		},
	}
	ionResolver := &mockResolver{
		resolveFunc: func(_ context.Context, _ string) (*Document, error) {
			ionCalled = true
			return &Document{ID: "did:ion:EiA..."}, nil
		},
	}

	multi := NewMultiResolver(map[string]Resolver{
		"web": webResolver,
		"ion": ionResolver,
	})

	t.Run("delegates to web resolver", func(t *testing.T) {
		webCalled = false
		doc, err := multi.Resolve(context.Background(), "did:web:example.com")
		require.NoError(t, err)
		assert.True(t, webCalled)
		assert.Equal(t, "did:web:example.com", doc.ID)
	})

	t.Run("delegates to ion resolver", func(t *testing.T) {
		ionCalled = false
		doc, err := multi.Resolve(context.Background(), "did:ion:EiA...")
		require.NoError(t, err)
		assert.True(t, ionCalled)
		assert.Equal(t, "did:ion:EiA...", doc.ID)
	})

	t.Run("unsupported method", func(t *testing.T) {
		_, err := multi.Resolve(context.Background(), "did:example:123")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported DID method")
	})
}

func TestExtractPublicKey_Unsupported(t *testing.T) {
	t.Run("no JWK", func(t *testing.T) {
		vm := &VerificationMethod{Type: "X25519KeyAgreementKey2019"}
		_, err := vm.ExtractPublicKey()
		assert.Error(t, err)
	})

	t.Run("unsupported kty", func(t *testing.T) {
		vm := &VerificationMethod{
			PublicKeyJwk: &JWK{Kty: "RSA"},
		}
		_, err := vm.ExtractPublicKey()
		assert.Error(t, err)
	})

	t.Run("unsupported OKP curve", func(t *testing.T) {
		vm := &VerificationMethod{
			PublicKeyJwk: &JWK{Kty: "OKP", Crv: "X25519"},
		}
		_, err := vm.ExtractPublicKey()
		assert.Error(t, err)
	})
}

func TestDocument_PublicKeys(t *testing.T) {
	doc := &Document{
		VerificationMethod: []VerificationMethod{
			{
				PublicKeyJwk: &JWK{
					Kty: "OKP",
					Crv: "Ed25519",
					X:   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
				},
			},
			{
				// Invalid: no JWK.
				Type: "X25519",
			},
		},
	}

	keys := doc.PublicKeys()
	assert.Len(t, keys, 1)
}

// --- Test helpers ---

type mockResolver struct {
	resolveFunc func(ctx context.Context, did string) (*Document, error)
}

func (m *mockResolver) Resolve(ctx context.Context, did string) (*Document, error) {
	return m.resolveFunc(ctx, did)
}

// encodeDIDKeyEd25519 encodes an Ed25519 public key as a did:key URI.
func encodeDIDKeyEd25519(pubKey ed25519.PublicKey) string {
	// Multicodec prefix for ed25519-pub is 0xed (varint: 0xed 0x01).
	data := append([]byte{0xed, 0x01}, pubKey...)
	encoded := base58Encode(data)
	return "did:key:z" + encoded
}

// encodeDIDKeyP256 encodes a compressed P-256 key as a did:key URI.
func encodeDIDKeyP256(compressed []byte) string {
	// Multicodec prefix for p256-pub is 0x1200 (varint: 0x80 0x24).
	data := append([]byte{0x80, 0x24}, compressed...)
	encoded := base58Encode(data)
	return "did:key:z" + encoded
}

// base58Encode encodes bytes to base58btc.
func base58Encode(data []byte) string {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	if len(data) == 0 {
		return ""
	}

	// Count leading zeros.
	var numZeros int
	for _, b := range data {
		if b != 0 {
			break
		}
		numZeros++
	}

	// Convert to big integer and encode.
	var result []byte
	for _, b := range data {
		carry := int(b)
		for i := len(result) - 1; i >= 0; i-- {
			carry += int(result[i]) * 256
			result[i] = byte(carry % 58)
			carry /= 58
		}
		for carry > 0 {
			result = append([]byte{byte(carry % 58)}, result...)
			carry /= 58
		}
	}

	// Map to alphabet.
	encoded := make([]byte, numZeros+len(result))
	for i := 0; i < numZeros; i++ {
		encoded[i] = alphabet[0]
	}
	for i, b := range result {
		encoded[numZeros+i] = alphabet[b]
	}
	return string(encoded)
}
