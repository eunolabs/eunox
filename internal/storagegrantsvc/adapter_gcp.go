// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package storagegrantsvc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// GCPServiceAccountSigner signs blobs using a GCP service account's private key.
// Implementations may use a local RSA key or the IAM signBlob API.
type GCPServiceAccountSigner interface {
	// Sign signs the given data using the service account's private key.
	Sign(ctx context.Context, data []byte) ([]byte, error)
	// Email returns the service account email used for the credential.
	Email() string
}

// RSAServiceAccountSigner signs data with a local RSA private key.
type RSAServiceAccountSigner struct {
	key   *rsa.PrivateKey
	email string
}

// NewRSAServiceAccountSigner creates a signer from a private key and email.
func NewRSAServiceAccountSigner(key *rsa.PrivateKey, email string) *RSAServiceAccountSigner {
	return &RSAServiceAccountSigner{key: key, email: email}
}

// Sign implements GCPServiceAccountSigner.
func (s *RSAServiceAccountSigner) Sign(_ context.Context, data []byte) ([]byte, error) {
	hashed := sha256.Sum256(data)
	return rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, hashed[:])
}

// Email implements GCPServiceAccountSigner.
func (s *RSAServiceAccountSigner) Email() string {
	return s.email
}

// RealGCPGCSAdapterConfig configures the production GCP GCS adapter.
type RealGCPGCSAdapterConfig struct {
	// DefaultBucket is the default GCS bucket if none specified in the request.
	DefaultBucket string
	// Signer signs the string-to-sign using a service account key.
	Signer GCPServiceAccountSigner
}

// RealGCPGCSAdapter generates V4 signed URLs for Google Cloud Storage.
type RealGCPGCSAdapter struct {
	defaultBucket string
	signer        GCPServiceAccountSigner
}

// NewRealGCPGCSAdapter creates a production GCP GCS signed URL adapter.
func NewRealGCPGCSAdapter(cfg RealGCPGCSAdapterConfig) (*RealGCPGCSAdapter, error) {
	if cfg.Signer == nil {
		return nil, fmt.Errorf("storagegrantsvc: GCP service account signer is required")
	}
	return &RealGCPGCSAdapter{
		defaultBucket: cfg.DefaultBucket,
		signer:        cfg.Signer,
	}, nil
}

// Name implements CloudStorageAdapter.
func (a *RealGCPGCSAdapter) Name() string { return "gcp-gcs" }

// MintGrant generates a V4 signed URL for GCS.
func (a *RealGCPGCSAdapter) MintGrant(ctx context.Context, req *MintStorageGrantRequest) (*StorageGrant, error) {
	bucket := req.Bucket
	if bucket == "" {
		bucket = a.defaultBucket
	}
	if bucket == "" {
		return nil, fmt.Errorf("storagegrantsvc: bucket is required")
	}

	signedURL, err := a.generateV4SignedURL(ctx, bucket, req.Path, req.Permission, req.TTL)
	if err != nil {
		return nil, fmt.Errorf("storagegrantsvc: generate GCS signed URL: %w", err)
	}

	return &StorageGrant{
		URL:        signedURL,
		Bucket:     bucket,
		Path:       req.Path,
		Permission: req.Permission,
		ExpiresAt:  time.Now().Add(req.TTL),
		Adapter:    a.Name(),
	}, nil
}

// generateV4SignedURL creates a GCS V4 signed URL.
// See: https://cloud.google.com/storage/docs/authentication/signatures
func (a *RealGCPGCSAdapter) generateV4SignedURL(ctx context.Context, bucket, objectPath, permission string, ttl time.Duration) (string, error) {
	now := time.Now().UTC()
	datestamp := now.Format("20060102")
	requestTimestamp := now.Format("20060102T150405Z")

	// HTTP method based on permission.
	method := "GET"
	if permission == "write" || permission == "readwrite" {
		method = "PUT"
	}

	// Expiry in seconds (max 7 days for GCS V4).
	expiry := int(ttl.Seconds())
	if expiry > 604800 {
		expiry = 604800
	}

	// Credential scope.
	credentialScope := fmt.Sprintf("%s/auto/storage/goog4_request", datestamp)
	credential := fmt.Sprintf("%s/%s", a.signer.Email(), credentialScope)

	// Canonical resource path.
	canonicalPath := "/" + bucket + "/" + strings.TrimPrefix(objectPath, "/")

	// Query parameters.
	params := url.Values{}
	params.Set("X-Goog-Algorithm", "GOOG4-RSA-SHA256")
	params.Set("X-Goog-Credential", credential)
	params.Set("X-Goog-Date", requestTimestamp)
	params.Set("X-Goog-Expires", fmt.Sprintf("%d", expiry))
	params.Set("X-Goog-SignedHeaders", "host")

	// Build canonical request.
	host := "storage.googleapis.com"
	canonicalQueryString := buildGCSCanonicalQueryString(params)
	canonicalHeaders := fmt.Sprintf("host:%s\n", host)

	canonicalRequest := strings.Join([]string{
		method,
		canonicalPath,
		canonicalQueryString,
		canonicalHeaders,
		"host",
		"UNSIGNED-PAYLOAD",
	}, "\n")

	// String to sign.
	stringToSign := strings.Join([]string{
		"GOOG4-RSA-SHA256",
		requestTimestamp,
		credentialScope,
		gcsHexSHA256([]byte(canonicalRequest)),
	}, "\n")

	// Sign the string.
	signature, err := a.signer.Sign(ctx, []byte(stringToSign))
	if err != nil {
		return "", fmt.Errorf("sign GCS URL: %w", err)
	}

	params.Set("X-Goog-Signature", hex.EncodeToString(signature))

	// Build the final URL.
	signedURL := fmt.Sprintf("https://%s%s?%s", host, canonicalPath, params.Encode())

	return signedURL, nil
}

func gcsHexSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func buildGCSCanonicalQueryString(values url.Values) string {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var pairs []string
	for _, k := range keys {
		vs := values[k]
		sort.Strings(vs)
		for _, v := range vs {
			pairs = append(pairs, gcsPercentEncode(k)+"="+gcsPercentEncode(v))
		}
	}
	return strings.Join(pairs, "&")
}

func gcsPercentEncode(value string) string {
	const hexChars = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(value) * 3)
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexChars[c>>4])
		b.WriteByte(hexChars[c&0x0F])
	}
	return b.String()
}
