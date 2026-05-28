// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package storagegrantsvc

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// AWSCredentials holds AWS credentials for S3 presigning.
type AWSCredentials struct {
	AccessKeyID     string
	SecretAccessKey  string
	SessionToken    string
}

// AWSCredentialProvider provides AWS credentials. Implementations may use
// static credentials, environment variables, instance metadata (IMDS),
// or STS AssumeRole.
type AWSCredentialProvider interface {
	// Retrieve returns the current AWS credentials.
	Retrieve(ctx context.Context) (*AWSCredentials, error)
}

// StaticAWSCredentialProvider returns fixed credentials.
type StaticAWSCredentialProvider struct {
	Creds AWSCredentials
}

// Retrieve implements AWSCredentialProvider.
func (p *StaticAWSCredentialProvider) Retrieve(_ context.Context) (*AWSCredentials, error) {
	return &p.Creds, nil
}

// RealAWSS3AdapterConfig configures the production AWS S3 adapter.
type RealAWSS3AdapterConfig struct {
	// Region is the AWS region (e.g., "us-east-1").
	Region string
	// DefaultBucket is the default S3 bucket if none specified in the request.
	DefaultBucket string
	// CredentialProvider supplies AWS credentials for presigning.
	CredentialProvider AWSCredentialProvider
}

// RealAWSS3Adapter generates presigned S3 URLs using AWS SigV4.
type RealAWSS3Adapter struct {
	region        string
	defaultBucket string
	creds         AWSCredentialProvider
}

// NewRealAWSS3Adapter creates a production AWS S3 presigned URL adapter.
func NewRealAWSS3Adapter(cfg RealAWSS3AdapterConfig) (*RealAWSS3Adapter, error) {
	if cfg.Region == "" {
		return nil, fmt.Errorf("storagegrantsvc: AWS region is required")
	}
	if cfg.CredentialProvider == nil {
		return nil, fmt.Errorf("storagegrantsvc: AWS credential provider is required")
	}
	return &RealAWSS3Adapter{
		region:        cfg.Region,
		defaultBucket: cfg.DefaultBucket,
		creds:         cfg.CredentialProvider,
	}, nil
}

// Name implements CloudStorageAdapter.
func (a *RealAWSS3Adapter) Name() string { return "aws-s3" }

// MintGrant generates a presigned S3 URL for the specified bucket/path/permission.
func (a *RealAWSS3Adapter) MintGrant(ctx context.Context, req *MintStorageGrantRequest) (*StorageGrant, error) {
	creds, err := a.creds.Retrieve(ctx)
	if err != nil {
		return nil, fmt.Errorf("storagegrantsvc: retrieve AWS credentials: %w", err)
	}

	bucket := req.Bucket
	if bucket == "" {
		bucket = a.defaultBucket
	}
	if bucket == "" {
		return nil, fmt.Errorf("storagegrantsvc: bucket is required")
	}

	presignedURL := a.presignS3URL(creds, bucket, req.Path, req.Permission, req.TTL)

	return &StorageGrant{
		URL:        presignedURL,
		Bucket:     bucket,
		Path:       req.Path,
		Permission: req.Permission,
		ExpiresAt:  time.Now().Add(req.TTL),
		Adapter:    a.Name(),
	}, nil
}

// presignS3URL generates a presigned S3 URL using SigV4 using the current time.
func (a *RealAWSS3Adapter) presignS3URL(creds *AWSCredentials, bucket, path, permission string, ttl time.Duration) string {
	return a.presignS3URLAt(creds, bucket, path, permission, ttl, time.Now().UTC())
}

// presignS3URLAt generates a presigned S3 URL at a fixed point in time.
// Accepting the timestamp as a parameter enables deterministic, golden-output tests.
func (a *RealAWSS3Adapter) presignS3URLAt(creds *AWSCredentials, bucket, path, permission string, ttl time.Duration, now time.Time) string {
	datestamp := now.Format("20060102")
	amzdate := now.Format("20060102T150405Z")

	// Determine HTTP method based on permission.
	method := "GET"
	if permission == "write" || permission == "readwrite" {
		method = "PUT"
	}

	// Build the endpoint URL.
	host := fmt.Sprintf("%s.s3.%s.amazonaws.com", bucket, a.region)
	objectPath := "/" + strings.TrimPrefix(path, "/")

	// Expiry in seconds (max 7 days for S3).
	expiry := int(ttl.Seconds())
	if expiry > 604800 {
		expiry = 604800
	}

	// Credential scope.
	credentialScope := fmt.Sprintf("%s/%s/s3/aws4_request", datestamp, a.region)
	credential := fmt.Sprintf("%s/%s", creds.AccessKeyID, credentialScope)

	// Build presigned query parameters.
	params := url.Values{}
	params.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
	params.Set("X-Amz-Credential", credential)
	params.Set("X-Amz-Date", amzdate)
	params.Set("X-Amz-Expires", fmt.Sprintf("%d", expiry))
	params.Set("X-Amz-SignedHeaders", "host")

	if creds.SessionToken != "" {
		params.Set("X-Amz-Security-Token", creds.SessionToken)
	}

	// Build canonical request.
	canonicalQueryString := buildS3CanonicalQueryString(params)
	canonicalHeaders := fmt.Sprintf("host:%s\n", host)

	canonicalRequest := strings.Join([]string{
		method,
		s3URIEncode(objectPath),
		canonicalQueryString,
		canonicalHeaders,
		"host",
		"UNSIGNED-PAYLOAD",
	}, "\n")

	// String to sign.
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzdate,
		credentialScope,
		s3SHA256Hex([]byte(canonicalRequest)),
	}, "\n")

	// Derive signing key.
	signingKey := deriveS3SigningKey(creds.SecretAccessKey, datestamp, a.region)

	// Compute signature.
	signature := hex.EncodeToString(s3HMACSHA256(signingKey, []byte(stringToSign)))
	params.Set("X-Amz-Signature", signature)

	// Build the final URL.
	presignedURL := fmt.Sprintf("https://%s%s?%s", host, objectPath, params.Encode())

	return presignedURL
}

func s3SHA256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func s3HMACSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func deriveS3SigningKey(secretKey, datestamp, region string) []byte {
	kDate := s3HMACSHA256([]byte("AWS4"+secretKey), []byte(datestamp))
	kRegion := s3HMACSHA256(kDate, []byte(region))
	kService := s3HMACSHA256(kRegion, []byte("s3"))
	kSigning := s3HMACSHA256(kService, []byte("aws4_request"))
	return kSigning
}

func buildS3CanonicalQueryString(values url.Values) string {
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
			pairs = append(pairs, s3PercentEncode(k)+"="+s3PercentEncode(v))
		}
	}
	return strings.Join(pairs, "&")
}

func s3PercentEncode(value string) string {
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

// s3URIEncode encodes a URI path component for S3 presigning.
// Unlike standard percent-encoding, forward slashes are NOT encoded.
func s3URIEncode(path string) string {
	segments := strings.Split(path, "/")
	for i, seg := range segments {
		segments[i] = s3PercentEncode(seg)
	}
	return strings.Join(segments, "/")
}
