// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package dbtokensvc

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

// AWSCredentials holds AWS credentials for RDS IAM authentication.
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

// StaticAWSCredentialProvider returns fixed credentials. Suitable for testing
// or environments with externally-rotated credentials.
type StaticAWSCredentialProvider struct {
	Creds AWSCredentials
}

// Retrieve implements AWSCredentialProvider.
func (p *StaticAWSCredentialProvider) Retrieve(_ context.Context) (*AWSCredentials, error) {
	return &p.Creds, nil
}

// RealAWSRDSAdapterConfig configures the production AWS RDS adapter.
type RealAWSRDSAdapterConfig struct {
	// Region is the AWS region (e.g., "us-east-1").
	Region string
	// Endpoint is the RDS database endpoint hostname.
	Endpoint string
	// Port is the database port (default 5432 for PostgreSQL, 3306 for MySQL).
	Port int
	// CredentialProvider supplies AWS credentials for signing.
	CredentialProvider AWSCredentialProvider
}

// RealAWSRDSAdapter generates RDS IAM authentication tokens using AWS SigV4
// presigned requests, per https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.html
type RealAWSRDSAdapter struct {
	region   string
	endpoint string
	port     int
	creds    AWSCredentialProvider
}

// NewRealAWSRDSAdapter creates a production AWS RDS IAM adapter.
func NewRealAWSRDSAdapter(cfg RealAWSRDSAdapterConfig) (*RealAWSRDSAdapter, error) {
	if cfg.Region == "" {
		return nil, fmt.Errorf("dbtokensvc: AWS region is required")
	}
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("dbtokensvc: RDS endpoint is required")
	}
	if cfg.CredentialProvider == nil {
		return nil, fmt.Errorf("dbtokensvc: AWS credential provider is required")
	}
	if cfg.Port == 0 {
		cfg.Port = 5432
	}
	return &RealAWSRDSAdapter{
		region:   cfg.Region,
		endpoint: cfg.Endpoint,
		port:     cfg.Port,
		creds:    cfg.CredentialProvider,
	}, nil
}

// Name implements CloudDBAdapter.
func (a *RealAWSRDSAdapter) Name() string { return "aws-rds" }

// MintCredential generates an RDS IAM authentication token by creating a
// presigned STS GetCallerIdentity-style request against the RDS endpoint.
// The resulting token is a presigned URL that the database client uses as
// the password for IAM authentication.
func (a *RealAWSRDSAdapter) MintCredential(ctx context.Context, req *MintDBCredentialRequest) (*DBCredential, error) {
	creds, err := a.creds.Retrieve(ctx)
	if err != nil {
		return nil, fmt.Errorf("dbtokensvc: retrieve AWS credentials: %w", err)
	}

	// Generate the RDS IAM auth token (presigned URL).
	token := a.generateAuthToken(creds, req.DBUsername, req.TTL)

	return &DBCredential{
		Username:  req.DBUsername,
		Token:     token,
		Host:      a.endpoint,
		Port:      a.port,
		Database:  req.Database,
		ExpiresAt: time.Now().Add(req.TTL),
		Adapter:   a.Name(),
	}, nil
}

// generateAuthToken creates an RDS IAM authentication token using the current time.
func (a *RealAWSRDSAdapter) generateAuthToken(creds *AWSCredentials, dbUser string, ttl time.Duration) string {
	return a.generateAuthTokenAt(creds, dbUser, ttl, time.Now().UTC())
}

// generateAuthTokenAt creates an RDS IAM authentication token at a fixed point in time.
// Accepting the timestamp as a parameter enables deterministic, golden-output tests.
// This is equivalent to the AWS SDK's rdsutils.BuildAuthToken function.
// The token is a presigned HTTP request to the RDS endpoint using SigV4.
func (a *RealAWSRDSAdapter) generateAuthTokenAt(creds *AWSCredentials, dbUser string, ttl time.Duration, now time.Time) string {
	// Build query parameters.
	params := url.Values{}
	params.Set("Action", "connect")
	params.Set("DBUser", dbUser)

	datestamp := now.Format("20060102")
	amzdate := now.Format("20060102T150405Z")

	// Expiry in seconds (capped at 15 minutes per AWS docs).
	expiry := int(ttl.Seconds())
	if expiry > 900 {
		expiry = 900
	}

	// Credential scope.
	credentialScope := fmt.Sprintf("%s/%s/rds-db/aws4_request", datestamp, a.region)
	credential := fmt.Sprintf("%s/%s", creds.AccessKeyID, credentialScope)

	// Presigned query parameters.
	params.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
	params.Set("X-Amz-Credential", credential)
	params.Set("X-Amz-Date", amzdate)
	params.Set("X-Amz-Expires", fmt.Sprintf("%d", expiry))

	signedHeaders := "host"
	params.Set("X-Amz-SignedHeaders", signedHeaders)

	if creds.SessionToken != "" {
		params.Set("X-Amz-Security-Token", creds.SessionToken)
	}

	// Build canonical request for presigned URL.
	canonicalURI := "/"
	canonicalQueryString := buildRDSCanonicalQueryString(params)
	canonicalHeaders := fmt.Sprintf("host:%s:%d\n", a.endpoint, a.port)

	canonicalRequest := strings.Join([]string{
		"GET",
		canonicalURI,
		canonicalQueryString,
		canonicalHeaders,
		signedHeaders,
		"UNSIGNED-PAYLOAD",
	}, "\n")

	// String to sign.
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzdate,
		credentialScope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	// Derive signing key.
	signingKey := deriveRDSSigningKey(creds.SecretAccessKey, datestamp, a.region)

	// Compute signature.
	signature := hex.EncodeToString(hmacSHA256RDS(signingKey, []byte(stringToSign)))

	// Build the final presigned URL (token).
	params.Set("X-Amz-Signature", signature)

	// The RDS auth token is host:port/?query (without scheme).
	token := fmt.Sprintf("%s:%d/?%s", a.endpoint, a.port, params.Encode())

	return token
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func hmacSHA256RDS(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func deriveRDSSigningKey(secretKey, datestamp, region string) []byte {
	kDate := hmacSHA256RDS([]byte("AWS4"+secretKey), []byte(datestamp))
	kRegion := hmacSHA256RDS(kDate, []byte(region))
	kService := hmacSHA256RDS(kRegion, []byte("rds-db"))
	kSigning := hmacSHA256RDS(kService, []byte("aws4_request"))
	return kSigning
}

func buildRDSCanonicalQueryString(values url.Values) string {
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
			pairs = append(pairs, rdsPercentEncode(k)+"="+rdsPercentEncode(v))
		}
	}
	return strings.Join(pairs, "&")
}

func rdsPercentEncode(value string) string {
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
