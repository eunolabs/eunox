// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package main

// providers.go contains bundled credential / token / key provider implementations
// that the storage-grant-svc binary uses to authenticate against cloud APIs.
//
// Design rationale: same as db-token-svc/providers.go — minimal HTTP clients
// rather than heavy cloud SDKs. See db-token-svc/providers.go for extended notes.

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/eunolabs/eunox/internal/storagegrantsvc"
)

// ── AWS ──────────────────────────────────────────────────────────────────────

// envAWSCredentialProvider reads AWS credentials from standard AWS environment
// variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN).
type envAWSCredentialProvider struct{}

func (p *envAWSCredentialProvider) Retrieve(_ context.Context) (*storagegrantsvc.AWSCredentials, error) {
	keyID := os.Getenv("AWS_ACCESS_KEY_ID")
	secret := os.Getenv("AWS_SECRET_ACCESS_KEY")
	if keyID == "" || secret == "" {
		return nil, errors.New("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set")
	}
	return &storagegrantsvc.AWSCredentials{
		AccessKeyID:     keyID,
		SecretAccessKey: secret,
		SessionToken:    os.Getenv("AWS_SESSION_TOKEN"),
	}, nil
}

// ── Azure ─────────────────────────────────────────────────────────────────────

// imdsAzureStorageTokenProvider acquires Azure AD access tokens for Azure Blob
// Storage from the Azure Instance Metadata Service (IMDS).
// See db-token-svc/providers.go for full design notes.
type imdsAzureStorageTokenProvider struct {
	client *http.Client
}

func newIMDSAzureStorageTokenProvider() *imdsAzureStorageTokenProvider {
	return &imdsAzureStorageTokenProvider{client: &http.Client{Timeout: 10 * time.Second}}
}

//nolint:gosec // This is a well-known Azure metadata service URL, not a credential.
const azureStorageIMDSBaseURL = "http://169.254.169.254/metadata/token?api-version=2018-02-01&resource="

func (p *imdsAzureStorageTokenProvider) GetToken(ctx context.Context, scope string) (*storagegrantsvc.AzureStorageToken, error) {
	resource := strings.TrimSuffix(scope, "/.default")
	reqURL := azureStorageIMDSBaseURL + url.QueryEscape(resource)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("azure IMDS: build request: %w", err)
	}
	req.Header.Set("Metadata", "true")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("azure IMDS: request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if readErr != nil {
		return nil, fmt.Errorf("azure IMDS: read response: %w", readErr)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("azure IMDS: unexpected status %d: %s", resp.StatusCode, body)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresOn   string `json:"expires_on"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("azure IMDS: decode response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return nil, errors.New("azure IMDS: empty access_token in response")
	}

	if tokenResp.ExpiresOn == "" {
		return nil, errors.New("azure IMDS: missing expires_on in response")
	}
	epoch, parseErr := strconv.ParseInt(tokenResp.ExpiresOn, 10, 64)
	if parseErr != nil {
		return nil, fmt.Errorf("azure IMDS: parse expires_on %q: %w", tokenResp.ExpiresOn, parseErr)
	}
	expiresAt := time.Unix(epoch, 0).UTC()

	return &storagegrantsvc.AzureStorageToken{
		AccessToken: tokenResp.AccessToken,
		ExpiresOn:   expiresAt,
	}, nil
}

// restAzureDelegationKeyProvider retrieves Azure Blob Storage user delegation
// keys by calling the Azure Storage REST API.
//
// The delegation key is used to sign user-delegation SAS tokens without
// requiring a shared-account key (which has account-wide permissions).
//
// API Reference:
// https://learn.microsoft.com/rest/api/storageservices/get-user-delegation-key
type restAzureDelegationKeyProvider struct {
	tokenProvider storagegrantsvc.AzureStorageTokenProvider
	client        *http.Client
}

func newRESTAzureDelegationKeyProvider(tp storagegrantsvc.AzureStorageTokenProvider) *restAzureDelegationKeyProvider {
	return &restAzureDelegationKeyProvider{
		tokenProvider: tp,
		client:        &http.Client{Timeout: 15 * time.Second},
	}
}

func (p *restAzureDelegationKeyProvider) GetUserDelegationKey(
	ctx context.Context,
	accountName string,
	start, expiry time.Time,
) (*storagegrantsvc.AzureUserDelegationKey, error) {
	// Acquire a bearer token for Azure Blob Storage.
	token, err := p.tokenProvider.GetToken(ctx, storagegrantsvc.AzureBlobStorageScope)
	if err != nil {
		return nil, fmt.Errorf("azure delegation key: acquire token: %w", err)
	}

	// Build the GetUserDelegationKey request body.
	startStr := start.UTC().Format(time.RFC3339)
	expiryStr := expiry.UTC().Format(time.RFC3339)
	reqBody := fmt.Sprintf(
		"<?xml version=\"1.0\" encoding=\"utf-8\"?><KeyInfo><Start>%s</Start><Expiry>%s</Expiry></KeyInfo>",
		startStr, expiryStr,
	)

	reqURL := fmt.Sprintf("https://%s.blob.core.windows.net/?restype=service&comp=userdelegationkey", accountName)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewBufferString(reqBody))
	if err != nil {
		return nil, fmt.Errorf("azure delegation key: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("x-ms-version", storagegrantsvc.AzureStorageAPIVersion)
	req.Header.Set("Content-Type", "application/xml")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("azure delegation key: request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if readErr != nil {
		return nil, fmt.Errorf("azure delegation key: read response: %w", readErr)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("azure delegation key: unexpected status %d: %s", resp.StatusCode, respBody)
	}

	// Parse the XML delegation key response.
	var xmlKey struct {
		XMLName       xml.Name `xml:"UserDelegationKey"`
		SignedOID     string   `xml:"SignedOid"`
		SignedTID     string   `xml:"SignedTid"`
		SignedStart   string   `xml:"SignedStart"`
		SignedExpiry  string   `xml:"SignedExpiry"`
		SignedService string   `xml:"SignedService"`
		SignedVersion string   `xml:"SignedVersion"`
		Value         string   `xml:"Value"`
	}
	if err := xml.Unmarshal(respBody, &xmlKey); err != nil {
		return nil, fmt.Errorf("azure delegation key: parse response: %w", err)
	}

	signedStart, err := time.Parse(time.RFC3339, xmlKey.SignedStart)
	if err != nil {
		return nil, fmt.Errorf("azure delegation key: parse SignedStart %q: %w", xmlKey.SignedStart, err)
	}
	signedExpiry, err := time.Parse(time.RFC3339, xmlKey.SignedExpiry)
	if err != nil {
		return nil, fmt.Errorf("azure delegation key: parse SignedExpiry %q: %w", xmlKey.SignedExpiry, err)
	}

	return &storagegrantsvc.AzureUserDelegationKey{
		Value:         xmlKey.Value,
		SignedStart:   signedStart,
		SignedExpiry:  signedExpiry,
		SignedOID:     xmlKey.SignedOID,
		SignedTID:     xmlKey.SignedTID,
		SignedService: xmlKey.SignedService,
		SignedVersion: xmlKey.SignedVersion,
	}, nil
}

// ── GCP ───────────────────────────────────────────────────────────────────────

// serviceAccountKeyJSON is the structure of a GCP service account key file.
// Ref: https://cloud.google.com/iam/docs/keys-create-delete#iam-service-account-keys-create-console
type serviceAccountKeyJSON struct {
	Type        string `json:"type"`
	PrivateKey  string `json:"private_key"`
	ClientEmail string `json:"client_email"`
}

// loadServiceAccountSigner loads a GCP service account RSA signer from the
// JSON key file at the path given by GOOGLE_APPLICATION_CREDENTIALS.
//
// The key file must be a service account key (type: "service_account").
// The private key field supports both PKCS#8 ("BEGIN PRIVATE KEY") and
// PKCS#1 ("BEGIN RSA PRIVATE KEY") PEM encoding.
func loadServiceAccountSigner() (*storagegrantsvc.RSAServiceAccountSigner, error) {
	keyFile := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	if keyFile == "" {
		return nil, errors.New("GOOGLE_APPLICATION_CREDENTIALS must be set for gcp-gcs adapter")
	}

	data, err := os.ReadFile(keyFile) //nolint:gosec // Path comes from GOOGLE_APPLICATION_CREDENTIALS env var, a documented operator-supplied config path.
	if err != nil {
		return nil, fmt.Errorf("GCS: read service account key: %w", err)
	}

	var keyJSON serviceAccountKeyJSON
	if err := json.Unmarshal(data, &keyJSON); err != nil {
		return nil, fmt.Errorf("GCS: parse service account key JSON: %w", err)
	}
	if keyJSON.Type != "service_account" {
		return nil, fmt.Errorf("GCS: expected service_account key type, got %q", keyJSON.Type)
	}
	if keyJSON.PrivateKey == "" || keyJSON.ClientEmail == "" {
		return nil, errors.New("GCS: service account key JSON missing private_key or client_email")
	}

	block, _ := pem.Decode([]byte(keyJSON.PrivateKey))
	if block == nil {
		return nil, errors.New("GCS: failed to decode PEM private key")
	}

	var rsaKey *rsa.PrivateKey
	switch block.Type {
	case "PRIVATE KEY":
		// PKCS#8 encoding — standard for GCP service account keys.
		key, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if parseErr != nil {
			return nil, fmt.Errorf("GCS: parse PKCS#8 private key: %w", parseErr)
		}
		var ok bool
		rsaKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("GCS: expected RSA private key, got %T", key)
		}
	case "RSA PRIVATE KEY":
		// PKCS#1 encoding — legacy format, supported for flexibility.
		var parseErr error
		rsaKey, parseErr = x509.ParsePKCS1PrivateKey(block.Bytes)
		if parseErr != nil {
			return nil, fmt.Errorf("GCS: parse PKCS#1 RSA private key: %w", parseErr)
		}
	default:
		return nil, fmt.Errorf("GCS: unsupported PEM block type %q", block.Type)
	}

	return storagegrantsvc.NewRSAServiceAccountSigner(rsaKey, keyJSON.ClientEmail), nil
}
