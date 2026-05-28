// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package main

// providers.go contains bundled credential / token provider implementations
// that the db-token-svc binary uses to authenticate against cloud APIs.
//
// Design rationale: rather than pulling in heavy SDKs (aws-sdk-go-v2, azure-sdk-go,
// google-cloud-go), each provider uses a minimal HTTP client or environment
// variable lookup.  This keeps the binary lean and avoids transitive dependency
// sprawl.  Operators who need more sophisticated credential chains (e.g., EKS
// Pod Identity, GKE Workload Identity Federation) can swap implementations by
// extending this file without touching the adapter interfaces.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/eunolabs/eunox/internal/dbtokensvc"
)

// ── AWS ──────────────────────────────────────────────────────────────────────

// envAWSCredentialProvider reads AWS credentials from standard AWS environment
// variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN).
//
// This covers:
//   - ECS task-role credentials injected via ECS credential helper
//   - Explicit static credentials (IAM user keys, CI pipelines)
//   - Temporary STS credentials (e.g., from AssumeRole, AWS SSO)
//
// For EC2 instance profiles without explicit env vars, extend this type to
// fall back to the IMDSv2 credential endpoint.
type envAWSCredentialProvider struct{}

func (p *envAWSCredentialProvider) Retrieve(_ context.Context) (*dbtokensvc.AWSCredentials, error) {
	keyID := os.Getenv("AWS_ACCESS_KEY_ID")
	secret := os.Getenv("AWS_SECRET_ACCESS_KEY")
	if keyID == "" || secret == "" {
		return nil, errors.New("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set")
	}
	return &dbtokensvc.AWSCredentials{
		AccessKeyID:     keyID,
		SecretAccessKey: secret,
		SessionToken:    os.Getenv("AWS_SESSION_TOKEN"), // empty string is valid for long-term creds
	}, nil
}

// ── Azure ─────────────────────────────────────────────────────────────────────

// imdsAzureTokenProvider acquires Azure AD access tokens from the Azure
// Instance Metadata Service (IMDS).
//
// Available on:
//   - Azure VMs with a managed identity assigned
//   - AKS pods with Azure AD Workload Identity enabled
//   - Azure Container Instances with managed identity
//
// Ref: https://learn.microsoft.com/azure/active-directory/managed-identities-azure-resources/how-to-use-vm-token
type imdsAzureTokenProvider struct {
	client *http.Client
}

func newIMDSAzureTokenProvider() *imdsAzureTokenProvider {
	return &imdsAzureTokenProvider{client: &http.Client{Timeout: 10 * time.Second}}
}

// azureIMDSTokenBaseURL is the IMDS token endpoint for managed identity.
//
//nolint:gosec // This is a well-known Azure metadata service URL, not a credential.
const azureIMDSTokenBaseURL = "http://169.254.169.254/metadata/token?api-version=2018-02-01&resource="

func (p *imdsAzureTokenProvider) GetToken(ctx context.Context, scope string) (*dbtokensvc.AzureToken, error) {
	// IMDS uses the "resource" parameter (audience), not the OAuth2 scope.
	// Strip the "/.default" suffix that MSAL-style callers append.
	resource := strings.TrimSuffix(scope, "/.default")
	reqURL := azureIMDSTokenBaseURL + url.QueryEscape(resource)

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
		ExpiresOn   string `json:"expires_on"` // Unix epoch as decimal string
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

	return &dbtokensvc.AzureToken{
		AccessToken: tokenResp.AccessToken,
		ExpiresOn:   expiresAt,
	}, nil
}

// ── GCP ───────────────────────────────────────────────────────────────────────

// metadataGCPTokenProvider acquires GCP OAuth2 access tokens from the Compute
// Engine Metadata Service.
//
// Available on:
//   - GCE VMs
//   - GKE pods with Workload Identity enabled
//   - Cloud Run services
//   - Cloud Functions
//
// Ref: https://cloud.google.com/compute/docs/access/authenticate-workloads
type metadataGCPTokenProvider struct {
	client *http.Client
}

func newMetadataGCPTokenProvider() *metadataGCPTokenProvider {
	return &metadataGCPTokenProvider{client: &http.Client{Timeout: 10 * time.Second}}
}

// gcpMetadataTokenURL is the metadata server endpoint for a service account token.
//
//nolint:gosec // This is a well-known GCP metadata service URL, not a credential.
const gcpMetadataTokenURL = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

func (p *metadataGCPTokenProvider) GetAccessToken(ctx context.Context, scopes []string) (*dbtokensvc.GCPToken, error) {
	reqURL := gcpMetadataTokenURL
	if len(scopes) > 0 {
		reqURL += "?scopes=" + url.QueryEscape(strings.Join(scopes, ","))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("GCP metadata: build request: %w", err)
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GCP metadata: request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if readErr != nil {
		return nil, fmt.Errorf("GCP metadata: read response: %w", readErr)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GCP metadata: unexpected status %d: %s", resp.StatusCode, body)
	}

	var tokenResp struct {
		AccessToken string  `json:"access_token"`
		ExpiresIn   float64 `json:"expires_in"` // seconds until expiry
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("GCP metadata: decode response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return nil, errors.New("GCP metadata: empty access_token in response")
	}

	return &dbtokensvc.GCPToken{
		AccessToken: tokenResp.AccessToken,
		ExpiresAt:   time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
	}, nil
}
