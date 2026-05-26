// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package storagegrantsvc

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

// AzureStorageTokenProvider acquires Azure AD access tokens for Azure Blob Storage.
// Implementations may use managed identity, client credentials, or workload identity.
type AzureStorageTokenProvider interface {
	// GetToken acquires an access token for the specified resource scope.
	GetToken(ctx context.Context, scope string) (*AzureStorageToken, error)
}

// AzureStorageToken represents an Azure AD access token.
type AzureStorageToken struct {
	// AccessToken is the bearer token string.
	AccessToken string
	// ExpiresOn is when the token expires.
	ExpiresOn time.Time
}

// AzureUserDelegationKey holds the key used to sign user-delegation SAS tokens.
type AzureUserDelegationKey struct {
	// Value is the base64-encoded delegation key.
	Value string
	// SignedStart is the start time of the key validity.
	SignedStart time.Time
	// SignedExpiry is the expiry time of the key.
	SignedExpiry time.Time
	// SignedOID is the object ID of the user/managed identity.
	SignedOID string
	// SignedTID is the tenant ID.
	SignedTID string
	// SignedService is the service scope (b=blob).
	SignedService string
	// SignedVersion is the storage API version.
	SignedVersion string
}

// AzureDelegationKeyProvider retrieves user delegation keys for SAS token generation.
type AzureDelegationKeyProvider interface {
	// GetUserDelegationKey retrieves a user delegation key valid for the given time range.
	GetUserDelegationKey(ctx context.Context, accountName string, start, expiry time.Time) (*AzureUserDelegationKey, error)
}

// RealAzureBlobAdapterConfig configures the production Azure Blob adapter.
type RealAzureBlobAdapterConfig struct {
	// AccountName is the Azure Storage account name.
	AccountName string
	// DefaultContainer is the default container if none specified in the request.
	DefaultContainer string
	// DelegationKeyProvider supplies user delegation keys for SAS token signing.
	DelegationKeyProvider AzureDelegationKeyProvider
}

// RealAzureBlobAdapter generates user-delegation SAS tokens for Azure Blob Storage.
type RealAzureBlobAdapter struct {
	accountName       string
	defaultContainer  string
	delegationKeyProv AzureDelegationKeyProvider
}

// AzureBlobStorageScope is the resource identifier for Azure Blob Storage.
const AzureBlobStorageScope = "https://storage.azure.com/.default"

// AzureStorageAPIVersion is the storage services version used in SAS tokens.
const AzureStorageAPIVersion = "2024-11-04"

// NewRealAzureBlobAdapter creates a production Azure Blob SAS adapter.
func NewRealAzureBlobAdapter(cfg RealAzureBlobAdapterConfig) (*RealAzureBlobAdapter, error) {
	if cfg.AccountName == "" {
		return nil, fmt.Errorf("storagegrantsvc: Azure storage account name is required")
	}
	if cfg.DelegationKeyProvider == nil {
		return nil, fmt.Errorf("storagegrantsvc: Azure delegation key provider is required")
	}
	return &RealAzureBlobAdapter{
		accountName:       cfg.AccountName,
		defaultContainer:  cfg.DefaultContainer,
		delegationKeyProv: cfg.DelegationKeyProvider,
	}, nil
}

// Name implements CloudStorageAdapter.
func (a *RealAzureBlobAdapter) Name() string { return "azure-blob" }

// MintGrant generates a user-delegation SAS URL for Azure Blob Storage.
func (a *RealAzureBlobAdapter) MintGrant(ctx context.Context, req *MintStorageGrantRequest) (*StorageGrant, error) {
	container := req.Bucket
	if container == "" {
		container = a.defaultContainer
	}
	if container == "" {
		return nil, fmt.Errorf("storagegrantsvc: container is required")
	}

	now := time.Now().UTC()
	expiry := now.Add(req.TTL)

	// Get user delegation key.
	delegationKey, err := a.delegationKeyProv.GetUserDelegationKey(ctx, a.accountName, now, expiry)
	if err != nil {
		return nil, fmt.Errorf("storagegrantsvc: get Azure delegation key: %w", err)
	}

	// Generate SAS token.
	sasToken, err := a.generateUserDelegationSAS(delegationKey, container, req.Path, req.Permission, now, expiry)
	if err != nil {
		return nil, fmt.Errorf("storagegrantsvc: generate Azure SAS: %w", err)
	}

	// Build the full URL.
	blobURL := fmt.Sprintf("https://%s.blob.core.windows.net/%s/%s?%s",
		a.accountName, container, req.Path, sasToken)

	return &StorageGrant{
		URL:        blobURL,
		Token:      sasToken,
		Bucket:     container,
		Path:       req.Path,
		Permission: req.Permission,
		ExpiresAt:  expiry,
		Adapter:    a.Name(),
	}, nil
}

// generateUserDelegationSAS creates a user-delegation SAS token string.
func (a *RealAzureBlobAdapter) generateUserDelegationSAS(
	key *AzureUserDelegationKey,
	container, blobPath, permission string,
	start, expiry time.Time,
) (string, error) {
	// Map permission to SAS permission string.
	sp := azureBlobPermission(permission)

	// Format times.
	st := start.Format("2006-01-02T15:04:05Z")
	se := expiry.Format("2006-01-02T15:04:05Z")

	// Canonical resource.
	canonicalResource := fmt.Sprintf("/blob/%s/%s/%s", a.accountName, container, blobPath)

	// String to sign for user delegation SAS.
	// See: https://learn.microsoft.com/en-us/rest/api/storageservices/create-user-delegation-sas
	stringToSign := strings.Join([]string{
		sp,                   // signedPermissions
		st,                   // signedStart
		se,                   // signedExpiry
		canonicalResource,    // canonicalizedResource
		key.SignedOID,        // signedKeyObjectId
		key.SignedTID,        // signedKeyTenantId
		key.SignedStart.Format("2006-01-02T15:04:05Z"),  // signedKeyStart
		key.SignedExpiry.Format("2006-01-02T15:04:05Z"), // signedKeyExpiry
		key.SignedService,    // signedKeyService
		key.SignedVersion,    // signedKeyVersion
		"",                   // signedAuthorizedUserObjectId
		"",                   // signedUnauthorizedUserObjectId
		"",                   // signedCorrelationId
		"",                   // signedIP
		"https",              // signedProtocol
		AzureStorageAPIVersion, // signedVersion
		"b",                  // signedResource (b=blob)
		"",                   // signedSnapshotTime
		"",                   // signedEncryptionScope
		"",                   // rscc (cache-control)
		"",                   // rscd (content-disposition)
		"",                   // rsce (content-encoding)
		"",                   // rscl (content-language)
		"",                   // rsct (content-type)
	}, "\n")

	// Sign with the delegation key.
	keyBytes, err := base64.StdEncoding.DecodeString(key.Value)
	if err != nil {
		return "", fmt.Errorf("decode delegation key: %w", err)
	}
	sig := azureBlobHMACSHA256(keyBytes, []byte(stringToSign))
	signature := base64.StdEncoding.EncodeToString(sig)

	// Build query string.
	params := fmt.Sprintf(
		"sp=%s&st=%s&se=%s&skoid=%s&sktid=%s&skt=%s&ske=%s&sks=%s&skv=%s&spr=https&sv=%s&sr=b&sig=%s",
		sp,
		st,
		se,
		key.SignedOID,
		key.SignedTID,
		key.SignedStart.Format("2006-01-02T15:04:05Z"),
		key.SignedExpiry.Format("2006-01-02T15:04:05Z"),
		key.SignedService,
		key.SignedVersion,
		AzureStorageAPIVersion,
		signature,
	)

	return params, nil
}

func azureBlobPermission(perm string) string {
	switch perm {
	case "read":
		return "r"
	case "write":
		return "w"
	case "readwrite":
		return "rw"
	default:
		return "r"
	}
}

func azureBlobHMACSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}
