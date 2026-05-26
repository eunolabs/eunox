// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

// Package storagegrantsvc implements the Storage Grant Service for minting short-lived storage credentials.
package storagegrantsvc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/edgeobs/eunox/pkg/observability"
)

const maxBodySize = 1 << 20 // 1 MB

// Errors returned by the storage grant service.
var (
	ErrInvalidToken        = errors.New("storagegrantsvc: invalid token")
	ErrNoStorageCapability = errors.New("storagegrantsvc: no storage:// capability in token")
	ErrUnsupportedAdapter  = errors.New("storagegrantsvc: unsupported cloud adapter")
	ErrMintFailed          = errors.New("storagegrantsvc: credential mint failed")
)

// StorageGrant represents a minted short-lived storage credential.
type StorageGrant struct {
	URL        string    `json:"url"`
	Token      string    `json:"token,omitempty"`
	Bucket     string    `json:"bucket"`
	Path       string    `json:"path"`
	Permission string    `json:"permission"` // "read", "write", "readwrite"
	ExpiresAt  time.Time `json:"expiresAt"`
	Adapter    string    `json:"adapter"`
}

// MintStorageGrantRequest is the input to a cloud storage adapter.
type MintStorageGrantRequest struct {
	UserID     string
	TenantID   string
	Bucket     string
	Path       string
	Permission string
	TTL        time.Duration
}

// CloudStorageAdapter mints short-lived storage credentials for a specific cloud provider.
type CloudStorageAdapter interface {
	// Name returns the adapter name (e.g., "aws-s3", "azure-blob", "gcp-gcs").
	Name() string
	// MintGrant mints a short-lived storage grant.
	MintGrant(ctx context.Context, req *MintStorageGrantRequest) (*StorageGrant, error)
}

// TokenVerifier verifies JWTs and extracts claims.
type TokenVerifier interface {
	// VerifyAndExtractCaps verifies a JWT and returns the subject and storage:// capabilities.
	VerifyAndExtractCaps(ctx context.Context, tokenStr string) (*TokenClaims, error)
}

// TokenClaims holds extracted token information relevant for storage grant minting.
type TokenClaims struct {
	Subject          string
	TenantID         string
	StorageResources []string // storage:// resource URIs from capabilities.
}

// Config holds the storage grant service configuration.
type Config struct {
	DefaultTTL time.Duration
	MaxTTL     time.Duration
	Adapter    string // "aws-s3", "azure-blob", "gcp-gcs"
}

// Dependencies holds the injected backends for the storage grant service.
type Dependencies struct {
	Adapter  CloudStorageAdapter
	Verifier TokenVerifier
	Logger   *slog.Logger
	Metrics  *observability.MetricsRegistry
}

// App is the Storage Grant Service HTTP application.
type App struct {
	config  Config
	deps    Dependencies
	router  chi.Router
	metrics *storageMetrics
}

type storageMetrics struct {
	grantTotal    *prometheus.CounterVec
	grantDuration *prometheus.HistogramVec
}

// New creates a new Storage Grant Service App.
func New(cfg Config, deps Dependencies) *App {
	if cfg.DefaultTTL == 0 {
		cfg.DefaultTTL = 15 * time.Minute
	}
	if cfg.MaxTTL == 0 {
		cfg.MaxTTL = 60 * time.Minute
	}
	app := &App{
		config: cfg,
		deps:   deps,
	}
	app.metrics = app.initMetrics()
	app.router = app.buildRouter()
	return app
}

// Handler returns the http.Handler for the storage grant service.
func (app *App) Handler() http.Handler {
	return app.router
}

func (app *App) initMetrics() *storageMetrics {
	if app.deps.Metrics == nil {
		return nil
	}
	return &storageMetrics{
		grantTotal: app.deps.Metrics.NewCounter(
			"storage_grants_minted_total",
			"Total storage grants minted",
			"adapter", "status",
		),
		grantDuration: app.deps.Metrics.NewHistogram(
			"storage_grant_mint_duration_seconds",
			"Duration of storage grant minting",
			observability.DefaultHTTPBuckets,
			"adapter",
		),
	}
}

func (app *App) buildRouter() chi.Router {
	r := chi.NewRouter()

	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.RequestID)

	if app.deps.Logger != nil {
		r.Use(observability.RequestLogging(app.deps.Logger))
	}

	r.Get("/health/live", app.handleLive)
	r.Get("/health/ready", app.handleReady)

	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/storage-grants", app.handleMintStorageGrant)
	})

	return r
}

func (app *App) handleLive(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (app *App) handleReady(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

// handleMintStorageGrant verifies a JWT and mints short-lived storage credentials.
func (app *App) handleMintStorageGrant(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Extract bearer token.
	tokenStr := extractBearerToken(r)
	if tokenStr == "" {
		writeError(w, http.StatusUnauthorized, "missing_token", "Authorization header required")
		return
	}

	// Verify token and extract capabilities.
	claims, err := app.deps.Verifier.VerifyAndExtractCaps(r.Context(), tokenStr)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_token", "token verification failed")
		return
	}

	// Check for storage:// capabilities.
	if len(claims.StorageResources) == 0 {
		writeError(w, http.StatusForbidden, "no_capability",
			"token does not contain storage:// capabilities")
		return
	}

	// Parse request body for optional parameters.
	var req struct {
		Bucket     string `json:"bucket"`
		Path       string `json:"path"`
		Permission string `json:"permission"`
		TTL        int    `json:"ttlSeconds"`
	}
	if r.Body != nil && r.Body != http.NoBody {
		if err := readJSON(w, r, &req); err != nil {
			if errors.Is(err, io.EOF) {
				// Treat an empty body as "no body".
			} else {
				var maxBytesErr *http.MaxBytesError
				if errors.As(err, &maxBytesErr) {
					writeError(w, http.StatusRequestEntityTooLarge, "request_too_large", "request body too large")
					return
				}
				writeError(w, http.StatusBadRequest, "invalid_request", "invalid request body")
				return
			}
		}
	}

	// Determine TTL.
	ttl := app.config.DefaultTTL
	if req.TTL > 0 {
		ttl = time.Duration(req.TTL) * time.Second
		if ttl > app.config.MaxTTL {
			ttl = app.config.MaxTTL
		}
	}

	// Extract bucket and path from capability if not specified.
	bucket := req.Bucket
	path := req.Path
	permission := req.Permission
	if bucket == "" && len(claims.StorageResources) > 0 {
		bucket, path = extractStorageFromURI(claims.StorageResources[0])
	}
	if permission == "" {
		permission = "read"
	}
	if bucket == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "bucket is required")
		return
	}
	if path == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "path is required")
		return
	}

	// Validate permission matches capability.
	if !isPermissionAllowed(permission, claims.StorageResources) {
		writeError(w, http.StatusForbidden, "permission_denied",
			"requested permission exceeds capability")
		return
	}

	// Mint grant.
	mintReq := MintStorageGrantRequest{
		UserID:     claims.Subject,
		TenantID:   claims.TenantID,
		Bucket:     bucket,
		Path:       path,
		Permission: permission,
		TTL:        ttl,
	}

	grant, err := app.deps.Adapter.MintGrant(r.Context(), &mintReq)
	if err != nil {
		if app.metrics != nil {
			app.metrics.grantTotal.WithLabelValues(app.deps.Adapter.Name(), "error").Inc()
		}
		writeError(w, http.StatusInternalServerError, "mint_failed", "failed to mint storage grant")
		return
	}

	if app.metrics != nil {
		app.metrics.grantTotal.WithLabelValues(app.deps.Adapter.Name(), "success").Inc()
		app.metrics.grantDuration.WithLabelValues(app.deps.Adapter.Name()).Observe(time.Since(start).Seconds())
	}

	writeJSON(w, http.StatusOK, grant)
}

func extractStorageFromURI(uri string) (bucket, path string) {
	// Remove the storage:// scheme and split the remainder into bucket/path components.
	trimmed := strings.TrimPrefix(uri, "storage://")
	parts := strings.SplitN(trimmed, "/", 2)
	if len(parts) >= 1 {
		bucket = parts[0]
	}
	if len(parts) >= 2 {
		path = parts[1]
	}
	return
}

func isPermissionAllowed(requested string, resources []string) bool {
	return requested == "read" && len(resources) > 0
}

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{
		"error":   code,
		"message": message,
	})
}

func readJSON(w http.ResponseWriter, r *http.Request, v interface{}) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
	return json.NewDecoder(r.Body).Decode(v)
}

// --- Cloud Adapter Implementations ---

// AWSS3Adapter generates presigned URLs for AWS S3.
type AWSS3Adapter struct {
	Region string
	Bucket string
}

// NewAWSS3Adapter creates an AWS S3 presigned URL adapter.
func NewAWSS3Adapter(region, bucket string) *AWSS3Adapter {
	return &AWSS3Adapter{Region: region, Bucket: bucket}
}

// Name implements CloudStorageAdapter.
func (a *AWSS3Adapter) Name() string { return "aws-s3" }

// MintGrant implements CloudStorageAdapter.
func (a *AWSS3Adapter) MintGrant(_ context.Context, req *MintStorageGrantRequest) (*StorageGrant, error) {
	// In production, this would use AWS SDK to generate a presigned URL
	// using s3.PresignClient with PutObject or GetObject.
	bucket := req.Bucket
	if bucket == "" {
		bucket = a.Bucket
	}

	presignedURL := fmt.Sprintf(
		"https://%s.s3.%s.amazonaws.com/%s?X-Amz-Expires=%d&X-Amz-SignedHeaders=host",
		bucket, a.Region, req.Path, int(req.TTL.Seconds()),
	)

	return &StorageGrant{
		URL:        presignedURL,
		Bucket:     bucket,
		Path:       req.Path,
		Permission: req.Permission,
		ExpiresAt:  time.Now().Add(req.TTL),
		Adapter:    a.Name(),
	}, nil
}

// AzureBlobAdapter generates SAS tokens for Azure Blob Storage.
type AzureBlobAdapter struct {
	AccountName string
	Container   string
}

// NewAzureBlobAdapter creates an Azure Blob SAS adapter.
func NewAzureBlobAdapter(accountName, container string) *AzureBlobAdapter {
	return &AzureBlobAdapter{AccountName: accountName, Container: container}
}

// Name implements CloudStorageAdapter.
func (a *AzureBlobAdapter) Name() string { return "azure-blob" }

// MintGrant implements CloudStorageAdapter.
func (a *AzureBlobAdapter) MintGrant(_ context.Context, req *MintStorageGrantRequest) (*StorageGrant, error) {
	// In production, this would use Azure SDK to generate a user-delegation SAS token.
	bucket := req.Bucket
	if bucket == "" {
		bucket = a.Container
	}

	expiry := time.Now().Add(req.TTL)
	sasURL := fmt.Sprintf(
		"https://%s.blob.core.windows.net/%s/%s?se=%s&sp=%s&sv=2024-01-01",
		a.AccountName, bucket, req.Path,
		expiry.UTC().Format(time.RFC3339),
		permissionToSASPermission(req.Permission),
	)

	return &StorageGrant{
		URL:        sasURL,
		Bucket:     bucket,
		Path:       req.Path,
		Permission: req.Permission,
		ExpiresAt:  expiry,
		Adapter:    a.Name(),
	}, nil
}

func permissionToSASPermission(perm string) string {
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

// GCPGCSAdapter generates signed URLs for Google Cloud Storage.
type GCPGCSAdapter struct {
	ProjectID string
	Bucket    string
}

// NewGCPGCSAdapter creates a GCP GCS signed-URL adapter.
func NewGCPGCSAdapter(projectID, bucket string) *GCPGCSAdapter {
	return &GCPGCSAdapter{ProjectID: projectID, Bucket: bucket}
}

// Name implements CloudStorageAdapter.
func (a *GCPGCSAdapter) Name() string { return "gcp-gcs" }

// MintGrant implements CloudStorageAdapter.
func (a *GCPGCSAdapter) MintGrant(_ context.Context, req *MintStorageGrantRequest) (*StorageGrant, error) {
	// In production, this would use GCP storage client to generate a V4 signed URL.
	bucket := req.Bucket
	if bucket == "" {
		bucket = a.Bucket
	}

	expiry := time.Now().Add(req.TTL)
	signedURL := fmt.Sprintf(
		"https://storage.googleapis.com/%s/%s?X-Goog-Expires=%d&X-Goog-SignedHeaders=host",
		bucket, req.Path, int(req.TTL.Seconds()),
	)

	return &StorageGrant{
		URL:        signedURL,
		Bucket:     bucket,
		Path:       req.Path,
		Permission: req.Permission,
		ExpiresAt:  expiry,
		Adapter:    a.Name(),
	}, nil
}
