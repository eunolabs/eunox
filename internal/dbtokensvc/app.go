// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

// Package dbtokensvc implements the DB Token Service for minting short-lived database credentials.
package dbtokensvc

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

	"github.com/eunolabs/eunox/pkg/observability"
)

const defaultMaxBodySize int64 = 1 << 20 // 1 MB

// Errors returned by the db token service.
var (
	ErrInvalidToken       = errors.New("dbtokensvc: invalid token")
	ErrNoDBCapability     = errors.New("dbtokensvc: no db:// capability in token")
	ErrUnsupportedAdapter = errors.New("dbtokensvc: unsupported cloud adapter")
	ErrMintFailed         = errors.New("dbtokensvc: credential mint failed")
	ErrNotImplemented     = errors.New("dbtokensvc: cloud adapter not implemented for production use")
)

// StubAdapter is an interface that stub adapters can implement to identify themselves.
// Any adapter implementing this interface will be rejected in production mode.
type StubAdapter interface {
	IsStub() bool
}

// DBCredential represents a minted short-lived database credential.
type DBCredential struct {
	Username  string    `json:"username"`
	Password  string    `json:"password,omitempty"`
	Token     string    `json:"token,omitempty"`
	Host      string    `json:"host"`
	Port      int       `json:"port"`
	Database  string    `json:"database"`
	ExpiresAt time.Time `json:"expiresAt"`
	Adapter   string    `json:"adapter"`
}

// MintDBCredentialRequest is the input to a cloud adapter.
type MintDBCredentialRequest struct {
	UserID     string
	TenantID   string
	Database   string
	DBUsername string
	TTL        time.Duration
	Region     string
}

// CloudDBAdapter mints short-lived database credentials for a specific cloud provider.
type CloudDBAdapter interface {
	// Name returns the adapter name (e.g., "aws-rds", "azure-sql", "gcp-cloudsql").
	Name() string
	// MintCredential mints a short-lived database credential.
	MintCredential(ctx context.Context, req *MintDBCredentialRequest) (*DBCredential, error)
}

// TokenVerifier verifies JWTs and extracts claims.
type TokenVerifier interface {
	// VerifyAndExtractCaps verifies a JWT and returns the subject and db:// capabilities.
	VerifyAndExtractCaps(ctx context.Context, tokenStr string) (*TokenClaims, error)
}

// TokenClaims holds extracted token information relevant for DB token minting.
type TokenClaims struct {
	Subject      string
	TenantID     string
	DBResources  []string // db:// resource URIs from capabilities.
	PolicyUserID string   // Mapped DB username from policy.
}

// CapabilityMapping maps db:// capabilities to database usernames.
type CapabilityMapping struct {
	// ResourceToUsername maps db:// resource patterns to DB usernames.
	ResourceToUsername map[string]string
}

// Config holds the DB token service configuration.
type Config struct {
	DefaultTTL     time.Duration
	MaxTTL         time.Duration
	Adapter        string // "aws-rds", "azure-sql", "gcp-cloudsql"
	ProductionMode bool   // When true, stub adapters are rejected.
}

// Dependencies holds the injected backends for the DB token service.
type Dependencies struct {
	Adapter  CloudDBAdapter
	Verifier TokenVerifier
	Mapping  *CapabilityMapping
	Logger   *slog.Logger
	Metrics  *observability.MetricsRegistry
}

// App is the DB Token Service HTTP application.
type App struct {
	config  Config
	deps    Dependencies
	router  chi.Router
	metrics *dbTokenMetrics
}

type dbTokenMetrics struct {
	mintTotal    *prometheus.CounterVec
	mintDuration *prometheus.HistogramVec
}

// New creates a new DB Token Service App.
// In production mode, it returns an error if a stub adapter is configured.
func New(cfg Config, deps Dependencies) (*App, error) {
	if cfg.DefaultTTL == 0 {
		cfg.DefaultTTL = 15 * time.Minute
	}
	if cfg.MaxTTL == 0 {
		cfg.MaxTTL = 60 * time.Minute
	}

	// In production mode, reject stub adapters.
	if cfg.ProductionMode {
		if stub, ok := deps.Adapter.(StubAdapter); ok && stub.IsStub() {
			return nil, fmt.Errorf("%w: adapter %q is a stub and cannot be used in production; configure real cloud SDK credentials", ErrNotImplemented, deps.Adapter.Name())
		}
	}

	app := &App{
		config: cfg,
		deps:   deps,
	}
	app.metrics = app.initMetrics()
	app.router = app.buildRouter()
	return app, nil
}

// Handler returns the http.Handler for the DB token service.
func (app *App) Handler() http.Handler {
	return app.router
}

func (app *App) initMetrics() *dbTokenMetrics {
	if app.deps.Metrics == nil {
		return nil
	}
	return &dbTokenMetrics{
		mintTotal: app.deps.Metrics.NewCounter(
			"db_tokens_minted_total",
			"Total DB tokens minted",
			"adapter", "status",
		),
		mintDuration: app.deps.Metrics.NewHistogram(
			"db_token_mint_duration_seconds",
			"Duration of DB token minting",
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
		r.Post("/db-tokens", app.handleMintDBToken)
	})

	return r
}

func (app *App) handleLive(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (app *App) handleReady(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

// handleMintDBToken verifies a JWT and mints short-lived DB credentials.
func (app *App) handleMintDBToken(w http.ResponseWriter, r *http.Request) {
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

	// Check for db:// capabilities.
	if len(claims.DBResources) == 0 {
		writeError(w, http.StatusForbidden, "no_capability",
			"token does not contain db:// capabilities")
		return
	}

	// Parse request body for optional TTL and database selection.
	var req struct {
		Database string `json:"database"`
		TTL      int    `json:"ttlSeconds"`
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

	// Map capability to database username.
	dbUsername := app.mapToDBUsername(claims)
	if dbUsername == "" {
		writeError(w, http.StatusForbidden, "no_mapping",
			"no database username mapping for capabilities")
		return
	}

	// Determine database.
	database := req.Database
	if database == "" && len(claims.DBResources) > 0 {
		database = extractDatabaseFromURI(claims.DBResources[0])
	}
	if database == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "database is required")
		return
	}

	// Mint credential.
	mintReq := MintDBCredentialRequest{
		UserID:     claims.Subject,
		TenantID:   claims.TenantID,
		Database:   database,
		DBUsername: dbUsername,
		TTL:        ttl,
	}

	cred, err := app.deps.Adapter.MintCredential(r.Context(), &mintReq)
	if err != nil {
		if app.metrics != nil {
			app.metrics.mintTotal.WithLabelValues(app.deps.Adapter.Name(), "error").Inc()
		}
		writeError(w, http.StatusInternalServerError, "mint_failed", "failed to mint DB credential")
		return
	}

	if app.metrics != nil {
		app.metrics.mintTotal.WithLabelValues(app.deps.Adapter.Name(), "success").Inc()
		app.metrics.mintDuration.WithLabelValues(app.deps.Adapter.Name()).Observe(time.Since(start).Seconds())
	}

	writeJSON(w, http.StatusOK, cred)
}

func (app *App) mapToDBUsername(claims *TokenClaims) string {
	if claims.PolicyUserID != "" {
		return claims.PolicyUserID
	}
	if app.deps.Mapping == nil {
		return ""
	}
	for _, resource := range claims.DBResources {
		if username, ok := app.deps.Mapping.ResourceToUsername[resource]; ok {
			return username
		}
	}
	return ""
}

func extractDatabaseFromURI(uri string) string {
	// Extract the database name from a db URI such as db://host/database.
	parts := strings.SplitN(uri, "/", 4)
	if len(parts) >= 4 {
		return parts[3]
	}
	return ""
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
	r.Body = http.MaxBytesReader(w, r.Body, defaultMaxBodySize)
	return json.NewDecoder(r.Body).Decode(v)
}

// --- Cloud Adapter Implementations ---

// AWSRDSAdapter mints IAM authentication tokens for AWS RDS.
type AWSRDSAdapter struct {
	Region   string
	Endpoint string
	Port     int
}

// NewAWSRDSAdapter creates an AWS RDS IAM adapter.
func NewAWSRDSAdapter(region, endpoint string, port int) *AWSRDSAdapter {
	if port == 0 {
		port = 5432
	}
	return &AWSRDSAdapter{Region: region, Endpoint: endpoint, Port: port}
}

// Name implements CloudDBAdapter.
func (a *AWSRDSAdapter) Name() string { return "aws-rds" }

// IsStub implements StubAdapter — these adapters generate placeholder tokens.
func (a *AWSRDSAdapter) IsStub() bool { return true }

// MintCredential implements CloudDBAdapter.
func (a *AWSRDSAdapter) MintCredential(_ context.Context, req *MintDBCredentialRequest) (*DBCredential, error) {
	// In production, this would use AWS STS AssumeRole + RDS IAM auth token generation.
	// For now, we generate the token structure that would be returned.
	token := fmt.Sprintf("rds-iam-token:%s:%s:%s:%d",
		a.Region, req.DBUsername, req.Database, time.Now().Add(req.TTL).Unix())

	return &DBCredential{
		Username:  req.DBUsername,
		Token:     token,
		Host:      a.Endpoint,
		Port:      a.Port,
		Database:  req.Database,
		ExpiresAt: time.Now().Add(req.TTL),
		Adapter:   a.Name(),
	}, nil
}

// AzureSQLAdapter mints tokens for Azure SQL Database.
type AzureSQLAdapter struct {
	ServerName string
	Port       int
}

// NewAzureSQLAdapter creates an Azure SQL token adapter.
func NewAzureSQLAdapter(serverName string, port int) *AzureSQLAdapter {
	if port == 0 {
		port = 1433
	}
	return &AzureSQLAdapter{ServerName: serverName, Port: port}
}

// Name implements CloudDBAdapter.
func (a *AzureSQLAdapter) Name() string { return "azure-sql" }

// IsStub implements StubAdapter — these adapters generate placeholder tokens.
func (a *AzureSQLAdapter) IsStub() bool { return true }

// MintCredential implements CloudDBAdapter.
func (a *AzureSQLAdapter) MintCredential(_ context.Context, req *MintDBCredentialRequest) (*DBCredential, error) {
	// In production, this would use Azure managed identity to acquire an access token
	// for the Azure SQL resource (https://database.windows.net/).
	token := fmt.Sprintf("azure-sql-token:%s:%s:%d",
		req.DBUsername, req.Database, time.Now().Add(req.TTL).Unix())

	return &DBCredential{
		Username:  req.DBUsername,
		Token:     token,
		Host:      a.ServerName,
		Port:      a.Port,
		Database:  req.Database,
		ExpiresAt: time.Now().Add(req.TTL),
		Adapter:   a.Name(),
	}, nil
}

// GCPCloudSQLAdapter mints tokens for GCP Cloud SQL.
type GCPCloudSQLAdapter struct {
	InstanceConnection string
	Port               int
}

// NewGCPCloudSQLAdapter creates a GCP Cloud SQL IAM adapter.
func NewGCPCloudSQLAdapter(instanceConnection string, port int) *GCPCloudSQLAdapter {
	if port == 0 {
		port = 5432
	}
	return &GCPCloudSQLAdapter{InstanceConnection: instanceConnection, Port: port}
}

// Name implements CloudDBAdapter.
func (a *GCPCloudSQLAdapter) Name() string { return "gcp-cloudsql" }

// IsStub implements StubAdapter — these adapters generate placeholder tokens.
func (a *GCPCloudSQLAdapter) IsStub() bool { return true }

// MintCredential implements CloudDBAdapter.
func (a *GCPCloudSQLAdapter) MintCredential(_ context.Context, req *MintDBCredentialRequest) (*DBCredential, error) {
	// In production, this would use GCP OAuth2 to mint an IAM access token
	// for Cloud SQL IAM authentication.
	token := fmt.Sprintf("gcp-cloudsql-token:%s:%s:%d",
		req.DBUsername, req.Database, time.Now().Add(req.TTL).Unix())

	return &DBCredential{
		Username:  req.DBUsername,
		Token:     token,
		Host:      a.InstanceConnection,
		Port:      a.Port,
		Database:  req.Database,
		ExpiresAt: time.Now().Add(req.TTL),
		Adapter:   a.Name(),
	}, nil
}
