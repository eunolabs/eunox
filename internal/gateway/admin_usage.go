// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

// --- Token Revocation Handlers ---

func (app *App) handleAdminRevoke(w http.ResponseWriter, r *http.Request) {
	jti := chi.URLParam(r, "jti")
	if jti == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse("jti is required"))
		return
	}

	if app.deps.Revocation == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse("revocation store not configured"))
		return
	}

	// Parse optional TTL from body.
	var body struct {
		TTLSeconds int `json:"ttlSeconds,omitempty"`
	}
	if r.Body != nil {
		raw, err := io.ReadAll(io.LimitReader(r.Body, app.maxBodySizeFor()+1))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse("invalid request body"))
			return
		}
		if int64(len(raw)) > app.maxBodySizeFor() {
			writeJSON(w, http.StatusBadRequest, errorResponse("request body too large"))
			return
		}

		trimmed := bytes.TrimSpace(raw)
		if len(trimmed) > 0 {
			if err := json.Unmarshal(trimmed, &body); err != nil {
				writeJSON(w, http.StatusBadRequest, errorResponse("invalid request body"))
				return
			}
		}
	}

	ttl := 24 * time.Hour
	if body.TTLSeconds > 0 {
		ttl = time.Duration(body.TTLSeconds) * time.Second
	}

	if err := app.deps.Revocation.Revoke(r.Context(), jti, ttl); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse("failed to revoke token"))
		return
	}

	identity := adminIdentityFromContext(r.Context())
	app.emitAdminAuditEvent(r.Context(), identity, "token.revoke", jti)

	writeJSON(w, http.StatusOK, map[string]any{
		"status": "revoked",
		"jti":    jti,
		"ttl":    ttl.String(),
	})
}

func (app *App) handleAdminRevocationStatus(w http.ResponseWriter, r *http.Request) {
	if app.deps.Revocation == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse("revocation store not configured"))
		return
	}

	// Check if a specific JTI is revoked.
	jti := r.URL.Query().Get("jti")
	if jti != "" {
		revoked, err := app.deps.Revocation.IsRevoked(r.Context(), jti)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, errorResponse("failed to check revocation status"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"jti":     jti,
			"revoked": revoked,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status": "operational",
	})
}

// --- Usage Metering Handlers ---

func (app *App) handleAdminUsage(w http.ResponseWriter, r *http.Request) {
	if app.usageTracker == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse("usage tracking not configured"))
		return
	}

	identity := adminIdentityFromContext(r.Context())
	tenantFilter := r.URL.Query().Get("tenant_id")
	if tenantFilter == "" && identity != nil {
		tenantFilter = identity.TenantID
	}

	stats := app.usageTracker.GetStats(tenantFilter)
	writeJSON(w, http.StatusOK, stats)
}

func (app *App) handleAdminUsageReset(w http.ResponseWriter, r *http.Request) {
	if app.usageTracker == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse("usage tracking not configured"))
		return
	}

	if err := app.requireCrossTenantAck(r); err != nil {
		writeJSON(w, http.StatusForbidden, errorResponse(err.Error()))
		return
	}

	app.usageTracker.Reset()

	identity := adminIdentityFromContext(r.Context())
	app.emitAdminAuditEvent(r.Context(), identity, "usage.reset", "usage-meter")

	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "reset",
		"message": "usage counters cleared",
	})
}
