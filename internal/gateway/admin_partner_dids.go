// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package gateway

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"

	"github.com/go-chi/chi/v5"
)

// Partner DID list pagination defaults and limits (consistent with audit routes).
const (
	partnerDIDDefaultPageSize = 50
	partnerDIDMaxPageSize     = 1000
)

// --- Partner DID Handlers ---

func (app *App) handlePartnerDIDRegister(w http.ResponseWriter, r *http.Request) {
	if app.adminDeps.PartnerDIDs == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse("partner DID store not configured"))
		return
	}

	var body struct {
		DID         string `json:"did"`
		Name        string `json:"name"`
		Description string `json:"description,omitempty"`
	}

	if err := json.NewDecoder(io.LimitReader(r.Body, app.maxBodySizeFor())).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse("invalid request body"))
		return
	}

	if body.DID == "" || body.Name == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse("did and name are required"))
		return
	}

	if err := app.adminDeps.PartnerDIDs.Register(r.Context(), body.DID, body.Name, body.Description); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse("failed to register partner DID"))
		return
	}

	identity := adminIdentityFromContext(r.Context())
	app.emitAdminAuditEvent(r.Context(), identity, "partner-did.register", body.DID)

	writeJSON(w, http.StatusCreated, map[string]any{
		"status": "registered",
		"did":    body.DID,
		"name":   body.Name,
	})
}

// handlePartnerDIDList handles GET /admin/partner-dids.
//
// Supports cursor-free, offset-based pagination via query parameters:
//   - page_size (default 50, max 1000)
//   - page      (1-indexed, default 1)
//
// The response always includes total_count, page, page_size, has_more, and
// count (number of items on this page) for easy client pagination.
func (app *App) handlePartnerDIDList(w http.ResponseWriter, r *http.Request) {
	if app.adminDeps.PartnerDIDs == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse("partner DID store not configured"))
		return
	}

	partners, err := app.adminDeps.PartnerDIDs.List(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse("failed to list partner DIDs"))
		return
	}

	// Parse pagination parameters.
	pageSize := partnerDIDDefaultPageSize
	if ps := r.URL.Query().Get("page_size"); ps != "" {
		if v, err := strconv.Atoi(ps); err == nil && v > 0 {
			if v > partnerDIDMaxPageSize {
				v = partnerDIDMaxPageSize
			}
			pageSize = v
		}
	}
	pageNum := 1
	if p := r.URL.Query().Get("page"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 1 {
			pageNum = v
		}
	}

	// Stable sort: by RegisteredAt ASC, then DID ASC as tiebreaker.
	sort.Slice(partners, func(i, j int) bool {
		if partners[i].RegisteredAt.Equal(partners[j].RegisteredAt) {
			return partners[i].DID < partners[j].DID
		}
		return partners[i].RegisteredAt.Before(partners[j].RegisteredAt)
	})

	totalCount := len(partners)
	offset := (pageNum - 1) * pageSize
	if offset > totalCount {
		offset = totalCount
	}
	end := offset + pageSize
	if end > totalCount {
		end = totalCount
	}
	page := partners[offset:end]

	writeJSON(w, http.StatusOK, map[string]any{
		"partners":    page,
		"count":       len(page),
		"total_count": totalCount,
		"page":        pageNum,
		"page_size":   pageSize,
		"has_more":    end < totalCount,
	})
}

func (app *App) handlePartnerDIDUnregister(w http.ResponseWriter, r *http.Request) {
	if app.adminDeps.PartnerDIDs == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse("partner DID store not configured"))
		return
	}

	did := chi.URLParam(r, "did")
	if did == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse("did is required"))
		return
	}

	if _, found, err := app.adminDeps.PartnerDIDs.Get(r.Context(), did); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse("failed to get partner DID"))
		return
	} else if !found {
		writeJSON(w, http.StatusNotFound, errorResponse("partner DID not found"))
		return
	}

	if err := app.adminDeps.PartnerDIDs.Unregister(r.Context(), did); err != nil {
		if errors.Is(err, ErrPartnerDIDNotFound) {
			writeJSON(w, http.StatusNotFound, errorResponse("partner DID not found"))
			return
		}
		writeJSON(w, http.StatusInternalServerError, errorResponse("failed to unregister partner DID"))
		return
	}

	identity := adminIdentityFromContext(r.Context())
	app.emitAdminAuditEvent(r.Context(), identity, "partner-did.unregister", did)

	writeJSON(w, http.StatusOK, map[string]any{
		"status": "unregistered",
		"did":    did,
	})
}

func (app *App) handlePartnerDIDApprove(w http.ResponseWriter, r *http.Request) {
	app.handlePartnerDIDStatusChange(w, r, "approved")
}

func (app *App) handlePartnerDIDRevoke(w http.ResponseWriter, r *http.Request) {
	app.handlePartnerDIDStatusChange(w, r, "revoked")
}

func (app *App) handlePartnerDIDRefresh(w http.ResponseWriter, r *http.Request) {
	app.handlePartnerDIDStatusChange(w, r, "refreshed")
}

func (app *App) handlePartnerDIDStatusChange(w http.ResponseWriter, r *http.Request, status string) {
	if app.adminDeps.PartnerDIDs == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse("partner DID store not configured"))
		return
	}

	did := chi.URLParam(r, "did")
	if did == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse("did is required"))
		return
	}

	if _, found, err := app.adminDeps.PartnerDIDs.Get(r.Context(), did); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse("failed to get partner DID"))
		return
	} else if !found {
		writeJSON(w, http.StatusNotFound, errorResponse("partner DID not found"))
		return
	}

	if err := app.adminDeps.PartnerDIDs.SetStatus(r.Context(), did, status); err != nil {
		if errors.Is(err, ErrPartnerDIDNotFound) {
			writeJSON(w, http.StatusNotFound, errorResponse("partner DID not found"))
			return
		}
		writeJSON(w, http.StatusInternalServerError, errorResponse("failed to update partner DID status"))
		return
	}

	identity := adminIdentityFromContext(r.Context())
	app.emitAdminAuditEvent(r.Context(), identity, "partner-did."+status, did)

	writeJSON(w, http.StatusOK, map[string]any{
		"status": status,
		"did":    did,
	})
}
