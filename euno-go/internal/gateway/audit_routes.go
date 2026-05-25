// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

package gateway

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/edgeobs/euno-platform/euno-go/pkg/audit"
)

// AuditDependencies holds optional audit pipeline dependencies for the gateway.
type AuditDependencies struct {
	QueryStore  audit.QueryStore
	Pipeline    audit.Pipeline
	SigningKeys []SigningKeyInfo
}

// SigningKeyInfo describes a public key used for audit evidence signing.
type SigningKeyInfo struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
	CreatedAt string `json:"created_at,omitempty"`
}

// handleAuditRecords handles GET /api/v1/audit/records.
// Returns paginated audit records filtered by tenant, event type, or actor.
func (app *App) handleAuditRecords(w http.ResponseWriter, r *http.Request) {
	if app.deps.Audit == nil || app.deps.Audit.QueryStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse("audit query store not configured"))
		return
	}

	filter := audit.QueryFilter{
		TenantID:  r.URL.Query().Get("tenant_id"),
		EventType: r.URL.Query().Get("event_type"),
		ActorID:   r.URL.Query().Get("actor_id"),
	}

	if since := r.URL.Query().Get("since"); since != "" {
		if t, err := time.Parse(time.RFC3339, since); err == nil {
			filter.StartTime = &t
		}
	}
	if until := r.URL.Query().Get("until"); until != "" {
		if t, err := time.Parse(time.RFC3339, until); err == nil {
			filter.EndTime = &t
		}
	}

	page := parsePageParams(r)

	result, err := app.deps.Audit.QueryStore.Query(r.Context(), filter, page)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse("failed to query audit records"))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"records":     result.Records,
		"total_count": result.TotalCount,
		"has_more":    result.HasMore,
	})
}

// handleAuditExport handles GET /api/v1/audit/export.
// Exports audit records in OCSF v1.1 format for SIEM ingestion.
func (app *App) handleAuditExport(w http.ResponseWriter, r *http.Request) {
	if app.deps.Audit == nil || app.deps.Audit.QueryStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse("audit query store not configured"))
		return
	}

	filter := audit.QueryFilter{
		TenantID:  r.URL.Query().Get("tenant_id"),
		EventType: r.URL.Query().Get("event_type"),
	}

	page := parsePageParams(r)

	result, err := app.deps.Audit.QueryStore.Query(r.Context(), filter, page)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse("failed to export audit records"))
		return
	}

	// Extract OCSF events from the audit records.
	events := make([]any, 0, len(result.Records))
	for _, rec := range result.Records {
		if rec.Record.OCSFEvent != nil {
			events = append(events, rec.Record.OCSFEvent)
		} else {
			// Wrap the record in a minimal OCSF envelope if no event is stored.
			events = append(events, map[string]any{
				"class_uid":    6003,
				"category_uid": 6,
				"activity_id":  1,
				"time":         rec.Record.Timestamp.Unix(),
				"message":      rec.Record.Action + ":" + rec.Record.Outcome,
				"metadata": map[string]string{
					"record_id":  rec.Record.ID,
					"tenant_id":  rec.Record.TenantID,
					"event_type": rec.Record.EventType,
				},
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-OCSF-Version", "1.1.0")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"schema_version": "1.1.0",
		"events":         events,
		"total_count":    result.TotalCount,
	})
}

// handleAuditSigningKeys handles GET /api/v1/audit/signing-keys.
// Returns the public signing keys used to sign audit evidence (for offline verification).
func (app *App) handleAuditSigningKeys(w http.ResponseWriter, _ *http.Request) {
	if app.deps.Audit == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse("audit pipeline not configured"))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"keys": app.deps.Audit.SigningKeys,
	})
}

// handleAuditChainProof handles GET /api/v1/audit/chain-proof.
// Returns chain proof data for verifying the integrity of a range of audit records.
func (app *App) handleAuditChainProof(w http.ResponseWriter, r *http.Request) {
	if app.deps.Audit == nil || app.deps.Audit.QueryStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse("audit query store not configured"))
		return
	}

	replicaID := r.URL.Query().Get("replica_id")
	if replicaID == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse("replica_id is required"))
		return
	}

	fromSeq, err := strconv.ParseInt(r.URL.Query().Get("from_seq"), 10, 64)
	if err != nil || fromSeq < 1 {
		writeJSON(w, http.StatusBadRequest, errorResponse("from_seq must be a positive integer"))
		return
	}

	toSeq, err := strconv.ParseInt(r.URL.Query().Get("to_seq"), 10, 64)
	if err != nil || toSeq < fromSeq {
		writeJSON(w, http.StatusBadRequest, errorResponse("to_seq must be >= from_seq"))
		return
	}

	segment, err := app.deps.Audit.QueryStore.GetChainSegment(r.Context(), replicaID, fromSeq, toSeq)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse("failed to retrieve chain segment"))
		return
	}

	// Verify chain integrity for the segment.
	valid := true
	var brokenAt int64
	for i := range segment {
		if !audit.VerifyChainHash(&segment[i]) {
			valid = false
			brokenAt = segment[i].SequenceNum
			break
		}
	}

	proof := map[string]any{
		"replica_id": replicaID,
		"from_seq":   fromSeq,
		"to_seq":     toSeq,
		"count":      len(segment),
		"valid":      valid,
	}

	if !valid {
		proof["broken_at_seq"] = brokenAt
	}

	if len(segment) > 0 {
		proof["first_hash"] = segment[0].ChainHash
		proof["last_hash"] = segment[len(segment)-1].ChainHash
		proof["first_previous_hash"] = segment[0].PreviousHash
	}

	writeJSON(w, http.StatusOK, proof)
}

// parsePageParams extracts pagination parameters from the request query string.
func parsePageParams(r *http.Request) audit.PageParams {
	page := audit.PageParams{
		Offset: 0,
		Limit:  50,
	}

	if p := r.URL.Query().Get("page"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 1 {
			page.Offset = (v - 1) * page.Limit
		}
	}

	if ps := r.URL.Query().Get("page_size"); ps != "" {
		if v, err := strconv.Atoi(ps); err == nil && v > 0 && v <= 1000 {
			page.Limit = v
		}
	}

	if orderBy := r.URL.Query().Get("order_by"); orderBy != "" {
		_ = orderBy // Reserved for future use in query store.
	}

	if dir := r.URL.Query().Get("order_dir"); strings.EqualFold(dir, "asc") {
		_ = dir // Reserved for future use.
	}

	return page
}
