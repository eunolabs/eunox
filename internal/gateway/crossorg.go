// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/eunolabs/eunox/pkg/audit"
	"github.com/eunolabs/eunox/pkg/did"
	"github.com/eunolabs/eunox/pkg/ocsf"
)

// CrossOrgAnnotation holds metadata for cross-organization audit entries.
type CrossOrgAnnotation struct {
	CrossOrg   bool   `json:"crossOrg"`
	PartnerDID string `json:"partnerDID,omitempty"`
}

// EmitCrossOrgAuditEvent emits an OCSF audit event annotated with cross-org metadata.
// Called during enforcement when a partner-issued token is used.
func (app *App) EmitCrossOrgAuditEvent(ctx context.Context, partnerDID, subject, action, resource, decision string) {
	if app.deps.Audit == nil || app.deps.Audit.Pipeline == nil {
		return
	}

	actor := ocsf.Actor{
		UserID: subject,
	}

	event := &ocsf.AuthorizationEvent{
		BaseEvent: ocsf.BaseEvent{
			ClassUID:      ocsf.ClassAuthorization,
			ActivityID:    ocsf.ActivityAuthOther,
			CategoryUID:   3,
			TypeUID:       300399,
			SchemaVersion: ocsf.SchemaVersion,
			Time:          time.Now().UTC(),
			SeverityID:    ocsf.SeverityInformational,
			StatusID:      ocsf.StatusSuccess,
			Message:       "cross-org enforcement: " + action,
			SOC2Controls:  []ocsf.SOC2Control{ocsf.SOC2CC63},
		},
		Actor: actor,
		Resource: ocsf.Resource{
			UID:  resource,
			Type: "cross-org-operation",
		},
		Decision:   decision,
		OperatorID: partnerDID,
	}

	detail, _ := json.Marshal(CrossOrgAnnotation{
		CrossOrg:   true,
		PartnerDID: partnerDID,
	})

	entry := &audit.LogEntry{
		Timestamp: time.Now().UTC(),
		EventType: "cross-org.enforce",
		Actor:     actor,
		Action:    action,
		Resource: ocsf.Resource{
			UID:  resource,
			Type: "cross-org-operation",
		},
		Outcome:   decision,
		OCSFEvent: event,
		Detail:    detail,
	}

	_ = app.deps.Audit.Pipeline.Append(ctx, entry)
}

// IONHealthChecker checks the health of the ION resolver.
type IONHealthChecker struct {
	resolver *did.IONResolver
}

// NewIONHealthChecker creates a health checker for the DID ION resolver.
func NewIONHealthChecker(resolver *did.IONResolver) *IONHealthChecker {
	return &IONHealthChecker{resolver: resolver}
}

// handleDIDIONHealth handles GET /healthz/did-ion.
func (app *App) handleDIDIONHealth(w http.ResponseWriter, r *http.Request) {
	if app.ionHealthChecker == nil || app.ionHealthChecker.resolver == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":  "unconfigured",
			"message": "DID ION resolver not configured",
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	err := app.ionHealthChecker.resolver.Healthy(ctx)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"status": "unhealthy",
			"error":  err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status": "healthy",
	})
}
