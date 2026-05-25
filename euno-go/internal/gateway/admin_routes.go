// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/edgeobs/euno-platform/euno-go/pkg/audit"
	"github.com/edgeobs/euno-platform/euno-go/pkg/ocsf"
)

// PartnerDIDStore manages trusted partner DIDs.
type PartnerDIDStore interface {
	// Register adds a trusted partner DID.
	Register(did, name, description string) error
	// Unregister removes a trusted partner DID.
	Unregister(did string) error
	// List returns all registered partner DIDs.
	List() []PartnerDID
	// Get returns a single partner DID by DID string.
	Get(did string) (*PartnerDID, bool)
	// SetStatus updates the status of a partner DID.
	SetStatus(did, status string) error
}

// PartnerDID represents a registered partner DID entry.
type PartnerDID struct {
	DID         string    `json:"did"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Status      string    `json:"status"`
	RegisteredAt time.Time `json:"registeredAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// InMemoryPartnerDIDStore provides an in-memory implementation of PartnerDIDStore.
type InMemoryPartnerDIDStore struct {
	partners map[string]*PartnerDID
	now      func() time.Time
}

// NewInMemoryPartnerDIDStore creates a new in-memory partner DID store.
func NewInMemoryPartnerDIDStore() *InMemoryPartnerDIDStore {
	return &InMemoryPartnerDIDStore{
		partners: make(map[string]*PartnerDID),
		now:      time.Now,
	}
}

// Register adds a new partner DID to the store.
func (s *InMemoryPartnerDIDStore) Register(did, name, description string) error {
	now := s.now()
	s.partners[did] = &PartnerDID{
		DID:          did,
		Name:         name,
		Description:  description,
		Status:       "approved",
		RegisteredAt: now,
		UpdatedAt:    now,
	}
	return nil
}

// Unregister removes a partner DID from the store.
func (s *InMemoryPartnerDIDStore) Unregister(did string) error {
	delete(s.partners, did)
	return nil
}

// List returns all registered partner DIDs.
func (s *InMemoryPartnerDIDStore) List() []PartnerDID {
	result := make([]PartnerDID, 0, len(s.partners))
	for _, p := range s.partners {
		result = append(result, *p)
	}
	return result
}

// Get retrieves a partner DID by its identifier.
func (s *InMemoryPartnerDIDStore) Get(did string) (*PartnerDID, bool) {
	p, ok := s.partners[did]
	if !ok {
		return nil, false
	}
	return p, true
}

// SetStatus updates the status of a partner DID.
func (s *InMemoryPartnerDIDStore) SetStatus(did, status string) error {
	p, ok := s.partners[did]
	if !ok {
		return fmt.Errorf("partner DID not found: %s", did)
	}
	p.Status = status
	p.UpdatedAt = s.now()
	return nil
}

// AdminDependencies holds dependencies for the admin API.
type AdminDependencies struct {
	PartnerDIDs PartnerDIDStore
}

// buildAdminRouter creates the admin-only router (bound to localhost:3003).
func (app *App) buildAdminRouter() chi.Router {
	r := chi.NewRouter()

	// Health endpoints (no auth required on admin port).
	r.Get("/health/live", app.handleLive)
	r.Get("/health/ready", app.handleReady)

	// All admin routes require authentication.
	r.Group(func(r chi.Router) {
		r.Use(app.adminMiddleware)
		r.Use(app.idempotencyMiddleware)

		// Kill-switch management.
		r.Route("/admin/kill-switch", func(r chi.Router) {
			r.Post("/global/activate", app.handleKillSwitchGlobalActivate)
			r.Post("/global/deactivate", app.handleKillSwitchGlobalDeactivate)
			r.Post("/agent/{agentId}/kill", app.handleKillSwitchAgentKill)
			r.Post("/agent/{agentId}/revive", app.handleKillSwitchAgentRevive)
			r.Post("/session/{sessionId}/kill", app.handleKillSwitchSessionKill)
			r.Post("/session/{sessionId}/revive", app.handleKillSwitchSessionRevive)
			r.Post("/reset", app.handleKillSwitchReset)
			r.Get("/status", app.handleKillSwitchStatus)
		})

		// Token revocation.
		r.Post("/admin/revoke/{jti}", app.handleAdminRevoke)
		r.Get("/admin/revocation/status", app.handleAdminRevocationStatus)

		// Usage metering.
		r.Get("/admin/usage", app.handleAdminUsage)
		r.Post("/admin/usage/reset", app.handleAdminUsageReset)

		// Partner DID management.
		r.Route("/admin/partner-dids", func(r chi.Router) {
			r.Post("/", app.handlePartnerDIDRegister)
			r.Get("/", app.handlePartnerDIDList)
			r.Delete("/{did}", app.handlePartnerDIDUnregister)
			r.Post("/{did}/approve", app.handlePartnerDIDApprove)
			r.Post("/{did}/revoke", app.handlePartnerDIDRevoke)
			r.Post("/{did}/refresh", app.handlePartnerDIDRefresh)
		})
	})

	return r
}

// --- Kill-Switch Handlers ---

func (app *App) handleKillSwitchGlobalActivate(w http.ResponseWriter, r *http.Request) {
	if err := requireCrossTenantAck(r); err != nil {
		writeJSON(w, http.StatusForbidden, errorResponse(err.Error()))
		return
	}

	if app.deps.KillSwitch == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse("kill switch not configured"))
		return
	}

	if err := app.deps.KillSwitch.ActivateGlobal(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse("failed to activate global kill switch"))
		return
	}

	identity := adminIdentityFromContext(r.Context())
	app.emitAdminAuditEvent(r.Context(), identity, "kill-switch.global.activate", "kill-switch")

	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "activated",
		"message": "global kill switch activated",
	})
}

func (app *App) handleKillSwitchGlobalDeactivate(w http.ResponseWriter, r *http.Request) {
	if err := requireCrossTenantAck(r); err != nil {
		writeJSON(w, http.StatusForbidden, errorResponse(err.Error()))
		return
	}

	if app.deps.KillSwitch == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse("kill switch not configured"))
		return
	}

	if err := app.deps.KillSwitch.DeactivateGlobal(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse("failed to deactivate global kill switch"))
		return
	}

	identity := adminIdentityFromContext(r.Context())
	app.emitAdminAuditEvent(r.Context(), identity, "kill-switch.global.deactivate", "kill-switch")

	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "deactivated",
		"message": "global kill switch deactivated",
	})
}

func (app *App) handleKillSwitchAgentKill(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	if agentID == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse("agentId is required"))
		return
	}

	if app.deps.KillSwitch == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse("kill switch not configured"))
		return
	}

	if err := app.deps.KillSwitch.KillAgent(r.Context(), agentID); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse("failed to kill agent"))
		return
	}

	identity := adminIdentityFromContext(r.Context())
	app.emitAdminAuditEvent(r.Context(), identity, "kill-switch.agent.kill", agentID)

	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "killed",
		"agentId": agentID,
	})
}

func (app *App) handleKillSwitchAgentRevive(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	if agentID == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse("agentId is required"))
		return
	}

	if app.deps.KillSwitch == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse("kill switch not configured"))
		return
	}

	if err := app.deps.KillSwitch.ReviveAgent(r.Context(), agentID); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse("failed to revive agent"))
		return
	}

	identity := adminIdentityFromContext(r.Context())
	app.emitAdminAuditEvent(r.Context(), identity, "kill-switch.agent.revive", agentID)

	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "revived",
		"agentId": agentID,
	})
}

func (app *App) handleKillSwitchSessionKill(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "sessionId")
	if sessionID == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse("sessionId is required"))
		return
	}

	if app.deps.KillSwitch == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse("kill switch not configured"))
		return
	}

	if err := app.deps.KillSwitch.KillSession(r.Context(), sessionID); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse("failed to kill session"))
		return
	}

	identity := adminIdentityFromContext(r.Context())
	app.emitAdminAuditEvent(r.Context(), identity, "kill-switch.session.kill", sessionID)

	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "killed",
		"sessionId": sessionID,
	})
}

func (app *App) handleKillSwitchSessionRevive(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "sessionId")
	if sessionID == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse("sessionId is required"))
		return
	}

	if app.deps.KillSwitch == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse("kill switch not configured"))
		return
	}

	if err := app.deps.KillSwitch.ReviveSession(r.Context(), sessionID); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse("failed to revive session"))
		return
	}

	identity := adminIdentityFromContext(r.Context())
	app.emitAdminAuditEvent(r.Context(), identity, "kill-switch.session.revive", sessionID)

	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "revived",
		"sessionId": sessionID,
	})
}

func (app *App) handleKillSwitchReset(w http.ResponseWriter, r *http.Request) {
	if err := requireCrossTenantAck(r); err != nil {
		writeJSON(w, http.StatusForbidden, errorResponse(err.Error()))
		return
	}

	if app.deps.KillSwitch == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse("kill switch not configured"))
		return
	}

	if err := app.deps.KillSwitch.Reset(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse("failed to reset kill switch"))
		return
	}

	identity := adminIdentityFromContext(r.Context())
	app.emitAdminAuditEvent(r.Context(), identity, "kill-switch.reset", "kill-switch")

	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "reset",
		"message": "all kill-switch state cleared",
	})
}

func (app *App) handleKillSwitchStatus(w http.ResponseWriter, r *http.Request) {
	if app.deps.KillSwitch == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse("kill switch not configured"))
		return
	}

	status, err := app.deps.KillSwitch.Status(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse("failed to get kill switch status"))
		return
	}

	writeJSON(w, http.StatusOK, status)
}

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
		_ = json.NewDecoder(r.Body).Decode(&body)
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

	if err := requireCrossTenantAck(r); err != nil {
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

	if err := json.NewDecoder(io.LimitReader(r.Body, maxBodySize)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse("invalid request body"))
		return
	}

	if body.DID == "" || body.Name == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse("did and name are required"))
		return
	}

	if err := app.adminDeps.PartnerDIDs.Register(body.DID, body.Name, body.Description); err != nil {
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

func (app *App) handlePartnerDIDList(w http.ResponseWriter, _ *http.Request) {
	if app.adminDeps.PartnerDIDs == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse("partner DID store not configured"))
		return
	}

	partners := app.adminDeps.PartnerDIDs.List()
	writeJSON(w, http.StatusOK, map[string]any{
		"partners": partners,
		"count":    len(partners),
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

	if _, found := app.adminDeps.PartnerDIDs.Get(did); !found {
		writeJSON(w, http.StatusNotFound, errorResponse("partner DID not found"))
		return
	}

	if err := app.adminDeps.PartnerDIDs.Unregister(did); err != nil {
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

	if _, found := app.adminDeps.PartnerDIDs.Get(did); !found {
		writeJSON(w, http.StatusNotFound, errorResponse("partner DID not found"))
		return
	}

	if err := app.adminDeps.PartnerDIDs.SetStatus(did, status); err != nil {
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

// --- OCSF Audit Emission ---

// emitAdminAuditEvent emits an OCSF Authorization event for a successful admin action.
func (app *App) emitAdminAuditEvent(ctx context.Context, identity *AdminIdentity, action, resource string) {
	if app.deps.Audit == nil || app.deps.Audit.Pipeline == nil {
		return
	}

	var actor ocsf.Actor
	if identity != nil {
		actor = ocsf.Actor{
			UserID:   identity.OperatorID,
			TenantID: identity.TenantID,
		}
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
			Message:       "admin action: " + action,
			SOC2Controls:  []ocsf.SOC2Control{ocsf.SOC2CC63},
		},
		Actor: actor,
		Resource: ocsf.Resource{
			UID:  resource,
			Type: "admin-operation",
		},
		Decision: "success",
	}

	if identity != nil {
		event.OperatorID = identity.OperatorID
	}

	entry := &audit.LogEntry{
		Timestamp: time.Now().UTC(),
		TenantID:  actor.TenantID,
		EventType: "admin." + action,
		Actor:     actor,
		Action:    action,
		Resource: ocsf.Resource{
			UID:  resource,
			Type: "admin-operation",
		},
		Outcome:   "success",
		OCSFEvent: event,
	}

	// Best-effort: don't block the admin response on audit pipeline.
	_ = app.deps.Audit.Pipeline.Append(ctx, entry)
}
