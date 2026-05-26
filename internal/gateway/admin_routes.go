// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package gateway

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/edgeobs/eunox/pkg/audit"
	"github.com/edgeobs/eunox/pkg/ocsf"
)

// ErrPartnerDIDNotFound indicates a requested partner DID entry does not exist.
var ErrPartnerDIDNotFound = errors.New("partner DID not found")

// PartnerDIDStore manages trusted partner DIDs.
type PartnerDIDStore interface {
	// Register adds a trusted partner DID.
	Register(ctx context.Context, did, name, description string) error
	// Unregister removes a trusted partner DID.
	Unregister(ctx context.Context, did string) error
	// List returns all registered partner DIDs.
	List(ctx context.Context) ([]PartnerDID, error)
	// Get returns a single partner DID by DID string.
	Get(ctx context.Context, did string) (*PartnerDID, bool, error)
	// SetStatus updates the status of a partner DID.
	SetStatus(ctx context.Context, did, status string) error
}

// PartnerDID represents a registered partner DID entry.
type PartnerDID struct {
	DID          string    `json:"did"`
	Name         string    `json:"name"`
	Description  string    `json:"description,omitempty"`
	Status       string    `json:"status"`
	RegisteredAt time.Time `json:"registeredAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

// InMemoryPartnerDIDStore provides an in-memory implementation of PartnerDIDStore.
type InMemoryPartnerDIDStore struct {
	mu       sync.RWMutex
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
func (s *InMemoryPartnerDIDStore) Register(_ context.Context, did, name, description string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	s.partners[did] = &PartnerDID{
		DID:          did,
		Name:         name,
		Description:  description,
		Status:       "pending",
		RegisteredAt: now,
		UpdatedAt:    now,
	}
	return nil
}

// Unregister removes a partner DID from the store.
func (s *InMemoryPartnerDIDStore) Unregister(_ context.Context, did string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.partners[did]; !ok {
		return fmt.Errorf("%w: %s", ErrPartnerDIDNotFound, did)
	}

	delete(s.partners, did)
	return nil
}

// List returns all registered partner DIDs.
func (s *InMemoryPartnerDIDStore) List(_ context.Context) ([]PartnerDID, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]PartnerDID, 0, len(s.partners))
	for _, p := range s.partners {
		result = append(result, *p)
	}
	return result, nil
}

// Get retrieves a partner DID by its identifier.
func (s *InMemoryPartnerDIDStore) Get(_ context.Context, did string) (*PartnerDID, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	p, ok := s.partners[did]
	if !ok {
		return nil, false, nil
	}
	clone := *p
	return &clone, true, nil
}

// SetStatus updates the status of a partner DID.
func (s *InMemoryPartnerDIDStore) SetStatus(_ context.Context, did, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, ok := s.partners[did]
	if !ok {
		return fmt.Errorf("%w: %s", ErrPartnerDIDNotFound, did)
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

	// All admin routes require authentication and are rate-limited (CR-4).
	r.Group(func(r chi.Router) {
		r.Use(app.adminRateLimitMiddleware)
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
