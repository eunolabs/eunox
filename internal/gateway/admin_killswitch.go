// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package gateway

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

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
