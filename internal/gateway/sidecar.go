// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package gateway

import (
	"net/http"
)

// sidecarAgentMiddleware is an HTTP middleware that, in sidecar mode, rejects
// enforcement requests for agents other than the configured SidecarAgentID.
//
// In sidecar mode, the gateway is co-located with a single agent pod. Requests
// from any other agent identity are rejected with 403 to prevent misrouting
// (e.g., if another pod accidentally routes to this sidecar's localhost port).
//
// The agentID is extracted from the "X-Agent-Id" header on the request. This
// header must be set by the agent container before calling the gateway. If the
// header is absent, the middleware allows the request through — enforcement will
// fail at the token verification stage if the token does not belong to this agent.
func (app *App) sidecarAgentMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agentID := r.Header.Get("X-Agent-Id")
		if agentID != "" && agentID != app.config.SidecarAgentID {
			http.Error(w, `{"error":"wrong sidecar: request is for a different agent"}`, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
