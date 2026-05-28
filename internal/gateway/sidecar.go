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
// header is required: requests without it are rejected with 403 to enforce strict
// single-agent isolation and prevent a valid token for a different agent from
// being accepted when the header is absent.
func (app *App) sidecarAgentMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agentID := r.Header.Get("X-Agent-Id")
		if agentID == "" || agentID != app.config.SidecarAgentID {
			writeJSON(w, http.StatusForbidden, errorResponse("wrong sidecar: request is for a different agent"))
			return
		}
		next.ServeHTTP(w, r)
	})
}
