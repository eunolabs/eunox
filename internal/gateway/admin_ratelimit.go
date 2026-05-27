// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package gateway

import (
	"net"
	"net/http"
	"strconv"
	"time"
)

// adminRateLimitMiddleware enforces per-IP rate limiting on admin endpoints.
func (app *App) adminRateLimitMiddleware(next http.Handler) http.Handler {
	limit := app.config.AdminRateLimitPerMinute
	if limit <= 0 {
		limit = defaultAdminRateLimitPerMinute
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := adminRateLimitKey(r)

		result, err := app.adminRateLimiter.Check(r.Context(), key)
		if err != nil {
			http.Error(w, "internal rate limiter error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limit))
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(result.ResetAfter).Unix(), 10))

		if !result.Allowed {
			w.Header().Set("Retry-After", strconv.Itoa(int(result.RetryAfter.Seconds())+1))
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func adminRateLimitKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// publicRateLimitMiddleware enforces per-IP rate limiting on the public /api/v1
// route group.  The key is derived from extractClientIP so that trusted
// proxy CIDRs are respected and the real caller IP is used rather than the
// proxy's address.
func (app *App) publicRateLimitMiddleware(next http.Handler) http.Handler {
	limit := app.config.RateLimitRequests
	if limit <= 0 {
		limit = defaultPublicRateLimitPerMinute
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := app.extractClientIP(r)

		result, err := app.publicRateLimiter.Check(r.Context(), key)
		if err != nil {
			http.Error(w, "internal rate limiter error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limit))
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(result.ResetAfter).Unix(), 10))

		if !result.Allowed {
			w.Header().Set("Retry-After", strconv.Itoa(int(result.RetryAfter.Seconds())+1))
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}
