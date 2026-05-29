// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package minter

import "context"

type contextKey string

const operatorIDKey contextKey = "operatorID"

func withOperatorID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, operatorIDKey, id)
}

func getOperatorID(ctx context.Context) string {
	if v, ok := ctx.Value(operatorIDKey).(string); ok {
		return v
	}
	return ""
}
