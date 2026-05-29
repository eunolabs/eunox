// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package posture

// sanitizeID replaces characters that are invalid in cloud resource identifiers.
func sanitizeID(id string) string {
	result := make([]byte, 0, len(id))
	for _, c := range []byte(id) {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			result = append(result, c)
		} else {
			result = append(result, '-')
		}
	}
	return string(result)
}
