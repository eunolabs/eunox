// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package issuer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Helper ---

func doDelete(app *App, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodDelete, path, http.NoBody)
	req.Header.Set(adminAPIKeyHeader(), app.config.AdminAPIKey)
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)
	return w
}

func doPatch(app *App, path string, body interface{}) *httptest.ResponseRecorder {
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPatch, path, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(adminAPIKeyHeader(), app.config.AdminAPIKey)
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)
	return w
}

func doPut(app *App, path string, body interface{}) *httptest.ResponseRecorder {
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, path, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(adminAPIKeyHeader(), app.config.AdminAPIKey)
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)
	return w
}

func createTestUser(t *testing.T, app *App, userName string) string {
	t.Helper()
	w := doPost(app, "/scim/v2/Users", SCIMUserRequest{
		Schemas:  []string{scimUserSchema},
		UserName: userName,
		Active:   true,
	})
	require.Equal(t, http.StatusCreated, w.Code)
	var resp SCIMUser
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	return resp.ID
}

func createTestGroup(t *testing.T, app *App, displayName string) string {
	t.Helper()
	w := doPost(app, "/scim/v2/Groups", SCIMGroupRequest{
		Schemas:     []string{scimGroupSchema},
		DisplayName: displayName,
	})
	require.Equal(t, http.StatusCreated, w.Code)
	var resp SCIMGroup
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	return resp.ID
}

// --- User CRUD Tests ---

func TestSCIM_GetUser(t *testing.T) {
	app := testApp(t)
	id := createTestUser(t, app, "alice")

	w := doGet(app, "/scim/v2/Users/"+id)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/scim+json")

	var user SCIMUser
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &user))
	assert.Equal(t, id, user.ID)
	assert.Equal(t, "alice", user.UserName)
	assert.True(t, user.Active)
}

func TestSCIM_GetUser_NotFound(t *testing.T) {
	app := testApp(t)
	w := doGet(app, "/scim/v2/Users/nonexistent-id")
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestSCIM_ListUsers(t *testing.T) {
	app := testApp(t)
	createTestUser(t, app, "alice")
	createTestUser(t, app, "bob")

	w := doGet(app, "/scim/v2/Users")
	assert.Equal(t, http.StatusOK, w.Code)

	var resp SCIMListResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 2, resp.TotalResults)
}

func TestSCIM_ListUsers_Filter(t *testing.T) {
	app := testApp(t)
	createTestUser(t, app, "alice")
	createTestUser(t, app, "bob")

	req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", http.NoBody)
	q := req.URL.Query()
	q.Set("filter", `userName eq "alice"`)
	req.URL.RawQuery = q.Encode()
	req.Header.Set(adminAPIKeyHeader(), app.config.AdminAPIKey)
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp SCIMListResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 1, resp.TotalResults)
}

func TestSCIM_ListUsers_FilterByExternalId(t *testing.T) {
	app := testApp(t)

	// Create user with externalId
	w := doPost(app, "/scim/v2/Users", SCIMUserRequest{
		Schemas:    []string{scimUserSchema},
		UserName:   "alice",
		ExternalID: "ext-123",
		Active:     true,
	})
	require.Equal(t, http.StatusCreated, w.Code)

	createTestUser(t, app, "bob")

	req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", http.NoBody)
	q := req.URL.Query()
	q.Set("filter", `externalId eq "ext-123"`)
	req.URL.RawQuery = q.Encode()
	req.Header.Set(adminAPIKeyHeader(), app.config.AdminAPIKey)
	w = httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp SCIMListResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 1, resp.TotalResults)

	// Re-unmarshal to get the actual users
	var fullResp struct {
		Schemas      []string   `json:"schemas"`
		TotalResults int        `json:"totalResults"`
		StartIndex   int        `json:"startIndex"`
		ItemsPerPage int        `json:"itemsPerPage"`
		Resources    []SCIMUser `json:"Resources"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &fullResp))
	assert.Equal(t, "alice", fullResp.Resources[0].UserName)
	assert.Equal(t, "ext-123", fullResp.Resources[0].ExternalID)
}

func TestSCIM_ListGroups_FilterByExternalId(t *testing.T) {
	app := testApp(t)

	// Create group with externalId
	w := doPost(app, "/scim/v2/Groups", SCIMGroupRequest{
		Schemas:     []string{scimGroupSchema},
		DisplayName: "Engineering",
		ExternalID:  "ext-grp-456",
	})
	require.Equal(t, http.StatusCreated, w.Code)

	createTestGroup(t, app, "Security")

	req := httptest.NewRequest(http.MethodGet, "/scim/v2/Groups", http.NoBody)
	q := req.URL.Query()
	q.Set("filter", `externalId eq "ext-grp-456"`)
	req.URL.RawQuery = q.Encode()
	req.Header.Set(adminAPIKeyHeader(), app.config.AdminAPIKey)
	w = httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp SCIMListResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 1, resp.TotalResults)

	// Re-unmarshal to get the actual groups
	var fullResp struct {
		Schemas      []string    `json:"schemas"`
		TotalResults int         `json:"totalResults"`
		StartIndex   int         `json:"startIndex"`
		ItemsPerPage int         `json:"itemsPerPage"`
		Resources    []SCIMGroup `json:"Resources"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &fullResp))
	assert.Equal(t, "Engineering", fullResp.Resources[0].DisplayName)
	assert.Equal(t, "ext-grp-456", fullResp.Resources[0].ExternalID)
}

func TestSCIM_UserGroupsSynchronization(t *testing.T) {
	app := testApp(t)

	// Create users
	userID1 := createTestUser(t, app, "alice")
	userID2 := createTestUser(t, app, "bob")

	// Create group with members
	w := doPost(app, "/scim/v2/Groups", SCIMGroupRequest{
		Schemas:     []string{scimGroupSchema},
		DisplayName: "Engineering",
		Members: []struct {
			Value   string `json:"value"`
			Display string `json:"display"`
		}{
			{Value: userID1, Display: "Alice"},
		},
	})
	require.Equal(t, http.StatusCreated, w.Code)
	var group SCIMGroup
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &group))

	// Verify alice has the group
	w = doGet(app, "/scim/v2/Users/"+userID1)
	assert.Equal(t, http.StatusOK, w.Code)
	var alice SCIMUser
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &alice))
	assert.Len(t, alice.Groups, 1)
	assert.Equal(t, group.ID, alice.Groups[0].Value)
	assert.Equal(t, "Engineering", alice.Groups[0].Display)

	// Verify bob doesn't have the group
	w = doGet(app, "/scim/v2/Users/"+userID2)
	assert.Equal(t, http.StatusOK, w.Code)
	var bob SCIMUser
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &bob))
	assert.Empty(t, bob.Groups)

	// Add bob to the group via PATCH
	patch := SCIMPatchOp{
		Schemas: []string{scimPatchSchema},
		Operations: []SCIMPatchOpEntry{
			{Op: "add", Path: "members", Value: []map[string]interface{}{
				{"value": userID2, "display": "Bob"},
			}},
		},
	}
	w = doPatch(app, "/scim/v2/Groups/"+group.ID, patch)
	assert.Equal(t, http.StatusOK, w.Code)

	// Verify bob now has the group
	w = doGet(app, "/scim/v2/Users/"+userID2)
	assert.Equal(t, http.StatusOK, w.Code)
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &bob))
	assert.Len(t, bob.Groups, 1)
	assert.Equal(t, group.ID, bob.Groups[0].Value)

	// Delete the group
	w = doDelete(app, "/scim/v2/Groups/"+group.ID)
	assert.Equal(t, http.StatusNoContent, w.Code)

	// Verify users no longer have the group
	w = doGet(app, "/scim/v2/Users/"+userID1)
	assert.Equal(t, http.StatusOK, w.Code)
	var aliceAfterDelete SCIMUser
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &aliceAfterDelete))
	assert.Empty(t, aliceAfterDelete.Groups, "alice should have no groups after group deletion")

	w = doGet(app, "/scim/v2/Users/"+userID2)
	assert.Equal(t, http.StatusOK, w.Code)
	var bobAfterDelete SCIMUser
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &bobAfterDelete))
	assert.Empty(t, bobAfterDelete.Groups, "bob should have no groups after group deletion")
}

func TestSCIM_PatchUser_ReplaceActive(t *testing.T) {
	app := testApp(t)
	id := createTestUser(t, app, "alice")

	patch := SCIMPatchOp{
		Schemas: []string{scimPatchSchema},
		Operations: []SCIMPatchOpEntry{
			{Op: "replace", Path: "active", Value: false},
		},
	}
	w := doPatch(app, "/scim/v2/Users/"+id, patch)
	assert.Equal(t, http.StatusOK, w.Code)

	var user SCIMUser
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &user))
	assert.False(t, user.Active)
}

func TestSCIM_PatchUser_ReplaceUserName(t *testing.T) {
	app := testApp(t)
	id := createTestUser(t, app, "alice")

	patch := SCIMPatchOp{
		Schemas: []string{scimPatchSchema},
		Operations: []SCIMPatchOpEntry{
			{Op: "replace", Path: "userName", Value: "alice-updated"},
		},
	}
	w := doPatch(app, "/scim/v2/Users/"+id, patch)
	assert.Equal(t, http.StatusOK, w.Code)

	var user SCIMUser
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &user))
	assert.Equal(t, "alice-updated", user.UserName)
}

func TestSCIM_PatchUser_AddEmails(t *testing.T) {
	app := testApp(t)
	id := createTestUser(t, app, "alice")

	patch := SCIMPatchOp{
		Schemas: []string{scimPatchSchema},
		Operations: []SCIMPatchOpEntry{
			{Op: "add", Path: "emails", Value: []map[string]interface{}{
				{"value": "alice@example.com", "primary": true},
			}},
		},
	}
	w := doPatch(app, "/scim/v2/Users/"+id, patch)
	assert.Equal(t, http.StatusOK, w.Code)

	var user SCIMUser
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &user))
	require.Len(t, user.Emails, 1)
	assert.Equal(t, "alice@example.com", user.Emails[0].Value)
}

func TestSCIM_PatchUser_RemoveEmails(t *testing.T) {
	app := testApp(t)
	w := doPost(app, "/scim/v2/Users", SCIMUserRequest{
		Schemas:  []string{scimUserSchema},
		UserName: "alice",
		Emails:   []struct{ Value string `json:"value"`; Primary bool `json:"primary"` }{{Value: "a@b.com", Primary: true}},
		Active:   true,
	})
	require.Equal(t, http.StatusCreated, w.Code)
	var created SCIMUser
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))

	patch := SCIMPatchOp{
		Schemas: []string{scimPatchSchema},
		Operations: []SCIMPatchOpEntry{
			{Op: "remove", Path: "emails"},
		},
	}
	w = doPatch(app, "/scim/v2/Users/"+created.ID, patch)
	assert.Equal(t, http.StatusOK, w.Code)

	var user SCIMUser
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &user))
	assert.Empty(t, user.Emails)
}

func TestSCIM_PatchUser_NotFound(t *testing.T) {
	app := testApp(t)
	patch := SCIMPatchOp{
		Schemas:    []string{scimPatchSchema},
		Operations: []SCIMPatchOpEntry{{Op: "replace", Path: "active", Value: false}},
	}
	w := doPatch(app, "/scim/v2/Users/nonexistent", patch)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestSCIM_PatchUser_InvalidOp(t *testing.T) {
	app := testApp(t)
	id := createTestUser(t, app, "alice")

	patch := SCIMPatchOp{
		Schemas:    []string{scimPatchSchema},
		Operations: []SCIMPatchOpEntry{{Op: "invalid", Path: "active", Value: false}},
	}
	w := doPatch(app, "/scim/v2/Users/"+id, patch)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSCIM_ReplaceUser(t *testing.T) {
	app := testApp(t)
	id := createTestUser(t, app, "alice")

	w := doPut(app, "/scim/v2/Users/"+id, SCIMUserRequest{
		Schemas:  []string{scimUserSchema},
		UserName: "alice-replaced",
		Active:   false,
	})
	assert.Equal(t, http.StatusOK, w.Code)

	var user SCIMUser
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &user))
	assert.Equal(t, "alice-replaced", user.UserName)
	assert.False(t, user.Active)
	assert.Equal(t, id, user.ID)
}

func TestSCIM_ReplaceUser_NotFound(t *testing.T) {
	app := testApp(t)
	w := doPut(app, "/scim/v2/Users/nonexistent", SCIMUserRequest{
		Schemas:  []string{scimUserSchema},
		UserName: "alice",
		Active:   true,
	})
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestSCIM_ReplaceUser_MissingUserName(t *testing.T) {
	app := testApp(t)
	id := createTestUser(t, app, "alice")
	w := doPut(app, "/scim/v2/Users/"+id, SCIMUserRequest{Active: true})
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSCIM_DeleteUser(t *testing.T) {
	app := testApp(t)
	id := createTestUser(t, app, "alice")

	w := doDelete(app, "/scim/v2/Users/"+id)
	assert.Equal(t, http.StatusNoContent, w.Code)

	// Verify deleted
	w = doGet(app, "/scim/v2/Users/"+id)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestSCIM_DeleteUser_NotFound(t *testing.T) {
	app := testApp(t)
	w := doDelete(app, "/scim/v2/Users/nonexistent")
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- Group CRUD Tests ---

func TestSCIM_GetGroup(t *testing.T) {
	app := testApp(t)
	id := createTestGroup(t, app, "Engineering")

	w := doGet(app, "/scim/v2/Groups/"+id)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/scim+json")

	var group SCIMGroup
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &group))
	assert.Equal(t, id, group.ID)
	assert.Equal(t, "Engineering", group.DisplayName)
}

func TestSCIM_GetGroup_NotFound(t *testing.T) {
	app := testApp(t)
	w := doGet(app, "/scim/v2/Groups/nonexistent")
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestSCIM_ListGroups(t *testing.T) {
	app := testApp(t)
	createTestGroup(t, app, "Engineering")
	createTestGroup(t, app, "Security")

	w := doGet(app, "/scim/v2/Groups")
	assert.Equal(t, http.StatusOK, w.Code)

	var resp SCIMListResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 2, resp.TotalResults)
}

func TestSCIM_ListGroups_Filter(t *testing.T) {
	app := testApp(t)
	createTestGroup(t, app, "Engineering")
	createTestGroup(t, app, "Security")

	req := httptest.NewRequest(http.MethodGet, "/scim/v2/Groups", http.NoBody)
	q := req.URL.Query()
	q.Set("filter", `displayName eq "Security"`)
	req.URL.RawQuery = q.Encode()
	req.Header.Set(adminAPIKeyHeader(), app.config.AdminAPIKey)
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp SCIMListResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 1, resp.TotalResults)
}

func TestSCIM_PatchGroup_ReplaceDisplayName(t *testing.T) {
	app := testApp(t)
	id := createTestGroup(t, app, "Engineering")

	patch := SCIMPatchOp{
		Schemas: []string{scimPatchSchema},
		Operations: []SCIMPatchOpEntry{
			{Op: "replace", Path: "displayName", Value: "Platform Engineering"},
		},
	}
	w := doPatch(app, "/scim/v2/Groups/"+id, patch)
	assert.Equal(t, http.StatusOK, w.Code)

	var group SCIMGroup
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &group))
	assert.Equal(t, "Platform Engineering", group.DisplayName)
}

func TestSCIM_PatchGroup_AddMembers(t *testing.T) {
	app := testApp(t)
	id := createTestGroup(t, app, "Engineering")

	patch := SCIMPatchOp{
		Schemas: []string{scimPatchSchema},
		Operations: []SCIMPatchOpEntry{
			{Op: "add", Path: "members", Value: []map[string]interface{}{
				{"value": "user-1", "display": "Alice"},
				{"value": "user-2", "display": "Bob"},
			}},
		},
	}
	w := doPatch(app, "/scim/v2/Groups/"+id, patch)
	assert.Equal(t, http.StatusOK, w.Code)

	var group SCIMGroup
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &group))
	assert.Len(t, group.Members, 2)
}

func TestSCIM_PatchGroup_RemoveMembers(t *testing.T) {
	app := testApp(t)
	gReq := SCIMGroupRequest{
		Schemas:     []string{scimGroupSchema},
		DisplayName: "Team",
		Members: []struct {
			Value   string `json:"value"`
			Display string `json:"display"`
		}{
			{Value: "user-1", Display: "Alice"},
			{Value: "user-2", Display: "Bob"},
		},
	}
	w := doPost(app, "/scim/v2/Groups", gReq)
	require.Equal(t, http.StatusCreated, w.Code)
	var created SCIMGroup
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))

	patch := SCIMPatchOp{
		Schemas: []string{scimPatchSchema},
		Operations: []SCIMPatchOpEntry{
			{Op: "remove", Path: "members", Value: []map[string]interface{}{
				{"value": "user-1"},
			}},
		},
	}
	w = doPatch(app, fmt.Sprintf("/scim/v2/Groups/%s", created.ID), patch)
	assert.Equal(t, http.StatusOK, w.Code)

	var group SCIMGroup
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &group))
	assert.Len(t, group.Members, 1)
	assert.Equal(t, "user-2", group.Members[0].Value)
}

func TestSCIM_PatchGroup_RemoveAllMembers(t *testing.T) {
	app := testApp(t)
	gReq := SCIMGroupRequest{
		Schemas:     []string{scimGroupSchema},
		DisplayName: "Team",
		Members: []struct {
			Value   string `json:"value"`
			Display string `json:"display"`
		}{
			{Value: "user-1", Display: "Alice"},
		},
	}
	w := doPost(app, "/scim/v2/Groups", gReq)
	require.Equal(t, http.StatusCreated, w.Code)
	var created SCIMGroup
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))

	patch := SCIMPatchOp{
		Schemas: []string{scimPatchSchema},
		Operations: []SCIMPatchOpEntry{
			{Op: "remove", Path: "members"},
		},
	}
	w = doPatch(app, fmt.Sprintf("/scim/v2/Groups/%s", created.ID), patch)
	assert.Equal(t, http.StatusOK, w.Code)

	var group SCIMGroup
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &group))
	assert.Empty(t, group.Members)
}

func TestSCIM_PatchGroup_NotFound(t *testing.T) {
	app := testApp(t)
	patch := SCIMPatchOp{
		Schemas:    []string{scimPatchSchema},
		Operations: []SCIMPatchOpEntry{{Op: "replace", Path: "displayName", Value: "X"}},
	}
	w := doPatch(app, "/scim/v2/Groups/nonexistent", patch)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestSCIM_ReplaceGroup(t *testing.T) {
	app := testApp(t)
	id := createTestGroup(t, app, "Engineering")

	w := doPut(app, "/scim/v2/Groups/"+id, SCIMGroupRequest{
		Schemas:     []string{scimGroupSchema},
		DisplayName: "Platform",
		Members: []struct {
			Value   string `json:"value"`
			Display string `json:"display"`
		}{
			{Value: "user-1", Display: "Alice"},
		},
	})
	assert.Equal(t, http.StatusOK, w.Code)

	var group SCIMGroup
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &group))
	assert.Equal(t, "Platform", group.DisplayName)
	assert.Len(t, group.Members, 1)
	assert.Equal(t, id, group.ID)
}

func TestSCIM_ReplaceGroup_NotFound(t *testing.T) {
	app := testApp(t)
	w := doPut(app, "/scim/v2/Groups/nonexistent", SCIMGroupRequest{
		Schemas:     []string{scimGroupSchema},
		DisplayName: "Team",
	})
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestSCIM_ReplaceGroup_MissingDisplayName(t *testing.T) {
	app := testApp(t)
	id := createTestGroup(t, app, "Engineering")
	w := doPut(app, "/scim/v2/Groups/"+id, SCIMGroupRequest{})
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSCIM_DeleteGroup(t *testing.T) {
	app := testApp(t)
	id := createTestGroup(t, app, "Engineering")

	w := doDelete(app, "/scim/v2/Groups/"+id)
	assert.Equal(t, http.StatusNoContent, w.Code)

	// Verify deleted
	w = doGet(app, "/scim/v2/Groups/"+id)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestSCIM_DeleteGroup_NotFound(t *testing.T) {
	app := testApp(t)
	w := doDelete(app, "/scim/v2/Groups/nonexistent")
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- Auth Tests for new endpoints ---

func TestSCIM_ListUsers_RequiresAuth(t *testing.T) {
	app := testApp(t)
	req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", http.NoBody)
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSCIM_DeleteUser_RequiresAuth(t *testing.T) {
	app := testApp(t)
	req := httptest.NewRequest(http.MethodDelete, "/scim/v2/Users/some-id", http.NoBody)
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSCIM_PatchGroup_RequiresAuth(t *testing.T) {
	app := testApp(t)
	data, _ := json.Marshal(SCIMPatchOp{Schemas: []string{scimPatchSchema}})
	req := httptest.NewRequest(http.MethodPatch, "/scim/v2/Groups/id", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// --- Error response format ---

func TestSCIM_ErrorFormat(t *testing.T) {
	app := testApp(t)
	w := doGet(app, "/scim/v2/Users/nonexistent-id")
	assert.Equal(t, http.StatusNotFound, w.Code)

	var errResp SCIMErrorResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &errResp))
	assert.Contains(t, errResp.Schemas, scimErrorSchema)
	assert.Equal(t, "404", errResp.Status)
	assert.NotEmpty(t, errResp.Detail)
}
