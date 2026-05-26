// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package issuer

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// SCIMStore provides in-memory storage for SCIM Users and Groups.
type SCIMStore struct {
	mu     sync.RWMutex
	users  map[string]*SCIMUser
	groups map[string]*SCIMGroup
}

// NewSCIMStore creates an empty SCIM store.
func NewSCIMStore() *SCIMStore {
	return &SCIMStore{
		users:  make(map[string]*SCIMUser),
		groups: make(map[string]*SCIMGroup),
	}
}

// SCIMUser is the internal representation of a SCIM 2.0 user resource.
type SCIMUser struct {
	ID         string         `json:"id"`
	Schemas    []string       `json:"schemas"`
	UserName   string         `json:"userName"`
	Name       SCIMName       `json:"name,omitempty"`
	Emails     []SCIMEmail    `json:"emails,omitempty"`
	Active     bool           `json:"active"`
	ExternalID string         `json:"externalId,omitempty"`
	Meta       SCIMMetadata   `json:"meta"`
	Groups     []SCIMGroupRef `json:"groups,omitempty"`
}

// SCIMName contains structured name components.
type SCIMName struct {
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
	Formatted  string `json:"formatted,omitempty"`
}

// SCIMEmail represents an email value in SCIM.
type SCIMEmail struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary,omitempty"`
	Type    string `json:"type,omitempty"`
}

// SCIMGroup is the internal representation of a SCIM 2.0 group resource.
type SCIMGroup struct {
	ID          string       `json:"id"`
	Schemas     []string     `json:"schemas"`
	DisplayName string       `json:"displayName"`
	Members     []SCIMMember `json:"members,omitempty"`
	ExternalID  string       `json:"externalId,omitempty"`
	Meta        SCIMMetadata `json:"meta"`
}

// SCIMMember represents a group member reference.
type SCIMMember struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
	Ref     string `json:"$ref,omitempty"`
}

// SCIMGroupRef is a reference to a group on a user resource.
type SCIMGroupRef struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
	Ref     string `json:"$ref,omitempty"`
}

// SCIMMetadata holds SCIM resource metadata.
type SCIMMetadata struct {
	ResourceType string `json:"resourceType"`
	Created      string `json:"created"`
	LastModified string `json:"lastModified"`
	Location     string `json:"location,omitempty"`
}

// SCIMListResponse is the standard SCIM list response envelope.
type SCIMListResponse struct {
	Schemas      []string    `json:"schemas"`
	TotalResults int         `json:"totalResults"`
	StartIndex   int         `json:"startIndex"`
	ItemsPerPage int         `json:"itemsPerPage"`
	Resources    interface{} `json:"Resources"`
}

// SCIMErrorResponse is the standard SCIM error format.
type SCIMErrorResponse struct {
	Schemas  []string `json:"schemas"`
	Detail   string   `json:"detail"`
	Status   string   `json:"status"`
	ScimType string   `json:"scimType,omitempty"`
}

// SCIMPatchOp represents a SCIM PATCH operation.
type SCIMPatchOp struct {
	Schemas    []string           `json:"schemas"`
	Operations []SCIMPatchOpEntry `json:"Operations"`
}

// SCIMPatchOpEntry is a single operation within a SCIM PATCH request.
type SCIMPatchOpEntry struct {
	Op    string      `json:"op"`
	Path  string      `json:"path,omitempty"`
	Value interface{} `json:"value,omitempty"`
}

const (
	scimUserSchema  = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimGroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"
	scimListSchema  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	scimErrorSchema = "urn:ietf:params:scim:api:messages:2.0:Error"
	scimPatchSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
)

// --- Store Methods ---

// CreateUser adds a user to the store.
func (s *SCIMStore) CreateUser(user *SCIMUser) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[user.ID] = user
}

// GetUser retrieves a user by ID.
func (s *SCIMStore) GetUser(id string) (*SCIMUser, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	return u, ok
}

// ListUsers returns all users, optionally filtered by SCIM filter expression.
func (s *SCIMStore) ListUsers(filter string) []*SCIMUser {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*SCIMUser, 0, len(s.users))
	for _, u := range s.users {
		if filter != "" && !matchesUserFilter(u, filter) {
			continue
		}
		result = append(result, u)
	}
	return result
}

// UpdateUser replaces user attributes.
func (s *SCIMStore) UpdateUser(user *SCIMUser) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[user.ID] = user
}

// DeleteUser removes a user by ID.
func (s *SCIMStore) DeleteUser(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[id]; !ok {
		return false
	}
	delete(s.users, id)
	return true
}

// CreateGroup adds a group to the store and synchronizes user.groups.
func (s *SCIMStore) CreateGroup(group *SCIMGroup) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.groups[group.ID] = group
	s.syncUserGroupsForGroup(group.ID)
}

// GetGroup retrieves a group by ID.
func (s *SCIMStore) GetGroup(id string) (*SCIMGroup, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	g, ok := s.groups[id]
	return g, ok
}

// ListGroups returns all groups, optionally filtered by SCIM filter expression.
func (s *SCIMStore) ListGroups(filter string) []*SCIMGroup {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*SCIMGroup, 0, len(s.groups))
	for _, g := range s.groups {
		if filter != "" && !matchesGroupFilter(g, filter) {
			continue
		}
		result = append(result, g)
	}
	return result
}

// UpdateGroup replaces group attributes and synchronizes user.groups.
func (s *SCIMStore) UpdateGroup(group *SCIMGroup) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.groups[group.ID] = group
	s.syncUserGroupsForGroup(group.ID)
}

// DeleteGroup removes a group by ID and clears user.groups references.
func (s *SCIMStore) DeleteGroup(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.groups[id]; !ok {
		return false
	}
	delete(s.groups, id)
	s.removeGroupFromAllUsers(id)
	return true
}

// syncUserGroupsForGroup updates the groups field on all users referenced by this group.
// Must be called with mu held.
func (s *SCIMStore) syncUserGroupsForGroup(groupID string) {
	group, ok := s.groups[groupID]
	if !ok {
		return
	}

	// Build a map of user IDs that should have this group
	memberIDs := make(map[string]bool, len(group.Members))
	for _, m := range group.Members {
		memberIDs[m.Value] = true
	}

	// Update all users: add or remove group reference as needed
	for userID, user := range s.users {
		shouldHaveGroup := memberIDs[userID]
		hasGroup := false
		groupIdx := -1

		// Check if user already has this group
		for i, gr := range user.Groups {
			if gr.Value == groupID {
				hasGroup = true
				groupIdx = i
				break
			}
		}

		switch {
		case shouldHaveGroup && !hasGroup:
			// Add group to user
			user.Groups = append(user.Groups, SCIMGroupRef{
				Value:   groupID,
				Display: group.DisplayName,
			})
		case !shouldHaveGroup && hasGroup:
			// Remove group from user
			user.Groups = append(user.Groups[:groupIdx], user.Groups[groupIdx+1:]...)
		case shouldHaveGroup && hasGroup:
			// Update display name if changed
			user.Groups[groupIdx].Display = group.DisplayName
		}
	}
}

// removeGroupFromAllUsers clears references to a deleted group from all users.
// Must be called with mu held.
func (s *SCIMStore) removeGroupFromAllUsers(groupID string) {
	for _, user := range s.users {
		for i, gr := range user.Groups {
			if gr.Value == groupID {
				user.Groups = append(user.Groups[:i], user.Groups[i+1:]...)
				break
			}
		}
	}
}

// matchesUserFilter applies a SCIM filter to a user resource.
// Supports eq operator on userName, displayName (formatted name), and externalId.
func matchesUserFilter(user *SCIMUser, filter string) bool {
	filter = strings.TrimSpace(filter)
	parts := strings.SplitN(filter, " eq ", 2)
	if len(parts) == 2 {
		attr := strings.TrimSpace(strings.ToLower(parts[0]))
		filterVal := strings.TrimSpace(parts[1])
		filterVal = strings.Trim(filterVal, `"`)

		switch attr {
		case "username":
			return strings.EqualFold(user.UserName, filterVal)
		case "displayname":
			formatted := user.Name.Formatted
			if formatted == "" && (user.Name.GivenName != "" || user.Name.FamilyName != "") {
				formatted = strings.TrimSpace(user.Name.GivenName + " " + user.Name.FamilyName)
			}
			return strings.EqualFold(formatted, filterVal)
		case "externalid":
			return strings.EqualFold(user.ExternalID, filterVal)
		default:
			// Unsupported attribute
			return false
		}
	}
	// Fallback: substring match on userName (for backward compatibility)
	return strings.Contains(strings.ToLower(user.UserName), strings.ToLower(filter))
}

// matchesGroupFilter applies a SCIM filter to a group resource.
// Supports eq operator on displayName and externalId.
func matchesGroupFilter(group *SCIMGroup, filter string) bool {
	filter = strings.TrimSpace(filter)
	parts := strings.SplitN(filter, " eq ", 2)
	if len(parts) == 2 {
		attr := strings.TrimSpace(strings.ToLower(parts[0]))
		filterVal := strings.TrimSpace(parts[1])
		filterVal = strings.Trim(filterVal, `"`)

		switch attr {
		case "displayname":
			return strings.EqualFold(group.DisplayName, filterVal)
		case "externalid":
			return strings.EqualFold(group.ExternalID, filterVal)
		default:
			// Unsupported attribute
			return false
		}
	}
	// Fallback: substring match on displayName (for backward compatibility)
	return strings.Contains(strings.ToLower(group.DisplayName), strings.ToLower(filter))
}

// --- SCIM Route Registration ---

func (app *App) registerSCIMRoutes(r chi.Router) {
	r.Route("/scim/v2", func(r chi.Router) {
		r.Use(app.requireSCIMAuth)

		// Users
		r.Post("/Users", app.handleSCIMCreateUser)
		r.Get("/Users", app.handleSCIMListUsers)
		r.Get("/Users/{id}", app.handleSCIMGetUser)
		r.Patch("/Users/{id}", app.handleSCIMPatchUser)
		r.Put("/Users/{id}", app.handleSCIMReplaceUser)
		r.Delete("/Users/{id}", app.handleSCIMDeleteUser)

		// Groups
		r.Post("/Groups", app.handleSCIMCreateGroup)
		r.Get("/Groups", app.handleSCIMListGroups)
		r.Get("/Groups/{id}", app.handleSCIMGetGroup)
		r.Patch("/Groups/{id}", app.handleSCIMPatchGroup)
		r.Put("/Groups/{id}", app.handleSCIMReplaceGroup)
		r.Delete("/Groups/{id}", app.handleSCIMDeleteGroup)
	})
}

// requireSCIMAuth is a middleware that enforces admin authentication for SCIM endpoints
// and returns SCIM-formatted error responses.
func (app *App) requireSCIMAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if app.config.AdminAPIKey == "" {
			writeSCIMError(w, http.StatusServiceUnavailable, "SCIM API is not configured", "")
			return
		}

		provided := r.Header.Get(scimAdminAPIKeyHeader())
		if subtle.ConstantTimeCompare([]byte(provided), []byte(app.config.AdminAPIKey)) != 1 {
			writeSCIMError(w, http.StatusUnauthorized, "authentication failed", "")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func scimAdminAPIKeyHeader() string {
	return strings.Join([]string{"X", "Admin", "Api", "Key"}, "-")
}

// --- User Handlers ---

func (app *App) handleSCIMCreateUser(w http.ResponseWriter, r *http.Request) {
	var req SCIMUserRequest
	if err := app.readJSON(r, &req); err != nil {
		writeSCIMError(w, http.StatusBadRequest, err.Error(), "invalidValue")
		return
	}

	if req.UserName == "" {
		writeSCIMError(w, http.StatusBadRequest, "userName is required", "invalidValue")
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)
	user := &SCIMUser{
		ID:       uuid.New().String(),
		Schemas:  []string{scimUserSchema},
		UserName: req.UserName,
		Name: SCIMName{
			GivenName:  req.Name.GivenName,
			FamilyName: req.Name.FamilyName,
		},
		Active:     req.Active,
		ExternalID: req.ExternalID,
		Meta: SCIMMetadata{
			ResourceType: "User",
			Created:      now,
			LastModified: now,
		},
	}

	for _, e := range req.Emails {
		user.Emails = append(user.Emails, SCIMEmail{
			Value:   e.Value,
			Primary: e.Primary,
		})
	}

	app.scimStore.CreateUser(user)

	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(user)
}

func (app *App) handleSCIMListUsers(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("filter")
	users := app.scimStore.ListUsers(filter)

	resp := SCIMListResponse{
		Schemas:      []string{scimListSchema},
		TotalResults: len(users),
		StartIndex:   1,
		ItemsPerPage: len(users),
		Resources:    users,
	}

	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (app *App) handleSCIMGetUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	user, ok := app.scimStore.GetUser(id)
	if !ok {
		writeSCIMError(w, http.StatusNotFound, fmt.Sprintf("user %q not found", id), "")
		return
	}

	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(user)
}

func (app *App) handleSCIMPatchUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	user, ok := app.scimStore.GetUser(id)
	if !ok {
		writeSCIMError(w, http.StatusNotFound, fmt.Sprintf("user %q not found", id), "")
		return
	}

	var patch SCIMPatchOp
	if err := app.readJSON(r, &patch); err != nil {
		writeSCIMError(w, http.StatusBadRequest, err.Error(), "invalidValue")
		return
	}

	if err := app.applySCIMUserPatch(user, patch.Operations); err != nil {
		writeSCIMError(w, http.StatusBadRequest, err.Error(), "invalidValue")
		return
	}

	user.Meta.LastModified = time.Now().UTC().Format(time.RFC3339)
	app.scimStore.UpdateUser(user)

	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(user)
}

func (app *App) handleSCIMReplaceUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	existing, ok := app.scimStore.GetUser(id)
	if !ok {
		writeSCIMError(w, http.StatusNotFound, fmt.Sprintf("user %q not found", id), "")
		return
	}

	var req SCIMUserRequest
	if err := app.readJSON(r, &req); err != nil {
		writeSCIMError(w, http.StatusBadRequest, err.Error(), "invalidValue")
		return
	}

	if req.UserName == "" {
		writeSCIMError(w, http.StatusBadRequest, "userName is required", "invalidValue")
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)
	user := &SCIMUser{
		ID:       id,
		Schemas:  []string{scimUserSchema},
		UserName: req.UserName,
		Name: SCIMName{
			GivenName:  req.Name.GivenName,
			FamilyName: req.Name.FamilyName,
		},
		Active:     req.Active,
		ExternalID: req.ExternalID,
		Meta: SCIMMetadata{
			ResourceType: "User",
			Created:      existing.Meta.Created,
			LastModified: now,
		},
	}

	for _, e := range req.Emails {
		user.Emails = append(user.Emails, SCIMEmail{
			Value:   e.Value,
			Primary: e.Primary,
		})
	}

	app.scimStore.UpdateUser(user)

	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(user)
}

func (app *App) handleSCIMDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !app.scimStore.DeleteUser(id) {
		writeSCIMError(w, http.StatusNotFound, fmt.Sprintf("user %q not found", id), "")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Group Handlers ---

func (app *App) handleSCIMCreateGroup(w http.ResponseWriter, r *http.Request) {
	var req SCIMGroupRequest
	if err := app.readJSON(r, &req); err != nil {
		writeSCIMError(w, http.StatusBadRequest, err.Error(), "invalidValue")
		return
	}

	if req.DisplayName == "" {
		writeSCIMError(w, http.StatusBadRequest, "displayName is required", "invalidValue")
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)
	group := &SCIMGroup{
		ID:          uuid.New().String(),
		Schemas:     []string{scimGroupSchema},
		DisplayName: req.DisplayName,
		ExternalID:  req.ExternalID,
		Meta: SCIMMetadata{
			ResourceType: "Group",
			Created:      now,
			LastModified: now,
		},
	}

	for _, m := range req.Members {
		group.Members = append(group.Members, SCIMMember{
			Value:   m.Value,
			Display: m.Display,
		})
	}

	app.scimStore.CreateGroup(group)

	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(group)
}

func (app *App) handleSCIMListGroups(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("filter")
	groups := app.scimStore.ListGroups(filter)

	resp := SCIMListResponse{
		Schemas:      []string{scimListSchema},
		TotalResults: len(groups),
		StartIndex:   1,
		ItemsPerPage: len(groups),
		Resources:    groups,
	}

	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (app *App) handleSCIMGetGroup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	group, ok := app.scimStore.GetGroup(id)
	if !ok {
		writeSCIMError(w, http.StatusNotFound, fmt.Sprintf("group %q not found", id), "")
		return
	}

	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(group)
}

func (app *App) handleSCIMPatchGroup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	group, ok := app.scimStore.GetGroup(id)
	if !ok {
		writeSCIMError(w, http.StatusNotFound, fmt.Sprintf("group %q not found", id), "")
		return
	}

	var patch SCIMPatchOp
	if err := app.readJSON(r, &patch); err != nil {
		writeSCIMError(w, http.StatusBadRequest, err.Error(), "invalidValue")
		return
	}

	if err := app.applySCIMGroupPatch(group, patch.Operations); err != nil {
		writeSCIMError(w, http.StatusBadRequest, err.Error(), "invalidValue")
		return
	}

	group.Meta.LastModified = time.Now().UTC().Format(time.RFC3339)
	app.scimStore.UpdateGroup(group)

	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(group)
}

func (app *App) handleSCIMReplaceGroup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	existing, ok := app.scimStore.GetGroup(id)
	if !ok {
		writeSCIMError(w, http.StatusNotFound, fmt.Sprintf("group %q not found", id), "")
		return
	}

	var req SCIMGroupRequest
	if err := app.readJSON(r, &req); err != nil {
		writeSCIMError(w, http.StatusBadRequest, err.Error(), "invalidValue")
		return
	}

	if req.DisplayName == "" {
		writeSCIMError(w, http.StatusBadRequest, "displayName is required", "invalidValue")
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)
	group := &SCIMGroup{
		ID:          id,
		Schemas:     []string{scimGroupSchema},
		DisplayName: req.DisplayName,
		ExternalID:  req.ExternalID,
		Meta: SCIMMetadata{
			ResourceType: "Group",
			Created:      existing.Meta.Created,
			LastModified: now,
		},
	}

	for _, m := range req.Members {
		group.Members = append(group.Members, SCIMMember{
			Value:   m.Value,
			Display: m.Display,
		})
	}

	app.scimStore.UpdateGroup(group)

	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(group)
}

func (app *App) handleSCIMDeleteGroup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !app.scimStore.DeleteGroup(id) {
		writeSCIMError(w, http.StatusNotFound, fmt.Sprintf("group %q not found", id), "")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- SCIM Patch Helpers ---

func (app *App) applySCIMUserPatch(user *SCIMUser, ops []SCIMPatchOpEntry) error {
	for _, op := range ops {
		switch strings.ToLower(op.Op) {
		case "replace":
			if err := applySCIMUserReplace(user, op); err != nil {
				return err
			}
		case "add":
			if err := applySCIMUserAdd(user, op); err != nil {
				return err
			}
		case "remove":
			applySCIMUserRemove(user, op)
		default:
			return fmt.Errorf("unsupported SCIM operation: %q", op.Op)
		}
	}
	return nil
}

func applySCIMUserReplace(user *SCIMUser, op SCIMPatchOpEntry) error {
	path := strings.ToLower(op.Path)
	switch path {
	case "active":
		v, ok := op.Value.(bool)
		if !ok {
			return fmt.Errorf("active must be a boolean")
		}
		user.Active = v
	case "username":
		v, ok := op.Value.(string)
		if !ok {
			return fmt.Errorf("userName must be a string")
		}
		user.UserName = v
	case "name.givenname":
		v, ok := op.Value.(string)
		if !ok {
			return fmt.Errorf("name.givenName must be a string")
		}
		user.Name.GivenName = v
	case "name.familyname":
		v, ok := op.Value.(string)
		if !ok {
			return fmt.Errorf("name.familyName must be a string")
		}
		user.Name.FamilyName = v
	case "externalid":
		v, ok := op.Value.(string)
		if !ok {
			return fmt.Errorf("externalId must be a string")
		}
		user.ExternalID = v
	case "":
		// Bulk replace: value is a map
		return applySCIMUserBulkReplace(user, op.Value)
	default:
		return fmt.Errorf("unsupported path for replace: %q", op.Path)
	}
	return nil
}

func applySCIMUserBulkReplace(user *SCIMUser, value interface{}) error {
	m, ok := value.(map[string]interface{})
	if !ok {
		return fmt.Errorf("replace without path requires a map value")
	}
	for k, v := range m {
		switch strings.ToLower(k) {
		case "active":
			if b, ok := v.(bool); ok {
				user.Active = b
			}
		case "username":
			if s, ok := v.(string); ok {
				user.UserName = s
			}
		case "externalid":
			if s, ok := v.(string); ok {
				user.ExternalID = s
			}
		}
	}
	return nil
}

func applySCIMUserAdd(user *SCIMUser, op SCIMPatchOpEntry) error {
	path := strings.ToLower(op.Path)
	switch path {
	case "emails":
		return addSCIMEmails(user, op.Value)
	default:
		// Treat add on scalar paths the same as replace.
		return applySCIMUserReplace(user, op)
	}
}

func addSCIMEmails(user *SCIMUser, value interface{}) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("invalid emails value: %w", err)
	}
	var emails []SCIMEmail
	if err := json.Unmarshal(raw, &emails); err != nil {
		// Try single email
		var email SCIMEmail
		if err2 := json.Unmarshal(raw, &email); err2 != nil {
			return fmt.Errorf("invalid emails value")
		}
		emails = []SCIMEmail{email}
	}
	user.Emails = append(user.Emails, emails...)
	return nil
}

func applySCIMUserRemove(user *SCIMUser, op SCIMPatchOpEntry) {
	path := strings.ToLower(op.Path)
	switch path {
	case "emails":
		user.Emails = nil
	case "externalid":
		user.ExternalID = ""
	case "name.givenname":
		user.Name.GivenName = ""
	case "name.familyname":
		user.Name.FamilyName = ""
	}
}

func (app *App) applySCIMGroupPatch(group *SCIMGroup, ops []SCIMPatchOpEntry) error {
	for _, op := range ops {
		switch strings.ToLower(op.Op) {
		case "replace":
			if err := applySCIMGroupReplace(group, op); err != nil {
				return err
			}
		case "add":
			if err := applySCIMGroupAdd(group, op); err != nil {
				return err
			}
		case "remove":
			applySCIMGroupRemove(group, op)
		default:
			return fmt.Errorf("unsupported SCIM operation: %q", op.Op)
		}
	}
	return nil
}

func applySCIMGroupReplace(group *SCIMGroup, op SCIMPatchOpEntry) error {
	path := strings.ToLower(op.Path)
	switch path {
	case "displayname":
		v, ok := op.Value.(string)
		if !ok {
			return fmt.Errorf("displayName must be a string")
		}
		group.DisplayName = v
	case "externalid":
		v, ok := op.Value.(string)
		if !ok {
			return fmt.Errorf("externalId must be a string")
		}
		group.ExternalID = v
	case "members":
		return replaceSCIMMembers(group, op.Value)
	case "":
		return applySCIMGroupBulkReplace(group, op.Value)
	default:
		return fmt.Errorf("unsupported path for replace: %q", op.Path)
	}
	return nil
}

func applySCIMGroupBulkReplace(group *SCIMGroup, value interface{}) error {
	m, ok := value.(map[string]interface{})
	if !ok {
		return fmt.Errorf("replace without path requires a map value")
	}
	for k, v := range m {
		switch strings.ToLower(k) {
		case "displayname":
			if s, ok := v.(string); ok {
				group.DisplayName = s
			}
		case "externalid":
			if s, ok := v.(string); ok {
				group.ExternalID = s
			}
		}
	}
	return nil
}

func applySCIMGroupAdd(group *SCIMGroup, op SCIMPatchOpEntry) error {
	path := strings.ToLower(op.Path)
	switch path {
	case "members":
		return addSCIMMembers(group, op.Value)
	default:
		return applySCIMGroupReplace(group, op)
	}
}

func addSCIMMembers(group *SCIMGroup, value interface{}) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("invalid members value: %w", err)
	}
	var members []SCIMMember
	if err := json.Unmarshal(raw, &members); err != nil {
		var member SCIMMember
		if err2 := json.Unmarshal(raw, &member); err2 != nil {
			return fmt.Errorf("invalid members value")
		}
		members = []SCIMMember{member}
	}
	group.Members = append(group.Members, members...)
	return nil
}

func replaceSCIMMembers(group *SCIMGroup, value interface{}) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("invalid members value: %w", err)
	}
	var members []SCIMMember
	if err := json.Unmarshal(raw, &members); err != nil {
		return fmt.Errorf("invalid members value: %w", err)
	}
	group.Members = members
	return nil
}

func applySCIMGroupRemove(group *SCIMGroup, op SCIMPatchOpEntry) {
	path := strings.ToLower(op.Path)
	switch path {
	case "members":
		// If value specified, remove specific members; otherwise clear all.
		if op.Value != nil {
			removeSCIMMembers(group, op.Value)
		} else {
			group.Members = nil
		}
	case "externalid":
		group.ExternalID = ""
	}
}

func removeSCIMMembers(group *SCIMGroup, value interface{}) {
	raw, _ := json.Marshal(value)
	var toRemove []SCIMMember
	if err := json.Unmarshal(raw, &toRemove); err != nil {
		return
	}
	removeIDs := make(map[string]bool, len(toRemove))
	for _, m := range toRemove {
		removeIDs[m.Value] = true
	}
	filtered := make([]SCIMMember, 0, len(group.Members))
	for _, m := range group.Members {
		if !removeIDs[m.Value] {
			filtered = append(filtered, m)
		}
	}
	group.Members = filtered
}

// --- SCIM Error Helper ---

func writeSCIMError(w http.ResponseWriter, status int, detail, scimType string) {
	resp := SCIMErrorResponse{
		Schemas:  []string{scimErrorSchema},
		Detail:   detail,
		Status:   fmt.Sprintf("%d", status),
		ScimType: scimType,
	}
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}
