// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import "strings"

// ActionCategory is the semantic action type for an MCP tool call.
// It maps to the action vocabulary used in capability manifest constraints
// (e.g. actions: ["read"]) allowing fine-grained policy without listing
// every tool name individually.
type ActionCategory string

const (
	// ActionRead covers tools that only retrieve data without side effects.
	ActionRead ActionCategory = "read"
	// ActionWrite covers tools that create or update data.
	ActionWrite ActionCategory = "write"
	// ActionDelete covers tools that remove or archive data.
	ActionDelete ActionCategory = "delete"
	// ActionExecute covers tools that run processes, commands, or browser actions.
	ActionExecute ActionCategory = "execute"
	// ActionAdmin covers tools that modify access controls, permissions, or
	// platform-level configuration.
	ActionAdmin ActionCategory = "admin"
)

// ActionResolver maps an MCP tool name to a semantic ActionCategory.
// The category is matched against capability constraint actions so that
// policies like actions: ["read"] work without enumerating every read tool.
//
// Returning "" signals that the tool is unknown to this resolver; callers
// should fall through to the next resolver in a chain or treat the tool as
// unclassified (which falls back to the generic "call" action check).
type ActionResolver interface {
	Resolve(toolName string) ActionCategory
}

// -----------------------------------------------------------------
// StaticActionResolver — exact lookup from a pre-built map
// -----------------------------------------------------------------

// StaticActionResolver resolves tool names from an explicit map.
// It is the building block for both built-in server profiles and
// user-supplied action-map files.
type StaticActionResolver struct {
	toolMap map[string]ActionCategory
}

// NewStaticActionResolver creates a resolver from a tool→category map.
// Lookups are case-sensitive and O(1).
func NewStaticActionResolver(m map[string]ActionCategory) *StaticActionResolver {
	return &StaticActionResolver{toolMap: m}
}

// Resolve implements ActionResolver.
// Returns "" when toolName is not in the map.
func (r *StaticActionResolver) Resolve(toolName string) ActionCategory {
	return r.toolMap[toolName]
}

// -----------------------------------------------------------------
// HeuristicResolver — name-prefix inference
// -----------------------------------------------------------------

// HeuristicResolver infers an ActionCategory from well-known tool name
// prefixes and substrings. It is used as the last-resort resolver when
// neither a built-in profile nor a custom action map covers the tool.
//
// The heuristics are intentionally conservative: when a prefix is
// ambiguous the resolver returns "" rather than guessing, leaving the
// decision to the PDP's generic "call" action fallback.
type HeuristicResolver struct{}

var (
	adminPrefixes   = []string{"admin_", "grant_", "revoke_", "promote_", "demote_", "approve_", "reject_"}
	deletePrefixes  = []string{"delete_", "remove_", "drop_", "purge_", "destroy_", "archive_", "close_", "clear_"}
	executePrefixes = []string{"run_", "execute_", "launch_", "start_", "stop_", "restart_", "invoke_", "trigger_", "apply_", "deploy_", "install_", "eval_"}
	writePrefixes   = []string{"create_", "update_", "write_", "set_", "put_", "post_", "send_", "add_", "insert_", "upsert_", "patch_", "edit_", "modify_", "push_", "upload_", "save_", "append_", "publish_", "fork_", "merge_"}
	readPrefixes    = []string{"get_", "list_", "search_", "read_", "describe_", "fetch_", "show_", "find_", "query_", "view_", "check_", "inspect_", "peek_", "stat_", "open_"}
)

// Resolve implements ActionResolver using name-prefix heuristics.
// Returns "" when no prefix matches.
func (HeuristicResolver) Resolve(toolName string) ActionCategory {
	lower := strings.ToLower(toolName) + "_" // append separator so prefix matching is word-boundary safe
	for _, p := range adminPrefixes {
		if strings.HasPrefix(lower, p) {
			return ActionAdmin
		}
	}
	for _, p := range deletePrefixes {
		if strings.HasPrefix(lower, p) {
			return ActionDelete
		}
	}
	for _, p := range executePrefixes {
		if strings.HasPrefix(lower, p) {
			return ActionExecute
		}
	}
	for _, p := range writePrefixes {
		if strings.HasPrefix(lower, p) {
			return ActionWrite
		}
	}
	for _, p := range readPrefixes {
		if strings.HasPrefix(lower, p) {
			return ActionRead
		}
	}
	return "" // unknown — caller falls back to generic "call" check
}

// -----------------------------------------------------------------
// ChainedResolver — ordered fallthrough
// -----------------------------------------------------------------

// ChainedResolver tries each resolver in order, returning the first
// non-empty result. Use it to layer a custom action-map file on top
// of a built-in server profile and the heuristic fallback:
//
//	NewChainedResolver(customFileResolver, builtinResolver, HeuristicResolver{})
type ChainedResolver struct {
	resolvers []ActionResolver
}

// NewChainedResolver creates a resolver that queries each resolver in
// order, returning the first non-empty ActionCategory.
func NewChainedResolver(resolvers ...ActionResolver) *ChainedResolver {
	return &ChainedResolver{resolvers: resolvers}
}

// Resolve implements ActionResolver.
func (c *ChainedResolver) Resolve(toolName string) ActionCategory {
	for _, r := range c.resolvers {
		if cat := r.Resolve(toolName); cat != "" {
			return cat
		}
	}
	return ""
}
