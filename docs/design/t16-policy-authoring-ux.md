# T-16: Policy Authoring UX — Design Document

**Status:** Draft  
**Phase:** 3 · Weeks 10–20  
**Priority:** P2  
**Effort:** 4–6 weeks  
**Owner:** Design + Eng  
**Depends on:** T-06 (sub-20-min onboarding)  
**Date:** 2026-05-28

---

## Problem

Every eunox policy today is a hand-edited JSON file. A `RoleCapabilityPolicy` can have deeply nested `Constraint` objects, polymorphic `Condition` discriminated unions (11 types), and a JSON-Schema subset for argument validation. Writing this correctly requires reading Go struct tags and understanding glob-matching semantics.

The success metric for the Cloud Team tier is **50% of users authoring policies via UI rather than raw YAML by month 7**. That means the UI must cover the full policy surface — not just a simplified subset — while remaining navigable by a compliance officer or security manager who has never seen a JSON file.

This is not a "nice polish" task. If the policy surface is only accessible to engineers, the product cannot reach the CISO-level buyers who fund enterprise deals.

---

## Goals

1. A non-engineer can create, edit, and delete a role policy without touching JSON or YAML.
2. Policies authored via the UI are semantically identical to policies authored by hand — no capability surface is hidden or locked away.
3. Real-time feedback: the user understands what an agent *can* and *cannot* do before saving.
4. The UI is embedded in the existing issuer binary — zero new infrastructure to deploy.
5. Template library for SOC 2, HIPAA, and PCI-DSS reduces time-to-first-policy to under 5 minutes.

## Non-Goals

- Policy version history, approval workflows, or multi-author collaboration (these belong to T-18, the SaaS control plane).
- Visual debugging of live traffic (belongs to T-15, the replayable audit session UI).
- OPA/Cedar policy authoring (not eunox's format).
- Mobile-responsive layout (admin tooling; desktop only).

---

## Technology Decisions

### Decision 1: Frontend Framework — React 19 + Vite 6

**Chosen:** React 19 with Vite 6 as the build tool.

**Rationale:**  
The policy editor is a stateful admin application with complex nested forms (roles → capabilities arrays → discriminated-union conditions). React's `useFieldArray` from react-hook-form handles this pattern cleanly. The ecosystem has the broadest set of accessible component primitives (Radix UI) and the code editor bindings we need (CodeMirror 6 React wrapper).

The `site/` directory already uses Astro, but that is a documentation/marketing site built for static output to Cloudflare Workers. Embedding a complex stateful app in Astro adds unnecessary framework bridging. The policy editor is a separate concern and warrants its own SPA.

**Alternatives considered:**  
- **Svelte 5** — Smaller bundle, but fewer form library options and no team familiarity established. The discriminated-union condition form is the hardest UX problem; React's ecosystem reduces that risk.  
- **Vue 3** — Viable, but no existing Vue code in the repo and no compelling advantage over React for this use case.
- **HTMX + Go templates** — Appealing for minimal footprint, but the live-preview panel (real-time policy simulation) requires enough client-side state that a SPA is the more honest approach. A hybrid would end up as a SPA anyway.

**Build output location:** `internal/issuer/ui/` (source), `internal/issuer/ui/dist/` (build output, embedded into Go binary).

---

### Decision 2: Code Editor Component — CodeMirror 6

**Chosen:** CodeMirror 6 via `@uiw/react-codemirror`.

The form-based editor is the primary path, but power users need a raw JSON escape hatch — especially for `ArgumentSchema` objects which can become arbitrarily nested. CodeMirror 6 provides this with inline JSON validation, syntax highlighting, and bracket matching.

**Why not Monaco Editor:**  
Monaco is the VS Code engine — excellent, but ships at ~3–4 MB minified. For an embedded admin UI where the server also handles enforcement, that bundle size is inappropriate. CodeMirror 6 is modular and tree-shakeable; the JSON + YAML modes together come in under 250 KB gzipped.

**JSON Schema validation in the editor:** The `codemirror-json-schema` package can wire the `RoleCapabilityPolicy` JSON Schema (generated from the Go types) into CodeMirror for inline error markers. This gives the raw JSON view the same validation feedback as the form view.

---

### Decision 3: Component Library — shadcn/ui (Radix UI + Tailwind CSS v4)

**Chosen:** shadcn/ui.

shadcn/ui copies components into the project rather than importing them as a dependency. This means: no runtime dependency version conflicts, full ownership of component markup, and accessibility baked in via Radix UI primitives (WCAG 2.1 AA).

The policy editor needs: Select, Combobox (for resource autocomplete), MultiSelect (for actions), DateTimePicker (for timeWindow conditions), TagInput (for IP CIDRs, allowed extensions), DataTable (for allowedTables condition), Badge, Sheet (slide-in drawer for condition authoring), Dialog (delete confirm, template picker), Tabs, and Form validation states. shadcn/ui covers all of these.

**Tailwind CSS v4** is the styling foundation — utility-first, no runtime, pairs naturally with shadcn/ui.

---

### Decision 4: State Management — Zustand 5

**Chosen:** Zustand 5 for editor state.

The policy editor has enough state that React Context + `useReducer` gets verbose: current policy draft, per-field validation errors from the server, simulation results, dirty/clean state, and undo history. Zustand keeps this flat and typed without Redux boilerplate.

Undo/redo (Ctrl+Z during policy editing) uses the `zundo` middleware for Zustand — this adds temporal state slices with minimal overhead.

**Form state** stays in react-hook-form (controlled by `useForm` + `useFieldArray`). Zustand holds everything *outside* the form: server validation responses, simulation panel state, template selection.

---

### Decision 5: Form Validation — react-hook-form 7 + Zod 3

**Chosen:** react-hook-form 7 with Zod 3 for client-side schema validation.

The `RoleCapabilityPolicy` structure maps cleanly to a Zod schema:

```typescript
const ConstraintSchema = z.object({
  resource: z.string().min(1),
  actions: z.array(z.enum(["read","write","execute","delete","admin","*"])).min(1),
  argumentSchema: ArgumentSchemaZ.optional(),
  conditions: z.array(ConditionWrapperSchema).optional(),
});

const RoleCapabilityPolicySchema = z.object({
  role: z.string().regex(/^[a-zA-Z][a-zA-Z0-9_-]*$/),
  description: z.string().optional(),
  maxTtlSeconds: z.number().int().min(60).max(86400),
  capabilities: z.array(ConstraintSchema).min(1),
  allowedActions: z.array(z.string()).optional(),
  maxCalls: z.number().int().positive().optional(),
  conditions: z.array(ConditionWrapperSchema).optional(),
});
```

The Zod schema is the TypeScript source of truth for the frontend. It runs on every keystroke (debounced) for immediate field-level feedback, while the authoritative server-side validation runs on save and on explicit "validate" triggers.

The `ConditionWrapperSchema` uses Zod's `discriminatedUnion` on the `type` field — this mirrors the `ConditionWrapper` / `ConditionType()` discriminator pattern in `pkg/capability/condition.go`.

---

### Decision 6: Policy Validation API — New `POST /admin/role-policy/validate` Endpoint

**New endpoint added to the issuer.**

```
POST /admin/role-policy/validate
Authorization: Bearer <admin-key>

{
  "policy": { ...RoleCapabilityPolicy... },
  "simulate": {                    // optional
    "resource": "api://tools/read_file",
    "actions": ["read"],
    "arguments": { "path": "/internal/secrets" }
  }
}

→ 200 OK
{
  "valid": true | false,
  "errors": [
    { "field": "capabilities[0].actions", "message": "no intersection with role policy" }
  ],
  "simulation": {         // only if simulate block provided
    "decision": "DENY",
    "reason": "resource api://tools/read_file not covered by any capability in this policy",
    "matchedCapability": null
  }
}
```

This endpoint runs the Go validation logic (`IntersectCapabilities`, `ValidateSubset`, condition type checks) against a proposed policy *without persisting it*. The frontend calls this debounced (400 ms) on significant form changes.

This keeps the frontend's Zod schema as a fast first-pass check (field presence, type coercion) while the Go backend is authoritative for semantic correctness (glob intersection, subset constraints, condition compatibility).

---

### Decision 7: Embedding the UI in the Issuer Binary

The built React SPA is embedded into the issuer binary using Go's `//go:embed` directive:

```go
// internal/issuer/ui.go
//go:embed ui/dist
var uiFS embed.FS

// Registered in app.go router setup:
// r.Handle("/ui/*", http.StripPrefix("/ui", SPAHandler(uiFS)))
```

The SPA is served at `/ui/`. A `SPAHandler` wrapper intercepts 404s on the embedded FS and serves `index.html` instead — standard SPA fallback for client-side routing.

In dev mode (`EUNOX_UI_DEV=true`), the issuer proxies `/ui/*` requests to `http://localhost:5173` (the Vite dev server) instead of serving the embedded dist. This gives hot-module replacement during development without needing a separate CORS proxy.

**Why not a separate deployment:**  
Keeping the UI co-deployed with the issuer is strictly simpler for the self-hosted and `eunox dev` (T-06) use cases. A compliance officer accessing the policy editor should not need to deploy a separate frontend app. For T-18 (SaaS control plane), the UI becomes independently deployable — the architecture supports it because the UI only communicates with the issuer via its existing HTTP API.

---

### Decision 8: Policy Persistence in the Issuer

Currently, the issuer loads policies from a JSON file at startup and hot-reloads on change. API-created policies (`POST /admin/role-policy/{role}`) are in-memory only and lost on restart.

For T-16 to be useful, policies authored in the UI must survive restarts. Three options:

| Option | Notes |
|--------|-------|
| Write-back to the policy JSON file | Simple; consistent with existing hot-reload model; works for both self-hosted and `eunox dev` |
| Persist to Postgres (minter's `key_policies` table) | Correct long-term; the schema already exists; requires the issuer to connect to Postgres |
| Both (file for dev, Postgres for hosted) | Too much indirection for Phase 1 |

**Decision:** Write-back to the policy JSON file for Phase 1. When `POST /admin/role-policy/{role}` is called, the issuer updates its in-memory engine *and* rewrites the policy file atomically (write to `.tmp`, then `os.Rename`). The existing `Engine.StartHotReload()` poll loop detects the new mtime and confirms consistency.

For the Cloud Team tier (post T-18), Postgres persistence replaces the file write-back. The issuer's policy source is feature-flagged at startup: `EUNOX_POLICY_BACKEND=file|postgres`.

---

## Architecture

```
Browser
  └─ React SPA (served at /ui/*)
       ├─ Form-based policy editor
       ├─ Live preview panel (simulation)
       └─ Template picker

Issuer (internal/issuer, :3001)
  ├─ GET  /ui/*                              ← embedded SPA (embed.FS)
  ├─ GET  /admin/role-policy                 ← existing: list all policies
  ├─ GET  /admin/role-policy/{role}          ← NEW: fetch single policy
  ├─ POST /admin/role-policy/{role}          ← existing + write-back to file
  ├─ POST /admin/role-policy/validate        ← NEW: validate + simulate
  └─ DELETE /admin/role-policy/{role}        ← existing
```

All admin routes require the `Authorization: Bearer <admin-key>` header. The SPA stores the admin key in `sessionStorage` (cleared on browser close). There is no separate authentication system for Phase 1 — the policy editor inherits the issuer's existing admin auth.

---

## Task Breakdown

Tasks are ordered by dependency. Each task specifies the file(s) it touches, what "done" means, and the acceptance condition.

---

### Task 1 — Add `GET /admin/role-policy/{role}` endpoint

**File:** `internal/issuer/app.go`  
**Why now:** The SPA edit flow needs to load a single policy by role name. The current `GET /admin/role-policy` returns all policies but has no single-resource variant. Adding it is a one-day backend task with no frontend dependency, so it ships first and unblocks the edit form.

**What to build:**
- Handler `handleGetRolePolicy` that calls `app.policyEngine.GetPolicy(role)` and returns the `RoleCapabilityPolicy` as JSON.
- Returns 404 with `{"error": "no policy found for role"}` when the role does not exist (matches the `ErrPolicyNotFound` sentinel in `internal/issuer/policy/policy.go:22`).
- Route registration: `r.Get("/admin/role-policy/{role}", app.handleGetRolePolicy)` — add to the existing admin route block at `internal/issuer/app.go:144`.

**Acceptance:** `curl -H "Authorization: Bearer $ADMIN_KEY" http://localhost:3001/admin/role-policy/developer` returns the developer policy JSON. Non-existent role returns 404.

---

### Task 2 — Add `POST /admin/role-policy/validate` endpoint

**File:** `internal/issuer/app.go`, new handler file `internal/issuer/validate_handler.go`  
**Why now:** The live preview panel depends on this. The frontend's Zod schema catches structural errors; this endpoint catches semantic errors that require the Go engine (resource glob intersection, condition compatibility, subset invariants). It also powers the simulation result shown in the preview panel.

**What to build:**

`ValidateRequest` struct:
```go
type ValidateRequest struct {
    Policy   policy.RoleCapabilityPolicy `json:"policy"`
    Simulate *SimulateInput              `json:"simulate,omitempty"`
}

type SimulateInput struct {
    Resource  string                 `json:"resource"`
    Actions   []string               `json:"actions"`
    Arguments map[string]interface{} `json:"arguments,omitempty"`
}
```

`ValidateResponse` struct:
```go
type ValidateResponse struct {
    Valid      bool              `json:"valid"`
    Errors     []ValidationError `json:"errors"`
    Simulation *SimulationResult `json:"simulation,omitempty"`
}

type ValidationError struct {
    Field   string `json:"field"`   // JSON path, e.g. "capabilities[0].actions"
    Message string `json:"message"`
}

type SimulationResult struct {
    Decision          string  `json:"decision"` // "ALLOW" | "DENY"
    Reason            string  `json:"reason"`
    MatchedCapability *string `json:"matchedCapability,omitempty"` // resource string
}
```

Validation logic (in order):
1. Structural: role name non-empty, `maxTtlSeconds` ≥ 60, at least one capability.
2. Per-capability: resource non-empty, actions non-empty.
3. Condition type validity: each condition's `type` field must be a known discriminator (use the constants in `pkg/capability/condition.go`).
4. If `simulate` is provided: call `engine.IntersectCapabilities` with the simulate resource/actions against the submitted policy (not the stored one). Return the decision and the matched capability resource.

Route: `r.Post("/admin/role-policy/validate", app.handleValidatePolicy)` — add *before* `{role}` routes to avoid chi routing the literal string "validate" as a role name.

**Acceptance:** Posting a valid policy returns `{"valid": true, "errors": []}`. Posting a policy with an empty `capabilities` array returns `{"valid": false, "errors": [{"field": "capabilities", "message": "at least one capability required"}]}`.

---

### Task 3 — Write-back policy persistence

**File:** `internal/issuer/app.go` (handleSetRolePolicy handler), `internal/issuer/policy/policy.go`  
**Why now:** Without this, policies authored in the UI vanish on issuer restart. This is a correctness requirement before the UI ships.

**What to build:**
- Add `WriteToFile(filePath string) error` method on `policy.Engine`. It marshals the current in-memory policies to a `policy.File` struct and writes atomically: `os.WriteFile` to `filePath+".tmp"`, then `os.Rename`.
- Call `engine.WriteToFile` at the end of `handleSetRolePolicy` and `handleDeleteRolePolicy` (only if the engine was initialized with a file path).
- If `filePath` is empty (in-memory-only mode, e.g. tests), skip the write silently.
- The existing hot-reload poll loop in `StartHotReload` already detects mtime changes — no changes needed there.

**Failure mode:** If `WriteToFile` fails (disk full, permissions), the API returns 500 and does *not* update in-memory state (rollback). Log the error with the file path.

**Acceptance:** Create a policy via `POST /admin/role-policy/newrole`, restart the issuer, confirm the policy is present via `GET /admin/role-policy/newrole`.

---

### Task 4 — Embed and serve the UI from the issuer binary

**Files:** `internal/issuer/ui.go` (new), `internal/issuer/app.go`  
**Why now:** This is the integration point. All frontend tasks build to `internal/issuer/ui/dist/`. Without the embed+serve wiring, the frontend cannot be tested against the real API.

**What to build:**

```go
// internal/issuer/ui.go
package issuer

import (
    "embed"
    "io/fs"
    "net/http"
    "os"
)

//go:embed ui/dist
var uiFS embed.FS

func uiHandler() http.Handler {
    // In dev mode, proxy to Vite dev server
    if os.Getenv("EUNOX_UI_DEV") == "true" {
        return newDevProxy("http://localhost:5173")
    }
    sub, _ := fs.Sub(uiFS, "ui/dist")
    return spaFileServer(http.FS(sub))
}
```

`spaFileServer` wraps `http.FileServer` to serve `index.html` for any path that does not match a real file (client-side routing fallback).

Route registration in `app.go`: `r.Handle("/ui/*", http.StripPrefix("/ui", uiHandler()))`.

**Makefile target:**
```makefile
ui-build:
	cd internal/issuer/ui && npm ci && npm run build
```

The `go build` for the issuer should fail with a clear message if `ui/dist` does not exist, pointing to `make ui-build`. Use a build tag `//go:build !noembed` to allow building without the UI for CI environments that only run Go tests.

**Acceptance:** `make ui-build && go run ./cmd/issuer` → browser at `http://localhost:3001/ui/` loads the React app.

---

### Task 5 — Initialize the React SPA project

**Directory:** `internal/issuer/ui/`  
**Why now:** Establishes the build pipeline that all subsequent frontend tasks build on.

**What to build:**
- `npm create vite@latest . -- --template react-ts` inside `internal/issuer/ui/`
- Configure `vite.config.ts`:
  - `base: "/ui/"` — all asset paths are relative to the issuer's `/ui/` mount point
  - `build.outDir: "dist"`
  - `server.proxy: {"/admin": "http://localhost:3001", "/.well-known": "http://localhost:3001"}` — dev proxy for API calls
- Install base dependencies: `react-router-dom@7`, `zustand@5`, `react-hook-form@7`, `zod@3`, `@uiw/react-codemirror`, `@codemirror/lang-json`, `@codemirror/lang-yaml`
- Initialize shadcn/ui: `npx shadcn-ui@latest init` (Tailwind v4, CSS variables, `src/components/ui/` output)
- Add `internal/issuer/ui/dist/` to `.gitignore` (it's a build artifact, embedded at build time)
- Add `internal/issuer/ui/node_modules/` to `.gitignore`

**App shell layout:**
```
/ui/                          → redirect to /ui/policies
/ui/policies                  → roles list page
/ui/policies/new              → new role form
/ui/policies/:role            → edit role form
/ui/policies/:role/simulate   → simulation sandbox
```

**Acceptance:** `npm run dev` inside `internal/issuer/ui/` starts Vite at port 5173. `npm run build` produces `dist/index.html` and `dist/assets/*.js`.

---

### Task 6 — Roles list page

**Files:** `internal/issuer/ui/src/pages/PoliciesPage.tsx`  
**Why now:** This is the entry point UX. Every user lands here. It must load quickly and communicate what exists before they open any editor.

**What to build:**
- Fetch `GET /admin/role-policy` on mount.
- Render a card grid. Each card shows:
  - Role name (bold)
  - Description (truncated to 2 lines)
  - Capability count badge ("3 capabilities")
  - TTL badge ("max 1 hr")
  - "Edit" button → `/ui/policies/:role`
  - "Delete" icon → confirmation dialog
- "New role" button → `/ui/policies/new`
- Empty state: "No policies yet. Create your first role." with a template picker CTA.
- Loading state: skeleton cards.
- Error state: inline error with a retry button (do not throw to the router error boundary for a list fetch failure).

**Data shape returned by `GET /admin/role-policy`** (current, from `handleListRolePolicies`):
```json
{ "policies": [ { "role": "developer", "description": "...", ... } ] }
```

**Acceptance:** With the issuer running and `EUNOX_UI_DEV=true`, the list page shows the 5 roles from `infra/policies/role-policy.json` after a cold browser load. Deleting a role via the confirmation dialog removes it from the list without a full page reload.

---

### Task 7 — Role header form fields

**Files:** `internal/issuer/ui/src/components/PolicyEditor/RoleHeader.tsx`  
**Why now:** The simplest part of the form, and a good place to establish the react-hook-form + Zod integration pattern that all subsequent sections follow.

**What to build:**
- `role` field: text input, disabled when editing an existing role (role name is the PK; renaming requires delete + create). Pattern validation: `^[a-zA-Z][a-zA-Z0-9_-]*$`. Shows error inline.
- `description` field: textarea, optional.
- `maxTtlSeconds` field: number input with a human-readable hint that updates live. Input is in seconds; hint reads "= 15 minutes" or "= 4 hours". Max 86400 (24 hours). Min 60 (1 minute).
- Wire to react-hook-form's `useForm<RoleCapabilityPolicySchema>`.

**Acceptance:** Typing "90" in maxTtlSeconds shows "= 1 minute 30 seconds". Clearing the role name field and blurring shows an inline error "Role name is required".

---

### Task 8 — Capabilities builder (resource + actions)

**Files:** `internal/issuer/ui/src/components/PolicyEditor/CapabilitiesSection.tsx`  
**Why now:** This is the core of every policy. Getting the resource/action UX right is the highest-stakes interaction — it must be clear that resources are glob-matched URI strings, not literal paths.

**What to build:**
- `useFieldArray` for the `capabilities` array.
- Each capability row:
  - **Resource** text input with placeholder `"api://tools/**"`. Below the input: a one-line hint showing what the glob matches ("matches all paths starting with api://tools/"). Hint uses the `resourceCovers` glob logic re-implemented in TypeScript.
  - **Actions** multi-select using shadcn `ToggleGroup`: `read`, `write`, `execute`, `delete`, `admin`, `*` (wildcard). Selecting `*` deselects all others and shows a warning badge "grants all actions".
  - **Conditions** badge showing count of attached conditions; clicking opens the condition sheet (Task 9).
  - **ArgumentSchema** collapse toggle (Task 10).
  - Drag handle for reordering (optional — lower priority, add after core UX is working).
  - Delete row button.
- "Add capability" button appends a new empty row.
- Validation: each row gets the server validation errors for `capabilities[i].resource` and `capabilities[i].actions` wired inline.

**Resource autocomplete:** A datalist suggesting common prefixes (`api://`, `storage://`, `db://`, `file://`) as the user types. Not a forced enum — free-form text is the primary mode.

**Acceptance:** A user can add three capability rows with different resources and action sets, save the policy, reload the page, and see the same three rows. A resource of `api://tools/**` with actions `["read","execute"]` saves correctly and the `resourceCovers("api://tools/**", "api://tools/read_file")` hint shows "matches api://tools/..." below the field.

---

### Task 9 — Condition builder (all 11 condition types)

**Files:** `internal/issuer/ui/src/components/PolicyEditor/ConditionSheet.tsx`, `internal/issuer/ui/src/components/conditions/*.tsx`  
**Why now:** Conditions are where the policy surface gets complex. Each condition type has a completely different sub-form. The sheet pattern (slide-in drawer) lets the user focus on one condition at a time without losing the capability row context.

**Condition sub-forms to build (one component each):**

| Condition type | Fields | Notes |
|---|---|---|
| `timeWindow` | notBefore (datetime), notAfter (datetime) | ISO 8601; both optional but at least one required |
| `ipRange` | cidrs (tag input) | Validate each tag as a valid CIDR on add |
| `allowedOperations` | operations (tag input) | Free-form strings; hint shows example for DB ("SELECT", "INSERT") |
| `allowedExtensions` | extensions (tag input) | Dot prefix normalised (`.pdf` not `pdf`); maps to `AllowedExtensionsCondition` |
| `allowedTables` | tables (tag input), columns (per-table column list) | Column list is optional; add table → expand column config |
| `maxCalls` | count (number), windowSeconds (number + unit picker: seconds/minutes/hours) | Both required; min count 1 |
| `recipientDomain` | domains (tag input) | Validate domain format on add |
| `redactFields` | fields (tag input) | Field path strings; hint: "e.g. patient.ssn" for HIPAA |
| `allowedValues` | argument (text), values (tag input for scalars) | Argument is the key in the tool call's arguments map |
| `policy` | backend (text), config (CodeMirror JSON editor) | Advanced; show a warning "requires backend integration" |
| `custom` | name (text), config (CodeMirror JSON editor) | Show warning "implementation-specific" |

**Sheet UX flow:**
1. User clicks "Add condition" on a capability row.
2. Sheet opens with a condition type selector (dropdown of 11 types with human-readable labels and a one-line description for each).
3. After selecting a type, the matching sub-form renders below.
4. "Add" button appends the condition to the capability's `conditions` array and closes the sheet.
5. Existing conditions shown as removable badges on the capability row. Clicking a badge reopens the sheet in edit mode for that condition.

**Acceptance:** A user can add a `maxCalls` condition (count: 10, window: 5 minutes) to a capability, save, reload, and see "10 calls / 5 min" shown as a badge on the capability row. Clicking the badge reopens the sheet with the values pre-filled.

---

### Task 10 — ArgumentSchema editor

**Files:** `internal/issuer/ui/src/components/PolicyEditor/ArgumentSchemaEditor.tsx`  
**Why now:** `ArgumentSchema` is the most technically demanding part of the policy model — it's a JSON Schema subset with recursive `properties`. Most non-engineers will never need it; for those who do, the raw JSON editor is the escape hatch.

**Two modes (tab toggle on each capability row):**

**Guided mode (default):**
- Type selector: `string`, `number`, `boolean`, `object`, `array` (maps to `SchemaType`).
- For `object`: add/remove property rows. Each property has a name field + recursive type selector.
- `required` checkbox per property.
- `pattern` (for string) and min/max (for number/array) as optional fields.
- This covers the common case: validate a `path` argument is a string matching a regex, or validate a `tableName` is one of an enum.

**Raw mode (fallback):**
- CodeMirror 6 JSON editor with the `ArgumentSchema` JSON Schema wired for inline validation.
- The editor is pre-populated from the guided mode state when switching to raw.
- Switching back to guided mode attempts to parse the raw JSON; if the raw JSON has constructs the guided mode cannot represent, it stays in raw mode and shows a notice.

**Acceptance:** A user in guided mode can define a schema `{type: "object", properties: {path: {type: "string", pattern: "^/reports/.*"}}, required: ["path"]}`, switch to raw mode and see the corresponding JSON, edit it in raw mode, switch back to guided, and see the values reflected.

---

### Task 11 — Live preview panel

**Files:** `internal/issuer/ui/src/components/PolicyPreview/PreviewPanel.tsx`  
**Why now:** This is the primary mechanism by which a non-engineer understands what they are authoring. "What can an agent do under this policy?" must be answerable without leaving the editor.

**Two sections:**

**"What this agent can do" summary:**
- Renders each capability as a human-readable sentence. Example:
  - "Read and execute anything under `api://tools/**`"
  - "Read from `storage://sales-data/**`, limited to 10 calls per 5 minutes, only from IP ranges 10.0.0.0/8"
  - "Read from `api://crm/customers` (fields: ssn, dob will be redacted)"
- Regenerated locally whenever the form changes (no API call needed for this part — pure TypeScript rendering of the in-memory form state).
- Updates in real time as the user types.

**"Try a tool call" simulator:**
- Resource input, action selector, optional arguments (CodeMirror JSON editor, small).
- "Check" button calls `POST /admin/role-policy/validate` with `simulate: { resource, actions, arguments }` and the current policy draft (unsaved).
- Shows result:
  - ALLOW: green badge, "Matched capability: `api://tools/**` — read, execute"
  - DENY: red badge, reason string from the server
- The last simulate result persists while the user continues editing.

**Acceptance:** With an empty policy draft, "Try a tool call" for resource `api://tools/read_file` / action `read` shows DENY. After adding a capability `api://tools/**` with `["read","execute"]`, the same simulation shows ALLOW — without saving.

---

### Task 12 — Policy save, cancel, and delete flows

**Files:** `internal/issuer/ui/src/components/PolicyEditor/PolicyActions.tsx`  
**Why now:** Without save/delete, nothing authored in the editor persists.

**What to build:**

**Save button:**
- Calls `POST /admin/role-policy/validate` first (pre-save validation). If invalid, shows errors and does not proceed.
- Calls `POST /admin/role-policy/{role}` with the policy JSON.
- On success: shows toast "Policy saved", marks form as clean, updates the URL to `/ui/policies/:role` if creating a new role.
- On 409 conflict (role already exists, create flow): shows inline error "A role with this name already exists".

**Cancel button:**
- If form is dirty: shows a "Discard unsaved changes?" dialog.
- If clean: navigates back to the roles list.

**Delete button (edit flow only):**
- Opens a confirmation dialog: "Delete role {roleName}? This will immediately prevent any agents using this role from receiving capability tokens."
- On confirm: calls `DELETE /admin/role-policy/{role}`.
- On success: navigates to `/ui/policies`, shows toast "Role deleted".

**Unsaved changes guard:**
- React Router v7's `useBeforeUnload` + `useBlocker` hooks prompt the user if they navigate away with unsaved changes.

**Acceptance:** Creating a new role, saving, refreshing the page, and navigating back to that role shows the saved values. Attempting to navigate away with unsaved changes shows the discard dialog.

---

### Task 13 — Policy template library

**Files:** `internal/issuer/ui/src/data/templates.ts`, `internal/issuer/ui/src/components/TemplatePicker.tsx`  
**Why now:** The success metric is 50% of Cloud Team users authoring policies via UI. Templates are the mechanism that gets a non-engineer to "first policy saved" in under 5 minutes. Without them, the empty form is intimidating.

**Templates to ship (5):**

1. **SOC 2 Read-Only Auditor**  
   Access to audit logs and reports only. `read` on `storage://audit-logs/**` and `api://reports/**`. No write actions. TTL: 4 hours.

2. **HIPAA Clinical Agent**  
   EHR read, note write, lab retrieval. Includes `redactFields` conditions on `ssn`, `dob`, `mrn`. TTL: 30 minutes. Adds `maxCalls` guard (100 calls / hour).

3. **PCI-DSS Cardholder Data Reader**  
   Read-only on `api://payments/**` and `storage://card-data/**`. Includes `ipRange` condition (empty — user must fill in their IP ranges). TTL: 15 minutes. `redactFields` on `card_number`, `cvv`.

4. **LangGraph Agent (typical)**  
   `read` and `execute` on `api://tools/**`. `read` on `storage://workspace/**`, `write` on `storage://workspace/output/**`. TTL: 10 minutes. `maxCalls` (200 / hour).

5. **Developer Sandbox**  
   Broad access (`api://**`, `storage://**`) with a `timeWindow` condition (business hours only, Mon–Fri 09:00–18:00 local). TTL: 1 hour. Explicitly labeled "not for production."

**Template picker UX:**
- Shown on the "New role" page *before* the empty form.
- Cards with title, one-line description, and compliance badge (SOC 2 / HIPAA / PCI-DSS / None).
- "Start from template" pre-fills the form; user must still name the role.
- "Start from scratch" skips to the empty form.

**Acceptance:** Selecting the HIPAA template, naming the role `clinical-copilot`, and saving creates a policy with the `redactFields` conditions intact. The preview panel shows the redacted fields in the human-readable summary.

---

### Task 14 — Build pipeline and CI integration

**Files:** `Makefile`, `.github/workflows/ci.yml` (or equivalent), `internal/issuer/ui/.gitignore`  
**Why now:** Without this, the UI never ships in a binary that others can download.

**What to build:**

Makefile targets:
```makefile
.PHONY: ui-install ui-build ui-dev

ui-install:
	cd internal/issuer/ui && npm ci

ui-build: ui-install
	cd internal/issuer/ui && npm run build

ui-dev:
	EUNOX_UI_DEV=true go run ./cmd/issuer &
	cd internal/issuer/ui && npm run dev

build: ui-build
	go build ./...
```

Build tag in `internal/issuer/ui.go`:
```go
//go:build !noembed
```

A companion file `internal/issuer/ui_stub.go` with `//go:build noembed` provides a stub `uiHandler()` that returns a plain 404, allowing `go test ./...` (which does not run `make ui-build` first) to compile cleanly.

CI pipeline additions:
- Cache `internal/issuer/ui/node_modules` by `package-lock.json` hash.
- Run `npm run build` and `npm run typecheck` as a separate CI job.
- The Go build in CI uses `-tags noembed` for unit tests; the release build does not.

**Acceptance:** `make build` on a clean checkout (with node available) produces an issuer binary that serves the policy editor at `/ui/`. `go test -tags noembed ./...` passes without running the UI build.

---

## Success Metric

From the GTM plan: **50% of Cloud Team users author policies via the UI rather than raw YAML by month 7.**

Proxy metrics to track before month 7:
- Time from `/ui/` load to first policy saved, for new users (target: under 5 minutes with a template, under 15 minutes without).
- `POST /admin/role-policy/{role}` calls with `User-Agent: eunox-ui/*` vs. `curl`/other (requires a user-agent header from the frontend).
- Number of validate endpoint calls per policy saved (high ratio = user is iterating, which is healthy).
- Template usage rate (how many saved policies originated from a template).

---

## Open Questions

1. **Policy naming collision (create flow):** The issuer's `SetPolicy` is upsert — it does not reject a create if the role already exists. The UI adds a client-side "this role already exists" check, but this is a TOCTOU race. Should the API expose a strict `POST` (fail if exists) vs. `PUT` (upsert) distinction? Decision needed before Task 12 ships.

2. **Admin key UX:** Storing the admin key in `sessionStorage` is acceptable for Phase 1 (dev tool, not a consumer product). For the Cloud Team tier, the authentication model needs to be revisited — an admin key visible in the browser's devtools is not acceptable in a shared enterprise environment. This is a T-18 concern but should be flagged in the architecture review.

3. **Condition ordering:** `mergeConditions` in `internal/issuer/policy/policy.go:437` concatenates conditions from requested and policy. The UI renders conditions as an ordered list. Does condition order affect enforcement? If yes, the UI needs a drag-to-reorder UX on the conditions list. If no, this is just cosmetic.

4. **`eunox dev` integration (T-06):** The `eunox dev` single-binary should embed the policy editor by default. Confirm that `cmd/dev` (T-06) links against the issuer package and inherits the `/ui/*` route automatically, rather than needing a separate embed.
