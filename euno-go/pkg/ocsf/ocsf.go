// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

// Package ocsf implements OCSF (Open Cybersecurity Schema Framework) v1.1 event types
// for audit logging. It provides Authorization events (class_uid 3003) and API Activity
// events (class_uid 6003) with SOC2 control mapping metadata.
package ocsf

import "time"

// SchemaVersion is the OCSF schema version implemented by this package.
const SchemaVersion = "1.1.0"

// ClassUID identifies the OCSF event class.
type ClassUID int

const (
	// ClassAuthorization represents authorization events (access grant/deny decisions).
	ClassAuthorization ClassUID = 3003
	// ClassAPIActivity represents API activity events (tool calls, validations).
	ClassAPIActivity ClassUID = 6003
)

// ActivityID identifies the specific activity within a class.
type ActivityID int

// Authorization activity IDs.
const (
	ActivityAuthGrant      ActivityID = 1
	ActivityAuthDeny       ActivityID = 2
	ActivityAuthRevoke     ActivityID = 3
	ActivityAuthAttenuate  ActivityID = 4
	ActivityAuthRenew      ActivityID = 5
	ActivityAuthOther      ActivityID = 99
)

// API Activity activity IDs.
const (
	ActivityAPICall     ActivityID = 1
	ActivityAPIAllow    ActivityID = 2
	ActivityAPIDeny     ActivityID = 3
	ActivityAPIValidate ActivityID = 4
	ActivityAPIOther    ActivityID = 99
)

// SeverityID classifies the event severity.
type SeverityID int

// Severity level constants.
const (
	SeverityUnknown       SeverityID = 0
	SeverityInformational SeverityID = 1
	SeverityLow           SeverityID = 2
	SeverityMedium        SeverityID = 3
	SeverityHigh          SeverityID = 4
	SeverityCritical      SeverityID = 5
	SeverityFatal         SeverityID = 6
)

// StatusID indicates outcome status.
type StatusID int

// Status outcome constants.
const (
	StatusUnknown StatusID = 0
	StatusSuccess StatusID = 1
	StatusFailure StatusID = 2
	StatusOther   StatusID = 99
)

// SOC2Control maps events to SOC2 Trust Services Criteria.
type SOC2Control struct {
	ControlID   string `json:"control_id"`
	Category    string `json:"category"`
	Description string `json:"description"`
}

// Predefined SOC2 control mappings.
var (
	// SOC2CC61 maps to CC6.1: Logical and Physical Access Controls (security software).
	SOC2CC61 = SOC2Control{
		ControlID:   "CC6.1",
		Category:    "Logical and Physical Access Controls",
		Description: "The entity implements logical access security software, infrastructure, and architectures over protected information assets.",
	}
	// SOC2CC62 maps to CC6.2: Logical and Physical Access Controls (user registration).
	SOC2CC62 = SOC2Control{
		ControlID:   "CC6.2",
		Category:    "Logical and Physical Access Controls",
		Description: "Prior to issuing system credentials and granting system access, the entity registers and authorizes new internal and external users.",
	}
	// SOC2CC63 maps to CC6.3: Logical and Physical Access Controls (access authorization).
	SOC2CC63 = SOC2Control{
		ControlID:   "CC6.3",
		Category:    "Logical and Physical Access Controls",
		Description: "The entity authorizes, modifies, or removes access to data, software, functions, and other protected information assets.",
	}
	// SOC2CC72 maps to CC7.2: System Operations (anomaly monitoring).
	SOC2CC72 = SOC2Control{
		ControlID:   "CC7.2",
		Category:    "System Operations",
		Description: "The entity monitors system components and the operation of those components for anomalies.",
	}
	// SOC2CC81 maps to CC8.1: Change Management.
	SOC2CC81 = SOC2Control{
		ControlID:   "CC8.1",
		Category:    "Change Management",
		Description: "The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes.",
	}
)

// BaseEvent contains the common fields shared by all OCSF events.
type BaseEvent struct {
	// Metadata
	ClassUID      ClassUID   `json:"class_uid"`
	ActivityID    ActivityID `json:"activity_id"`
	CategoryUID   int        `json:"category_uid"`
	TypeUID       int        `json:"type_uid"`
	SchemaVersion string     `json:"metadata.version"`
	Time          time.Time  `json:"time"`

	// Severity
	SeverityID SeverityID `json:"severity_id"`
	Severity   string     `json:"severity,omitempty"`

	// Status
	StatusID StatusID `json:"status_id"`
	Status   string   `json:"status,omitempty"`
	Message  string   `json:"message,omitempty"`

	// Observables
	Observables map[string]string `json:"observables,omitempty"`

	// SOC2 mapping
	SOC2Controls []SOC2Control `json:"unmapped.soc2_controls,omitempty"`
}

// Actor represents the entity performing the action.
type Actor struct {
	UserID    string `json:"user.uid,omitempty"`
	UserName  string `json:"user.name,omitempty"`
	TenantID  string `json:"user.org.uid,omitempty"`
	SessionID string `json:"session.uid,omitempty"`
	AgentID   string `json:"process.uid,omitempty"`
}

// Resource represents the target resource of the action.
type Resource struct {
	UID   string `json:"uid,omitempty"`
	Name  string `json:"name,omitempty"`
	Type  string `json:"type,omitempty"`
	Group string `json:"group,omitempty"`
}

// AuthorizationEvent represents an OCSF Authorization event (class_uid 3003).
// Used for: token issuance, denial, revocation, attenuation decisions.
type AuthorizationEvent struct {
	BaseEvent

	// Actor who triggered the authorization decision.
	Actor Actor `json:"actor"`

	// Resource being accessed.
	Resource Resource `json:"dst_endpoint,omitempty"`

	// Authorization-specific fields.
	Decision    string   `json:"disposition,omitempty"`
	Privileges  []string `json:"privileges,omitempty"`
	TokenID     string   `json:"unmapped.token_id,omitempty"`
	ParentToken string   `json:"unmapped.parent_token_id,omitempty"`
	OperatorID  string   `json:"unmapped.operator_id,omitempty"`

	// Cross-org annotation.
	CrossOrg   bool   `json:"unmapped.cross_org,omitempty"`
	PartnerDID string `json:"unmapped.partner_did,omitempty"`
}

// APIActivityEvent represents an OCSF API Activity event (class_uid 6003).
// Used for: tool call allow/deny, validation, detail logging.
type APIActivityEvent struct {
	BaseEvent

	// Actor who made the API call.
	Actor Actor `json:"actor"`

	// API details.
	APIOperation string `json:"api.operation,omitempty"`
	APIService   string `json:"api.service.name,omitempty"`
	APIVersion   string `json:"api.version,omitempty"`

	// HTTP details.
	HTTPMethod string `json:"http_request.http_method,omitempty"`
	HTTPURL    string `json:"http_request.url.path,omitempty"`
	HTTPStatus int    `json:"http_response.code,omitempty"`

	// Source/destination.
	SrcIP   string `json:"src_endpoint.ip,omitempty"`
	SrcPort int    `json:"src_endpoint.port,omitempty"`
	DstIP   string `json:"dst_endpoint.ip,omitempty"`
	DstPort int    `json:"dst_endpoint.port,omitempty"`

	// Tool-specific fields.
	ToolName   string `json:"unmapped.tool_name,omitempty"`
	ToolAction string `json:"unmapped.tool_action,omitempty"`
	SessionID  string `json:"unmapped.session_id,omitempty"`
	RequestID  string `json:"unmapped.request_id,omitempty"`

	// Duration.
	Duration int64 `json:"duration,omitempty"` // milliseconds
}

// NewAuthorizationEvent creates a new AuthorizationEvent with standard fields pre-populated.
func NewAuthorizationEvent(activityID ActivityID, actor Actor) *AuthorizationEvent {
	typeUID := int(ClassAuthorization)*100 + int(activityID)
	return &AuthorizationEvent{
		BaseEvent: BaseEvent{
			ClassUID:      ClassAuthorization,
			ActivityID:    activityID,
			CategoryUID:   3, // Identity & Access Management
			TypeUID:       typeUID,
			SchemaVersion: SchemaVersion,
			Time:          time.Now().UTC(),
			SeverityID:    SeverityInformational,
		},
		Actor: actor,
	}
}

// NewAPIActivityEvent creates a new APIActivityEvent with standard fields pre-populated.
func NewAPIActivityEvent(activityID ActivityID, actor Actor) *APIActivityEvent {
	typeUID := int(ClassAPIActivity)*100 + int(activityID)
	return &APIActivityEvent{
		BaseEvent: BaseEvent{
			ClassUID:      ClassAPIActivity,
			ActivityID:    activityID,
			CategoryUID:   6, // Application Activity
			TypeUID:       typeUID,
			SchemaVersion: SchemaVersion,
			Time:          time.Now().UTC(),
			SeverityID:    SeverityInformational,
		},
		Actor: actor,
	}
}

// WithStatus sets the status on a BaseEvent and returns it for chaining.
func (e *AuthorizationEvent) WithStatus(statusID StatusID, status string) *AuthorizationEvent {
	e.StatusID = statusID
	e.Status = status
	return e
}

// WithSeverity sets the severity on the event.
func (e *AuthorizationEvent) WithSeverity(severityID SeverityID, severity string) *AuthorizationEvent {
	e.SeverityID = severityID
	e.Severity = severity
	return e
}

// WithSOC2Controls sets the SOC2 control mappings.
func (e *AuthorizationEvent) WithSOC2Controls(controls ...SOC2Control) *AuthorizationEvent {
	e.SOC2Controls = controls
	return e
}

// WithStatus sets the status on an APIActivityEvent.
func (e *APIActivityEvent) WithStatus(statusID StatusID, status string) *APIActivityEvent {
	e.StatusID = statusID
	e.Status = status
	return e
}

// WithSeverity sets the severity on an APIActivityEvent.
func (e *APIActivityEvent) WithSeverity(severityID SeverityID, severity string) *APIActivityEvent {
	e.SeverityID = severityID
	e.Severity = severity
	return e
}

// WithSOC2Controls sets the SOC2 control mappings on an APIActivityEvent.
func (e *APIActivityEvent) WithSOC2Controls(controls ...SOC2Control) *APIActivityEvent {
	e.SOC2Controls = controls
	return e
}
