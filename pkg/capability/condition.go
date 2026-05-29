// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package capability

// Condition type discriminator values.
const (
	ConditionTypeTimeWindow        = "timeWindow"
	ConditionTypeIPRange           = "ipRange"
	ConditionTypeAllowedOperations = "allowedOperations"
	ConditionTypeAllowedExtensions = "allowedExtensions"
	ConditionTypeAllowedTables     = "allowedTables"
	ConditionTypeMaxCalls          = "maxCalls"
	ConditionTypeRecipientDomain   = "recipientDomain"
	ConditionTypeRedactFields      = "redactFields"
	ConditionTypeAllowedValues     = "allowedValues"
	ConditionTypePolicy            = "policy"
	ConditionTypeCustom            = "custom"
)

// Condition is the interface for all capability conditions.
// All conditions have a Type() method returning the discriminator string.
type Condition interface {
	ConditionType() string
}

// TimeWindowCondition limits use to a not-before and not-after time window.
type TimeWindowCondition struct {
	NotBefore string `json:"notBefore,omitempty"`
	NotAfter  string `json:"notAfter,omitempty"`
}

// IPRangeCondition limits use to requests originating from the provided CIDRs.
type IPRangeCondition struct {
	CIDRs []string `json:"cidrs"`
}

// AllowedOperationsCondition limits use to the listed operations.
type AllowedOperationsCondition struct {
	Operations []string `json:"operations"`
}

// AllowedExtensionsCondition limits file access to the listed extensions.
type AllowedExtensionsCondition struct {
	Extensions []string `json:"extensions"`
}

// AllowedTablesCondition limits database access to the listed tables and columns.
type AllowedTablesCondition struct {
	Tables  []string            `json:"tables"`
	Columns map[string][]string `json:"columns,omitempty"`
}

// MaxCallsCondition limits the number of calls within a rolling window.
type MaxCallsCondition struct {
	Count         int `json:"count"`
	WindowSeconds int `json:"windowSeconds"`
}

// RecipientDomainCondition limits recipients to the listed email domains.
type RecipientDomainCondition struct {
	Domains []string `json:"domains"`
}

// RedactFieldsCondition requires the listed fields to be redacted.
type RedactFieldsCondition struct {
	Fields []string `json:"fields"`
}

// PolicyCondition delegates evaluation to a named policy backend.
type PolicyCondition struct {
	Backend string      `json:"backend"`
	Config  interface{} `json:"config,omitempty"`
	Input   interface{} `json:"input,omitempty"`
}

// CustomCondition carries an implementation-specific condition payload.
type CustomCondition struct {
	Name   string      `json:"name"`
	Config interface{} `json:"config"`
}

// AllowedValuesCondition limits a named argument to a fixed set of allowed values.
// The Argument field names the key in EnforceRequest.Arguments to check.
// Values contains the allowed scalar values (string, number, boolean, or null).
type AllowedValuesCondition struct {
	Argument string        `json:"argument"`
	Values   []interface{} `json:"values"`
}

// ConditionType returns the time window discriminator.
func (TimeWindowCondition) ConditionType() string { return ConditionTypeTimeWindow }

// ConditionType returns the IP range discriminator.
func (IPRangeCondition) ConditionType() string { return ConditionTypeIPRange }

// ConditionType returns the allowed operations discriminator.
func (AllowedOperationsCondition) ConditionType() string { return ConditionTypeAllowedOperations }

// ConditionType returns the allowed extensions discriminator.
func (AllowedExtensionsCondition) ConditionType() string { return ConditionTypeAllowedExtensions }

// ConditionType returns the allowed tables discriminator.
func (AllowedTablesCondition) ConditionType() string { return ConditionTypeAllowedTables }

// ConditionType returns the max calls discriminator.
func (MaxCallsCondition) ConditionType() string { return ConditionTypeMaxCalls }

// ConditionType returns the recipient domain discriminator.
func (RecipientDomainCondition) ConditionType() string { return ConditionTypeRecipientDomain }

// ConditionType returns the redact fields discriminator.
func (RedactFieldsCondition) ConditionType() string { return ConditionTypeRedactFields }

// ConditionType returns the policy discriminator.
func (PolicyCondition) ConditionType() string { return ConditionTypePolicy }

// ConditionType returns the custom discriminator.
func (CustomCondition) ConditionType() string { return ConditionTypeCustom }

// ConditionType returns the allowedValues discriminator.
func (AllowedValuesCondition) ConditionType() string { return ConditionTypeAllowedValues }

// MarshalJSON serializes TimeWindowCondition with its discriminator.
func (c TimeWindowCondition) MarshalJSON() ([]byte, error) { return marshalCondition(c) }

// MarshalJSON serializes IPRangeCondition with its discriminator.
func (c IPRangeCondition) MarshalJSON() ([]byte, error) { return marshalCondition(c) }

// MarshalJSON serializes AllowedOperationsCondition with its discriminator.
func (c AllowedOperationsCondition) MarshalJSON() ([]byte, error) { return marshalCondition(c) }

// MarshalJSON serializes AllowedExtensionsCondition with its discriminator.
func (c AllowedExtensionsCondition) MarshalJSON() ([]byte, error) { return marshalCondition(c) }

// MarshalJSON serializes AllowedTablesCondition with its discriminator.
func (c AllowedTablesCondition) MarshalJSON() ([]byte, error) { return marshalCondition(c) }

// MarshalJSON serializes MaxCallsCondition with its discriminator.
func (c MaxCallsCondition) MarshalJSON() ([]byte, error) { return marshalCondition(c) }

// MarshalJSON serializes RecipientDomainCondition with its discriminator.
func (c RecipientDomainCondition) MarshalJSON() ([]byte, error) { return marshalCondition(c) }

// MarshalJSON serializes RedactFieldsCondition with its discriminator.
func (c RedactFieldsCondition) MarshalJSON() ([]byte, error) { return marshalCondition(c) }

// MarshalJSON serializes PolicyCondition with its discriminator.
func (c PolicyCondition) MarshalJSON() ([]byte, error) { return marshalCondition(c) }

// MarshalJSON serializes CustomCondition with its discriminator.
func (c CustomCondition) MarshalJSON() ([]byte, error) { return marshalCondition(c) }

// MarshalJSON serializes AllowedValuesCondition with its discriminator.
func (c AllowedValuesCondition) MarshalJSON() ([]byte, error) { return marshalCondition(c) }
