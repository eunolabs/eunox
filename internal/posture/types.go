// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

// Package posture implements the posture emitter service for AI asset inventory
// reporting to cloud security platforms (CSPM).
package posture

import (
	"context"
	"encoding/json"
	"time"
)

// EventType represents the type of posture event.
type EventType string

const (
	// EventObserved indicates an agent was observed (issuance/renewal).
	EventObserved EventType = "observed"
	// EventRevoked indicates an agent credential was revoked.
	EventRevoked EventType = "revoked"
)

// AgentInventoryRecord represents a single AI agent in the asset inventory.
type AgentInventoryRecord struct {
	// AgentID uniquely identifies the agent instance.
	AgentID string `json:"agentId"`
	// OwningTeam identifies the team responsible for this agent.
	OwningTeam string `json:"owningTeam"`
	// CapabilityManifestHash is the SHA-256 of the canonical manifest.
	CapabilityManifestHash string `json:"capabilityManifestHash"`
	// Runtime identifies the runtime environment (e.g., "langchain-go/0.1").
	Runtime string `json:"runtime"`
	// Region identifies the deployment region.
	Region string `json:"region"`
	// Capabilities lists the granted capability constraints.
	Capabilities []string `json:"capabilities"`
	// FirstSeen is when the agent was first observed.
	FirstSeen time.Time `json:"firstSeen"`
	// LastSeen is when the agent was most recently observed.
	LastSeen time.Time `json:"lastSeen"`
	// RevokedAt is set when the agent's credentials are revoked.
	RevokedAt *time.Time `json:"revokedAt,omitempty"`
}

// QueuedEvent represents a posture event stored in the durable queue.
type QueuedEvent struct {
	// ID is the unique queue entry identifier.
	ID int64 `json:"id"`
	// Type is the event type (observed or revoked).
	Type EventType `json:"type"`
	// Payload is the JSON-encoded event data.
	Payload []byte `json:"payload"`
	// InsertedAt is when the event was enqueued (Unix milliseconds).
	InsertedAt int64 `json:"insertedAt"`
	// Attempts is the number of delivery attempts made.
	Attempts int `json:"attempts"`
	// NextAttemptAt is the earliest time for the next delivery attempt (Unix ms).
	NextAttemptAt int64 `json:"nextAttemptAt"`
	// LastError is the error message from the most recent failed attempt.
	LastError string `json:"lastError,omitempty"`
}

// Plugin is the interface that CSPM backend plugins must implement.
// Each plugin adapts AgentInventoryRecord into the platform-specific
// payload format and delivers it to the cloud security API.
type Plugin interface {
	// Name returns the plugin identifier (e.g., "defender", "security-hub", "scc").
	Name() string
	// EmitObserved delivers an observed agent record to the CSPM backend.
	EmitObserved(ctx context.Context, record *AgentInventoryRecord) error
	// EmitRevoked notifies the CSPM backend that an agent has been revoked.
	EmitRevoked(ctx context.Context, agentID string, revokedAt time.Time) error
}

// Queue is the interface for the durable event queue.
type Queue interface {
	// Push enqueues a new event. Returns the assigned event ID.
	Push(ctx context.Context, eventType EventType, payload []byte) (int64, error)
	// Peek returns up to limit events that are ready for delivery.
	Peek(ctx context.Context, limit int) ([]QueuedEvent, error)
	// Ack removes a successfully delivered event from the queue.
	Ack(ctx context.Context, id int64) error
	// Nack reschedules a failed event for later retry.
	Nack(ctx context.Context, id, nextAttemptAt int64, errMsg string) error
	// DeadLetter moves an event from the active queue to the dead-letter table.
	DeadLetter(ctx context.Context, event *QueuedEvent) error
	// ListDeadLetters returns up to limit dead-lettered events, ordered by dead-letter time.
	ListDeadLetters(ctx context.Context, limit int) ([]DeadLetteredEvent, error)
	// DeadLetterDepth returns the total number of dead-lettered events.
	DeadLetterDepth(ctx context.Context) (int64, error)
	// Depth returns the total number of events in the queue.
	Depth(ctx context.Context) (int64, error)
	// Close releases queue resources.
	Close() error
}

// DeadLetteredEvent represents an event that exhausted delivery retries.
type DeadLetteredEvent struct {
	// ID is the dead-letter table primary key.
	ID int64 `json:"id"`
	// OriginalID is the original queue entry identifier.
	OriginalID int64 `json:"originalId"`
	// Type is the event type (observed or revoked).
	Type EventType `json:"type"`
	// Payload is the JSON-encoded event data.
	Payload json.RawMessage `json:"payload"`
	// InsertedAt is when the event was originally enqueued (Unix milliseconds).
	InsertedAt int64 `json:"insertedAt"`
	// Attempts is the number of delivery attempts made.
	Attempts int `json:"attempts"`
	// LastError is the error message from the most recent failed attempt.
	LastError string `json:"lastError,omitempty"`
	// DeadLetteredAt is when the event was moved to the DLQ (Unix milliseconds).
	DeadLetteredAt int64 `json:"deadLetteredAt"`
}

// RecordStore manages the in-memory inventory of observed agents.
type RecordStore interface {
	// Upsert adds or updates a record. Returns true if the record should be emitted
	// (i.e., it's new or outside the deduplication window).
	Upsert(record *AgentInventoryRecord) bool
	// MarkRevoked marks an agent as revoked. Returns the record if found.
	MarkRevoked(agentID string, revokedAt time.Time) *AgentInventoryRecord
	// ListActive returns all non-revoked records.
	ListActive() []AgentInventoryRecord
	// Size returns the total number of tracked records.
	Size() int
}
