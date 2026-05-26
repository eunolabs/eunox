// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package posture

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

const (
	// DefaultMaxAttempts is the maximum number of delivery attempts before dead-lettering.
	DefaultMaxAttempts = 10
	// DefaultBackoffBase is the base duration for exponential backoff.
	DefaultBackoffBase = 1 * time.Second
	// DefaultBackoffMax is the maximum backoff duration.
	DefaultBackoffMax = 5 * time.Minute
	// DefaultBatchSize is the number of events fetched per delivery tick.
	DefaultBatchSize = 50
	// DefaultPollInterval is the interval between delivery ticks.
	DefaultPollInterval = 1 * time.Second
	// DefaultPluginTimeout is the per-plugin delivery timeout.
	DefaultPluginTimeout = 5 * time.Second
)

// DeliveryMetrics provides hooks for observing delivery outcomes.
type DeliveryMetrics interface {
	OnDelivered(eventType EventType, pluginName string)
	OnDeliveryError(eventType EventType, pluginName string)
	OnDeadLettered(eventType EventType)
}

// DeliveryWorkerConfig holds configuration for the delivery worker.
type DeliveryWorkerConfig struct {
	MaxAttempts   int
	BackoffBase   time.Duration
	BackoffMax    time.Duration
	BatchSize     int
	PollInterval  time.Duration
	PluginTimeout time.Duration
}

// DefaultDeliveryConfig returns the default delivery worker configuration.
func DefaultDeliveryConfig() DeliveryWorkerConfig {
	return DeliveryWorkerConfig{
		MaxAttempts:   DefaultMaxAttempts,
		BackoffBase:   DefaultBackoffBase,
		BackoffMax:    DefaultBackoffMax,
		BatchSize:     DefaultBatchSize,
		PollInterval:  DefaultPollInterval,
		PluginTimeout: DefaultPluginTimeout,
	}
}

// DeliveryWorker polls the durable queue and delivers events to plugins.
type DeliveryWorker struct {
	queue   Queue
	plugins []Plugin
	config  DeliveryWorkerConfig
	logger  *slog.Logger
	metrics DeliveryMetrics

	ctx    context.Context
	cancel context.CancelFunc
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewDeliveryWorker creates a new delivery worker.
func NewDeliveryWorker(queue Queue, plugins []Plugin, cfg DeliveryWorkerConfig, logger *slog.Logger, metrics DeliveryMetrics) *DeliveryWorker {
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = DefaultMaxAttempts
	}
	if cfg.BackoffBase <= 0 {
		cfg.BackoffBase = DefaultBackoffBase
	}
	if cfg.BackoffMax <= 0 {
		cfg.BackoffMax = DefaultBackoffMax
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = DefaultBatchSize
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = DefaultPollInterval
	}
	if cfg.PluginTimeout <= 0 {
		cfg.PluginTimeout = DefaultPluginTimeout
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &DeliveryWorker{
		queue:   queue,
		plugins: plugins,
		config:  cfg,
		logger:  logger,
		metrics: metrics,
		ctx:     ctx,
		cancel:  cancel,
		stopCh:  make(chan struct{}),
	}
}

// Start begins the delivery polling loop in a background goroutine.
func (w *DeliveryWorker) Start() {
	w.wg.Add(1)
	go w.pollLoop()
}

// Stop signals the worker to stop and waits for the current tick to complete.
func (w *DeliveryWorker) Stop() {
	close(w.stopCh)
	w.wg.Wait()
	w.cancel()
}

func (w *DeliveryWorker) pollLoop() {
	defer w.wg.Done()

	ticker := time.NewTicker(w.config.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-w.stopCh:
			// Perform one final drain before exiting.
			w.tick()
			return
		case <-ticker.C:
			w.tick()
		}
	}
}

func (w *DeliveryWorker) tick() {
	events, err := w.queue.Peek(w.ctx, w.config.BatchSize)
	if err != nil {
		if w.logger != nil {
			w.logger.Error("delivery worker: peek failed", slog.String("error", err.Error()))
		}
		return
	}

	for i := range events {
		w.deliverEvent(&events[i])
	}
}

func (w *DeliveryWorker) deliverEvent(event *QueuedEvent) {
	// Check if we've exceeded max attempts (dead-letter).
	if event.Attempts >= w.config.MaxAttempts {
		w.deadLetter(event)
		return
	}

	var deliveryErr error
	for _, plugin := range w.plugins {
		ctx, cancel := context.WithTimeout(w.ctx, w.config.PluginTimeout)
		err := w.deliverToPlugin(ctx, plugin, event)
		cancel()
		if err != nil {
			deliveryErr = err
			if w.metrics != nil {
				w.metrics.OnDeliveryError(event.Type, plugin.Name())
			}
			if w.logger != nil {
				w.logger.Warn("delivery failed",
					slog.String("plugin", plugin.Name()),
					slog.String("eventType", string(event.Type)),
					slog.Int64("eventID", event.ID),
					slog.String("error", err.Error()),
				)
			}
		} else if w.metrics != nil {
			w.metrics.OnDelivered(event.Type, plugin.Name())
		}
	}

	if deliveryErr != nil {
		// Nack with exponential backoff.
		nextAttempt := w.computeNextAttempt(event.Attempts)
		if err := w.queue.Nack(w.ctx, event.ID, nextAttempt, deliveryErr.Error()); err != nil && w.logger != nil {
			w.logger.Error("delivery worker: nack failed",
				slog.Int64("eventID", event.ID),
				slog.String("error", err.Error()),
			)
		}
	} else {
		// All plugins succeeded: ack.
		if err := w.queue.Ack(w.ctx, event.ID); err != nil && w.logger != nil {
			w.logger.Error("delivery worker: ack failed",
				slog.Int64("eventID", event.ID),
				slog.String("error", err.Error()),
			)
		}
	}
}

func (w *DeliveryWorker) deliverToPlugin(ctx context.Context, plugin Plugin, event *QueuedEvent) error {
	switch event.Type {
	case EventObserved:
		var record AgentInventoryRecord
		if err := json.Unmarshal(event.Payload, &record); err != nil {
			return fmt.Errorf("unmarshal observed record: %w", err)
		}
		return plugin.EmitObserved(ctx, &record)

	case EventRevoked:
		var revocation RevokedPayload
		if err := json.Unmarshal(event.Payload, &revocation); err != nil {
			return fmt.Errorf("unmarshal revoked payload: %w", err)
		}
		return plugin.EmitRevoked(ctx, revocation.AgentID, revocation.RevokedAt)

	default:
		return fmt.Errorf("unknown event type: %s", event.Type)
	}
}

func (w *DeliveryWorker) deadLetter(event *QueuedEvent) {
	if w.logger != nil {
		w.logger.Error("dead-lettered event",
			slog.Int64("eventID", event.ID),
			slog.String("eventType", string(event.Type)),
			slog.Int("attempts", event.Attempts),
			slog.String("lastError", event.LastError),
		)
	}
	if w.metrics != nil {
		w.metrics.OnDeadLettered(event.Type)
	}
	// Move to dead-letter table for operator inspection and replay.
	if err := w.queue.DeadLetter(w.ctx, event); err != nil && w.logger != nil {
		w.logger.Error("delivery worker: dead-letter failed",
			slog.Int64("eventID", event.ID),
			slog.String("error", err.Error()),
		)
	}
}

func (w *DeliveryWorker) computeNextAttempt(currentAttempts int) int64 {
	// Exponential backoff: base * 2^attempts, capped at max.
	backoff := w.config.BackoffBase * (1 << uint(currentAttempts))
	if backoff > w.config.BackoffMax {
		backoff = w.config.BackoffMax
	}
	return time.Now().Add(backoff).UnixMilli()
}

// RevokedPayload is the JSON payload for revocation events in the queue.
type RevokedPayload struct {
	AgentID   string    `json:"agentId"`
	RevokedAt time.Time `json:"revokedAt"`
}
