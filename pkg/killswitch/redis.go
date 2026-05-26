// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package killswitch

import (
	"context"
	"sync"

	"github.com/redis/go-redis/v9"
)

const (
	redisGlobalKey   = "killswitch:global"
	redisAgentPrefix = "killswitch:agent:"
	redisSessionPfx  = "killswitch:session:"
	redisPubSubChan  = "killswitch:events"
)

// Redis is a Redis-backed kill-switch manager with pub/sub propagation and local cache.
type Redis struct {
	client redis.Cmdable

	// Local cache for fast reads (refreshed via pub/sub).
	mu             sync.RWMutex
	globalActive   bool
	killedAgents   map[string]bool
	killedSessions map[string]bool

	lifecycleCtx context.Context
	cancel       context.CancelFunc
}

// NewRedis creates a Redis-backed kill-switch manager.
// It subscribes to a pub/sub channel for real-time state propagation.
func NewRedis(client redis.Cmdable) *Redis {
	r := &Redis{
		client:         client,
		killedAgents:   make(map[string]bool),
		killedSessions: make(map[string]bool),
	}
	return r
}

// Start begins the pub/sub subscription for state synchronization.
// It should be called once during application startup.
func (r *Redis) Start(ctx context.Context) {
	subCtx, cancel := context.WithCancel(ctx)
	r.lifecycleCtx = subCtx
	r.cancel = cancel

	// Load initial state
	_ = r.refreshState(subCtx)

	// Subscribe in background
	if sub, ok := r.client.(interface {
		Subscribe(ctx context.Context, channels ...string) *redis.PubSub
	}); ok {
		pubsub := sub.Subscribe(subCtx, redisPubSubChan)
		go r.listenPubSub(subCtx, pubsub)
	}
}

// Stop cancels the pub/sub subscription.
func (r *Redis) Stop() {
	if r.cancel != nil {
		r.cancel()
	}
}

// ShouldBlock checks if any kill switch is active, using local cache first.
func (r *Redis) ShouldBlock(_ context.Context, agentID, sessionID string) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.globalActive {
		return true, nil
	}
	if agentID != "" && r.killedAgents[agentID] {
		return true, nil
	}
	if sessionID != "" && r.killedSessions[sessionID] {
		return true, nil
	}
	return false, nil
}

// ActivateGlobal activates the global kill switch.
func (r *Redis) ActivateGlobal(ctx context.Context) error {
	if err := r.client.Set(ctx, redisGlobalKey, "1", 0).Err(); err != nil {
		return err
	}
	r.publish(ctx, "global:activate")
	r.mu.Lock()
	r.globalActive = true
	r.mu.Unlock()
	return nil
}

// DeactivateGlobal deactivates the global kill switch.
func (r *Redis) DeactivateGlobal(ctx context.Context) error {
	if err := r.client.Del(ctx, redisGlobalKey).Err(); err != nil {
		return err
	}
	r.publish(ctx, "global:deactivate")
	r.mu.Lock()
	r.globalActive = false
	r.mu.Unlock()
	return nil
}

// KillAgent blocks the specified agent.
func (r *Redis) KillAgent(ctx context.Context, agentID string) error {
	if err := r.client.Set(ctx, redisAgentPrefix+agentID, "1", 0).Err(); err != nil {
		return err
	}
	r.publish(ctx, "agent:kill:"+agentID)
	r.mu.Lock()
	r.killedAgents[agentID] = true
	r.mu.Unlock()
	return nil
}

// ReviveAgent removes the kill on the specified agent.
func (r *Redis) ReviveAgent(ctx context.Context, agentID string) error {
	if err := r.client.Del(ctx, redisAgentPrefix+agentID).Err(); err != nil {
		return err
	}
	r.publish(ctx, "agent:revive:"+agentID)
	r.mu.Lock()
	delete(r.killedAgents, agentID)
	r.mu.Unlock()
	return nil
}

// KillSession blocks the specified session.
func (r *Redis) KillSession(ctx context.Context, sessionID string) error {
	if err := r.client.Set(ctx, redisSessionPfx+sessionID, "1", 0).Err(); err != nil {
		return err
	}
	r.publish(ctx, "session:kill:"+sessionID)
	r.mu.Lock()
	r.killedSessions[sessionID] = true
	r.mu.Unlock()
	return nil
}

// ReviveSession removes the kill on the specified session.
func (r *Redis) ReviveSession(ctx context.Context, sessionID string) error {
	if err := r.client.Del(ctx, redisSessionPfx+sessionID).Err(); err != nil {
		return err
	}
	r.publish(ctx, "session:revive:"+sessionID)
	r.mu.Lock()
	delete(r.killedSessions, sessionID)
	r.mu.Unlock()
	return nil
}

// Reset clears all kill-switch state.
func (r *Redis) Reset(ctx context.Context) error {
	// Delete global key
	_ = r.client.Del(ctx, redisGlobalKey).Err()

	// Scan and delete agent/session keys
	r.deleteByPrefix(ctx, redisAgentPrefix)
	r.deleteByPrefix(ctx, redisSessionPfx)

	r.publish(ctx, "reset")

	r.mu.Lock()
	r.globalActive = false
	r.killedAgents = make(map[string]bool)
	r.killedSessions = make(map[string]bool)
	r.mu.Unlock()
	return nil
}

// Status returns the current kill-switch state.
func (r *Redis) Status(_ context.Context) (*Status, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	agents := make([]string, 0, len(r.killedAgents))
	for id := range r.killedAgents {
		agents = append(agents, id)
	}

	sessions := make([]string, 0, len(r.killedSessions))
	for id := range r.killedSessions {
		sessions = append(sessions, id)
	}

	return &Status{
		GlobalActive:   r.globalActive,
		KilledAgents:   agents,
		KilledSessions: sessions,
	}, nil
}

func (r *Redis) publish(ctx context.Context, msg string) {
	if pub, ok := r.client.(interface {
		Publish(ctx context.Context, channel string, message interface{}) *redis.IntCmd
	}); ok {
		_ = pub.Publish(ctx, redisPubSubChan, msg).Err()
	}
}

func (r *Redis) refreshState(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check global
	val, err := r.client.Get(ctx, redisGlobalKey).Result()
	if err == nil && val == "1" {
		r.globalActive = true
	} else {
		r.globalActive = false
	}

	// Scan agents
	r.killedAgents = make(map[string]bool)
	r.scanPrefix(ctx, redisAgentPrefix, r.killedAgents)

	// Scan sessions
	r.killedSessions = make(map[string]bool)
	r.scanPrefix(ctx, redisSessionPfx, r.killedSessions)

	return nil
}

func (r *Redis) scanPrefix(ctx context.Context, prefix string, target map[string]bool) {
	if scanner, ok := r.client.(interface {
		Scan(ctx context.Context, cursor uint64, match string, count int64) *redis.ScanCmd
	}); ok {
		var cursor uint64
		for {
			keys, next, err := scanner.Scan(ctx, cursor, prefix+"*", 100).Result()
			if err != nil {
				break
			}
			for _, key := range keys {
				id := key[len(prefix):]
				target[id] = true
			}
			cursor = next
			if cursor == 0 {
				break
			}
		}
	}
}

func (r *Redis) deleteByPrefix(ctx context.Context, prefix string) {
	if scanner, ok := r.client.(interface {
		Scan(ctx context.Context, cursor uint64, match string, count int64) *redis.ScanCmd
	}); ok {
		var cursor uint64
		for {
			keys, next, err := scanner.Scan(ctx, cursor, prefix+"*", 100).Result()
			if err != nil {
				break
			}
			if len(keys) > 0 {
				_ = r.client.Del(ctx, keys...).Err()
			}
			cursor = next
			if cursor == 0 {
				break
			}
		}
	}
}

func (r *Redis) listenPubSub(ctx context.Context, pubsub *redis.PubSub) {
	defer func() { _ = pubsub.Close() }()
	ch := pubsub.Channel()
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			r.handlePubSubMessage(msg.Payload)
		}
	}
}

// handlePubSubMessage processes a kill-switch event and updates local cache immediately.
// Message format: "global:activate", "global:deactivate", "agent:kill:<id>",
// "agent:revive:<id>", "session:kill:<id>", "session:revive:<id>", "reset".
func (r *Redis) handlePubSubMessage(payload string) {
	r.mu.Lock()
	shouldRefresh := false

	switch {
	case payload == "global:activate":
		r.globalActive = true
	case payload == "global:deactivate":
		r.globalActive = false
	case payload == "reset":
		r.globalActive = false
		r.killedAgents = make(map[string]bool)
		r.killedSessions = make(map[string]bool)
	case len(payload) > len("agent:kill:") && payload[:len("agent:kill:")] == "agent:kill:":
		r.killedAgents[payload[len("agent:kill:"):]] = true
	case len(payload) > len("agent:revive:") && payload[:len("agent:revive:")] == "agent:revive:":
		delete(r.killedAgents, payload[len("agent:revive:"):])
	case len(payload) > len("session:kill:") && payload[:len("session:kill:")] == "session:kill:":
		r.killedSessions[payload[len("session:kill:"):]] = true
	case len(payload) > len("session:revive:") && payload[:len("session:revive:")] == "session:revive:":
		delete(r.killedSessions, payload[len("session:revive:"):])
	default:
		// Unknown message — trigger a full refresh from Redis.
		shouldRefresh = true
	}
	r.mu.Unlock()

	if shouldRefresh && r.client != nil {
		ctx := r.lifecycleCtx
		if ctx == nil {
			ctx = context.Background()
		}
		_ = r.refreshState(ctx)
	}
}
