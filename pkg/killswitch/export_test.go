// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// export_test.go exposes internal helpers for black-box tests in package killswitch_test.
package killswitch

// HandleAgentEventForTest directly invokes handleAgentEvent on the named agent's
// partition, creating the partition if it does not yet exist. This allows tests
// to simulate per-agent pub/sub events without requiring an actual Redis round-trip.
func HandleAgentEventForTest(p *PartitionedKillSwitch, agentID, payload string) {
	p.mu.Lock()
	part, ok := p.partitions[agentID]
	if !ok {
		part = &agentPartition{}
		p.partitions[agentID] = part
	}
	p.mu.Unlock()
	p.handleAgentEvent(part, payload)
}

// SetPartitionDegraded sets the degraded flag on the named agent partition in p.
// It is used in tests to simulate a per-agent subscription failure without
// requiring an actual Redis connection interruption.
func SetPartitionDegraded(p *PartitionedKillSwitch, agentID string, degraded bool) {
	p.mu.Lock()
	part, ok := p.partitions[agentID]
	if !ok {
		part = &agentPartition{}
		p.partitions[agentID] = part
	}
	p.mu.Unlock()

	part.mu.Lock()
	part.degraded = degraded
	part.mu.Unlock()
}
