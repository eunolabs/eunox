// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

// export_test.go exposes internal helpers for black-box tests in package killswitch_test.
package killswitch

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
