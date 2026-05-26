// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

// Package testutil provides reusable test helpers for time, HTTP, and crypto.
package testutil

import (
	"sync"
	"time"
)

// Clock provides time-related operations that can be mocked in tests.
type Clock interface {
	Now() time.Time
	Since(t time.Time) time.Duration
	After(d time.Duration) <-chan time.Time
}

// RealClock implements Clock using the actual system time.
type RealClock struct{}

// FakeClock is a controllable clock for deterministic testing.
type FakeClock struct {
	mu      sync.Mutex
	now     time.Time
	waiters []*fakeClockWaiter
}

type fakeClockWaiter struct {
	deadline time.Time
	ch       chan time.Time
}

// NewFakeClock creates a FakeClock set to the given time.
func NewFakeClock(t time.Time) *FakeClock {
	return &FakeClock{now: t}
}

// Now returns the current fake time.
func (fc *FakeClock) Now() time.Time {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	return fc.now
}

// Since returns the time elapsed since t according to the fake clock.
func (fc *FakeClock) Since(t time.Time) time.Duration {
	return fc.Now().Sub(t)
}

// After returns a channel that receives when the fake clock reaches the deadline.
func (fc *FakeClock) After(d time.Duration) <-chan time.Time {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	ch := make(chan time.Time, 1)
	deadline := fc.now.Add(d)
	if !deadline.After(fc.now) {
		ch <- fc.now
		return ch
	}

	fc.waiters = append(fc.waiters, &fakeClockWaiter{deadline: deadline, ch: ch})
	return ch
}

// Advance moves the clock forward and triggers expired waiters.
func (fc *FakeClock) Advance(d time.Duration) {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	fc.now = fc.now.Add(d)
	fc.triggerExpiredWaitersLocked()
}

// Set sets the clock to the given time.
func (fc *FakeClock) Set(t time.Time) {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	fc.now = t
	fc.triggerExpiredWaitersLocked()
}

// Now returns the current system time.
func (fc *RealClock) Now() time.Time {
	return time.Now()
}

// Since returns the elapsed real time since t.
func (fc *RealClock) Since(t time.Time) time.Duration {
	return time.Since(t)
}

// After waits for the real clock duration to elapse.
func (fc *RealClock) After(d time.Duration) <-chan time.Time {
	return time.After(d)
}

func (fc *FakeClock) triggerExpiredWaitersLocked() {
	pending := fc.waiters[:0]
	for _, waiter := range fc.waiters {
		if waiter.deadline.After(fc.now) {
			pending = append(pending, waiter)
			continue
		}
		waiter.ch <- fc.now
	}
	fc.waiters = pending
}
