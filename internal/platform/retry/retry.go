// Package retry computes bounded exponential backoff with jitter.
package retry

import (
	"context"
	"math/rand/v2"
	"time"
)

// Backoff grows from Base to Max. Jitter keeps a fleet of agents from
// reconnecting in lockstep after the center comes back.
type Backoff struct {
	Base time.Duration
	Max  time.Duration
}

// Delay returns the wait before the attempt-th retry, counting from zero.
func (b Backoff) Delay(attempt int) time.Duration {
	delay := b.Base
	for range attempt {
		if delay >= b.Max/2 {
			delay = b.Max
			break
		}
		delay *= 2
	}
	half := delay / 2
	//nolint:gosec // Jitter has no security role.
	return half + rand.N(half+1)
}

// Sleep waits for d and reports false if ctx ended first.
func Sleep(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
