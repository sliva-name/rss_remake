package retry_test

import (
	"context"
	"testing"
	"time"

	"dataguard/internal/platform/retry"
)

func TestDelayStaysWithinBounds(t *testing.T) {
	backoff := retry.Backoff{Base: 100 * time.Millisecond, Max: time.Second}
	for attempt := range 64 {
		delay := backoff.Delay(attempt)
		if delay <= 0 || delay > backoff.Max {
			t.Fatalf("attempt %d: delay %s out of bounds", attempt, delay)
		}
	}
}

func TestDelayGrows(t *testing.T) {
	backoff := retry.Backoff{Base: 100 * time.Millisecond, Max: time.Hour}
	if first, later := backoff.Delay(0), backoff.Delay(10); later <= first {
		t.Fatalf("delay did not grow: %s then %s", first, later)
	}
}

func TestSleepStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if retry.Sleep(ctx, time.Hour) {
		t.Fatal("Sleep must report false on a cancelled context")
	}
}
