package background_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"dataguard/internal/platform/safelog"
	"dataguard/internal/server/background"
)

type runs struct {
	mu      sync.Mutex
	outcome map[string][]error
}

func (r *runs) TaskRan(task string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.outcome[task] = append(r.outcome[task], err)
}

func (r *runs) of(task string) []error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]error(nil), r.outcome[task]...)
}

// A task runs at once and then on its period; one that fails keeps its
// schedule and does not stop the others.
func TestTasksRepeatAndSurviveFailures(t *testing.T) {
	observed := &runs{outcome: map[string][]error{}}
	failure := errors.New("database unavailable")
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		background.Run(ctx, []background.Task{
			{Name: "fine", Every: 10 * time.Millisecond, Run: func(context.Context) error { return nil }},
			{Name: "broken", Every: 10 * time.Millisecond, Run: func(context.Context) error { return failure }},
		}, observed, safelog.Discard())
	}()
	deadline := time.Now().Add(5 * time.Second)
	for len(observed.of("fine")) < 3 || len(observed.of("broken")) < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("runs: fine %d, broken %d", len(observed.of("fine")), len(observed.of("broken")))
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	for _, err := range observed.of("fine") {
		if err != nil {
			t.Fatalf("fine run failed: %v", err)
		}
	}
	for _, err := range observed.of("broken") {
		if !errors.Is(err, failure) {
			t.Fatalf("broken run reported %v", err)
		}
	}
}

// A run that hangs is cancelled at the end of its period instead of holding
// up the next.
func TestHungRunIsCancelledAfterItsPeriod(t *testing.T) {
	observed := &runs{outcome: map[string][]error{}}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		background.Run(ctx, []background.Task{{Name: "hung", Every: 20 * time.Millisecond, Run: func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		}}}, observed, safelog.Discard())
	}()
	deadline := time.Now().Add(5 * time.Second)
	for len(observed.of("hung")) < 2 {
		if time.Now().After(deadline) {
			t.Fatal("a hung run was not cancelled")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if err := observed.of("hung")[0]; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("hung run reported %v", err)
	}
}

// Stopping the server is not a failure of the run it interrupts.
func TestStopIsNotAFailure(t *testing.T) {
	observed := &runs{outcome: map[string][]error{}}
	ctx, cancel := context.WithCancel(t.Context())
	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		background.Run(ctx, []background.Task{{Name: "long", Every: time.Hour, Run: func(ctx context.Context) error {
			close(started)
			<-ctx.Done()
			return ctx.Err()
		}}}, observed, safelog.Discard())
	}()
	<-started
	cancel()
	<-done
	if got := observed.of("long"); len(got) != 0 {
		t.Fatalf("an interrupted run was reported: %v", got)
	}
}
