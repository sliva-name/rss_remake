// Package background runs the server's periodic work: what no request starts,
// such as queueing scheduled scans (ADR-0016). Every instance runs every task.
// A task that changes shared state takes its rows with FOR UPDATE SKIP LOCKED,
// so two instances running it at once do no work twice.
package background

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Task is work the server repeats on its own.
type Task struct {
	// Name labels the task in logs and metrics: letters, digits and _.
	Name  string
	Every time.Duration
	Run   func(ctx context.Context) error
}

// Observer learns how each run ended.
type Observer interface {
	TaskRan(task string, err error)
}

// Run starts every task at once and then once per its period, until ctx ends.
// A failed run is logged and counted, and the next starts on time anyway. A run
// is cancelled when it outlasts its period, so a database that hangs does not
// pile up runs.
func Run(ctx context.Context, tasks []Task, observer Observer, logger *slog.Logger) {
	var running sync.WaitGroup
	for _, task := range tasks {
		running.Go(func() { repeat(ctx, task, observer, logger) })
	}
	running.Wait()
}

func repeat(ctx context.Context, task Task, observer Observer, logger *slog.Logger) {
	ticker := time.NewTicker(task.Every)
	defer ticker.Stop()
	for {
		runOnce(ctx, task, observer, logger)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func runOnce(ctx context.Context, task Task, observer Observer, logger *slog.Logger) {
	runContext, cancel := context.WithTimeout(ctx, task.Every)
	defer cancel()
	err := task.Run(runContext)
	if ctx.Err() != nil {
		// The server is stopping: a run cut short by that is not a failure.
		return
	}
	if err != nil {
		logger.Error("background task failed", "task", task.Name, "error", err)
	}
	observer.TaskRan(task.Name, err)
}
