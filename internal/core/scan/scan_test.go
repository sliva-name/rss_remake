package scan_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"dataguard/internal/core/oplog"
	"dataguard/internal/core/scan"
)

type fakeRepository struct {
	scan.Repository
	schedule scan.Schedule
	entry    oplog.Entry
	next     func(scan.Schedule) time.Time
}

func (r *fakeRepository) SetSchedule(_ context.Context, _, _ uuid.UUID, schedule scan.Schedule, entry oplog.Entry) error {
	r.schedule, r.entry = schedule, entry
	return nil
}

func (r *fakeRepository) EnqueueScheduled(_ context.Context, _ uuid.UUID, _ time.Time, _ int, next func(scan.Schedule) time.Time) (int, error) {
	r.next = next
	return 0, nil
}

func TestNextRunKeepsTheRhythm(t *testing.T) {
	anchor := time.Date(2026, 11, 13, 2, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	for _, test := range []struct {
		name string
		now  time.Time
		want time.Time
	}{
		{"anchor still ahead", anchor.Add(-time.Hour), anchor},
		{"exactly at the anchor", anchor, anchor.Add(day)},
		{"later the same day", anchor.Add(13 * time.Hour), anchor.Add(day)},
		{"a week of missed runs", anchor.Add(7*day + time.Minute), anchor.Add(8 * day)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := scan.NextRun(anchor, day, test.now); !got.Equal(test.want) {
				t.Fatalf("NextRun = %v, want %v", got, test.want)
			}
		})
	}
}

// "Every day at 02:00" is given as today at 02:00, whatever the time now: a
// first run in the past sets the rhythm and the next run is still ahead.
func TestScheduleFromAPastFirstRunStartsAhead(t *testing.T) {
	repository := &fakeRepository{}
	service := scan.NewService(repository, nil)
	firstRun := time.Now().Add(-30 * time.Hour).Truncate(time.Minute)
	schedule, err := service.SetSchedule(t.Context(), uuid.New(), uuid.New(), 24, firstRun)
	if err != nil {
		t.Fatal(err)
	}
	if !schedule.NextRun.After(time.Now()) || schedule.NextRun.After(time.Now().Add(24*time.Hour)) {
		t.Fatalf("next run %v is not within the next day", schedule.NextRun)
	}
	if offset := schedule.NextRun.Sub(firstRun) % (24 * time.Hour); offset != 0 {
		t.Fatalf("next run %v is off the rhythm of %v by %v", schedule.NextRun, firstRun, offset)
	}
	if repository.entry.Action != oplog.ScanScheduleUpdate || repository.entry.Details[oplog.DetailEveryHours] != "24" {
		t.Fatalf("journal entry = %+v", repository.entry)
	}
}

func TestScheduleOutsideItsBoundsIsRefused(t *testing.T) {
	service := scan.NewService(&fakeRepository{}, nil)
	now := time.Now()
	for _, test := range []struct {
		name       string
		everyHours int
		firstRun   time.Time
	}{
		{"never", 0, now},
		{"longer than a month", scan.MaxScheduleHours + 1, now},
		{"first run years ago", 24, now.AddDate(-2, 0, 0)},
		{"first run years ahead", 24, now.AddDate(2, 0, 0)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := service.SetSchedule(t.Context(), uuid.New(), uuid.New(), test.everyHours, test.firstRun); !errors.Is(err, scan.ErrInvalid) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

// After a run, or after the server was down for a while, the next run is the
// next one of the rhythm ahead, never a backlog of past ones.
func TestScheduledRunMovesToTheNextRunAhead(t *testing.T) {
	repository := &fakeRepository{}
	service := scan.NewService(repository, nil)
	if _, err := service.RunSchedules(t.Context(), uuid.New()); err != nil {
		t.Fatal(err)
	}
	due := scan.Schedule{EveryHours: 6, NextRun: time.Now().Add(-20 * time.Hour)}
	next := repository.next(due)
	if !next.After(time.Now()) || next.After(time.Now().Add(6*time.Hour)) {
		t.Fatalf("next run %v is not within the next 6 hours", next)
	}
}
