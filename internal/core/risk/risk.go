// Package risk turns access counts into heuristic signals: reasons for a person
// to look, never verdicts. Each signal carries its rule and the numbers it was
// computed from, so the reader can judge it.
package risk

import (
	"cmp"
	"slices"
	"time"

	"dataguard/internal/core/audit"
)

// Kinds of signals.
const (
	// VolumeSpike: a principal read a category far more in the last day than on
	// an average day of the week before.
	VolumeSpike = "VOLUME_SPIKE"
	// NewCategory: a principal read a category it had not read in the 30 days before.
	NewCategory = "NEW_CATEGORY"
	// FailedAccess: a principal had many refused statements, far more than usual.
	FailedAccess = "FAILED_ACCESS"
)

// Thresholds. A spike needs both a floor and a multiple of the usual daily
// count, so a quiet principal reading a few rows does not raise a signal.
const (
	MinSpike     = 50
	SpikeFactor  = 3
	MinFailed    = 10
	FailedFactor = 3
)

// Windows the signals compare: the last day against the week, or the month,
// before it.
const (
	Recent        = 24 * time.Hour
	SpikeBaseline = 7 * 24 * time.Hour
	NewBaseline   = 30 * 24 * time.Hour
)

type Signal struct {
	Kind                 string
	DatabasePrincipal    string
	ApplicationPrincipal string
	IdentityConfidence   string
	Category             string
	Observed             uint64
	// Baseline is the usual daily count for spikes and failures, and the count
	// in the 30 days before for a new category, which is zero by definition.
	Baseline float64
	LastSeen time.Time
}

type key struct {
	database, application, identity, category string
}

func keyOf(item *audit.Activity) key {
	return key{item.DatabasePrincipal, item.ApplicationPrincipal, item.IdentityConfidence, item.Category}
}

func index(items []audit.Activity) map[key]*audit.Activity {
	byKey := make(map[key]*audit.Activity, len(items))
	for i := range items {
		byKey[keyOf(&items[i])] = &items[i]
	}
	return byKey
}

// Signals compares the last day with the week and the month before it.
// Category rows feed spikes and new categories; the principal's total row
// (empty category) feeds failures.
func Signals(recent, week, month []audit.Activity) []Signal {
	weekly := index(week)
	monthly := index(month)
	days := SpikeBaseline.Hours() / 24
	var signals []Signal
	for i := range recent {
		item := &recent[i]
		k := keyOf(item)
		signal := Signal{
			DatabasePrincipal: item.DatabasePrincipal, ApplicationPrincipal: item.ApplicationPrincipal,
			IdentityConfidence: item.IdentityConfidence, Category: item.Category, LastSeen: item.LastEvent,
		}
		if item.Category == "" {
			var usual float64
			if before, ok := weekly[k]; ok {
				usual = float64(before.Failed) / days
			}
			if item.Failed >= MinFailed && float64(item.Failed) >= FailedFactor*usual {
				signal.Kind, signal.Observed, signal.Baseline = FailedAccess, item.Failed, usual
				signals = append(signals, signal)
			}
			continue
		}
		if before, ok := monthly[k]; !ok || before.Events == 0 {
			signal.Kind, signal.Observed, signal.Baseline = NewCategory, item.Events, 0
			signals = append(signals, signal)
			continue
		}
		var usual float64
		if before, ok := weekly[k]; ok {
			usual = float64(before.Events) / days
		}
		if item.Events >= MinSpike && float64(item.Events) >= SpikeFactor*usual {
			signal.Kind, signal.Observed, signal.Baseline = VolumeSpike, item.Events, usual
			signals = append(signals, signal)
		}
	}
	slices.SortFunc(signals, func(a, b Signal) int {
		return cmp.Or(
			cmp.Compare(strength(b), strength(a)),
			cmp.Compare(a.DatabasePrincipal, b.DatabasePrincipal),
			cmp.Compare(a.Category, b.Category),
		)
	})
	return signals
}

// strength orders signals by how far they are from the usual.
func strength(signal Signal) float64 {
	return float64(signal.Observed) / (signal.Baseline + 1)
}
