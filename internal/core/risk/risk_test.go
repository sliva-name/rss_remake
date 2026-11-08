package risk

import (
	"testing"
	"time"

	"dataguard/internal/core/audit"
)

func activity(database, category string, events, failed uint64) audit.Activity {
	return audit.Activity{DatabasePrincipal: database, IdentityConfidence: "IDENTITY_CONFIDENCE_DB_PRINCIPAL_ONLY", Category: category, Events: events, Failed: failed, LastEvent: time.Unix(1, 0)}
}

func kinds(signals []Signal) map[string]string {
	result := map[string]string{}
	for _, signal := range signals {
		result[signal.DatabasePrincipal+"/"+signal.Category] = signal.Kind
	}
	return result
}

func TestSpikeNeedsBothAFloorAndAMultipleOfTheUsualDay(t *testing.T) {
	recent := []audit.Activity{
		activity("spiky", "PERSONAL.EMAIL", 300, 0),
		activity("steady", "PERSONAL.EMAIL", 300, 0),
		activity("quiet", "PERSONAL.EMAIL", 40, 0),
	}
	// 700 over 7 days is 100 a day: 300 is three times that.
	week := []audit.Activity{activity("spiky", "PERSONAL.EMAIL", 700, 0), activity("steady", "PERSONAL.EMAIL", 1400, 0), activity("quiet", "PERSONAL.EMAIL", 7, 0)}
	month := week
	got := kinds(Signals(recent, week, month))
	if got["spiky/PERSONAL.EMAIL"] != VolumeSpike {
		t.Errorf("three times the usual day is a spike: %v", got)
	}
	if _, ok := got["steady/PERSONAL.EMAIL"]; ok {
		t.Errorf("one and a half times the usual day is not: %v", got)
	}
	if _, ok := got["quiet/PERSONAL.EMAIL"]; ok {
		t.Errorf("below the floor is not, whatever the multiple: %v", got)
	}
}

func TestNewCategoryIsOneNotReadInTheMonthBefore(t *testing.T) {
	recent := []audit.Activity{activity("analyst", "GOVERNMENT.PASSPORT", 2, 0), activity("analyst", "PERSONAL.EMAIL", 2, 0)}
	month := []audit.Activity{activity("analyst", "PERSONAL.EMAIL", 30, 0)}
	got := kinds(Signals(recent, nil, month))
	if got["analyst/GOVERNMENT.PASSPORT"] != NewCategory {
		t.Errorf("passport was not read before: %v", got)
	}
	if _, ok := got["analyst/PERSONAL.EMAIL"]; ok {
		t.Errorf("email was: %v", got)
	}
}

func TestFailuresCountOncePerPrincipalAndAgainstTheUsual(t *testing.T) {
	recent := []audit.Activity{activity("prober", "", 40, 25), activity("flaky", "", 40, 25), activity("prober", "PERSONAL.EMAIL", 40, 25)}
	week := []audit.Activity{activity("flaky", "", 700, 140)}
	got := kinds(Signals(recent, week, recent))
	if got["prober/"] != FailedAccess {
		t.Errorf("25 refusals with none before: %v", got)
	}
	if _, ok := got["flaky/"]; ok {
		t.Errorf("25 refusals against 20 a day is usual: %v", got)
	}
	if got["prober/PERSONAL.EMAIL"] == FailedAccess {
		t.Errorf("failures come from the total row only, or an event would count once per category: %v", got)
	}
}

func TestStrongestFirst(t *testing.T) {
	recent := []audit.Activity{activity("small", "PERSONAL.EMAIL", 60, 0), activity("large", "PERSONAL.EMAIL", 600, 0)}
	week := []audit.Activity{activity("small", "PERSONAL.EMAIL", 70, 0), activity("large", "PERSONAL.EMAIL", 70, 0)}
	signals := Signals(recent, week, week)
	if len(signals) != 2 || signals[0].DatabasePrincipal != "large" {
		t.Errorf("signals = %+v", signals)
	}
}
