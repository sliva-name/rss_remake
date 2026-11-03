package synthetic_test

import (
	"strings"
	"testing"

	"dataguard/internal/testkit/synthetic"
)

func TestGeneratorIsDeterministic(t *testing.T) {
	first, second := synthetic.New(7), synthetic.New(7)
	for range 100 {
		if a, b := first.INN12(), second.INN12(); a != b {
			t.Fatalf("seeded generators diverged: %s != %s", a, b)
		}
	}
}

func TestEmailsAreMarkedAndUseReservedDomain(t *testing.T) {
	email := synthetic.New(1).Email()
	if !strings.Contains(email, synthetic.CanaryMarker) || !strings.HasSuffix(email, ".invalid") {
		t.Fatalf("email %q must carry the canary marker and a reserved domain", email)
	}
}

func TestValueShapes(t *testing.T) {
	generator := synthetic.New(3)
	cases := map[string]struct {
		value  string
		length int
	}{
		"inn12": {generator.INN12(), 12},
		"inn10": {generator.INN10(), 10},
		"card":  {generator.PaymentCard(), 16},
		"snils": {generator.SNILS(), 14},
		"phone": {generator.PhoneRU(), 12},
	}
	for name, testCase := range cases {
		if len(testCase.value) != testCase.length {
			t.Errorf("%s: %q has length %d, want %d", name, testCase.value, len(testCase.value), testCase.length)
		}
	}
}
