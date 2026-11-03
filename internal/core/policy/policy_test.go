package policy

import (
	"errors"
	"strings"
	"testing"

	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
)

func TestDetectorLimits(t *testing.T) {
	valid := &agentv1.CustomDetector{CategoryId: "CUSTOM.CONTRACT", ValuePattern: `^C-\d{6}$`}
	tooMany := make([]*agentv1.CustomDetector, maxDetectors+1)
	for i := range tooMany {
		tooMany[i] = valid
	}
	cases := map[string][]*agentv1.CustomDetector{
		"too many detectors":     tooMany,
		"value pattern too long": {{CategoryId: "CUSTOM.CONTRACT", ValuePattern: strings.Repeat("a", maxPatternRunes+1)}},
		"name pattern too long":  {{CategoryId: "CUSTOM.CONTRACT", NamePattern: strings.Repeat("я", maxPatternRunes+1)}},
	}
	for name, detectors := range cases {
		if err := validateDetectors(detectors); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
	atLimit := []*agentv1.CustomDetector{{CategoryId: "CUSTOM.CONTRACT", NamePattern: strings.Repeat("я", maxPatternRunes)}}
	if err := validateDetectors(append(tooMany[:maxDetectors-1], atLimit...)); err != nil {
		t.Errorf("detectors at the limits rejected: %v", err)
	}
}
