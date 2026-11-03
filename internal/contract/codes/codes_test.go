package codes_test

import (
	"encoding/json"
	"os"
	"slices"
	"testing"

	"dataguard/internal/contract/codes"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
)

const failuresFile = "../../../web/dashboard/src/failures.json"

type explanation struct {
	Problem string `json:"problem"`
	Action  string `json:"action"`
}

func shown() []string {
	all := codes.All()
	for number, name := range agentv1.GapReason_name {
		if number != int32(agentv1.GapReason_GAP_REASON_UNSPECIFIED) {
			all = append(all, name)
		}
	}
	return all
}

func TestDashboardExplainsEveryCode(t *testing.T) {
	data, err := os.ReadFile(failuresFile)
	if err != nil {
		t.Fatal(err)
	}
	var failures map[string]explanation
	if err := json.Unmarshal(data, &failures); err != nil {
		t.Fatal(err)
	}
	all := shown()
	for _, code := range all {
		failure, ok := failures[code]
		if !ok {
			t.Errorf("%s: no explanation in %s", code, failuresFile)
			continue
		}
		if failure.Problem == "" || failure.Action == "" {
			t.Errorf("%s: says what happened and what to do, both are required", code)
		}
	}
	for code := range failures {
		if !slices.Contains(all, code) {
			t.Errorf("%s: explained but never produced", code)
		}
	}
}

func TestCodesAreUnique(t *testing.T) {
	all := shown()
	slices.Sort(all)
	if compacted := slices.Compact(slices.Clone(all)); len(compacted) != len(all) {
		t.Errorf("a code is declared twice: %v", all)
	}
}
