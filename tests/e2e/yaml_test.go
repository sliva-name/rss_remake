//go:build e2e

package e2e_test

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func encodeYAML(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := yaml.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
