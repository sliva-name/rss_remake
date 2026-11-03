package classifier

import (
	"fmt"
	"regexp"

	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
)

// custom is a tenant-defined detector. Go regular expressions run in linear
// time, so a pattern from a policy cannot stall the scanner.
type custom struct {
	category string
	value    *regexp.Regexp
	name     *regexp.Regexp
}

func (c custom) Category() string             { return c.category }
func (c custom) NamePattern() *regexp.Regexp  { return c.name }
func (custom) ContextPattern() *regexp.Regexp { return nil }
func (custom) HasChecksum() bool              { return false }
func (c custom) RequiresContext() bool        { return c.value == nil }
func (c custom) Inspect(value []byte, _ bool) Verdict {
	return Verdict{Format: c.value.Match(value)}
}

// Custom is the compiled form of a tenant's policy.
type Custom struct {
	Detectors []Detector
	Metadata  []MetadataRule
}

// CompileCustom compiles policy detectors. The policy was validated when it was
// published, but it crossed a trust boundary, so errors are still handled. A
// definition without a value pattern can only ever match by name, which makes it
// a metadata rule.
func CompileCustom(definitions []*agentv1.CustomDetector) (Custom, error) {
	var compiled Custom
	for _, definition := range definitions {
		category := definition.GetCategoryId()
		value, err := optionalPattern(definition.GetValuePattern())
		if err != nil {
			return Custom{}, fmt.Errorf("value pattern of %s: %w", category, err)
		}
		name, err := optionalPattern(definition.GetNamePattern())
		if err != nil {
			return Custom{}, fmt.Errorf("name pattern of %s: %w", category, err)
		}
		if value == nil {
			compiled.Metadata = append(compiled.Metadata, MetadataRule{Category: category, Pattern: name})
			continue
		}
		compiled.Detectors = append(compiled.Detectors, custom{category: category, value: value, name: name})
	}
	return compiled, nil
}

func optionalPattern(pattern string) (*regexp.Regexp, error) {
	if pattern == "" {
		return nil, nil
	}
	return regexp.Compile(pattern)
}
