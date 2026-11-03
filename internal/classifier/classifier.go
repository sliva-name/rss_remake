// Package classifier decides what a column contains. It works as a stream:
// values are inspected one at a time and only counters survive, so there is no
// sample of data to protect. Detectors see bytes; they neither keep nor return
// them.
package classifier

import (
	"cmp"
	"regexp"
	"slices"
	"strings"

	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
)

// Category identifiers of the built-in catalog.
const (
	CategoryEmail       = "PERSONAL.EMAIL"
	CategoryPhone       = "PERSONAL.PHONE"
	CategoryPersonName  = "PERSONAL.NAME"
	CategoryBirthDate   = "PERSONAL.DATE_OF_BIRTH"
	CategoryAddress     = "PERSONAL.ADDRESS"
	CategoryTaxID       = "GOVERNMENT.TAX_ID"
	CategorySNILS       = "GOVERNMENT.SNILS"
	CategoryPassport    = "GOVERNMENT.PASSPORT"
	CategoryPaymentCard = "FINANCIAL.PAYMENT_CARD"
	CategoryBankAccount = "FINANCIAL.BANK_ACCOUNT"
	CategoryPassword    = "AUTHENTICATION.PASSWORD"
	CategorySecret      = "AUTHENTICATION.SECRET"
	CategoryMedical     = "MEDICAL.RECORD"
)

// Confidence model. The numbers are tuned against the corpus in corpus_test.go,
// which pins the resulting precision and recall.
const (
	reportThreshold      = 0.5
	minFormatRatio       = 0.6
	minChecksumRatio     = 0.85
	formatWeight         = 0.70
	checksumFormatWeight = 0.45
	checksumWeight       = 0.45
	nameBonus            = 0.25
	contextBonus         = 0.05
	metadataConfidence   = 0.6
	// A handful of values proves little, so small samples are discounted.
	fullEvidenceSamples = 20
	sparseSampleFactor  = 0.8
	maxConfidence       = 0.999
)

// ColumnContext is everything known about a column before reading it. Comment
// is used locally and is never sent to the center.
type ColumnContext struct {
	Schema     string
	Table      string
	Column     string
	NativeType string
	Comment    string
}

// Verdict is a detector's opinion on a single value.
type Verdict struct {
	Format bool
	// Checksum is meaningful only for detectors that declare HasChecksum.
	Checksum bool
}

// Detector recognizes one category from individual values.
type Detector interface {
	Category() string
	// NamePattern matches column names and comments suggesting this category.
	NamePattern() *regexp.Regexp
	// ContextPattern matches table names suggesting this category; it may be nil.
	ContextPattern() *regexp.Regexp
	HasChecksum() bool
	// RequiresContext forbids a verdict from values alone. Used where the format
	// is too generic, like ten digits for a passport.
	RequiresContext() bool
	// Inspect judges one value. hasContext lets a detector accept a weak format
	// only when the name already points at it.
	Inspect(value []byte, hasContext bool) Verdict
}

// MetadataRule classifies by name alone, for data whose format is unrecognizable.
type MetadataRule struct {
	Category string
	Pattern  *regexp.Regexp
}

// Engine holds the detectors for a scan. It is immutable and shared by workers.
type Engine struct {
	detectors []Detector
	metadata  []MetadataRule
}

// NewEngine builds an engine from built-in rules and tenant-defined detectors.
func NewEngine(custom Custom) *Engine {
	return &Engine{
		detectors: append(builtinDetectors(), custom.Detectors...),
		metadata:  append(builtinMetadataRules(), custom.Metadata...),
	}
}

// Column accumulates evidence for one column. It is not safe for concurrent use.
type Column struct {
	context ColumnContext
	tallies []*tally
	values  uint64
}

type tally struct {
	detector   Detector
	hasName    bool
	hasContext bool
	format     uint64
	checksum   uint64
}

// NewColumn starts collecting evidence. Detectors that require context and have
// none are dropped here, which also saves inspecting values for them.
func (e *Engine) NewColumn(context ColumnContext) *Column {
	column := &Column{context: context}
	for _, detector := range e.detectors {
		item := &tally{detector: detector, hasName: nameMatches(detector.NamePattern(), context)}
		item.hasContext = contextMatches(detector.ContextPattern(), context)
		if detector.RequiresContext() && !item.hasName && !item.hasContext {
			continue
		}
		column.tallies = append(column.tallies, item)
	}
	return column
}

func nameMatches(pattern *regexp.Regexp, context ColumnContext) bool {
	if pattern == nil {
		return false
	}
	return pattern.MatchString(strings.ToLower(context.Column)) || pattern.MatchString(strings.ToLower(context.Comment))
}

func contextMatches(pattern *regexp.Regexp, context ColumnContext) bool {
	return pattern != nil && pattern.MatchString(strings.ToLower(context.Table))
}

// Observe feeds one non-null value. The value is not retained.
func (c *Column) Observe(value []byte) {
	c.values++
	for _, item := range c.tallies {
		verdict := item.detector.Inspect(value, item.hasName || item.hasContext)
		if verdict.Format {
			item.format++
		}
		if verdict.Checksum {
			item.checksum++
		}
	}
}

// Finding is a classification with its explanation.
type Finding struct {
	Category   string
	Confidence float64
	Evidence   *agentv1.ClassificationEvidence
	Matched    uint64
}

// Findings returns categories above the report threshold, strongest first.
func (e *Engine) Findings(column *Column) []Finding {
	var findings []Finding
	for _, item := range column.tallies {
		if finding, ok := column.judge(item); ok {
			findings = append(findings, finding)
		}
	}
	if column.values == 0 {
		findings = append(findings, e.metadataFindings(column.context, findings)...)
	} else {
		findings = append(findings, e.metadataOnlyFindings(column, findings)...)
	}
	slices.SortFunc(findings, func(a, b Finding) int {
		return cmp.Or(cmp.Compare(b.Confidence, a.Confidence), cmp.Compare(a.Category, b.Category))
	})
	return findings
}

func (c *Column) judge(item *tally) (Finding, bool) {
	if c.values == 0 {
		return Finding{}, false
	}
	formatRatio := float64(item.format) / float64(c.values)
	if formatRatio < minFormatRatio {
		return Finding{}, false
	}
	var confidence float64
	evidence := &agentv1.ClassificationEvidence{
		NameMatch:        item.hasName,
		ContextMatch:     item.hasContext,
		TypeMatch:        true,
		FormatMatchRatio: formatRatio,
	}
	if item.detector.HasChecksum() {
		checksumRatio := float64(item.checksum) / float64(c.values)
		evidence.ChecksumValidRatio = &checksumRatio
		if checksumRatio < minChecksumRatio {
			return Finding{}, false
		}
		confidence = checksumFormatWeight*formatRatio + checksumWeight*checksumRatio
	} else {
		confidence = formatWeight * formatRatio
	}
	if item.hasName {
		confidence += nameBonus
	}
	if item.hasContext {
		confidence += contextBonus
	}
	if c.values < fullEvidenceSamples {
		confidence *= sparseSampleFactor
	}
	confidence = min(confidence, maxConfidence)
	if confidence < reportThreshold {
		return Finding{}, false
	}
	return Finding{Category: item.detector.Category(), Confidence: confidence, Evidence: evidence, Matched: item.format}, true
}

func (e *Engine) metadataFindings(context ColumnContext, existing []Finding) []Finding {
	var findings []Finding
	for _, item := range e.nameCandidates(context) {
		if !hasCategory(existing, item) {
			findings = append(findings, metadataFinding(item))
		}
	}
	return findings
}

// metadataOnlyFindings covers categories that have no value detector. Names of
// detector-backed categories do not count once values were read, because the
// values have already disagreed with the name.
func (e *Engine) metadataOnlyFindings(column *Column, existing []Finding) []Finding {
	var findings []Finding
	for _, rule := range e.metadata {
		if nameMatches(rule.Pattern, column.context) && !hasCategory(existing, rule.Category) {
			findings = append(findings, metadataFinding(rule.Category))
		}
	}
	return findings
}

func (e *Engine) nameCandidates(context ColumnContext) []string {
	var categories []string
	for _, detector := range e.detectors {
		if nameMatches(detector.NamePattern(), context) {
			categories = append(categories, detector.Category())
		}
	}
	for _, rule := range e.metadata {
		if nameMatches(rule.Pattern, context) {
			categories = append(categories, rule.Category)
		}
	}
	return categories
}

func hasCategory(findings []Finding, category string) bool {
	return slices.ContainsFunc(findings, func(f Finding) bool { return f.Category == category })
}

func metadataFinding(category string) Finding {
	return Finding{
		Category:   category,
		Confidence: metadataConfidence,
		Evidence:   &agentv1.ClassificationEvidence{NameMatch: true},
	}
}
