package classifier_test

import (
	"fmt"
	"strconv"
	"testing"

	"dataguard/internal/classifier"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
	"dataguard/internal/testkit/synthetic"
)

const sampleSize = 200

type corpusColumn struct {
	name     string
	context  classifier.ColumnContext
	generate func(*synthetic.Generator, int) string
	want     string // empty: the column must stay unclassified
}

func column(table, name string) classifier.ColumnContext {
	return classifier.ColumnContext{Table: table, Column: name, NativeType: "text"}
}

func noisy(generate func(*synthetic.Generator) string, everyNth int) func(*synthetic.Generator, int) string {
	return func(g *synthetic.Generator, i int) string {
		if i%everyNth == 0 {
			return "n/a"
		}
		return generate(g)
	}
}

func always(generate func(*synthetic.Generator) string) func(*synthetic.Generator, int) string {
	return func(g *synthetic.Generator, _ int) string { return generate(g) }
}

func corpus() []corpusColumn {
	digits := func(count int) func(*synthetic.Generator) string {
		return func(g *synthetic.Generator) string { return g.RandomDigits(count) }
	}
	return []corpusColumn{
		// Positive: values and name agree.
		{"named email", column("users", "email"), always((*synthetic.Generator).Email), classifier.CategoryEmail},
		{"named phone", column("users", "phone"), always((*synthetic.Generator).PhoneRU), classifier.CategoryPhone},
		{"named inn12", column("users", "inn"), always((*synthetic.Generator).INN12), classifier.CategoryTaxID},
		{"named inn10", column("orgs", "inn"), always((*synthetic.Generator).INN10), classifier.CategoryTaxID},
		{"named snils", column("users", "snils"), always((*synthetic.Generator).SNILS), classifier.CategorySNILS},
		{"named card", column("payments", "card_number"), always((*synthetic.Generator).PaymentCard), classifier.CategoryPaymentCard},
		{"named passport", column("users", "passport"), always((*synthetic.Generator).PassportRU), classifier.CategoryPassport},

		// Positive: the name says nothing, the values must be enough.
		{"anonymous email", column("t1", "c1"), always((*synthetic.Generator).Email), classifier.CategoryEmail},
		{"anonymous phone", column("t1", "c2"), always((*synthetic.Generator).PhoneRU), classifier.CategoryPhone},
		{"anonymous inn12", column("t1", "c3"), always((*synthetic.Generator).INN12), classifier.CategoryTaxID},
		{"anonymous snils", column("t1", "c4"), always((*synthetic.Generator).SNILS), classifier.CategorySNILS},
		{"anonymous card", column("t1", "c5"), always((*synthetic.Generator).PaymentCard), classifier.CategoryPaymentCard},

		// Positive: dirty data, and context carried by the table, not the column.
		{"dirty email", column("users", "contact"), noisy((*synthetic.Generator).Email, 5), classifier.CategoryEmail},
		{"passport by table", column("passport_documents", "number"), always((*synthetic.Generator).PassportRU), classifier.CategoryPassport},

		// Negative: digit strings of the right length without valid checksums. Some
		// values pass by chance, which is why the decision is made per column.
		{"random 12 digits", column("orders", "external_ref"), always(digits(12)), ""},
		{"random 10 digits", column("orders", "tracking"), always(digits(10)), ""},
		{"random 16 digits", column("orders", "barcode"), always(digits(16)), ""},
		{"random 11 digits", column("orders", "invoice"), always(digits(11)), ""},
		{"sequential ids", column("orders", "id"), func(_ *synthetic.Generator, i int) string { return strconv.Itoa(1_000_000_000 + i) }, ""},

		// Negative: passport-shaped numbers without any passport context.
		{"passport shape, no context", column("orders", "number"), always((*synthetic.Generator).PassportRU), ""},

		// Negative: the name suggests a category the values refute.
		{"misnamed phone", column("users", "phone_note"), func(_ *synthetic.Generator, i int) string { return fmt.Sprintf("call after %d pm", i%12) }, ""},
		{"status flags", column("users", "status"), func(_ *synthetic.Generator, i int) string { return []string{"active", "blocked"}[i%2] }, ""},
		{"product codes", column("items", "sku"), func(_ *synthetic.Generator, i int) string { return fmt.Sprintf("SKU-%05d", i) }, ""},
		{"uuids", column("items", "uid"), func(_ *synthetic.Generator, i int) string { return fmt.Sprintf("%08x-0000-4000-8000-%012x", i, i) }, ""},
	}
}

func classify(t *testing.T, engine *classifier.Engine, testCase corpusColumn, seed uint64) []classifier.Finding {
	t.Helper()
	generator := synthetic.New(seed)
	collector := engine.NewColumn(testCase.context)
	for i := range sampleSize {
		collector.Observe([]byte(testCase.generate(generator, i)))
	}
	return engine.Findings(collector)
}

// TestCorpusPrecisionAndRecall pins detection quality. It evaluates several
// seeds because a detector that passes on one lucky draw is not reliable.
func TestCorpusPrecisionAndRecall(t *testing.T) {
	const seeds = 25
	engine := classifier.NewEngine(classifier.Custom{})
	var truePositives, falsePositives, falseNegatives int

	for _, testCase := range corpus() {
		t.Run(testCase.name, func(t *testing.T) {
			for seed := range uint64(seeds) {
				findings := classify(t, engine, testCase, seed)
				truePositive := false
				for _, finding := range findings {
					if finding.Category == testCase.want {
						truePositive = true
						continue
					}
					falsePositives++
					t.Errorf("seed %d: unexpected %s (%.3f)", seed, finding.Category, finding.Confidence)
				}
				switch {
				case truePositive:
					truePositives++
				case testCase.want != "":
					falseNegatives++
					t.Errorf("seed %d: %s not detected", seed, testCase.want)
				}
			}
		})
	}

	precision := float64(truePositives) / float64(truePositives+falsePositives)
	recall := float64(truePositives) / float64(truePositives+falseNegatives)
	t.Logf("precision %.4f, recall %.4f on %d decisions", precision, recall, truePositives+falsePositives+falseNegatives)
	if precision < 1 || recall < 1 {
		t.Fatalf("precision %.4f, recall %.4f: the corpus must classify cleanly", precision, recall)
	}
}

func TestEvidenceExplainsDecision(t *testing.T) {
	engine := classifier.NewEngine(classifier.Custom{})
	findings := classify(t, engine, corpusColumn{
		context: column("users", "inn"), generate: always((*synthetic.Generator).INN12),
	}, 1)
	if len(findings) != 1 {
		t.Fatalf("findings = %+v", findings)
	}
	evidence := findings[0].Evidence
	if !evidence.GetNameMatch() || evidence.GetFormatMatchRatio() != 1 || evidence.ChecksumValidRatio == nil || *evidence.ChecksumValidRatio != 1 {
		t.Fatalf("evidence = %+v", evidence)
	}
	if findings[0].Confidence <= 0.9 || findings[0].Confidence >= 1 {
		t.Fatalf("confidence = %f", findings[0].Confidence)
	}
}

func TestSmallSampleLowersConfidence(t *testing.T) {
	engine := classifier.NewEngine(classifier.Custom{})
	collect := func(count int) float64 {
		generator := synthetic.New(1)
		collector := engine.NewColumn(column("t", "c"))
		for range count {
			collector.Observe([]byte(generator.Email()))
		}
		findings := engine.Findings(collector)
		if len(findings) == 0 {
			return 0
		}
		return findings[0].Confidence
	}
	if small, large := collect(3), collect(100); small >= large {
		t.Fatalf("small sample %f must be less confident than large %f", small, large)
	}
}

func TestEmptyColumnFallsBackToNames(t *testing.T) {
	engine := classifier.NewEngine(classifier.Custom{})
	findings := engine.Findings(engine.NewColumn(column("users", "email")))
	if len(findings) != 1 || findings[0].Category != classifier.CategoryEmail {
		t.Fatalf("findings = %+v", findings)
	}
	if findings[0].Evidence.GetFormatMatchRatio() != 0 || findings[0].Confidence >= 0.7 {
		t.Fatalf("metadata-only finding must be modest: %+v", findings[0])
	}
}

func TestMetadataRulesCoverUndetectableData(t *testing.T) {
	engine := classifier.NewEngine(classifier.Custom{})
	cases := map[string]string{
		"password_hash": classifier.CategoryPassword,
		"api_key":       classifier.CategorySecret,
		"first_name":    classifier.CategoryPersonName,
		"date_of_birth": classifier.CategoryBirthDate,
		"home_address":  classifier.CategoryAddress,
	}
	for name, want := range cases {
		collector := engine.NewColumn(column("users", name))
		collector.Observe([]byte("opaque value"))
		findings := engine.Findings(collector)
		if len(findings) != 1 || findings[0].Category != want {
			t.Errorf("%s: findings = %+v", name, findings)
		}
	}
}

func TestCommentContributesContext(t *testing.T) {
	engine := classifier.NewEngine(classifier.Custom{})
	context := column("t", "c")
	context.Comment = "Паспорт клиента"
	generator := synthetic.New(1)
	collector := engine.NewColumn(context)
	for range sampleSize {
		collector.Observe([]byte(generator.PassportRU()))
	}
	findings := engine.Findings(collector)
	if len(findings) != 1 || findings[0].Category != classifier.CategoryPassport {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestCustomDetector(t *testing.T) {
	compiled, err := classifier.CompileCustom([]*agentv1.CustomDetector{{
		CategoryId: "CUSTOM.EMPLOYEE_ID", ValuePattern: `^EMP-[0-9]{6}$`,
	}})
	if err != nil {
		t.Fatalf("CompileCustom: %v", err)
	}
	engine := classifier.NewEngine(compiled)
	collector := engine.NewColumn(column("staff", "code"))
	for i := range sampleSize {
		collector.Observe(fmt.Appendf(nil, "EMP-%06d", i))
	}
	findings := engine.Findings(collector)
	if len(findings) != 1 || findings[0].Category != "CUSTOM.EMPLOYEE_ID" {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestCustomDetectorMatchesByNameEvenWhenValuesWereRead(t *testing.T) {
	compiled, err := classifier.CompileCustom([]*agentv1.CustomDetector{{
		CategoryId: "CUSTOM.SALARY", NamePattern: `salary`,
	}})
	if err != nil {
		t.Fatalf("CompileCustom: %v", err)
	}
	engine := classifier.NewEngine(compiled)
	collector := engine.NewColumn(column("staff", "base_salary"))
	collector.Observe([]byte("100"))
	findings := engine.Findings(collector)
	if len(findings) != 1 || findings[0].Category != "CUSTOM.SALARY" {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestCustomDetectorRejectsBadPattern(t *testing.T) {
	_, err := classifier.CompileCustom([]*agentv1.CustomDetector{{CategoryId: "CUSTOM.X", ValuePattern: "("}})
	if err == nil {
		t.Fatal("expected an error")
	}
}

func BenchmarkObserve(b *testing.B) {
	engine := classifier.NewEngine(classifier.Custom{})
	collector := engine.NewColumn(column("users", "contact"))
	value := []byte("synthetic.value@example.invalid")
	b.ReportAllocs()
	for b.Loop() {
		collector.Observe(value)
	}
}
