// Package metrics exposes Prometheus metrics whose label values come only from
// closed sets: enumerations, codes, identifiers and route templates. A metric
// endpoint is read by people and systems outside the trust of the data, so a
// label must never carry a value, an object name or an error text. A label value
// that does not fit its kind is replaced by "INVALID" and counted, the way the
// egress guard blocks instead of rewriting.
package metrics

import (
	"net/http"
	"regexp"
	"slices"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Invalid replaces a label value that does not fit its kind.
const Invalid = "INVALID"

var (
	codePattern  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)
	uuidPattern  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	routePattern = regexp.MustCompile(`^([A-Z]+ )?/[A-Za-z0-9_./{}-]{0,127}$`)
)

// Label declares a label and the only values it may take.
type Label struct {
	Name  string
	valid func(string) bool
}

// Enum allows exactly the listed values.
func Enum(name string, values ...string) Label {
	return Label{Name: name, valid: func(value string) bool { return slices.Contains(values, value) }}
}

// Code allows identifiers such as TARGET_NOT_ALLOWED or unavailable.
func Code(name string) Label {
	return Label{Name: name, valid: codePattern.MatchString}
}

// UUID allows a lowercase UUID.
func UUID(name string) Label {
	return Label{Name: name, valid: uuidPattern.MatchString}
}

// Route allows a route template such as "GET /api/v1/sources/{id}".
func Route(name string) Label {
	return Label{Name: name, valid: routePattern.MatchString}
}

// Registry holds the metrics of one process.
type Registry struct {
	registry *prometheus.Registry
	prefix   string
	invalid  *prometheus.CounterVec
}

// New creates a registry with Go runtime and process metrics. Every metric name
// starts with prefix.
func New(prefix string) *Registry {
	registry := prometheus.NewRegistry()
	registry.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	invalid := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: prefix + "_metric_label_rejections_total",
		Help: "Label values replaced because they did not fit their kind.",
	}, []string{"metric"})
	registry.MustRegister(invalid)
	return &Registry{registry: registry, prefix: prefix, invalid: invalid}
}

// Handler serves the registry in the Prometheus text format.
func (r *Registry) Handler() http.Handler {
	return promhttp.HandlerFor(r.registry, promhttp.HandlerOpts{ErrorHandling: promhttp.ContinueOnError})
}

// Gather returns the current samples, for tests.
func (r *Registry) Gather() (map[string]float64, error) {
	families, err := r.registry.Gather()
	if err != nil {
		return nil, err
	}
	samples := map[string]float64{}
	for _, family := range families {
		for _, metric := range family.GetMetric() {
			key := family.GetName()
			for _, pair := range metric.GetLabel() {
				key += "|" + pair.GetName() + "=" + pair.GetValue()
			}
			switch {
			case metric.GetCounter() != nil:
				samples[key] = metric.GetCounter().GetValue()
			case metric.GetGauge() != nil:
				samples[key] = metric.GetGauge().GetValue()
			case metric.GetHistogram() != nil:
				samples[key] = float64(metric.GetHistogram().GetSampleCount())
			}
		}
	}
	return samples, nil
}

func names(labels []Label) []string {
	result := make([]string, len(labels))
	for i, label := range labels {
		result[i] = label.Name
	}
	return result
}

// checked counts one rejection per sample, however many of its values were wrong.
func (r *Registry) checked(metric string, labels []Label, values []string) []string {
	if len(values) != len(labels) {
		values = make([]string, len(labels))
	}
	result := make([]string, len(values))
	rejected := false
	for i, value := range values {
		if labels[i].valid(value) {
			result[i] = value
			continue
		}
		result[i] = Invalid
		rejected = true
	}
	if rejected {
		r.invalid.WithLabelValues(metric).Inc()
	}
	return result
}

// Counter only grows.
type Counter struct {
	registry *Registry
	name     string
	labels   []Label
	vector   *prometheus.CounterVec
}

// Counter registers a counter.
func (r *Registry) Counter(name, help string, labels ...Label) *Counter {
	full := r.prefix + "_" + name
	vector := prometheus.NewCounterVec(prometheus.CounterOpts{Name: full, Help: help}, names(labels))
	r.registry.MustRegister(vector)
	return &Counter{registry: r, name: full, labels: labels, vector: vector}
}

// Add increases the counter for the label values, given in declaration order.
func (c *Counter) Add(delta float64, values ...string) {
	c.vector.WithLabelValues(c.registry.checked(c.name, c.labels, values)...).Add(delta)
}

// Inc adds one.
func (c *Counter) Inc(values ...string) { c.Add(1, values...) }

// Gauge goes up and down.
type Gauge struct {
	registry *Registry
	name     string
	labels   []Label
	vector   *prometheus.GaugeVec
}

// Gauge registers a gauge.
func (r *Registry) Gauge(name, help string, labels ...Label) *Gauge {
	full := r.prefix + "_" + name
	vector := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: full, Help: help}, names(labels))
	r.registry.MustRegister(vector)
	return &Gauge{registry: r, name: full, labels: labels, vector: vector}
}

// Set sets the gauge for the label values.
func (g *Gauge) Set(value float64, values ...string) {
	g.vector.WithLabelValues(g.registry.checked(g.name, g.labels, values)...).Set(value)
}

// Histogram counts observations into buckets.
type Histogram struct {
	registry *Registry
	name     string
	labels   []Label
	vector   *prometheus.HistogramVec
}

// Histogram registers a histogram with the given upper bounds.
func (r *Registry) Histogram(name, help string, buckets []float64, labels ...Label) *Histogram {
	full := r.prefix + "_" + name
	vector := prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: full, Help: help, Buckets: buckets}, names(labels))
	r.registry.MustRegister(vector)
	return &Histogram{registry: r, name: full, labels: labels, vector: vector}
}

// Observe records one value.
func (h *Histogram) Observe(value float64, values ...string) {
	h.vector.WithLabelValues(h.registry.checked(h.name, h.labels, values)...).Observe(value)
}

// Emit reports one sample of a snapshot.
type Emit func(value float64, labelValues ...string)

// Snapshot registers a gauge computed when the registry is read, from state the
// process already keeps. Samples absent from a read disappear, so a removed
// source stops being reported instead of freezing at its last value.
func (r *Registry) Snapshot(name, help string, read func(emit Emit), labels ...Label) {
	full := r.prefix + "_" + name
	r.registry.MustRegister(&snapshot{
		registry: r, name: full, labels: labels, read: read,
		description: prometheus.NewDesc(full, help, names(labels), nil),
	})
}

type snapshot struct {
	registry    *Registry
	name        string
	labels      []Label
	read        func(emit Emit)
	description *prometheus.Desc
	mu          sync.Mutex
}

func (s *snapshot) Describe(descriptions chan<- *prometheus.Desc) { descriptions <- s.description }

func (s *snapshot) Collect(metrics chan<- prometheus.Metric) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.read(func(value float64, labelValues ...string) {
		metrics <- prometheus.MustNewConstMetric(s.description, prometheus.GaugeValue, value,
			s.registry.checked(s.name, s.labels, labelValues)...)
	})
}
