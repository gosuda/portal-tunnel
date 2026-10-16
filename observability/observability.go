package observability

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	runtimemetrics "runtime/metrics"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

type Config struct {
	ServiceName string
}

type Runtime struct {
	provider *sdkmetric.MeterProvider
	exporter *prometheusExporter
	meter    metric.Meter
	runtime  metric.Registration
}

func Start(ctx context.Context, cfg Config) (*Runtime, error) {
	exporter := newPrometheusExporter()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exporter, sdkmetric.WithInterval(5*time.Second))))
	otel.SetMeterProvider(provider)
	r := &Runtime{provider: provider, exporter: exporter, meter: provider.Meter(cfg.ServiceName)}
	registration, err := registerRuntimeMetrics(r.meter)
	if err != nil {
		_ = provider.Shutdown(context.Background())
		return nil, fmt.Errorf("register runtime metrics: %w", err)
	}
	r.runtime = registration
	return r, nil
}

func (r *Runtime) Meter() metric.Meter   { return r.meter }
func (r *Runtime) Handler() http.Handler { return r.exporter }

func (r *Runtime) Shutdown(ctx context.Context) error {
	if r == nil {
		return nil
	}
	if r.runtime != nil {
		_ = r.runtime.Unregister()
	}
	return r.provider.Shutdown(ctx)
}

func registerRuntimeMetrics(meter metric.Meter) (metric.Registration, error) {
	cpu, err := meter.Float64ObservableCounter("go.cpu.seconds", metric.WithUnit("s"), metric.WithDescription("Total CPU time used by the Go process"))
	if err != nil {
		return nil, err
	}
	runtimeMemory, err := meter.Int64ObservableGauge("go.memory.runtime.bytes", metric.WithUnit("By"), metric.WithDescription("Memory managed by the Go runtime"))
	if err != nil {
		return nil, err
	}
	heapMemory, err := meter.Int64ObservableGauge("go.memory.heap.bytes", metric.WithUnit("By"), metric.WithDescription("Heap object memory used by the Go runtime"))
	if err != nil {
		return nil, err
	}
	goroutines, err := meter.Int64ObservableGauge("go.goroutines", metric.WithUnit("{goroutine}"), metric.WithDescription("Current number of goroutines"))
	if err != nil {
		return nil, err
	}

	samples := []runtimemetrics.Sample{
		{Name: "/cpu/classes/total:cpu-seconds"},
		{Name: "/memory/classes/total:bytes"},
		{Name: "/memory/classes/heap/objects:bytes"},
		{Name: "/sched/goroutines:goroutines"},
	}
	return meter.RegisterCallback(func(_ context.Context, observer metric.Observer) error {
		// runtime/metrics.Read updates the sample values in place and is safe for
		// concurrent readers, so no application-level state is required here.
		runtimemetrics.Read(samples)
		if samples[0].Value.Kind() == runtimemetrics.KindFloat64 {
			observer.ObserveFloat64(cpu, samples[0].Value.Float64())
		}
		if samples[1].Value.Kind() == runtimemetrics.KindUint64 {
			observer.ObserveInt64(runtimeMemory, int64(samples[1].Value.Uint64()))
		}
		if samples[2].Value.Kind() == runtimemetrics.KindUint64 {
			observer.ObserveInt64(heapMemory, int64(samples[2].Value.Uint64()))
		}
		if samples[3].Value.Kind() == runtimemetrics.KindUint64 {
			observer.ObserveInt64(goroutines, int64(samples[3].Value.Uint64()))
		}
		return nil
	}, cpu, runtimeMemory, heapMemory, goroutines)
}

func WrapHTTP(meter metric.Meter, next http.Handler) http.Handler {
	requests, _ := meter.Int64Counter("portal.http.server.requests", metric.WithDescription("HTTP requests handled by the relay"))
	duration, _ := meter.Float64Histogram("portal.http.server.duration", metric.WithUnit("ms"), metric.WithDescription("HTTP request duration"))
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		started := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, req)
		attrs := []attribute.KeyValue{
			attribute.String("http.method", req.Method),
			attribute.Int("http.status_code", recorder.status),
		}
		requests.Add(req.Context(), 1, metric.WithAttributes(attrs...))
		duration.Record(req.Context(), float64(time.Since(started))/float64(time.Millisecond), metric.WithAttributes(attrs...))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (w *statusRecorder) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
func (w *statusRecorder) Write(p []byte) (int, error) {
	if w.status == http.StatusOK {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(p)
}

func (w *statusRecorder) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
func (w *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("response writer does not support hijacking")
	}
	return h.Hijack()
}
func (w *statusRecorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// LokiWriter preserves the existing log writer and mirrors each completed line to Loki.
type LokiWriter struct {
	local    io.Writer
	endpoint string
	client   *http.Client
	labels   map[string]string
	queue    chan []byte
	done     chan struct{}
	once     sync.Once
}

func NewLokiWriter(local io.Writer, endpoint, service string) (*LokiWriter, error) {
	endpoint = strings.TrimRight(strings.TrimSpace(endpoint), "/")
	if endpoint == "" {
		return &LokiWriter{local: local}, nil
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid Loki URL %q", endpoint)
	}
	w := &LokiWriter{local: local, endpoint: endpoint + "/loki/api/v1/push", client: &http.Client{Timeout: 5 * time.Second}, labels: map[string]string{"service": service}, queue: make(chan []byte, 256), done: make(chan struct{})}
	go w.run()
	return w, nil
}

func (w *LokiWriter) Write(p []byte) (int, error) {
	n, err := w.local.Write(p)
	if w.queue != nil {
		line := bytes.TrimSpace(append([]byte(nil), p...))
		select {
		case w.queue <- line:
		default:
		}
	}
	return n, err
}

func (w *LokiWriter) Close() {
	if w.queue != nil {
		w.once.Do(func() { close(w.done) })
	}
}
func (w *LokiWriter) run() {
	for {
		select {
		case p := <-w.queue:
			w.push(p)
		case <-w.done:
			return
		}
	}
}
func (w *LokiWriter) push(line []byte) {
	body := map[string]any{"streams": []any{map[string]any{"stream": map[string]string{"service": w.labels["service"]}, "values": [][]string{{fmt.Sprint(time.Now().UnixNano()), string(line)}}}}}
	data, _ := json.Marshal(body)
	resp, err := w.client.Post(w.endpoint, "application/json", bytes.NewReader(data))
	if err == nil {
		resp.Body.Close()
	}
}

type prometheusExporter struct {
	mu      sync.RWMutex
	metrics map[string]metricSnapshot
	stopped bool
}
type metricSnapshot struct {
	name, help string
	kind       prometheus.ValueType
	labels     []string
	values     []metricPoint
	buckets    []float64
}
type metricPoint struct {
	labels []string
	value  float64
	count  uint64
	sum    float64
	bucket []uint64
}

func newPrometheusExporter() *prometheusExporter {
	return &prometheusExporter{metrics: map[string]metricSnapshot{}}
}
func (e *prometheusExporter) Temporality(sdkmetric.InstrumentKind) metricdata.Temporality {
	return metricdata.CumulativeTemporality
}
func (e *prometheusExporter) Aggregation(kind sdkmetric.InstrumentKind) sdkmetric.Aggregation {
	return sdkmetric.DefaultAggregationSelector(kind)
}
func (e *prometheusExporter) Export(_ context.Context, rm *metricdata.ResourceMetrics) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopped {
		return sdkmetric.ErrExporterShutdown
	}
	for _, scope := range rm.ScopeMetrics {
		for _, m := range scope.Metrics {
			s := metricSnapshot{name: sanitize(m.Name), help: m.Description, kind: prometheus.GaugeValue, labels: nil}
			switch data := m.Data.(type) {
			case metricdata.Sum[int64]:
				s.kind = prometheus.CounterValue
				s.name += "_total"
				for _, p := range data.DataPoints {
					s.addNumber(p.Attributes, float64(p.Value))
				}
			case metricdata.Sum[float64]:
				s.kind = prometheus.CounterValue
				s.name += "_total"
				for _, p := range data.DataPoints {
					s.addNumber(p.Attributes, p.Value)
				}
			case metricdata.Gauge[int64]:
				for _, p := range data.DataPoints {
					s.addNumber(p.Attributes, float64(p.Value))
				}
			case metricdata.Gauge[float64]:
				for _, p := range data.DataPoints {
					s.addNumber(p.Attributes, p.Value)
				}
			case metricdata.Histogram[int64]:
				s.kind = prometheus.GaugeValue
				for _, p := range data.DataPoints {
					s.addHistogram(p.Attributes, p.Count, float64(p.Sum), p.Bounds, p.BucketCounts)
				}
			case metricdata.Histogram[float64]:
				s.kind = prometheus.GaugeValue
				for _, p := range data.DataPoints {
					s.addHistogram(p.Attributes, p.Count, p.Sum, p.Bounds, p.BucketCounts)
				}
			default:
				continue
			}
			e.metrics[s.name] = s
		}
	}
	return nil
}
func (e *prometheusExporter) ForceFlush(context.Context) error { return nil }
func (e *prometheusExporter) Shutdown(context.Context) error {
	e.mu.Lock()
	e.stopped = true
	e.mu.Unlock()
	return nil
}
func (s *metricSnapshot) addNumber(set attribute.Set, value float64) {
	labels, vals := attrs(set)
	if s.labels == nil {
		s.labels = labels
	}
	s.values = append(s.values, metricPoint{labels: vals, value: value})
}
func (s *metricSnapshot) addHistogram(set attribute.Set, count uint64, sum float64, bounds []float64, buckets []uint64) {
	labels, vals := attrs(set)
	if s.labels == nil {
		s.labels = labels
	}
	s.buckets = append([]float64(nil), bounds...)
	s.values = append(s.values, metricPoint{labels: vals, count: count, sum: sum, bucket: append([]uint64(nil), buckets...)})
}
func attrs(set attribute.Set) ([]string, []string) {
	kvs := set.ToSlice()
	sort.Slice(kvs, func(i, j int) bool { return kvs[i].Key < kvs[j].Key })
	keys, vals := make([]string, 0, len(kvs)), make([]string, 0, len(kvs))
	for _, kv := range kvs {
		keys = append(keys, sanitize(string(kv.Key)))
		vals = append(vals, kv.Value.Emit())
	}
	return keys, vals
}
func sanitize(s string) string {
	var b strings.Builder
	for i, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9' && i > 0) || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out == "" {
		return "metric"
	}
	return out
}
func (e *prometheusExporter) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	reg := prometheus.NewRegistry()
	reg.MustRegister(e)
	h := promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
	h.ServeHTTP(w, nil)
}
func (e *prometheusExporter) Describe(chan<- *prometheus.Desc) {}
func (e *prometheusExporter) Collect(ch chan<- prometheus.Metric) {
	for _, s := range e.metrics {
		desc := prometheus.NewDesc(s.name, s.help, s.labels, nil)
		for _, p := range s.values {
			if len(p.bucket) > 0 {
				ch <- prometheus.MustNewConstHistogram(desc, p.count, p.sum, func() map[float64]uint64 {
					m := map[float64]uint64{}
					for i, v := range p.bucket {
						if i < len(s.buckets) {
							m[s.buckets[i]] = v
						}
					}
					return m
				}(), p.labels...)
			} else {
				ch <- prometheus.MustNewConstMetric(desc, s.kind, p.value, p.labels...)
			}
		}
	}
}
