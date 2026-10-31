package main

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/gosuda/portal-tunnel/v2/portal"
)

// relayMetrics belongs to this executable. The relay supplies only its
// aggregate snapshot; registration, HTTP instrumentation, and exposition stay
// here. A private registry also keeps repeated in-process servers independent.
type relayMetrics struct {
	handler  http.Handler
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
}

func newRelayMetrics(server *portal.Server) *relayMetrics {
	registry := prometheus.NewRegistry()
	registry.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	registry.MustRegister(
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "portal_relay_active_leases",
			Help: "Current non-expired relay lease registrations, counted once per lease.",
		}, func() float64 { return float64(server.Stats().ActiveLeases) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "portal_relay_active_connections",
			Help: "Current bridged HTTP/SNI and raw TCP stream connections, including overlay streams.",
		}, func() float64 { return float64(server.Stats().ActiveConnections) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "portal_relay_active_udp_flows",
			Help: "Current tracked UDP flows on active leases, including idle flows until expiry.",
		}, func() float64 { return float64(server.Stats().ActiveUDPFlows) }),
		prometheus.NewCounterFunc(prometheus.CounterOpts{
			Name: "portal_relay_forwarded_stream_bytes_total",
			Help: "Cumulative successful HTTP/SNI and raw TCP stream bytes written in both directions, excluding UDP; resets with the Server instance.",
		}, func() float64 { return float64(server.Stats().ForwardedBytes) }),
	)
	requests := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "portal_relay_http_requests_total",
		Help: "HTTP requests handled by the relay, by normalized method and response status.",
	}, []string{"method", "code"})
	duration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "portal_relay_http_request_duration_seconds",
		Help:    "HTTP request handling duration in seconds, by response status.",
		Buckets: prometheus.DefBuckets,
	}, []string{"code"})
	registry.MustRegister(requests, duration)
	return &relayMetrics{
		handler:  promhttp.HandlerFor(registry, promhttp.HandlerOpts{}),
		requests: requests,
		duration: duration,
	}
}

func (m *relayMetrics) instrument(next http.Handler) http.Handler {
	return promhttp.InstrumentHandlerCounter(m.requests,
		promhttp.InstrumentHandlerDuration(m.duration, next))
}
