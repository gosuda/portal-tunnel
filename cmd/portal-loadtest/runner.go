package main

import (
	"sort"
	"time"
)

type Metrics struct {
	Oscillations int
	P99Latency   time.Duration
	SelectionTPS float64
	MemUsageMB   float64
	ErrorRate    float64
}

// CalculateMetrics aggregates raw observations into the 5 requested stress metrics.
func CalculateMetrics(history []string, latencies []time.Duration, errors int, totalOps int, duration time.Duration) Metrics {
	oscillations := 0
	for i := 1; i < len(history); i++ {
		if history[i] != history[i-1] {
			oscillations++
		}
	}

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	p99Idx := int(float64(len(latencies)) * 0.99)
	if p99Idx >= len(latencies) {
		p99Idx = len(latencies) - 1
	}

	return Metrics{
		Oscillations: oscillations,
		P99Latency:   latencies[p99Idx],
		SelectionTPS: float64(totalOps) / duration.Seconds(),
		ErrorRate:    float64(errors) / float64(totalOps),
	}
}
