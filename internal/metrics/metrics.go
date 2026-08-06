// Package metrics provides Prometheus metric registrations for the proxy.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Prometheus metrics for monitoring proxy behavior.
var (
	// TrafficTotal tracks total requests by domain and action taken.
	TrafficTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "proxy_traffic_total",
		Help: "Total requests by domain and action",
	}, []string{"domain", "action"})

	// RequestDuration measures request latency distribution by action.
	RequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "proxy_request_duration_seconds",
		Help:    "Request duration in seconds",
		Buckets: prometheus.DefBuckets,
	}, []string{"action"})

	// ConfigLoadErrors counts configuration loading failures.
	ConfigLoadErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "proxy_config_load_errors_total",
		Help: "Total number of configuration load errors",
	})

	// ConfigReloads counts successful configuration reloads.
	ConfigReloads = promauto.NewCounter(prometheus.CounterOpts{
		Name: "proxy_config_reloads_total",
		Help: "Total number of successful configuration reloads",
	})

	// UpstreamErrors counts errors connecting to upstream servers.
	UpstreamErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "proxy_upstream_errors_total",
		Help: "Total upstream connection errors by type",
	}, []string{"type"})

	// ResponseStatus counts responses by status code class.
	ResponseStatus = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "proxy_response_status_total",
		Help: "Total responses by status code class",
	}, []string{"class"})

	// BytesTransferred tracks bytes sent and received.
	BytesTransferred = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "proxy_bytes_total",
		Help: "Total bytes transferred by direction",
	}, []string{"direction"})

	// TraceRecords counts emitted trace records by mode (mitm or passthrough).
	TraceRecords = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "proxy_trace_records_total",
		Help: "Total emitted trace records by mode",
	}, []string{"mode"})
)

// RegisterActiveConnections publishes the live client-connection count under
// proxy_active_connections.
//
// It takes a source function rather than exposing Inc/Dec because the previous
// gauge was incremented and decremented inside the OnRequest filter, which
// returns before the upstream round-trip. It therefore bracketed rule
// evaluation -- microseconds -- and read ~0 at every scrape under any load,
// while never counting passthrough CONNECTs at all. The connection-tracking
// listener added for graceful shutdown already holds an exact live count;
// this publishes that instead of a number that was never meaningful.
//
// Call once during startup.
func RegisterActiveConnections(source func() float64) {
	promauto.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "proxy_active_connections",
		Help: "Number of client connections currently open",
	}, source)
}
