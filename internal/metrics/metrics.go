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

	// ActiveConnections tracks currently active proxy connections.
	ActiveConnections = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "proxy_active_connections",
		Help: "Number of active proxy connections",
	})

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
)
