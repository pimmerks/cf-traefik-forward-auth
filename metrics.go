package main

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Values of the reason label on denied requests. The set is fixed so that
// token contents, such as an unknown audience, never become label values.
const (
	reasonNone        = ""
	reasonNoToken     = "no_token"
	reasonBadAudience = "bad_audience"
	reasonExpired     = "expired"
	reasonInvalid     = "invalid"
)

// denyReason maps a verification error to a reason label value.
func denyReason(err error) string {
	var expired *oidc.TokenExpiredError
	switch {
	case errors.Is(err, errNoToken):
		return reasonNoToken
	case errors.Is(err, errBadAudience):
		return reasonBadAudience
	case errors.As(err, &expired):
		return reasonExpired
	default:
		return reasonInvalid
	}
}

// metrics holds the Prometheus collectors of one authenticator.
type metrics struct {
	registry   *prometheus.Registry
	requests   *prometheus.CounterVec
	duration   *prometheus.HistogramVec
	keyFetches *prometheus.CounterVec
}

func newMetrics() *metrics {
	m := &metrics{
		registry: prometheus.NewRegistry(),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "cf_forward_auth_requests_total",
			Help: "Auth requests by result (granted or denied) and, for denied requests, reason.",
		}, []string{"result", "reason"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "cf_forward_auth_request_duration_seconds",
			Help:    "Time taken to answer an auth request, including any signing key fetch.",
			Buckets: prometheus.DefBuckets,
		}, []string{"result"}),
		keyFetches: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "cf_forward_auth_key_fetches_total",
			Help: "Fetches of the Cloudflare Access signing keys by HTTP status code, or \"error\" when no response was received.",
		}, []string{"code"}),
	}
	m.registry.MustRegister(
		m.requests, m.duration, m.keyFetches,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	// Start the common series at zero so rate() and alerts work before the
	// first request of each kind.
	m.requests.WithLabelValues("granted", reasonNone)
	for _, r := range []string{reasonNoToken, reasonBadAudience, reasonExpired, reasonInvalid} {
		m.requests.WithLabelValues("denied", r)
	}
	return m
}

// handler serves the metrics in the Prometheus exposition format.
func (m *metrics) handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// keyFetchClient returns an HTTP client that counts every request it makes,
// for use as the signing key fetcher.
func (m *metrics) keyFetchClient() *http.Client {
	return &http.Client{Transport: &countingTransport{next: http.DefaultTransport, count: m.keyFetches}}
}

type countingTransport struct {
	next  http.RoundTripper
	count *prometheus.CounterVec
}

func (t *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := t.next.RoundTrip(r)
	code := "error"
	if err == nil {
		code = strconv.Itoa(resp.StatusCode)
	}
	t.count.WithLabelValues(code).Inc()
	return resp, err
}

func newMetricsMux(m *metrics) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", m.handler())
	return mux
}
