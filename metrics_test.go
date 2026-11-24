package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// scrape returns the authenticator's metrics in the text exposition format.
func scrape(t *testing.T, a *authenticator) string {
	t.Helper()
	rec := httptest.NewRecorder()
	newMetricsMux(a.metrics).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /metrics: status = %d, want 200", rec.Code)
	}
	return rec.Body.String()
}

func TestMetricsCountOutcomes(t *testing.T) {
	f := newFakeAccess(t)
	a := f.authenticator(testAud)
	past := time.Now().Add(-2 * time.Hour)

	doAuth(a, withHeader(f.token(nil)))
	doAuth(a, withHeader(f.token(nil)))
	doAuth(a, nil)
	doAuth(a, withHeader("not.a.jwt"))
	doAuth(a, withHeader(f.token(map[string]any{"aud": []string{"another-app"}})))
	doAuth(a, withHeader(f.token(map[string]any{
		"iat": past.Unix(), "nbf": past.Unix(), "exp": past.Add(time.Hour).Unix(),
	})))

	out := scrape(t, a)
	for _, want := range []string{
		`cf_forward_auth_requests_total{reason="",result="granted"} 2`,
		`cf_forward_auth_requests_total{reason="no_token",result="denied"} 1`,
		`cf_forward_auth_requests_total{reason="invalid",result="denied"} 1`,
		`cf_forward_auth_requests_total{reason="bad_audience",result="denied"} 1`,
		`cf_forward_auth_requests_total{reason="expired",result="denied"} 1`,
		`cf_forward_auth_request_duration_seconds_count{result="granted"} 2`,
		`cf_forward_auth_request_duration_seconds_count{result="denied"} 4`,
		`cf_forward_auth_key_fetches_total{code="200"} 1`,
		"go_goroutines ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics output lacks %q", want)
		}
	}
	// The rejected audience must not leak into a label.
	if strings.Contains(out, "another-app") {
		t.Error("token contents appear in the metrics output")
	}
}

func TestMetricsKeyFetchError(t *testing.T) {
	f := newFakeAccess(t)
	a := f.authenticator(testAud)
	token := f.token(nil)
	f.server.Close()

	if rec := doAuth(a, withHeader(token)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 when keys cannot be fetched", rec.Code)
	}
	if out := scrape(t, a); !strings.Contains(out, `cf_forward_auth_key_fetches_total{code="error"} 1`) {
		t.Error("failed key fetch was not counted")
	}
}

func TestMetricsEndpointOnly(t *testing.T) {
	f := newFakeAccess(t)
	mux := newMetricsMux(f.authenticator(testAud).metrics)
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodPost, "/metrics", http.StatusMethodNotAllowed},
		{http.MethodGet, "/", http.StatusNotFound},
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		if rec.Code != tc.want {
			t.Errorf("%s %s: status = %d, want %d", tc.method, tc.path, rec.Code, tc.want)
		}
	}
}

func TestDenyReason(t *testing.T) {
	for err, want := range map[error]string{
		errNoToken:                                           reasonNoToken,
		fmt.Errorf("%w: [x]", errBadAudience):                reasonBadAudience,
		&oidc.TokenExpiredError{Expiry: time.Now()}:          reasonExpired,
		fmt.Errorf("wrapped: %w", &oidc.TokenExpiredError{}): reasonExpired,
		errors.New("oidc: malformed jwt"):                    reasonInvalid,
	} {
		if got := denyReason(err); got != want {
			t.Errorf("denyReason(%v) = %q, want %q", err, got, want)
		}
	}
}

func TestMetricsAddrConfig(t *testing.T) {
	env := map[string]string{"CF_ACCESS_TEAM_DOMAIN": "myteam", "CF_ACCESS_AUD": "aud"}
	for in, want := range map[string]string{"": ":9090", "off": "", "127.0.0.1:9100": "127.0.0.1:9100"} {
		env["METRICS_ADDR"] = in
		cfg, err := loadConfig(func(k string) string { return env[k] })
		if err != nil || cfg.metricsAddr != want {
			t.Errorf("METRICS_ADDR=%q: metricsAddr = %q, err = %v; want %q", in, cfg.metricsAddr, err, want)
		}
	}
}
