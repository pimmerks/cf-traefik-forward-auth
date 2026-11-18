package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const testAud = "4714c1358e65fe4b408ad6d432a5f878f08194bdb4752441fd56faefa9b2b6f2"

// fakeAccess mimics the Cloudflare Access certs endpoint and signs tokens.
type fakeAccess struct {
	t      *testing.T
	server *httptest.Server
	key    *rsa.PrivateKey
}

func newFakeAccess(t *testing.T) *fakeAccess {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeAccess{t: t, key: key}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &key.PublicKey, KeyID: "test-key", Algorithm: "RS256", Use: "sig"},
		}}
		json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeAccess) issuer() string { return f.server.URL }

func (f *fakeAccess) authenticator(auds ...string) *authenticator {
	f.t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	a, err := newAuthenticator(context.Background(), f.issuer(), f.server.URL+"/cdn-cgi/access/certs", auds, log)
	if err != nil {
		f.t.Fatal(err)
	}
	return a
}

func signWith(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test-key"),
	)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	token, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// userClaims returns valid claims for a user login; overrides replace entries.
func (f *fakeAccess) userClaims(overrides map[string]any) map[string]any {
	now := time.Now()
	c := map[string]any{
		"iss":   f.issuer(),
		"aud":   []string{testAud},
		"sub":   "7335d417-61da-459d-899c-0a01c76a2f94",
		"email": "user@example.com",
		"type":  "app",
		"iat":   now.Unix(),
		"nbf":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	}
	for k, v := range overrides {
		c[k] = v
	}
	return c
}

func (f *fakeAccess) token(overrides map[string]any) string {
	return signWith(f.t, f.key, f.userClaims(overrides))
}

func doAuth(a *authenticator, mutate func(*http.Request)) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Host", "app.example.com")
	if mutate != nil {
		mutate(req)
	}
	rec := httptest.NewRecorder()
	newMux(a).ServeHTTP(rec, req)
	return rec
}

func withHeader(token string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set(accessJWTHeader, token) }
}

func TestValidTokenInHeader(t *testing.T) {
	f := newFakeAccess(t)
	rec := doAuth(f.authenticator(testAud), withHeader(f.token(nil)))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get(headerEmail); got != "user@example.com" {
		t.Errorf("%s = %q", headerEmail, got)
	}
	if got := rec.Header().Get(headerUser); got != "7335d417-61da-459d-899c-0a01c76a2f94" {
		t.Errorf("%s = %q", headerUser, got)
	}
	if _, ok := rec.Header()[headerCommonName]; ok {
		t.Errorf("%s should be absent for a user token", headerCommonName)
	}
}

func TestValidTokenInCookie(t *testing.T) {
	f := newFakeAccess(t)
	token := f.token(nil)
	rec := doAuth(f.authenticator(testAud), func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: accessJWTCookie, Value: token})
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestServiceToken(t *testing.T) {
	f := newFakeAccess(t)
	token := f.token(map[string]any{"sub": "", "email": nil, "common_name": "abc123.access"})
	rec := doAuth(f.authenticator(testAud), withHeader(token))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get(headerCommonName); got != "abc123.access" {
		t.Errorf("%s = %q", headerCommonName, got)
	}
	if _, ok := rec.Header()[headerEmail]; ok {
		t.Errorf("%s should be absent for a service token", headerEmail)
	}
}

func TestOneOfSeveralAudiences(t *testing.T) {
	f := newFakeAccess(t)
	rec := doAuth(f.authenticator("some-other-aud", testAud), withHeader(f.token(nil)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestRejected(t *testing.T) {
	f := newFakeAccess(t)
	a := f.authenticator(testAud)

	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-2 * time.Hour)

	cases := map[string]func(*http.Request){
		"no token":       nil,
		"garbage":        withHeader("not.a.jwt"),
		"wrong audience": withHeader(f.token(map[string]any{"aud": []string{"another-app"}})),
		"wrong issuer":   withHeader(f.token(map[string]any{"iss": "https://evil.cloudflareaccess.com"})),
		"expired": withHeader(f.token(map[string]any{
			"iat": past.Unix(), "nbf": past.Unix(), "exp": past.Add(time.Hour).Unix(),
		})),
		"not yet valid": withHeader(f.token(map[string]any{
			"nbf": time.Now().Add(time.Hour).Unix(), "exp": time.Now().Add(2 * time.Hour).Unix(),
		})),
		"wrong signing key": withHeader(signWith(t, otherKey, f.userClaims(nil))),
		"alg none": withHeader(
			// {"alg":"none","typ":"JWT"} . {"email":"user@example.com"} . (no signature)
			"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20ifQ.",
		),
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			rec := doAuth(a, func(r *http.Request) {
				// A client-supplied identity header must never be echoed back.
				r.Header.Set(headerEmail, "attacker@example.com")
				if mutate != nil {
					mutate(r)
				}
			})
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", rec.Code)
			}
			if got := rec.Header().Get(headerEmail); got != "" {
				t.Errorf("%s = %q on a rejected request", headerEmail, got)
			}
		})
	}
}

func TestHealthz(t *testing.T) {
	f := newFakeAccess(t)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	newMux(f.authenticator(testAud)).ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
}

func TestIssuerFromTeamDomain(t *testing.T) {
	const want = "https://myteam.cloudflareaccess.com"
	for _, in := range []string{
		"myteam",
		"myteam.cloudflareaccess.com",
		"https://myteam.cloudflareaccess.com",
		" https://myteam.cloudflareaccess.com/ ",
	} {
		got, err := issuerFromTeamDomain(in)
		if err != nil || got != want {
			t.Errorf("issuerFromTeamDomain(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "  ", "my team.example.com", "myteam.example.com/path"} {
		if got, err := issuerFromTeamDomain(in); err == nil {
			t.Errorf("issuerFromTeamDomain(%q) = %q, want error", in, got)
		}
	}
}

func TestLoadConfig(t *testing.T) {
	env := map[string]string{
		"CF_ACCESS_TEAM_DOMAIN": "myteam",
		"CF_ACCESS_AUD":         "aud-one, aud-two,",
		"LOG_LEVEL":             "debug",
	}
	cfg, err := loadConfig(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.certsURL != "https://myteam.cloudflareaccess.com/cdn-cgi/access/certs" {
		t.Errorf("certsURL = %q", cfg.certsURL)
	}
	if len(cfg.audiences) != 2 || cfg.audiences[0] != "aud-one" || cfg.audiences[1] != "aud-two" {
		t.Errorf("audiences = %v", cfg.audiences)
	}
	if cfg.listenAddr != ":8080" || cfg.logLevel != slog.LevelDebug {
		t.Errorf("listenAddr = %q, logLevel = %v", cfg.listenAddr, cfg.logLevel)
	}

	delete(env, "CF_ACCESS_AUD")
	if _, err := loadConfig(func(k string) string { return env[k] }); err == nil {
		t.Error("expected an error without CF_ACCESS_AUD")
	}
}
