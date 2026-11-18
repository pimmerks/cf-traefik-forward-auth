package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

const (
	// Header and cookie in which Cloudflare Access passes the application token.
	accessJWTHeader = "Cf-Access-Jwt-Assertion"
	accessJWTCookie = "CF_Authorization"

	// Headers set on a successful response. List these in the Traefik
	// middleware's authResponseHeaders to pass them on to the backend.
	headerEmail      = "X-Auth-Email"
	headerUser       = "X-Auth-User"
	headerCommonName = "X-Auth-Common-Name"
)

var (
	errNoToken     = errors.New("no Cloudflare Access token in request")
	errBadAudience = errors.New("token audience is not allowed")
)

// claims are the Cloudflare Access application token claims we care about.
type claims struct {
	Email string `json:"email"`
	// CommonName is set instead of Email for service tokens.
	CommonName string `json:"common_name"`
}

// identity is the verified caller.
type identity struct {
	Subject    string
	Email      string
	CommonName string
}

// authenticator validates Cloudflare Access JWTs for one team.
type authenticator struct {
	verifier  *oidc.IDTokenVerifier
	audiences map[string]struct{}
	log       *slog.Logger
	// audit, when set, records the outcome of every request regardless of
	// the level of log. When nil, outcomes go to log instead.
	audit *slog.Logger
}

// newAuthenticator builds an authenticator that trusts tokens issued by issuer,
// signed by a key published at certsURL, and addressed to one of audiences.
func newAuthenticator(ctx context.Context, issuer, certsURL string, audiences []string, log *slog.Logger) (*authenticator, error) {
	if len(audiences) == 0 {
		return nil, errors.New("at least one audience is required")
	}
	set := make(map[string]struct{}, len(audiences))
	for _, a := range audiences {
		set[a] = struct{}{}
	}
	// The remote key set caches keys and refetches when it sees an unknown
	// key ID, which covers Cloudflare's signing key rotation. ctx bounds the
	// lifetime of those background fetches, not of a single request.
	keySet := oidc.NewRemoteKeySet(ctx, certsURL)
	verifier := oidc.NewVerifier(issuer, keySet, &oidc.Config{
		// Audience is checked in verify, since we accept any of several.
		SkipClientIDCheck:    true,
		SupportedSigningAlgs: []string{oidc.RS256},
	})
	return &authenticator{verifier: verifier, audiences: set, log: log}, nil
}

// tokenFromRequest extracts the Access JWT from the header, falling back to
// the cookie. Cloudflare recommends the header; the cookie is not guaranteed
// to be passed to the origin.
func tokenFromRequest(r *http.Request) string {
	if t := strings.TrimSpace(r.Header.Get(accessJWTHeader)); t != "" {
		return t
	}
	if c, err := r.Cookie(accessJWTCookie); err == nil {
		return c.Value
	}
	return ""
}

// verify checks signature, issuer, expiry and audience of the request's token.
func (a *authenticator) verify(r *http.Request) (*identity, error) {
	raw := tokenFromRequest(r)
	if raw == "" {
		return nil, errNoToken
	}
	token, err := a.verifier.Verify(r.Context(), raw)
	if err != nil {
		return nil, err
	}
	if !a.audienceAllowed(token.Audience) {
		return nil, fmt.Errorf("%w: %v", errBadAudience, token.Audience)
	}
	var c claims
	if err := token.Claims(&c); err != nil {
		return nil, fmt.Errorf("decoding claims: %w", err)
	}
	return &identity{Subject: token.Subject, Email: c.Email, CommonName: c.CommonName}, nil
}

func (a *authenticator) audienceAllowed(tokenAud []string) bool {
	for _, aud := range tokenAud {
		if _, ok := a.audiences[aud]; ok {
			return true
		}
	}
	return false
}

// originalURL rebuilds the URL of the request Traefik is asking about from
// the X-Forwarded-* headers it sends.
func originalURL(r *http.Request) string {
	url := r.Header.Get("X-Forwarded-Host") + r.Header.Get("X-Forwarded-Uri")
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		url = proto + "://" + url
	}
	return url
}

// ServeHTTP implements the Traefik ForwardAuth contract: 2xx lets the original
// request through, anything else is returned to the client.
func (a *authenticator) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// With the audit log on, every outcome is recorded there: failures at
	// WARN and successes at INFO. Without it, failures still log at WARN but
	// successes only at DEBUG, to keep the default output quiet.
	log, successLevel := a.log, slog.LevelDebug
	if a.audit != nil {
		log, successLevel = a.audit, slog.LevelInfo
	}
	log = log.With(
		"method", r.Header.Get("X-Forwarded-Method"),
		"url", originalURL(r),
		"client", r.Header.Get("X-Forwarded-For"),
	)

	id, err := a.verify(r)
	if err != nil {
		log.Warn("access denied", "reason", err.Error())
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Only set headers that have a value: Traefik strips any
	// authResponseHeaders entry that is absent from this response, so a
	// client cannot smuggle its own X-Auth-* headers to the backend.
	for name, value := range map[string]string{
		headerEmail:      id.Email,
		headerUser:       id.Subject,
		headerCommonName: id.CommonName,
	} {
		if value != "" {
			w.Header().Set(name, value)
		}
	}
	log.Log(r.Context(), successLevel, "access granted",
		"user_id", id.Subject, "email", id.Email, "common_name", id.CommonName)
	w.WriteHeader(http.StatusOK)
}
