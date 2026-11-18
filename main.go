// Command cf-traefik-forward-auth is a Traefik ForwardAuth server that only
// lets requests through when they carry a valid Cloudflare Access JWT.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type config struct {
	issuer     string
	certsURL   string
	audiences  []string
	listenAddr string
	logLevel   slog.Level
	auditLog   bool
}

// issuerFromTeamDomain accepts "myteam", "myteam.cloudflareaccess.com" or
// "https://myteam.cloudflareaccess.com" and returns the issuer URL.
func issuerFromTeamDomain(team string) (string, error) {
	team = strings.TrimSpace(team)
	team = strings.TrimPrefix(team, "https://")
	team = strings.TrimRight(team, "/")
	if team == "" {
		return "", errors.New("team domain is empty")
	}
	if !strings.Contains(team, ".") {
		team += ".cloudflareaccess.com"
	}
	u, err := url.Parse("https://" + team)
	if err != nil || u.Host != team {
		return "", fmt.Errorf("invalid team domain %q", team)
	}
	return u.String(), nil
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func loadConfig(getenv func(string) string) (config, error) {
	cfg := config{listenAddr: ":8080", logLevel: slog.LevelInfo}

	issuer, err := issuerFromTeamDomain(getenv("CF_ACCESS_TEAM_DOMAIN"))
	if err != nil {
		return cfg, fmt.Errorf("CF_ACCESS_TEAM_DOMAIN: %w", err)
	}
	cfg.issuer = issuer
	cfg.certsURL = issuer + "/cdn-cgi/access/certs"

	cfg.audiences = splitList(getenv("CF_ACCESS_AUD"))
	if len(cfg.audiences) == 0 {
		return cfg, errors.New("CF_ACCESS_AUD: at least one application audience (AUD) tag is required")
	}

	if v := getenv("LISTEN_ADDR"); v != "" {
		cfg.listenAddr = v
	}
	if v := getenv("AUDIT_LOG"); v != "" {
		enabled, err := strconv.ParseBool(v)
		if err != nil {
			return cfg, fmt.Errorf("AUDIT_LOG: %q is not true or false", v)
		}
		cfg.auditLog = enabled
	}
	if v := getenv("LOG_LEVEL"); v != "" {
		if err := cfg.logLevel.UnmarshalText([]byte(v)); err != nil {
			return cfg, fmt.Errorf("LOG_LEVEL: %w", err)
		}
	}
	return cfg, nil
}

func newMux(auth http.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	// Traefik forwards every method to the configured address, so the
	// auth handler answers on any other path and method.
	mux.Handle("/", auth)
	return mux
}

func run(log *slog.Logger, level *slog.LevelVar) error {
	cfg, err := loadConfig(os.Getenv)
	if err != nil {
		return err
	}
	level.Set(cfg.logLevel)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	auth, err := newAuthenticator(ctx, cfg.issuer, cfg.certsURL, cfg.audiences, log)
	if err != nil {
		return err
	}

	auth.audit = cfg.auditLog

	srv := &http.Server{
		Addr:              cfg.listenAddr,
		Handler:           newMux(auth),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       90 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	log.Info("listening", "addr", cfg.listenAddr, "issuer", cfg.issuer, "audiences", len(cfg.audiences), "audit_log", cfg.auditLog)

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

func main() {
	// The logger exists before the config is loaded so that startup errors
	// are logged in the same format; the level is adjusted once it is known.
	level := new(slog.LevelVar)
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(log)

	if err := run(log, level); err != nil {
		log.Error("fatal error", "error", err.Error())
		os.Exit(1)
	}
}
