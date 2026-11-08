// Package app wires the server together. It is shared by the binary and the
// integration tests, so tests exercise the real composition.
package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"dataguard/internal/core/audit"
	"dataguard/internal/core/coverage"
	"dataguard/internal/core/fleet"
	"dataguard/internal/core/policy"
	"dataguard/internal/core/preference"
	"dataguard/internal/core/scan"
	"dataguard/internal/core/tenant"
	"dataguard/internal/platform/pki"
	"dataguard/internal/server/agentapi"
	"dataguard/internal/server/api"
	"dataguard/internal/server/storage/clickhouse"
	"dataguard/internal/server/storage/postgres"
	"dataguard/internal/server/telemetry"
)

const (
	readHeaderTimeout = 10 * time.Second
	shutdownTimeout   = 15 * time.Second
)

// Options are the dependencies chosen by the caller.
type Options struct {
	Store          *postgres.Store
	Events         *clickhouse.Store
	PKIDirectory   string
	CertificateTTL time.Duration
	Authenticator  api.Authenticator
	Logger         *slog.Logger
	OIDCIssuer     string
	OIDCClientID   string
	// Broker receives accepted events (ADR-0009).
	Broker Broker
	// Metrics may be nil.
	Metrics *telemetry.Server
	// WebDirectory is the built dashboard; empty disables serving it.
	WebDirectory string
}

// App holds the composed services and handlers.
type App struct {
	Tenants  *tenant.Service
	Fleet    *fleet.Service
	Policies *policy.Service
	Scans    *scan.Service
	// Events stores what the broker consumer reads.
	Events *audit.Service

	APIHandler   http.Handler
	AgentHandler http.Handler
}

// Broker is where ingest hands events over.
type Broker interface {
	audit.Publisher
	Ping(ctx context.Context) error
}

// Build composes the application.
func Build(options Options) (*App, error) {
	authority, err := pki.LoadAuthority(
		filepath.Join(options.PKIDirectory, pki.CACertFile),
		filepath.Join(options.PKIDirectory, pki.CAKeyFile),
		options.CertificateTTL)
	if err != nil {
		return nil, err
	}
	signer, err := pki.LoadPolicySigner(filepath.Join(options.PKIDirectory, pki.PolicyKeyFile))
	if err != nil {
		return nil, fmt.Errorf("load policy key: %w", err)
	}
	tenants := tenant.NewService(options.Store)
	fleetService := fleet.NewService(options.Store, agentapi.Issuer{Authority: authority}, signer)
	policies := policy.NewService(options.Store, signer)
	scans := scan.NewService(options.Store, options.Store)
	services := api.Services{
		Tenants: tenants, Fleet: fleetService, Policies: policies, Scans: scans, Catalog: options.Store,
		Events: options.Events, Coverage: coverage.NewService(fleetService, options.Store, options.Events),
		Preferences: preference.NewService(options.Store),
	}

	apiRoutes, err := apiHandler(options, services)
	if err != nil {
		return nil, err
	}
	events := audit.NewService(options.Store, options.Store, options.Events, options.Broker, options.Metrics)
	return &App{
		Tenants:    tenants,
		Fleet:      fleetService,
		Policies:   policies,
		Scans:      scans,
		Events:     events,
		APIHandler: apiRoutes,
		AgentHandler: agentapi.Handler(agentapi.Dependencies{
			Fleet: fleetService, Policies: policies, Scans: scans, Logger: options.Logger,
			Audit: events, Health: options.Store,
			Metrics:       options.Metrics,
			CACertificate: authority.CertificatePEM(), PolicyPublicKey: signer.PublicKey(),
		}),
	}, nil
}

func apiHandler(options Options, services api.Services) (http.Handler, error) {
	mux := http.NewServeMux()
	mux.Handle("/api/", api.Handler(api.New(services), options.Authenticator, options.Logger, options.Metrics))
	mux.HandleFunc("GET /ui-config", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": options.OIDCIssuer, "clientId": options.OIDCClientID})
	})
	if options.WebDirectory != "" {
		web, err := webHandler(options.WebDirectory, options.OIDCIssuer)
		if err != nil {
			return nil, err
		}
		mux.Handle("/", web)
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if err := errors.Join(options.Store.Ping(r.Context()), options.Events.Ping(r.Context()), options.Broker.Ping(r.Context())); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	return mux, nil
}

// webHandler serves the dashboard. Unknown paths return the page, because routes
// live in the browser. The policy allows scripts only from this origin, which
// limits what an injected value could do with the access token.
func webHandler(directory, issuer string) (http.Handler, error) {
	// os.Root refuses any path that leaves the directory, including through links.
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, fmt.Errorf("open web directory: %w", err)
	}
	files := http.FileServerFS(root.FS())
	provider := originOf(issuer)
	policy := "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
		"connect-src 'self' " + provider + "; frame-ancestors 'none'; base-uri 'none'; form-action " + provider
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", policy)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if _, err := root.Stat(name); name == "" || err != nil {
			http.ServeFileFS(w, r, root.FS(), "index.html")
			return
		}
		files.ServeHTTP(w, r)
	}), nil
}

// originOf reduces the issuer to its origin. A CSP source with a path matches that
// exact path only, which would block the provider's discovery document.
func originOf(issuer string) string {
	parsed, err := url.Parse(issuer)
	if err != nil || parsed.Host == "" {
		return "'none'"
	}
	return parsed.Scheme + "://" + parsed.Host
}

// AgentTLSConfig requires TLS 1.3. Client certificates are optional at the TLS
// layer only because enrollment happens before an agent has one; anything
// presented must still chain to the platform CA, and AgentService then refuses
// requests without it.
func AgentTLSConfig(pkiDirectory string) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(
		filepath.Join(pkiDirectory, pki.ServerCertFile),
		filepath.Join(pkiDirectory, pki.ServerKeyFile))
	if err != nil {
		return nil, fmt.Errorf("load server certificate: %w", err)
	}
	caPEM, err := os.ReadFile(filepath.Join(filepath.Clean(pkiDirectory), pki.CACertFile))
	if err != nil {
		return nil, fmt.Errorf("read ca: %w", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("ca file has no certificates")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		ClientCAs:    clientCAs,
		ClientAuth:   tls.VerifyClientCertIfGiven,
		NextProtos:   []string{"h2", "http/1.1"},
	}, nil
}

// Serve runs the public API, the agent endpoint and, when metricsAddress is set,
// the metrics endpoint until ctx ends. Metrics get a port of their own, so a
// scraper needs no access to the API and the API exposes no metrics.
func Serve(ctx context.Context, application *App, apiAddress, agentAddress, metricsAddress, pkiDirectory string, metrics *telemetry.Server) error {
	tlsConfig, err := AgentTLSConfig(pkiDirectory)
	if err != nil {
		return err
	}
	apiServer := &http.Server{Addr: apiAddress, Handler: application.APIHandler, ReadHeaderTimeout: readHeaderTimeout}
	agentServer := &http.Server{Addr: agentAddress, Handler: application.AgentHandler, ReadHeaderTimeout: readHeaderTimeout, TLSConfig: tlsConfig}

	servers := []*http.Server{apiServer, agentServer}
	group, groupContext := errgroup.WithContext(ctx)
	group.Go(func() error { return ignoreClosed(apiServer.ListenAndServe()) })
	group.Go(func() error { return ignoreClosed(agentServer.ListenAndServeTLS("", "")) })
	if metricsAddress != "" {
		mux := http.NewServeMux()
		mux.Handle("GET /metrics", metrics.Handler())
		metricsServer := &http.Server{Addr: metricsAddress, Handler: mux, ReadHeaderTimeout: readHeaderTimeout}
		servers = append(servers, metricsServer)
		group.Go(func() error { return ignoreClosed(metricsServer.ListenAndServe()) })
	}
	group.Go(func() error {
		<-groupContext.Done()
		shutdownContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
		defer cancel()
		var errs []error
		for _, server := range servers {
			errs = append(errs, server.Shutdown(shutdownContext))
		}
		return errors.Join(errs...)
	})
	return group.Wait()
}

func ignoreClosed(err error) error {
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
