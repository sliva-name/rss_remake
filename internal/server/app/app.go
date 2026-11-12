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

	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"

	"dataguard/internal/core/audit"
	"dataguard/internal/core/coverage"
	"dataguard/internal/core/fleet"
	"dataguard/internal/core/oplog"
	"dataguard/internal/core/policy"
	"dataguard/internal/core/preference"
	"dataguard/internal/core/scan"
	"dataguard/internal/core/tenant"
	"dataguard/internal/platform/pki"
	"dataguard/internal/server/agentapi"
	"dataguard/internal/server/api"
	"dataguard/internal/server/background"
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
	// TaskPeriod replaces the period of every background task when set, so
	// tests need not wait for production periods.
	TaskPeriod time.Duration
}

// App holds the composed services and handlers.
type App struct {
	Tenants  *tenant.Service
	Fleet    *fleet.Service
	Policies *policy.Service
	Scans    *scan.Service
	// Events stores what the broker consumer reads.
	Events  *audit.Service
	Journal *oplog.Service

	APIHandler   http.Handler
	AgentHandler http.Handler

	pkiDirectory       string
	serverCertificates *pki.ServerCertificates
	logger             *slog.Logger
	metrics            *telemetry.Server
	taskPeriod         time.Duration
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
	signer, err := pki.LoadPolicyKeys(options.PKIDirectory)
	if err != nil {
		return nil, err
	}
	serverCertificates, err := pki.LoadServerCertificates(options.PKIDirectory, authority)
	if err != nil {
		return nil, err
	}
	tenants := tenant.NewService(options.Store)
	fleetService := fleet.NewService(options.Store, agentapi.Issuer{Authority: authority}, signer)
	policies := policy.NewService(options.Store, signer)
	scans := scan.NewService(options.Store, options.Store)
	journal := oplog.NewService(options.Store)
	services := api.Services{
		Tenants: tenants, Fleet: fleetService, Policies: policies, Scans: scans, Catalog: options.Store,
		Events: options.Events, Coverage: coverage.NewService(fleetService, options.Store, options.Events),
		Preferences: preference.NewService(options.Store), Journal: journal,
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
		Journal:    journal,
		APIHandler: apiRoutes,
		AgentHandler: agentapi.Handler(agentapi.Dependencies{
			Fleet: fleetService, Policies: policies, Scans: scans, Logger: options.Logger,
			Audit: events, Health: options.Store,
			Metrics:       options.Metrics,
			CACertificate: authority.CertificatePEM(), PolicyKeys: signer,
		}),
		pkiDirectory:       options.PKIDirectory,
		serverCertificates: serverCertificates,
		logger:             options.Logger,
		metrics:            options.Metrics,
		taskPeriod:         options.TaskPeriod,
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
// requests without it. The server certificate comes from a source that renews
// it, so the endpoint outlives any one certificate.
func (a *App) AgentTLSConfig() (*tls.Config, error) {
	caPEM, err := os.ReadFile(filepath.Join(filepath.Clean(a.pkiDirectory), pki.CACertFile))
	if err != nil {
		return nil, fmt.Errorf("read ca: %w", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("ca file has no certificates")
	}
	return &tls.Config{
		MinVersion:     tls.VersionTLS13,
		GetCertificate: a.serverCertificates.GetCertificate,
		ClientCAs:      clientCAs,
		ClientAuth:     tls.VerifyClientCertIfGiven,
		NextProtos:     []string{"h2", "http/1.1"},
	}, nil
}

// How often each background task looks for work. A scheduled scan starts at
// most scheduleCheck late; a draft stays at most draftCheck past its hour.
const (
	scheduleCheck    = 30 * time.Second
	draftCheck       = 5 * time.Minute
	certificateCheck = time.Hour
)

// RunBackground runs the server's periodic tasks until ctx ends (ADR-0016).
func (a *App) RunBackground(ctx context.Context) {
	background.Run(ctx, []background.Task{
		{Name: "scan_schedule", Every: a.period(scheduleCheck), Run: a.forEachTenant(func(ctx context.Context, tenantID uuid.UUID) error {
			queued, err := a.Scans.RunSchedules(ctx, tenantID)
			a.metrics.ScansScheduled(queued)
			return err
		})},
		{Name: "draft_cleanup", Every: a.period(draftCheck), Run: a.forEachTenant(func(ctx context.Context, tenantID uuid.UUID) error {
			_, err := a.Fleet.RemoveStaleDrafts(ctx, tenantID)
			return err
		})},
		{Name: "server_certificate", Every: a.period(certificateCheck), Run: a.renewServerCertificate},
	}, a.metrics, a.logger)
}

func (a *App) period(production time.Duration) time.Duration {
	if a.taskPeriod > 0 {
		return a.taskPeriod
	}
	return production
}

// forEachTenant runs work for every organization in turn, each under its own
// row security, so a task reads no more than a request of that organization
// could. One that fails does not stop the rest.
func (a *App) forEachTenant(work func(ctx context.Context, tenantID uuid.UUID) error) func(context.Context) error {
	return func(ctx context.Context) error {
		tenants, err := a.Tenants.ListTenants(ctx)
		if err != nil {
			return err
		}
		var errs []error
		for _, organization := range tenants {
			errs = append(errs, work(ctx, organization.ID))
		}
		return errors.Join(errs...)
	}
}

// renewServerCertificate keeps the agent endpoint's certificate fresh. Each
// instance holds its own certificate in memory, so each renews its own.
func (a *App) renewServerCertificate(context.Context) error {
	renewed, err := a.serverCertificates.RenewIfDue(time.Now())
	if renewed {
		a.logger.Info("server certificate renewed")
	}
	return err
}

// ServeOptions are where the server listens.
type ServeOptions struct {
	// APIAddress serves the dashboard and the REST API: over HTTPS when
	// APICertificate is set, which an installation needs, over HTTP otherwise.
	APIAddress     string
	APICertificate *pki.FileCertificate
	AgentAddress   string
	// MetricsAddress may be empty.
	MetricsAddress string
}

// APITLSConfig serves the dashboard's certificate. Browsers and the identity
// provider's redirects reach this port, so TLS 1.2 is still accepted here;
// the agent endpoint, which only agents reach, requires 1.3.
func APITLSConfig(certificate *pki.FileCertificate) *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: certificate.GetCertificate,
		NextProtos:     []string{"h2", "http/1.1"},
	}
}

// hstsMaxAge is a year: browsers keep using HTTPS for the dashboard's address
// even when someone types http:// or follows such a link.
const hstsMaxAge = "max-age=31536000"

func strictTransport(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", hstsMaxAge)
		next.ServeHTTP(w, r)
	})
}

// Serve runs the public API, the agent endpoint, the background tasks and,
// when a metrics address is set, the metrics endpoint until ctx ends. Metrics
// get a port of their own, so a scraper needs no access to the API and the API
// exposes no metrics.
func Serve(ctx context.Context, application *App, options ServeOptions, metrics *telemetry.Server) error {
	tlsConfig, err := application.AgentTLSConfig()
	if err != nil {
		return err
	}
	apiServer := &http.Server{Addr: options.APIAddress, Handler: application.APIHandler, ReadHeaderTimeout: readHeaderTimeout}
	if options.APICertificate != nil {
		apiServer.Handler = strictTransport(application.APIHandler)
		apiServer.TLSConfig = APITLSConfig(options.APICertificate)
	}
	agentServer := &http.Server{Addr: options.AgentAddress, Handler: application.AgentHandler, ReadHeaderTimeout: readHeaderTimeout, TLSConfig: tlsConfig}

	servers := []*http.Server{apiServer, agentServer}
	group, groupContext := errgroup.WithContext(ctx)
	group.Go(func() error {
		if apiServer.TLSConfig != nil {
			return ignoreClosed(apiServer.ListenAndServeTLS("", ""))
		}
		return ignoreClosed(apiServer.ListenAndServe())
	})
	group.Go(func() error { return ignoreClosed(agentServer.ListenAndServeTLS("", "")) })
	group.Go(func() error { application.RunBackground(groupContext); return nil })
	if options.MetricsAddress != "" {
		mux := http.NewServeMux()
		mux.Handle("GET /metrics", metrics.Handler())
		metricsServer := &http.Server{Addr: options.MetricsAddress, Handler: mux, ReadHeaderTimeout: readHeaderTimeout}
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
