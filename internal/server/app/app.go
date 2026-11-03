// Package app wires the server together. It is shared by the binary and the
// integration tests, so tests exercise the real composition.
package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sync/errgroup"

	"dataguard/internal/core/fleet"
	"dataguard/internal/core/policy"
	"dataguard/internal/core/tenant"
	"dataguard/internal/platform/pki"
	"dataguard/internal/server/agentapi"
	"dataguard/internal/server/api"
	"dataguard/internal/server/storage/postgres"
)

const (
	readHeaderTimeout = 10 * time.Second
	shutdownTimeout   = 15 * time.Second
)

// Options are the dependencies chosen by the caller.
type Options struct {
	Store          *postgres.Store
	PKIDirectory   string
	CertificateTTL time.Duration
	Authenticator  api.Authenticator
	Logger         *slog.Logger
}

// App holds the composed services and handlers.
type App struct {
	Tenants  *tenant.Service
	Fleet    *fleet.Service
	Policies *policy.Service

	APIHandler   http.Handler
	AgentHandler http.Handler
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
	fleetService := fleet.NewService(options.Store, agentapi.Issuer{Authority: authority})
	policies := policy.NewService(options.Store, signer)

	return &App{
		Tenants:    tenants,
		Fleet:      fleetService,
		Policies:   policies,
		APIHandler: apiHandler(options, tenants, fleetService),
		AgentHandler: agentapi.Handler(agentapi.Dependencies{
			Fleet: fleetService, Policies: policies, Logger: options.Logger,
			CACertificate: authority.CertificatePEM(), PolicyPublicKey: signer.PublicKey(),
		}),
	}, nil
}

func apiHandler(options Options, tenants *tenant.Service, fleetService *fleet.Service) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/api/", api.Handler(api.New(tenants, fleetService), options.Authenticator, options.Logger))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if err := options.Store.Ping(r.Context()); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	return mux
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

// Serve runs the public API and the agent endpoint until ctx ends.
func Serve(ctx context.Context, application *App, apiAddress, agentAddress, pkiDirectory string) error {
	tlsConfig, err := AgentTLSConfig(pkiDirectory)
	if err != nil {
		return err
	}
	apiServer := &http.Server{Addr: apiAddress, Handler: application.APIHandler, ReadHeaderTimeout: readHeaderTimeout}
	agentServer := &http.Server{Addr: agentAddress, Handler: application.AgentHandler, ReadHeaderTimeout: readHeaderTimeout, TLSConfig: tlsConfig}

	group, groupContext := errgroup.WithContext(ctx)
	group.Go(func() error { return ignoreClosed(apiServer.ListenAndServe()) })
	group.Go(func() error { return ignoreClosed(agentServer.ListenAndServeTLS("", "")) })
	group.Go(func() error {
		<-groupContext.Done()
		shutdownContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
		defer cancel()
		return errors.Join(apiServer.Shutdown(shutdownContext), agentServer.Shutdown(shutdownContext))
	})
	return group.Wait()
}

func ignoreClosed(err error) error {
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
