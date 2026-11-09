package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"dataguard/internal/platform/pki"
	"dataguard/internal/server/app"
)

// serveHTTPS answers /readyz with the dashboard's TLS settings and returns the
// address and the certificate file.
func serveHTTPS(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	if err := pki.Bootstrap(dir, []string{"127.0.0.1", "dashboard.example.com"}); err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(dir, pki.ServerCertFile)
	certificate, err := pki.LoadFileCertificate(certFile, filepath.Join(dir, pki.ServerKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
		ReadHeaderTimeout: time.Second,
	}
	go func() { _ = server.Serve(tls.NewListener(listener, app.APITLSConfig(certificate))) }()
	t.Cleanup(func() { _ = server.Close() })
	return listener.Addr().String(), certFile
}

// The container healthcheck reaches the API over HTTPS by its loopback address:
// it trusts the configured certificate under its own name, without the
// customer's CA and without switching verification off.
func TestReadyChecksTheAPIOverHTTPS(t *testing.T) {
	address, certFile := serveHTTPS(t)
	t.Setenv("DG_API_ADDR", address)
	t.Setenv("DG_API_TLS_CERT_FILE", certFile)
	if err := ready(t.Context()); err != nil {
		t.Fatalf("ready over https: %v", err)
	}

	// Another certificate under the same name does not pass.
	_, foreign := serveHTTPS(t)
	t.Setenv("DG_API_TLS_CERT_FILE", foreign)
	var unknown x509.UnknownAuthorityError
	if err := ready(t.Context()); err == nil || !errors.As(err, &unknown) {
		t.Fatalf("a certificate other than the configured one: %v", err)
	}
}
