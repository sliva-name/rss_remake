package pki_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"dataguard/internal/platform/pki"
)

// A renewed dashboard certificate takes effect without a restart; a key that
// does not match yet leaves the previous certificate in service.
func TestFileCertificateFollowsRenewal(t *testing.T) {
	_, dir := newAuthority(t)
	certPath, keyPath := filepath.Join(dir, pki.ServerCertFile), filepath.Join(dir, pki.ServerKeyFile)
	served, err := pki.LoadFileCertificate(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	names := func() []string {
		t.Helper()
		certificate, err := served.GetCertificate(nil)
		if err != nil {
			t.Fatal(err)
		}
		return certificate.Leaf.DNSNames
	}
	if got := names(); !slices.Equal(got, []string{"dataguard.test"}) {
		t.Fatalf("names = %v", got)
	}

	if _, err := pki.EnsureServerCertificate(dir, []string{"dashboard.example.com"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := names(); !slices.Equal(got, []string{"dashboard.example.com"}) {
		t.Fatalf("after renewal names = %v", got)
	}

	stray, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(stray)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := names(); !slices.Equal(got, []string{"dashboard.example.com"}) {
		t.Fatalf("a half-replaced pair changed what is served: %v", got)
	}
}
