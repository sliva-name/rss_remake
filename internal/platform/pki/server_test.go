package pki_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"dataguard/internal/platform/pki"
)

const halfAYear = 200 * 24 * time.Hour

func servedLeaf(t *testing.T, dir string) *x509.Certificate {
	t.Helper()
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, pki.ServerCertFile), filepath.Join(dir, pki.ServerKeyFile))
	if err != nil {
		t.Fatalf("server key pair: %v", err)
	}
	return pair.Leaf
}

func TestServerCertificateIsRenewedWhenDueOrHostsChange(t *testing.T) {
	_, dir := newAuthority(t)
	hosts := []string{"127.0.0.1", "dataguard.test"}
	first := servedLeaf(t, dir)

	if renewed, err := pki.EnsureServerCertificate(dir, hosts, time.Now()); err != nil || renewed {
		t.Fatalf("a fresh certificate was replaced: %v, %v", renewed, err)
	}
	if renewed, err := pki.EnsureServerCertificate(dir, hosts, time.Now().Add(halfAYear)); err != nil || !renewed {
		t.Fatalf("a certificate past half its life was kept: %v, %v", renewed, err)
	}
	second := servedLeaf(t, dir)
	if second.SerialNumber.Cmp(first.SerialNumber) == 0 || !slices.Equal(second.DNSNames, []string{"dataguard.test"}) {
		t.Fatalf("renewed certificate: serial %v, names %v", second.SerialNumber, second.DNSNames)
	}

	if renewed, err := pki.EnsureServerCertificate(dir, []string{"center.example.com"}, time.Now()); err != nil || !renewed {
		t.Fatalf("a new host list was ignored: %v, %v", renewed, err)
	}
	if names := servedLeaf(t, dir).DNSNames; !slices.Equal(names, []string{"center.example.com"}) || len(servedLeaf(t, dir).IPAddresses) != 0 {
		t.Fatalf("names = %v", names)
	}
}

// A crash between writing the key and the certificate leaves a pair that does
// not match; the next run repairs it instead of leaving the server unable to start.
func TestServerCertificateMismatchIsRepaired(t *testing.T) {
	_, dir := newAuthority(t)
	stray, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(stray)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, pki.ServerKeyFile), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if renewed, err := pki.EnsureServerCertificate(dir, []string{"127.0.0.1", "dataguard.test"}, time.Now()); err != nil || !renewed {
		t.Fatalf("mismatched pair: %v, %v", renewed, err)
	}
	servedLeaf(t, dir)
}

// The running server renews in memory: it mounts the PKI directory read-only
// and may run for longer than a certificate lives.
func TestRunningServerRenewsItsCertificate(t *testing.T) {
	authority, dir := newAuthority(t)
	certificates, err := pki.LoadServerCertificates(dir, authority)
	if err != nil {
		t.Fatal(err)
	}
	first := certificates.Leaf()
	if renewed, err := certificates.RenewIfDue(time.Now()); err != nil || renewed {
		t.Fatalf("renewed too early: %v, %v", renewed, err)
	}
	if renewed, err := certificates.RenewIfDue(time.Now().Add(halfAYear)); err != nil || !renewed {
		t.Fatalf("not renewed when due: %v, %v", renewed, err)
	}
	served, err := certificates.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if served.Leaf.SerialNumber.Cmp(first.SerialNumber) == 0 || !slices.Equal(served.Leaf.DNSNames, first.DNSNames) ||
		!served.Leaf.IPAddresses[0].Equal(first.IPAddresses[0]) {
		t.Fatalf("renewed certificate does not replace the first one for the same names")
	}
	ca, err := pki.ReadCertificate(filepath.Join(dir, pki.CACertFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := served.Leaf.CheckSignatureFrom(ca); err != nil {
		t.Fatalf("renewed certificate does not chain to the CA: %v", err)
	}
}
