package pki_test

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"dataguard/internal/platform/pki"
)

func newAuthority(t *testing.T) (*pki.Authority, string) {
	t.Helper()
	dir := t.TempDir()
	if err := pki.Bootstrap(dir, []string{"127.0.0.1", "dataguard.test"}); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	authority, err := pki.LoadAuthority(filepath.Join(dir, pki.CACertFile), filepath.Join(dir, pki.CAKeyFile), time.Hour)
	if err != nil {
		t.Fatalf("LoadAuthority: %v", err)
	}
	return authority, dir
}

func parse(t *testing.T, certificatePEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certificatePEM)
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return certificate
}

func TestIssuedCertificateCarriesIdentityAndChainsToCA(t *testing.T) {
	authority, _ := newAuthority(t)
	identity := pki.Identity{TenantID: uuid.New(), AgentID: uuid.New()}
	csr, _, err := pki.NewCSR()
	if err != nil {
		t.Fatalf("NewCSR: %v", err)
	}

	certificatePEM, notAfter, err := authority.IssueAgentCertificate(csr, identity)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	certificate := parse(t, certificatePEM)
	got, err := pki.IdentityOf(certificate)
	if err != nil {
		t.Fatalf("IdentityOf: %v", err)
	}
	if got != identity {
		t.Fatalf("identity = %+v, want %+v", got, identity)
	}
	if !notAfter.Equal(certificate.NotAfter) || time.Until(notAfter) > time.Hour {
		t.Fatalf("unexpected lifetime: %s", notAfter)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parse(t, authority.CertificatePEM()))
	_, err = certificate.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestIssueRejectsGarbageCSR(t *testing.T) {
	authority, _ := newAuthority(t)
	if _, _, err := authority.IssueAgentCertificate([]byte("not a csr"), pki.Identity{}); err == nil {
		t.Fatal("expected an error")
	}
}

func TestIdentityOfRejectsForeignCertificate(t *testing.T) {
	if _, err := pki.IdentityOf(&x509.Certificate{}); !errors.Is(err, pki.ErrInvalidIdentity) {
		t.Fatalf("err = %v", err)
	}
}

func TestBootstrapRefusesToOverwrite(t *testing.T) {
	_, dir := newAuthority(t)
	if err := pki.Bootstrap(dir, nil); err == nil {
		t.Fatal("second Bootstrap must fail")
	}
}

func TestPolicySignature(t *testing.T) {
	_, dir := newAuthority(t)
	signer, err := pki.LoadPolicyKeys(dir)
	if err != nil {
		t.Fatalf("LoadPolicyKeys: %v", err)
	}
	payload := []byte("policy v1")
	signature := signer.Sign(payload)

	if err := pki.VerifyPolicy(signer.PublicKey(), payload, signature); err != nil {
		t.Fatalf("VerifyPolicy: %v", err)
	}
	if err := pki.VerifyPolicy(signer.PublicKey(), []byte("policy v2"), signature); !errors.Is(err, pki.ErrBadSignature) {
		t.Fatalf("tampered payload: err = %v", err)
	}
}
