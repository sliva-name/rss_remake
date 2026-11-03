// Package pki issues agent certificates and signs policies. The tenant and the
// agent id live inside the certificate, so a request cannot claim another
// tenant: the identity comes from the CA, not from the message.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	caLifetime     = 10 * 365 * 24 * time.Hour
	serverLifetime = 365 * 24 * time.Hour
	serialBits     = 128
	identityScheme = "spiffe"
	identityHost   = "dataguard"
	privateMode    = 0o600
	publicMode     = 0o644
	directoryMode  = 0o700

	blockCertificate = "CERTIFICATE"
	blockPrivateKey  = "PRIVATE KEY"
	blockCSR         = "CERTIFICATE REQUEST"
)

// ErrInvalidIdentity marks a certificate without a well-formed agent identity.
var ErrInvalidIdentity = errors.New("certificate has no valid agent identity")

// Identity is who a client certificate speaks for.
type Identity struct {
	TenantID uuid.UUID
	AgentID  uuid.UUID
}

func (i Identity) uri() *url.URL {
	return &url.URL{
		Scheme: identityScheme,
		Host:   identityHost,
		Path:   "/tenant/" + i.TenantID.String() + "/agent/" + i.AgentID.String(),
	}
}

// IdentityOf extracts the agent identity from a verified peer certificate.
func IdentityOf(cert *x509.Certificate) (Identity, error) {
	if len(cert.URIs) != 1 {
		return Identity{}, ErrInvalidIdentity
	}
	uri := cert.URIs[0]
	parts := strings.Split(strings.TrimPrefix(uri.Path, "/"), "/")
	if uri.Scheme != identityScheme || uri.Host != identityHost || len(parts) != 4 ||
		parts[0] != "tenant" || parts[2] != "agent" {
		return Identity{}, ErrInvalidIdentity
	}
	tenantID, err := uuid.Parse(parts[1])
	if err != nil {
		return Identity{}, ErrInvalidIdentity
	}
	agentID, err := uuid.Parse(parts[3])
	if err != nil {
		return Identity{}, ErrInvalidIdentity
	}
	return Identity{TenantID: tenantID, AgentID: agentID}, nil
}

// Authority is the platform's internal CA.
type Authority struct {
	certificate *x509.Certificate
	key         crypto.Signer
	lifetime    time.Duration
	now         func() time.Time
}

// LoadAuthority reads the CA from PEM files. lifetime bounds issued agent
// certificates.
func LoadAuthority(certPath, keyPath string, lifetime time.Duration) (*Authority, error) {
	certificate, err := ReadCertificate(certPath)
	if err != nil {
		return nil, fmt.Errorf("read ca certificate: %w", err)
	}
	key, err := ReadPrivateKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read ca key: %w", err)
	}
	return &Authority{certificate: certificate, key: key, lifetime: lifetime, now: time.Now}, nil
}

// CertificatePEM returns the CA certificate in PEM form.
func (a *Authority) CertificatePEM() []byte {
	return encodePEM(blockCertificate, a.certificate.Raw)
}

// IssueAgentCertificate signs csrPEM for identity. Only the public key is taken
// from the CSR; subject and SANs it may carry are ignored, so a client cannot
// request another identity.
func (a *Authority) IssueAgentCertificate(csrPEM []byte, identity Identity) ([]byte, time.Time, error) {
	publicKey, err := verifiedCSRKey(csrPEM)
	if err != nil {
		return nil, time.Time{}, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, time.Time{}, err
	}
	notBefore := a.now().Add(-time.Minute).UTC().Truncate(time.Second)
	notAfter := notBefore.Add(a.lifetime)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "agent " + identity.AgentID.String()},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{identity.uri()},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.certificate, publicKey, a.key)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("sign agent certificate: %w", err)
	}
	return encodePEM(blockCertificate, der), notAfter, nil
}

func verifiedCSRKey(csrPEM []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != blockCSR {
		return nil, errors.New("not a pem certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate request: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("verify certificate request: %w", err)
	}
	return csr.PublicKey, nil
}

// NewCSR creates a key pair and a certificate request. The key never leaves the
// agent; the CSR only proves possession of it.
func NewCSR() (csrPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate request: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("encode key: %w", err)
	}
	return encodePEM(blockCSR, der), encodePEM(blockPrivateKey, keyDER), nil
}

// Bootstrap creates a CA, a server certificate for hosts and a policy signing
// key in dir. It refuses to overwrite: replacing a CA silently would orphan
// every enrolled agent.
func Bootstrap(dir string, hosts []string) error {
	if _, err := os.Stat(filepath.Join(dir, CAKeyFile)); err == nil {
		return fmt.Errorf("%s already exists", CAKeyFile)
	}
	if err := os.MkdirAll(dir, directoryMode); err != nil {
		return fmt.Errorf("create pki directory: %w", err)
	}
	caCert, caKey, err := createCA(dir)
	if err != nil {
		return err
	}
	if err := createServerCertificate(dir, caCert, caKey, hosts); err != nil {
		return err
	}
	return createPolicyKey(dir)
}

// File names inside the directory produced by Bootstrap.
const (
	CACertFile     = "ca.crt"
	CAKeyFile      = "ca.key"
	ServerCertFile = "server.crt"
	ServerKeyFile  = "server.key"
	PolicyKeyFile  = "policy.key"
)

func createCA(dir string) (*x509.Certificate, crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ca key: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "DataGuard Internal CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(caLifetime),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, nil, fmt.Errorf("sign ca certificate: %w", err)
	}
	if err := writeKeyPair(dir, CACertFile, CAKeyFile, der, key); err != nil {
		return nil, nil, err
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ca certificate: %w", err)
	}
	return certificate, key, nil
}

func createServerCertificate(dir string, ca *x509.Certificate, caKey crypto.Signer, hosts []string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate server key: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "dataguard-server"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(serverLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, host)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, key.Public(), caKey)
	if err != nil {
		return fmt.Errorf("sign server certificate: %w", err)
	}
	return writeKeyPair(dir, ServerCertFile, ServerKeyFile, der, key)
}

func createPolicyKey(dir string) error {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate policy key: %w", err)
	}
	return writePrivateKey(filepath.Join(dir, PolicyKeyFile), key)
}

func writeKeyPair(dir, certName, keyName string, certificateDER []byte, key crypto.Signer) error {
	certPath := filepath.Join(dir, certName)
	if err := os.WriteFile(certPath, encodePEM(blockCertificate, certificateDER), publicMode); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}
	return writePrivateKey(filepath.Join(dir, keyName), key)
}

func writePrivateKey(path string, key crypto.Signer) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("encode private key: %w", err)
	}
	if err := os.WriteFile(path, encodePEM(blockPrivateKey, der), privateMode); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	return nil
}

// ReadCertificate loads a PEM certificate.
func ReadCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != blockCertificate {
		return nil, errors.New("not a pem certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

// ReadPrivateKey loads a PEM PKCS#8 private key.
func ReadPrivateKey(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != blockPrivateKey {
		return nil, errors.New("not a pem private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("key cannot sign")
	}
	return signer, nil
}

func newSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), serialBits))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	return serial, nil
}

func encodePEM(blockType string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}
