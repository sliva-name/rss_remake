package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

// ServerCertificates serves the agent endpoint's certificate and renews it in
// memory before it expires. The server keeps running for longer than one
// certificate lives, and it mounts the PKI directory read-only, so it does not
// wait for pki-init to write a new file: it issues the next certificate from the
// CA itself, for the same names.
type ServerCertificates struct {
	authority *Authority
	mu        sync.RWMutex
	current   *tls.Certificate
}

// LoadServerCertificates starts from the certificate pki-init wrote.
func LoadServerCertificates(directory string, authority *Authority) (*ServerCertificates, error) {
	certificate, err := tls.LoadX509KeyPair(filepath.Join(directory, ServerCertFile), filepath.Join(directory, ServerKeyFile))
	if err != nil {
		return nil, fmt.Errorf("load server certificate: %w", err)
	}
	return &ServerCertificates{authority: authority, current: &certificate}, nil
}

// GetCertificate satisfies tls.Config.GetCertificate.
func (s *ServerCertificates) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current, nil
}

// Leaf is the certificate being served.
func (s *ServerCertificates) Leaf() *x509.Certificate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current.Leaf
}

// RenewIfDue issues a new certificate once half of the current one's lifetime
// has passed, as agents do with theirs.
func (s *ServerCertificates) RenewIfDue(now time.Time) (bool, error) {
	leaf := s.Leaf()
	if !renewalDue(leaf, now) {
		return false, nil
	}
	certificate, err := s.authority.issueServerCertificate(leaf.DNSNames, leaf.IPAddresses)
	if err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.current = certificate
	return true, nil
}

func renewalDue(leaf *x509.Certificate, now time.Time) bool {
	return now.After(leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) / 2))
}

// issueServerCertificate signs a fresh key for the given names.
func (a *Authority) issueServerCertificate(dnsNames []string, addresses []net.IP) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate server key: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	notBefore := a.now().Add(-time.Minute).UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "dataguard-server"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(serverLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  addresses,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.certificate, key.Public(), a.key)
	if err != nil {
		return nil, fmt.Errorf("sign server certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse server certificate: %w", err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// EnsureServerCertificate rewrites the server certificate in directory when it
// is missing, past half of its lifetime, does not match its key, or names other
// hosts than requested. pki-init runs it on every start, so a restarted server
// begins with a fresh certificate and a changed host list takes effect.
func EnsureServerCertificate(directory string, hosts []string, now time.Time) (bool, error) {
	authority, err := LoadAuthority(filepath.Join(directory, CACertFile), filepath.Join(directory, CAKeyFile), time.Hour)
	if err != nil {
		return false, err
	}
	dnsNames, addresses := splitHosts(hosts)
	existing, err := tls.LoadX509KeyPair(filepath.Join(directory, ServerCertFile), filepath.Join(directory, ServerKeyFile))
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		// A key and a certificate that do not match: a crash between writing
		// the two. Issuing anew repairs it.
	case !renewalDue(existing.Leaf, now) && sameHosts(existing.Leaf, dnsNames, addresses) && existing.Leaf.CheckSignatureFrom(authority.certificate) == nil:
		return false, nil
	}
	certificate, err := authority.issueServerCertificate(dnsNames, addresses)
	if err != nil {
		return false, err
	}
	key, ok := certificate.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return false, errors.New("server key is not ecdsa")
	}
	// The key first: a crash before the certificate leaves a pair that does not
	// match, which the next run detects and repairs.
	if err := writePrivateKeyAtomic(filepath.Join(directory, ServerKeyFile), key); err != nil {
		return false, err
	}
	if err := writeFileAtomic(filepath.Join(directory, ServerCertFile), encodePEM(blockCertificate, certificate.Certificate[0]), publicMode); err != nil {
		return false, err
	}
	return true, nil
}

func splitHosts(hosts []string) ([]string, []net.IP) {
	var dnsNames []string
	var addresses []net.IP
	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			addresses = append(addresses, ip)
		} else {
			dnsNames = append(dnsNames, host)
		}
	}
	return dnsNames, addresses
}

func sameHosts(leaf *x509.Certificate, dnsNames []string, addresses []net.IP) bool {
	return slices.Equal(leaf.DNSNames, dnsNames) &&
		slices.EqualFunc(leaf.IPAddresses, addresses, func(a, b net.IP) bool { return a.Equal(b) })
}

func writePrivateKeyAtomic(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("encode private key: %w", err)
	}
	return writeFileAtomic(path, encodePEM(blockPrivateKey, der), privateMode)
}

// writeFileAtomic renames over the target, so a reader sees the old or the new
// file, never a part of one.
func writeFileAtomic(path string, content []byte, mode os.FileMode) error {
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, content, mode); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("replace %s: %w", filepath.Base(path), err)
	}
	return nil
}
