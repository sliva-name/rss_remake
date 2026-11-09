package pki

import (
	"crypto/tls"
	"fmt"
	"os"
	"sync"
	"time"
)

// FileCertificate serves a certificate the customer issues and renews, such as
// the dashboard's. It reads the files again when either one changes, so a
// renewed certificate takes effect without a restart. Files replaced one after
// the other may briefly not match: the previous certificate is served until
// they do.
type FileCertificate struct {
	certPath, keyPath string

	mu       sync.Mutex
	current  *tls.Certificate
	modified [2]time.Time
}

// LoadFileCertificate reads the pair once, so a wrong path fails at start.
func LoadFileCertificate(certPath, keyPath string) (*FileCertificate, error) {
	file := &FileCertificate{certPath: certPath, keyPath: keyPath}
	if err := file.reload(); err != nil {
		return nil, err
	}
	return file, nil
}

// GetCertificate satisfies tls.Config.GetCertificate.
func (f *FileCertificate) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if modified, err := f.modifiedAt(); err == nil && modified != f.modified {
		_ = f.reloadLocked()
	}
	return f.current, nil
}

func (f *FileCertificate) reload() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reloadLocked()
}

func (f *FileCertificate) reloadLocked() error {
	modified, err := f.modifiedAt()
	if err != nil {
		return err
	}
	certificate, err := tls.LoadX509KeyPair(f.certPath, f.keyPath)
	if err != nil {
		return fmt.Errorf("load certificate: %w", err)
	}
	f.current, f.modified = &certificate, modified
	return nil
}

func (f *FileCertificate) modifiedAt() ([2]time.Time, error) {
	var modified [2]time.Time
	for i, path := range []string{f.certPath, f.keyPath} {
		info, err := os.Stat(path)
		if err != nil {
			return modified, fmt.Errorf("certificate file: %w", err)
		}
		modified[i] = info.ModTime()
	}
	return modified, nil
}
