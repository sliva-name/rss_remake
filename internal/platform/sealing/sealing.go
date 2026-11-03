// Package sealing encrypts a database password so that only one agent can open
// it, and only for the target it was entered for. The center stores the result
// and cannot decrypt it.
//
// Format, version 1: 0x01 | ephemeral P-256 public point (65) | nonce (12) |
// AES-256-GCM ciphertext and tag. The key is HKDF-SHA256 over the ECDH secret,
// salted with both public points. The browser implements the same format in
// web/dashboard/src/sealing.ts; testdata/browser-v1.json pins them together.
package sealing

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"github.com/google/uuid"
)

const (
	version1    = 1
	pointSize   = 65
	nonceSize   = 12
	keySize     = 32
	tagSize     = 16
	info        = "dataguard sealed password v1"
	aadPrefix   = "dataguard-sealed-password-v1"
	minimumSize = 1 + pointSize + nonceSize + tagSize
	// MaxSecret bounds a password; anything longer is not a database password.
	MaxSecret = 1024
)

var (
	ErrMalformed = errors.New("sealed password is malformed")
	// ErrNotForThisTarget covers a wrong key, a changed target and tampering:
	// authenticated decryption cannot tell them apart, and need not.
	ErrNotForThisTarget = errors.New("sealed password does not open for this agent and target")
)

// Binding is what the password is sealed to. Changing any field, for example
// the host, makes the old ciphertext useless.
type Binding struct {
	TenantID uuid.UUID
	AgentID  uuid.UUID
	Engine   string
	Host     string
	Port     int
	Database string
	Username string
	TLS      string
}

// AAD is the associated data both sides authenticate. Fields are joined by
// newlines, so none of them may contain a control character.
func (b Binding) AAD() ([]byte, error) {
	fields := []string{
		aadPrefix, b.TenantID.String(), b.AgentID.String(), b.Engine, b.Host,
		strconv.Itoa(b.Port), b.Database, b.Username, b.TLS,
	}
	for _, field := range fields {
		if strings.ContainsFunc(field, unicode.IsControl) {
			return nil, fmt.Errorf("%w: control character in binding", ErrMalformed)
		}
	}
	return []byte(strings.Join(fields, "\n")), nil
}

// GenerateKey creates an agent's sealing key.
func GenerateKey() (*ecdh.PrivateKey, error) {
	return ecdh.P256().GenerateKey(rand.Reader)
}

// Seal encrypts secret for the agent owning agentPublic.
func Seal(agentPublic []byte, binding Binding, secret []byte) ([]byte, error) {
	if len(secret) == 0 || len(secret) > MaxSecret {
		return nil, fmt.Errorf("%w: secret length", ErrMalformed)
	}
	recipient, err := ecdh.P256().NewPublicKey(agentPublic)
	if err != nil {
		return nil, fmt.Errorf("%w: agent key", ErrMalformed)
	}
	ephemeral, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := ephemeral.ECDH(recipient)
	if err != nil {
		return nil, err
	}
	aead, err := newAEAD(shared, ephemeral.PublicKey().Bytes(), agentPublic)
	if err != nil {
		return nil, err
	}
	aad, err := binding.AAD()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	sealed := append([]byte{version1}, ephemeral.PublicKey().Bytes()...)
	sealed = append(sealed, nonce...)
	return aead.Seal(sealed, nonce, secret, aad), nil
}

// Open decrypts a sealed password. The caller must clear the result after use.
func Open(private *ecdh.PrivateKey, binding Binding, sealed []byte) ([]byte, error) {
	if len(sealed) < minimumSize || len(sealed) > minimumSize+MaxSecret || sealed[0] != version1 {
		return nil, ErrMalformed
	}
	ephemeralBytes := sealed[1 : 1+pointSize]
	ephemeral, err := ecdh.P256().NewPublicKey(ephemeralBytes)
	if err != nil {
		return nil, ErrMalformed
	}
	shared, err := private.ECDH(ephemeral)
	if err != nil {
		return nil, ErrMalformed
	}
	aead, err := newAEAD(shared, ephemeralBytes, private.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	aad, err := binding.AAD()
	if err != nil {
		return nil, err
	}
	nonce := sealed[1+pointSize : 1+pointSize+nonceSize]
	secret, err := aead.Open(nil, nonce, sealed[1+pointSize+nonceSize:], aad)
	if err != nil {
		return nil, ErrNotForThisTarget
	}
	return secret, nil
}

func newAEAD(shared, ephemeralPublic, agentPublic []byte) (cipher.AEAD, error) {
	salt := append(append([]byte{}, ephemeralPublic...), agentPublic...)
	key, err := hkdf.Key(sha256.New, shared, salt, info, keySize)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
