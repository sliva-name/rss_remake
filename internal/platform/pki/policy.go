package pki

import (
	"crypto/ed25519"
	"errors"
)

// ErrBadSignature means a policy did not come from the holder of the signing key.
var ErrBadSignature = errors.New("policy signature is invalid")

// PolicySigner signs serialized policies.
type PolicySigner struct {
	key ed25519.PrivateKey
}

// LoadPolicySigner reads the Ed25519 key created by Bootstrap.
func LoadPolicySigner(path string) (*PolicySigner, error) {
	key, err := ReadPrivateKey(path)
	if err != nil {
		return nil, err
	}
	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("policy key is not ed25519")
	}
	return &PolicySigner{key: edKey}, nil
}

// Sign returns the signature of payload.
func (s *PolicySigner) Sign(payload []byte) []byte {
	return ed25519.Sign(s.key, payload)
}

// PublicKey returns the key agents pin at enrollment.
func (s *PolicySigner) PublicKey() []byte {
	public, ok := s.key.Public().(ed25519.PublicKey)
	if !ok {
		return nil
	}
	return public
}

// VerifyPolicy checks payload against the pinned public key.
func VerifyPolicy(publicKey, payload, signature []byte) error {
	if len(publicKey) != ed25519.PublicKeySize || !ed25519.Verify(publicKey, payload, signature) {
		return ErrBadSignature
	}
	return nil
}
