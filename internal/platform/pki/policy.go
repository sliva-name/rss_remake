package pki

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"google.golang.org/protobuf/proto"

	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
)

// ErrBadSignature means a policy did not come from the holder of the signing key.
var ErrBadSignature = errors.New("policy signature is invalid")

// VerifyPolicy checks payload against the pinned public key.
func VerifyPolicy(publicKey, payload, signature []byte) error {
	if len(publicKey) != ed25519.PublicKeySize || !ed25519.Verify(publicKey, payload, signature) {
		return ErrBadSignature
	}
	return nil
}

// sourceListContext separates source list signatures from policy signatures
// made with the same key: a policy payload never starts with these bytes.
const sourceListContext = "dataguard source list v1\x00"

// SourceListSigningInput is what is signed and verified for a source list.
func SourceListSigningInput(payload []byte) []byte {
	return append([]byte(sourceListContext), payload...)
}

// endorsementContext separates endorsements of the next key from policies and
// source lists signed with the same key.
const endorsementContext = "dataguard policy key endorsement v1\x00"

func endorsementSigningInput(payload []byte) []byte {
	return append([]byte(endorsementContext), payload...)
}

// ErrBrokenChain means an endorsement does not follow from the key before it.
var ErrBrokenChain = errors.New("policy key endorsements do not form a chain")

// FollowEndorsements walks chain from a trusted key of a known epoch and returns
// the newest key it leads to. Endorsements of earlier epochs are skipped, each
// later one must be signed by the key of the epoch just before it.
func FollowEndorsements(trusted []byte, epoch uint32, chain []*agentv1.SignedEndorsement) ([]byte, uint32, error) {
	for _, signed := range chain {
		endorsement := &agentv1.PolicyKeyEndorsement{}
		if err := proto.Unmarshal(signed.GetEndorsement(), endorsement); err != nil {
			return nil, 0, fmt.Errorf("%w: undecodable endorsement", ErrBrokenChain)
		}
		if endorsement.GetEpoch() <= epoch {
			continue
		}
		if endorsement.GetEpoch() != epoch+1 || len(endorsement.GetPublicKey()) != ed25519.PublicKeySize {
			return nil, 0, fmt.Errorf("%w: epoch %d does not follow %d", ErrBrokenChain, endorsement.GetEpoch(), epoch)
		}
		if err := VerifyPolicy(trusted, endorsementSigningInput(signed.GetEndorsement()), signed.GetSignature()); err != nil {
			return nil, 0, fmt.Errorf("%w: epoch %d is not signed by epoch %d", ErrBrokenChain, epoch+1, epoch)
		}
		trusted, epoch = endorsement.GetPublicKey(), epoch+1
	}
	return trusted, epoch, nil
}

// File names of the policy key and its history inside the PKI directory.
const (
	PolicyKeyFile   = "policy.key"
	PolicyChainFile = "policy-chain.json"
	// policyNextKeyFile holds a new key while a rotation is in progress.
	policyNextKeyFile = "policy.key.next"
)

// chainFile is the policy key history. Root is the first key, epoch 1; each
// endorsement adds the next epoch. Only public keys are kept: a retired private
// key is deleted by the rotation that retires it.
type chainFile struct {
	Root         []byte         `json:"root_public_key"`
	Endorsements []signedOnDisk `json:"endorsements"`
}

type signedOnDisk struct {
	Endorsement []byte `json:"endorsement"`
	Signature   []byte `json:"signature"`
}

// PolicyKeys signs policies and source lists with the current key and keeps the
// public keys of all earlier epochs, to check what was signed before a rotation.
type PolicyKeys struct {
	current ed25519.PrivateKey
	// public[i] is the key of epoch i+1.
	public       []ed25519.PublicKey
	endorsements []*agentv1.SignedEndorsement
	// pending is set when the current key still sits in policyNextKeyFile.
	pending bool
}

// LoadPolicyKeys reads the current key and its history. A rotation stopped
// after the chain was written but before the new key took its place is
// completed in memory, so the server works from a read-only mount; the next
// rotation or pki-init moves the file.
func LoadPolicyKeys(directory string) (*PolicyKeys, error) {
	key, err := readEd25519(filepath.Join(directory, PolicyKeyFile))
	if err != nil {
		return nil, fmt.Errorf("load policy key: %w", err)
	}
	chain, err := readChain(directory, publicOf(key))
	if err != nil {
		return nil, err
	}
	keys := &PolicyKeys{current: key, public: []ed25519.PublicKey{chain.Root}}
	for _, signed := range chain.Endorsements {
		endorsement := &agentv1.SignedEndorsement{Endorsement: signed.Endorsement, Signature: signed.Signature}
		last := keys.public[len(keys.public)-1]
		next, epoch, err := FollowEndorsements(last, uint32(len(keys.public)), []*agentv1.SignedEndorsement{endorsement})
		if err != nil || int(epoch) != len(keys.public)+1 {
			return nil, fmt.Errorf("%s: %w", PolicyChainFile, ErrBrokenChain)
		}
		keys.public = append(keys.public, next)
		keys.endorsements = append(keys.endorsements, endorsement)
	}
	if !publicOf(key).Equal(keys.public[len(keys.public)-1]) {
		next, err := readEd25519(filepath.Join(directory, policyNextKeyFile))
		if err != nil || !publicOf(next).Equal(keys.public[len(keys.public)-1]) {
			return nil, errors.New("policy.key is not the newest key of policy-chain.json")
		}
		keys.current, keys.pending = next, true
	}
	return keys, nil
}

func readChain(directory string, onlyKey ed25519.PublicKey) (chainFile, error) {
	data, err := os.ReadFile(filepath.Join(filepath.Clean(directory), PolicyChainFile))
	if errors.Is(err, os.ErrNotExist) {
		// Never rotated: the one key is epoch 1.
		return chainFile{Root: onlyKey}, nil
	}
	if err != nil {
		return chainFile{}, fmt.Errorf("read %s: %w", PolicyChainFile, err)
	}
	var chain chainFile
	if err := json.Unmarshal(data, &chain); err != nil || len(chain.Root) != ed25519.PublicKeySize {
		return chainFile{}, fmt.Errorf("%s is malformed", PolicyChainFile)
	}
	return chain, nil
}

func readEd25519(path string) (ed25519.PrivateKey, error) {
	key, err := ReadPrivateKey(path)
	if err != nil {
		return nil, err
	}
	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("policy key is not ed25519")
	}
	return edKey, nil
}

func publicOf(key ed25519.PrivateKey) ed25519.PublicKey {
	public, _ := key.Public().(ed25519.PublicKey)
	return public
}

// Sign returns the signature of payload by the current key.
func (k *PolicyKeys) Sign(payload []byte) []byte {
	return ed25519.Sign(k.current, payload)
}

// PublicKey is the current key, the one an enrolling agent pins.
func (k *PolicyKeys) PublicKey() []byte {
	return publicOf(k.current)
}

// Epoch of the current key; the first key is epoch 1.
func (k *PolicyKeys) Epoch() uint32 {
	return uint32(len(k.public))
}

// Endorsements lead from the first key to the current one, oldest first.
func (k *PolicyKeys) Endorsements() []*agentv1.SignedEndorsement {
	return k.endorsements
}

// Verify checks a signature made by the key of epoch.
func (k *PolicyKeys) Verify(epoch uint32, payload, signature []byte) error {
	if epoch == 0 || int(epoch) > len(k.public) {
		return ErrBadSignature
	}
	return VerifyPolicy(k.public[epoch-1], payload, signature)
}

// RotatePolicyKey replaces the policy key with a new one endorsed by it and
// returns the new epoch. The steps survive a crash at any point: the new key is
// written aside first, then the chain that names it, then it takes the place of
// the old key, whose private half is gone afterwards. A rotation interrupted
// after the chain was written is finished instead of starting another one.
func RotatePolicyKey(directory string) (uint32, error) {
	keys, err := LoadPolicyKeys(directory)
	if err != nil {
		return 0, err
	}
	nextPath := filepath.Join(directory, policyNextKeyFile)
	if keys.pending {
		return keys.Epoch(), os.Rename(nextPath, filepath.Join(directory, PolicyKeyFile))
	}
	_, next, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return 0, fmt.Errorf("generate policy key: %w", err)
	}
	if err := writeKeyAtomic(nextPath, next); err != nil {
		return 0, err
	}
	epoch := keys.Epoch() + 1
	endorsement, err := proto.MarshalOptions{Deterministic: true}.Marshal(&agentv1.PolicyKeyEndorsement{Epoch: epoch, PublicKey: publicOf(next)})
	if err != nil {
		return 0, fmt.Errorf("encode endorsement: %w", err)
	}
	chain := chainFile{Root: keys.public[0]}
	for _, signed := range keys.endorsements {
		chain.Endorsements = append(chain.Endorsements, signedOnDisk{Endorsement: signed.GetEndorsement(), Signature: signed.GetSignature()})
	}
	chain.Endorsements = append(chain.Endorsements, signedOnDisk{
		Endorsement: endorsement, Signature: ed25519.Sign(keys.current, endorsementSigningInput(endorsement)),
	})
	data, err := json.MarshalIndent(chain, "", "  ")
	if err != nil {
		return 0, fmt.Errorf("encode %s: %w", PolicyChainFile, err)
	}
	if err := writeFileAtomic(filepath.Join(directory, PolicyChainFile), data, publicMode); err != nil {
		return 0, err
	}
	if err := os.Rename(nextPath, filepath.Join(directory, PolicyKeyFile)); err != nil {
		return 0, fmt.Errorf("replace policy key: %w", err)
	}
	return epoch, nil
}

// FinishPolicyKeyRotation moves a new key into place when a rotation stopped
// just before doing it. pki-init runs it on every start.
func FinishPolicyKeyRotation(directory string) (bool, error) {
	keys, err := LoadPolicyKeys(directory)
	if err != nil || !keys.pending {
		return false, err
	}
	return true, os.Rename(filepath.Join(directory, policyNextKeyFile), filepath.Join(directory, PolicyKeyFile))
}

func writeKeyAtomic(path string, key ed25519.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("encode policy key: %w", err)
	}
	return writeFileAtomic(path, encodePEM(blockPrivateKey, der), privateMode)
}
