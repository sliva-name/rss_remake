package pki_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"

	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
	"dataguard/internal/platform/pki"
)

func TestRotatedKeyIsReachedFromAnyEarlierOne(t *testing.T) {
	_, dir := newAuthority(t)
	first, err := pki.LoadPolicyKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	signedBefore := first.Sign([]byte("policy v1"))
	for want := uint32(2); want <= 3; want++ {
		epoch, err := pki.RotatePolicyKey(dir)
		if err != nil || epoch != want {
			t.Fatalf("rotation to %d: epoch %d, %v", want, epoch, err)
		}
	}
	keys, err := pki.LoadPolicyKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	if keys.Epoch() != 3 || len(keys.Endorsements()) != 2 {
		t.Fatalf("epoch %d with %d endorsements", keys.Epoch(), len(keys.Endorsements()))
	}
	// An agent that pinned the first key walks to the newest one.
	key, epoch, err := pki.FollowEndorsements(first.PublicKey(), 1, keys.Endorsements())
	if err != nil || epoch != 3 || !ed25519.PublicKey(key).Equal(ed25519.PublicKey(keys.PublicKey())) {
		t.Fatalf("walk from epoch 1: epoch %d, %v", epoch, err)
	}
	// What the old key signed is still checked against it, never against the new one.
	if err := keys.Verify(1, []byte("policy v1"), signedBefore); err != nil {
		t.Fatalf("an epoch-1 signature: %v", err)
	}
	if err := pki.VerifyPolicy(keys.PublicKey(), []byte("policy v1"), signedBefore); !errors.Is(err, pki.ErrBadSignature) {
		t.Fatal("the new key accepts what the old key signed")
	}
}

// An endorsement must be signed by the key of the epoch before it: a center
// that holds a stranger key cannot make agents trust it.
func TestEndorsementByAnotherKeyIsRefused(t *testing.T) {
	_, dir := newAuthority(t)
	keys, err := pki.LoadPolicyKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	public, stranger, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	endorsement, err := proto.Marshal(&agentv1.PolicyKeyEndorsement{Epoch: 2, PublicKey: public})
	if err != nil {
		t.Fatal(err)
	}
	forged := &agentv1.SignedEndorsement{Endorsement: endorsement, Signature: ed25519.Sign(stranger, endorsement)}
	if _, _, err := pki.FollowEndorsements(keys.PublicKey(), 1, []*agentv1.SignedEndorsement{forged}); !errors.Is(err, pki.ErrBrokenChain) {
		t.Fatalf("a self-signed endorsement: %v", err)
	}
	// Skipping an epoch is refused as well.
	if _, err := pki.RotatePolicyKey(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := pki.RotatePolicyKey(dir); err != nil {
		t.Fatal(err)
	}
	rotated, err := pki.LoadPolicyKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := pki.FollowEndorsements(keys.PublicKey(), 1, rotated.Endorsements()[1:]); !errors.Is(err, pki.ErrBrokenChain) {
		t.Fatalf("a chain with a missing epoch: %v", err)
	}
}

// A crash after the chain names the new key but before it replaces the old one
// leaves the server working with the new key, and the next run finishes the move.
func TestInterruptedRotationIsFinished(t *testing.T) {
	_, dir := newAuthority(t)
	keyPath := filepath.Join(dir, pki.PolicyKeyFile)
	old, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pki.RotatePolicyKey(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(keyPath, keyPath+".next"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, old, 0o600); err != nil {
		t.Fatal(err)
	}

	keys, err := pki.LoadPolicyKeys(dir)
	if err != nil {
		t.Fatalf("interrupted rotation: %v", err)
	}
	if keys.Epoch() != 2 || keys.Verify(2, []byte("x"), keys.Sign([]byte("x"))) != nil {
		t.Fatal("the server does not sign with the key the chain names")
	}
	finished, err := pki.FinishPolicyKeyRotation(dir)
	if err != nil || !finished {
		t.Fatalf("finish: %v, %v", finished, err)
	}
	if _, err := os.Stat(keyPath + ".next"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the new key was not moved into place")
	}
	again, err := pki.LoadPolicyKeys(dir)
	if err != nil || again.Epoch() != 2 {
		t.Fatalf("after finishing: %v", err)
	}
}
