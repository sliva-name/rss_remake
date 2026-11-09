package policy_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"dataguard/internal/core/policy"
	"dataguard/internal/platform/pki"
)

type storedPolicy struct {
	policy.Repository
	latest   policy.Signed
	resigned []policy.Signed
}

func (r *storedPolicy) Latest(context.Context, uuid.UUID) (policy.Signed, error) {
	return r.latest, nil
}

func (r *storedPolicy) Resign(_ context.Context, _ uuid.UUID, signed policy.Signed) error {
	r.resigned = append(r.resigned, signed)
	return nil
}

func keysBeforeAndAfterRotation(t *testing.T) (before, after *pki.PolicyKeys) {
	t.Helper()
	dir := t.TempDir()
	if err := pki.Bootstrap(dir, []string{"127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	before, err := pki.LoadPolicyKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pki.RotatePolicyKey(dir); err != nil {
		t.Fatal(err)
	}
	after, err = pki.LoadPolicyKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	return before, after
}

// After rotation an agent trusts only the new key, so the latest policy, signed
// before, is checked with the old key and signed again with the new one.
func TestLatestPolicyIsSignedAgainAfterRotation(t *testing.T) {
	before, after := keysBeforeAndAfterRotation(t)
	payload := []byte("policy v1")
	repository := &storedPolicy{latest: policy.Signed{Version: 1, Payload: payload, Signature: before.Sign(payload), KeyEpoch: 1}}

	latest, err := policy.NewService(repository, after).Latest(t.Context(), uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if latest.KeyEpoch != 2 || pki.VerifyPolicy(after.PublicKey(), payload, latest.Signature) != nil {
		t.Fatalf("served epoch %d, not signed by the new key", latest.KeyEpoch)
	}
	if len(repository.resigned) != 1 || repository.resigned[0].KeyEpoch != 2 {
		t.Fatalf("stored again: %+v", repository.resigned)
	}
}

// Someone who can write the database but not read the key cannot slip a policy
// in by waiting for a rotation to sign it.
func TestTamperedPolicyIsNotSignedAgain(t *testing.T) {
	before, after := keysBeforeAndAfterRotation(t)
	repository := &storedPolicy{latest: policy.Signed{
		Version: 1, Payload: []byte("policy by an intruder"), Signature: before.Sign([]byte("policy v1")), KeyEpoch: 1,
	}}
	if _, err := policy.NewService(repository, after).Latest(t.Context(), uuid.New()); !errors.Is(err, policy.ErrTampered) {
		t.Fatalf("err = %v", err)
	}
	if len(repository.resigned) != 0 {
		t.Fatal("a tampered policy was signed with the new key")
	}
}

// An instance not restarted after rotation finds a newer signature than it can
// check. That is a pending restart, not tampering.
func TestInstanceStartedBeforeRotationAsksForRestart(t *testing.T) {
	before, after := keysBeforeAndAfterRotation(t)
	payload := []byte("policy v1")
	repository := &storedPolicy{latest: policy.Signed{Version: 1, Payload: payload, Signature: after.Sign(payload), KeyEpoch: 2}}
	if _, err := policy.NewService(repository, before).Latest(t.Context(), uuid.New()); !errors.Is(err, policy.ErrKeyRotated) {
		t.Fatalf("err = %v", err)
	}
}
