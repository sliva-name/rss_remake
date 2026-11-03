package fleet_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"dataguard/internal/core/fleet"
)

type fakeRepository struct {
	fleet.Repository
	consumed    [][]byte
	consumeErr  error
	agent       fleet.Agent
	createdWith []fleet.Agent
}

func (r *fakeRepository) CreateEnrollmentToken(context.Context, uuid.UUID, uuid.UUID, []byte, time.Time) error {
	return nil
}

func (r *fakeRepository) ConsumeEnrollmentToken(_ context.Context, _ uuid.UUID, hash []byte) (uuid.UUID, error) {
	r.consumed = append(r.consumed, hash)
	return uuid.New(), r.consumeErr
}

func (r *fakeRepository) CreateAgent(_ context.Context, agent fleet.Agent) error {
	r.createdWith = append(r.createdWith, agent)
	return nil
}

func (r *fakeRepository) GetAgent(context.Context, uuid.UUID, uuid.UUID) (fleet.Agent, error) {
	return r.agent, nil
}

type fakeIssuer struct{ err error }

func (i fakeIssuer) Issue([]byte, uuid.UUID, uuid.UUID) ([]byte, time.Time, error) {
	return []byte("cert"), time.Now().Add(time.Hour), i.err
}

func TestTokenEmbedsTenantAndIsOnlyStoredHashed(t *testing.T) {
	repository := &fakeRepository{}
	service := fleet.NewService(repository, fakeIssuer{})
	tenantID := uuid.New()

	token, _, err := service.CreateEnrollmentToken(context.Background(), tenantID, uuid.New())
	if err != nil {
		t.Fatalf("CreateEnrollmentToken: %v", err)
	}

	enrollment, err := service.Enroll(context.Background(), token, []byte("csr"), "1.0")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if enrollment.TenantID != tenantID {
		t.Fatalf("tenant = %s, want %s", enrollment.TenantID, tenantID)
	}
	if strings.Contains(string(repository.consumed[0]), token) {
		t.Fatal("token must reach the repository hashed")
	}
	if got := repository.createdWith[0].Status; got != fleet.StatusActive {
		t.Fatalf("status = %s", got)
	}
}

func TestEnrollRejectsMalformedToken(t *testing.T) {
	service := fleet.NewService(&fakeRepository{}, fakeIssuer{})
	for _, token := range []string{"", "no-separator", "nothex_secret"} {
		if _, err := service.Enroll(context.Background(), token, nil, ""); !errors.Is(err, fleet.ErrInvalidToken) {
			t.Errorf("token %q: err = %v", token, err)
		}
	}
}

func TestEnrollDoesNotCreateAgentWhenCSRIsRejected(t *testing.T) {
	repository := &fakeRepository{}
	service := fleet.NewService(repository, fakeIssuer{err: errors.New("bad csr")})
	token := uuid.New().String() + "_secret"

	if _, err := service.Enroll(context.Background(), token, nil, ""); !errors.Is(err, fleet.ErrInvalid) {
		t.Fatalf("err = %v", err)
	}
	if len(repository.createdWith) != 0 {
		t.Fatal("agent must not be created")
	}
}

func TestAuthorizeRejectsRevokedAgent(t *testing.T) {
	repository := &fakeRepository{agent: fleet.Agent{Status: fleet.StatusRevoked}}
	service := fleet.NewService(repository, fakeIssuer{})
	err := service.Authorize(context.Background(), uuid.New(), uuid.New())
	if !errors.Is(err, fleet.ErrNotActive) {
		t.Fatalf("err = %v", err)
	}
}
