package fleet_test

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"dataguard/internal/core/fleet"
	"dataguard/internal/core/oplog"
)

type fakeRepository struct {
	fleet.Repository
	consumed    [][]byte
	consumeErr  error
	issuer      oplog.Actor
	agent       fleet.Agent
	createdWith []fleet.Agent
	source      fleet.Source
	saved       []fleet.Source
	journal     []oplog.Entry
}

func (r *fakeRepository) record(entry *oplog.Entry) {
	if entry != nil {
		r.journal = append(r.journal, *entry)
	}
}

func (r *fakeRepository) CreateEnrollmentToken(_ context.Context, _, _ uuid.UUID, _ []byte, _ time.Time, entry oplog.Entry) error {
	r.record(&entry)
	return nil
}

func (r *fakeRepository) ConsumeEnrollmentToken(_ context.Context, _ uuid.UUID, hash []byte) (uuid.UUID, oplog.Actor, error) {
	r.consumed = append(r.consumed, hash)
	return uuid.New(), r.issuer, r.consumeErr
}

func (r *fakeRepository) CreateAgent(_ context.Context, agent fleet.Agent, entry oplog.Entry) error {
	r.createdWith = append(r.createdWith, agent)
	r.record(&entry)
	return nil
}

func (r *fakeRepository) GetAgent(context.Context, uuid.UUID, uuid.UUID) (fleet.Agent, error) {
	return r.agent, nil
}

func (r *fakeRepository) GetSource(context.Context, uuid.UUID, uuid.UUID) (fleet.Source, error) {
	return r.source, nil
}

func (r *fakeRepository) CreateSource(_ context.Context, source fleet.Source, entry *oplog.Entry) error {
	r.saved = append(r.saved, source)
	r.record(entry)
	return nil
}

func (r *fakeRepository) UpdateSource(_ context.Context, source fleet.Source, entry *oplog.Entry) error {
	r.saved = append(r.saved, source)
	r.record(entry)
	return nil
}

func (r *fakeRepository) DeleteSource(_ context.Context, _, _ uuid.UUID, entry *oplog.Entry) error {
	r.record(entry)
	return nil
}

type fakeSigner struct{}

func (fakeSigner) Sign([]byte) []byte { return []byte("signature") }

func sealingKey(t *testing.T) []byte {
	t.Helper()
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key.PublicKey().Bytes()
}

type fakeIssuer struct{ err error }

func (i fakeIssuer) Issue([]byte, uuid.UUID, uuid.UUID) ([]byte, time.Time, error) {
	return []byte("cert"), time.Now().Add(time.Hour), i.err
}

func TestTokenEmbedsTenantAndIsOnlyStoredHashed(t *testing.T) {
	repository := &fakeRepository{}
	service := fleet.NewService(repository, fakeIssuer{}, fakeSigner{})
	tenantID := uuid.New()

	token, _, err := service.CreateEnrollmentToken(t.Context(), tenantID, uuid.New())
	if err != nil {
		t.Fatalf("CreateEnrollmentToken: %v", err)
	}

	enrollment, err := service.Enroll(t.Context(), token, []byte("csr"), sealingKey(t), "1.0")
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
	service := fleet.NewService(&fakeRepository{}, fakeIssuer{}, fakeSigner{})
	for _, token := range []string{"", "no-separator", "nothex_secret"} {
		if _, err := service.Enroll(t.Context(), token, nil, sealingKey(t), ""); !errors.Is(err, fleet.ErrInvalidToken) {
			t.Errorf("token %q: err = %v", token, err)
		}
	}
}

func TestEnrollDoesNotCreateAgentWhenCSRIsRejected(t *testing.T) {
	repository := &fakeRepository{}
	service := fleet.NewService(repository, fakeIssuer{err: errors.New("bad csr")}, fakeSigner{})
	token := uuid.New().String() + "_secret"

	if _, err := service.Enroll(t.Context(), token, nil, sealingKey(t), ""); !errors.Is(err, fleet.ErrInvalid) {
		t.Fatalf("err = %v", err)
	}
	if len(repository.createdWith) != 0 {
		t.Fatal("agent must not be created")
	}
}

func TestAuthorizeRejectsRevokedAgent(t *testing.T) {
	repository := &fakeRepository{agent: fleet.Agent{Status: fleet.StatusRevoked}}
	service := fleet.NewService(repository, fakeIssuer{}, fakeSigner{})
	err := service.Authorize(t.Context(), uuid.New(), uuid.New())
	if !errors.Is(err, fleet.ErrNotActive) {
		t.Fatalf("err = %v", err)
	}
}

func TestEnrollRejectsAMissingSealingKey(t *testing.T) {
	repository := &fakeRepository{}
	service := fleet.NewService(repository, fakeIssuer{}, fakeSigner{})
	token, _, err := service.CreateEnrollmentToken(t.Context(), uuid.New(), uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Enroll(t.Context(), token, []byte("csr"), []byte("not a key"), "1.0"); !errors.Is(err, fleet.ErrInvalid) {
		t.Fatalf("err = %v", err)
	}
	if len(repository.createdWith) != 0 {
		t.Fatal("agent must not be created")
	}
}

// sealedPassword has the envelope shape the center checks; only an agent could
// tell whether it opens.
func sealedPassword() []byte {
	sealed := make([]byte, 1+65+12+16+8)
	sealed[0], sealed[1] = 1, 4
	return sealed
}

func draft() fleet.Source {
	return fleet.Source{
		Key: "crm", Engine: "postgresql", Host: "db.internal", Port: 5432, Database: "crm",
		Username: "dg_scanner", TLS: "verify-full", SealedPassword: sealedPassword(), AgentID: uuid.New(),
	}
}

func TestCreateSourceValidatesTheDefinition(t *testing.T) {
	cases := map[string]func(*fleet.Source){
		"unknown engine":        func(s *fleet.Source) { s.Engine = "oracle" },
		"name with spaces":      func(s *fleet.Source) { s.Key = "CRM main" },
		"host with a path":      func(s *fleet.Source) { s.Host = "db.internal/x" },
		"port out of range":     func(s *fleet.Source) { s.Port = 70000 },
		"newline in user":       func(s *fleet.Source) { s.Username = "dg\nadmin" },
		"unknown tls mode":      func(s *fleet.Source) { s.TLS = "prefer" },
		"relative audit dir":    func(s *fleet.Source) { s.AuditDirectory = "var/log" },
		"unclean audit dir":     func(s *fleet.Source) { s.AuditDirectory = "/var/log/../etc" },
		"too many connections":  func(s *fleet.Source) { s.MaxConnections = 50 },
		"no password":           func(s *fleet.Source) { s.SealedPassword = nil },
		"plaintext as password": func(s *fleet.Source) { s.SealedPassword = []byte("secret-password") },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			repository := &fakeRepository{agent: fleet.Agent{Status: fleet.StatusActive, SealingPublicKey: sealingKey(t)}}
			service := fleet.NewService(repository, fakeIssuer{}, fakeSigner{})
			source := draft()
			change(&source)
			if _, err := service.CreateSource(t.Context(), uuid.New(), source); !errors.Is(err, fleet.ErrInvalid) {
				t.Fatalf("err = %v", err)
			}
			if len(repository.saved) != 0 {
				t.Fatal("an invalid source was saved")
			}
		})
	}
}

func TestCreateSourceNeedsAnAgentThatCanOpenPasswords(t *testing.T) {
	for name, agent := range map[string]fleet.Agent{
		"revoked":        {Status: fleet.StatusRevoked, SealingPublicKey: sealingKey(t)},
		"no sealing key": {Status: fleet.StatusActive},
	} {
		t.Run(name, func(t *testing.T) {
			service := fleet.NewService(&fakeRepository{agent: agent}, fakeIssuer{}, fakeSigner{})
			if _, err := service.CreateSource(t.Context(), uuid.New(), draft()); !errors.Is(err, fleet.ErrInvalid) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestUpdateSourceAsksForThePasswordWhenTheTargetChanges(t *testing.T) {
	current := draft()
	current.ID, current.Engine = uuid.New(), "ENGINE_POSTGRESQL"
	repository := &fakeRepository{source: current}
	service := fleet.NewService(repository, fakeIssuer{}, fakeSigner{})

	renamed := draft()
	renamed.Key, renamed.SealedPassword = "crm-main", nil
	updated, err := service.UpdateSource(t.Context(), uuid.New(), current.ID, renamed)
	if err != nil {
		t.Fatalf("rename: %v", err)
	}
	if string(updated.SealedPassword) != string(current.SealedPassword) || updated.AgentID != current.AgentID {
		t.Fatal("a rename must keep the password and the agent")
	}

	moved := draft()
	moved.Host, moved.SealedPassword = "attacker.example.invalid", nil
	if _, err := service.UpdateSource(t.Context(), uuid.New(), current.ID, moved); !errors.Is(err, fleet.ErrInvalid) {
		t.Fatalf("a new host without a new password: %v", err)
	}

	otherEngine := draft()
	otherEngine.Engine = "mysql"
	if _, err := service.UpdateSource(t.Context(), uuid.New(), current.ID, otherEngine); !errors.Is(err, fleet.ErrInvalid) {
		t.Fatalf("engine change: %v", err)
	}
}

var operator = oplog.Actor{Subject: "8c1b", Name: "ivanova"}

func TestJournalNamesWhatChangedWithoutValues(t *testing.T) {
	current := draft()
	current.ID, current.Engine, current.MaxConnections = uuid.New(), "ENGINE_POSTGRESQL", 2
	repository := &fakeRepository{source: current}
	service := fleet.NewService(repository, fakeIssuer{}, fakeSigner{})
	ctx := oplog.WithActor(t.Context(), operator)

	moved := draft()
	moved.Host, moved.Port = "db2.internal", 6432
	if _, err := service.UpdateSource(ctx, uuid.New(), current.ID, moved); err != nil {
		t.Fatal(err)
	}
	unchanged := current
	unchanged.Engine, unchanged.SealedPassword = "postgresql", nil
	if _, err := service.UpdateSource(ctx, uuid.New(), current.ID, unchanged); err != nil {
		t.Fatal(err)
	}
	if len(repository.journal) != 1 {
		t.Fatalf("journal = %+v, want one entry: a save without changes is not an action", repository.journal)
	}
	entry := repository.journal[0]
	if entry.Action != oplog.SourceUpdate || entry.Actor != operator || entry.ObjectID != current.ID || entry.ObjectLabel != "crm" {
		t.Fatalf("entry = %+v", entry)
	}
	if changes := entry.Details[oplog.DetailChanges]; changes != "host,port,password" {
		t.Fatalf("changes = %q", changes)
	}
	for _, value := range entry.Details {
		if strings.Contains(value, "db2.internal") || strings.Contains(value, "6432") {
			t.Fatalf("a setting value reached the journal: %q", value)
		}
	}
}

func TestDraftsStayOutOfTheJournal(t *testing.T) {
	repository := &fakeRepository{agent: fleet.Agent{Status: fleet.StatusActive, SealingPublicKey: sealingKey(t)}}
	service := fleet.NewService(repository, fakeIssuer{}, fakeSigner{})
	ctx := oplog.WithActor(t.Context(), operator)

	checked := draft()
	checked.Draft = true
	created, err := service.CreateSource(ctx, uuid.New(), checked)
	if err != nil {
		t.Fatal(err)
	}
	repository.source = created
	if err := service.DeleteSource(ctx, uuid.New(), created.ID); err != nil {
		t.Fatal(err)
	}
	if len(repository.journal) != 0 {
		t.Fatalf("a draft reached the journal: %+v", repository.journal)
	}
	if _, err := service.CreateSource(ctx, uuid.New(), draft()); err != nil {
		t.Fatal(err)
	}
	if len(repository.journal) != 1 || repository.journal[0].Action != oplog.SourceCreate {
		t.Fatalf("journal = %+v", repository.journal)
	}
}

func TestEnrolledAgentIsAttributedToWhoIssuedTheToken(t *testing.T) {
	repository := &fakeRepository{issuer: operator}
	service := fleet.NewService(repository, fakeIssuer{}, fakeSigner{})
	token, _, err := service.CreateEnrollmentToken(oplog.WithActor(t.Context(), operator), uuid.New(), uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	// The agent itself has no operator behind its request.
	enrolled, err := service.Enroll(t.Context(), token, []byte("csr"), sealingKey(t), "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(repository.journal) != 2 {
		t.Fatalf("journal = %+v", repository.journal)
	}
	issued, joined := repository.journal[0], repository.journal[1]
	if issued.Action != oplog.EnrollmentTokenIssue || issued.Actor != operator {
		t.Fatalf("token entry = %+v", issued)
	}
	if joined.Action != oplog.AgentEnroll || joined.Actor != operator || joined.ObjectID != enrolled.AgentID {
		t.Fatalf("enrollment entry = %+v", joined)
	}
}
