// Package oplog is the journal of what operators did in an organization: who
// created, changed or deleted a source, published a policy, revoked an agent,
// issued an enrollment token. A service builds the entry and the repository
// writes it in the same transaction as the change it describes, so a change
// cannot be committed without its entry. The journal only grows: the server's
// database role may add entries, not change or remove them.
package oplog

import (
	"context"
	"maps"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Action is what was done, as object.verb.
type Action string

// Every action the journal records.
const (
	TenantCreate         Action = "tenant.create"
	EnvironmentCreate    Action = "environment.create"
	EnrollmentTokenIssue Action = "enrollment_token.issue"
	AgentEnroll          Action = "agent.enroll"
	AgentRevoke          Action = "agent.revoke"
	SourceCreate         Action = "source.create"
	SourceUpdate         Action = "source.update"
	SourceDelete         Action = "source.delete"
	ScanRequest          Action = "scan.request"
	ScanScheduleUpdate   Action = "scan_schedule.update"
	ScanScheduleDelete   Action = "scan_schedule.delete"
	PolicyPublish        Action = "policy.publish"
)

// Kinds of the object an entry points to.
const (
	KindTenant      = "tenant"
	KindEnvironment = "environment"
	KindAgent       = "agent"
	KindSource      = "source"
)

// ObjectKind is what Entry.ObjectID refers to. A token is issued for an
// environment, a scan is requested and scheduled for a source and a policy
// belongs to the organization, so for them it is not the first word of the action.
func (a Action) ObjectKind() string {
	switch a {
	case EnrollmentTokenIssue:
		return KindEnvironment
	case ScanRequest, ScanScheduleUpdate, ScanScheduleDelete:
		return KindSource
	case PolicyPublish:
		return KindTenant
	default:
		kind, _, _ := strings.Cut(string(a), ".")
		return kind
	}
}

// Keys of Entry.Details. Values name fields and versions, never data.
const (
	// DetailChanges lists the changed settings of a source, comma-separated.
	DetailChanges = "changes"
	// DetailVersion is the version a policy was published as.
	DetailVersion = "version"
	// DetailEnvironment is the environment a token or an agent belongs to.
	DetailEnvironment = "environment"
	// DetailReason says why the platform itself acted.
	DetailReason = "reason"
	// DetailEveryHours is the period of a scan schedule, in hours.
	DetailEveryHours = "every_hours"
)

// ReasonRestore: the center was restored from a backup older than what agents
// had applied, and the platform published the restored state again above it.
const ReasonRestore = "restore"

// Actor is who acted, as the identity provider named them at the time. The zero
// Actor is the platform itself.
type Actor struct {
	Subject string
	Name    string
}

type actorKey struct{}

// WithActor marks everything done with ctx as done by actor.
func WithActor(ctx context.Context, actor Actor) context.Context {
	return context.WithValue(ctx, actorKey{}, actor)
}

// ActorFrom returns who acts through ctx.
func ActorFrom(ctx context.Context) Actor {
	actor, _ := ctx.Value(actorKey{}).(Actor)
	return actor
}

// Entry is one action on one object.
type Entry struct {
	Actor    Actor
	Action   Action
	ObjectID uuid.UUID
	// ObjectLabel is the object's name when it happened: the object may be
	// renamed or deleted later.
	ObjectLabel string
	Details     map[string]string
}

// New is an entry by the actor of ctx.
func New(ctx context.Context, action Action, objectID uuid.UUID, label string) Entry {
	return Entry{Actor: ActorFrom(ctx), Action: action, ObjectID: objectID, ObjectLabel: label}
}

// With adds a detail.
func (e Entry) With(key, value string) Entry {
	details := maps.Clone(e.Details)
	if details == nil {
		details = map[string]string{}
	}
	details[key] = value
	e.Details = details
	return e
}

// Recorded is an entry as the journal keeps it.
type Recorded struct {
	Entry
	ID uuid.UUID
	At time.Time
}

// Query selects entries, newest first.
type Query struct {
	// Before continues a listing after the entry with this id.
	Before *uuid.UUID
	// ObjectID limits the listing to one object.
	ObjectID *uuid.UUID
	Limit    int
}

const (
	defaultLimit = 50
	maxLimit     = 500
)

// Repository reads the journal. Writes happen inside the repositories of the
// objects, in their transactions.
type Repository interface {
	ListActions(ctx context.Context, tenantID uuid.UUID, query Query) ([]Recorded, error)
}

type Service struct {
	repository Repository
}

func NewService(repository Repository) *Service {
	return &Service{repository: repository}
}

// List returns entries newest first.
func (s *Service) List(ctx context.Context, tenantID uuid.UUID, query Query) ([]Recorded, error) {
	if query.Limit <= 0 {
		query.Limit = defaultLimit
	}
	query.Limit = min(query.Limit, maxLimit)
	return s.repository.ListActions(ctx, tenantID, query)
}
