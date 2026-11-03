// Package broker carries accepted events from ingest to ClickHouse through
// Redpanda (ADR-0009). Ingest acknowledges an agent once the broker holds the
// events; the consumer commits its position only after ClickHouse holds them.
package broker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl/scram"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"dataguard/internal/core/audit"
	centerv1 "dataguard/internal/gen/dataguard/center/v1"
	"dataguard/internal/platform/retry"
	"dataguard/internal/platform/safeerr"
)

const (
	dialTimeout = 10 * time.Second
	// A poll is processed while rebalancing waits, so it stays small enough to be
	// written to ClickHouse well within the rebalance timeout.
	maxPollRecords   = 5_000
	rebalanceTimeout = 2 * time.Minute
	backoffBase      = time.Second
	backoffMax       = time.Minute
)

// Settings locate the broker and the topic.
type Settings struct {
	Brokers  []string
	Topic    string
	Group    string
	User     string
	Password string
	// CAFile enables TLS to the brokers when set.
	CAFile string
}

func (s Settings) options() ([]kgo.Opt, error) {
	if len(s.Brokers) == 0 || s.Topic == "" || s.User == "" || s.Password == "" {
		return nil, errors.New("broker addresses, topic, user and password are required")
	}
	options := []kgo.Opt{
		kgo.SeedBrokers(s.Brokers...),
		kgo.SASL(scram.Auth{User: s.User, Pass: s.Password}.AsSha256Mechanism()),
		kgo.DialTimeout(dialTimeout),
	}
	if s.CAFile != "" {
		data, err := os.ReadFile(filepath.Clean(s.CAFile))
		if err != nil {
			return nil, fmt.Errorf("read broker ca: %w", err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(data) {
			return nil, errors.New("broker ca file has no certificates")
		}
		dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: dialTimeout}, Config: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
		options = append(options, kgo.Dialer(dialer.DialContext))
	}
	return options, nil
}

func unavailable(op string, err error) error {
	return safeerr.New(op, safeerr.CodeUnavailable, err)
}

// Publisher writes accepted events to the topic.
type Publisher struct {
	client *kgo.Client
}

// NewPublisher connects an idempotent producer that waits for every in-sync
// replica, so an acknowledged event survives the loss of a broker.
func NewPublisher(settings Settings) (*Publisher, error) {
	options, err := settings.options()
	if err != nil {
		return nil, err
	}
	options = append(options, kgo.DefaultProduceTopic(settings.Topic), kgo.RequiredAcks(kgo.AllISRAcks()))
	client, err := kgo.NewClient(options...)
	if err != nil {
		return nil, fmt.Errorf("create broker producer: %w", err)
	}
	return &Publisher{client: client}, nil
}

// Publish implements audit.Publisher. Records are keyed by agent, so one agent's
// events keep their order in one partition.
func (p *Publisher) Publish(ctx context.Context, events []audit.Event) error {
	records := make([]*kgo.Record, len(events))
	for i := range events {
		value, err := proto.Marshal(toRecord(&events[i]))
		if err != nil {
			return safeerr.New("encode event record", safeerr.CodeInternal, err)
		}
		records[i] = &kgo.Record{Key: events[i].AgentID[:], Value: value}
	}
	if err := p.client.ProduceSync(ctx, records...).FirstErr(); err != nil {
		return unavailable("publish events", err)
	}
	return nil
}

// Ping reports whether a broker answers.
func (p *Publisher) Ping(ctx context.Context) error {
	if err := p.client.Ping(ctx); err != nil {
		return unavailable("ping broker", err)
	}
	return nil
}

// Close flushes nothing: Publish already waited for every record.
func (p *Publisher) Close() { p.client.Close() }

// Observer learns what the consumer could not do. It may be nil.
type Observer interface {
	ConsumerFailed()
	RecordRejected()
}

// Consumer moves events from the topic to storage.
type Consumer struct {
	settings Settings
	store    func(ctx context.Context, events []audit.Event) error
	observer Observer
	logger   *slog.Logger
	backoff  retry.Backoff
}

// NewConsumer creates the consumer; store must be durable when it returns.
func NewConsumer(settings Settings, store func(context.Context, []audit.Event) error, observer Observer, logger *slog.Logger) *Consumer {
	return &Consumer{
		settings: settings, store: store, observer: observer, logger: logger,
		backoff: retry.Backoff{Base: backoffBase, Max: backoffMax},
	}
}

// Run consumes until ctx ends. A failure leaves the group without committing,
// and the next session reads again from the last committed position.
func (c *Consumer) Run(ctx context.Context) {
	failures := 0
	for {
		committed, err := c.session(ctx)
		if ctx.Err() != nil {
			return
		}
		// A session that stored something ended a run of failures; the next pause
		// starts short again.
		if committed {
			failures = 0
		}
		wait := c.backoff.Delay(failures)
		failures++
		if c.observer != nil {
			c.observer.ConsumerFailed()
		}
		c.logger.Warn("event consumer restarts", "error", err, "backoff", wait.String())
		if !retry.Sleep(ctx, wait) {
			return
		}
	}
}

func (c *Consumer) session(ctx context.Context) (committed bool, err error) {
	options, err := c.settings.options()
	if err != nil {
		return false, err
	}
	options = append(options,
		kgo.ConsumerGroup(c.settings.Group), kgo.ConsumeTopics(c.settings.Topic),
		// A new group starts at the oldest record: nothing published before the first
		// consumer joined may be skipped.
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
		kgo.DisableAutoCommit(), kgo.BlockRebalanceOnPoll(), kgo.RebalanceTimeout(rebalanceTimeout),
	)
	client, err := kgo.NewClient(options...)
	if err != nil {
		return false, fmt.Errorf("create broker consumer: %w", err)
	}
	// Leaving the group waits for a blocked rebalance, so it is allowed first. The
	// polled records stay uncommitted and are read again by the next owner.
	defer func() {
		client.AllowRebalance()
		client.Close()
	}()
	for {
		fetches := client.PollRecords(ctx, maxPollRecords)
		if fetches.IsClientClosed() || ctx.Err() != nil {
			return committed, ctx.Err()
		}
		if err := fetches.Err(); err != nil {
			return committed, unavailable("fetch events", err)
		}
		records := fetches.Records()
		if len(records) > 0 {
			if err := c.store(ctx, c.decode(records)); err != nil {
				return committed, err
			}
			if err := client.CommitRecords(ctx, records...); err != nil {
				return committed, unavailable("commit event offsets", err)
			}
			committed = true
		}
		client.AllowRebalance()
	}
}

// decode skips a record it cannot read and counts it. Only the server writes the
// topic, so such a record means corruption; blocking on it would stop every
// event behind it.
func (c *Consumer) decode(records []*kgo.Record) []audit.Event {
	events := make([]audit.Event, 0, len(records))
	for _, record := range records {
		var message centerv1.EventRecord
		event, err := fromRecord(&message, proto.Unmarshal(record.Value, &message))
		if err != nil {
			if c.observer != nil {
				c.observer.RecordRejected()
			}
			c.logger.Error("event record rejected", "partition", strconv.Itoa(int(record.Partition)), "offset", strconv.FormatInt(record.Offset, 10))
			continue
		}
		events = append(events, event)
	}
	return events
}

// Lag counts records the group has not committed yet. It is computed from the
// committed offsets and the partition ends, not from group membership, so it
// stays right while the consumer is away from the group after a failure.
func (c *Consumer) Lag(ctx context.Context) (int64, error) {
	options, err := c.settings.options()
	if err != nil {
		return 0, err
	}
	client, err := kgo.NewClient(options...)
	if err != nil {
		return 0, err
	}
	defer client.Close()
	admin := kadm.NewClient(client)
	committed, err := admin.FetchOffsets(ctx, c.settings.Group)
	if err == nil {
		err = committed.Error()
	}
	if err != nil {
		return 0, unavailable("read committed offsets", err)
	}
	starts, err := admin.ListStartOffsets(ctx, c.settings.Topic)
	if err == nil {
		err = starts.Error()
	}
	if err != nil {
		return 0, unavailable("read partition starts", err)
	}
	ends, err := admin.ListEndOffsets(ctx, c.settings.Topic)
	if err == nil {
		err = ends.Error()
	}
	if err != nil {
		return 0, unavailable("read partition ends", err)
	}
	var lag int64
	ends.Each(func(end kadm.ListedOffset) {
		position := int64(0)
		if start, found := starts.Lookup(end.Topic, end.Partition); found {
			position = start.Offset
		}
		if commit, found := committed.Lookup(end.Topic, end.Partition); found {
			position = max(position, commit.At)
		}
		lag += max(end.Offset-position, 0)
	})
	return lag, nil
}

func toRecord(event *audit.Event) *centerv1.EventRecord {
	columnIDs := make([]string, len(event.ColumnIDs))
	for i, id := range event.ColumnIDs {
		columnIDs[i] = id.String()
	}
	return &centerv1.EventRecord{
		TenantId: event.TenantID.String(), EventId: event.ID.String(), EventTime: timestamppb.New(event.Time),
		EventType: event.Type, AgentId: event.AgentID.String(), SourceId: event.SourceID.String(),
		DatabasePrincipal: event.DatabasePrincipal, ApplicationPrincipal: event.ApplicationPrincipal,
		ApplicationId: event.ApplicationID, IdentityConfidence: event.IdentityConfidence,
		ClientAddress: event.ClientAddress, Operation: event.Operation, Tables: event.Tables,
		Columns: event.Columns, ColumnIds: columnIDs, Categories: event.Categories,
		QueryFingerprint: event.QueryFingerprint, ExecutionStatus: event.ExecutionStatus,
		ErrorCode: event.ErrorCode, EvidenceLevel: event.EvidenceLevel, ObjectResolution: event.ObjectResolution,
		SessionId: event.SessionID, TransactionId: event.TransactionID, TraceId: event.TraceID,
		GapReason: event.GapReason, GapLostEvents: event.GapLostEvents,
	}
}

func fromRecord(message *centerv1.EventRecord, decodeErr error) (audit.Event, error) {
	if decodeErr != nil {
		return audit.Event{}, decodeErr
	}
	ids := make([]uuid.UUID, 0, 3+len(message.GetColumnIds()))
	for _, text := range append([]string{message.GetTenantId(), message.GetEventId(), message.GetAgentId(), message.GetSourceId()}, message.GetColumnIds()...) {
		id, err := uuid.Parse(text)
		if err != nil {
			return audit.Event{}, err
		}
		ids = append(ids, id)
	}
	if message.GetEventTime() == nil {
		return audit.Event{}, errors.New("event record has no time")
	}
	return audit.Event{
		TenantID: ids[0], ID: ids[1], AgentID: ids[2], SourceID: ids[3], ColumnIDs: ids[4:],
		Time: message.GetEventTime().AsTime(), Type: message.GetEventType(),
		DatabasePrincipal: message.GetDatabasePrincipal(), ApplicationPrincipal: message.GetApplicationPrincipal(),
		ApplicationID: message.GetApplicationId(), IdentityConfidence: message.GetIdentityConfidence(),
		ClientAddress: message.GetClientAddress(), Operation: message.GetOperation(), Tables: message.GetTables(),
		Columns: message.GetColumns(), Categories: message.GetCategories(), QueryFingerprint: message.GetQueryFingerprint(),
		ExecutionStatus: message.GetExecutionStatus(), ErrorCode: message.GetErrorCode(),
		EvidenceLevel: message.GetEvidenceLevel(), ObjectResolution: message.GetObjectResolution(),
		SessionID: message.GetSessionId(), TransactionID: message.GetTransactionId(), TraceID: message.GetTraceId(),
		GapReason: message.GetGapReason(), GapLostEvents: message.GapLostEvents,
	}, nil
}
