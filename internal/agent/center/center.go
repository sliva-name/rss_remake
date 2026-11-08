// Package center is the agent's only way to talk to the platform. The egress
// check sits in the client interceptor, so no call path can skip it.
package center

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"dataguard/internal/agent/identity"
	"dataguard/internal/agent/telemetry"
	"dataguard/internal/contract/egress"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
	"dataguard/internal/gen/dataguard/agent/v1/agentv1connect"
)

const (
	schemaVersion  = 1
	requestTimeout = 30 * time.Second
)

// egressInterceptor checks every message as it is sent, so nothing reaches the
// transport unchecked.
func egressInterceptor(next connect.ClientFunc) connect.ClientFunc {
	return func(ctx context.Context, spec connect.Spec) (connect.ClientStream, error) {
		stream, err := next(ctx, spec)
		if err != nil {
			return nil, err
		}
		return checkedStream{ClientStream: stream}, nil
	}
}

type checkedStream struct {
	connect.ClientStream
}

func (s checkedStream) Send(message any) error {
	typed, ok := message.(proto.Message)
	if !ok {
		return egress.ErrBlocked
	}
	if err := egress.Check(typed); err != nil {
		return err
	}
	return s.ClientStream.Send(message)
}

// metricsInterceptor sits outside the egress check, so a blocked message counts as
// a call that never left the agent.
func metricsInterceptor(observer *telemetry.Agent) connect.ClientInterceptor {
	return func(next connect.ClientFunc) connect.ClientFunc {
		return func(ctx context.Context, spec connect.Spec) (connect.ClientStream, error) {
			procedure := path.Base(spec.Procedure)
			stream, err := next(ctx, spec)
			if err != nil {
				observer.Request(procedure, err)
				return nil, err
			}
			return &observedStream{ClientStream: stream, observer: observer, procedure: procedure}, nil
		}
	}
}

// observedStream records a unary call when CallUnary closes it, with the first
// error the call met.
type observedStream struct {
	connect.ClientStream
	observer  *telemetry.Agent
	procedure string
	err       error
}

func (s *observedStream) Send(message any) error {
	err := s.ClientStream.Send(message)
	if errors.Is(err, egress.ErrBlocked) {
		if typed, ok := message.(proto.Message); ok {
			s.observer.Blocked(string(typed.ProtoReflect().Descriptor().Name()))
		}
	}
	return s.keep(err)
}

func (s *observedStream) CloseSend() error { return s.keep(s.ClientStream.CloseSend()) }

func (s *observedStream) Receive(message any) error { return s.keep(s.ClientStream.Receive(message)) }

func (s *observedStream) Close() error {
	err := s.keep(s.ClientStream.Close())
	s.observer.Request(s.procedure, s.err)
	return err
}

func (s *observedStream) keep(err error) error {
	if s.err == nil && !errors.Is(err, io.EOF) {
		s.err = err
	}
	return err
}

func trustedRoots(caFile string) (*x509.CertPool, error) {
	data, err := os.ReadFile(filepath.Clean(caFile))
	if err != nil {
		return nil, fmt.Errorf("read center ca: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(data) {
		return nil, errors.New("center ca file has no certificates")
	}
	return roots, nil
}

func httpClient(config *tls.Config) *http.Client {
	config.MinVersion = tls.VersionTLS13
	return &http.Client{
		Timeout:   requestTimeout,
		Transport: &http.Transport{TLSClientConfig: config, ForceAttemptHTTP2: true},
	}
}

// Enroll exchanges a one-time token for a certificate. There is no client
// certificate yet, so the pinned CA is what authenticates the center.
func Enroll(ctx context.Context, url, caFile string, request *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error) {
	roots, err := trustedRoots(caFile)
	if err != nil {
		return nil, err
	}
	transport := connecthttp.NewTransport(httpClient(&tls.Config{RootCAs: roots}), url)
	request.SchemaVersion = schemaVersion
	return agentv1connect.NewEnrollmentServiceClient(connect.NewClient(transport, egressInterceptor)).Enroll(ctx, request)
}

// Client is the authenticated connection to the center.
type Client struct {
	rpc      agentv1connect.AgentServiceClient
	identity *identity.Store
}

// New creates a client that presents the agent's certificate. Metrics may be nil.
func New(url, caFile string, store *identity.Store, observer *telemetry.Agent) (*Client, error) {
	roots, err := trustedRoots(caFile)
	if err != nil {
		return nil, err
	}
	transport := connecthttp.NewTransport(httpClient(&tls.Config{RootCAs: roots, GetClientCertificate: store.ClientCertificate}), url)
	return &Client{
		rpc:      agentv1connect.NewAgentServiceClient(connect.NewClient(transport, metricsInterceptor(observer), egressInterceptor)),
		identity: store,
	}, nil
}

func (c *Client) envelope() *agentv1.Envelope {
	return &agentv1.Envelope{
		SchemaVersion: schemaVersion,
		MessageId:     uuid.Must(uuid.NewV7()).String(),
		TenantId:      c.identity.TenantID().String(),
		AgentId:       c.identity.AgentID().String(),
		CreatedAt:     timestamppb.Now(),
	}
}

func (c *Client) Heartbeat(ctx context.Context, request *agentv1.HeartbeatRequest) (*agentv1.HeartbeatResponse, error) {
	request.Envelope = c.envelope()
	return c.rpc.Heartbeat(ctx, request)
}

func (c *Client) ReportSources(ctx context.Context, sources []*agentv1.SourceReport) (*agentv1.ReportSourcesResponse, error) {
	return c.rpc.ReportSources(ctx, &agentv1.ReportSourcesRequest{Envelope: c.envelope(), Sources: sources})
}

func (c *Client) RenewCertificate(ctx context.Context, csrPEM []byte) ([]byte, error) {
	response, err := c.rpc.RenewCertificate(ctx, &agentv1.RenewCertificateRequest{Envelope: c.envelope(), CsrPem: csrPEM})
	return response.GetCertificatePem(), err
}

func (c *Client) GetPolicy(ctx context.Context) (*agentv1.GetPolicyResponse, error) {
	return c.rpc.GetPolicy(ctx, &agentv1.GetPolicyRequest{Envelope: c.envelope()})
}

func (c *Client) GetSources(ctx context.Context) (*agentv1.GetSourcesResponse, error) {
	return c.rpc.GetSources(ctx, &agentv1.GetSourcesRequest{Envelope: c.envelope()})
}

func (c *Client) PullJobs(ctx context.Context, maxJobs uint32) ([]*agentv1.ScanJob, error) {
	response, err := c.rpc.PullJobs(ctx, &agentv1.PullJobsRequest{Envelope: c.envelope(), MaxJobs: maxJobs})
	return response.GetJobs(), err
}

func (c *Client) SubmitScanResult(ctx context.Context, result *agentv1.ScanResult) error {
	_, err := c.rpc.SubmitScanResult(ctx, &agentv1.SubmitScanResultRequest{Envelope: c.envelope(), Result: result})
	return err
}

func (c *Client) SubmitEvents(ctx context.Context, events []*agentv1.AuditEvent) ([]string, error) {
	response, err := c.rpc.SubmitEvents(ctx, &agentv1.SubmitEventsRequest{Envelope: c.envelope(), Events: events})
	return response.GetAcceptedEventIds(), err
}
