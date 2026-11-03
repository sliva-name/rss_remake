// Package center is the agent's only way to talk to the platform. The egress
// check sits in the client interceptor, so no call path can skip it.
package center

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"time"

	"connectrpc.com/connect"
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

func egressInterceptor() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, request connect.AnyRequest) (connect.AnyResponse, error) {
			message, ok := request.Any().(proto.Message)
			if !ok {
				return nil, egress.ErrBlocked
			}
			if err := egress.Check(message); err != nil {
				return nil, err
			}
			return next(ctx, request)
		}
	}
}

// metricsInterceptor sits outside the egress check, so a blocked message counts as
// a call that never left the agent.
func metricsInterceptor(observer *telemetry.Agent) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, request connect.AnyRequest) (connect.AnyResponse, error) {
			response, err := next(ctx, request)
			observer.Request(path.Base(request.Spec().Procedure), err)
			if errors.Is(err, egress.ErrBlocked) {
				if message, ok := request.Any().(proto.Message); ok {
					observer.Blocked(string(message.ProtoReflect().Descriptor().Name()))
				}
			}
			return response, err
		}
	}
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
	client := agentv1connect.NewEnrollmentServiceClient(
		httpClient(&tls.Config{RootCAs: roots}), url, connect.WithInterceptors(egressInterceptor()))
	response, err := client.Enroll(ctx, connect.NewRequest(request))
	if err != nil {
		return nil, err
	}
	return response.Msg, nil
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
	transport := httpClient(&tls.Config{RootCAs: roots, GetClientCertificate: store.ClientCertificate})
	return &Client{
		rpc: agentv1connect.NewAgentServiceClient(transport, url,
			connect.WithInterceptors(metricsInterceptor(observer), egressInterceptor())),
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
	response, err := c.rpc.Heartbeat(ctx, connect.NewRequest(request))
	if err != nil {
		return nil, err
	}
	return response.Msg, nil
}

func (c *Client) ReportSources(ctx context.Context, sources []*agentv1.SourceReport) (*agentv1.ReportSourcesResponse, error) {
	request := &agentv1.ReportSourcesRequest{Envelope: c.envelope(), Sources: sources}
	response, err := c.rpc.ReportSources(ctx, connect.NewRequest(request))
	if err != nil {
		return nil, err
	}
	return response.Msg, nil
}

func (c *Client) RenewCertificate(ctx context.Context, csrPEM []byte) ([]byte, error) {
	request := &agentv1.RenewCertificateRequest{Envelope: c.envelope(), CsrPem: csrPEM}
	response, err := c.rpc.RenewCertificate(ctx, connect.NewRequest(request))
	if err != nil {
		return nil, err
	}
	return response.Msg.GetCertificatePem(), nil
}

func (c *Client) GetPolicy(ctx context.Context) (*agentv1.GetPolicyResponse, error) {
	response, err := c.rpc.GetPolicy(ctx, connect.NewRequest(&agentv1.GetPolicyRequest{Envelope: c.envelope()}))
	if err != nil {
		return nil, err
	}
	return response.Msg, nil
}

func (c *Client) GetSources(ctx context.Context) (*agentv1.GetSourcesResponse, error) {
	response, err := c.rpc.GetSources(ctx, connect.NewRequest(&agentv1.GetSourcesRequest{Envelope: c.envelope()}))
	if err != nil {
		return nil, err
	}
	return response.Msg, nil
}

func (c *Client) PullJobs(ctx context.Context, maxJobs uint32) ([]*agentv1.ScanJob, error) {
	request := &agentv1.PullJobsRequest{Envelope: c.envelope(), MaxJobs: maxJobs}
	response, err := c.rpc.PullJobs(ctx, connect.NewRequest(request))
	if err != nil {
		return nil, err
	}
	return response.Msg.GetJobs(), nil
}

func (c *Client) SubmitScanResult(ctx context.Context, result *agentv1.ScanResult) error {
	request := &agentv1.SubmitScanResultRequest{Envelope: c.envelope(), Result: result}
	_, err := c.rpc.SubmitScanResult(ctx, connect.NewRequest(request))
	return err
}

func (c *Client) SubmitEvents(ctx context.Context, events []*agentv1.AuditEvent) ([]string, error) {
	request := &agentv1.SubmitEventsRequest{Envelope: c.envelope(), Events: events}
	response, err := c.rpc.SubmitEvents(ctx, connect.NewRequest(request))
	if err != nil {
		return nil, err
	}
	return response.Msg.GetAcceptedEventIds(), nil
}
