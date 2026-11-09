package egress_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"dataguard/internal/contract/egress"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
)

const (
	validUUID = "0190a8c4-7b1e-7c3d-9f10-2a4b6c8d0e1f"
	// Synthetic, generated for tests; it belongs to nobody.
	canaryEmail = "canary.subject@dataguard.invalid"
)

// outboundRoots are all messages an agent sends. A new RPC request must be
// added here, otherwise TestEveryOutboundFieldIsClosed will not cover it.
func outboundRoots() []proto.Message {
	return []proto.Message{
		&agentv1.EnrollRequest{},
		&agentv1.HeartbeatRequest{},
		&agentv1.ReportSourcesRequest{},
		&agentv1.RenewCertificateRequest{},
		&agentv1.GetPolicyRequest{},
		&agentv1.GetSourcesRequest{},
		&agentv1.GetSigningKeysRequest{},
		&agentv1.PullJobsRequest{},
		&agentv1.SubmitScanResultRequest{},
		&agentv1.SubmitEventsRequest{},
	}
}

func TestEveryAgentRPCRequestIsListed(t *testing.T) {
	listed := map[protoreflect.FullName]bool{}
	for _, root := range outboundRoots() {
		listed[root.ProtoReflect().Descriptor().FullName()] = true
	}
	services := agentv1.File_dataguard_agent_v1_agent_service_proto.Services()
	for i := range services.Len() {
		methods := services.Get(i).Methods()
		for j := range methods.Len() {
			input := methods.Get(j).Input().FullName()
			if !listed[input] {
				t.Errorf("request %s is missing from outboundRoots", input)
			}
		}
	}
}

// TestEveryOutboundFieldIsClosed makes a free-form field a build failure: a
// new string, bytes or map field cannot reach the wire without a declared kind.
func TestEveryOutboundFieldIsClosed(t *testing.T) {
	seen := map[protoreflect.FullName]bool{}
	for _, root := range outboundRoots() {
		walkFields(t, root.ProtoReflect().Descriptor(), seen)
	}
	if len(seen) == 0 {
		t.Fatal("no messages were walked")
	}
}

func walkFields(t *testing.T, message protoreflect.MessageDescriptor, seen map[protoreflect.FullName]bool) {
	t.Helper()
	if seen[message.FullName()] {
		return
	}
	seen[message.FullName()] = true
	fields := message.Fields()
	for i := range fields.Len() {
		field := fields.Get(i)
		if field.IsMap() {
			t.Errorf("%s: map fields are forbidden outbound", field.FullName())
			continue
		}
		switch field.Kind() {
		case protoreflect.MessageKind:
			walkMessageField(t, field, seen)
		case protoreflect.StringKind, protoreflect.BytesKind:
			assertClosedKind(t, field)
		default:
		}
	}
}

func walkMessageField(t *testing.T, field protoreflect.FieldDescriptor, seen map[protoreflect.FullName]bool) {
	t.Helper()
	target := field.Message()
	if target.ParentFile().Package() == "google.protobuf" {
		if target.FullName() != "google.protobuf.Timestamp" {
			t.Errorf("%s: open well-known type %s is forbidden", field.FullName(), target.FullName())
		}
		return
	}
	walkFields(t, target, seen)
}

func assertClosedKind(t *testing.T, field protoreflect.FieldDescriptor) {
	t.Helper()
	switch egress.KindOf(field) {
	case agentv1.FieldKind_FIELD_KIND_UNSPECIFIED, agentv1.FieldKind_FIELD_KIND_INBOUND_ONLY:
		t.Errorf("%s: outbound field has no closed kind", field.FullName())
	default:
	}
}

func TestCheckAcceptsWellFormedEvent(t *testing.T) {
	event := wellFormedEvent()
	if err := egress.Check(event); err != nil {
		t.Fatalf("Check: %v", err)
	}
}

func TestCheckRejectsValueSmuggledIntoClosedField(t *testing.T) {
	cases := map[string]func(*agentv1.SubmitEventsRequest){
		"value as fingerprint": func(r *agentv1.SubmitEventsRequest) {
			r.Events[0].Operation.QueryFingerprint = canaryEmail
		},
		"value as code": func(r *agentv1.SubmitEventsRequest) {
			r.Events[0].Execution.ErrorCode = "duplicate key " + canaryEmail
		},
		"value as address": func(r *agentv1.SubmitEventsRequest) {
			r.Events[0].Actor.ClientAddress = canaryEmail
		},
		"newline in identifier": func(r *agentv1.SubmitEventsRequest) {
			r.Events[0].Operation.Tables[0].Table = "users\n" + canaryEmail
		},
		"oversized identifier": func(r *agentv1.SubmitEventsRequest) {
			r.Events[0].Operation.Tables[0].Table = strings.Repeat("x", 129)
		},
		"value as correlation id": func(r *agentv1.SubmitEventsRequest) {
			r.Events[0].Correlation.TraceId = "SELECT email FROM users WHERE id = 1"
		},
		"bad uuid in envelope": func(r *agentv1.SubmitEventsRequest) {
			r.Envelope.MessageId = canaryEmail
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			request := &agentv1.SubmitEventsRequest{
				Envelope: &agentv1.Envelope{MessageId: validUUID},
				Events:   []*agentv1.AuditEvent{wellFormedEvent()},
			}
			mutate(request)
			err := egress.Check(request)
			if !errors.Is(err, egress.ErrBlocked) {
				t.Fatalf("want ErrBlocked, got %v", err)
			}
			if strings.Contains(err.Error(), canaryEmail) {
				t.Fatal("violation text must not echo the rejected value")
			}
		})
	}
}

func TestCheckRejectsInboundMaterialOutbound(t *testing.T) {
	err := egress.Check(&agentv1.GetPolicyResponse{Signature: []byte("x")})
	if !errors.Is(err, egress.ErrBlocked) {
		t.Fatalf("want ErrBlocked, got %v", err)
	}
}

func TestCheckAcceptsOnlyARealSealingKey(t *testing.T) {
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := egress.Check(&agentv1.EnrollRequest{SealingPublicKey: key.PublicKey().Bytes()}); err != nil {
		t.Fatalf("real key: %v", err)
	}
	// 65 bytes of anything would fit the field if only the length were checked.
	smuggled := append([]byte{4}, []byte(strings.Repeat(canaryEmail, 2))[:64]...)
	if err := egress.Check(&agentv1.EnrollRequest{SealingPublicKey: smuggled}); !errors.Is(err, egress.ErrBlocked) {
		t.Fatalf("want ErrBlocked, got %v", err)
	}
}

func wellFormedEvent() *agentv1.AuditEvent {
	return &agentv1.AuditEvent{
		EventId:   validUUID,
		EventType: agentv1.EventType_EVENT_TYPE_DATA_ACCESS,
		SourceId:  validUUID,
		Actor: &agentv1.Actor{
			DatabasePrincipal:  "crm_service",
			IdentityConfidence: agentv1.IdentityConfidence_IDENTITY_CONFIDENCE_DB_PRINCIPAL_ONLY,
			ClientAddress:      "10.0.0.5",
		},
		Operation: &agentv1.Operation{
			Type:             agentv1.OperationType_OPERATION_TYPE_SELECT,
			Tables:           []*agentv1.TablePath{{Database: "crm", Schema: "public", Table: "users"}},
			QueryFingerprint: "sha256:" + strings.Repeat("ab", 32),
		},
		Execution:   &agentv1.Execution{Status: agentv1.ExecutionStatus_EXECUTION_STATUS_SUCCESS, ErrorCode: "23505"},
		Correlation: &agentv1.Correlation{SessionId: "6728e4a1.2f", TransactionId: "3/1042", TraceId: "4bf92f3577b34da6a3ce929d0e0e4736"},
		Evidence: &agentv1.Evidence{
			Source:           agentv1.EvidenceSource_EVIDENCE_SOURCE_NATIVE_AUDIT,
			Level:            agentv1.EvidenceLevel_EVIDENCE_LEVEL_EXECUTED,
			ObjectResolution: agentv1.ObjectResolution_OBJECT_RESOLUTION_RESOLVED,
		},
	}
}
