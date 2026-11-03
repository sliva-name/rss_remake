// Package egress is the last check before a message leaves the customer's
// network. It validates each outbound field against the kind declared in the
// protobuf contract, so what may leave is defined by the schema, not by code
// that has to remember every field.
package egress

import (
	"crypto/ecdh"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"unicode"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
)

const (
	maxIdentifierRunes = 128
	maxPrincipalRunes  = 128
	maxVersionRunes    = 64
	maxCorrelationLen  = 64
	maxCodeLen         = 32
	maxCategoryLen     = 96
	maxCSRBytes        = 8 << 10
)

var (
	uuidPattern        = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	categoryPattern    = regexp.MustCompile(`^[A-Z][A-Z0-9_]*(\.[A-Z][A-Z0-9_]*)+$`)
	fingerprintPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	correlationPattern = regexp.MustCompile(`^[0-9A-Za-z/_.:-]+$`)
	codePattern        = regexp.MustCompile(`^[0-9A-Za-z_]+$`)
	tokenPattern       = regexp.MustCompile(`^[0-9A-Za-z_-]{32,128}$`)
)

// ErrBlocked marks a message the guard refused to let out.
var ErrBlocked = errors.New("egress blocked")

// Violation names the offending field. It deliberately holds no value, so
// logging a rejected message cannot itself leak what was rejected.
type Violation struct {
	Field protoreflect.FullName
	Rule  string
}

func (v *Violation) Error() string {
	return fmt.Sprintf("%v: field %s: %s", ErrBlocked, v.Field, v.Rule)
}

func (v *Violation) Unwrap() error { return ErrBlocked }

// Check returns a *Violation for the first field that breaks its declared
// kind. It never mutates the message: rewriting a bad field would hide a bug
// in the producer.
func Check(message proto.Message) error {
	return checkMessage(message.ProtoReflect())
}

func checkMessage(message protoreflect.Message) error {
	var violation error
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		violation = checkField(field, value)
		return violation == nil
	})
	return violation
}

func checkField(field protoreflect.FieldDescriptor, value protoreflect.Value) error {
	if field.IsMap() {
		return &Violation{Field: field.FullName(), Rule: "map fields are not allowed"}
	}
	if !field.IsList() {
		return checkSingular(field, value)
	}
	list := value.List()
	for i := range list.Len() {
		if err := checkSingular(field, list.Get(i)); err != nil {
			return err
		}
	}
	return nil
}

func checkSingular(field protoreflect.FieldDescriptor, value protoreflect.Value) error {
	switch field.Kind() {
	case protoreflect.MessageKind:
		return checkMessage(value.Message())
	case protoreflect.StringKind:
		return checkText(field, value.String())
	case protoreflect.BytesKind:
		return checkBytes(field, value.Bytes())
	default:
		return nil
	}
}

// KindOf reports the kind declared on a field.
func KindOf(field protoreflect.FieldDescriptor) agentv1.FieldKind {
	kind, ok := proto.GetExtension(field.Options(), agentv1.E_FieldKind).(agentv1.FieldKind)
	if !ok {
		return agentv1.FieldKind_FIELD_KIND_UNSPECIFIED
	}
	return kind
}

func checkText(field protoreflect.FieldDescriptor, value string) error {
	if value == "" {
		return nil
	}
	if rule := textRule(KindOf(field), value); rule != "" {
		return &Violation{Field: field.FullName(), Rule: rule}
	}
	return nil
}

func textRule(kind agentv1.FieldKind, value string) string {
	switch kind {
	case agentv1.FieldKind_FIELD_KIND_UUID:
		return matchRule(uuidPattern, value, "not a uuid")
	case agentv1.FieldKind_FIELD_KIND_IDENTIFIER:
		return nameRule(value, maxIdentifierRunes)
	case agentv1.FieldKind_FIELD_KIND_PRINCIPAL:
		return nameRule(value, maxPrincipalRunes)
	case agentv1.FieldKind_FIELD_KIND_VERSION:
		return nameRule(value, maxVersionRunes)
	case agentv1.FieldKind_FIELD_KIND_CATEGORY_ID:
		if len(value) > maxCategoryLen {
			return "category id too long"
		}
		return matchRule(categoryPattern, value, "not a category id")
	case agentv1.FieldKind_FIELD_KIND_FINGERPRINT:
		return matchRule(fingerprintPattern, value, "not a fingerprint")
	case agentv1.FieldKind_FIELD_KIND_CORRELATION_ID:
		if len(value) > maxCorrelationLen {
			return "correlation id too long"
		}
		return matchRule(correlationPattern, value, "not a correlation id")
	case agentv1.FieldKind_FIELD_KIND_CODE:
		if len(value) > maxCodeLen {
			return "code too long"
		}
		return matchRule(codePattern, value, "not a code")
	case agentv1.FieldKind_FIELD_KIND_NETWORK_ADDRESS:
		if _, err := netip.ParseAddr(value); err != nil {
			return "not an ip address"
		}
		return ""
	case agentv1.FieldKind_FIELD_KIND_ENROLLMENT_TOKEN:
		return matchRule(tokenPattern, value, "not an enrollment token")
	default:
		return "field has no outbound kind"
	}
}

func matchRule(pattern *regexp.Regexp, value, rule string) string {
	if pattern.MatchString(value) {
		return ""
	}
	return rule
}

func nameRule(value string, maxRunes int) string {
	if !utf8.ValidString(value) {
		return "invalid utf-8"
	}
	if utf8.RuneCountInString(value) > maxRunes {
		return "name too long"
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return "control character in name"
		}
	}
	return ""
}

func checkBytes(field protoreflect.FieldDescriptor, value []byte) error {
	if len(value) == 0 {
		return nil
	}
	switch KindOf(field) {
	case agentv1.FieldKind_FIELD_KIND_CSR:
		if len(value) > maxCSRBytes {
			return &Violation{Field: field.FullName(), Rule: "csr too large"}
		}
		return nil
	case agentv1.FieldKind_FIELD_KIND_SEALING_PUBLIC_KEY:
		// Parsing proves the bytes are a point on the curve and nothing else.
		if _, err := ecdh.P256().NewPublicKey(value); err != nil {
			return &Violation{Field: field.FullName(), Rule: "not a p-256 public key"}
		}
		return nil
	default:
		return &Violation{Field: field.FullName(), Rule: "bytes field has no outbound kind"}
	}
}
