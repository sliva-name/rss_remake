package appcontext_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"dataguard/sdk/go/appcontext"
)

func keys(t *testing.T) (ed25519.PrivateKey, map[string]ed25519.PublicKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return private, map[string]ed25519.PublicKey{"crm": public}
}

func TestValidTokenVerifies(t *testing.T) {
	private, public := keys(t)
	token, err := appcontext.NewSigner("crm", private).Token("employee-123", "crm_service", "trace")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := appcontext.Verify(token, public, "crm_service", time.Now())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != "employee-123" || claims.Application != "crm" {
		t.Fatalf("claims = %+v", claims)
	}
}

func TestForgeriesAreRejected(t *testing.T) {
	private, public := keys(t)
	token, err := appcontext.NewSigner("crm", private).Token("employee-123", "crm_service", "")
	if err != nil {
		t.Fatal(err)
	}
	foreign, _ := keys(t)
	stranger, err := appcontext.NewSigner("crm", foreign).Token("employee-999", "crm_service", "")
	if err != nil {
		t.Fatal(err)
	}
	segments := strings.Split(token, ".")
	otherSegments := strings.Split(stranger, ".")

	cases := map[string]struct {
		token string
		user  string
		at    time.Time
	}{
		"signed by a foreign key": {stranger, "crm_service", time.Now()},
		"payload swapped":         {segments[0] + "." + otherSegments[1] + "." + segments[2], "crm_service", time.Now()},
		"expired":                 {token, "crm_service", time.Now().Add(time.Hour)},
		"other database user":     {token, "attacker", time.Now()},
		"garbage":                 {"not.a.token", "crm_service", time.Now()},
		"empty":                   {"", "crm_service", time.Now()},
		"truncated":               {segments[0] + "." + segments[1], "crm_service", time.Now()},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := appcontext.Verify(testCase.token, public, testCase.user, testCase.at)
			if !errors.Is(err, appcontext.ErrInvalid) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestSubjectMustBeAnIdentifier(t *testing.T) {
	private, _ := keys(t)
	if _, err := appcontext.NewSigner("crm", private).Token("Иванов Иван", "", ""); err == nil {
		t.Fatal("a display name must be refused")
	}
}

func TestStatementCannotBreakOutOfQuotes(t *testing.T) {
	private, _ := keys(t)
	token, err := appcontext.NewSigner("crm", private).Token("employee-123", "", "x'; DROP TABLE users; --")
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(token, "'; ") {
		t.Fatalf("token alphabet is unsafe: %s", token)
	}
}
