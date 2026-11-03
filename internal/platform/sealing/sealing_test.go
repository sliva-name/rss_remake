package sealing_test

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"

	"dataguard/internal/platform/sealing"
)

func binding() sealing.Binding {
	return sealing.Binding{
		TenantID: uuid.MustParse("0190a8c4-7b1e-7c3d-9f10-2a4b6c8d0e1f"),
		AgentID:  uuid.MustParse("0190a8c4-7b1e-7c3d-9f10-2a4b6c8d0e2a"),
		Engine:   "postgresql", Host: "db.example.invalid", Port: 5432, Database: "crm",
		Username: "dg_scanner", TLS: "verify-full",
	}
}

func TestSealedPasswordOpensOnlyForItsTarget(t *testing.T) {
	key, err := sealing.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := sealing.Seal(key.PublicKey().Bytes(), binding(), []byte("synthetic-password"))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := sealing.Open(key, binding(), sealed)
	if err != nil || string(opened) != "synthetic-password" {
		t.Fatalf("open: %q %v", opened, err)
	}

	retargeted := []func(*sealing.Binding){
		func(b *sealing.Binding) { b.Host = "attacker.example.invalid" },
		func(b *sealing.Binding) { b.Port = 5433 },
		func(b *sealing.Binding) { b.TLS = "disable" },
		func(b *sealing.Binding) { b.Username = "postgres" },
		func(b *sealing.Binding) { b.AgentID = uuid.New() },
		func(b *sealing.Binding) { b.TenantID = uuid.New() },
	}
	for _, change := range retargeted {
		changed := binding()
		change(&changed)
		if _, err := sealing.Open(key, changed, sealed); !errors.Is(err, sealing.ErrNotForThisTarget) {
			t.Errorf("changed binding %+v opened: %v", changed, err)
		}
	}

	other, err := sealing.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sealing.Open(other, binding(), sealed); !errors.Is(err, sealing.ErrNotForThisTarget) {
		t.Errorf("another agent opened it: %v", err)
	}
	tampered := append([]byte{}, sealed...)
	tampered[len(tampered)-1] ^= 1
	if _, err := sealing.Open(key, binding(), tampered); !errors.Is(err, sealing.ErrNotForThisTarget) {
		t.Errorf("tampered ciphertext opened: %v", err)
	}
	if _, err := sealing.Open(key, binding(), sealed[:20]); !errors.Is(err, sealing.ErrMalformed) {
		t.Errorf("truncated: %v", err)
	}
}

func TestBindingRejectsControlCharacters(t *testing.T) {
	changed := binding()
	// A newline would let one field impersonate the next one in the AAD.
	changed.Host = "db\nexample"
	if _, err := changed.AAD(); !errors.Is(err, sealing.ErrMalformed) {
		t.Fatalf("want ErrMalformed, got %v", err)
	}
}

// TestBrowserSealedPasswordOpens pins the Go and browser implementations to the
// same format: the fixture was sealed by web/dashboard/src/sealing.ts.
func TestBrowserSealedPasswordOpens(t *testing.T) {
	data, err := os.ReadFile("testdata/browser-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		AgentPrivateKey string `json:"agentPrivateKey"`
		Secret          string `json:"secret"`
		Sealed          string `json:"sealed"`
		Binding         struct {
			TenantID, AgentID, Engine, Host, Database, Username, TLS string
			Port                                                     int
		} `json:"binding"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	scalar, err := hex.DecodeString(fixture.AgentPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdh.P256().NewPrivateKey(scalar)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := base64.StdEncoding.DecodeString(fixture.Sealed)
	if err != nil {
		t.Fatal(err)
	}
	b := fixture.Binding
	opened, err := sealing.Open(key, sealing.Binding{
		TenantID: uuid.MustParse(b.TenantID), AgentID: uuid.MustParse(b.AgentID), Engine: b.Engine,
		Host: b.Host, Port: b.Port, Database: b.Database, Username: b.Username, TLS: b.TLS,
	}, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if string(opened) != fixture.Secret {
		t.Fatalf("opened %q", opened)
	}
}
