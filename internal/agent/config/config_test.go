package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dataguard/internal/agent/config"
)

const valid = `
center: {url: "https://center.test:8443", ca_file: /tmp/ca.crt}
state_dir: /tmp/state
sources:
  - key: crm
    engine: postgresql
    host: db.test
    port: 5432
    database: crm
    username: scanner
    password_file: /tmp/password
`

func write(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadAppliesDefaults(t *testing.T) {
	loaded, err := config.Load(write(t, valid))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.QueueCap <= 0 || len(loaded.Sources) != 1 {
		t.Fatalf("unexpected config: %+v", loaded)
	}
}

func TestLoadRejectsInvalid(t *testing.T) {
	cases := map[string]string{
		"plain http":     strings.ReplaceAll(valid, "https://", "http://"),
		"unknown key":    valid + "\nunknown_setting: true\n",
		"unknown engine": strings.ReplaceAll(valid, "postgresql", "oracle"),
		"bad port":       strings.ReplaceAll(valid, "5432", "70000"),
		"bad key":        strings.ReplaceAll(valid, "key: crm", "key: 'Crm Main'"),
		"duplicate key":  valid + "  - {key: crm, engine: mysql, host: h, port: 1, database: d, username: u, password_file: p}\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := config.Load(write(t, content)); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestPasswordTrimsTrailingNewline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(path, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := config.Source{Key: "crm", PasswordFile: path}
	got, err := source.Password()
	if err != nil || got != "secret" {
		t.Fatalf("Password = %q, %v", got, err)
	}
}
