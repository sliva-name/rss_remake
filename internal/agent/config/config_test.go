package config_test

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dataguard/internal/agent/config"
)

const valid = `
center: {url: "https://center.test:8443", ca_file: /tmp/ca.crt}
state_dir: /tmp/state
allowed:
  hosts: ["10.20.0.0/16", "192.0.2.7", "db.test", "*.db.corp"]
  audit_directories: [/var/log/postgresql]
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
	if loaded.QueueCap <= 0 || loaded.Allowlist() == nil {
		t.Fatalf("unexpected config: %+v", loaded)
	}
	if loaded.Metrics.Address != "" {
		t.Fatal("the metrics port must stay closed unless configured")
	}
}

func TestLoadRejectsInvalid(t *testing.T) {
	cases := map[string]string{
		"plain http":        strings.ReplaceAll(valid, "https://", "http://"),
		"unknown key":       valid + "\nunknown_setting: true\n",
		"no allowlist":      strings.Split(valid, "allowed:")[0],
		"bare wildcard":     strings.ReplaceAll(valid, `"db.test"`, `"*"`),
		"relative audit":    strings.ReplaceAll(valid, "/var/log/postgresql", "var/log"),
		"unclean audit":     strings.ReplaceAll(valid, "/var/log/postgresql", "/var/log/../etc"),
		"sources in config": valid + "sources: []\n",
		"metrics no port":   valid + "metrics: {address: 127.0.0.1}\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := config.Load(write(t, content)); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func resolverOf(addresses map[string][]string) config.Resolver {
	return func(_ context.Context, _, host string) ([]netip.Addr, error) {
		found, ok := addresses[host]
		if !ok {
			return nil, errors.New("no such host")
		}
		parsed := make([]netip.Addr, 0, len(found))
		for _, address := range found {
			parsed = append(parsed, netip.MustParseAddr(address))
		}
		return parsed, nil
	}
}

func TestAllowlistLimitsWhereTheCenterCanPointTheAgent(t *testing.T) {
	loaded, err := config.Load(write(t, valid))
	if err != nil {
		t.Fatal(err)
	}
	resolve := resolverOf(map[string][]string{
		"inside.example":  {"10.20.4.5"},
		"outside.example": {"203.0.113.9"},
		// One address outside is enough to refuse: the driver may pick it.
		"split.example": {"10.20.4.5", "203.0.113.9"},
	})
	cases := map[string]bool{
		"10.20.1.1":             true,
		"10.21.0.1":             false,
		"192.0.2.7":             true,
		"192.0.2.8":             false,
		"db.test":               true,
		"DB.TEST.":              true,
		"other.test":            false,
		"crm.db.corp":           true,
		"db.corp":               false,
		"evildb.corp":           false,
		"inside.example":        true,
		"outside.example":       false,
		"split.example":         false,
		"unresolvable.example":  false,
		"::ffff:10.20.0.9":      true,
		"169.254.169.254":       false,
		"localhost":             false,
		"db.test.attacker.test": false,
	}
	allowlist := loaded.Allowlist()
	for host, want := range cases {
		if got := allowlist.PermitsHost(context.Background(), host, resolve); got != want {
			t.Errorf("%s: permitted = %v, want %v", host, got, want)
		}
	}
	directories := map[string]bool{
		"/var/log/postgresql":         true,
		"/var/log/postgresql/main":    true,
		"/var/log/postgresql-evil":    false,
		"/var/log/postgresql/../../x": false,
		"/var/lib/dataguard":          false,
		"relative":                    false,
	}
	for directory, want := range directories {
		if got := allowlist.PermitsAuditDirectory(directory); got != want {
			t.Errorf("%s: permitted = %v, want %v", directory, got, want)
		}
	}
}
