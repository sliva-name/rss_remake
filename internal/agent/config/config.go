// Package config loads the agent's local configuration. This file, not the
// center, defines which databases the agent may touch and how to log in to
// them, so a compromised center cannot retarget the agent.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Engine names accepted in the configuration.
const (
	EnginePostgreSQL = "postgresql"
	EngineMySQL      = "mysql"
	EngineMariaDB    = "mariadb"
	EngineMSSQL      = "mssql"
)

const (
	maxPort               = 65535
	maxSourceKeyLen       = 64
	defaultQueueSize      = 256 << 20
	defaultMaxConnections = 2
)

var sourceKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)

// Config is the root of the agent's YAML file.
type Config struct {
	Center   Center   `yaml:"center"`
	StateDir string   `yaml:"state_dir"`
	QueueCap int64    `yaml:"queue_capacity_bytes"`
	Sources  []Source `yaml:"sources"`
}

// Center says how to reach the platform.
type Center struct {
	URL    string `yaml:"url"`
	CAFile string `yaml:"ca_file"`
}

// Source is one database the agent is allowed to work with.
type Source struct {
	Key          string `yaml:"key"`
	Engine       string `yaml:"engine"`
	Host         string `yaml:"host"`
	Port         int    `yaml:"port"`
	Database     string `yaml:"database"`
	Username     string `yaml:"username"`
	PasswordFile string `yaml:"password_file"`
	// TLS defaults to verify-full; weakening it has to be written down.
	TLS string `yaml:"tls"`
	// MaxConnections caps the pool locally, so no job can exceed what the
	// customer allowed for this database.
	MaxConnections int   `yaml:"max_connections"`
	Audit          Audit `yaml:"audit"`
}

// Audit locates the audit log. An empty Directory on a file-based engine means
// auditing is not configured, which is reported rather than assumed.
type Audit struct {
	Directory string `yaml:"directory"`
}

// Load reads and validates the configuration, rejecting unknown keys so a typo
// cannot silently disable a setting.
func Load(path string) (*Config, error) {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer func() { _ = file.Close() }()

	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	var loaded Config
	if err := decoder.Decode(&loaded); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if loaded.QueueCap == 0 {
		loaded.QueueCap = defaultQueueSize
	}
	if err := loaded.validate(); err != nil {
		return nil, err
	}
	return &loaded, nil
}

func (c *Config) validate() error {
	parsed, err := url.Parse(c.Center.URL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return errors.New("center.url must be an https url")
	}
	if c.Center.CAFile == "" || c.StateDir == "" {
		return errors.New("center.ca_file and state_dir are required")
	}
	if c.QueueCap <= 0 {
		return errors.New("queue_capacity_bytes must be positive")
	}
	seen := make(map[string]bool, len(c.Sources))
	for i := range c.Sources {
		source := &c.Sources[i]
		if err := source.validate(); err != nil {
			return fmt.Errorf("source %d: %w", i, err)
		}
		if seen[source.Key] {
			return fmt.Errorf("source %d: duplicate key", i)
		}
		seen[source.Key] = true
	}
	return nil
}

func (s *Source) validate() error {
	if len(s.Key) > maxSourceKeyLen || !sourceKeyPattern.MatchString(s.Key) {
		return errors.New("key must match ^[a-z][a-z0-9_-]*$")
	}
	switch s.Engine {
	case EnginePostgreSQL, EngineMySQL, EngineMariaDB, EngineMSSQL:
	default:
		return errors.New("unknown engine")
	}
	if s.Host == "" || s.Username == "" || s.Database == "" || s.PasswordFile == "" {
		return errors.New("host, database, username and password_file are required")
	}
	if s.Port <= 0 || s.Port > maxPort {
		return errors.New("port is out of range")
	}
	switch s.TLS {
	case "":
		s.TLS = "verify-full"
	case "verify-full", "require", "disable":
	default:
		return errors.New("tls must be verify-full, require or disable")
	}
	if s.MaxConnections == 0 {
		s.MaxConnections = defaultMaxConnections
	}
	if s.MaxConnections < 0 {
		return errors.New("max_connections must be positive")
	}
	return nil
}

// Password reads the secret at the moment of use, so it is not kept in the
// configuration struct and a rotated file takes effect on the next connection.
func (s *Source) Password() (string, error) {
	data, err := os.ReadFile(filepath.Clean(s.PasswordFile))
	if err != nil {
		return "", fmt.Errorf("read password file of source %s: %w", s.Key, err)
	}
	return strings.TrimRight(string(data), "\r\n"), nil
}
