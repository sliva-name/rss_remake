// Package config loads the agent's local configuration. Sources come from the
// center (ADR-0006); this file says where the center is and which targets the
// agent may be pointed at, so a compromised center cannot retarget it freely.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// DefaultQueueCapacity applies when queue_capacity_bytes is not set.
const DefaultQueueCapacity = 256 << 20

// Config is the root of the agent's YAML file.
type Config struct {
	Center   Center `yaml:"center"`
	StateDir string `yaml:"state_dir"`
	QueueCap int64  `yaml:"queue_capacity_bytes"`
	// Allowed limits which sources from the center the agent agrees to open.
	Allowed Allowed `yaml:"allowed"`
	// Applications lists keys that may sign user context. Without an entry, a
	// context from that application is reported as an unverified claim.
	Applications []Application `yaml:"applications"`
	// Metrics is off unless an address is set (ADR-0008).
	Metrics Metrics `yaml:"metrics"`

	allowlist *Allowlist
}

// Metrics opens the agent's only listening port, serving GET /metrics.
type Metrics struct {
	Address string `yaml:"address"`
}

// Application is a client application allowed to attest its users.
type Application struct {
	ID            string `yaml:"id"`
	PublicKeyFile string `yaml:"public_key_file"`
}

// Center says how to reach the platform.
type Center struct {
	URL    string `yaml:"url"`
	CAFile string `yaml:"ca_file"`
}

// Allowlist returns the compiled form of Allowed.
func (c *Config) Allowlist() *Allowlist { return c.allowlist }

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
		loaded.QueueCap = DefaultQueueCapacity
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
	for i, application := range c.Applications {
		if application.ID == "" || application.PublicKeyFile == "" {
			return fmt.Errorf("application %d: id and public_key_file are required", i)
		}
	}
	if c.Metrics.Address != "" {
		if _, port, err := net.SplitHostPort(c.Metrics.Address); err != nil || port == "" {
			return errors.New("metrics.address must be host:port, such as 127.0.0.1:9464")
		}
	}
	allowlist, err := CompileAllowed(c.Allowed)
	if err != nil {
		return fmt.Errorf("allowed: %w", err)
	}
	c.allowlist = allowlist
	return nil
}
