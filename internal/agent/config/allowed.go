package config

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path"
	"regexp"
	"strings"
)

var hostnamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

// Allowed is written by the customer when the agent is installed. The agent
// refuses any source from the center outside it.
type Allowed struct {
	// Hosts holds networks (10.20.0.0/16), addresses, host names and wildcard
	// domains (*.db.corp). At least one entry is required.
	Hosts []string `yaml:"hosts"`
	// AuditDirectories are the only directories file-based audit logs may be
	// read from, with their subdirectories.
	AuditDirectories []string `yaml:"audit_directories"`
}

// Allowlist is the compiled form of Allowed.
type Allowlist struct {
	networks    []netip.Prefix
	names       map[string]bool
	suffixes    []string
	directories []string
}

// Resolver looks up host addresses; net.DefaultResolver.LookupNetIP fits.
type Resolver func(ctx context.Context, network, host string) ([]netip.Addr, error)

// CompileAllowed checks and compiles an allowlist; Load does this for the file.
func CompileAllowed(allowed Allowed) (*Allowlist, error) {
	if len(allowed.Hosts) == 0 {
		return nil, errors.New("hosts is required: list the networks or hosts the center may point this agent at")
	}
	list := &Allowlist{names: map[string]bool{}}
	for _, entry := range allowed.Hosts {
		if err := list.addHost(strings.ToLower(strings.TrimSpace(entry))); err != nil {
			return nil, err
		}
	}
	for _, directory := range allowed.AuditDirectories {
		if !strings.HasPrefix(directory, "/") || path.Clean(directory) != directory {
			return nil, fmt.Errorf("audit directory %q must be an absolute clean path", directory)
		}
		list.directories = append(list.directories, directory)
	}
	return list, nil
}

func (a *Allowlist) addHost(entry string) error {
	if prefix, err := netip.ParsePrefix(entry); err == nil {
		a.networks = append(a.networks, prefix.Masked())
		return nil
	}
	if address, err := netip.ParseAddr(entry); err == nil {
		a.networks = append(a.networks, netip.PrefixFrom(address, address.BitLen()))
		return nil
	}
	if suffix, wildcard := strings.CutPrefix(entry, "*."); wildcard {
		if !hostnamePattern.MatchString(suffix) {
			return fmt.Errorf("host %q is not a valid wildcard domain", entry)
		}
		a.suffixes = append(a.suffixes, "."+suffix)
		return nil
	}
	if !hostnamePattern.MatchString(entry) {
		return fmt.Errorf("host %q is not a network, address, host name or *.domain", entry)
	}
	a.names[entry] = true
	return nil
}

// PermitsHost reports whether the agent may connect to host. A name allowed
// by name or domain passes as is. Any other name passes only if every address
// it resolves to is inside an allowed network.
func (a *Allowlist) PermitsHost(ctx context.Context, host string, resolve Resolver) bool {
	if address, err := netip.ParseAddr(host); err == nil {
		return a.inNetworks(address)
	}
	name := strings.TrimSuffix(strings.ToLower(host), ".")
	if a.names[name] {
		return true
	}
	for _, suffix := range a.suffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	if len(a.networks) == 0 || !hostnamePattern.MatchString(name) {
		return false
	}
	addresses, err := resolve(ctx, "ip", name)
	if err != nil || len(addresses) == 0 {
		return false
	}
	for _, address := range addresses {
		if !a.inNetworks(address) {
			return false
		}
	}
	return true
}

func (a *Allowlist) inNetworks(address netip.Addr) bool {
	address = address.Unmap()
	for _, network := range a.networks {
		if network.Contains(address) {
			return true
		}
	}
	return false
}

// PermitsAuditDirectory reports whether a file-based audit log may be read from
// directory.
func (a *Allowlist) PermitsAuditDirectory(directory string) bool {
	if !strings.HasPrefix(directory, "/") || path.Clean(directory) != directory {
		return false
	}
	for _, allowed := range a.directories {
		if directory == allowed || allowed == "/" || strings.HasPrefix(directory, allowed+"/") {
			return true
		}
	}
	return false
}
