package adapter

import "time"

type RuleSetProviderSnapshot struct {
	Type      string
	Format    string
	UpdatedAt time.Time
	Revision  uint64
	IPCIDR    RuleSetIPCIDRExport
}

type RuleSetProvider interface {
	ProviderSnapshot() RuleSetProviderSnapshot
}

type RuleSetUpdater interface {
	Update() error
}

// Digest names the rest of the export by its content, so a consumer can tell an
// unchanged rule-set from a changed one across core reloads, where Revision
// starts over.
type RuleSetIPCIDRExport struct {
	Digest     string                 `json:"digest"`
	IPv4       []string               `json:"ipv4"`
	IPv6       []string               `json:"ipv6"`
	ScopedIPv4 []RuleSetIPCIDRScoped  `json:"scoped_ipv4"`
	ScopedIPv6 []RuleSetIPCIDRScoped  `json:"scoped_ipv6"`
	Skipped    []RuleSetIPCIDRSkipped `json:"skipped,omitempty"`
}

// A group of addresses that only matches under a condition the consumer has to
// carry with them. An empty Networks or PortRanges means the group is not
// constrained that way; a group constrained neither way is exported as a plain
// address instead.
type RuleSetIPCIDRScoped struct {
	Prefixes   []string           `json:"prefixes"`
	Networks   []string           `json:"networks"`
	PortRanges []RuleSetPortRange `json:"port_ranges"`
}

type RuleSetPortRange struct {
	Start uint16 `json:"start"`
	End   uint16 `json:"end"`
}

type RuleSetIPCIDRSkipped struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}
