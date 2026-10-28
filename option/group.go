package option

import "github.com/sagernet/sing/common/json/badoption"

type SelectorOutboundOptions struct {
	GroupCommonOption
	Default                   string `json:"default,omitempty" reference:"outbound"`
	InterruptExistConnections bool   `json:"interrupt_exist_connections,omitempty"`
}

type URLTestOutboundOptions struct {
	GroupCommonOption
	URL                       badoption.Listable[string] `json:"url,omitempty"`
	ExpectedStatus            string                     `json:"expected_status,omitempty"`
	Interval                  badoption.Duration         `json:"interval,omitempty"`
	Tolerance                 uint16                     `json:"tolerance,omitempty"`
	IdleTimeout               badoption.Duration         `json:"idle_timeout,omitempty"`
	InterruptExistConnections bool                       `json:"interrupt_exist_connections,omitempty"`
}

type FallbackOutboundOptions struct {
	GroupCommonOption
	Groups                    []FallbackGroupOptions `json:"groups,omitempty"`
	URL                       string                 `json:"url,omitempty"`
	Interval                  badoption.Duration     `json:"interval,omitempty"`
	Timeout                   badoption.Duration     `json:"timeout,omitempty"`
	AttemptTimeout            badoption.Duration     `json:"attempt_timeout,omitempty"`
	ExpectedStatus            string                 `json:"expected_status,omitempty"`
	IdleTimeout               badoption.Duration     `json:"idle_timeout,omitempty"`
	InterruptExistConnections bool                   `json:"interrupt_exist_connections,omitempty"`
}

type FallbackGroupOptions struct {
	GroupCommonOption
}

type GroupCommonOption struct {
	Outbounds       []string                   `json:"outbounds" reference:"outbound"`
	Providers       badoption.Listable[string] `json:"providers,omitempty"`
	Exclude         *badoption.Regexp          `json:"exclude,omitempty"`
	Include         *badoption.Regexp          `json:"include,omitempty"`
	ExcludeTypes    badoption.Listable[string] `json:"exclude_types,omitempty"`
	UseAllProviders bool                       `json:"use_all_providers,omitempty"`
}
