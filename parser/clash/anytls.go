package clash

import (
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

type AnyTLSOption struct {
	DialerOptions            `yaml:",inline"`
	ServerOptions            `yaml:",inline"`
	TLSOptions               `yaml:",inline"`
	Password                 string `yaml:"password"`
	UDP                      bool   `yaml:"udp,omitempty"`
	IdleSessionCheckInterval int    `yaml:"idle-session-check-interval,omitempty"`
	IdleSessionTimeout       int    `yaml:"idle-session-timeout,omitempty"`
	MinIdleSession           int    `yaml:"min-idle-session,omitempty"`
}

func (a *AnyTLSOption) Build() any {
	a.TLS = true
	return &option.AnyTLSOutboundOptions{
		DialerOptions:               a.DialerOptions.Build(),
		ServerOptions:               a.ServerOptions.Build(),
		OutboundTLSOptionsContainer: clashTLSOptions(a.Server, &a.TLSOptions),
		Password:                    a.Password,
		IdleSessionCheckInterval:    badoption.Duration(a.IdleSessionCheckInterval),
		IdleSessionTimeout:          badoption.Duration(a.IdleSessionTimeout),
		MinIdleSession:              a.MinIdleSession,
	}
}
