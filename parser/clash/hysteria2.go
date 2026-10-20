package clash

import (
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

type Hysteria2Option struct {
	DialerOptions `yaml:",inline"`
	ServerOptions `yaml:",inline"`
	TLSOptions    `yaml:",inline"`
	Ports         string `yaml:"ports,omitempty"`
	HopInterval   int    `yaml:"hop-interval,omitempty"`
	Up            string `yaml:"up,omitempty"`
	Down          string `yaml:"down,omitempty"`
	Password      string `yaml:"password,omitempty"`
	Obfs          string `yaml:"obfs,omitempty"`
	ObfsPassword  string `yaml:"obfs-password,omitempty"`
}

func (h *Hysteria2Option) Build() any {
	h.TLS = true
	return &option.Hysteria2OutboundOptions{
		DialerOptions:               h.DialerOptions.Build(),
		ServerOptions:               h.ServerOptions.Build(),
		ServerPorts:                 clashPorts(h.Ports),
		HopInterval:                 badoption.Duration(h.HopInterval),
		UpMbps:                      clashSpeedToIntMbps(h.Up),
		DownMbps:                    clashSpeedToIntMbps(h.Down),
		Obfs:                        clashHysteria2Obfs(h.Obfs, h.ObfsPassword),
		Password:                    h.Password,
		OutboundTLSOptionsContainer: clashTLSOptions(h.Server, &h.TLSOptions),
	}
}
