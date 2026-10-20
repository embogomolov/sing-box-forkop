package clash

import (
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

type HysteriaOption struct {
	DialerOptions       `yaml:",inline"`
	ServerOptions       `yaml:",inline"`
	TLSOptions          `yaml:",inline"`
	Ports               string `yaml:"ports,omitempty"`
	Up                  string `yaml:"up"`
	UpSpeed             int    `yaml:"up-speed,omitempty"` // compatible with Stash
	Down                string `yaml:"down"`
	DownSpeed           int    `yaml:"down-speed,omitempty"` // compatible with Stash
	Auth                string `yaml:"auth,omitempty"`
	AuthString          string `yaml:"auth-str,omitempty"`
	Obfs                string `yaml:"obfs,omitempty"`
	ReceiveWindowConn   int    `yaml:"recv-window-conn,omitempty"`
	ReceiveWindow       int    `yaml:"recv-window,omitempty"`
	DisableMTUDiscovery bool   `yaml:"disable-mtu-discovery,omitempty"`
	FastOpen            bool   `yaml:"fast-open,omitempty"`
	HopInterval         int    `yaml:"hop-interval,omitempty"`
}

func (h *HysteriaOption) Build() any {
	h.TLS = true
	h.TFO = h.FastOpen
	return &option.HysteriaOutboundOptions{
		DialerOptions:               h.DialerOptions.Build(),
		ServerOptions:               h.ServerOptions.Build(),
		ServerPorts:                 clashPorts(h.Ports),
		HopInterval:                 badoption.Duration(h.HopInterval),
		Up:                          clashSpeedToNetworkBytes(h.Up),
		UpMbps:                      h.UpSpeed,
		Down:                        clashSpeedToNetworkBytes(h.Down),
		DownMbps:                    h.DownSpeed,
		Obfs:                        h.Obfs,
		Auth:                        []byte(h.Auth),
		AuthString:                  h.AuthString,
		ReceiveWindowConn:           uint64(h.ReceiveWindowConn),
		ReceiveWindow:               uint64(h.ReceiveWindow),
		DisableMTUDiscovery:         h.DisableMTUDiscovery,
		OutboundTLSOptionsContainer: clashTLSOptions(h.Server, &h.TLSOptions),
	}
}
