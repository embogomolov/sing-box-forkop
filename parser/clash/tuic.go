package clash

import (
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

type TuicOption struct {
	DialerOptions        `yaml:",inline"`
	ServerOptions        `yaml:",inline"`
	TLSOptions           `yaml:",inline"`
	UUID                 string `yaml:"uuid,omitempty"`
	Password             string `yaml:"password,omitempty"`
	Ip                   string `yaml:"ip,omitempty"`
	HeartbeatInterval    int    `yaml:"heartbeat-interval,omitempty"`
	DisableSni           bool   `yaml:"disable-sni,omitempty"`
	ReduceRtt            bool   `yaml:"reduce-rtt,omitempty"`
	UdpRelayMode         string `yaml:"udp-relay-mode,omitempty"`
	CongestionController string `yaml:"congestion-controller,omitempty"`
	FastOpen             bool   `yaml:"fast-open,omitempty"`
	DisableMTUDiscovery  bool   `yaml:"disable-mtu-discovery,omitempty"`
	UDPOverStream        bool   `yaml:"udp-over-stream,omitempty"`
}

func (t *TuicOption) Build() any {
	t.TLS = true
	t.TFO = t.FastOpen
	options := &option.TUICOutboundOptions{
		DialerOptions:               t.DialerOptions.Build(),
		ServerOptions:               t.ServerOptions.Build(),
		UUID:                        t.UUID,
		Password:                    t.Password,
		CongestionControl:           t.CongestionController,
		UDPRelayMode:                t.UdpRelayMode,
		UDPOverStream:               t.UDPOverStream,
		ZeroRTTHandshake:            t.ReduceRtt,
		Heartbeat:                   badoption.Duration(t.HeartbeatInterval),
		OutboundTLSOptionsContainer: clashTLSOptions(t.Server, &t.TLSOptions),
	}
	if t.Ip != "" {
		options.Server = t.Ip
	}
	if t.DisableSni {
		options.TLS.DisableSNI = true
	}
	return options
}
