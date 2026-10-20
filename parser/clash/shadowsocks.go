package clash

import (
	"strings"

	"github.com/sagernet/sing-box/option"
	F "github.com/sagernet/sing/common/format"
)

type ShadowSocksOption struct {
	DialerOptions     `yaml:",inline"`
	ServerOptions     `yaml:",inline"`
	Password          string         `yaml:"password"`
	Cipher            string         `yaml:"cipher"`
	UDP               bool           `yaml:"udp,omitempty"`
	Plugin            string         `yaml:"plugin,omitempty"`
	PluginOpts        map[string]any `yaml:"plugin-opts,omitempty"`
	UDPOverTCP        bool           `yaml:"udp-over-tcp,omitempty"`
	UDPOverTCPVersion int            `yaml:"udp-over-tcp-version,omitempty"`
	MuxOpts           *MuxOptions    `yaml:"smux,omitempty"`
}

func (s *ShadowSocksOption) Build() any {
	return &option.ShadowsocksOutboundOptions{
		DialerOptions: s.DialerOptions.Build(),
		ServerOptions: s.ServerOptions.Build(),
		Password:      s.Password,
		Method:        clashShadowsocksCipher(s.Cipher),
		Plugin:        clashPluginName(s.Plugin),
		PluginOptions: clashPluginOptions(s.Plugin, s.PluginOpts),
		Network:       clashNetworks(s.UDP),
		UDPOverTCP: &option.UDPOverTCPOptions{
			Enabled: s.UDPOverTCP,
			Version: uint8(s.UDPOverTCPVersion),
		},
		Multiplex: s.MuxOpts.Build(),
	}
}

type shadowsocksPluginOptionsBuilder map[string]any

func (o shadowsocksPluginOptionsBuilder) Build() string {
	var opts []string
	for key, value := range o {
		if value == nil {
			continue
		}
		opts = append(opts, F.ToString(key, "=", value))
	}
	return strings.Join(opts, ";")
}
