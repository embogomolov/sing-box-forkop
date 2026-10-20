package clash

import "github.com/sagernet/sing-box/option"

type Socks5Option struct {
	DialerOptions `yaml:",inline"`
	ServerOptions `yaml:",inline"`
	UserName      string `yaml:"username,omitempty"`
	Password      string `yaml:"password,omitempty"`
	UDP           bool   `yaml:"udp,omitempty"`
}

func (s *Socks5Option) Build() any {
	return &option.SOCKSOutboundOptions{
		DialerOptions: s.DialerOptions.Build(),
		ServerOptions: s.ServerOptions.Build(),
		Username:      s.UserName,
		Password:      s.Password,
		Network:       clashNetworks(s.UDP),
	}
}
