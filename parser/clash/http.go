package clash

import "github.com/sagernet/sing-box/option"

type HttpOption struct {
	DialerOptions `yaml:",inline"`
	ServerOptions `yaml:",inline"`
	*TLSOptions   `yaml:",inline"`
	UserName      string            `yaml:"username,omitempty"`
	Password      string            `yaml:"password,omitempty"`
	Headers       map[string]string `yaml:"headers,omitempty"`
}

func (h *HttpOption) Build() any {
	return &option.HTTPOutboundOptions{
		DialerOptions:               h.DialerOptions.Build(),
		ServerOptions:               h.ServerOptions.Build(),
		Username:                    h.UserName,
		Password:                    h.Password,
		OutboundTLSOptionsContainer: clashTLSOptions(h.Server, h.TLSOptions),
		Headers:                     clashHeaders(h.Headers),
	}
}
