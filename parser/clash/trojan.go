package clash

import (
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/parser/subscription"
	E "github.com/sagernet/sing/common/exceptions"
)

type trojanOptions struct {
	dialerOptions
	serverOptions
	tlsOptions
	transportOptions
	Password subscription.String `json:"password"`
	UDP      subscription.Bool   `json:"udp"`
	SSOpts   *trojanSSOptions    `json:"ss-opts"`
	MuxOpts  *muxOptions         `json:"smux"`
}

// trojanSSOptions is trojan-go's Shadowsocks layer, which encrypts the stream
// inside the Trojan connection. sing-box's Trojan speaks the plain protocol, so
// a client without it hands the server bytes it cannot decrypt.
type trojanSSOptions struct {
	Enabled  subscription.Bool   `json:"enabled"`
	Method   string              `json:"method"`
	Password subscription.String `json:"password"`
}

func (t *trojanOptions) Build() (any, error) {
	if err := t.serverOptions.check(); err != nil {
		return nil, err
	}
	if t.Password == "" {
		return nil, E.New("missing password")
	}
	if err := t.tlsOptions.check(); err != nil {
		return nil, err
	}
	if t.SSOpts != nil && t.SSOpts.Enabled.Value() {
		return nil, E.New("trojan-go Shadowsocks layer has no sing-box equivalent")
	}
	transport, err := t.transportOptions.build()
	if err != nil {
		return nil, err
	}
	return &option.TrojanOutboundOptions{
		DialerOptions:               t.dialerOptions.build(),
		ServerOptions:               t.serverOptions.build(),
		Password:                    string(t.Password),
		Network:                     networks(t.UDP),
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: t.tlsOptions.build(t.Server, true)},
		Multiplex:                   t.MuxOpts.build(),
		Transport:                   transport,
	}, nil
}
