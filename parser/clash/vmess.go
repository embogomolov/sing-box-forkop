package clash

import (
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/parser/subscription"
	E "github.com/sagernet/sing/common/exceptions"
)

type vmessOptions struct {
	dialerOptions
	serverOptions
	tlsOptions
	transportOptions
	UUID                subscription.String `json:"uuid"`
	AlterID             subscription.Int    `json:"alterid"`
	Cipher              string              `json:"cipher"`
	UDP                 subscription.Bool   `json:"udp"`
	PacketAddr          subscription.Bool   `json:"packet-addr"`
	XUDP                subscription.Bool   `json:"xudp"`
	PacketEncoding      string              `json:"packet-encoding"`
	GlobalPadding       subscription.Bool   `json:"global-padding"`
	AuthenticatedLength subscription.Bool   `json:"authenticated-length"`
	MuxOpts             *muxOptions         `json:"smux"`
}

func (v *vmessOptions) Build() (any, error) {
	if err := v.serverOptions.check(); err != nil {
		return nil, err
	}
	if v.UUID == "" {
		return nil, E.New("missing uuid")
	}
	if err := v.tlsOptions.check(); err != nil {
		return nil, err
	}
	transport, err := v.transportOptions.build()
	if err != nil {
		return nil, err
	}
	alterID, err := v.AlterID.Value("alterId")
	if err != nil {
		return nil, err
	}
	security := v.Cipher
	if security == "" {
		security = "auto"
	}
	packetEncoding := v.PacketEncoding
	switch packetEncoding {
	case "":
		if v.XUDP.Value() {
			packetEncoding = "xudp"
		} else if v.PacketAddr.Value() {
			packetEncoding = "packetaddr"
		}
	case "packet":
		packetEncoding = "packetaddr"
	}
	// Clash omits the tls key for h2, which only exists over TLS.
	tls := v.tlsOptions.build(v.Server, v.Network == "h2")
	return &option.VMessOutboundOptions{
		DialerOptions:               v.dialerOptions.build(),
		ServerOptions:               v.serverOptions.build(),
		UUID:                        string(v.UUID),
		Security:                    security,
		AlterId:                     alterID,
		GlobalPadding:               v.GlobalPadding.Value(),
		AuthenticatedLength:         v.AuthenticatedLength.Value(),
		Network:                     networks(v.UDP),
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tls},
		PacketEncoding:              packetEncoding,
		Multiplex:                   v.MuxOpts.build(),
		Transport:                   transport,
	}, nil
}
