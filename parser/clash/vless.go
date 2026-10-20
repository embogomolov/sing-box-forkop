package clash

import (
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/parser/subscription"
	E "github.com/sagernet/sing/common/exceptions"
)

type vlessOptions struct {
	dialerOptions
	serverOptions
	tlsOptions
	transportOptions
	UUID           subscription.String `json:"uuid"`
	Flow           string              `json:"flow"`
	Encryption     string              `json:"encryption"`
	UDP            subscription.Bool   `json:"udp"`
	PacketAddr     subscription.Bool   `json:"packet-addr"`
	PacketEncoding string              `json:"packet-encoding"`
	MuxOpts        *muxOptions         `json:"smux"`
}

func (v *vlessOptions) Build() (any, error) {
	if err := v.serverOptions.check(); err != nil {
		return nil, err
	}
	if v.UUID == "" {
		return nil, E.New("missing uuid")
	}
	if err := v.tlsOptions.check(); err != nil {
		return nil, err
	}
	if err := subscription.CheckVLESSFlow(v.Flow); err != nil {
		return nil, err
	}
	transport, err := v.transportOptions.build()
	if err != nil {
		return nil, err
	}
	// Leaving the encoding unset is what both Clash and sing-box read as xudp,
	// so a node that names none is left alone rather than written out with a
	// value the other formats would not have produced.
	packetEncoding := v.PacketEncoding
	switch {
	case packetEncoding == "packet":
		packetEncoding = "packetaddr"
	case packetEncoding == "" && v.PacketAddr.Value():
		packetEncoding = "packetaddr"
	}
	options := &option.VLESSOutboundOptions{
		DialerOptions:               v.dialerOptions.build(),
		ServerOptions:               v.serverOptions.build(),
		UUID:                        string(v.UUID),
		Flow:                        v.Flow,
		Encryption:                  subscription.VLESSEncryption(v.Encryption),
		Network:                     networks(v.UDP),
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: v.tlsOptions.build(v.Server, false)},
		Multiplex:                   v.MuxOpts.build(),
		Transport:                   transport,
	}
	if packetEncoding != "" {
		options.PacketEncoding = &packetEncoding
	}
	return options, nil
}
