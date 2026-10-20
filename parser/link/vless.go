package link

import (
	"net/url"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/parser/subscription"
	E "github.com/sagernet/sing/common/exceptions"
)

func parseVLESSLink(link string) (option.Outbound, error) {
	linkURL, err := url.Parse(link)
	if err != nil {
		return option.Outbound{}, err
	}
	if linkURL.User == nil || linkURL.User.Username() == "" {
		return option.Outbound{}, E.New("missing uuid")
	}
	server, err := serverAddress(linkURL)
	if err != nil {
		return option.Outbound{}, err
	}
	port, err := serverPort(linkURL, 0)
	if err != nil {
		return option.Outbound{}, err
	}
	q := linkQuery(linkURL)
	flow := q.get("flow")
	if err = subscription.CheckVLESSFlow(flow); err != nil {
		return option.Outbound{}, err
	}
	transport, err := linkTransport(q)
	if err != nil {
		return option.Outbound{}, err
	}
	tls, err := linkTLS(q, server, false)
	if err != nil {
		return option.Outbound{}, err
	}
	if tls != nil && len(tls.ALPN) == 0 && transport != nil && transport.Type == C.V2RayTransportTypeXHTTP {
		// XHTTP runs over HTTP; a client offering no protocol gets what the CDN in front prefers, rarely
		// what the server listens for, so links offer both.
		tls.ALPN = []string{"h2", "http/1.1"}
	}
	options := &option.VLESSOutboundOptions{
		ServerOptions:               option.ServerOptions{Server: server, ServerPort: port},
		UUID:                        linkURL.User.Username(),
		Flow:                        flow,
		Encryption:                  subscription.VLESSEncryption(q.get("encryption")),
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tls},
		Transport:                   transport,
		DialerOptions:               option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{TCPFastOpen: q.flag("tfo", "tcp-fast-open", "tcp_fast_open")}},
	}
	if encoding := q.get("packetEncoding", "packet_encoding"); encoding != "" {
		options.PacketEncoding = &encoding
	}
	return option.Outbound{
		Type:    C.TypeVLESS,
		Tag:     linkURL.Fragment,
		Options: options,
	}, nil
}
