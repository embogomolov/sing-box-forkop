package link

import (
	"net/url"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func parseTrojanLink(link string) (option.Outbound, error) {
	linkURL, err := url.Parse(link)
	if err != nil {
		return option.Outbound{}, err
	}
	if linkURL.User == nil || linkURL.User.Username() == "" {
		return option.Outbound{}, E.New("missing password")
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
	var tls *option.OutboundTLSOptions
	if !strings.EqualFold(q.get("security"), "none") {
		tls, err = linkTLS(q, server, true)
		if err != nil {
			return option.Outbound{}, err
		}
	}
	transport, err := linkTransport(q, tls)
	if err != nil {
		return option.Outbound{}, err
	}
	return option.Outbound{
		Type: C.TypeTrojan,
		Tag:  linkURL.Fragment,
		Options: &option.TrojanOutboundOptions{
			ServerOptions:               option.ServerOptions{Server: server, ServerPort: port},
			Password:                    linkURL.User.Username(),
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tls},
			Transport:                   transport,
			DialerOptions:               option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{TCPFastOpen: q.flag("tfo", "tcp-fast-open", "tcp_fast_open")}},
		},
	}, nil
}
