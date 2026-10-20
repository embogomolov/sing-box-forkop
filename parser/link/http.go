package link

import (
	"net/url"
	"strconv"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func parseHTTPLink(link string) (option.Outbound, error) {
	linkURL, err := url.Parse(link)
	if err != nil {
		return option.Outbound{}, err
	}
	if linkURL.Hostname() == "" {
		return option.Outbound{}, E.New("missing server")
	}
	// A subscription can also contain ordinary web links, so only treat one as a
	// proxy when it names a proxy endpoint through credentials, an explicit port
	// or a node name.
	if linkURL.User == nil && linkURL.Port() == "" && linkURL.Fragment == "" {
		return option.Outbound{}, E.New("not an HTTP proxy link")
	}
	serverPort := uint64(80)
	if linkURL.Scheme == "https" {
		serverPort = 443
	}
	if linkURL.Port() != "" {
		serverPort, err = strconv.ParseUint(linkURL.Port(), 10, 16)
		if err != nil || serverPort == 0 {
			return option.Outbound{}, E.New("invalid server port")
		}
	}
	options := option.HTTPOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     linkURL.Hostname(),
			ServerPort: uint16(serverPort),
		},
		Path: linkURL.EscapedPath(),
	}
	if linkURL.User != nil {
		options.Username = linkURL.User.Username()
		options.Password, _ = linkURL.User.Password()
	}
	if linkURL.Scheme == "https" {
		options.TLS = &option.OutboundTLSOptions{Enabled: true}
	}
	return option.Outbound{
		Type:    C.TypeHTTP,
		Tag:     linkURL.Fragment,
		Options: &options,
	}, nil
}
