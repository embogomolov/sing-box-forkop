package link

import (
	"strings"
	"unicode/utf8"

	"github.com/sagernet/sing-box/common"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/parser/subscription"
	E "github.com/sagernet/sing/common/exceptions"
)

func parseSOCKSLink(link string) (option.Outbound, error) {
	linkURL, err := parseLinkURL(link)
	if err != nil {
		return option.Outbound{}, err
	}
	if linkURL.Hostname() == "" || linkURL.Port() == "" {
		return option.Outbound{}, E.New("missing server or port")
	}
	version := "5"
	switch linkURL.Scheme {
	case "socks4":
		version = "4"
	case "socks4a":
		version = "4a"
	}
	options := &option.SOCKSOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     linkURL.Hostname(),
			ServerPort: common.StringToType[uint16](linkURL.Port()),
		},
		Version: version,
	}
	if options.ServerPort == 0 {
		return option.Outbound{}, E.New("invalid server port")
	}
	if linkURL.User != nil {
		options.Username = linkURL.User.Username()
		options.Password, _ = linkURL.User.Password()
		if _, hasPassword := linkURL.User.Password(); !hasPassword && linkURL.Scheme == "socks" {
			// v2rayN writes "user:password" in base64
			if decoded, isEncoded := subscription.DecodeBase64(options.Username); isEncoded && utf8.ValidString(decoded) {
				if username, password, found := strings.Cut(decoded, ":"); found {
					options.Username, options.Password = username, password
				}
			}
		}
	}
	return option.Outbound{
		Type:    C.TypeSOCKS,
		Tag:     linkURL.Fragment,
		Options: options,
	}, nil
}
