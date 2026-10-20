package link

import (
	"net/url"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/parser/subscription"
	E "github.com/sagernet/sing/common/exceptions"
)

// parseShadowsocksLink reads the three shapes a Shadowsocks link comes in: the
// original one, which encodes the whole of method:password@host:port; SIP002,
// which encodes only the credentials; and the plain form that encodes nothing.
func parseShadowsocksLink(link string) (option.Outbound, error) {
	linkURL, err := shadowsocksLinkURL(strings.TrimPrefix(link, "ss://"))
	if err != nil {
		return option.Outbound{}, err
	}
	server, port, q, err := linkEndpoint(linkURL, 0)
	if err != nil {
		return option.Outbound{}, err
	}
	switch strings.ToLower(q.get("type", "net")) {
	case "", "tcp", "raw", "none":
	default:
		return option.Outbound{}, E.New("unsupported transport of Xray for Shadowsocks: ", q.get("type", "net"))
	}
	switch strings.ToLower(q.get("security")) {
	case "", "none":
	default:
		return option.Outbound{}, E.New("unsupported security of Xray for Shadowsocks: ", q.get("security"))
	}
	password, _ := linkURL.User.Password()
	options := &option.ShadowsocksOutboundOptions{
		ServerOptions: option.ServerOptions{Server: server, ServerPort: port},
		Method:        linkURL.User.Username(),
		Password:      password,
	}
	if plugin := q.get("plugin"); plugin != "" {
		name, arguments, _ := strings.Cut(plugin, ";")
		if pluginNamesLocalFile(arguments) {
			return option.Outbound{}, E.New("unsupported plugin option: cert names a file of this router")
		}
		options.Plugin = name
		options.PluginOptions = arguments
	}
	if q.flag("udp-over-tcp") || q.get("uot") == "1" {
		options.UDPOverTCP = &option.UDPOverTCPOptions{Enabled: true, Version: 2}
	}
	return option.Outbound{
		Type:    C.TypeShadowsocks,
		Tag:     linkURL.Fragment,
		Options: options,
	}, nil
}

func shadowsocksLinkURL(body string) (*url.URL, error) {
	body, fragment, _ := strings.Cut(body, "#")
	payload, rawQuery, hasQuery := strings.Cut(body, "?")
	credentials, endpoint, hasEndpoint := strings.Cut(payload, "@")
	encoded := false
	if !hasEndpoint {
		decoded, isEncoded := subscription.DecodeBase64(payload)
		if !isEncoded {
			return nil, E.New("invalid Shadowsocks link")
		}
		// The password may itself contain an at sign, so the endpoint is what
		// follows the last one.
		index := strings.LastIndex(decoded, "@")
		if index < 0 {
			return nil, E.New("invalid Shadowsocks link")
		}
		credentials, endpoint, encoded = decoded[:index], decoded[index+1:], true
	} else if decoded, isEncoded := subscription.DecodeBase64(credentials); isEncoded {
		credentials, encoded = decoded, true
	}
	// SIP002 separates the query from the port with a slash, and generators fold
	// the path and the query into an encoded payload, often leaving an empty
	// query behind.
	if cut := strings.IndexAny(endpoint, "/?#"); cut >= 0 {
		tail := endpoint[cut:]
		endpoint = endpoint[:cut]
		if inner, found := strings.CutPrefix(strings.TrimPrefix(tail, "/"), "?"); found && !hasQuery {
			rawQuery, hasQuery = inner, inner != ""
		}
	}
	method, password, hasPassword := strings.Cut(credentials, ":")
	if !hasPassword {
		return nil, E.New("invalid Shadowsocks credentials")
	}
	if !encoded {
		// Only a link that wrote the credentials out escapes them.
		method, _ = url.PathUnescape(method)
		password, _ = url.PathUnescape(password)
	}
	tag, err := url.PathUnescape(fragment)
	if err != nil {
		tag = fragment
	}
	linkURL := &url.URL{
		Scheme:   "ss",
		User:     url.UserPassword(method, password),
		Host:     endpoint,
		Fragment: tag,
	}
	if hasQuery {
		linkURL.RawQuery = rawQuery
	}
	if linkURL.Hostname() == "" {
		return nil, E.New("missing server")
	}
	return linkURL, nil
}

// v2ray-plugin reads a certificate from the file of this router that cert= names.
func pluginNamesLocalFile(arguments string) bool {
	for _, argument := range strings.Split(arguments, ";") {
		key, _, _ := strings.Cut(argument, "=")
		if strings.EqualFold(strings.TrimSpace(key), "cert") {
			return true
		}
	}
	return false
}
