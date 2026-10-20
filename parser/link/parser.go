package link

import (
	"strings"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// ParseSubscriptionLink reads one share link. A scheme no sing-box outbound can
// speak is reported rather than guessed at, so the caller leaves that one link
// out and keeps the rest of the subscription.
func ParseSubscriptionLink(link string) (option.Outbound, error) {
	scheme, _, found := strings.Cut(link, "://")
	if !found {
		return option.Outbound{}, E.New("not a share link")
	}
	switch strings.ToLower(scheme) {
	case "http2", "http3", "naive+https", "naive+quic":
		return parseNaiveLink(link)
	case "http", "https":
		return parseHTTPLink(link)
	case "mieru", "mierus":
		return parseMieruLink(link)
	case "socks", "socks4", "socks4a", "socks5", "socks5h":
		return parseSOCKSLink(link)
	case "tuic":
		return parseTuicLink(link)
	case "trojan":
		return parseTrojanLink(link)
	case "vless":
		return parseVLESSLink(link)
	case "hysteria", "hy":
		return parseHysteriaLink(link)
	case "hy2", "hysteria2":
		return parseHysteria2Link(link)
	case "anytls":
		return parseAnyTLSLink(link)
	case "ss":
		return parseShadowsocksLink(link)
	case "ssr":
		// sing-box removed ShadowsocksR in 1.6.0, so naming where the protocol
		// went beats reporting the scheme as merely unknown.
		return option.Outbound{}, E.New("ShadowsocksR was removed from sing-box in 1.6.0")
	case "vmess":
		return parseVMessLink(link)
	}
	return option.Outbound{}, E.New("unsupported scheme: ", scheme)
}
