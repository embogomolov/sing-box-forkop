package link

import (
	"net/url"
	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/parser/subscription"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
)

func parseAnyTLSLink(link string) (option.Outbound, error) {
	linkURL, err := url.Parse(link)
	if err != nil {
		return option.Outbound{}, err
	}
	if linkURL.User == nil || linkURL.User.Username() == "" {
		return option.Outbound{}, E.New("missing password")
	}
	server, port, q, err := linkEndpoint(linkURL, 0)
	if err != nil {
		return option.Outbound{}, err
	}
	tls, err := linkTLS(q, server, true)
	if err != nil {
		return option.Outbound{}, err
	}
	return option.Outbound{
		Type: C.TypeAnyTLS,
		Tag:  linkURL.Fragment,
		Options: &option.AnyTLSOutboundOptions{
			ServerOptions:               option.ServerOptions{Server: server, ServerPort: port},
			Password:                    linkURL.User.Username(),
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tls},
			DialerOptions:               option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{TCPFastOpen: q.flag("tfo", "tcp-fast-open", "tcp_fast_open")}},
		},
	}, nil
}

func parseTuicLink(link string) (option.Outbound, error) {
	linkURL, err := url.Parse(link)
	if err != nil {
		return option.Outbound{}, err
	}
	if linkURL.User == nil || linkURL.User.Username() == "" {
		return option.Outbound{}, E.New("missing uuid")
	}
	server, port, q, err := linkEndpoint(linkURL, 0)
	if err != nil {
		return option.Outbound{}, err
	}
	tls, err := linkTLS(q, server, true)
	if err != nil {
		return option.Outbound{}, err
	}
	tls = subscription.QUICSecurity(tls)
	tls.DisableSNI = q.flag("disable_sni", "disable-sni")
	// A link that names one credential rather than a pair is TUIC v4, whose
	// handshake version 5 replaced; sing-box only speaks version 5, so such a
	// server never gets past it.
	password, isVersion5 := linkURL.User.Password()
	if !isVersion5 {
		return option.Outbound{}, E.New("TUIC v4 has no sing-box equivalent")
	}
	options := &option.TUICOutboundOptions{
		ServerOptions:               option.ServerOptions{Server: server, ServerPort: port},
		UUID:                        linkURL.User.Username(),
		Password:                    password,
		UDPRelayMode:                q.get("udp_relay_mode", "udp-relay-mode"),
		UDPOverStream:               q.flag("udp_over_stream", "udp-over-stream"),
		ZeroRTTHandshake:            q.flag("zero_rtt_handshake", "reduce_rtt", "reduce-rtt"),
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tls},
		DialerOptions:               option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{TCPFastOpen: q.flag("tfo", "tcp-fast-open", "tcp_fast_open")}},
	}
	if control := q.get("congestion_control", "congestion-control"); control != "" && control != "cubic" {
		options.CongestionControl = control
	}
	if heartbeat := q.get("heartbeat_interval", "heartbeat-interval"); heartbeat != "" {
		var duration badoption.Duration
		if err = duration.UnmarshalJSON([]byte(`"` + heartbeat + `"`)); err != nil {
			return option.Outbound{}, E.Cause(err, "invalid heartbeat interval")
		}
		options.Heartbeat = duration
	}
	if options.UDPOverStream {
		options.UDPRelayMode = ""
	}
	return option.Outbound{Type: C.TypeTUIC, Tag: linkURL.Fragment, Options: options}, nil
}

func parseHysteriaLink(link string) (option.Outbound, error) {
	linkURL, err := url.Parse(link)
	if err != nil {
		return option.Outbound{}, err
	}
	server, port, q, err := linkEndpoint(linkURL, 0)
	if err != nil {
		return option.Outbound{}, err
	}
	tls, err := linkTLS(q, server, true)
	if err != nil {
		return option.Outbound{}, err
	}
	tls = subscription.QUICSecurity(tls)
	if certificate := q.get("ca_str", "ca-str"); certificate != "" {
		tls.Certificate = badoption.Listable[string]{certificate}
	}
	tls.CertificatePath = q.get("ca")
	options := &option.HysteriaOutboundOptions{
		ServerOptions:               option.ServerOptions{Server: server, ServerPort: port},
		AuthString:                  q.get("auth", "auth_str", "auth-str"),
		Obfs:                        q.get("obfsParam", "obfs-param", "obfs"),
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tls},
		DialerOptions:               option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{TCPFastOpen: q.flag("tfo", "tcp-fast-open", "tcp_fast_open")}},
	}
	options.UpMbps, _ = strconv.Atoi(q.get("upmbps", "up_mbps"))
	options.DownMbps, _ = strconv.Atoi(q.get("downmbps", "down_mbps"))
	options.Up = subscription.ParseBandwidth(q.get("up"))
	options.Down = subscription.ParseBandwidth(q.get("down"))
	return option.Outbound{Type: C.TypeHysteria, Tag: linkURL.Fragment, Options: options}, nil
}

func parseHysteria2Link(link string) (option.Outbound, error) {
	link, ports := splitHopPorts(link)
	linkURL, err := url.Parse(link)
	if err != nil {
		return option.Outbound{}, err
	}
	// The Hysteria 2 URI leaves the port out when the server listens on 443.
	server, port, q, err := linkEndpoint(linkURL, 443)
	if err != nil {
		return option.Outbound{}, err
	}
	tls, err := linkTLS(q, server, true)
	if err != nil {
		return option.Outbound{}, err
	}
	options := &option.Hysteria2OutboundOptions{
		ServerOptions:               option.ServerOptions{Server: server, ServerPort: port},
		ServerPorts:                 ports,
		BBRProfile:                  q.get("bbr-profile", "bbr_profile"),
		DisableChromeParrot:         q.flag("disable-chrome-parrot", "disable_chrome_parrot"),
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: subscription.QUICSecurity(tls)},
	}
	options.HopInterval, options.HopIntervalMax, err = subscription.HopInterval(q.get("hop-interval", "hopInterval"))
	if err != nil {
		return option.Outbound{}, err
	}
	if linkURL.User != nil {
		options.Password = linkURL.User.Username()
		if password, isSet := linkURL.User.Password(); isSet && password != "" {
			// Hysteria 2 authenticates with one string; a link that splits it
			// around a colon means the whole of it.
			options.Password += ":" + password
		}
	}
	options.UpMbps = subscription.BandwidthMbps(q.get("up"))
	options.DownMbps = subscription.BandwidthMbps(q.get("down"))
	if obfs := q.get("obfs"); obfs != "" {
		if obfs != "salamander" && obfs != "gecko" {
			return option.Outbound{}, E.New("unsupported obfuscation: ", obfs)
		}
		options.Obfs = &option.Hysteria2Obfs{
			Type:     obfs,
			Password: q.get("obfs-password", "obfs_password"),
		}
	}
	return option.Outbound{Type: C.TypeHysteria2, Tag: linkURL.Fragment, Options: options}, nil
}

// linkEndpoint reads the server, the port and the parameters of a share link at
// once, since every one of them needs all three.
func linkEndpoint(linkURL *url.URL, fallbackPort uint16) (string, uint16, query, error) {
	server, err := serverAddress(linkURL)
	if err != nil {
		return "", 0, query{}, err
	}
	port, err := serverPort(linkURL, fallbackPort)
	if err != nil {
		return "", 0, query{}, err
	}
	return server, port, linkQuery(linkURL), nil
}

// splitHopPorts takes a Hysteria port hopping list out of a link's authority.
// The list is written where the port goes - host:443,20000-30000 - which is not
// a URL any more, so it has to come out before the link is parsed at all.
func splitHopPorts(link string) (string, badoption.Listable[string]) {
	scheme := strings.Index(link, "://")
	if scheme < 0 {
		return link, nil
	}
	head, rest := link[:scheme+3], link[scheme+3:]
	authority, tail := rest, ""
	if end := strings.IndexAny(rest, "/?#"); end >= 0 {
		authority, tail = rest[:end], rest[end:]
	}
	userinfo := ""
	if at := strings.LastIndex(authority, "@"); at >= 0 {
		userinfo, authority = authority[:at+1], authority[at+1:]
	}
	if strings.Contains(authority, "]") {
		return link, nil
	}
	colon := strings.LastIndex(authority, ":")
	if colon < 0 {
		return link, nil
	}
	host, ports := authority[:colon], authority[colon+1:]
	if !strings.ContainsAny(ports, ",-") {
		return link, nil
	}
	first, _, _ := strings.Cut(ports, ",")
	first, _, _ = strings.Cut(first, "-")
	if _, err := strconv.ParseUint(first, 10, 16); err != nil {
		return link, nil
	}
	return head + userinfo + host + ":" + first + tail, subscription.PortRanges(ports)
}
