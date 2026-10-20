package link

import (
	"net/url"
	"strings"

	"github.com/sagernet/sing-box/common"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
)

func parseTuicLink(link string) (option.Outbound, error) {
	linkURL, err := url.Parse(link)
	if err != nil {
		return option.Outbound{}, err
	}
	if linkURL.User == nil || linkURL.User.Username() == "" {
		return option.Outbound{}, E.New("missing uuid")
	}
	var options option.TUICOutboundOptions
	TLSOptions := option.OutboundTLSOptions{
		Enabled: true,
		ECH:     &option.OutboundECHOptions{},
		UTLS:    &option.OutboundUTLSOptions{},
		Reality: &option.OutboundRealityOptions{},
	}
	options.UUID = linkURL.User.Username()
	options.Password, _ = linkURL.User.Password()
	options.ServerOptions.Server = linkURL.Hostname()
	TLSOptions.ServerName = linkURL.Hostname()
	options.ServerOptions.ServerPort = common.StringToType[uint16](linkURL.Port())
	for key, values := range linkURL.Query() {
		value := values[0]
		switch key {
		case "congestion_control":
			if value != "cubic" {
				options.CongestionControl = value
			}
		case "udp_relay_mode":
			options.UDPRelayMode = value
		case "udp_over_stream":
			if value == "true" || value == "1" {
				options.UDPOverStream = true
			}
		case "zero_rtt_handshake", "reduce_rtt":
			if value == "true" || value == "1" {
				options.ZeroRTTHandshake = true
			}
		case "heartbeat_interval":
			options.Heartbeat = common.StringToType[badoption.Duration](value)
		case "sni":
			TLSOptions.ServerName = value
		case "insecure", "skip-cert-verify", "allow_insecure":
			if value == "1" || value == "true" {
				TLSOptions.Insecure = true
			}
		case "disable_sni":
			if value == "1" || value == "true" {
				TLSOptions.DisableSNI = true
			}
		case "tfo", "tcp-fast-open", "tcp_fast_open":
			if value == "1" || value == "true" {
				options.TCPFastOpen = true
			}
		case "alpn":
			TLSOptions.ALPN = strings.Split(value, ",")
		}
	}
	if options.UDPOverStream {
		options.UDPRelayMode = ""
	}
	outbound := option.Outbound{
		Type: C.TypeTUIC,
		Tag:  linkURL.Fragment,
	}
	options.TLS = &TLSOptions
	outbound.Options = &options
	return outbound, nil
}
