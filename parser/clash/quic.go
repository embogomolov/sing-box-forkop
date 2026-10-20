package clash

import (
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/parser/subscription"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
)

// The QUIC protocols below count their intervals in whole seconds or
// milliseconds, while sing-box takes a duration, so every unit is spelled out.

type hysteriaOptions struct {
	dialerOptions
	serverOptions
	tlsOptions
	Ports               subscription.String `json:"ports"`
	Protocol            string              `json:"protocol"`
	ObfsProtocol        string              `json:"obfs-protocol"`
	Up                  subscription.String `json:"up"`
	UpSpeed             subscription.Int    `json:"up-speed"`
	Down                subscription.String `json:"down"`
	DownSpeed           subscription.Int    `json:"down-speed"`
	Auth                subscription.String `json:"auth"`
	AuthString          subscription.String `json:"auth-str"`
	Obfs                subscription.String `json:"obfs"`
	ReceiveWindowConn   subscription.Int    `json:"recv-window-conn"`
	ReceiveWindow       subscription.Int    `json:"recv-window"`
	DisableMTUDiscovery subscription.Bool   `json:"disable-mtu-discovery"`
	FastOpen            subscription.Bool   `json:"fast-open"`
	HopInterval         subscription.Int    `json:"hop-interval"`
}

func (h *hysteriaOptions) Build() (any, error) {
	if err := h.serverOptions.check(); err != nil {
		return nil, err
	}
	if err := h.tlsOptions.check(); err != nil {
		return nil, err
	}
	// Hysteria's protocol picks the packet shape on the wire. sing-box speaks
	// plain UDP only, and a faketcp server never answers a UDP client.
	for _, protocol := range []string{h.Protocol, h.ObfsProtocol} {
		switch protocol {
		case "", "udp":
		default:
			return nil, E.New("unsupported Hysteria protocol: ", protocol)
		}
	}
	dialer := h.dialerOptions.build()
	dialer.TCPFastOpen = dialer.TCPFastOpen || h.FastOpen.Value()
	return &option.HysteriaOutboundOptions{
		DialerOptions:               dialer,
		ServerOptions:               h.serverOptions.build(),
		ServerPorts:                 subscription.PortRanges(string(h.Ports)),
		HopInterval:                 badoption.Duration(time.Duration(h.HopInterval) * time.Second),
		Up:                          subscription.ParseBandwidth(string(h.Up)),
		UpMbps:                      int(h.UpSpeed),
		Down:                        subscription.ParseBandwidth(string(h.Down)),
		DownMbps:                    int(h.DownSpeed),
		Obfs:                        string(h.Obfs),
		Auth:                        []byte(h.Auth),
		AuthString:                  string(h.AuthString),
		ReceiveWindowConn:           uint64(h.ReceiveWindowConn),
		ReceiveWindow:               uint64(h.ReceiveWindow),
		DisableMTUDiscovery:         h.DisableMTUDiscovery.Value(),
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: subscription.QUICSecurity(h.tlsOptions.build(h.Server, true))},
	}, nil
}

type hysteria2Options struct {
	dialerOptions
	serverOptions
	tlsOptions
	Ports               subscription.String `json:"ports"`
	HopInterval         subscription.String `json:"hop-interval"`
	Up                  subscription.String `json:"up"`
	Down                subscription.String `json:"down"`
	Password            subscription.String `json:"password"`
	Obfs                subscription.String `json:"obfs"`
	ObfsPassword        subscription.String `json:"obfs-password"`
	BBRProfile          string              `json:"bbr-profile"`
	DisableChromeParrot subscription.Bool   `json:"disable-chrome-parrot"`
}

func (h *hysteria2Options) Build() (any, error) {
	if err := h.serverOptions.check(); err != nil {
		return nil, err
	}
	if err := h.tlsOptions.check(); err != nil {
		return nil, err
	}
	options := &option.Hysteria2OutboundOptions{
		DialerOptions:               h.dialerOptions.build(),
		ServerOptions:               h.serverOptions.build(),
		ServerPorts:                 subscription.PortRanges(string(h.Ports)),
		UpMbps:                      subscription.BandwidthMbps(string(h.Up)),
		DownMbps:                    subscription.BandwidthMbps(string(h.Down)),
		Password:                    string(h.Password),
		BBRProfile:                  h.BBRProfile,
		DisableChromeParrot:         h.DisableChromeParrot.Value(),
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: subscription.QUICSecurity(h.tlsOptions.build(h.Server, true))},
	}
	if h.Obfs != "" {
		if h.Obfs != "salamander" && h.Obfs != "gecko" {
			return nil, E.New("unsupported Hysteria 2 obfuscation: ", string(h.Obfs))
		}
		options.Obfs = &option.Hysteria2Obfs{Type: string(h.Obfs), Password: string(h.ObfsPassword)}
	}
	var err error
	options.HopInterval, options.HopIntervalMax, err = subscription.HopInterval(string(h.HopInterval))
	if err != nil {
		return nil, err
	}
	return options, nil
}

type tuicOptions struct {
	dialerOptions
	serverOptions
	tlsOptions
	Token                subscription.String `json:"token"`
	UUID                 string              `json:"uuid"`
	Password             subscription.String `json:"password"`
	IP                   string              `json:"ip"`
	HeartbeatInterval    subscription.Int    `json:"heartbeat-interval"`
	DisableSNI           subscription.Bool   `json:"disable-sni"`
	ReduceRTT            subscription.Bool   `json:"reduce-rtt"`
	UDPRelayMode         string              `json:"udp-relay-mode"`
	CongestionController string              `json:"congestion-controller"`
	FastOpen             subscription.Bool   `json:"fast-open"`
	UDPOverStream        subscription.Bool   `json:"udp-over-stream"`
}

func (t *tuicOptions) Build() (any, error) {
	if err := t.serverOptions.check(); err != nil {
		return nil, err
	}
	if err := t.tlsOptions.check(); err != nil {
		return nil, err
	}
	// A token names a TUIC v4 server. Version 5 replaced the handshake, and
	// sing-box only speaks version 5, so a v4 server never gets past it.
	if t.Token != "" {
		return nil, E.New("TUIC v4 has no sing-box equivalent")
	}
	if t.UUID == "" {
		return nil, E.New("missing uuid")
	}
	dialer := t.dialerOptions.build()
	dialer.TCPFastOpen = dialer.TCPFastOpen || t.FastOpen.Value()
	options := &option.TUICOutboundOptions{
		DialerOptions:               dialer,
		ServerOptions:               t.serverOptions.build(),
		UUID:                        t.UUID,
		Password:                    string(t.Password),
		CongestionControl:           t.CongestionController,
		UDPRelayMode:                t.UDPRelayMode,
		UDPOverStream:               t.UDPOverStream.Value(),
		ZeroRTTHandshake:            t.ReduceRTT.Value(),
		Heartbeat:                   badoption.Duration(time.Duration(t.HeartbeatInterval) * time.Millisecond),
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: subscription.QUICSecurity(t.tlsOptions.build(t.Server, true))},
	}
	if t.UDPOverStream.Value() {
		options.UDPRelayMode = ""
	}
	if t.IP != "" {
		// Clash dials the address in ip and keeps the server name for TLS.
		options.Server = t.IP
	}
	if t.DisableSNI.Value() {
		options.TLS.DisableSNI = true
	}
	return options, nil
}

type anyTLSOptions struct {
	dialerOptions
	serverOptions
	tlsOptions
	Password                 subscription.String `json:"password"`
	IdleSessionCheckInterval subscription.Int    `json:"idle-session-check-interval"`
	IdleSessionTimeout       subscription.Int    `json:"idle-session-timeout"`
	MinIdleSession           subscription.Int    `json:"min-idle-session"`
}

func (a *anyTLSOptions) Build() (any, error) {
	if err := a.serverOptions.check(); err != nil {
		return nil, err
	}
	if a.Password == "" {
		return nil, E.New("missing password")
	}
	if err := a.tlsOptions.check(); err != nil {
		return nil, err
	}
	return &option.AnyTLSOutboundOptions{
		DialerOptions:               a.dialerOptions.build(),
		ServerOptions:               a.serverOptions.build(),
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: a.tlsOptions.build(a.Server, true)},
		Password:                    string(a.Password),
		IdleSessionCheckInterval:    badoption.Duration(time.Duration(a.IdleSessionCheckInterval) * time.Second),
		IdleSessionTimeout:          badoption.Duration(time.Duration(a.IdleSessionTimeout) * time.Second),
		MinIdleSession:              int(a.MinIdleSession),
	}, nil
}
