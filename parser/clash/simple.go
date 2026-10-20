package clash

import (
	"strings"

	mierupb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/parser/subscription"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
)

type socksOptions struct {
	dialerOptions
	serverOptions
	UserName string              `json:"username"`
	Password subscription.String `json:"password"`
	UDP      subscription.Bool   `json:"udp"`
	TLS      subscription.Bool   `json:"tls"`
}

func (s *socksOptions) Build() (any, error) {
	if err := s.serverOptions.check(); err != nil {
		return nil, err
	}
	// Clash can wrap a SOCKS connection in TLS; sing-box's SOCKS outbound
	// cannot, and speaking SOCKS in the clear to a TLS listener gets nowhere.
	if s.TLS.Value() {
		return nil, E.New("SOCKS over TLS has no sing-box equivalent")
	}
	return &option.SOCKSOutboundOptions{
		DialerOptions: s.dialerOptions.build(),
		ServerOptions: s.serverOptions.build(),
		Version:       "5",
		Username:      s.UserName,
		Password:      string(s.Password),
		Network:       networks(s.UDP),
	}, nil
}

type httpOptions struct {
	dialerOptions
	serverOptions
	tlsOptions
	UserName string              `json:"username"`
	Password subscription.String `json:"password"`
	Headers  map[string]string   `json:"headers"`
}

func (h *httpOptions) Build() (any, error) {
	if err := h.serverOptions.check(); err != nil {
		return nil, err
	}
	if err := h.tlsOptions.check(); err != nil {
		return nil, err
	}
	return &option.HTTPOutboundOptions{
		DialerOptions:               h.dialerOptions.build(),
		ServerOptions:               h.serverOptions.build(),
		Username:                    h.UserName,
		Password:                    string(h.Password),
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: h.tlsOptions.build(h.Server, false)},
		Headers:                     subscription.Headers(h.Headers),
	}, nil
}

type sshOptions struct {
	dialerOptions
	serverOptions
	UserName             string                  `json:"username"`
	Password             string                  `json:"password"`
	PrivateKey           string                  `json:"private-key"`
	PrivateKeyPassphrase string                  `json:"private-key-passphrase"`
	HostKey              subscription.StringList `json:"host-key"`
	HostKeyAlgorithms    subscription.StringList `json:"host-key-algorithms"`
}

func (s *sshOptions) Build() (any, error) {
	if err := s.serverOptions.check(); err != nil {
		return nil, err
	}
	options := &option.SSHOutboundOptions{
		DialerOptions:        s.dialerOptions.build(),
		ServerOptions:        s.serverOptions.build(),
		User:                 s.UserName,
		Password:             s.Password,
		PrivateKeyPassphrase: s.PrivateKeyPassphrase,
		HostKey:              badoption.Listable[string](s.HostKey),
		HostKeyAlgorithms:    badoption.Listable[string](s.HostKeyAlgorithms),
	}
	if strings.Contains(s.PrivateKey, "PRIVATE KEY") {
		options.PrivateKey = nonEmptyLines(s.PrivateKey)
	} else {
		options.PrivateKeyPath = s.PrivateKey
	}
	return options, nil
}

type snellOptions struct {
	dialerOptions
	serverOptions
	PSK      subscription.String `json:"psk"`
	Version  subscription.Int    `json:"version"`
	UDP      subscription.Bool   `json:"udp"`
	Reuse    subscription.Bool   `json:"reuse"`
	ObfsOpts map[string]any      `json:"obfs-opts"`
	UserKey  string              `json:"userkey"`
	Mode     string              `json:"mode"`
}

func (s *snellOptions) Build() (any, error) {
	if err := s.serverOptions.check(); err != nil {
		return nil, err
	}
	if s.PSK == "" {
		return nil, E.New("missing psk")
	}
	options := &option.SnellOutboundOptions{
		Version: int(s.Version),
		AbstractSnellOutboundOptions: option.AbstractSnellOutboundOptions{
			DialerOptions: s.dialerOptions.build(),
			ServerOptions: s.serverOptions.build(),
			PSK:           string(s.PSK),
			UserKey:       s.UserKey,
			Reuse:         s.Reuse.Value(),
			Network:       networks(s.UDP),
		},
	}
	if options.Version == 5 {
		options.Version = 4
	}
	if options.Version != 4 && options.Version != 6 {
		return nil, E.New("Snell requires version 4 or 6; legacy servers must be upgraded")
	}
	if mode := pluginString(s.ObfsOpts, "mode"); mode != "" {
		if options.Version != 4 {
			return nil, E.New("Snell obfs is only supported by version 4")
		}
		options.ObfsOptions = option.SnellObfsClientOptions{
			ObfsMode: mode,
			ObfsHost: pluginString(s.ObfsOpts, "host"),
		}
	}
	if s.Mode != "" && options.Version != 6 {
		return nil, E.New("Snell mode is only supported by version 6")
	}
	options.V6Options.Mode = s.Mode
	return options, nil
}

type mieruOptions struct {
	dialerOptions
	serverOptions
	PortRange      string              `json:"port-range"`
	Transport      string              `json:"transport"`
	UserName       string              `json:"username"`
	Password       subscription.String `json:"password"`
	Multiplexing   string              `json:"multiplexing"`
	HandshakeMode  string              `json:"handshake-mode"`
	MTU            subscription.Int    `json:"mtu"`
	TrafficPattern string              `json:"traffic-pattern"`
}

func (m *mieruOptions) Build() (any, error) {
	if m.Server == "" {
		return nil, E.New("missing server")
	}
	if m.Port == 0 && m.PortRange == "" {
		return nil, E.New("missing port")
	}
	if m.UserName == "" || m.Password == "" {
		return nil, E.New("missing credentials")
	}
	transport := strings.ToUpper(m.Transport)
	if transport == "" {
		transport = "TCP"
	}
	if transport != "TCP" && transport != "UDP" {
		return nil, E.New("unsupported Mieru transport: ", m.Transport)
	}
	mode := strings.ToUpper(m.HandshakeMode)
	if mode != "" {
		if !strings.HasPrefix(mode, "HANDSHAKE_") {
			mode = "HANDSHAKE_" + mode
		}
		if _, ok := mierupb.HandshakeMode_value[mode]; !ok {
			return nil, E.New("unsupported Mieru handshake mode: ", m.HandshakeMode)
		}
	}
	if m.MTU < 0 || m.MTU > 65535 {
		return nil, E.New("invalid Mieru MTU: ", m.MTU)
	}
	options := &option.MieruOutboundOptions{
		DialerOptions:  m.dialerOptions.build(),
		ServerOptions:  option.ServerOptions{Server: m.Server, ServerPort: uint16(m.Port)},
		Transport:      transport,
		UserName:       m.UserName,
		Password:       string(m.Password),
		Multiplexing:   m.Multiplexing,
		TrafficPattern: m.TrafficPattern,
		MTU:            uint32(m.MTU),
		HandshakeMode:  mode,
	}
	if m.PortRange != "" {
		options.ServerPortRanges = badoption.Listable[string]{m.PortRange}
	}
	return options, nil
}
