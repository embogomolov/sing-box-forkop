package clash

import (
	"encoding/base64"
	"encoding/pem"
	"strings"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/parser/subscription"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	N "github.com/sagernet/sing/common/network"
)

type serverOptions struct {
	Server string            `json:"server"`
	Port   subscription.Port `json:"port"`
}

func (s *serverOptions) check() error {
	if s.Server == "" {
		return E.New("missing server")
	}
	if s.Port == 0 {
		return E.New("missing port")
	}
	return nil
}

func (s *serverOptions) build() option.ServerOptions {
	return option.ServerOptions{
		Server:     s.Server,
		ServerPort: uint16(s.Port),
	}
}

type dialerOptions struct {
	TFO         subscription.Bool `json:"tfo"`
	MPTCP       subscription.Bool `json:"mptcp"`
	Interface   string            `json:"interface-name"`
	RoutingMark subscription.Int  `json:"routing-mark"`
	DialerProxy string            `json:"dialer-proxy"`
}

func (d *dialerOptions) build() option.DialerOptions {
	detour := d.DialerProxy
	switch strings.ToUpper(detour) {
	case "DIRECT", "GLOBAL", "COMPATIBLE":
		// Clash names the plain connection DIRECT; sing-box writes it as no
		// detour at all.
		detour = ""
	}
	return option.DialerOptions{
		Detour: detour,
		AbstractDialerOptions: option.AbstractDialerOptions{
			BindInterface: d.Interface,
			TCPFastOpen:   d.TFO.Value(),
			TCPMultiPath:  d.MPTCP.Value(),
			RoutingMark:   option.FwMark(d.RoutingMark),
		},
	}
}

// tlsOptions covers the TLS fields Clash inlines into every proxy, with the three obfuscation
// layers it can put under TLS. Those are different handshakes, so a node carrying one is skipped.
type tlsOptions struct {
	TLS               subscription.Bool       `json:"tls"`
	SNI               string                  `json:"sni"`
	ServerName        string                  `json:"servername"`
	SkipCertVerify    subscription.Bool       `json:"skip-cert-verify"`
	ALPN              subscription.StringList `json:"alpn"`
	ClientFingerprint string                  `json:"client-fingerprint"`
	CustomCA          string                  `json:"ca"`
	CustomCAString    string                  `json:"ca-str"`
	Certificate       string                  `json:"certificate"`
	PrivateKey        string                  `json:"private-key"`
	ECHOpts           *echOptions             `json:"ech-opts"`
	RealityOpts       *realityOptions         `json:"reality-opts"`
	ShadowTLSOpts     *shadowTLSOptions       `json:"shadow-tls-opts"`
	RestlsOpts        *restlsOptions          `json:"restls-opts"`
	JLSOpts           *jlsOptions             `json:"jls-opts"`
}

type echOptions struct {
	Enable          subscription.Bool `json:"enable"`
	Config          string            `json:"config"`
	QueryServerName string            `json:"query-server-name"`
}

type realityOptions struct {
	PublicKey string `json:"public-key"`
	ShortID   string `json:"short-id"`
}

type shadowTLSOptions struct {
	Password string           `json:"password"`
	Version  subscription.Int `json:"version"`
}

type restlsOptions struct {
	Password     string `json:"password"`
	VersionHint  string `json:"version-hint"`
	RestlsScript string `json:"restls-script"`
}

type jlsOptions struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (t *tlsOptions) check() error {
	for _, layer := range []struct {
		name    string
		options any
	}{
		{"shadow-tls-opts", t.ShadowTLSOpts},
		{"restls-opts", t.RestlsOpts},
		{"jls-opts", t.JLSOpts},
	} {
		if subscription.IsSet(layer.options) {
			return E.New("Clash ", layer.name, " changes the handshake and has no sing-box equivalent")
		}
	}
	if t.ServerName != "" && t.SNI != "" && t.ServerName != t.SNI {
		return E.New("conflicting Clash sni and servername")
	}
	return nil
}

func (t *tlsOptions) serverName() string {
	if t.ServerName != "" {
		return t.ServerName
	}
	return t.SNI
}

// build renders the TLS block. enabled says whether the protocol carries TLS by
// definition - Trojan, TUIC, Hysteria and AnyTLS always do, and Clash omits the
// tls key for them.
func (t *tlsOptions) build(server string, enabled bool) *option.OutboundTLSOptions {
	if !enabled && !t.TLS.Value() {
		return nil
	}
	serverName := t.serverName()
	if serverName == "" {
		serverName = server
	}
	options := &option.OutboundTLSOptions{
		Enabled:         true,
		ServerName:      serverName,
		Insecure:        t.SkipCertVerify.Value(),
		ALPN:            badoption.Listable[string](t.ALPN),
		CertificatePath: t.CustomCA,
		Certificate:     nonEmptyLines(t.CustomCAString),
	}
	if t.ClientFingerprint != "" {
		options.UTLS = &option.OutboundUTLSOptions{Enabled: true, Fingerprint: t.ClientFingerprint}
	}
	if subscription.IsSet(t.RealityOpts) {
		options.Reality = &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: t.RealityOpts.PublicKey,
			ShortID:   t.RealityOpts.ShortID,
		}
		if options.UTLS == nil {
			// Reality is only distinguishable from the site it borrows when the
			// hello is a browser's, and Clash always sends one.
			options.UTLS = &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"}
		}
	}
	if t.ECHOpts != nil && t.ECHOpts.Enable.Value() {
		options.ECH = &option.OutboundECHOptions{
			Enabled:         true,
			QueryServerName: t.ECHOpts.QueryServerName,
		}
		if list, err := base64.StdEncoding.DecodeString(t.ECHOpts.Config); err == nil && len(list) > 0 {
			options.ECH.Config = nonEmptyLines(string(pem.EncodeToMemory(&pem.Block{Type: "ECH CONFIGS", Bytes: list})))
		}
	}
	if strings.HasPrefix(t.Certificate, "-----BEGIN ") {
		options.ClientCertificate = nonEmptyLines(t.Certificate)
	} else {
		options.ClientCertificatePath = t.Certificate
	}
	if strings.HasPrefix(t.PrivateKey, "-----BEGIN ") {
		options.ClientKey = nonEmptyLines(t.PrivateKey)
	} else {
		options.ClientKeyPath = t.PrivateKey
	}
	return options
}

type muxOptions struct {
	Enabled        subscription.Bool `json:"enabled"`
	Protocol       string            `json:"protocol"`
	MaxConnections subscription.Int  `json:"max-connections"`
	MinStreams     subscription.Int  `json:"min-streams"`
	MaxStreams     subscription.Int  `json:"max-streams"`
	Padding        subscription.Bool `json:"padding"`
	BrutalOpts     *brutalOptions    `json:"brutal-opts"`
}

func (m *muxOptions) build() *option.OutboundMultiplexOptions {
	if m == nil {
		return nil
	}
	return &option.OutboundMultiplexOptions{
		Enabled:        m.Enabled.Value(),
		Protocol:       m.Protocol,
		MaxConnections: int(m.MaxConnections),
		MinStreams:     int(m.MinStreams),
		MaxStreams:     int(m.MaxStreams),
		Padding:        m.Padding.Value(),
		Brutal:         m.BrutalOpts.build(),
	}
}

type brutalOptions struct {
	Enabled subscription.Bool `json:"enabled"`
	Up      string            `json:"up"`
	Down    string            `json:"down"`
}

func (b *brutalOptions) build() *option.BrutalOptions {
	if b == nil {
		return nil
	}
	return &option.BrutalOptions{
		Enabled:  b.Enabled.Value(),
		UpMbps:   subscription.BandwidthMbps(b.Up),
		DownMbps: subscription.BandwidthMbps(b.Down),
	}
}

func networks(udpEnabled subscription.Bool) option.NetworkList {
	if !udpEnabled.Value() {
		return N.NetworkTCP
	}
	return ""
}

func nonEmptyLines(content string) []string {
	if content == "" {
		return nil
	}
	return common.Filter(strings.Split(content, "\n"), func(line string) bool {
		return strings.TrimSpace(line) != ""
	})
}
