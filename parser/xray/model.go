package xray

import (
	"encoding/json"

	"github.com/sagernet/sing-box/parser/subscription"
	"github.com/sagernet/sing-box/parser/xhttp"
	E "github.com/sagernet/sing/common/exceptions"
)

// The model follows Xray's configuration types, naming only the fields that decide how a
// connection is made; the rest is ignored, as Xray ignores it for dialling a server.

type document struct {
	Remarks   string            `json:"remarks"`
	Outbounds []json.RawMessage `json:"outbounds"`
}

type sourceOutbound struct {
	Protocol       string          `json:"protocol"`
	Tag            string          `json:"tag"`
	Settings       json.RawMessage `json:"settings"`
	StreamSettings streamSettings  `json:"streamSettings"`
	ProxySettings  *proxySettings  `json:"proxySettings"`
}

// proxySettings names another outbound to reach this server through. Xray dials
// through the named handler either way; transportLayer only decides whether it
// does so as a transport or as a protocol, and both are a detour in sing-box.
type proxySettings struct {
	Tag string `json:"tag"`
}

type sockopt struct {
	DialerProxy string `json:"dialerProxy"`
}

type streamSettings struct {
	Network  string `json:"network"`
	Security string `json:"security"`

	Sockopt          sockopt          `json:"sockopt"`
	HysteriaSettings hysteriaSettings `json:"hysteriaSettings"`

	TLSSettings     *tlsSettings `json:"tlsSettings"`
	RealitySettings *tlsSettings `json:"realitySettings"`

	TCPSettings         *tcpSettings         `json:"tcpSettings"`
	RAWSettings         *tcpSettings         `json:"rawSettings"`
	WSSettings          *websocketSettings   `json:"wsSettings"`
	GRPCSettings        *grpcSettings        `json:"grpcSettings"`
	HTTPSettings        *httpSettings        `json:"httpSettings"`
	HTTPUpgradeSettings *httpUpgradeSettings `json:"httpupgradeSettings"`
	XHTTPSettings       *xhttp.Settings      `json:"xhttpSettings"`
	SplitHTTPSettings   *xhttp.Settings      `json:"splithttpSettings"`
}

// transport reports which transport the stream settings select, resolving the
// spellings Xray accepts for the same one.
func (s streamSettings) transport() string {
	network := s.Network
	switch network {
	case "", "tcp", "raw":
		return "tcp"
	case "ws", "websocket":
		return "ws"
	case "grpc", "gun":
		return "grpc"
	case "http", "h2", "h3":
		return "http"
	case "httpupgrade":
		return "httpupgrade"
	case "xhttp", "splithttp":
		return "xhttp"
	}
	return network
}

func (s streamSettings) tcp() *tcpSettings {
	if s.RAWSettings != nil {
		return s.RAWSettings
	}
	return s.TCPSettings
}

func (s streamSettings) xhttp() *xhttp.Settings {
	if s.XHTTPSettings != nil {
		return s.XHTTPSettings
	}
	return s.SplitHTTPSettings
}

type hysteriaSettings struct {
	Version subscription.Int `json:"version"`
	Auth    string           `json:"auth"`
}

type tlsSettings struct {
	ServerName           string                  `json:"serverName"`
	ALPN                 subscription.StringList `json:"alpn"`
	AllowInsecure        subscription.Bool       `json:"allowInsecure"`
	VerifyPeerCertByName subscription.StringList `json:"verifyPeerCertByName"`
	Fingerprint          string                  `json:"fingerprint"`
	ECHConfigList        string                  `json:"echConfigList"`
	PublicKey            string                  `json:"publicKey"`
	Password             string                  `json:"password"`
	ShortID              string                  `json:"shortId"`
}

type websocketSettings struct {
	Host string `json:"host"`
	Path string `json:"path"`
	// A v2fly document spells the early data length out instead of writing it
	// into the path as Xray does.
	MaxEarlyData        subscription.Int  `json:"maxEarlyData"`
	EarlyDataHeaderName string            `json:"earlyDataHeaderName"`
	Headers             map[string]string `json:"headers"`
}

type tcpSettings struct {
	Header struct {
		Type string `json:"type"`
	} `json:"header"`
}

type grpcSettings struct {
	ServiceName string `json:"serviceName"`
}

type httpSettings struct {
	Host subscription.StringList `json:"host"`
	Path subscription.StringList `json:"path"`
}

type httpUpgradeSettings struct {
	Host    string            `json:"host"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
}

// uniqueString takes the value of several spellings of one setting, refusing a
// document that gives them different values rather than guessing which one the
// server was configured with.
func uniqueString(name string, values ...string) (string, error) {
	var selected string
	for _, value := range values {
		if value == "" {
			continue
		}
		if selected != "" && value != selected {
			return "", E.New("conflicting Xray ", name)
		}
		selected = value
	}
	return selected, nil
}
