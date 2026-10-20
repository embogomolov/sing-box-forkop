package xray

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/parser/subscription"
	"github.com/sagernet/sing-box/parser/xhttp"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
)

var (
	// errNotAServer marks the plumbing outbounds that every Xray document
	// carries beside the server it describes. They name no endpoint, so they
	// are skipped rather than reported as an unsupported protocol.
	errNotAServer = errors.New("not a server outbound")
	// errDropsTraffic marks the plumbing that discards what it is handed.
	// Dialing through Xray's freedom outbound is a direct connection and needs
	// no detour, but dialing through blackhole leaves the caller unusable.
	errDropsTraffic = fmt.Errorf("%w: drops traffic", errNotAServer)
)

type parsedOutbound struct {
	sourceTag string
	detour    string
	outbound  option.Outbound
}

func parseSourceOutbound(content json.RawMessage, fallbackTag string) (parsedOutbound, error) {
	var source sourceOutbound
	if err := json.Unmarshal(content, &source); err != nil {
		return parsedOutbound{}, err
	}
	protocol := strings.ToLower(source.Protocol)
	if protocol == "" {
		return parsedOutbound{}, E.New("missing protocol")
	}
	switch protocol {
	case "freedom", "direct":
		return parsedOutbound{}, errNotAServer
	case "blackhole", "block", "dns", "loopback":
		return parsedOutbound{}, errDropsTraffic
	}
	detour, err := sourceDetour(source)
	if err != nil {
		return parsedOutbound{}, err
	}
	tag := source.Tag
	if tag == "" {
		tag = fallbackTag
	}
	var options any
	var outboundType string
	switch protocol {
	case C.TypeVLESS:
		outboundType = C.TypeVLESS
		options, err = parseVLESS(source)
	case C.TypeVMess:
		outboundType = C.TypeVMess
		options, err = parseVMess(source)
	case C.TypeSOCKS:
		outboundType = C.TypeSOCKS
		options, err = parseSOCKS(source)
	case C.TypeShadowsocks, "ss":
		outboundType = C.TypeShadowsocks
		options, err = parseShadowsocks(source)
	case C.TypeTrojan:
		outboundType = C.TypeTrojan
		options, err = parseTrojan(source)
	case C.TypeHTTP:
		outboundType = C.TypeHTTP
		options, err = parseHTTP(source)
	case C.TypeHysteria:
		outboundType = C.TypeHysteria2
		options, err = parseHysteria2(source)
	default:
		return parsedOutbound{}, E.New("unsupported protocol: ", source.Protocol)
	}
	if err != nil {
		return parsedOutbound{}, err
	}
	if detour != "" {
		dialer := options.(option.DialerOptionsWrapper)
		dialerOptions := dialer.TakeDialerOptions()
		dialerOptions.Detour = detour
		dialer.ReplaceDialerOptions(dialerOptions)
	}
	return parsedOutbound{
		sourceTag: tag,
		detour:    detour,
		outbound: option.Outbound{
			Type:    outboundType,
			Tag:     tag,
			Options: options,
		},
	}, nil
}

func parseVLESS(source sourceOutbound) (*option.VLESSOutboundOptions, error) {
	var settings struct {
		VNext []struct {
			Address string            `json:"address"`
			Port    subscription.Port `json:"port"`
			Users   []struct {
				ID         string `json:"id"`
				Flow       string `json:"flow"`
				Encryption string `json:"encryption"`
			} `json:"users"`
		} `json:"vnext"`
	}
	if err := json.Unmarshal(source.Settings, &settings); err != nil {
		return nil, E.Cause(err, "invalid VLESS settings")
	}
	if len(settings.VNext) != 1 || len(settings.VNext[0].Users) != 1 {
		return nil, E.New("VLESS requires exactly one server and one user")
	}
	server, user := settings.VNext[0], settings.VNext[0].Users[0]
	if server.Address == "" || server.Port == 0 || user.ID == "" {
		return nil, E.New("invalid VLESS server")
	}
	flow, err := subscription.VLESSFlow(user.Flow)
	if err != nil {
		return nil, err
	}
	transport, err := parseTransport(source.StreamSettings)
	if err != nil {
		return nil, err
	}
	tls, err := parseTLS(source.StreamSettings)
	if err != nil {
		return nil, err
	}
	encryption := subscription.VLESSEncryption(user.Encryption)
	if err = subscription.CheckVLESSVision(flow, encryption, tls, transport); err != nil {
		return nil, err
	}
	return &option.VLESSOutboundOptions{
		ServerOptions:               option.ServerOptions{Server: server.Address, ServerPort: uint16(server.Port)},
		UUID:                        user.ID,
		Flow:                        flow,
		Encryption:                  encryption,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tls},
		Transport:                   transport,
	}, nil
}

func parseVMess(source sourceOutbound) (*option.VMessOutboundOptions, error) {
	var settings struct {
		VNext []struct {
			Address string            `json:"address"`
			Port    subscription.Port `json:"port"`
			Users   []struct {
				ID       string           `json:"id"`
				Security string           `json:"security"`
				AlterID  subscription.Int `json:"alterId"`
			} `json:"users"`
		} `json:"vnext"`
	}
	if err := json.Unmarshal(source.Settings, &settings); err != nil {
		return nil, E.Cause(err, "invalid VMess settings")
	}
	if len(settings.VNext) != 1 || len(settings.VNext[0].Users) != 1 {
		return nil, E.New("VMess requires exactly one server and one user")
	}
	server, user := settings.VNext[0], settings.VNext[0].Users[0]
	if server.Address == "" || server.Port == 0 || user.ID == "" {
		return nil, E.New("invalid VMess server")
	}
	transport, err := parseTransport(source.StreamSettings)
	if err != nil {
		return nil, err
	}
	security := user.Security
	if security == "" {
		security = "auto"
	}
	alterID, err := user.AlterID.Value("VMess alter ID")
	if err != nil {
		return nil, err
	}
	if alterID < 0 {
		return nil, E.New("VMess alter ID is out of range")
	}
	tls, err := parseTLS(source.StreamSettings)
	if err != nil {
		return nil, err
	}
	return &option.VMessOutboundOptions{
		ServerOptions:               option.ServerOptions{Server: server.Address, ServerPort: uint16(server.Port)},
		UUID:                        user.ID,
		Security:                    security,
		AlterId:                     alterID,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tls},
		Transport:                   transport,
	}, nil
}

func parseSOCKS(source sourceOutbound) (*option.SOCKSOutboundOptions, error) {
	if err := checkPlainTransport(source.StreamSettings, false); err != nil {
		return nil, err
	}
	var settings struct {
		Servers []struct {
			Address string            `json:"address"`
			Port    subscription.Port `json:"port"`
			Users   []struct {
				User string `json:"user"`
				Pass string `json:"pass"`
			} `json:"users"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(source.Settings, &settings); err != nil {
		return nil, E.Cause(err, "invalid SOCKS settings")
	}
	if len(settings.Servers) != 1 || len(settings.Servers[0].Users) > 1 {
		return nil, E.New("SOCKS requires exactly one server and at most one user")
	}
	server := settings.Servers[0]
	if server.Address == "" || server.Port == 0 {
		return nil, E.New("invalid SOCKS server")
	}
	options := &option.SOCKSOutboundOptions{
		ServerOptions: option.ServerOptions{Server: server.Address, ServerPort: uint16(server.Port)},
		Version:       "5",
	}
	if len(server.Users) > 0 {
		options.Username = server.Users[0].User
		options.Password = server.Users[0].Pass
	}
	return options, nil
}

func parseShadowsocks(source sourceOutbound) (*option.ShadowsocksOutboundOptions, error) {
	if err := checkPlainTransport(source.StreamSettings, false); err != nil {
		return nil, err
	}
	var settings struct {
		Servers []struct {
			Address  string            `json:"address"`
			Port     subscription.Port `json:"port"`
			Method   string            `json:"method"`
			Password string            `json:"password"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(source.Settings, &settings); err != nil {
		return nil, E.Cause(err, "invalid Shadowsocks settings")
	}
	if len(settings.Servers) != 1 {
		return nil, E.New("Shadowsocks requires exactly one server")
	}
	server := settings.Servers[0]
	if server.Address == "" || server.Port == 0 || server.Method == "" || server.Password == "" {
		return nil, E.New("invalid Shadowsocks server")
	}
	return &option.ShadowsocksOutboundOptions{
		ServerOptions: option.ServerOptions{Server: server.Address, ServerPort: uint16(server.Port)},
		Method:        server.Method,
		Password:      server.Password,
	}, nil
}

func parseTrojan(source sourceOutbound) (*option.TrojanOutboundOptions, error) {
	var settings struct {
		Servers []struct {
			Address  string            `json:"address"`
			Port     subscription.Port `json:"port"`
			Password string            `json:"password"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(source.Settings, &settings); err != nil {
		return nil, E.Cause(err, "invalid Trojan settings")
	}
	if len(settings.Servers) != 1 {
		return nil, E.New("Trojan requires exactly one server")
	}
	server := settings.Servers[0]
	if server.Address == "" || server.Port == 0 || server.Password == "" {
		return nil, E.New("invalid Trojan server")
	}
	transport, err := parseTransport(source.StreamSettings)
	if err != nil {
		return nil, err
	}
	tls, err := parseTLS(source.StreamSettings)
	if err != nil {
		return nil, err
	}
	if tls == nil {
		tls = &option.OutboundTLSOptions{Enabled: true, ServerName: server.Address}
	}
	return &option.TrojanOutboundOptions{
		ServerOptions:               option.ServerOptions{Server: server.Address, ServerPort: uint16(server.Port)},
		Password:                    server.Password,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tls},
		Transport:                   transport,
	}, nil
}

func parseHTTP(source sourceOutbound) (*option.HTTPOutboundOptions, error) {
	if err := checkPlainTransport(source.StreamSettings, true); err != nil {
		return nil, err
	}
	var settings struct {
		Servers []struct {
			Address string            `json:"address"`
			Port    subscription.Port `json:"port"`
			Users   []struct {
				User     string `json:"user"`
				Pass     string `json:"pass"`
				Password string `json:"password"`
			} `json:"users"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(source.Settings, &settings); err != nil {
		return nil, E.Cause(err, "invalid HTTP settings")
	}
	if len(settings.Servers) != 1 || len(settings.Servers[0].Users) > 1 {
		return nil, E.New("HTTP requires exactly one server and at most one user")
	}
	server := settings.Servers[0]
	if server.Address == "" || server.Port == 0 {
		return nil, E.New("invalid HTTP server")
	}
	tls, err := parseTLS(source.StreamSettings)
	if err != nil {
		return nil, err
	}
	options := &option.HTTPOutboundOptions{
		ServerOptions:               option.ServerOptions{Server: server.Address, ServerPort: uint16(server.Port)},
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tls},
	}
	if len(server.Users) > 0 {
		options.Username = server.Users[0].User
		options.Password = server.Users[0].Pass
	}
	return options, nil
}

// checkPlainTransport guards the protocols that carry no transport of their own.
// Xray refuses to give them one too, so a document that asks for it describes
// something neither client can dial.
func checkPlainTransport(stream streamSettings, allowTLS bool) error {
	if transport := stream.transport(); transport != "tcp" {
		return E.New("unsupported Xray transport: ", stream.Network)
	}
	if header := headerType(stream.tcp()); header != "" {
		return E.New("unsupported Xray TCP header: ", header)
	}
	if !allowTLS && securityName(stream) != "" {
		return E.New("unsupported Xray security: ", stream.Security)
	}
	return nil
}

func parseHysteria2(source sourceOutbound) (*option.Hysteria2OutboundOptions, error) {
	var settings struct {
		Version subscription.Int  `json:"version"`
		Address string            `json:"address"`
		Port    subscription.Port `json:"port"`
	}
	if err := json.Unmarshal(source.Settings, &settings); err != nil {
		return nil, E.Cause(err, "invalid Hysteria2 settings")
	}
	version := settings.Version
	if version != 0 && source.StreamSettings.HysteriaSettings.Version != 0 && version != source.StreamSettings.HysteriaSettings.Version {
		return nil, E.New("conflicting Xray Hysteria version aliases")
	}
	if version == 0 {
		version = source.StreamSettings.HysteriaSettings.Version
	}
	if version != 2 {
		return nil, E.New("not a Hysteria2 outbound")
	}
	server := settings.Address
	password := source.StreamSettings.HysteriaSettings.Auth
	if server == "" || settings.Port == 0 || password == "" {
		return nil, E.New("invalid Hysteria2 server")
	}
	tls, err := parseTLS(source.StreamSettings)
	if err != nil {
		return nil, err
	}
	if tls == nil {
		tls = &option.OutboundTLSOptions{Enabled: true, ServerName: server}
	}
	return &option.Hysteria2OutboundOptions{
		ServerOptions:               option.ServerOptions{Server: server, ServerPort: uint16(settings.Port)},
		Password:                    password,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: subscription.QUICSecurity(tls)},
	}, nil
}

func sourceDetour(source sourceOutbound) (string, error) {
	proxyTag := ""
	if source.ProxySettings != nil {
		proxyTag = source.ProxySettings.Tag
	}
	return uniqueString("detour aliases", source.StreamSettings.Sockopt.DialerProxy, proxyTag)
}

// securityName reports the transport security Xray would apply, which is
// decided by the security field alone. Settings written beside a security of
// none are ignored by Xray.
func securityName(stream streamSettings) string {
	switch strings.ToLower(stream.Security) {
	case "", "none":
		return ""
	case "tls", "xtls":
		// Xray removed the legacy XTLS handshake; what is left under that name
		// is ordinary TLS with the flow doing the work.
		return "tls"
	case "reality":
		return "reality"
	}
	return stream.Security
}

func parseTLS(stream streamSettings) (*option.OutboundTLSOptions, error) {
	security := securityName(stream)
	settings := stream.TLSSettings
	switch security {
	case "":
		return nil, nil
	case "tls":
	case "reality":
		if stream.RealitySettings == nil {
			return nil, E.New("Xray Reality security without Reality settings")
		}
		settings = stream.RealitySettings
	default:
		return nil, E.New("unsupported Xray security: ", stream.Security)
	}
	if settings == nil {
		settings = &tlsSettings{}
	}
	tls := &option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: settings.ServerName,
		Insecure:   settings.AllowInsecure.Value(),
		ALPN:       badoption.Listable[string](settings.ALPN),
		ECH:        subscription.ECH(settings.ECHConfigList),
	}
	// Xray-core imitates Chrome when a document names no fingerprint.
	utls, err := subscription.UTLSFingerprint(settings.Fingerprint, "chrome", security == "reality")
	if err != nil {
		return nil, err
	}
	tls.UTLS = utls
	if security == "reality" {
		publicKey, err := uniqueString("Reality public key aliases", settings.PublicKey, settings.Password)
		if err != nil {
			return nil, err
		}
		tls.Reality = &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: publicKey,
			ShortID:   settings.ShortID,
		}
	}
	return tls, nil
}

// parseTransport reads the settings of the transport the stream selects. The
// blocks belonging to the other transports are ignored, exactly as Xray ignores
// them: a document that writes out every transport it knows still describes one
// way of connecting.
func parseTransport(stream streamSettings) (*option.V2RayTransportOptions, error) {
	switch stream.transport() {
	case "tcp":
		if header := headerType(stream.tcp()); header != "" {
			// The HTTP header masking Xray puts in front of a raw connection is
			// not an HTTP transport, and sing-box does not speak it.
			return nil, E.New("unsupported Xray TCP header: ", header)
		}
		return nil, nil
	case "ws":
		settings := stream.WSSettings
		if settings == nil {
			settings = &websocketSettings{}
		}
		header := websocketHeaders(settings)
		path, earlyData := subscription.SplitWebsocketEarlyData(settings.Path)
		maxEarlyData := uint32(settings.MaxEarlyData)
		earlyDataHeaderName := settings.EarlyDataHeaderName
		if earlyData > 0 {
			maxEarlyData = earlyData
			earlyDataHeaderName = "Sec-WebSocket-Protocol"
		}
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeWebsocket,
			WebsocketOptions: option.V2RayWebsocketOptions{
				Path:                path,
				Headers:             header,
				MaxEarlyData:        maxEarlyData,
				EarlyDataHeaderName: earlyDataHeaderName,
			},
		}, nil
	case "grpc":
		settings := stream.GRPCSettings
		if settings == nil {
			settings = &grpcSettings{}
		}
		return &option.V2RayTransportOptions{
			Type:        C.V2RayTransportTypeGRPC,
			GRPCOptions: option.V2RayGRPCOptions{ServiceName: settings.ServiceName},
		}, nil
	case "http":
		settings := stream.HTTPSettings
		if settings == nil {
			settings = &httpSettings{}
		}
		if len(settings.Path) > 1 {
			return nil, E.New("multiple Xray HTTP paths cannot be represented")
		}
		path := ""
		if len(settings.Path) > 0 {
			path = settings.Path[0]
		}
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeHTTP,
			HTTPOptions: option.V2RayHTTPOptions{
				Host: badoption.Listable[string](settings.Host),
				Path: path,
			},
		}, nil
	case "httpupgrade":
		settings := stream.HTTPUpgradeSettings
		if settings == nil {
			settings = &httpUpgradeSettings{}
		}
		path, _ := subscription.SplitWebsocketEarlyData(settings.Path)
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeHTTPUpgrade,
			HTTPUpgradeOptions: option.V2RayHTTPUpgradeOptions{
				Host:    settings.Host,
				Path:    path,
				Headers: subscription.Headers(settings.Headers),
			},
		}, nil
	case "xhttp":
		settings := stream.xhttp()
		if settings == nil {
			settings = &xhttp.Settings{}
		}
		return settings.Build(XHTTPDownload)
	}
	return nil, E.New("unsupported Xray transport: ", stream.Network)
}

// XHTTPDownload reads the downloadSettings of an XHTTP transport, in a document or the extra of
// a share link: stream settings of their own and the address and the port the leg dials, as
// Xray-core takes them, nothing inherited from the upload.
func XHTTPDownload(content json.RawMessage) (*option.V2RayXHTTPDownloadOptions, error) {
	var leg struct {
		Address string            `json:"address"`
		Port    subscription.Port `json:"port"`
		streamSettings
	}
	if err := json.Unmarshal(content, &leg); err != nil {
		return nil, err
	}
	if leg.Address == "" || leg.Port == 0 {
		return nil, E.New("missing address or port")
	}
	if leg.Network != "" && leg.transport() != "xhttp" {
		return nil, E.New("unsupported transport: ", leg.Network)
	}
	if leg.Sockopt.DialerProxy != "" {
		return nil, E.New("unsupported dialer proxy: ", leg.Sockopt.DialerProxy)
	}
	tls, err := parseTLS(leg.streamSettings)
	if err != nil {
		return nil, err
	}
	settings := leg.xhttp()
	if settings == nil {
		settings = &xhttp.Settings{}
	}
	base, err := settings.Base()
	if err != nil {
		return nil, err
	}
	return &option.V2RayXHTTPDownloadOptions{
		V2RayXHTTPBaseOptions:       base,
		ServerOptions:               option.ServerOptions{Server: leg.Address, ServerPort: uint16(leg.Port)},
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tls},
	}, nil
}

func headerType(settings *tcpSettings) string {
	if settings == nil {
		return ""
	}
	if header := strings.ToLower(settings.Header.Type); header != "" && header != "none" {
		return settings.Header.Type
	}
	return ""
}

// websocketHeaders folds the deprecated Host header into the independent host
// field the way Xray does, so a document written either way sends the same
// request.
func websocketHeaders(settings *websocketSettings) badoption.HTTPHeader {
	header := badoption.HTTPHeader{}
	host := settings.Host
	for key, value := range settings.Headers {
		if strings.EqualFold(key, "Host") {
			if host == "" {
				host = value
			}
			continue
		}
		header[key] = []string{value}
	}
	if host != "" {
		header["Host"] = []string{host}
	}
	if len(header) == 0 {
		return nil
	}
	return header
}
