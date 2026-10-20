package link

import (
	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/parser/subscription"
	"github.com/sagernet/sing-box/parser/xhttp"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
)

// linkTransport reads the transport a share link describes. The link format is
// Xray's, so the parameter names and their meanings are Xray's too.
func linkTransport(q query, tls *option.OutboundTLSOptions) (*option.V2RayTransportOptions, error) {
	switch q.get("type", "net") {
	case "", "tcp", "raw", "none":
		return tcpHeaderTransport(q.get("headerType"), q.list("host"), q.get("path"), tls)
	case "ws", "websocket":
		path, earlyData := subscription.SplitWebsocketEarlyData(q.get("path"))
		options := option.V2RayWebsocketOptions{Path: path}
		if host := websocketHost(q.get("host"), tls); host != "" {
			options.Headers = badoption.HTTPHeader{"Host": []string{host}}
		}
		// The length usually rides in the path, but some clients write it as a
		// parameter of its own instead.
		if value := q.get("ed"); value != "" {
			length, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return nil, E.Cause(err, "invalid early data length")
			}
			earlyData = uint32(length)
		}
		if earlyData > 0 {
			options.MaxEarlyData = earlyData
			options.EarlyDataHeaderName = "Sec-WebSocket-Protocol"
			if name := q.get("eh"); name != "" {
				options.EarlyDataHeaderName = name
			}
		}
		ownALPN(tls)
		return &option.V2RayTransportOptions{
			Type:             C.V2RayTransportTypeWebsocket,
			WebsocketOptions: options,
		}, nil
	case "httpupgrade":
		path, _ := subscription.SplitWebsocketEarlyData(q.get("path"))
		ownALPN(tls)
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeHTTPUpgrade,
			HTTPUpgradeOptions: option.V2RayHTTPUpgradeOptions{
				Host: q.get("host"),
				Path: path,
			},
		}, nil
	case "http", "h2", "h3":
		ownALPN(tls)
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeHTTP,
			HTTPOptions: option.V2RayHTTPOptions{
				Host: badoption.Listable[string](q.list("host")),
				Path: q.get("path"),
			},
		}, nil
	case "grpc", "gun":
		ownALPN(tls)
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeGRPC,
			GRPCOptions: option.V2RayGRPCOptions{
				ServiceName: q.get("serviceName", "grpc-service-name", "servicename"),
			},
		}, nil
	case "xhttp", "splithttp":
		settings, err := xhttp.LinkSettings(q.get("host"), q.get("path"), q.get("mode"), q.get("extra"))
		if err != nil {
			return nil, err
		}
		return settings.Build()
	case "quic":
		return nil, E.New("unsupported QUIC transport")
	}
	return nil, E.New("unsupported transport: ", q.get("type", "net"))
}

// The HTTP header of Xray's TCP transport is the HTTP transport of sing-box without TLS; over
// TLS that transport speaks HTTP/2.
func tcpHeaderTransport(header string, hosts []string, path string, tls *option.OutboundTLSOptions) (*option.V2RayTransportOptions, error) {
	switch header {
	case "", "none":
		return nil, nil
	case "http":
		if tls != nil {
			return nil, E.New("unsupported TCP header over TLS: http")
		}
		// Xray takes a list of paths and asks for one of them at random.
		path, _, _ = strings.Cut(path, ",")
		return &option.V2RayTransportOptions{
			Type:        C.V2RayTransportTypeHTTP,
			HTTPOptions: option.V2RayHTTPOptions{Host: badoption.Listable[string](hosts), Path: path},
		}, nil
	default:
		return nil, E.New("unsupported TCP header: ", header)
	}
}

// Without a host in the link Xray-core asks for the server name of TLS, which a CDN routes by,
// where sing-box would ask for the address of the server.
func websocketHost(host string, tls *option.OutboundTLSOptions) string {
	if host == "" && tls != nil {
		return tls.ServerName
	}
	return host
}

// Xray-core asks for the ALPN of such a transport whatever the link says, as sing-box does when
// none is set; panels write "h2,http/1.1" for every host, and HTTP/2 carries no WebSocket.
func ownALPN(tls *option.OutboundTLSOptions) {
	if tls != nil {
		tls.ALPN = nil
	}
}
