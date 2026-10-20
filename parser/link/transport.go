package link

import (
	"strconv"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/parser/subscription"
	"github.com/sagernet/sing-box/parser/xhttp"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
)

// linkTransport reads the transport a share link describes. The link format is
// Xray's, so the parameter names and their meanings are Xray's too.
func linkTransport(q query) (*option.V2RayTransportOptions, error) {
	switch q.get("type", "net") {
	case "", "tcp", "raw", "none":
		if header := q.get("headerType"); header != "" && header != "none" {
			// The HTTP request Xray writes in front of a raw connection is a
			// masking layer, not an HTTP transport, and sing-box has none.
			return nil, E.New("unsupported TCP header: ", header)
		}
		return nil, nil
	case "ws", "websocket":
		path, earlyData := subscription.SplitWebsocketEarlyData(q.get("path"))
		options := option.V2RayWebsocketOptions{Path: path}
		if host := q.get("host"); host != "" {
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
		return &option.V2RayTransportOptions{
			Type:             C.V2RayTransportTypeWebsocket,
			WebsocketOptions: options,
		}, nil
	case "httpupgrade":
		path, _ := subscription.SplitWebsocketEarlyData(q.get("path"))
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeHTTPUpgrade,
			HTTPUpgradeOptions: option.V2RayHTTPUpgradeOptions{
				Host: q.get("host"),
				Path: path,
			},
		}, nil
	case "http", "h2", "h3":
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeHTTP,
			HTTPOptions: option.V2RayHTTPOptions{
				Host: badoption.Listable[string](q.list("host")),
				Path: q.get("path"),
			},
		}, nil
	case "grpc", "gun":
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
