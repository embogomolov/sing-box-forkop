package clash

import (
	"encoding/json"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/parser/subscription"
	"github.com/sagernet/sing-box/parser/xhttp"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
)

// Every transport block a Clash proxy can carry; Clash reads only the one matching the network.
type transportOptions struct {
	Network   string            `json:"network"`
	HTTP2Opts *http2Options     `json:"h2-opts"`
	GrpcOpts  *grpcOptions      `json:"grpc-opts"`
	WSOpts    *websocketOptions `json:"ws-opts"`
	XHTTPOpts *json.RawMessage  `json:"xhttp-opts"`
	WSHeaders map[string]string `json:"ws-headers"`
}

type http2Options struct {
	Host subscription.StringList `json:"host"`
	Path string                  `json:"path"`
}

type grpcOptions struct {
	ServiceName string `json:"grpc-service-name"`
}

type websocketOptions struct {
	Path                string            `json:"path"`
	Headers             map[string]string `json:"headers"`
	MaxEarlyData        subscription.Int  `json:"max-early-data"`
	EarlyDataHeaderName string            `json:"early-data-header-name"`
	V2rayHTTPUpgrade    subscription.Bool `json:"v2ray-http-upgrade"`
}

func (t *transportOptions) build() (*option.V2RayTransportOptions, error) {
	switch t.Network {
	case "", "tcp", "raw":
		return nil, nil
	case "http":
		// Clash's "http" network is raw TCP behind one fake HTTP request, which sing-box does not speak.
		return nil, E.New("Clash HTTP masquerading has no sing-box equivalent")
	case "h2":
		options := http2Options{}
		if t.HTTP2Opts != nil {
			options = *t.HTTP2Opts
		}
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeHTTP,
			HTTPOptions: option.V2RayHTTPOptions{
				Host: badoption.Listable[string](options.Host),
				Path: options.Path,
			},
		}, nil
	case "grpc":
		options := grpcOptions{}
		if t.GrpcOpts != nil {
			options = *t.GrpcOpts
		}
		return &option.V2RayTransportOptions{
			Type:        C.V2RayTransportTypeGRPC,
			GRPCOptions: option.V2RayGRPCOptions{ServiceName: options.ServiceName},
		}, nil
	case "ws":
		options := websocketOptions{}
		if t.WSOpts != nil {
			options = *t.WSOpts
		}
		headerSource := options.Headers
		if len(headerSource) == 0 {
			headerSource = t.WSHeaders
		}
		header := subscription.Headers(headerSource)
		path, earlyData := subscription.SplitWebsocketEarlyData(options.Path)
		maxEarlyData := uint32(options.MaxEarlyData)
		earlyDataHeaderName := options.EarlyDataHeaderName
		if earlyData > 0 {
			maxEarlyData = earlyData
			earlyDataHeaderName = "Sec-WebSocket-Protocol"
		}
		if options.V2rayHTTPUpgrade.Value() {
			var host string
			if values := header["Host"]; len(values) > 0 {
				host = values[0]
			}
			return &option.V2RayTransportOptions{
				Type: C.V2RayTransportTypeHTTPUpgrade,
				HTTPUpgradeOptions: option.V2RayHTTPUpgradeOptions{
					Host:    host,
					Path:    path,
					Headers: header,
				},
			}, nil
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
	case "xhttp":
		settings, err := xhttpSettings(t.XHTTPOpts)
		if err != nil {
			return nil, err
		}
		return settings.Build()
	default:
		return nil, E.New("unsupported Clash transport: ", t.Network)
	}
}

// clashXHTTPKeys spells Clash's xhttp-opts the way Xray spells the same
// settings, so both are read by one implementation and a node imported from a
// Clash subscription dials exactly like the same node imported from a link.
var clashXHTTPKeys = map[string]string{
	"no-grpc-header":           "noGRPCHeader",
	"no-sse-header":            "noSSEHeader",
	"x-padding-bytes":          "xPaddingBytes",
	"x-padding-obfs-mode":      "xPaddingObfsMode",
	"x-padding-key":            "xPaddingKey",
	"x-padding-header":         "xPaddingHeader",
	"x-padding-placement":      "xPaddingPlacement",
	"x-padding-method":         "xPaddingMethod",
	"uplink-http-method":       "uplinkHTTPMethod",
	"uplink-data-placement":    "uplinkDataPlacement",
	"uplink-data-key":          "uplinkDataKey",
	"uplink-chunk-size":        "uplinkChunkSize",
	"session-placement":        "sessionIDPlacement",
	"session-key":              "sessionIDKey",
	"session-table":            "sessionIDTable",
	"session-length":           "sessionIDLength",
	"seq-placement":            "seqPlacement",
	"seq-key":                  "seqKey",
	"sc-max-each-post-bytes":   "scMaxEachPostBytes",
	"sc-min-posts-interval-ms": "scMinPostsIntervalMs",
	"sc-stream-up-server-secs": "scStreamUpServerSecs",
	"sc-max-buffered-posts":    "scMaxBufferedPosts",
	"server-max-header-bytes":  "serverMaxHeaderBytes",
	"congestion-controller":    "congestionController",
	"reuse-settings":           "xmux",
	"download-settings":        "downloadSettings",
}

var clashXmuxKeys = map[string]string{
	"max-concurrency":     "maxConcurrency",
	"max-connections":     "maxConnections",
	"c-max-reuse-times":   "cMaxReuseTimes",
	"h-max-request-times": "hMaxRequestTimes",
	"h-max-reusable-secs": "hMaxReusableSecs",
	"h-keep-alive-period": "hKeepAlivePeriod",
}

func xhttpSettings(content *json.RawMessage) (xhttp.Settings, error) {
	var settings xhttp.Settings
	if content == nil {
		return settings, nil
	}
	var options map[string]any
	if err := json.Unmarshal(*content, &options); err != nil {
		return settings, E.Cause(err, "invalid Clash xhttp-opts")
	}
	renamed := renameKeys(options, clashXHTTPKeys)
	if xmux, isObject := renamed["xmux"].(map[string]any); isObject {
		renamed["xmux"] = renameKeys(xmux, clashXmuxKeys)
	}
	encoded, err := json.Marshal(renamed)
	if err != nil {
		return settings, err
	}
	if err = json.Unmarshal(encoded, &settings); err != nil {
		return settings, E.Cause(err, "invalid Clash xhttp-opts")
	}
	return settings, nil
}

func renameKeys(source map[string]any, names map[string]string) map[string]any {
	result := make(map[string]any, len(source))
	for key, value := range source {
		if renamed, found := names[key]; found {
			key = renamed
		}
		result[key] = value
	}
	return result
}
