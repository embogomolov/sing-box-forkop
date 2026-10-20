package sip008

import (
	"context"
	"encoding/json"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/parser/subscription"
	E "github.com/sagernet/sing/common/exceptions"
)

type document struct {
	Servers []json.RawMessage `json:"servers"`
}

type server struct {
	Remarks    string            `json:"remarks"`
	Server     string            `json:"server"`
	ServerPort subscription.Port `json:"server_port"`
	Password   string            `json:"password"`
	Method     string            `json:"method"`
	Plugin     string            `json:"plugin"`
	PluginOpts string            `json:"plugin_opts"`
}

func ParseSIP008Subscription(_ context.Context, content string) (subscription.Result, error) {
	trimmed := strings.TrimSpace(content)
	if !strings.HasPrefix(trimmed, "{") {
		return subscription.Result{}, subscription.ErrUnrecognized
	}
	var parsed document
	if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil || parsed.Servers == nil {
		return subscription.Result{}, subscription.ErrUnrecognized
	}
	collector := subscription.NewCollector("SIP008")
	for index, rawServer := range parsed.Servers {
		var identity struct {
			Remarks string `json:"remarks"`
		}
		_ = json.Unmarshal(rawServer, &identity)
		label := collector.Label(index, identity.Remarks)
		var server server
		if err := json.Unmarshal(rawServer, &server); err != nil {
			collector.Skip(identity.Remarks, label, err)
			continue
		}
		if server.Server == "" || server.ServerPort == 0 || server.Password == "" || server.Method == "" {
			collector.Skip(identity.Remarks, label, E.New("incomplete server"))
			continue
		}
		collector.Add(option.Outbound{
			Type: C.TypeShadowsocks,
			Tag:  server.Remarks,
			Options: &option.ShadowsocksOutboundOptions{
				ServerOptions: option.ServerOptions{
					Server:     server.Server,
					ServerPort: uint16(server.ServerPort),
				},
				Password:      server.Password,
				Method:        server.Method,
				Plugin:        server.Plugin,
				PluginOptions: server.PluginOpts,
			},
		})
	}
	return collector.Result(), nil
}
