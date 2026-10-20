package clash

import (
	"strings"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/parser/subscription"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
)

type shadowsocksOptions struct {
	dialerOptions
	serverOptions
	Password          subscription.String `json:"password"`
	Cipher            subscription.String `json:"cipher"`
	UDP               subscription.Bool   `json:"udp"`
	Plugin            subscription.String `json:"plugin"`
	PluginOpts        map[string]any      `json:"plugin-opts"`
	UDPOverTCP        subscription.Bool   `json:"udp-over-tcp"`
	UDPOverTCPVersion subscription.Int    `json:"udp-over-tcp-version"`
	MuxOpts           *muxOptions         `json:"smux"`
}

func (s *shadowsocksOptions) Build() (any, error) {
	if err := s.serverOptions.check(); err != nil {
		return nil, err
	}
	if s.Cipher == "" {
		return nil, E.New("missing cipher")
	}
	plugin, pluginOptions, err := shadowsocksPlugin(string(s.Plugin), s.PluginOpts)
	if err != nil {
		return nil, err
	}
	options := &option.ShadowsocksOutboundOptions{
		DialerOptions: s.dialerOptions.build(),
		ServerOptions: s.serverOptions.build(),
		Password:      string(s.Password),
		Method:        shadowsocksMethod(string(s.Cipher)),
		Plugin:        plugin,
		PluginOptions: pluginOptions,
		Network:       networks(s.UDP),
		Multiplex:     s.MuxOpts.build(),
	}
	if s.UDPOverTCP.Value() {
		version := uint8(2)
		if s.UDPOverTCPVersion != 0 {
			version = uint8(s.UDPOverTCPVersion)
		}
		options.UDPOverTCP = &option.UDPOverTCPOptions{Enabled: true, Version: version}
	}
	return options, nil
}

func shadowsocksMethod(cipher string) string {
	if cipher == "dummy" {
		return "none"
	}
	return cipher
}

// shadowsocksPlugin renders the plugin arguments in the form sing-box's plugin
// takes. A plugin sing-box does not carry is refused: it wraps the stream, so a
// client that leaves it out sends the server something it cannot read.
func shadowsocksPlugin(plugin string, opts map[string]any) (string, string, error) {
	switch plugin {
	case "":
		return "", "", nil
	case "obfs", "obfs-local", "simple-obfs":
		var arguments []string
		if mode := pluginString(opts, "mode"); mode != "" {
			arguments = append(arguments, "obfs="+mode)
		}
		if host := pluginString(opts, "host"); host != "" {
			arguments = append(arguments, "obfs-host="+host)
		}
		return "obfs-local", strings.Join(arguments, ";"), nil
	case "v2ray-plugin":
		var arguments []string
		if mode := pluginString(opts, "mode"); mode != "" {
			arguments = append(arguments, "mode="+mode)
		}
		if host := pluginString(opts, "host"); host != "" {
			arguments = append(arguments, "host="+host)
		}
		if path := pluginString(opts, "path"); path != "" {
			arguments = append(arguments, "path="+path)
		}
		// The plugin reads tls as a flag: writing it out as tls=false would
		// still turn TLS on, so an unset or false value writes nothing.
		if pluginBool(opts, "tls") {
			arguments = append(arguments, "tls")
		}
		if pluginBool(opts, "mux") {
			arguments = append(arguments, "mux=1")
		} else {
			arguments = append(arguments, "mux=0")
		}
		return "v2ray-plugin", strings.Join(arguments, ";"), nil
	}
	return "", "", E.New("unsupported Shadowsocks plugin: ", plugin)
}

func pluginString(opts map[string]any, key string) string {
	value, exists := opts[key]
	if !exists || value == nil {
		return ""
	}
	return F.ToString(value)
}

func pluginBool(opts map[string]any, key string) bool {
	value, exists := opts[key]
	if !exists || value == nil {
		return false
	}
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		return typed == "true" || typed == "1"
	case float64:
		return typed != 0
	}
	return false
}
