//go:build with_quic

package xhttp

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

// The Chrome profile of quic-go refuses a TLS configuration that verifies the server by itself.
func TestChromeParrotLeavesWhatItRefuses(t *testing.T) {
	for _, test := range []struct {
		options option.OutboundTLSOptions
		parrot  bool
	}{
		{option.OutboundTLSOptions{Enabled: true, ServerName: "h3.example", ALPN: []string{"h3"}}, true},
		{option.OutboundTLSOptions{Enabled: true, ServerName: "h3.example", ALPN: []string{"h3"}, Insecure: true}, true},
		{option.OutboundTLSOptions{Enabled: true, ServerName: "h3.example", ALPN: []string{"h3"}, DisableSNI: true}, false},
	} {
		config, err := tls.NewClient(context.Background(), log.StdLogger(), "h3.example", test.options)
		if err != nil {
			t.Fatal(err)
		}
		if parrot := chromeParrot(config); parrot != test.parrot {
			t.Errorf("%+v: Chrome profile %v, want %v", test.options, parrot, test.parrot)
		}
	}
}
