//go:build with_quic

package xhttp

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func TestPooledHTTP3ConnectionIsInternal(t *testing.T) {
	require.Equal(t, []bool{false}, dialMarks(t, "h3"))
}

func TestMultiplexOverHTTP3(t *testing.T) {
	require.True(t, multiplexReported(t, option.V2RayXHTTPOptions{}, "h3"))
}

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

// QUIC carries no uTLS fingerprint: a leg over HTTP/3 with one is refused when the node is built, as
// sing-box refuses uTLS for its other QUIC protocols, instead of failing every connection.
func TestHTTP3RefusesUTLS(t *testing.T) {
	tlsOptions := option.OutboundTLSOptions{
		Enabled: true, ServerName: "h3.example", ALPN: []string{"h3"},
		UTLS: &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
	}
	tlsConfig, err := tls.NewClient(context.Background(), log.StdLogger(), "h3.example", tlsOptions)
	require.NoError(t, err)
	_, err = NewClient(context.Background(), N.SystemDialer, M.ParseSocksaddr("127.0.0.1:443"), option.V2RayXHTTPOptions{}, tlsConfig)
	require.ErrorContains(t, err, "uTLS")
	download := &option.V2RayXHTTPDownloadOptions{
		ServerOptions:               option.ServerOptions{Server: "127.0.0.1", ServerPort: 443},
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &tlsOptions},
	}
	_, err = NewClient(context.Background(), N.SystemDialer, M.ParseSocksaddr("127.0.0.1:443"), option.V2RayXHTTPOptions{Download: download}, nil)
	require.ErrorContains(t, err, "uTLS")
}
