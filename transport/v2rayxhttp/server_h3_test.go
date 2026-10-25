//go:build with_quic

package xhttp

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// A server listens where a client of the same TLS dials, Xray's rule: on QUIC for h3 alone, never for
// REALITY, which has no QUIC form.
func TestServerListensWhereClientsDial(t *testing.T) {
	key, certificate, err := tls.GenerateCertificate(nil, nil, time.Now, "xhttp.example", time.Now().Add(time.Hour))
	require.NoError(t, err)
	privateKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for _, test := range []struct {
		alpn    []string
		reality bool
		network string
	}{
		{alpn: []string{"h3"}, network: N.NetworkUDP},
		{alpn: []string{"h3", "h2"}, network: N.NetworkTCP},
		{alpn: []string{"h2"}, network: N.NetworkTCP},
		{alpn: []string{"h3"}, reality: true, network: N.NetworkTCP},
	} {
		options := option.InboundTLSOptions{Enabled: true, ServerName: "xhttp.example", ALPN: test.alpn}
		if test.reality {
			options.Reality = &option.InboundRealityOptions{
				Enabled:    true,
				PrivateKey: privateKey,
				ShortID:    []string{"01"},
				Handshake:  option.InboundRealityHandshakeOptions{ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 443}},
			}
		} else {
			options.Certificate = strings.Split(string(certificate), "\n")
			options.Key = strings.Split(string(key), "\n")
		}
		tlsConfig, err := tls.NewServer(context.Background(), log.StdLogger(), options)
		require.NoError(t, err)
		server, err := NewServer(context.Background(), log.StdLogger(), option.V2RayXHTTPOptions{}, tlsConfig, nil)
		require.NoError(t, err)
		require.Equal(t, test.network, server.network(), "alpn %q, reality %v", test.alpn, test.reality)
	}
}
