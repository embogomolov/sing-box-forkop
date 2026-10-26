package xhttp

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	gotls "crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// helloRecorder takes TLS connections and reports the ALPN list of each Client Hello, then fails the
// handshake.
func helloRecorder(t *testing.T) (M.Socksaddr, <-chan []string) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	offered := make(chan []string, 16)
	config := &gotls.Config{GetConfigForClient: func(hello *gotls.ClientHelloInfo) (*gotls.Config, error) {
		offered <- append([]string{}, hello.SupportedProtos...)
		return nil, errors.New("recorded")
	}}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = gotls.Server(conn, config).Handshake()
			}()
		}
	}()
	return M.SocksaddrFromNet(listener.Addr()), offered
}

// A server that lists h3 before h2 picks it over TCP and then cannot serve the connection: over TCP the
// Client Hello offers what the node sets less h3, as Xray's client never offers it there, and with nothing
// left a fingerprint's own list.
func TestClientHelloOverTCPOffersNoH3(t *testing.T) {
	server, offered := helloRecorder(t)
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	publicKey := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	chrome := &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"}
	for _, test := range []struct {
		alpn    []string
		utls    bool
		reality bool
		offered []string
	}{
		{alpn: []string{"h3", "h2"}, offered: []string{"h2"}},
		{alpn: []string{"h3", "h2"}, utls: true, offered: []string{"h2", "http/1.1"}},
		{alpn: []string{"h2", "http/1.1"}, utls: true, offered: []string{"h2", "http/1.1"}},
		{alpn: []string{"http/1.1"}, utls: true, offered: []string{"http/1.1"}},
		{offered: []string{"h2"}},
		{utls: true, offered: []string{"h2", "http/1.1"}},
		{alpn: []string{"h3"}, reality: true, offered: []string{"h2", "http/1.1"}},
	} {
		options := option.OutboundTLSOptions{Enabled: true, ServerName: "xhttp.example", Insecure: !test.reality, ALPN: test.alpn}
		if test.utls || test.reality {
			options.UTLS = chrome
		}
		if test.reality {
			options.Reality = &option.OutboundRealityOptions{Enabled: true, PublicKey: publicKey}
		}
		tlsConfig, err := tls.NewClient(context.Background(), log.StdLogger(), "xhttp.example", options)
		require.NoError(t, err)
		transport, err := NewClient(context.Background(), N.SystemDialer, server, option.V2RayXHTTPOptions{Mode: "stream-one"}, tlsConfig)
		require.NoError(t, err)
		transport.DialContext(context.Background())
		select {
		case protocols := <-offered:
			require.Equal(t, test.offered, protocols, "alpn %q, uTLS %v, REALITY %v", test.alpn, test.utls, test.reality)
		case <-time.After(5 * time.Second):
			t.Fatalf("alpn %q: no Client Hello", test.alpn)
		}
		transport.Close()
	}
}
