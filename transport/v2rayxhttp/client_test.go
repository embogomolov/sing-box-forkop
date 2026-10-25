package xhttp

import (
	"context"
	"net"
	"net/http"
	"os"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// markDialer refuses every dial and notes whether it was asked for an external connection.
type markDialer struct {
	access   sync.Mutex
	external []bool
}

func (d *markDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.access.Lock()
	d.external = append(d.external, interrupt.IsExternalConnectionFromContext(ctx))
	d.access.Unlock()
	return nil, E.New("refused")
}

func (d *markDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

// testTLSConfig is the TLS of a node offering alpn, none without it.
func testTLSConfig(t *testing.T, alpn ...string) tls.Config {
	if len(alpn) == 0 {
		return nil
	}
	tlsConfig, err := tls.NewClient(context.Background(), log.StdLogger(), "xhttp.example", option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: "xhttp.example",
		ALPN:       alpn,
	})
	require.NoError(t, err)
	return tlsConfig
}

// dialMarks opens a stream as an external connection would and returns the marks of the dials it made.
func dialMarks(t *testing.T, alpn ...string) []bool {
	dialer := &markDialer{}
	client, err := NewClient(context.Background(), dialer, M.ParseSocksaddr("127.0.0.1:443"), option.V2RayXHTTPOptions{Mode: "stream-one"}, testTLSConfig(t, alpn...))
	require.NoError(t, err)
	defer client.Close()
	_, err = client.DialContext(interrupt.ContextWithIsExternalConnection(context.Background(), true))
	require.Error(t, err)
	dialer.access.Lock()
	defer dialer.access.Unlock()
	return dialer.external
}

// A group switching members without interrupt_exist_connections closes only internal connections, and a
// pooled connection carries every later stream; an HTTP/1.1 connection carries one and keeps its mark.
func TestPooledConnectionIsInternal(t *testing.T) {
	require.Equal(t, []bool{true}, dialMarks(t))
	require.Equal(t, []bool{false}, dialMarks(t, "h2"))
}

// An IPv6 literal goes into the Host header in brackets: bare it is no valid host, and one whose last
// group has a letter does not even parse as a URL, so no stream opens.
func TestRequestHostBracketsIPv6(t *testing.T) {
	for _, test := range []struct {
		server     string
		tls        bool
		serverName string
		host       string
		expected   string
	}{
		{server: "[2001:db8::abcd]:8080", expected: "[2001:db8::abcd]"},
		{server: "[2001:db8::abcd]:443", tls: true, expected: "[2001:db8::abcd]"},
		{server: "192.0.2.1:80", expected: "192.0.2.1"},
		{server: "[2001:db8::1]:443", tls: true, serverName: "xhttp.example", expected: "xhttp.example"},
		{server: "[2001:db8::1]:443", tls: true, host: "cdn.example", expected: "cdn.example"},
	} {
		dest := M.ParseSocksaddr(test.server)
		var tlsConfig tls.Config
		if test.tls {
			var err error
			tlsConfig, err = tls.NewClient(context.Background(), log.StdLogger(), dest.AddrString(), option.OutboundTLSOptions{
				Enabled:    true,
				ServerName: test.serverName,
			})
			require.NoError(t, err)
		}
		requestURL, err := getBaseRequestURL(&option.V2RayXHTTPBaseOptions{Host: test.host}, dest, tlsConfig)
		require.NoError(t, err)
		require.Equal(t, test.expected, requestURL.Host, test.server)
		_, err = http.NewRequest(http.MethodGet, requestURL.String(), nil)
		require.NoError(t, err, test.server)
	}
}

func multiplexReported(t *testing.T, options option.V2RayXHTTPOptions, alpn ...string) bool {
	client, err := NewClient(context.Background(), &markDialer{}, M.ParseSocksaddr("127.0.0.1:443"), options, testTLSConfig(t, alpn...))
	require.NoError(t, err)
	defer client.Close()
	multiplexClient, isMultiplex := client.(adapter.V2RayMultiplexClientTransport)
	return isMultiplex && multiplexClient.MultiplexEnabled()
}

// A URL test warms a session up only when the measured request reuses it: pooled connections on both sides.
func TestMultiplexFollowsHTTPVersion(t *testing.T) {
	require.False(t, multiplexReported(t, option.V2RayXHTTPOptions{}))
	require.True(t, multiplexReported(t, option.V2RayXHTTPOptions{}, "h2"))
	download := &option.V2RayXHTTPDownloadOptions{ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 80}}
	require.False(t, multiplexReported(t, option.V2RayXHTTPOptions{Download: download}, "h2"))
}
