package xhttp

import (
	"context"
	"net"
	"os"
	"sync"
	"testing"

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
