//go:build with_quic

package xhttp

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// The connections of an outbound nothing references close once no request is on them: at once, and
// after each session but a warm-up's; an open session keeps its own.
func TestIdleConnectionsCloseWhenUnreferenced(t *testing.T) {
	for _, alpn := range []string{"h2", "h3"} {
		t.Run(alpn, func(t *testing.T) {
			logger := log.NewNOPFactory().NewLogger("test")
			key, certificate, err := tls.GenerateCertificate(nil, nil, time.Now, "xhttp.example", time.Now().Add(time.Hour))
			require.NoError(t, err)
			serverTLS, err := tls.NewServer(context.Background(), logger, option.InboundTLSOptions{
				Enabled: true, ServerName: "xhttp.example", ALPN: []string{alpn},
				Certificate: strings.Split(string(certificate), "\n"), Key: strings.Split(string(key), "\n"),
			})
			require.NoError(t, err)
			server, err := NewServer(context.Background(), logger, xhttpOptions(t, `{"type":"xhttp","path":"/x"}`), serverTLS, echoHandler{})
			require.NoError(t, err)
			defer server.Close()
			var address M.Socksaddr
			if alpn == "h3" {
				packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
				require.NoError(t, err)
				go server.ServePacket(packetConn)
				address = M.SocksaddrFromNet(packetConn.LocalAddr())
			} else {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				go server.Serve(listener)
				address = M.SocksaddrFromNet(listener.Addr())
			}
			clientTLS, err := tls.NewClient(context.Background(), logger, "xhttp.example", option.OutboundTLSOptions{
				Enabled: true, ServerName: "xhttp.example", Insecure: true, ALPN: []string{alpn},
			})
			require.NoError(t, err)
			dialer := &closeWatchingDialer{}
			// one connection: the default spreads sessions over three
			transport, err := NewClient(context.Background(), dialer, address,
				xhttpOptions(t, `{"type":"xhttp","path":"/x","mode":"stream-one","xmux":{"max_connections":1}}`), clientTLS)
			require.NoError(t, err)
			defer transport.Close()
			echo := func(conn net.Conn) {
				_, err := conn.Write([]byte("hi"))
				require.NoError(t, err)
				_, err = io.ReadFull(conn, make([]byte, 2))
				require.NoError(t, err)
			}
			session := func(ctx context.Context) net.Conn {
				conn, err := transport.DialContext(ctx)
				require.NoError(t, err)
				echo(conn)
				return conn
			}
			open := func() (count int) {
				dialer.access.Lock()
				defer dialer.access.Unlock()
				for _, conn := range dialer.conns {
					select {
					case <-conn.closed:
					default:
						count++
					}
				}
				return
			}
			allClosed := func() bool { return open() == 0 }

			session(context.Background()).Close()
			require.Equal(t, 1, open(), "the pool of a referenced outbound keeps its connection")

			busy := session(context.Background())
			transport.(adapter.IdleConnectionKeeper).SetKeepIdleConnections(false)
			require.Equal(t, 1, open(), "the connection of an open session closed")
			echo(busy)
			busy.Close()
			require.Eventually(t, allClosed, 5*time.Second, 10*time.Millisecond, "the connection a session left stays")

			session(adapter.ContextWithKeepSession(context.Background())).Close()
			require.Equal(t, 1, open(), "the connection of a warm-up closed before the test it is for")
			session(context.Background()).Close()
			require.Eventually(t, allClosed, 5*time.Second, 10*time.Millisecond, "the connection a test left stays")
			dialer.access.Lock()
			defer dialer.access.Unlock()
			require.Len(t, dialer.conns, 2, "the test after its warm-up dialed again")
		})
	}
}
