//go:build with_quic

package xhttp

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

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

// echoHandler sends each session back what it gets.
type echoHandler struct{}

func (echoHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		io.Copy(conn, conn)
		conn.Close()
	}()
}

// A server allows a QUIC connection so many open streams, 100 by quic-go's default that Xray's server keeps,
// and quic-go's client waits for a free one where HTTP/2's opens another connection: the sessions past the
// limit got no stream until others ended. More sessions than that each get through.
func TestHTTP3SessionsPastTheStreamLimit(t *testing.T) {
	logger := log.NewNOPFactory().NewLogger("test")
	key, certificate, err := tls.GenerateCertificate(nil, nil, time.Now, "xhttp.example", time.Now().Add(time.Hour))
	require.NoError(t, err)
	serverTLS, err := tls.NewServer(context.Background(), logger, option.InboundTLSOptions{
		Enabled: true, ServerName: "xhttp.example", ALPN: []string{"h3"},
		Certificate: strings.Split(string(certificate), "\n"), Key: strings.Split(string(key), "\n"),
	})
	require.NoError(t, err)
	server, err := NewServer(context.Background(), logger, xhttpOptions(t, `{"type":"xhttp","path":"/x"}`), serverTLS, echoHandler{})
	require.NoError(t, err)
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	go server.ServePacket(packetConn)
	defer server.Close()

	clientTLS, err := tls.NewClient(context.Background(), logger, "xhttp.example", option.OutboundTLSOptions{
		Enabled: true, ServerName: "xhttp.example", Insecure: true, ALPN: []string{"h3"},
	})
	require.NoError(t, err)
	// one pooled connection, which has to carry them all
	transport, err := NewClient(context.Background(), N.SystemDialer, M.SocksaddrFromNet(packetConn.LocalAddr()),
		xhttpOptions(t, `{"type":"xhttp","path":"/x","mode":"stream-one","xmux":{"max_connections":1}}`), clientTLS)
	require.NoError(t, err)
	defer transport.Close()
	for i := range 250 {
		conn, err := transport.DialContext(context.Background())
		require.NoError(t, err)
		defer conn.Close()
		message := []byte{byte(i), byte(i >> 8)}
		reply := make([]byte, len(message))
		echoed := make(chan error, 1)
		go func() {
			_, err := conn.Write(message)
			if err == nil {
				_, err = io.ReadFull(conn, reply)
			}
			echoed <- err
		}()
		select {
		case err = <-echoed:
			require.NoError(t, err, "session %d", i)
			require.Equal(t, message, reply, "session %d", i)
		case <-time.After(5 * time.Second):
			t.Fatalf("session %d got no stream", i)
		}
	}
	lanes := transport.(*Client).xmuxManager.xmuxClients[0].XmuxConn.(*DefaultDialerClient).client.Transport.(*http3Lanes)
	lanes.access.Lock()
	opened := len(lanes.lanes)
	lanes.access.Unlock()
	require.Equal(t, 3, opened, "QUIC connections for 250 sessions, %d to one", laneRequests)
}
