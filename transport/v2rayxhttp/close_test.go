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
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// countingHandler reads each session to its end and reports how much it got.
type countingHandler struct {
	received chan int64
}

func (h *countingHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		n, _ := io.Copy(io.Discard, conn)
		conn.Close()
		h.received <- n
	}()
}

func xhttpOptions(t *testing.T, content string) option.V2RayXHTTPOptions {
	var transport option.V2RayTransportOptions
	require.NoError(t, json.UnmarshalContext(context.Background(), []byte(content), &transport))
	return transport.XHTTPOptions
}

// sing-box closes a connection as soon as its source is done: what was written just before has to reach
// the server all the same, as it does from Xray's client.
func TestDataWrittenBeforeCloseArrives(t *testing.T) {
	logger := log.NewNOPFactory().NewLogger("test")
	key, certificate, err := tls.GenerateCertificate(nil, nil, time.Now, "xhttp.example", time.Now().Add(time.Hour))
	require.NoError(t, err)
	serverTLS, err := tls.NewServer(context.Background(), logger, option.InboundTLSOptions{
		Enabled: true, ServerName: "xhttp.example", ALPN: []string{"h2"},
		Certificate: strings.Split(string(certificate), "\n"), Key: strings.Split(string(key), "\n"),
	})
	require.NoError(t, err)
	handler := &countingHandler{received: make(chan int64, 1)}
	server, err := NewServer(context.Background(), logger, xhttpOptions(t, `{"type":"xhttp","path":"/x"}`), serverTLS, handler)
	require.NoError(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go server.Serve(listener)
	defer server.Close()

	clientTLS, err := tls.NewClient(context.Background(), logger, "xhttp.example", option.OutboundTLSOptions{
		Enabled: true, ServerName: "xhttp.example", Insecure: true, ALPN: []string{"h2"},
	})
	require.NoError(t, err)
	for _, mode := range []string{"stream-one", "stream-up", "packet-up"} {
		transport, err := NewClient(context.Background(), N.SystemDialer, M.SocksaddrFromNet(listener.Addr()),
			xhttpOptions(t, `{"type":"xhttp","path":"/x","mode":"`+mode+`"}`), clientTLS)
		require.NoError(t, err)
		for round := 0; round < 5; round++ {
			conn, err := transport.DialContext(context.Background())
			require.NoError(t, err)
			_, err = conn.Write(make([]byte, 100_000))
			require.NoError(t, err)
			require.NoError(t, conn.Close())
			select {
			case received := <-handler.received:
				require.EqualValues(t, 100_000, received, "%s, round %d", mode, round)
			case <-time.After(10 * time.Second):
				t.Fatalf("%s, round %d: the server never saw the end of the session", mode, round)
			}
		}
		transport.Close()
	}
}

// unopenedStream holds a stream request as a server that has not let it through yet: its body is never
// read and nothing answers it.
type unopenedStream struct {
	requestRecorder
	closed chan struct{}
}

func (s *unopenedStream) OpenStream(ctx context.Context, url string, sessionId string, body io.Reader, uploadOnly bool) (io.ReadCloser, net.Addr, net.Addr, error) {
	reader, _ := io.Pipe()
	return &closeSignal{PipeReader: reader, closed: s.closed}, nil, nil, nil
}

type closeSignal struct {
	*io.PipeReader
	closed chan struct{}
}

func (c *closeSignal) Close() error {
	close(c.closed)
	return c.PipeReader.Close()
}

// A session closed before anything was written to it has nothing to send: it goes at once, also while its
// stream has not opened, instead of waiting for an upload that never comes.
func TestSessionWithNothingWrittenClosesAtOnce(t *testing.T) {
	transport, err := NewClient(context.Background(), N.SystemDialer, M.ParseSocksaddr("127.0.0.1:443"), option.V2RayXHTTPOptions{Mode: "stream-one"}, nil)
	require.NoError(t, err)
	defer transport.Close()
	stream := &unopenedStream{closed: make(chan struct{})}
	client := transport.(*Client)
	client.getHTTPClient = func() (DialerClient, *XmuxClient) { return stream, nil }
	client.getHTTPClient2 = client.getHTTPClient
	conn, err := client.DialContext(context.Background())
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	select {
	case <-stream.closed:
	case <-time.After(time.Second):
		t.Fatal("the session stayed for an upload it never had")
	}
}
