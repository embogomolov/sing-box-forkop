package xhttp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/xray/buf"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// One failed request leaves the other sessions on its connection alone: the client takes no new sessions,
// as Xray's does, and its connections close once the last of them is over.
func TestFailedRequestKeepsItsNeighbours(t *testing.T) {
	more := make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/fail") {
			panic(http.ErrAbortHandler)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("a"))
		w.(http.Flusher).Flush()
		select {
		case <-more:
			w.Write([]byte("b"))
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		case <-r.Context().Done():
		}
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	destination := M.ParseSocksaddr(server.Listener.Addr().String())
	tlsConfig, err := tls.NewClient(context.Background(), log.NewNOPFactory().NewLogger("test"), destination.AddrString(), option.OutboundTLSOptions{
		Enabled:  true,
		Insecure: true,
		ALPN:     []string{"h2"},
	})
	require.NoError(t, err)
	client := createHTTPClient(context.Background(), destination, N.SystemDialer, &option.V2RayXHTTPBaseOptions{}, tlsConfig).(*DefaultDialerClient)
	download, _, _, err := client.OpenStream(context.Background(), server.URL+"/session", "session", nil, false)
	require.NoError(t, err)
	defer download.Close()
	received := make([]byte, 1)
	_, err = io.ReadFull(download, received)
	require.NoError(t, err)

	err = client.PostPacket(context.Background(), server.URL+"/fail", "session", "0", buf.MergeBytes(nil, []byte("upload")))
	require.Error(t, err)
	require.True(t, client.IsClosed())

	close(more)
	_, err = io.ReadFull(download, received)
	require.NoError(t, err)
	require.Equal(t, "b", string(received))
}
