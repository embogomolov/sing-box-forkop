package xhttp

import (
	"context"
	gotls "crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

// The test server announces 1 MiB frames, as Xray's does: without the cap every streamed
// upload held a request body buffer of 512 KiB for as long as it stayed open.
func TestStreamedUploadBufferIsCapped(t *testing.T) {
	release := make(chan struct{})
	received := make(chan string, 64)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buffer := make([]byte, 1024)
		_, _ = io.ReadFull(r.Body, buffer)
		received <- r.Proto
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-release
	}))
	h2Server := &http2.Server{MaxReadFrameSize: 1 << 20}
	server.TLS = &gotls.Config{NextProtos: []string{"h2"}}
	server.Config.TLSNextProto = map[string]func(*http.Server, *gotls.Conn, http.Handler){
		"h2": func(httpServer *http.Server, conn *gotls.Conn, handler http.Handler) {
			h2Server.ServeConn(conn, &http2.ServeConnOpts{BaseConfig: httpServer, Handler: handler})
		},
	}
	server.StartTLS()
	defer server.Close()
	defer close(release)

	destination := M.ParseSocksaddr(server.Listener.Addr().String())
	tlsConfig, err := tls.NewClient(context.Background(), log.NewNOPFactory().NewLogger("test"), destination.AddrString(), option.OutboundTLSOptions{
		Enabled:  true,
		Insecure: true,
		ALPN:     []string{"h2"},
	})
	require.NoError(t, err)
	client := createHTTPClient(context.Background(), destination, N.SystemDialer, &option.V2RayXHTTPBaseOptions{}, tlsConfig).(*DefaultDialerClient)

	upload := func() *io.PipeWriter {
		reader, writer := io.Pipe()
		request, err := http.NewRequest(http.MethodPost, server.URL, reader)
		require.NoError(t, err)
		go func() {
			// the session's download: open for as long as the session
			response, err := client.client.Do(request)
			if err == nil {
				<-release
				response.Body.Close()
			}
		}()
		_, err = writer.Write(make([]byte, 1024))
		require.NoError(t, err)
		require.Equal(t, "HTTP/2.0", <-received)
		return writer
	}
	upload().Close()
	heap := func() uint64 {
		runtime.GC()
		runtime.GC()
		var stats runtime.MemStats
		runtime.ReadMemStats(&stats)
		return stats.HeapAlloc
	}
	before := heap()
	const sessions = 50
	var writers []*io.PipeWriter
	for range sessions {
		writers = append(writers, upload())
	}
	perSession := (int64(heap()) - int64(before)) / sessions
	for _, writer := range writers {
		writer.Close()
	}
	t.Logf("heap per open streamed upload (client and test server): %d B", perSession)
	require.Less(t, perSession, int64(128*1024))
}
