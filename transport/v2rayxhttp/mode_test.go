package xhttp

import (
	"context"
	"encoding/base64"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/xray/buf"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// requestRecorder names the requests of a stream as Xray's server tells them apart and answers each one
// with an empty response.
type requestRecorder struct {
	access    sync.Mutex
	requests  []string
	postSizes []int32
}

func (r *requestRecorder) IsClosed() bool { return false }

func (r *requestRecorder) Close() {}

func (r *requestRecorder) OpenStream(ctx context.Context, url string, sessionId string, body io.Reader, uploadOnly bool) (io.ReadCloser, net.Addr, net.Addr, error) {
	switch {
	case body == nil:
		r.record("stream-down")
	case sessionId == "":
		r.record("stream-one")
	default:
		r.record("stream-up")
	}
	if body != nil {
		go io.Copy(io.Discard, body)
	}
	return io.NopCloser(strings.NewReader("")), nil, nil, nil
}

func (r *requestRecorder) PostPacket(ctx context.Context, url string, sessionId string, seqStr string, payload buf.MultiBuffer) error {
	r.access.Lock()
	r.postSizes = append(r.postSizes, payload.Len())
	r.access.Unlock()
	buf.ReleaseMulti(payload)
	r.record("packet-up")
	return nil
}

func (r *requestRecorder) posted() (largest int32, total int32) {
	r.access.Lock()
	defer r.access.Unlock()
	for _, size := range r.postSizes {
		largest = max(largest, size)
		total += size
	}
	return
}

func (r *requestRecorder) record(request string) {
	r.access.Lock()
	defer r.access.Unlock()
	r.requests = append(r.requests, request)
}

func (r *requestRecorder) recorded() []string {
	r.access.Lock()
	defer r.access.Unlock()
	return append([]string(nil), r.requests...)
}

// An auto node sends what Xray's client sends, as a server set to that mode refuses every other.
func TestAutoModeFollowsXray(t *testing.T) {
	publicKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	download := &option.V2RayXHTTPDownloadOptions{ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 443}}
	for _, test := range []struct {
		mode      string
		reality   bool
		kernelTLS bool
		download  *option.V2RayXHTTPDownloadOptions
		requests  []string
	}{
		{mode: "auto", requests: []string{"stream-down", "packet-up"}},
		{mode: "auto", reality: true, requests: []string{"stream-one"}},
		{mode: "", reality: true, requests: []string{"stream-one"}},
		{mode: "auto", reality: true, kernelTLS: true, requests: []string{"stream-one"}},
		{mode: "auto", reality: true, download: download, requests: []string{"stream-down", "stream-up"}},
		{mode: "packet-up", reality: true, requests: []string{"stream-down", "packet-up"}},
	} {
		tlsOptions := option.OutboundTLSOptions{Enabled: true, ServerName: "xhttp.example"}
		if test.reality {
			tlsOptions.UTLS = &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"}
			tlsOptions.Reality = &option.OutboundRealityOptions{Enabled: true, PublicKey: publicKey}
		}
		tlsConfig, err := tls.NewClient(context.Background(), log.StdLogger(), "xhttp.example", tlsOptions)
		require.NoError(t, err)
		if test.kernelTLS {
			tlsConfig = &tls.KTLSClientConfig{Config: tlsConfig}
		}
		options := option.V2RayXHTTPOptions{Mode: test.mode, Download: test.download}
		transport, err := NewClient(context.Background(), N.SystemDialer, M.ParseSocksaddr("127.0.0.1:443"), options, tlsConfig)
		require.NoError(t, err)
		recorder := &requestRecorder{}
		client := transport.(*Client)
		client.getHTTPClient = func() (DialerClient, *XmuxClient) { return recorder, nil }
		client.getHTTPClient2 = client.getHTTPClient
		conn, err := client.DialContext(context.Background())
		require.NoError(t, err)
		_, err = conn.Write([]byte("request"))
		require.NoError(t, err)
		require.Eventually(t, func() bool { return len(recorder.recorded()) >= len(test.requests) }, time.Second, time.Millisecond)
		require.Equal(t, test.requests, recorder.recorded(), "mode %q, reality %v, kTLS %v, download %v",
			test.mode, test.reality, test.kernelTLS, test.download != nil)
		conn.Close()
		client.Close()
	}
}

// Upload data carried in headers or cookies has to fit the 8 KiB of headers a server takes: a post of such
// a node is 4 KiB unless it sets its own size, where Xray's default megabyte failed every bulk upload.
func TestHeaderUploadsArePostedSmall(t *testing.T) {
	interval := &option.Range[int]{From: 1, To: 1}
	for _, test := range []struct {
		placement string
		size      *option.Range[int]
		largest   int32
	}{
		{placement: option.PlacementHeader, largest: 4096},
		{placement: option.PlacementCookie, largest: 4096},
		{placement: option.PlacementHeader, size: &option.Range[int]{From: 6000, To: 6000}, largest: 6000},
		{placement: option.PlacementBody, largest: 64 * 1024},
	} {
		options := option.V2RayXHTTPOptions{Mode: "packet-up", V2RayXHTTPBaseOptions: option.V2RayXHTTPBaseOptions{
			UplinkDataPlacement: test.placement, ScMaxEachPostBytes: test.size, ScMinPostsIntervalMs: interval,
		}}
		transport, err := NewClient(context.Background(), N.SystemDialer, M.ParseSocksaddr("127.0.0.1:443"), options, nil)
		require.NoError(t, err)
		recorder := &requestRecorder{}
		client := transport.(*Client)
		client.getHTTPClient = func() (DialerClient, *XmuxClient) { return recorder, nil }
		client.getHTTPClient2 = client.getHTTPClient
		conn, err := client.DialContext(context.Background())
		require.NoError(t, err)
		_, err = conn.Write(make([]byte, 64*1024))
		require.NoError(t, err)
		require.Eventually(t, func() bool { _, total := recorder.posted(); return total == 64*1024 }, 5*time.Second, time.Millisecond, test.placement)
		largest, _ := recorder.posted()
		require.LessOrEqual(t, largest, test.largest, test.placement)
		conn.Close()
		client.Close()
	}
}

// silentServer takes the posts of an upload and never answers them, as a server does whose destination
// stopped reading.
type silentServer struct {
	requestRecorder
	waiting atomic.Int32
}

func (s *silentServer) PostPacket(ctx context.Context, url string, sessionId string, seqStr string, payload buf.MultiBuffer) error {
	s.waiting.Add(1)
	<-ctx.Done()
	buf.ReleaseMulti(payload)
	return ctx.Err()
}

// Posts nobody answers hold their data: an upload stops at 4 MiB of them, where it went on taking the
// writes of the session until the router ran out of memory.
func TestUnansweredPostsAreBounded(t *testing.T) {
	options := option.V2RayXHTTPOptions{Mode: "packet-up", V2RayXHTTPBaseOptions: option.V2RayXHTTPBaseOptions{
		ScMinPostsIntervalMs: &option.Range[int]{From: 1, To: 1},
	}}
	transport, err := NewClient(context.Background(), N.SystemDialer, M.ParseSocksaddr("127.0.0.1:443"), options, nil)
	require.NoError(t, err)
	server := &silentServer{}
	client := transport.(*Client)
	client.getHTTPClient = func() (DialerClient, *XmuxClient) { return server, nil }
	client.getHTTPClient2 = client.getHTTPClient
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn, err := client.DialContext(ctx)
	require.NoError(t, err)
	var written atomic.Int64
	go func() {
		block := make([]byte, 64*1024)
		for {
			n, err := conn.Write(block)
			written.Add(int64(n))
			if err != nil {
				return
			}
		}
	}()
	time.Sleep(500 * time.Millisecond)
	require.EqualValues(t, 4, server.waiting.Load())
	require.Less(t, written.Load(), int64(8<<20))
	conn.Close()
	client.Close()
}
