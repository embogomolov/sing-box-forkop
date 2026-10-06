package route

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	"github.com/sagernet/sing-box/log"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type lockedBuffer struct {
	access sync.Mutex
	buffer bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.access.Lock()
	defer b.access.Unlock()
	return b.buffer.Write(p)
}

func (b *lockedBuffer) String() string {
	b.access.Lock()
	defer b.access.Unlock()
	return b.buffer.String()
}

// lines returns the log lines of level and above debug.
func (b *lockedBuffer) lines() []string {
	var lines []string
	for _, line := range strings.Split(strings.TrimSpace(b.String()), "\n") {
		if line != "" && !strings.HasPrefix(line, "DEBUG") {
			lines = append(lines, line)
		}
	}
	return lines
}

// A real logger: it panics on argument types it does not format.
func newLoggedRouter(t *testing.T) (*Router, *lockedBuffer) {
	output := new(lockedBuffer)
	factory := log.NewDefaultFactory(context.Background(), log.Formatter{BaseTime: time.Now(), DisableColors: true}, output, "", nil, false)
	require.NoError(t, factory.Start())
	t.Cleanup(func() { factory.Close() })
	return &Router{ctx: context.Background(), logger: factory.NewLogger("router")}, output
}

// onePacket delivers the same packet on every read.
type onePacket struct {
	N.PacketConn
}

func (onePacket) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	buffer.Write([]byte("packet"))
	return M.ParseSocksaddr("192.0.2.1:443"), nil
}

func (onePacket) SetReadDeadline(time.Time) error { return nil }

func panickingSniffer(context.Context, *adapter.InboundContext, []byte) error {
	var empty []byte
	_ = empty[1]
	return nil
}

func panickingStreamSniffer(context.Context, *adapter.InboundContext, io.Reader) error {
	return panickingSniffer(nil, nil, nil)
}

// A sniffer that panics on what a client sends panics for every such connection: its stack
// is logged for the first one and then at most once per interval, with the number of
// panics in between, and the error kept in the metadata of each connection is one line.
func TestSnifferPanicStackIsLoggedOncePerInterval(t *testing.T) {
	router, output := newLoggedRouter(t)
	action := &R.RuleActionSniff{
		PacketSniffers: []sniff.PacketSniffer{panickingSniffer},
		StreamSniffers: []sniff.StreamSniffer{panickingStreamSniffer},
	}
	sniffPacket := func() {
		var metadata adapter.InboundContext
		_, packetBuffers, fatalErr := router.actionSniff(context.Background(), &metadata, action, nil, onePacket{}, nil, nil)
		require.NoError(t, fatalErr)
		N.ReleaseMultiPacketBuffer(packetBuffers)
		require.ErrorIs(t, metadata.SniffError, sniff.ErrSnifferPanicked)
		require.Contains(t, metadata.SniffError.Error(), "index out of range")
		require.NotContains(t, metadata.SniffError.Error(), "\n", "the error of the connection carries no stack")
	}
	sniffStream := func() {
		var metadata adapter.InboundContext
		conn, peer := net.Pipe()
		defer conn.Close()
		defer peer.Close()
		go peer.Write([]byte("stream"))
		buffer, _, fatalErr := router.actionSniff(context.Background(), &metadata, action, conn, nil, nil, nil)
		require.NoError(t, fatalErr)
		buffer.Release()
		require.ErrorIs(t, metadata.SniffError, sniff.ErrSnifferPanicked)
		require.NotContains(t, metadata.SniffError.Error(), "\n", "the error of the connection carries no stack")
	}
	sniffPacket()
	for range 3 {
		sniffPacket()
		sniffStream()
	}
	logged := output.String()
	require.Equal(t, 1, strings.Count(logged, " [running]:"), logged)
	require.Contains(t, logged, "panickingSniffer")
	errorLines := 0
	for _, line := range output.lines() {
		if strings.HasPrefix(line, "ERROR") {
			errorLines++
			require.Contains(t, line, "sniffer panicked: runtime error: index out of range")
		}
	}
	require.Equal(t, 1, errorLines, logged)

	// the interval is over
	snifferPanicLogInterval = time.Nanosecond
	defer func() { snifferPanicLogInterval = time.Minute }()
	sniffPacket()
	logged = output.String()
	require.Equal(t, 2, strings.Count(logged, " [running]:"), logged)
	require.Contains(t, logged, "6 more since the last stack was logged")
}
