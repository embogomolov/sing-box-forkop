package vless

import (
	"bytes"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

// rawConn stands for the connection under the TLS one: it has a read waiter and counts
// what came through it.
type rawConn struct {
	net.Conn
	options N.ReadWaitOptions
	waits   atomic.Int32
}

func (c *rawConn) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	c.options = options
	return false
}

func (c *rawConn) WaitReadBuffer() (*buf.Buffer, error) {
	c.waits.Add(1)
	buffer := c.options.NewBuffer()
	n, err := c.Conn.Read(buffer.FreeBytes())
	if n > 0 {
		buffer.Truncate(n)
		return buffer, nil
	}
	buffer.Release()
	return nil, err
}

// In direct mode the copy loop takes the data buffered at the switch through the Vision
// connection, then reads the underlying connection itself, here through its read waiter.
func TestVisionDirectReadUnwraps(t *testing.T) {
	remote, local := net.Pipe()
	unused, unusedPeer := net.Pipe()
	defer unused.Close()
	defer unusedPeer.Close()
	raw := &rawConn{Conn: local}
	conn := &VisionConn{
		Conn:             unused,
		netConn:          raw,
		directRead:       true,
		remainingBuffers: []*buf.Buffer{buf.As([]byte("buffered "))},
	}
	if !conn.NeedHandshakeForRead() || conn.ReaderReplaceable() {
		t.Fatal("the connection is replaceable before the buffered data is out")
	}

	var output bytes.Buffer
	done := make(chan error, 1)
	go func() {
		_, err := bufio.Copy(&output, conn)
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	if _, err := remote.Write([]byte("direct")); err != nil {
		t.Fatal(err)
	}
	remote.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if output.String() != "buffered direct" {
		t.Fatalf("copied %q", output.String())
	}
	if raw.waits.Load() == 0 {
		t.Fatal("the copy loop kept reading through the Vision connection")
	}
	if conn.NeedHandshakeForRead() || !conn.ReaderReplaceable() || conn.UpstreamReader() != net.Conn(raw) {
		t.Fatal("the drained direct connection is not replaceable by its underlying one")
	}
}

// Before direct mode the connection stays in the copy path.
func TestVisionPaddingReadNotReplaceable(t *testing.T) {
	conn := &VisionConn{withinPaddingBuffers: true}
	if !conn.NeedHandshakeForRead() || conn.ReaderReplaceable() {
		t.Fatal("the connection is replaceable before direct mode")
	}
}
