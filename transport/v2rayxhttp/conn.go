package xhttp

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/common/badh2"
	"github.com/sagernet/sing-box/common/readwait"
	"github.com/sagernet/sing-box/common/xray/signal/done"
	N "github.com/sagernet/sing/common/network"
)

type splitConn struct {
	writer     io.WriteCloser
	reader     io.ReadCloser
	remoteAddr net.Addr
	localAddr  net.Addr
	onClose    func()

	// closed once the upload has left after a close; nil where a close takes the session down at once
	uploadSent    <-chan struct{}
	cancelUploads context.CancelFunc
	// written to at all, and since the other side last sent anything
	wrote        atomic.Bool
	unanswered   atomic.Bool
	closed       atomic.Bool
	teardownOnce sync.Once

	// what the read waiter's probe read, delivered before the next read
	probe      []byte
	pending    []byte
	pendingErr error
	flowing    bool
}

func (c *splitConn) Write(b []byte) (int, error) {
	if !c.unanswered.Load() {
		c.unanswered.Store(true)
		c.wrote.Store(true)
	}
	return c.writer.Write(b)
}

func (c *splitConn) answered(n int) {
	if n > 0 && c.unanswered.Load() {
		c.unanswered.Store(false)
	}
}

func (c *splitConn) Read(b []byte) (int, error) {
	if len(c.pending) > 0 {
		n := copy(b, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	if c.pendingErr != nil {
		err := c.pendingErr
		c.pendingErr = nil
		return 0, badh2.HideStreamError(err)
	}
	n, err := c.reader.Read(b)
	c.answered(n)
	c.flowing = n == len(b)
	return n, badh2.HideStreamError(err)
}

// probeSize is what an idle session holds while it waits for the other side.
const probeSize = 512

// CreateReadWaiter lets the copy loop wait for data without its buffer: a response body can't
// be peeked, so the waiter reads a small probe and hands it over first.
func (c *splitConn) CreateReadWaiter() (N.ReadWaiter, bool) {
	return readwait.NewPeekWaiter(c, c.waitData), true
}

func (c *splitConn) waitData() error {
	if len(c.pending) > 0 || c.pendingErr != nil || c.flowing {
		return nil
	}
	if c.probe == nil {
		c.probe = make([]byte, probeSize)
	}
	n, err := c.reader.Read(c.probe)
	c.answered(n)
	c.pending = c.probe[:n]
	c.pendingErr = err
	c.flowing = n == len(c.probe)
	return nil
}

// closeLinger bounds how long a closed session stays to send what was written before the close;
// closeGrace is how long it stays after that when the server has not answered the data, for the server
// to forward it, as an outbound of Xray waits after the end of an upload (its policy's downlinkOnly).
const (
	closeLinger = 5 * time.Second
	closeGrace  = time.Second
)

// Close ends the upload at once and takes the session down once the upload has left: sing-box closes a
// connection as soon as its source is done, and what was written just before must still reach the server.
// A session whose last write was answered, the usual end of an exchange, goes at once, as does one that
// wrote nothing, also while its stream has not opened.
func (c *splitConn) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	err := c.writer.Close()
	if c.uploadSent == nil || !c.wrote.Load() {
		c.teardown()
		return err
	}
	unanswered := c.unanswered.Load()
	if !unanswered {
		select {
		case <-c.uploadSent:
			c.teardown()
			return err
		default:
		}
	}
	go func() {
		defer c.teardown()
		timer := time.NewTimer(closeLinger)
		defer timer.Stop()
		select {
		case <-c.uploadSent:
		case <-timer.C:
			return
		}
		if unanswered {
			timer.Reset(closeGrace)
			<-timer.C
		}
	}()
	return err
}

// uploadBody is the body of the request that streams an upload: the HTTP client reading it to its end, or
// closing it, is the moment the upload has left.
type uploadBody struct {
	*io.PipeReader
	ended func()
}

func (b *uploadBody) Read(p []byte) (int, error) {
	n, err := b.PipeReader.Read(p)
	if err != nil {
		b.ended()
	}
	return n, err
}

func (b *uploadBody) Close() error {
	b.ended()
	return b.PipeReader.Close()
}

func (c *splitConn) teardown() {
	c.teardownOnce.Do(func() {
		if c.cancelUploads != nil {
			c.cancelUploads()
		}
		c.reader.Close()
		if c.onClose != nil {
			c.onClose()
		}
	})
}

func (c *splitConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *splitConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *splitConn) SetDeadline(t time.Time) error {
	// TODO cannot do anything useful
	return nil
}

func (c *splitConn) SetReadDeadline(t time.Time) error {
	// TODO cannot do anything useful
	return nil
}

func (c *splitConn) SetWriteDeadline(t time.Time) error {
	// TODO cannot do anything useful
	return nil
}

type H1Conn struct {
	UnreadedResponsesCount int
	RespBufReader          *bufio.Reader
	net.Conn
}

func NewH1Conn(conn net.Conn) *H1Conn {
	return &H1Conn{
		RespBufReader: bufio.NewReader(conn),
		Conn:          conn,
	}
}

type httpServerConn struct {
	sync.Mutex
	*done.Instance
	io.Reader // no need to Close request.Body
	http.ResponseWriter
}

func (c *httpServerConn) Write(b []byte) (int, error) {
	c.Lock()
	defer c.Unlock()
	if c.Done() {
		return 0, io.ErrClosedPipe
	}
	n, err := c.ResponseWriter.Write(b)
	if err == nil {
		c.ResponseWriter.(http.Flusher).Flush()
	}
	return n, err
}

func (c *httpServerConn) Close() error {
	c.Lock()
	defer c.Unlock()
	return c.Instance.Close()
}
