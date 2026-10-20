package xhttp

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"sync"
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

	// what the read waiter's probe read, delivered before the next read
	probe      []byte
	pending    []byte
	pendingErr error
	flowing    bool
}

func (c *splitConn) Write(b []byte) (int, error) {
	return c.writer.Write(b)
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
	c.pending = c.probe[:n]
	c.pendingErr = err
	c.flowing = n == len(c.probe)
	return nil
}

func (c *splitConn) Close() error {
	if c.onClose != nil {
		c.onClose()
	}

	err := c.writer.Close()
	err2 := c.reader.Close()
	if err != nil {
		return err
	}

	if err2 != nil {
		return err2
	}

	return nil
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
