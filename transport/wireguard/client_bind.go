package wireguard

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/device"
)

var _ conn.Bind = (*ClientBind)(nil)

// connectionIdleTimeout closes a connection to the server that brought nothing
// for so long: no WireGuard session outlives it, and a NAT on the way may have
// forgotten the connection without a word to either end.
var connectionIdleTimeout = device.RejectAfterTime

type ClientBind struct {
	ctx                 context.Context
	logger              logger.Logger
	pauseManager        pause.Manager
	bindCtx             context.Context
	bindDone            context.CancelFunc
	dialer              N.Dialer
	reservedAccess      sync.RWMutex
	reservedForEndpoint map[netip.AddrPort][3]uint8
	connAccess          sync.Mutex
	conn                atomic.Pointer[wireConn]
	connected           chan struct{}
	done                chan struct{}
	isConnect           bool
	connectAddr         M.Socksaddr
	reserved            [3]uint8
}

func NewClientBind(ctx context.Context, logger logger.Logger, dialer N.Dialer, isConnect bool, connectAddr M.Socksaddr, reserved [3]uint8) *ClientBind {
	return &ClientBind{
		ctx:                 ctx,
		logger:              logger,
		pauseManager:        service.FromContext[pause.Manager](ctx),
		dialer:              dialer,
		reservedForEndpoint: make(map[netip.AddrPort][3]uint8),
		connected:           make(chan struct{}),
		done:                make(chan struct{}),
		isConnect:           isConnect,
		connectAddr:         connectAddr,
		reserved:            reserved,
	}
}

// hasReserved reports whether a Cloudflare reserved value is configured. Without
// one the bind leaves bytes 1-3 alone, where an AmneziaWG magic header lives.
func (c *ClientBind) hasReserved() bool {
	if c.reserved != [3]uint8{} {
		return true
	}
	c.reservedAccess.RLock()
	defer c.reservedAccess.RUnlock()
	for _, reserved := range c.reservedForEndpoint {
		if reserved != [3]uint8{} {
			return true
		}
	}
	return false
}

func (c *ClientBind) connect() (*wireConn, error) {
	serverConn := c.conn.Load()
	if serverConn != nil {
		select {
		case <-serverConn.done:
			serverConn = nil
		default:
			return serverConn, nil
		}
	}
	c.connAccess.Lock()
	defer c.connAccess.Unlock()
	select {
	case <-c.done:
		return nil, net.ErrClosed
	default:
	}
	serverConn = c.conn.Load()
	if serverConn != nil {
		select {
		case <-serverConn.done:
			serverConn = nil
		default:
			return serverConn, nil
		}
	}
	if c.isConnect {
		udpConn, err := c.dialer.DialContext(c.bindCtx, N.NetworkUDP, c.connectAddr)
		if err != nil {
			return nil, err
		}
		serverConn = &wireConn{
			PacketConn: bufio.NewUnbindPacketConn(udpConn),
			done:       make(chan struct{}),
		}
	} else {
		udpConn, err := c.dialer.ListenPacket(c.bindCtx, M.Socksaddr{Addr: netip.IPv4Unspecified()})
		if err != nil {
			return nil, err
		}
		serverConn = &wireConn{
			PacketConn: bufio.NewPacketConn(udpConn),
			done:       make(chan struct{}),
		}
	}
	c.conn.Store(serverConn)
	close(c.connected)
	c.connected = make(chan struct{})
	go c.closeWhenIdle(serverConn, connectionIdleTimeout)
	return serverConn, nil
}

// awaitConn returns the connection Send dialed, waiting while there is none: the
// bind dials only to send, since a proxy server ends a session that carries
// nothing, as Xray's mux does after a minute.
func (c *ClientBind) awaitConn() (*wireConn, error) {
	for {
		c.connAccess.Lock()
		serverConn := c.conn.Load()
		connected := c.connected
		c.connAccess.Unlock()
		if serverConn != nil && !serverConn.closed() {
			return serverConn, nil
		}
		select {
		case <-c.done:
			return nil, net.ErrClosed
		case <-connected:
		}
	}
}

func (c *ClientBind) closeWhenIdle(serverConn *wireConn, timeout time.Duration) {
	ticker := time.NewTicker(timeout / 12)
	defer ticker.Stop()
	lastReceived := time.Now()
	for {
		select {
		case <-serverConn.done:
			return
		case now := <-ticker.C:
			if serverConn.received.Swap(false) {
				lastReceived = now
			} else if now.Sub(lastReceived) >= timeout {
				if serverConn.Close() == nil {
					c.logger.Debug("close the connection to the server, idle for ", timeout)
				}
				return
			}
		}
	}
}

// clearPath leaves the connection to a lone peer that WireGuard stopped trusting:
// writes into a connection that a NAT on the way forgot still succeed, so nothing
// else would end it. A connection several peers share is kept for the others.
func (c *ClientBind) clearPath() {
	if !c.isConnect {
		return
	}
	serverConn := c.conn.Load()
	if serverConn != nil && serverConn.Close() == nil {
		c.logger.Debug("close the connection to the server: the peer stopped answering")
	}
}

func (c *ClientBind) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	select {
	case <-c.done:
		c.done = make(chan struct{})
	default:
	}
	c.bindCtx, c.bindDone = context.WithCancel(c.ctx)
	return []conn.ReceiveFunc{c.receive}, 0, nil
}

func (c *ClientBind) receive(packets [][]byte, sizes []int, eps []conn.Endpoint) (count int, err error) {
	udpConn, err := c.awaitConn()
	if err != nil {
		return
	}
	n, addr, err := udpConn.ReadFrom(packets[0])
	if err != nil {
		lost := udpConn.Close() == nil
		select {
		case <-c.done:
		default:
			// a session ending after replies is routine, one without any is refused
			if lost && udpConn.delivered.Load() {
				c.logger.Debug(E.Cause(err, "read packet"))
			} else if lost {
				c.logger.Error(E.Cause(err, "read packet"))
			}
			err = nil
		}
		return
	}
	udpConn.noteReceived()
	sizes[0] = n
	if n > 3 && c.hasReserved() {
		b := packets[0]
		clear(b[1:4])
	}
	if c.connectAddr.IsFqdn() {
		eps[0] = domainEndpoint{c, c.connectAddr}
	} else {
		eps[0] = remoteEndpoint{c, M.SocksaddrFromNet(addr).Unwrap().AddrPort()}
	}
	count = 1
	return
}

func (c *ClientBind) Close() error {
	select {
	case <-c.done:
	default:
		close(c.done)
	}
	if c.bindDone != nil {
		c.bindDone()
	}
	c.connAccess.Lock()
	defer c.connAccess.Unlock()
	common.Close(common.PtrOrNil(c.conn.Load()))
	return nil
}

func (c *ClientBind) SetMark(mark uint32) error {
	return nil
}

func (c *ClientBind) Send(bufs [][]byte, ep conn.Endpoint, offset int) error {
	udpConn, err := c.connect()
	if err != nil {
		time.Sleep(time.Second)
		return err
	}
	var destination netip.AddrPort
	if endpoint, isRemote := ep.(remoteEndpoint); isRemote {
		destination = endpoint.addr
	}
	for _, buf := range bufs {
		if offset > 0 {
			buf = buf[offset:]
		}
		if len(buf) > 3 {
			c.reservedAccess.RLock()
			reserved, loaded := c.reservedForEndpoint[destination]
			c.reservedAccess.RUnlock()
			if !loaded {
				reserved = c.reserved
			}
			if reserved != [3]uint8{} {
				copy(buf[1:4], reserved[:])
			}
		}
		_, err = udpConn.WriteToUDPAddrPort(buf, destination)
		if err != nil {
			if udpConn.Close() != nil {
				// closed under the write by clearPath or closeWhenIdle: a lost datagram
				return nil
			}
			return err
		}
	}
	return nil
}

func (c *ClientBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	if c.connectAddr.IsFqdn() && s == c.connectAddr.String() {
		return domainEndpoint{c, c.connectAddr}, nil
	}
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return remoteEndpoint{c, ap}, nil
}

func (c *ClientBind) BatchSize() int {
	return 1
}

func (c *ClientBind) SetReservedForEndpoint(destination netip.AddrPort, reserved [3]byte) {
	c.reservedAccess.Lock()
	c.reservedForEndpoint[destination] = reserved
	c.reservedAccess.Unlock()
}

type wireConn struct {
	net.PacketConn
	conn      net.Conn
	access    sync.Mutex
	done      chan struct{}
	received  atomic.Bool
	delivered atomic.Bool
}

func (w *wireConn) noteReceived() {
	if !w.received.Load() {
		w.received.Store(true)
	}
	if !w.delivered.Load() {
		w.delivered.Store(true)
	}
}

func (w *wireConn) closed() bool {
	select {
	case <-w.done:
		return true
	default:
		return false
	}
}

func (w *wireConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	if w.conn != nil {
		return w.conn.Write(b)
	}
	return w.PacketConn.WriteTo(b, M.SocksaddrFromNetIP(addr).UDPAddr())
}

func (w *wireConn) Close() error {
	w.access.Lock()
	defer w.access.Unlock()
	select {
	case <-w.done:
		return net.ErrClosed
	default:
	}
	w.PacketConn.Close()
	close(w.done)
	return nil
}

var _ conn.Endpoint = (*remoteEndpoint)(nil)

type remoteEndpoint struct {
	bind *ClientBind
	addr netip.AddrPort
}

// ClearSrc is called by WireGuard before it sends again a handshake that went
// unanswered, or one because the peer fell silent.
func (e remoteEndpoint) ClearSrc() {
	e.bind.clearPath()
}

func (e remoteEndpoint) SrcToString() string {
	return ""
}

func (e remoteEndpoint) DstToString() string {
	return e.addr.String()
}

func (e remoteEndpoint) DstToBytes() []byte {
	b, _ := e.addr.MarshalBinary()
	return b
}

func (e remoteEndpoint) DstIP() netip.Addr {
	return e.addr.Addr()
}

func (e remoteEndpoint) SrcIP() netip.Addr {
	return netip.Addr{}
}

var _ conn.Endpoint = (*domainEndpoint)(nil)

// domainEndpoint is the peer of a bind connected to it by name: the dialer
// resolves the name where it connects, and every packet goes to and comes from
// that connection.
type domainEndpoint struct {
	bind        *ClientBind
	destination M.Socksaddr
}

func (e domainEndpoint) ClearSrc() {
	e.bind.clearPath()
}

func (e domainEndpoint) SrcToString() string {
	return ""
}

func (e domainEndpoint) DstToString() string {
	return e.destination.String()
}

func (e domainEndpoint) DstToBytes() []byte {
	return []byte(e.destination.String())
}

func (e domainEndpoint) DstIP() netip.Addr {
	return netip.Addr{}
}

func (e domainEndpoint) SrcIP() netip.Addr {
	return netip.Addr{}
}
