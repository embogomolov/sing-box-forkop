//go:build with_gvisor

package wireguard

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service/pause"

	"golang.org/x/crypto/curve25519"
)

func testKeyPair(t *testing.T) (string, string) {
	t.Helper()
	private := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(private); err != nil {
		t.Fatal(err)
	}
	private[0] &= 248
	private[31] = (private[31] & 127) | 64
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(private), base64.StdEncoding.EncodeToString(public)
}

// listenDialer stands for the direct dialer a server endpoint listens with.
type listenDialer struct{}

func (listenDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, net.ErrClosed
}

func (listenDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

func (listenDialer) UDPListenerControl() (control.Func, bool) {
	return nil, false
}

// proxyDialer stands for a detour to a proxy server without IPv6: it resolves a
// name it is asked to connect to itself, and its UDP session for several
// destinations ends for all of them when the server meets a datagram to an IPv6
// address, as a VLESS server's does. The client has already handed over what it
// sent after that datagram, and the server forwards none of it.
type proxyDialer struct {
	access   sync.Mutex
	dialed   []M.Socksaddr
	listened int
}

func (d *proxyDialer) DialContext(_ context.Context, _ string, destination M.Socksaddr) (net.Conn, error) {
	d.access.Lock()
	d.dialed = append(d.dialed, destination)
	d.access.Unlock()
	if destination.IsFqdn() {
		destination = M.SocksaddrFrom(netip.MustParseAddr("127.0.0.1"), destination.Port)
	}
	return net.DialUDP("udp4", nil, destination.UDPAddr())
}

func (d *proxyDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	d.access.Lock()
	d.listened++
	d.access.Unlock()
	packetConn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return nil, err
	}
	session := &ipv4OnlySession{
		PacketConn: packetConn,
		queue:      make(chan queuedDatagram, 64),
		done:       make(chan struct{}),
	}
	go session.serve()
	return session, nil
}

type queuedDatagram struct {
	data []byte
	addr net.Addr
	sent time.Time
}

type ipv4OnlySession struct {
	net.PacketConn
	queue chan queuedDatagram
	done  chan struct{}
	ended atomic.Bool
}

// serve is the proxy server: it takes the datagrams in the order they were sent,
// each once it had time to get there.
func (s *ipv4OnlySession) serve() {
	for {
		select {
		case <-s.done:
			return
		case datagram := <-s.queue:
			time.Sleep(time.Until(datagram.sent.Add(20 * time.Millisecond)))
			if udpAddr, isUDP := datagram.addr.(*net.UDPAddr); isUDP && udpAddr.IP.To4() == nil {
				s.Close()
				return
			}
			_, _ = s.PacketConn.WriteTo(datagram.data, datagram.addr)
		}
	}
}

func (s *ipv4OnlySession) WriteTo(p []byte, addr net.Addr) (int, error) {
	if !s.ended.Load() {
		select {
		case s.queue <- queuedDatagram{append([]byte(nil), p...), addr, time.Now()}:
		default:
		}
	}
	return len(p), nil
}

func (s *ipv4OnlySession) Close() error {
	if !s.ended.Swap(true) {
		close(s.done)
		return s.PacketConn.Close()
	}
	return nil
}

var _ N.Dialer = (*proxyDialer)(nil)

func startTestEndpoint(t *testing.T, options EndpointOptions, postStart bool) *Endpoint {
	t.Helper()
	endpoint, err := NewEndpoint(options)
	if err != nil {
		t.Fatal(err)
	}
	if err = endpoint.Start(postStart); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { endpoint.Close() })
	return endpoint
}

func handshakeCompleted(endpoint *Endpoint) bool {
	state, err := endpoint.device.IpcGet()
	return err == nil && strings.Contains(state, "last_handshake_time_sec=") &&
		!strings.Contains(state, "last_handshake_time_sec=0\n")
}

// A peer known by a name that has an IPv6 address the proxy cannot reach: led
// through the proxy it must still come up, since the proxy resolves the name.
func TestClientBindDialsLonePeerByNameThroughDetour(t *testing.T) {
	ctx := pause.WithDefaultManager(context.Background())
	serverPrivate, serverPublic := testKeyPair(t)
	clientPrivate, clientPublic := testKeyPair(t)
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(probe.LocalAddr().(*net.UDPAddr).Port)
	probe.Close()

	startTestEndpoint(t, EndpointOptions{
		Context:    ctx,
		Logger:     logger.NOP(),
		Dialer:     listenDialer{},
		Address:    []netip.Prefix{netip.MustParsePrefix("10.77.0.1/32")},
		PrivateKey: serverPrivate,
		ListenPort: port,
		Peers: []PeerOptions{{
			PublicKey:  clientPublic,
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.77.0.2/32")},
		}},
	}, false)

	proxy := &proxyDialer{}
	var resolved atomic.Bool
	client := startTestEndpoint(t, EndpointOptions{
		Context:    ctx,
		Logger:     logger.NOP(),
		Dialer:     proxy,
		Address:    []netip.Prefix{netip.MustParsePrefix("10.77.0.2/32")},
		PrivateKey: clientPrivate,
		ResolvePeer: func(string) ([]netip.Addr, error) {
			resolved.Store(true)
			return []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("127.0.0.1")}, nil
		},
		Peers: []PeerOptions{{
			Endpoint:                    M.ParseSocksaddrHostPort("wg.test", port),
			PublicKey:                   serverPublic,
			AllowedIPs:                  []netip.Prefix{netip.MustParsePrefix("10.77.0.1/32")},
			PersistentKeepaliveInterval: &option.Range[uint32]{From: 1, To: 1},
		}},
	}, true)

	deadline := time.Now().Add(8 * time.Second)
	for !handshakeCompleted(client) {
		if time.Now().After(deadline) {
			t.Fatal("the handshake through the proxy did not complete")
		}
		time.Sleep(50 * time.Millisecond)
	}
	proxy.access.Lock()
	defer proxy.access.Unlock()
	if resolved.Load() || proxy.listened != 0 {
		t.Fatalf("the peer's name was resolved here (%v) or raced through a shared session (%d)", resolved.Load(), proxy.listened)
	}
	if len(proxy.dialed) == 0 {
		t.Fatal("the proxy was never asked for the peer")
	}
	for _, destination := range proxy.dialed {
		if destination.Fqdn != "wg.test" || destination.Port != port {
			t.Fatalf("the proxy was asked for %s instead of the peer's name", destination)
		}
	}
}
