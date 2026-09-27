package device

import (
	"encoding/binary"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/wireguard-go/conn"
)

// capBind records the capacity behind every transport datagram it sends: the
// buffer a TUN-path element carried from the TUN reader to the socket.
type capBind struct {
	*chanBind
	mu   sync.Mutex
	caps []int
}

func (b *capBind) Send(bufs [][]byte, ep conn.Endpoint, offset int) error {
	b.mu.Lock()
	for _, buf := range bufs {
		if len(buf)-offset >= 4 && binary.LittleEndian.Uint32(buf[offset:]) == MessageTransportType {
			b.caps = append(b.caps, cap(buf)-offset)
		}
	}
	b.mu.Unlock()
	return b.chanBind.Send(bufs, ep, offset)
}

func (b *capBind) maxCap() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	result := 0
	for _, c := range b.caps {
		result = max(result, c)
	}
	return result
}

// After the peer's UDP window has grown past DefaultUdpWindow, the random
// trailer of a small packet read from the TUN still reaches up to that window:
// sizing the element for the packet must not shorten the obfuscation.
func TestTunPathTrailersReachUDPWindow(t *testing.T) {
	tap := &wireTap{}
	pair, peer := newObfuscatedPair(t, "random_trailers=1\n")
	pair.devA.net.bind.(*chanBind).tap = tap.record

	large := buildIPv4Packet(testIPA, testIPB, 1200)
	awaitPacket(t, pair.tunB, large, func() { pair.tunA.toDevice <- large })
	window := int(peer.udpWindow.Load())
	if window <= DefaultUdpWindow {
		t.Fatalf("UDP window %d did not grow past %d after a large packet", window, DefaultUdpWindow)
	}
	mark := len(tap.snapshot())

	small := buildIPv4Packet(testIPA, testIPB, 40)
	const count = 40
	for i := 0; i < count; i++ {
		pair.tunA.toDevice <- small
	}
	for i := 0; i < count; i++ {
		select {
		case <-pair.tunB.fromDevice:
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d of %d small packets arrived", i, count)
		}
	}

	beyondDefault := 0
	for _, dg := range tap.snapshot()[mark:] {
		if len(dg) < MessageTransportSize || binary.LittleEndian.Uint32(dg) != MessageTransportType {
			continue
		}
		if len(dg) > window {
			t.Errorf("datagram of %d bytes grew past the UDP window %d", len(dg), window)
		}
		if len(dg) > DefaultUdpWindow {
			beyondDefault++
		}
	}
	if beyondDefault == 0 {
		t.Errorf("no small-packet datagram carried a trailer past %d bytes with a %d-byte window", DefaultUdpWindow, window)
	}
}

// A packet read from a TUN that reads one packet at a time leaves in a buffer
// sized for its datagram, not in a MaxMessageSize one: thousands of them queue
// behind a slow uplink.
func TestTunPathElementsSizedToPacket(t *testing.T) {
	pair, _ := newObfuscatedPair(t, "")
	pkt := buildIPv4Packet(testIPA, testIPB, 40)
	awaitPacket(t, pair.tunB, pkt, func() { pair.tunA.toDevice <- pkt })
	// the keepalive that completes the handshake is not a TUN-path packet
	time.Sleep(200 * time.Millisecond)

	bind := &capBind{chanBind: pair.devA.net.bind.(*chanBind)}
	pair.devA.net.Lock()
	pair.devA.net.bind = bind
	pair.devA.net.Unlock()
	for i := 0; i < 20; i++ {
		pair.tunA.toDevice <- pkt
		<-pair.tunB.fromDevice
	}

	if got := bind.maxCap(); got == 0 || got > 2048 {
		t.Fatalf("TUN-path datagrams of %d bytes left in buffers of up to %d bytes", MessageTransportSize+len(pkt), got)
	}
}
