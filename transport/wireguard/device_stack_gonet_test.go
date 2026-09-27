//go:build with_gvisor

package wireguard

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	C "github.com/sagernet/sing-box/constant"
)

// gVisor retries an unanswered SYN for about two minutes, and nothing above
// the netstack puts a deadline on a dial, so a silent peer held every
// connection through the tunnel that long.
func TestDialTCPWithBindGivesUpOnSilentPeer(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the connect timeout")
	}
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	defer s.Close()
	if err := s.CreateNIC(1, channel.New(8, 1500, "")); err != nil {
		t.Fatal(err)
	}
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4([4]byte{10, 99, 0, 2}), PrefixLen: 32},
	}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := DialTCPWithBind(context.Background(), s, tcpip.FullAddress{}, tcpip.FullAddress{
			NIC:  1,
			Addr: tcpip.AddrFrom4([4]byte{203, 0, 113, 5}),
			Port: 80,
		}, ipv4.ProtocolNumber)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("dial to a silent peer failed with %v, want the connect deadline", err)
		}
		if elapsed := time.Since(start); elapsed < C.TCPTimeout-time.Second {
			t.Fatalf("dial gave up after %v, before the %v connect timeout", elapsed, C.TCPTimeout)
		}
	case <-time.After(C.TCPTimeout + 5*time.Second):
		t.Fatalf("dial to a silent peer still waiting after %v", C.TCPTimeout+5*time.Second)
	}
}
