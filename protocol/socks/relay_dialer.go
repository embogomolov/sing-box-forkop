package socks

import (
	"context"
	"net"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// relayDialer sends the UDP relay of a SOCKS5 association to the server's
// address when the server names an unspecified BND.ADDR, which Go would
// otherwise dial on the local machine.
type relayDialer struct {
	N.Dialer
	server M.Socksaddr
}

func (d *relayDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) == N.NetworkUDP && destination.IsIP() && destination.Addr.IsUnspecified() {
		destination = M.Socksaddr{Addr: d.server.Addr, Fqdn: d.server.Fqdn, Port: destination.Port}
	}
	return d.Dialer.DialContext(ctx, network, destination)
}

func (d *relayDialer) Upstream() any {
	return d.Dialer
}
