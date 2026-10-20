package net

import (
	"net"
)

// Destination represents a network destination including address and protocol (tcp / udp).
type Destination struct {
	Address Address
	Port    Port
	Network Network
}

// NetAddr returns the network address in this Destination in string form.
func (d Destination) NetAddr() string {
	addr := ""
	if d.Network == Network_TCP || d.Network == Network_UDP {
		addr = d.Address.String() + ":" + d.Port.String()
	} else if d.Network == Network_UNIX {
		addr = d.Address.String()
	}
	return addr
}

// RawNetAddr converts a net.Addr from its Destination presentation.
func (d Destination) RawNetAddr() net.Addr {
	var addr net.Addr
	switch d.Network {
	case Network_TCP:
		if d.Address.Family().IsIP() {
			addr = &net.TCPAddr{
				IP:   d.Address.IP(),
				Port: int(d.Port),
			}
		}
	case Network_UDP:
		if d.Address.Family().IsIP() {
			addr = &net.UDPAddr{
				IP:   d.Address.IP(),
				Port: int(d.Port),
			}
		}
	case Network_UNIX:
		if d.Address.Family().IsDomain() {
			addr = &net.UnixAddr{
				Name: d.Address.String(),
				Net:  d.Network.SystemString(),
			}
		}
	}
	return addr
}

// String returns the strings form of this Destination.
func (d Destination) String() string {
	prefix := "unknown:"
	switch d.Network {
	case Network_TCP:
		prefix = "tcp:"
	case Network_UDP:
		prefix = "udp:"
	case Network_UNIX:
		prefix = "unix:"
	}
	return prefix + d.NetAddr()
}

// IsValid returns true if this Destination is valid.
func (d Destination) IsValid() bool {
	return d.Network != Network_Unknown
}
