package net

type Network int32

const (
	Network_Unknown Network = 0
	Network_TCP     Network = 2
	Network_UDP     Network = 3
	Network_UNIX    Network = 4
)

func (n Network) SystemString() string {
	switch n {
	case Network_TCP:
		return "tcp"
	case Network_UDP:
		return "udp"
	case Network_UNIX:
		return "unix"
	default:
		return "unknown"
	}
}
