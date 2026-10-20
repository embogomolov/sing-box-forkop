package wireguard

import "github.com/sagernet/sing-box/adapter"

func SharesDevice(a, b adapter.Endpoint) bool {
	return a.(*Endpoint).device == b.(*Endpoint).device
}

// ReleaseDevice gives up the endpoint's share of its device, as closing the
// endpoint does.
func ReleaseDevice(e adapter.Endpoint) error {
	return e.(*Endpoint).device.release(e.(*Endpoint))
}
