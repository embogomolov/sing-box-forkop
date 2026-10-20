package group

import (
	"errors"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	N "github.com/sagernet/sing/common/network"
)

// Mihomo's groups check their members once a member refused a connection or after the fifth
// failure less than five seconds apart (adapter/outboundgroup/groupbase.go, onDialFailed).
const (
	dialFailureWindow = 5 * time.Second
	maxDialFailures   = 5
)

// dialFailures counts the failed dials of a member until they call for a check.
type dialFailures struct {
	count   int
	started time.Time
}

// add counts a failure and tells whether the failures so far call for a check, which starts
// the count again.
func (f *dialFailures) add(now time.Time, err error) bool {
	if f.count == 0 || now.Sub(f.started) > dialFailureWindow {
		f.count = 1
		f.started = now
	} else {
		f.count++
	}
	if errors.Is(err, syscall.ECONNREFUSED) || f.count >= maxDialFailures {
		*f = dialFailures{}
		return true
	}
	return false
}

// countableDialFailure mirrors Mihomo onDialFailed: failures of members that
// cannot be down, and failures caused by an unsupported request rather than by
// the member itself, must not push the group towards an early health check.
func countableDialFailure(detour adapter.Outbound, err error) bool {
	switch detour.Type() {
	case C.TypeDirect, C.TypeBlock, C.TypeDNS:
		return false
	}
	return !errors.Is(err, N.ErrUnknownNetwork)
}
