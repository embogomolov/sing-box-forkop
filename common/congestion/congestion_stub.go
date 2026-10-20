//go:build !with_quic

package congestion

import "time"

// Without QUIC nothing a controller could drive exists, so every name passes.
func NewCongestionControl(name string, cwnd int, timeFunc func() time.Time) (any, error) {
	return nil, nil
}
