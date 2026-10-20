package subscription

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/sagernet/sing/common/byteformats"
)

// ParseBandwidth reads a bandwidth as subscriptions write it: a bare number, read as Mbps, or a
// number with a unit as in "30 Mbps".
func ParseBandwidth(value string) *byteformats.NetworkBytesCompat {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if _, err := strconv.ParseUint(value, 10, 64); err == nil {
		value += "Mbps"
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	bandwidth := &byteformats.NetworkBytesCompat{}
	if err = bandwidth.UnmarshalJSON(encoded); err != nil {
		return nil
	}
	return bandwidth
}

// BandwidthMbps reads a bandwidth and rounds it to the whole megabits per
// second the Hysteria options are written in.
func BandwidthMbps(value string) int {
	bandwidth := ParseBandwidth(value)
	if bandwidth == nil {
		return 0
	}
	// Dividing last keeps the fraction of a megabyte that whole megabytes lose.
	return int(bandwidth.Value() * 8 / byteformats.MByte)
}
