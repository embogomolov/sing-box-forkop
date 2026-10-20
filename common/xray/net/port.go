package net

import (
	"strconv"
)

// Port represents a network port in TCP and UDP protocol.
type Port uint16

// Value return the corresponding uint16 value of a Port.
func (p Port) Value() uint16 {
	return uint16(p)
}

// String returns the string presentation of a Port.
func (p Port) String() string {
	return strconv.Itoa(int(p))
}
